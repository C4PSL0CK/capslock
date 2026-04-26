package detector

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ConfigExtractor extracts security configuration from Kubernetes namespaces
type ConfigExtractor struct {
	clientset kubernetes.Interface
}

// NewConfigExtractor creates a new config extractor
func NewConfigExtractor(clientset kubernetes.Interface) *ConfigExtractor {
	return &ConfigExtractor{
		clientset: clientset,
	}
}

// ExtractNamespaceConfig extracts complete security configuration from a namespace
func (ce *ConfigExtractor) ExtractNamespaceConfig(ctx context.Context, namespaceName string) (*NamespaceConfig, error) {
	// Get namespace object
	namespace, err := ce.clientset.CoreV1().Namespaces().Get(ctx, namespaceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace: %w", err)
	}

	// Initialize config
	config := NewNamespaceConfig(namespaceName)
	config.Labels = namespace.Labels

	// Extract Pod Security Standard from labels
	if enforce, ok := namespace.Labels["pod-security.kubernetes.io/enforce"]; ok {
		config.PodSecurity.Standard = enforce
	}

	// Extract pod security configuration
	if err := ce.extractPodSecurityConfig(ctx, namespaceName, config); err != nil {
		return nil, fmt.Errorf("failed to extract pod security config: %w", err)
	}

	// Extract RBAC configuration
	if err := ce.extractRBACConfig(ctx, namespaceName, config); err != nil {
		return nil, fmt.Errorf("failed to extract RBAC config: %w", err)
	}

	// Extract network configuration
	if err := ce.extractNetworkConfig(ctx, namespaceName, config); err != nil {
		return nil, fmt.Errorf("failed to extract network config: %w", err)
	}

	// Extract secrets configuration
	if err := ce.extractSecretsConfig(ctx, namespaceName, config); err != nil {
		return nil, fmt.Errorf("failed to extract secrets config: %w", err)
	}

	// Extract resource configuration
	if err := ce.extractResourceConfig(ctx, namespaceName, config); err != nil {
		return nil, fmt.Errorf("failed to extract resource config: %w", err)
	}

	// Extract audit configuration (cluster-level, but relevant)
	if err := ce.extractAuditConfig(ctx, config); err != nil {
		// Non-fatal - audit config is cluster-level
		// Just log and continue
	}

	return config, nil
}

// extractPodSecurityConfig extracts pod-level security settings
func (ce *ConfigExtractor) extractPodSecurityConfig(ctx context.Context, namespaceName string, config *NamespaceConfig) error {
	// Get all pods in namespace
	pods, err := ce.clientset.CoreV1().Pods(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	config.PodSecurity.TotalPods = len(pods.Items)

	// Analyze each pod
	for _, pod := range pods.Items {
		// Check privileged containers
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				config.PodSecurity.PrivilegedPods++
				config.PodSecurity.AllowPrivileged = true
			}

			// Check capabilities
			if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
				for _, cap := range container.SecurityContext.Capabilities.Add {
					capStr := string(cap)
					if !contains(config.PodSecurity.AllowedCapabilities, capStr) {
						config.PodSecurity.AllowedCapabilities = append(config.PodSecurity.AllowedCapabilities, capStr)
					}
				}
				for _, cap := range container.SecurityContext.Capabilities.Drop {
					capStr := string(cap)
					if !contains(config.PodSecurity.DroppedCapabilities, capStr) {
						config.PodSecurity.DroppedCapabilities = append(config.PodSecurity.DroppedCapabilities, capStr)
					}
					if capStr == "ALL" {
						config.PodSecurity.RequireDropAll = true
					}
				}
			}

			// Check resource limits
			if container.Resources.Limits == nil || (container.Resources.Limits.Cpu().IsZero() && container.Resources.Limits.Memory().IsZero()) {
				config.PodSecurity.PodsWithoutLimits++
			}
		}

		// Check host network
		if pod.Spec.HostNetwork {
			config.PodSecurity.HostNetworkPods++
			config.PodSecurity.AllowHostNetwork = true
		}

		// Check host PID
		if pod.Spec.HostPID {
			config.PodSecurity.AllowHostPID = true
		}

		// Check host IPC
		if pod.Spec.HostIPC {
			config.PodSecurity.AllowHostIPC = true
		}

		// Check host ports
		for _, container := range pod.Spec.Containers {
			if len(container.Ports) > 0 {
				for _, port := range container.Ports {
					if port.HostPort != 0 {
						config.PodSecurity.AllowHostPorts = true
						break
					}
				}
			}
		}

		// Check host path volumes
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath != nil {
				config.PodSecurity.AllowHostPath = true
				path := volume.HostPath.Path
				if !contains(config.PodSecurity.AllowedHostPaths, path) {
					config.PodSecurity.AllowedHostPaths = append(config.PodSecurity.AllowedHostPaths, path)
				}
			}
		}

		// Check security context
		if pod.Spec.SecurityContext != nil {
			// Seccomp
			if pod.Spec.SecurityContext.SeccompProfile != nil {
				config.PodSecurity.SeccompProfile = string(pod.Spec.SecurityContext.SeccompProfile.Type)
			}

			// RunAsNonRoot
			if pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot {
				config.PodSecurity.RunAsNonRoot = true
			} else {
				config.PodSecurity.PodsRunningAsRoot++
			}
		}

		// Check container-level security context
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil {
				// ReadOnlyRootFilesystem
				if container.SecurityContext.ReadOnlyRootFilesystem != nil && *container.SecurityContext.ReadOnlyRootFilesystem {
					config.PodSecurity.ReadOnlyRootFilesystem = true
				}

				// AllowPrivilegeEscalation
				if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
					config.PodSecurity.AllowPrivilegeEscalation = true
				}
			}
		}

		// Check AppArmor annotations
		if profile, ok := pod.Annotations["container.apparmor.security.beta.kubernetes.io/"+pod.Spec.Containers[0].Name]; ok {
			config.PodSecurity.AppArmorProfile = profile
		}
	}

	// Determine if resource limits are required
	config.PodSecurity.RequireResourceLimits = config.PodSecurity.PodsWithoutLimits == 0 && config.PodSecurity.TotalPods > 0

	return nil
}

// extractRBACConfig extracts RBAC-related configuration
func (ce *ConfigExtractor) extractRBACConfig(ctx context.Context, namespaceName string, config *NamespaceConfig) error {
	// Get service accounts
	serviceAccounts, err := ce.clientset.CoreV1().ServiceAccounts(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	config.RBAC.TotalServiceAccounts = len(serviceAccounts.Items)
	for _, sa := range serviceAccounts.Items {
		config.RBAC.ServiceAccountNames = append(config.RBAC.ServiceAccountNames, sa.Name)

		// Check if auto-mount is enabled
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			config.RBAC.ServiceAccountAutoMount = true
		}
	}

	// Check if pods are using default SA
	pods, _ := ce.clientset.CoreV1().Pods(namespaceName).List(ctx, metav1.ListOptions{})
	for _, pod := range pods.Items {
		if pod.Spec.ServiceAccountName == "default" || pod.Spec.ServiceAccountName == "" {
			config.RBAC.DefaultSAUsed = true
			break
		}
	}

	// Get role bindings in namespace
	roleBindings, err := ce.clientset.RbacV1().RoleBindings(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	config.RBAC.TotalRoleBindings = len(roleBindings.Items)

	// Check for cluster-admin bindings
	for _, rb := range roleBindings.Items {
		if rb.RoleRef.Name == "cluster-admin" {
			config.RBAC.ClusterAdminBindings = true
			config.RBAC.HasClusterAdminRole = true
		}
	}

	// Get cluster role bindings (check if any reference this namespace's SAs)
	clusterRoleBindings, err := ce.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range clusterRoleBindings.Items {
			for _, subject := range crb.Subjects {
				if subject.Kind == "ServiceAccount" && subject.Namespace == namespaceName {
					if crb.RoleRef.Name == "cluster-admin" {
						config.RBAC.ClusterAdminBindings = true
						config.RBAC.HasClusterAdminRole = true
					}
				}
			}
		}
	}

	// Get roles in namespace to check for wildcards and secrets access
	roles, err := ce.clientset.RbacV1().Roles(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, role := range roles.Items {
		for _, rule := range role.Rules {
			// Check for wildcard permissions
			for _, resource := range rule.Resources {
				if resource == "*" {
					config.RBAC.WildcardPermissions = true
					config.RBAC.HasWildcardRoles = true
				}
			}
			for _, verb := range rule.Verbs {
				if verb == "*" {
					config.RBAC.WildcardPermissions = true
					config.RBAC.HasWildcardRoles = true
				}
			}

			// Check for secrets access
			for _, resource := range rule.Resources {
				if resource == "secrets" || resource == "*" {
					config.RBAC.SecretsAccessCount++
					config.RBAC.SecretsAccessRoles = append(config.RBAC.SecretsAccessRoles, role.Name)

					// Check if it's read or write access
					for _, verb := range rule.Verbs {
						if verb == "get" || verb == "list" || verb == "watch" {
							config.RBAC.HasSecretsReadAccess = true
						}
						if verb == "create" || verb == "update" || verb == "patch" || verb == "delete" || verb == "*" {
							config.RBAC.HasSecretsWriteAccess = true
						}
					}
				}
			}
		}
	}

	return nil
}

// extractNetworkConfig extracts network policy configuration
func (ce *ConfigExtractor) extractNetworkConfig(ctx context.Context, namespaceName string, config *NamespaceConfig) error {
	// Get network policies
	networkPolicies, err := ce.clientset.NetworkingV1().NetworkPolicies(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	config.Network.TotalNetworkPolicies = len(networkPolicies.Items)
	config.Network.NetworkPoliciesExist = len(networkPolicies.Items) > 0

	// Check for default deny policies
	for _, np := range networkPolicies.Items {
		// Check if this is a default deny policy (empty pod selector + empty ingress/egress rules)
		if isDefaultDenyPolicy(&np) {
			for _, policyType := range np.Spec.PolicyTypes {
				if policyType == networkingv1.PolicyTypeIngress {
					config.Network.DefaultDenyIngress = true
				}
				if policyType == networkingv1.PolicyTypeEgress {
					config.Network.DefaultDenyEgress = true
				}
			}
		}

		// Count ingress and egress rules
		config.Network.IngressRulesCount += len(np.Spec.Ingress)
		config.Network.EgressRulesCount += len(np.Spec.Egress)
	}

	// Try to detect CNI plugin (this is a best-effort detection)
	config.Network.CNIPlugin = detectCNIPlugin(ce.clientset, ctx)
	config.Network.CNISupportsPolicy = cniSupportsNetworkPolicy(config.Network.CNIPlugin)

	return nil
}

// extractSecretsConfig extracts secrets management configuration
func (ce *ConfigExtractor) extractSecretsConfig(ctx context.Context, namespaceName string, config *NamespaceConfig) error {
	// Get secrets
	secrets, err := ce.clientset.CoreV1().Secrets(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	config.Secrets.TotalSecrets = len(secrets.Items)

	// Count by type
	for _, secret := range secrets.Items {
		switch secret.Type {
		case corev1.SecretTypeOpaque:
			config.Secrets.OpaqueSecrets++
		case corev1.SecretTypeTLS:
			config.Secrets.TLSSecrets++
		case corev1.SecretTypeDockerConfigJson:
			config.Secrets.DockerConfigSecrets++
		case corev1.SecretTypeServiceAccountToken:
			config.Secrets.ServiceAccountTokens++
		}
	}

	// Check if secrets are mounted as environment variables
	pods, _ := ce.clientset.CoreV1().Pods(namespaceName).List(ctx, metav1.ListOptions{})
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					config.Secrets.SecretsAsEnvVars = true
					config.Secrets.PodsWithSecretsAsEnv++
					break
				}
			}
		}

		// Check if secrets are mounted as volumes
		for _, volume := range pod.Spec.Volumes {
			if volume.Secret != nil {
				config.Secrets.SecretsAsVolumes = true
			}
		}
	}

	// Check for external secrets manager (External Secrets Operator)
	// Look for ExternalSecret CRDs (this requires dynamic client, simplified here)
	externalSecrets, _ := ce.clientset.CoreV1().Secrets(namespaceName).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=external-secrets",
	})
	if len(externalSecrets.Items) > 0 {
		config.Secrets.ExternalSecretsManager = true
		config.Secrets.ExternalSecretsManagerType = "external-secrets-operator"
	}

	// Check cluster-level encryption at rest (requires checking API server config)
	// This is a simplified check - real implementation would query API server
	config.Secrets.EncryptionAtRest = false // Default to false, would need cluster-level check
	config.Secrets.EncryptionProvider = "unknown"

	return nil
}

// extractResourceConfig extracts resource quota and limit range configuration
func (ce *ConfigExtractor) extractResourceConfig(ctx context.Context, namespaceName string, config *NamespaceConfig) error {
	// Get resource quotas
	resourceQuotas, err := ce.clientset.CoreV1().ResourceQuotas(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	config.Resources.ResourceQuotaExists = len(resourceQuotas.Items) > 0
	config.Resources.TotalResourceQuotas = len(resourceQuotas.Items)

	if len(resourceQuotas.Items) > 0 {
		// Extract quota details from first quota
		quota := resourceQuotas.Items[0]
		if cpu, ok := quota.Spec.Hard[corev1.ResourceRequestsCPU]; ok {
			config.Resources.CPUQuota = cpu.String()
		}
		if memory, ok := quota.Spec.Hard[corev1.ResourceRequestsMemory]; ok {
			config.Resources.MemoryQuota = memory.String()
		}
		if pods, ok := quota.Spec.Hard[corev1.ResourcePods]; ok {
			config.Resources.PodsQuota = pods.String()
		}
	}

	// Get limit ranges
	limitRanges, err := ce.clientset.CoreV1().LimitRanges(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	config.Resources.LimitRangeExists = len(limitRanges.Items) > 0
	config.Resources.TotalLimitRanges = len(limitRanges.Items)

	if len(limitRanges.Items) > 0 {
		// Extract limit range details from first limit range
		limitRange := limitRanges.Items[0]
		for _, limit := range limitRange.Spec.Limits {
			if limit.Type == corev1.LimitTypeContainer {
				if cpu, ok := limit.Default[corev1.ResourceCPU]; ok {
					config.Resources.DefaultCPULimit = cpu.String()
				}
				if memory, ok := limit.Default[corev1.ResourceMemory]; ok {
					config.Resources.DefaultMemoryLimit = memory.String()
				}
				if cpu, ok := limit.Min[corev1.ResourceCPU]; ok {
					config.Resources.MinCPU = cpu.String()
				}
				if cpu, ok := limit.Max[corev1.ResourceCPU]; ok {
					config.Resources.MaxCPU = cpu.String()
				}
				if memory, ok := limit.Min[corev1.ResourceMemory]; ok {
					config.Resources.MinMemory = memory.String()
				}
				if memory, ok := limit.Max[corev1.ResourceMemory]; ok {
					config.Resources.MaxMemory = memory.String()
				}
			}
		}
	}

	// Count pods with resource limits
	pods, _ := ce.clientset.CoreV1().Pods(namespaceName).List(ctx, metav1.ListOptions{})
	for _, pod := range pods.Items {
		hasCPULimit := false
		hasMemoryLimit := false

		for _, container := range pod.Spec.Containers {
			if !container.Resources.Limits.Cpu().IsZero() {
				hasCPULimit = true
			}
			if !container.Resources.Limits.Memory().IsZero() {
				hasMemoryLimit = true
			}
		}

		if hasCPULimit {
			config.Resources.PodsWithCPULimits++
		}
		if hasMemoryLimit {
			config.Resources.PodsWithMemoryLimits++
		}
		if !hasCPULimit && !hasMemoryLimit {
			config.Resources.PodsWithoutLimits++
		}
	}

	return nil
}

// extractAuditConfig extracts audit logging configuration (cluster-level)
func (ce *ConfigExtractor) extractAuditConfig(ctx context.Context, config *NamespaceConfig) error {
	// This is cluster-level configuration
	// Would require checking API server configuration
	// Simplified implementation - would need to check API server pod spec

	config.Audit.AuditLogEnabled = false // Default, would need cluster check
	config.Audit.AuditPolicyExists = false
	config.Audit.AuditBackend = "unknown"
	config.Audit.AuditLogMaxAge = 0
	config.Audit.AuditLogMaxBackup = 0
	config.Audit.AuditLogMaxSize = 0

	return nil
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func isDefaultDenyPolicy(np *networkingv1.NetworkPolicy) bool {
	// Default deny policy has empty pod selector and no ingress/egress rules
	if len(np.Spec.PodSelector.MatchLabels) > 0 || len(np.Spec.PodSelector.MatchExpressions) > 0 {
		return false
	}

	// Check if it has empty ingress/egress (which means deny all)
	for _, policyType := range np.Spec.PolicyTypes {
		if policyType == networkingv1.PolicyTypeIngress && len(np.Spec.Ingress) == 0 {
			return true
		}
		if policyType == networkingv1.PolicyTypeEgress && len(np.Spec.Egress) == 0 {
			return true
		}
	}

	return false
}

func detectCNIPlugin(clientset kubernetes.Interface, ctx context.Context) string {
	// Try to detect CNI plugin from common indicators
	// This is best-effort detection

	// Check for Calico
	_, err := clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
	})
	if err == nil {
		return "calico"
	}

	// Check for Cilium
	_, err = clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=cilium",
	})
	if err == nil {
		return "cilium"
	}

	// Check for Weave
	_, err = clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "name=weave-net",
	})
	if err == nil {
		return "weave-net"
	}

	// Check for Flannel
	_, err = clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "app=flannel",
	})
	if err == nil {
		return "flannel"
	}

	return "unknown"
}

func cniSupportsNetworkPolicy(cniPlugin string) bool {
	// CNI plugins that support NetworkPolicy
	supportedCNIs := map[string]bool{
		"calico":    true,
		"cilium":    true,
		"weave-net": true,
		"antrea":    true,
		"kube-router": true,
	}

	return supportedCNIs[cniPlugin]
}
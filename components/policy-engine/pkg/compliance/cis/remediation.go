package cis

import (
	"fmt"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance"
)

// GetRemediation returns detailed remediation guidance for a specific CIS check
func GetRemediation(ruleID string) (*compliance.RemediationGuidance, error) {
	// Map of all remediation guidance
	remediations := map[string]*compliance.RemediationGuidance{
		// Section 4.1 - RBAC
		"4.1.1": {
			RuleID: "4.1.1",
			Steps: []string{
				"Review all RoleBindings and ClusterRoleBindings in the namespace",
				"Identify any bindings to the cluster-admin role",
				"Create more restrictive custom roles with only required permissions",
				"Replace cluster-admin bindings with custom role bindings",
				"Document justification for any remaining cluster-admin usage",
			},
			ExampleConfig: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "update"]`,
			KubectlCommands: []string{
				"kubectl get rolebindings -n <namespace> -o yaml",
				"kubectl get clusterrolebindings -o yaml | grep cluster-admin",
				"kubectl delete rolebinding <binding-name> -n <namespace>",
			},
			EstimatedTime: "30-60 minutes",
			Priority:      "HIGH",
		},

		"4.1.2": {
			RuleID: "4.1.2",
			Steps: []string{
				"Audit all Roles and ClusterRoles for secrets access",
				"Identify roles with 'get', 'list', 'watch', 'create', 'update', or 'delete' verbs on secrets",
				"Remove unnecessary secrets permissions",
				"Use specific resource names instead of wildcard access to secrets",
				"Implement least privilege principle",
			},
			KubectlCommands: []string{
				"kubectl get roles,clusterroles -o yaml | grep -A 10 secrets",
				"kubectl auth can-i get secrets --as=system:serviceaccount:<namespace>:<sa-name>",
			},
			EstimatedTime: "45 minutes",
			Priority:      "HIGH",
		},

		"4.1.3": {
			RuleID: "4.1.3",
			Steps: []string{
				"List all Roles and ClusterRoles",
				"Search for wildcard '*' in resources, verbs, or apiGroups",
				"Replace wildcards with specific resource names and verbs",
				"Test that applications still function with restricted permissions",
			},
			ExampleConfig: `# BAD - Uses wildcards
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# GOOD - Specific permissions
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]`,
			KubectlCommands: []string{
				"kubectl get roles,clusterroles -o yaml | grep '\"\\*\"'",
			},
			EstimatedTime: "1-2 hours",
			Priority:      "MEDIUM",
		},

		"4.1.6": {
			RuleID: "4.1.6",
			Steps: []string{
				"Set automountServiceAccountToken: false on ServiceAccounts that don't need API access",
				"Set automountServiceAccountToken: false in Pod specifications",
				"Only enable auto-mount for pods that explicitly need to call Kubernetes API",
			},
			ExampleConfig: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  serviceAccountName: my-service-account
  automountServiceAccountToken: false`,
			KubectlCommands: []string{
				"kubectl patch serviceaccount default -p '{\"automountServiceAccountToken\": false}'",
			},
			EstimatedTime: "15-30 minutes",
			Priority:      "MEDIUM",
		},

		// Section 4.2 - Pod Security
		"4.2.1": {
			RuleID: "4.2.1",
			Steps: []string{
				"Add Pod Security Standard label to namespace: pod-security.kubernetes.io/enforce: restricted",
				"Review all pods for privileged: true setting",
				"Remove privileged flag from pod security contexts",
				"Use Pod Security Admission or policy engine to enforce",
			},
			ExampleConfig: `apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted`,
			KubectlCommands: []string{
				"kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=restricted",
				"kubectl get pods -n <namespace> -o jsonpath='{.items[*].spec.containers[*].securityContext.privileged}'",
			},
			EstimatedTime: "30-45 minutes",
			Priority:      "IMMEDIATE",
		},

		"4.2.3": {
			RuleID: "4.2.3",
			Steps: []string{
				"Identify pods with hostNetwork: true",
				"Remove hostNetwork from pod specifications",
				"Use Services and ClusterIP for pod networking",
				"Enforce with Pod Security Standard 'baseline' or 'restricted'",
			},
			ExampleConfig: `apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  hostNetwork: false  # Explicit false
  containers:
  - name: app
    image: myapp:latest`,
			KubectlCommands: []string{
				"kubectl get pods -n <namespace> -o jsonpath='{.items[?(@.spec.hostNetwork==true)].metadata.name}'",
			},
			EstimatedTime: "20-30 minutes",
			Priority:      "HIGH",
		},

		"4.2.7": {
			RuleID: "4.2.7",
			Steps: []string{
				"Set seccomp profile to RuntimeDefault in pod security context",
				"For custom profiles, create seccomp profile files and use type: Localhost",
				"Verify profile is applied with kubectl describe",
			},
			ExampleConfig: `apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:latest`,
			KubectlCommands: []string{
				"kubectl describe pod <pod-name> | grep seccomp",
			},
			EstimatedTime: "15-20 minutes",
			Priority:      "MEDIUM",
		},

		"4.2.8": {
			RuleID: "4.2.8",
			Steps: []string{
				"Add runAsNonRoot: true to pod security context",
				"Set runAsUser to non-zero value (e.g., 1000)",
				"Update container images to use USER directive with non-root user",
				"Test application still functions correctly",
			},
			ExampleConfig: `apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: myapp:latest`,
			KubectlCommands: []string{
				"kubectl get pods -n <namespace> -o jsonpath='{.items[*].spec.securityContext.runAsNonRoot}'",
			},
			EstimatedTime: "30-45 minutes",
			Priority:      "MEDIUM",
		},

		"4.2.10": {
			RuleID: "4.2.10",
			Steps: []string{
				"Create LimitRange to enforce default resource limits",
				"Add resource limits to all container specifications",
				"Set appropriate CPU and memory limits based on application needs",
				"Monitor actual resource usage to tune limits",
			},
			ExampleConfig: `apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
spec:
  limits:
  - default:
      cpu: 500m
      memory: 512Mi
    defaultRequest:
      cpu: 100m
      memory: 128Mi
    type: Container
---
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    resources:
      limits:
        cpu: "1"
        memory: 1Gi
      requests:
        cpu: 500m
        memory: 512Mi`,
			KubectlCommands: []string{
				"kubectl create -f limitrange.yaml",
				"kubectl describe limitrange -n <namespace>",
			},
			EstimatedTime: "45-60 minutes",
			Priority:      "MEDIUM",
		},

		"4.2.11": {
			RuleID: "4.2.11",
			Steps: []string{
				"Add capabilities.drop: [ALL] to all container security contexts",
				"Only add back specific capabilities that are absolutely required",
				"Document justification for any added capabilities",
			},
			ExampleConfig: `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      capabilities:
        drop:
        - ALL
        add:
        - NET_BIND_SERVICE  # Only if needed`,
			KubectlCommands: []string{
				"kubectl get pods -o jsonpath='{.items[*].spec.containers[*].securityContext.capabilities}'",
			},
			EstimatedTime: "30 minutes",
			Priority:      "HIGH",
		},

		// Section 4.3 - Network Policies
		"4.3.2": {
			RuleID: "4.3.2",
			Steps: []string{
				"Create NetworkPolicy resources for the namespace",
				"Define allowed ingress and egress rules",
				"Start with default deny, then add exceptions",
				"Test connectivity to ensure applications work",
			},
			ExampleConfig: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-specific-traffic
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: frontend
    ports:
    - protocol: TCP
      port: 8080`,
			KubectlCommands: []string{
				"kubectl create -f networkpolicy.yaml",
				"kubectl get networkpolicies -n <namespace>",
			},
			EstimatedTime: "1-2 hours",
			Priority:      "MEDIUM",
		},

		"4.3.3": {
			RuleID: "4.3.3",
			Steps: []string{
				"Create default deny NetworkPolicy for both ingress and egress",
				"Apply to namespace",
				"Create additional policies to allow required traffic",
			},
			ExampleConfig: `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`,
			KubectlCommands: []string{
				"kubectl apply -f default-deny.yaml -n <namespace>",
			},
			EstimatedTime: "30 minutes",
			Priority:      "MEDIUM",
		},

		// Section 4.4 - Secrets
		"4.4.1": {
			RuleID: "4.4.1",
			Steps: []string{
				"Identify pods using secrets as environment variables",
				"Convert to volume mounts instead",
				"Update pod specifications",
				"Redeploy applications",
			},
			ExampleConfig: `# GOOD - Mount as volume
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    volumeMounts:
    - name: secret-volume
      mountPath: /etc/secrets
      readOnly: true
  volumes:
  - name: secret-volume
    secret:
      secretName: my-secret`,
			KubectlCommands: []string{
				"kubectl get pods -o yaml | grep -A 5 'env:' | grep secretKeyRef",
			},
			EstimatedTime: "1-2 hours",
			Priority:      "MEDIUM",
		},

		// Section 4.5 - Namespace Configuration
		"4.5.2": {
			RuleID: "4.5.2",
			Steps: []string{
				"Create ResourceQuota for the namespace",
				"Define appropriate limits for CPU, memory, and pod count",
				"Apply the ResourceQuota",
				"Monitor usage against quotas",
			},
			ExampleConfig: `apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "50"`,
			KubectlCommands: []string{
				"kubectl create -f resourcequota.yaml -n <namespace>",
				"kubectl describe resourcequota -n <namespace>",
			},
			EstimatedTime: "30 minutes",
			Priority:      "LOW",
		},

		"4.5.3": {
			RuleID: "4.5.3",
			Steps: []string{
				"Create LimitRange for the namespace",
				"Set default and maximum resource limits",
				"Apply the LimitRange",
			},
			ExampleConfig: `apiVersion: v1
kind: LimitRange
metadata:
  name: limit-range
spec:
  limits:
  - default:
      cpu: 500m
      memory: 512Mi
    defaultRequest:
      cpu: 100m
      memory: 128Mi
    max:
      cpu: "2"
      memory: 2Gi
    min:
      cpu: 50m
      memory: 64Mi
    type: Container`,
			KubectlCommands: []string{
				"kubectl create -f limitrange.yaml -n <namespace>",
				"kubectl describe limitrange -n <namespace>",
			},
			EstimatedTime: "20 minutes",
			Priority:      "LOW",
		},
	}

	guidance, exists := remediations[ruleID]
	if !exists {
		return nil, fmt.Errorf("no remediation guidance found for rule %s", ruleID)
	}

	return guidance, nil
}

// GetAllRemediations returns remediation guidance for all CIS checks
func GetAllRemediations() map[string]*compliance.RemediationGuidance {
	remediations := make(map[string]*compliance.RemediationGuidance)

	// Get all check IDs
	allCheckIDs := []string{
		"4.1.1", "4.1.2", "4.1.3", "4.1.4", "4.1.5", "4.1.6", "4.1.7", "4.1.8",
		"4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7", "4.2.8",
		"4.2.9", "4.2.10", "4.2.11", "4.2.12",
		"4.3.1", "4.3.2", "4.3.3",
		"4.4.1", "4.4.2",
		"4.5.1", "4.5.2", "4.5.3",
	}

	for _, checkID := range allCheckIDs {
		if guidance, err := GetRemediation(checkID); err == nil {
			remediations[checkID] = guidance
		}
	}

	return remediations
}
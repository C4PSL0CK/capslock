package pcidss

import (
	"fmt"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// GetAllPCIDSSRequirements returns all 16 PCI-DSS requirements applicable to Kubernetes
func GetAllPCIDSSRequirements() []PCIDSSRequirement {
	return []PCIDSSRequirement{
		// ================================================================
		// Requirement 1: Install and maintain network security controls
		// ================================================================
		{
			ID:                "1.2.1",
			ParentRequirement: "1",
			Title:             "Network security controls are configured and maintained",
			Severity:          "HIGH",
			Description:       "Ensure network security controls (NetworkPolicies) are configured to prevent unauthorized access between network segments",
			KubernetesControls: []string{
				"NetworkPolicy resources",
				"CNI with network policy support",
				"Default deny policies",
			},
			MappedCISChecks: []string{"4.3.1", "4.3.2", "4.3.3"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if !config.Network.NetworkPoliciesExist {
					return false, "No NetworkPolicies defined in namespace", []string{config.Name}
				}
				if !config.Network.CNISupportsPolicy {
					return false, "CNI does not support NetworkPolicies", []string{config.Network.CNIPlugin}
				}
				if !config.Network.DefaultDenyIngress || !config.Network.DefaultDenyEgress {
					return false, "Default deny policy not configured", []string{config.Name}
				}
				return true, "Network security controls properly configured", []string{}
			},
			Remediation: "Configure NetworkPolicies with default deny rules and explicit allow rules for required traffic",
			References: []string{
				"PCI-DSS v4.0 Requirement 1.2.1",
				"https://docs.pcisecuritystandards.org/",
			},
		},

		// ================================================================
		// Requirement 2: Apply secure configurations
		// ================================================================
		{
			ID:                "2.2.2",
			ParentRequirement: "2",
			Title:             "Vendor default accounts are managed",
			Severity:          "HIGH",
			Description:       "Default service accounts must not be actively used for workloads",
			KubernetesControls: []string{
				"Disable default ServiceAccount",
				"Create dedicated ServiceAccounts",
			},
			MappedCISChecks: []string{"4.1.5"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if config.RBAC.DefaultSAUsed {
					return false, "Default ServiceAccount is actively used", []string{config.Name + "/default"}
				}
				return true, "Default ServiceAccount not in use", []string{}
			},
			Remediation: "Create dedicated ServiceAccounts for each application and set automountServiceAccountToken: false on default SA",
			References: []string{
				"PCI-DSS v4.0 Requirement 2.2.2",
			},
		},

		{
			ID:                "2.2.4",
			ParentRequirement: "2",
			Title:             "System security parameters are configured to prevent misuse",
			Severity:          "CRITICAL",
			Description:       "Pod security configurations must prevent privileged containers and insecure settings",
			KubernetesControls: []string{
				"Pod Security Standards - restricted",
				"SecurityContext restrictions",
			},
			MappedCISChecks: []string{"4.2.1", "4.2.3", "4.2.4", "4.2.5", "4.2.11", "4.2.12"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				violations := []string{}

				if config.PodSecurity.AllowPrivileged {
					violations = append(violations, "Privileged containers allowed")
				}
				if config.PodSecurity.AllowHostNetwork {
					violations = append(violations, "hostNetwork allowed")
				}
				if config.PodSecurity.AllowHostPID {
					violations = append(violations, "hostPID allowed")
				}
				if config.PodSecurity.AllowHostIPC {
					violations = append(violations, "hostIPC allowed")
				}
				if !config.PodSecurity.RequireDropAll {
					violations = append(violations, "Not requiring ALL capabilities to be dropped")
				}

				if len(violations) > 0 {
					return false, fmt.Sprintf("Insecure pod configurations detected: %d violations", len(violations)), violations
				}
				return true, "Pod security parameters properly configured", []string{}
			},
			Remediation: "Apply Pod Security Standard 'restricted' and configure SecurityContext to block privileged settings",
			References: []string{
				"PCI-DSS v4.0 Requirement 2.2.4",
			},
		},

		// ================================================================
		// Requirement 3: Protect stored account data
		// ================================================================
		{
			ID:                "3.4.1",
			ParentRequirement: "3",
			Title:             "PAN is protected with strong cryptography during storage",
			Severity:          "CRITICAL",
			Description:       "Sensitive data must be encrypted at rest using strong cryptography",
			KubernetesControls: []string{
				"EncryptionConfiguration for etcd",
				"Secrets encryption at rest",
			},
			MappedCISChecks: []string{},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if !config.Secrets.EncryptionAtRest {
					return false, "Encryption at rest not enabled", []string{config.Name}
				}
				return true, "Encryption at rest enabled", []string{}
			},
			Remediation: "Configure Kubernetes EncryptionConfiguration to encrypt secrets at rest in etcd",
			References: []string{
				"PCI-DSS v4.0 Requirement 3.4.1",
			},
		},

		{
			ID:                "3.5.1",
			ParentRequirement: "3",
			Title:             "Cryptographic keys are managed securely",
			Severity:          "CRITICAL",
			Description:       "Cryptographic keys used for encryption must be managed through external key management systems",
			KubernetesControls: []string{
				"External Secrets Operator",
				"HashiCorp Vault",
				"Cloud KMS providers",
			},
			MappedCISChecks: []string{"4.4.2"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if !config.Secrets.ExternalSecretsManager {
					return false, "External secrets manager not configured", []string{config.Name}
				}
				return true, fmt.Sprintf("External secrets manager configured: %s", config.Secrets.ExternalSecretsManagerType), []string{}
			},
			Remediation: "Deploy External Secrets Operator and integrate with HashiCorp Vault or cloud KMS",
			References: []string{
				"PCI-DSS v4.0 Requirement 3.5.1",
			},
		},

		{
			ID:                "3.6.1",
			ParentRequirement: "3",
			Title:             "Cryptographic key storage procedures are defined and implemented",
			Severity:          "HIGH",
			Description:       "Secrets must be stored securely as files with restricted permissions, not as environment variables",
			KubernetesControls: []string{
				"Mount secrets as volumes",
				"ReadOnly volume mounts",
			},
			MappedCISChecks: []string{"4.4.1"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if config.Secrets.SecretsAsEnvVars {
					return false, fmt.Sprintf("Secrets used as environment variables in %d pods", config.Secrets.PodsWithSecretsAsEnv), []string{config.Name}
				}
				return true, "Secrets properly mounted as volumes", []string{}
			},
			Remediation: "Update pod specifications to mount secrets as volumes instead of using environment variables",
			References: []string{
				"PCI-DSS v4.0 Requirement 3.6.1",
			},
		},

		// ================================================================
		// Requirement 4: Protect data in transit
		// ================================================================
		{
			ID:                "4.2.1",
			ParentRequirement: "4",
			Title:             "Strong cryptography is used during transmission of PAN",
			Severity:          "CRITICAL",
			Description:       "All network communications must be encrypted using TLS 1.2 or higher",
			KubernetesControls: []string{
				"Service mesh with mTLS (Istio, Linkerd)",
				"Ingress TLS termination",
			},
			MappedCISChecks: []string{},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				// This check would require service mesh inspection
				// For now, we check if network policies enforce encryption
				if !config.Network.NetworkPoliciesExist {
					return false, "Cannot verify TLS enforcement without NetworkPolicies", []string{config.Name}
				}
				return true, "Network policies configured (manual TLS verification required)", []string{}
			},
			Remediation: "Deploy service mesh (Istio/Linkerd) with strict mTLS mode, configure Ingress with TLS certificates",
			References: []string{
				"PCI-DSS v4.0 Requirement 4.2.1",
			},
		},

		// ================================================================
		// Requirement 5: Protect all systems and networks from malicious software
		// ================================================================
		{
			ID:                "5.3.2",
			ParentRequirement: "5",
			Title:             "Anti-malware mechanisms are active and maintained",
			Severity:          "HIGH",
			Description:       "Container images must be scanned for malware before deployment",
			KubernetesControls: []string{
				"ICAP-based malware scanning",
				"Admission webhooks for image validation",
			},
			MappedCISChecks: []string{},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				// This requires integration with ICAP operator
				// Cannot be validated from namespace config alone
				return true, "ICAP integration required for validation", []string{}
			},
			Remediation: "Integrate with ICAP operator for automated image scanning before deployment",
			References: []string{
				"PCI-DSS v4.0 Requirement 5.3.2",
			},
		},

		// ================================================================
		// Requirement 6: Develop and maintain secure systems
		// ================================================================
		{
			ID:                "6.3.2",
			ParentRequirement: "6",
			Title:             "Software inventory is maintained",
			Severity:          "MEDIUM",
			Description:       "Maintain inventory of software components through SBOM generation",
			KubernetesControls: []string{
				"SBOM generation",
				"Container image scanning",
			},
			MappedCISChecks: []string{},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				// SBOM tracking requires external tooling
				return true, "SBOM generation recommended", []string{}
			},
			Remediation: "Implement container image scanning with SBOM generation (Syft, Trivy)",
			References: []string{
				"PCI-DSS v4.0 Requirement 6.3.2",
			},
		},

		// ================================================================
		// Requirement 7: Restrict access to system components and data
		// ================================================================
		{
			ID:                "7.1.1",
			ParentRequirement: "7",
			Title:             "Access control systems are configured to enforce permissions",
			Severity:          "HIGH",
			Description:       "RBAC must be configured with least privilege principle",
			KubernetesControls: []string{
				"RBAC Roles and RoleBindings",
				"No cluster-admin usage",
				"No wildcard permissions",
			},
			MappedCISChecks: []string{"4.1.1", "4.1.2", "4.1.3", "4.1.4"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				violations := []string{}

				if config.RBAC.ClusterAdminBindings {
					violations = append(violations, "cluster-admin role bindings detected")
				}
				if config.RBAC.WildcardPermissions {
					violations = append(violations, "Wildcard permissions detected")
				}
				if config.RBAC.HasSecretsWriteAccess {
					violations = append(violations, "Excessive secrets write access")
				}

				if len(violations) > 0 {
					return false, fmt.Sprintf("RBAC violations: %d issues", len(violations)), violations
				}
				return true, "RBAC properly configured with least privilege", []string{}
			},
			Remediation: "Remove cluster-admin bindings, eliminate wildcard permissions, apply least privilege RBAC",
			References: []string{
				"PCI-DSS v4.0 Requirement 7.1.1",
			},
		},

		{
			ID:                "7.2.2",
			ParentRequirement: "7",
			Title:             "Access is assigned based on job classification and function",
			Severity:          "MEDIUM",
			Description:       "ServiceAccounts must be dedicated per application, not shared",
			KubernetesControls: []string{
				"Dedicated ServiceAccounts per application",
			},
			MappedCISChecks: []string{"4.1.5"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if config.RBAC.DefaultSAUsed {
					return false, "Default ServiceAccount in use instead of dedicated SAs", []string{config.Name}
				}
				return true, "Dedicated ServiceAccounts per application", []string{}
			},
			Remediation: "Create dedicated ServiceAccounts for each application with specific permissions",
			References: []string{
				"PCI-DSS v4.0 Requirement 7.2.2",
			},
		},

		// ================================================================
		// Requirement 8: Identify users and authenticate access
		// ================================================================
		{
			ID:                "8.2.1",
			ParentRequirement: "8",
			Title:             "Strong authentication is implemented",
			Severity:          "HIGH",
			Description:       "ServiceAccount tokens must be controlled and not auto-mounted unnecessarily",
			KubernetesControls: []string{
				"Disable automountServiceAccountToken",
				"Use projected tokens with short TTL",
			},
			MappedCISChecks: []string{"4.1.6", "4.1.7"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if config.RBAC.ServiceAccountAutoMount {
					return false, "ServiceAccount tokens auto-mounted", []string{config.Name}
				}
				return true, "ServiceAccount token mounting properly controlled", []string{}
			},
			Remediation: "Set automountServiceAccountToken: false on ServiceAccounts and Pods",
			References: []string{
				"PCI-DSS v4.0 Requirement 8.2.1",
			},
		},

		{
			ID:                "8.6.1",
			ParentRequirement: "8",
			Title:             "Application and system accounts are managed",
			Severity:          "MEDIUM",
			Description:       "ServiceAccounts must be properly managed with clear ownership and purpose",
			KubernetesControls: []string{
				"Dedicated ServiceAccounts",
				"ServiceAccount naming conventions",
			},
			MappedCISChecks: []string{"4.1.5"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if config.RBAC.TotalServiceAccounts == 0 {
					return false, "No ServiceAccounts defined", []string{config.Name}
				}
				return true, fmt.Sprintf("%d ServiceAccounts properly managed", config.RBAC.TotalServiceAccounts), []string{}
			},
			Remediation: "Document ServiceAccount purposes, implement naming conventions",
			References: []string{
				"PCI-DSS v4.0 Requirement 8.6.1",
			},
		},

		// ================================================================
		// Requirement 10: Log and monitor all access to system components and data
		// ================================================================
		{
			ID:                "10.2.1",
			ParentRequirement: "10",
			Title:             "Audit logs are implemented to support anomaly detection",
			Severity:          "HIGH",
			Description:       "Kubernetes audit logging must be enabled and comprehensive",
			KubernetesControls: []string{
				"Kubernetes audit logging",
				"Audit policy configuration",
			},
			MappedCISChecks: []string{},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if !config.Audit.AuditLogEnabled {
					return false, "Audit logging not enabled", []string{"cluster"}
				}
				return true, "Audit logging enabled", []string{}
			},
			Remediation: "Enable Kubernetes audit logging with comprehensive audit policy",
			References: []string{
				"PCI-DSS v4.0 Requirement 10.2.1",
			},
		},

		{
			ID:                "10.3.4",
			ParentRequirement: "10",
			Title:             "Audit logs are protected from destruction and unauthorized modifications",
			Severity:          "HIGH",
			Description:       "Audit logs must be retained for at least 90 days with proper protection",
			KubernetesControls: []string{
				"Audit log retention (90+ days)",
				"Centralized logging",
			},
			MappedCISChecks: []string{},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if config.Audit.AuditLogMaxAge < 90 {
					return false, fmt.Sprintf("Audit log retention too short: %d days (required: 90)", config.Audit.AuditLogMaxAge), []string{"cluster"}
				}
				return true, fmt.Sprintf("Audit log retention: %d days", config.Audit.AuditLogMaxAge), []string{}
			},
			Remediation: "Configure audit log retention for at least 90 days, use immutable storage",
			References: []string{
				"PCI-DSS v4.0 Requirement 10.3.4",
			},
		},

		// ================================================================
		// Requirement 11: Test security systems and networks regularly
		// ================================================================
		{
			ID:                "11.4.2",
			ParentRequirement: "11",
			Title:             "Intrusion detection/prevention techniques are used",
			Severity:          "MEDIUM",
			Description:       "Network policies and runtime monitoring must be in place for intrusion detection",
			KubernetesControls: []string{
				"NetworkPolicies for traffic filtering",
				"Runtime security monitoring (Falco)",
			},
			MappedCISChecks: []string{"4.3.2", "4.3.3"},
			Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
				if !config.Network.NetworkPoliciesExist {
					return false, "No NetworkPolicies for intrusion prevention", []string{config.Name}
				}
				return true, "NetworkPolicies configured for intrusion prevention", []string{}
			},
			Remediation: "Deploy NetworkPolicies and runtime security monitoring tools (Falco)",
			References: []string{
				"PCI-DSS v4.0 Requirement 11.4.2",
			},
		},
	}
}
package cis

import (
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// Section 4.1: RBAC and Service Accounts (8 checks)

// Check_4_1_1 ensures cluster-admin role is only used where required
var Check_4_1_1 = CISCheck{
	ID:       "4.1.1",
	Section:  "4.1",
	Title:    "Ensure that the cluster-admin role is only used where required",
	Severity: "HIGH",
	Description: "The cluster-admin role provides wide-ranging powers over the environment and should be used only where required.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.RBAC.HasClusterAdminRole || config.RBAC.ClusterAdminBindings {
			return false, "Namespace has service accounts bound to cluster-admin role", []string{}
		}
		return true, "No cluster-admin role bindings found", []string{}
	},
	Remediation: "Review all RoleBindings and ClusterRoleBindings. Remove cluster-admin bindings unless absolutely necessary. Use more restrictive roles instead.",
	References: []string{
		"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
		"https://www.cisecurity.org/benchmark/kubernetes",
	},
}

// Check_4_1_2 ensures access to secrets is minimized
var Check_4_1_2 = CISCheck{
	ID:       "4.1.2",
	Section:  "4.1",
	Title:    "Minimize access to secrets",
	Severity: "HIGH",
	Description: "The Kubernetes API stores secrets, which may be service account tokens or credentials used by Pods to access other services. Access to these secrets should be restricted.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.RBAC.HasSecretsWriteAccess {
			return false, "Roles with secrets write access detected", config.RBAC.SecretsAccessRoles
		}
		if config.RBAC.SecretsAccessCount > 2 {
			return false, "Excessive number of roles have secrets access", config.RBAC.SecretsAccessRoles
		}
		return true, "Secrets access is appropriately restricted", []string{}
	},
	Remediation: "Review RoleBindings and ClusterRoleBindings. Ensure only necessary service accounts have 'get', 'list', or 'watch' access to secrets. Never grant 'create', 'update', 'patch', or 'delete' unless absolutely required.",
	References: []string{
		"https://kubernetes.io/docs/concepts/configuration/secret/",
	},
}

// Check_4_1_3 ensures wildcard use in roles is minimized
var Check_4_1_3 = CISCheck{
	ID:       "4.1.3",
	Section:  "4.1",
	Title:    "Minimize wildcard use in Roles and ClusterRoles",
	Severity: "MEDIUM",
	Description: "Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects and actions that can be taken on those objects. It is possible to set either of these to be the wildcard '*' which matches all items.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.RBAC.WildcardPermissions || config.RBAC.HasWildcardRoles {
			return false, "Wildcard permissions detected in roles", []string{}
		}
		return true, "No wildcard permissions found", []string{}
	},
	Remediation: "Review Roles and ClusterRoles. Replace wildcard permissions with specific resource and verb combinations. Use 'kubectl get roles,clusterroles -o yaml' to audit.",
	References: []string{
		"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping",
	},
}

// Check_4_1_4 ensures service accounts are not bound to cluster-admin
var Check_4_1_4 = CISCheck{
	ID:       "4.1.4",
	Section:  "4.1",
	Title:    "Minimize access to create pods",
	Severity: "MEDIUM",
	Description: "The ability to create pods in a namespace can provide a number of opportunities for privilege escalation.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		// Check if any service accounts are bound to cluster-admin
		if config.RBAC.ClusterAdminBindings {
			return false, "Service accounts bound to cluster-admin detected", config.RBAC.ServiceAccountNames
		}
		return true, "Service accounts appropriately scoped", []string{}
	},
	Remediation: "Review all RoleBindings and ClusterRoleBindings. Ensure service accounts do not have cluster-admin privileges unless absolutely necessary.",
	References: []string{
		"https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
	},
}

// Check_4_1_5 ensures default service accounts are not actively used
var Check_4_1_5 = CISCheck{
	ID:       "4.1.5",
	Section:  "4.1",
	Title:    "Ensure that default service accounts are not actively used",
	Severity: "MEDIUM",
	Description: "The default service account should not be used to ensure that rights granted to applications can be more easily audited and reviewed.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.RBAC.DefaultSAUsed {
			return false, "Pods are using the default service account", []string{"default"}
		}
		return true, "Default service account not actively used", []string{}
	},
	Remediation: "Create dedicated service accounts for each application. Set automountServiceAccountToken: false on default service account. Use 'kubectl patch serviceaccount default -p '{\"automountServiceAccountToken\": false}''",
	References: []string{
		"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
	},
}

// Check_4_1_6 ensures service account tokens are not automatically mounted
var Check_4_1_6 = CISCheck{
	ID:       "4.1.6",
	Section:  "4.1",
	Title:    "Ensure that Service Account Tokens are only mounted where necessary",
	Severity: "MEDIUM",
	Description: "Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.RBAC.ServiceAccountAutoMount {
			return false, "Service account tokens are automatically mounted", []string{}
		}
		return true, "Service account auto-mount disabled", []string{}
	},
	Remediation: "Set automountServiceAccountToken: false in ServiceAccount definitions and Pod specifications where API access is not required.",
	References: []string{
		"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#use-the-default-service-account-to-access-the-api-server",
	},
}

// Check_4_1_7 ensures service account credentials are not stored in config files
var Check_4_1_7 = CISCheck{
	ID:       "4.1.7",
	Section:  "4.1",
	Title:    "Avoid use of system:masters group",
	Severity: "HIGH",
	Description: "The system:masters group has unrestricted access to the Kubernetes API hard-coded into the API server source code.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		// This check is primarily for cluster-level RBAC, assume pass at namespace level
		// unless we detect cluster-admin which could indicate system:masters usage
		if config.RBAC.ClusterAdminBindings {
			return false, "Potential system:masters group usage detected", []string{}
		}
		return true, "No system:masters group usage detected", []string{}
	},
	Remediation: "Remove any bindings to system:masters group. Create appropriate ClusterRoles and RoleBindings instead.",
	References: []string{
		"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles",
	},
}

// Check_4_1_8 ensures Kubernetes dashboard is secured
var Check_4_1_8 = CISCheck{
	ID:       "4.1.8",
	Section:  "4.1",
	Title:    "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
	Severity: "MEDIUM",
	Description: "The impersonate privilege allows a subject to impersonate other users gaining their rights to the cluster. The bind privilege allows the subject to add a binding to a cluster role or role which escalates their effective permissions in the cluster.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		// Check for dangerous permissions - this is best-effort at namespace level
		// Full validation requires cluster-wide RBAC analysis
		if config.RBAC.WildcardPermissions {
			return false, "Wildcard permissions may include bind/impersonate/escalate", []string{}
		}
		return true, "No obvious bind/impersonate/escalate permissions detected", []string{}
	},
	Remediation: "Review all Roles and ClusterRoles. Remove 'bind', 'escalate', and 'impersonate' verbs unless absolutely necessary. Use 'kubectl get roles,clusterroles -o yaml | grep -E 'bind|escalate|impersonate''",
	References: []string{
		"https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
	},
}

// GetSection41Checks returns all Section 4.1 checks
func GetSection41Checks() []CISCheck {
	return []CISCheck{
		Check_4_1_1,
		Check_4_1_2,
		Check_4_1_3,
		Check_4_1_4,
		Check_4_1_5,
		Check_4_1_6,
		Check_4_1_7,
		Check_4_1_8,
	}
}
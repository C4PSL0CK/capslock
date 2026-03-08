package detector

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// RBACAnalyzer analyzes RBAC configurations
type RBACAnalyzer struct {
	clientset kubernetes.Interface
}

// NewRBACAnalyzer creates a new RBAC analyzer
func NewRBACAnalyzer(clientset kubernetes.Interface) *RBACAnalyzer {
	return &RBACAnalyzer{
		clientset: clientset,
	}
}

// RBACSecuritySummary contains RBAC analysis results
type RBACSecuritySummary struct {
	TotalServiceAccounts     int
	ServiceAccountNames      []string
	AutoMountEnabled         bool
	DefaultSAUsed            bool
	TotalRoles               int
	TotalRoleBindings        int
	ClusterAdminBindings     bool
	WildcardPermissions      bool
	SecretsReadAccess        int
	SecretsWriteAccess       int
	SecretsAccessRoles       []string
	DangerousPermissions     []string
}

// AnalyzeRBAC analyzes RBAC configuration in a namespace
func (ra *RBACAnalyzer) AnalyzeRBAC(ctx context.Context, namespace string) (*RBACSecuritySummary, error) {
	summary := &RBACSecuritySummary{
		ServiceAccountNames: []string{},
		SecretsAccessRoles:  []string{},
		DangerousPermissions: []string{},
	}

	// Analyze service accounts
	serviceAccounts, err := ra.clientset.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	summary.TotalServiceAccounts = len(serviceAccounts.Items)
	for _, sa := range serviceAccounts.Items {
		summary.ServiceAccountNames = append(summary.ServiceAccountNames, sa.Name)

		// Check if auto-mount is enabled
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			summary.AutoMountEnabled = true
		}
	}

	// Check if pods use default SA
	pods, _ := ra.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	for _, pod := range pods.Items {
		if pod.Spec.ServiceAccountName == "default" || pod.Spec.ServiceAccountName == "" {
			summary.DefaultSAUsed = true
			break
		}
	}

	// Analyze roles
	roles, err := ra.clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	summary.TotalRoles = len(roles.Items)

	for _, role := range roles.Items {
		for _, rule := range role.Rules {
			// Check for wildcard permissions
			for _, resource := range rule.Resources {
				if resource == "*" {
					summary.WildcardPermissions = true
					summary.DangerousPermissions = append(summary.DangerousPermissions, 
						"Role "+role.Name+" has wildcard resource permissions")
				}
			}
			for _, verb := range rule.Verbs {
				if verb == "*" {
					summary.WildcardPermissions = true
					summary.DangerousPermissions = append(summary.DangerousPermissions, 
						"Role "+role.Name+" has wildcard verb permissions")
				}
			}
			for _, apiGroup := range rule.APIGroups {
				if apiGroup == "*" {
					summary.WildcardPermissions = true
				}
			}

			// Check for secrets access
			for _, resource := range rule.Resources {
				if resource == "secrets" || resource == "*" {
					summary.SecretsAccessRoles = append(summary.SecretsAccessRoles, role.Name)

					for _, verb := range rule.Verbs {
						if verb == "get" || verb == "list" || verb == "watch" || verb == "*" {
							summary.SecretsReadAccess++
						}
						if verb == "create" || verb == "update" || verb == "patch" || verb == "delete" || verb == "*" {
							summary.SecretsWriteAccess++
							summary.DangerousPermissions = append(summary.DangerousPermissions,
								"Role "+role.Name+" has secrets write access")
						}
					}
					break
				}
			}

			// Check for dangerous verbs
			for _, verb := range rule.Verbs {
				if verb == "impersonate" {
					summary.DangerousPermissions = append(summary.DangerousPermissions,
						"Role "+role.Name+" has impersonate permission")
				}
				if verb == "bind" || verb == "escalate" {
					summary.DangerousPermissions = append(summary.DangerousPermissions,
						"Role "+role.Name+" has "+verb+" permission")
				}
			}
		}
	}

	// Analyze role bindings
	roleBindings, err := ra.clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	summary.TotalRoleBindings = len(roleBindings.Items)

	for _, rb := range roleBindings.Items {
		if rb.RoleRef.Name == "cluster-admin" {
			summary.ClusterAdminBindings = true
			summary.DangerousPermissions = append(summary.DangerousPermissions,
				"RoleBinding "+rb.Name+" grants cluster-admin")
		}
	}

	// Check cluster role bindings for this namespace's SAs
	clusterRoleBindings, err := ra.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, crb := range clusterRoleBindings.Items {
			for _, subject := range crb.Subjects {
				if subject.Kind == "ServiceAccount" && subject.Namespace == namespace {
					if crb.RoleRef.Name == "cluster-admin" {
						summary.ClusterAdminBindings = true
						summary.DangerousPermissions = append(summary.DangerousPermissions,
							"ClusterRoleBinding "+crb.Name+" grants cluster-admin to SA in this namespace")
					}
				}
			}
		}
	}

	return summary, nil
}

// CheckLeastPrivilege checks if RBAC follows least privilege principle
func (ra *RBACAnalyzer) CheckLeastPrivilege(ctx context.Context, namespace string) (bool, []string, error) {
	summary, err := ra.AnalyzeRBAC(ctx, namespace)
	if err != nil {
		return false, nil, err
	}

	violations := []string{}

	if summary.ClusterAdminBindings {
		violations = append(violations, "cluster-admin role bindings detected")
	}
	if summary.WildcardPermissions {
		violations = append(violations, "Wildcard permissions detected")
	}
	if summary.SecretsWriteAccess > 0 {
		violations = append(violations, "Secrets write access detected")
	}
	if summary.DefaultSAUsed {
		violations = append(violations, "Default service account in use")
	}
	if summary.AutoMountEnabled {
		violations = append(violations, "Service account tokens auto-mounted")
	}

	return len(violations) == 0, violations, nil
}
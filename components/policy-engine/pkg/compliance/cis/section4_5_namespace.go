package cis

import (
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// Section 4.5: Namespace Configuration (3 checks)

// Check_4_5_1 ensures default namespace is not used
var Check_4_5_1 = CISCheck{
	ID:       "4.5.1",
	Section:  "4.5",
	Title:    "Ensure that the default namespace is not used for workload deployments",
	Severity: "LOW",
	Description: "Resources in a Kubernetes cluster should be segregated by namespace, to allow for security controls to be applied at that level and to make it easier to manage resources.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.Name == "default" && config.PodSecurity.TotalPods > 0 {
			return false, "Workloads are running in the default namespace", []string{"default"}
		}
		return true, "Default namespace not used for workloads", []string{}
	},
	Remediation: "Create dedicated namespaces for applications. Move workloads out of default namespace. Use: kubectl create namespace <app-namespace> && kubectl config set-context --current --namespace=<app-namespace>",
	References: []string{
		"https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/",
	},
}

// Check_4_5_2 ensures namespace resource quotas are defined
var Check_4_5_2 = CISCheck{
	ID:       "4.5.2",
	Section:  "4.5",
	Title:    "Ensure that namespace ResourceQuotas are in place",
	Severity: "LOW",
	Description: "Resource quotas must be used to limit the consumption of resources in a namespace. This is important to prevent denial of service attacks.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		// Skip check for system namespaces
		systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease", "default"}
		for _, ns := range systemNamespaces {
			if config.Name == ns {
				return true, "System namespace - ResourceQuota optional", []string{}
			}
		}
		
		if !config.Resources.ResourceQuotaExists {
			return false, "No ResourceQuota defined in namespace", []string{}
		}
		return true, "ResourceQuota is defined", []string{}
	},
	Remediation: `Create ResourceQuota for the namespace:
apiVersion: v1
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
	References: []string{
		"https://kubernetes.io/docs/concepts/policy/resource-quotas/",
	},
}

// Check_4_5_3 ensures namespace LimitRanges are defined
var Check_4_5_3 = CISCheck{
	ID:       "4.5.3",
	Section:  "4.5",
	Title:    "Ensure that namespace LimitRanges are in place",
	Severity: "LOW",
	Description: "LimitRanges enforce minimum and maximum compute resources usage per Pod or Container in a namespace. This is important to prevent resource exhaustion.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		// Skip check for system namespaces
		systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease", "default"}
		for _, ns := range systemNamespaces {
			if config.Name == ns {
				return true, "System namespace - LimitRange optional", []string{}
			}
		}
		
		if !config.Resources.LimitRangeExists {
			return false, "No LimitRange defined in namespace", []string{}
		}
		return true, "LimitRange is defined", []string{}
	},
	Remediation: `Create LimitRange for the namespace:
apiVersion: v1
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
    type: Container`,
	References: []string{
		"https://kubernetes.io/docs/concepts/policy/limit-range/",
	},
}

// GetSection45Checks returns all Section 4.5 checks
func GetSection45Checks() []CISCheck {
	return []CISCheck{
		Check_4_5_1,
		Check_4_5_2,
		Check_4_5_3,
	}
}
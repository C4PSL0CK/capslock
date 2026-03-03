package cis

import (
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// Section 4.3: Network Policies and CNI (3 checks)

// Check_4_3_1 ensures CNI plugin supports network policies
var Check_4_3_1 = CISCheck{
	ID:       "4.3.1",
	Section:  "4.3",
	Title:    "Ensure that the CNI in use supports NetworkPolicies",
	Severity: "HIGH",
	Description: "There are a variety of CNI plugins available for Kubernetes. If the CNI in use does not support NetworkPolicies, it may not be possible to effectively restrict traffic in the cluster.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if !config.Network.CNISupportsPolicy {
			return false, "CNI plugin does not support NetworkPolicies", []string{config.Network.CNIPlugin}
		}
		return true, "CNI supports NetworkPolicies", []string{config.Network.CNIPlugin}
	},
	Remediation: "Use a CNI plugin that supports NetworkPolicies such as Calico, Cilium, Weave Net, or Antrea. Verify with: kubectl get networkpolicies --all-namespaces",
	References: []string{
		"https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/",
		"https://kubernetes.io/docs/tasks/administer-cluster/network-policy-provider/",
	},
}

// Check_4_3_2 ensures all namespaces have network policies defined
var Check_4_3_2 = CISCheck{
	ID:       "4.3.2",
	Section:  "4.3",
	Title:    "Ensure that all Namespaces have NetworkPolicies defined",
	Severity: "MEDIUM",
	Description: "Use network policies to isolate traffic in your cluster network. Network policies should be applied to all namespaces to restrict traffic between pods.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if !config.Network.NetworkPoliciesExist || config.Network.TotalNetworkPolicies == 0 {
			return false, "No NetworkPolicies defined in namespace", []string{}
		}
		return true, "NetworkPolicies are defined", []string{}
	},
	Remediation: "Create NetworkPolicies for the namespace. At minimum, create a default deny policy and then selectively allow traffic. Use: kubectl create -f network-policy.yaml -n <namespace>",
	References: []string{
		"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
	},
}

// Check_4_3_3 ensures default deny network policy exists
var Check_4_3_3 = CISCheck{
	ID:       "4.3.3",
	Section:  "4.3",
	Title:    "Use NetworkPolicies to deny traffic by default",
	Severity: "MEDIUM",
	Description: "By default, if no policies exist in a namespace, then all ingress and egress traffic is allowed. Create a default deny NetworkPolicy to ensure traffic must be explicitly allowed.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if !config.Network.DefaultDenyIngress && !config.Network.DefaultDenyEgress {
			return false, "No default deny network policy exists", []string{}
		}
		if !config.Network.DefaultDenyIngress {
			return false, "Default deny ingress policy missing", []string{}
		}
		if !config.Network.DefaultDenyEgress {
			return false, "Default deny egress policy missing", []string{}
		}
		return true, "Default deny policies exist for ingress and egress", []string{}
	},
	Remediation: `Create default deny NetworkPolicy:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`,
	References: []string{
		"https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-policies",
	},
}

// GetSection43Checks returns all Section 4.3 checks
func GetSection43Checks() []CISCheck {
	return []CISCheck{
		Check_4_3_1,
		Check_4_3_2,
		Check_4_3_3,
	}
}
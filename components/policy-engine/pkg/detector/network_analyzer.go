package detector

import (
	"context"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NetworkAnalyzer analyzes network policies
type NetworkAnalyzer struct {
	clientset kubernetes.Interface
}

// NewNetworkAnalyzer creates a new network analyzer
func NewNetworkAnalyzer(clientset kubernetes.Interface) *NetworkAnalyzer {
	return &NetworkAnalyzer{
		clientset: clientset,
	}
}

// NetworkSecuritySummary contains network policy analysis
type NetworkSecuritySummary struct {
	NetworkPoliciesExist bool
	TotalPolicies        int
	DefaultDenyIngress   bool
	DefaultDenyEgress    bool
	IngressRulesCount    int
	EgressRulesCount     int
	CNIPlugin            string
	CNISupportsPolicy    bool
}

// AnalyzeNetworkPolicies analyzes network policies in a namespace
func (na *NetworkAnalyzer) AnalyzeNetworkPolicies(ctx context.Context, namespace string) (*NetworkSecuritySummary, error) {
	networkPolicies, err := na.clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	summary := &NetworkSecuritySummary{
		TotalPolicies:        len(networkPolicies.Items),
		NetworkPoliciesExist: len(networkPolicies.Items) > 0,
	}

	// Analyze each network policy
	for _, np := range networkPolicies.Items {
		// Check if this is a default deny policy
		if isDefaultDenyNetworkPolicy(&np) {
			for _, policyType := range np.Spec.PolicyTypes {
				if policyType == networkingv1.PolicyTypeIngress {
					summary.DefaultDenyIngress = true
				}
				if policyType == networkingv1.PolicyTypeEgress {
					summary.DefaultDenyEgress = true
				}
			}
		}

		// Count rules
		summary.IngressRulesCount += len(np.Spec.Ingress)
		summary.EgressRulesCount += len(np.Spec.Egress)
	}

	// Detect CNI plugin
	summary.CNIPlugin = na.detectCNI(ctx)
	summary.CNISupportsPolicy = cniSupportsPolicy(summary.CNIPlugin)

	return summary, nil
}

// isDefaultDenyNetworkPolicy checks if a policy is a default deny policy
func isDefaultDenyNetworkPolicy(np *networkingv1.NetworkPolicy) bool {
	// Default deny has empty pod selector and no ingress/egress rules
	if len(np.Spec.PodSelector.MatchLabels) > 0 || len(np.Spec.PodSelector.MatchExpressions) > 0 {
		return false
	}

	// Must have policy types but empty rules
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

// detectCNI attempts to detect the CNI plugin
func (na *NetworkAnalyzer) detectCNI(ctx context.Context) string {
	// Check for Calico
	calicoNodes, _ := na.clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
	})
	if len(calicoNodes.Items) > 0 {
		return "calico"
	}

	// Check for Cilium
	ciliumPods, _ := na.clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=cilium",
	})
	if len(ciliumPods.Items) > 0 {
		return "cilium"
	}

	// Check for Weave
	weavePods, _ := na.clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "name=weave-net",
	})
	if len(weavePods.Items) > 0 {
		return "weave-net"
	}

	// Check for Flannel
	flannelPods, _ := na.clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "app=flannel",
	})
	if len(flannelPods.Items) > 0 {
		return "flannel"
	}

	// Check for Antrea
	antreaPods, _ := na.clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "app=antrea",
	})
	if len(antreaPods.Items) > 0 {
		return "antrea"
	}

	return "unknown"
}

// cniSupportsPolicy checks if CNI supports network policies
func cniSupportsPolicy(cniPlugin string) bool {
	supported := map[string]bool{
		"calico":      true,
		"cilium":      true,
		"weave-net":   true,
		"antrea":      true,
		"kube-router": true,
	}

	return supported[cniPlugin]
}

// CheckNetworkSegmentation checks if proper network segmentation is in place
func (na *NetworkAnalyzer) CheckNetworkSegmentation(ctx context.Context, namespace string) (bool, []string, error) {
	summary, err := na.AnalyzeNetworkPolicies(ctx, namespace)
	if err != nil {
		return false, nil, err
	}

	violations := []string{}

	if !summary.NetworkPoliciesExist {
		violations = append(violations, "No network policies defined")
	}
	if !summary.DefaultDenyIngress {
		violations = append(violations, "No default deny ingress policy")
	}
	if !summary.DefaultDenyEgress {
		violations = append(violations, "No default deny egress policy")
	}
	if !summary.CNISupportsPolicy {
		violations = append(violations, "CNI plugin does not support network policies")
	}

	return len(violations) == 0, violations, nil
}
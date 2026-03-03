package detector

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PodAnalyzer analyzes pod security contexts
type PodAnalyzer struct {
	clientset *kubernetes.Clientset
}

// NewPodAnalyzer creates a new pod analyzer
func NewPodAnalyzer(clientset *kubernetes.Clientset) *PodAnalyzer {
	return &PodAnalyzer{
		clientset: clientset,
	}
}

// PodSecuritySummary contains aggregated pod security analysis
type PodSecuritySummary struct {
	TotalPods              int
	PrivilegedPods         int
	HostNetworkPods        int
	HostPIDPods            int
	HostIPCPods            int
	HostPathVolumePods     int
	PodsRunningAsRoot      int
	PodsWithoutLimits      int
	PodsWithCapabilities   int
	PodsWithHostPorts      int
	AllowedCapabilities    []string
	DroppedCapabilities    []string
	CommonSeccompProfile   string
	CommonAppArmorProfile  string
	RequireDropAll         bool
}

// AnalyzePodSecurity analyzes all pods in a namespace for security settings
func (pa *PodAnalyzer) AnalyzePodSecurity(ctx context.Context, namespace string) (*PodSecuritySummary, error) {
	pods, err := pa.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	summary := &PodSecuritySummary{
		TotalPods:           len(pods.Items),
		AllowedCapabilities: []string{},
		DroppedCapabilities: []string{},
	}

	capabilityMap := make(map[string]bool)
	droppedCapMap := make(map[string]bool)
	seccompProfiles := make(map[string]int)
	apparmorProfiles := make(map[string]int)

	for _, pod := range pods.Items {
		// Analyze pod-level security context
		if pod.Spec.SecurityContext != nil {
			// Check seccomp profile
			if pod.Spec.SecurityContext.SeccompProfile != nil {
				profileType := string(pod.Spec.SecurityContext.SeccompProfile.Type)
				seccompProfiles[profileType]++
			}

			// Check RunAsNonRoot at pod level
			if pod.Spec.SecurityContext.RunAsNonRoot == nil || !*pod.Spec.SecurityContext.RunAsNonRoot {
				summary.PodsRunningAsRoot++
			}
		} else {
			// No security context means running as root
			summary.PodsRunningAsRoot++
		}

		// Check host namespaces
		if pod.Spec.HostNetwork {
			summary.HostNetworkPods++
		}
		if pod.Spec.HostPID {
			summary.HostPIDPods++
		}
		if pod.Spec.HostIPC {
			summary.HostIPCPods++
		}

		// Check host path volumes
		hasHostPath := false
		for _, volume := range pod.Spec.Volumes {
			if volume.HostPath != nil {
				hasHostPath = true
				break
			}
		}
		if hasHostPath {
			summary.HostPathVolumePods++
		}

		// Analyze containers
		podHasLimits := false
		podHasCapabilities := false
		podHasHostPorts := false

		for _, container := range pod.Spec.Containers {
			// Check privileged
			if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				summary.PrivilegedPods++
				break // Count pod only once
			}

			// Check capabilities
			if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
				for _, cap := range container.SecurityContext.Capabilities.Add {
					capStr := string(cap)
					capabilityMap[capStr] = true
					podHasCapabilities = true
				}
				for _, cap := range container.SecurityContext.Capabilities.Drop {
					capStr := string(cap)
					droppedCapMap[capStr] = true
					if capStr == "ALL" {
						summary.RequireDropAll = true
					}
				}
			}

			// Check resource limits
			if !container.Resources.Limits.Cpu().IsZero() || !container.Resources.Limits.Memory().IsZero() {
				podHasLimits = true
			}

			// Check host ports
			for _, port := range container.Ports {
				if port.HostPort != 0 {
					podHasHostPorts = true
					break
				}
			}

			// Check AppArmor (from annotations)
			if profile, ok := pod.Annotations["container.apparmor.security.beta.kubernetes.io/"+container.Name]; ok {
				apparmorProfiles[profile]++
			}
		}

		if !podHasLimits {
			summary.PodsWithoutLimits++
		}
		if podHasCapabilities {
			summary.PodsWithCapabilities++
		}
		if podHasHostPorts {
			summary.PodsWithHostPorts++
		}
	}

	// Convert capability maps to slices
	for cap := range capabilityMap {
		summary.AllowedCapabilities = append(summary.AllowedCapabilities, cap)
	}
	for cap := range droppedCapMap {
		summary.DroppedCapabilities = append(summary.DroppedCapabilities, cap)
	}

	// Determine most common seccomp profile
	maxCount := 0
	for profile, count := range seccompProfiles {
		if count > maxCount {
			maxCount = count
			summary.CommonSeccompProfile = profile
		}
	}

	// Determine most common AppArmor profile
	maxCount = 0
	for profile, count := range apparmorProfiles {
		if count > maxCount {
			maxCount = count
			summary.CommonAppArmorProfile = profile
		}
	}

	return summary, nil
}

// CheckPodSecurityStandard checks if pods meet a specific Pod Security Standard
func (pa *PodAnalyzer) CheckPodSecurityStandard(ctx context.Context, namespace string, standard string) (bool, []string, error) {
	summary, err := pa.AnalyzePodSecurity(ctx, namespace)
	if err != nil {
		return false, nil, err
	}

	violations := []string{}

	switch standard {
	case "restricted":
		// Restricted standard - most strict
		if summary.PrivilegedPods > 0 {
			violations = append(violations, "Privileged containers not allowed")
		}
		if summary.HostNetworkPods > 0 {
			violations = append(violations, "Host network not allowed")
		}
		if summary.HostPIDPods > 0 {
			violations = append(violations, "Host PID not allowed")
		}
		if summary.HostIPCPods > 0 {
			violations = append(violations, "Host IPC not allowed")
		}
		if summary.HostPathVolumePods > 0 {
			violations = append(violations, "Host path volumes not allowed")
		}
		if summary.PodsRunningAsRoot > 0 {
			violations = append(violations, "Running as root not allowed")
		}
		if !summary.RequireDropAll {
			violations = append(violations, "Must drop ALL capabilities")
		}
		if summary.PodsWithHostPorts > 0 {
			violations = append(violations, "Host ports not allowed")
		}

	case "baseline":
		// Baseline standard - moderately strict
		if summary.PrivilegedPods > 0 {
			violations = append(violations, "Privileged containers not allowed")
		}
		if summary.HostNetworkPods > 0 {
			violations = append(violations, "Host network not allowed")
		}
		if summary.HostPIDPods > 0 {
			violations = append(violations, "Host PID not allowed")
		}
		if summary.HostIPCPods > 0 {
			violations = append(violations, "Host IPC not allowed")
		}
		if summary.HostPathVolumePods > 0 {
			violations = append(violations, "Host path volumes not allowed")
		}

	case "privileged":
		// Privileged standard - no restrictions
		// Always passes
	}

	return len(violations) == 0, violations, nil
}
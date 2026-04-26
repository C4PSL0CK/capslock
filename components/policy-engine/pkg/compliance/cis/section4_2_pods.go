package cis

import (
	"fmt"
	"strings"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// Section 4.2: Pod Security Standards (12 checks)

// Check_4_2_1 ensures privileged containers are not admitted
var Check_4_2_1 = CISCheck{
	ID:       "4.2.1",
	Section:  "4.2",
	Title:    "Minimize the admission of privileged containers",
	Severity: "CRITICAL",
	Description: "Privileged containers have access to all Linux Kernel capabilities and devices. A container running with full privileges can do almost everything that the host can do.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.PodSecurity.AllowPrivileged || config.PodSecurity.PrivilegedPods > 0 {
			affected := []string{}
			if config.PodSecurity.PrivilegedPods > 0 {
				affected = append(affected, fmt.Sprintf("%d privileged pods detected", config.PodSecurity.PrivilegedPods))
			}
			return false, "Privileged containers are allowed or detected", affected
		}
		if config.PodSecurity.Standard != "restricted" && config.PodSecurity.Standard != "baseline" {
			return false, "Pod Security Standard not set to baseline or restricted", []string{}
		}
		return true, "Privileged containers are blocked", []string{}
	},
	Remediation: "Set Pod Security Standard to 'restricted' or 'baseline'. Add namespace label: 'pod-security.kubernetes.io/enforce: restricted'. Use PodSecurityPolicy or admission controller to block privileged containers.",
	References: []string{
		"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
		"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
	},
}

// Check_4_2_2 ensures host path mounts are not allowed
var Check_4_2_2 = CISCheck{
	ID:       "4.2.2",
	Section:  "4.2",
	Title:    "Minimize the admission of containers wishing to share the host process ID namespace",
	Severity: "HIGH",
	Description: "A container running in the host's PID namespace can inspect processes running outside the container and can be used to escalate privileges outside of the container.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.PodSecurity.AllowHostPath {
			return false, "Host path mounts are allowed", []string{}
		}
		return true, "Host path mounts are not allowed", []string{}
	},
	Remediation: "Configure Pod Security Standard to 'restricted'. Add admission controller policy to deny hostPath volumes. Use PersistentVolumes instead of hostPath where possible.",
	References: []string{
		"https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems",
	},
}

// Check_4_2_3 ensures containers do not run with hostNetwork
var Check_4_2_3 = CISCheck{
	ID:       "4.2.3",
	Section:  "4.2",
	Title:    "Minimize the admission of containers wishing to share the host network namespace",
	Severity: "HIGH",
	Description: "A container running in the host's network namespace could access the host's loopback device, listen to traffic on localhost, and bypass network policy.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.PodSecurity.AllowHostNetwork || config.PodSecurity.HostNetworkPods > 0 {
			affected := []string{}
			if config.PodSecurity.HostNetworkPods > 0 {
				affected = append(affected, fmt.Sprintf("%d pods with hostNetwork detected", config.PodSecurity.HostNetworkPods))
			}
			return false, "Containers with hostNetwork are allowed or detected", affected
		}
		return true, "hostNetwork is blocked", []string{}
	},
	Remediation: "Set Pod Security Standard to 'baseline' or 'restricted'. Configure admission controller to deny hostNetwork. Set spec.hostNetwork: false in pod specifications.",
	References: []string{
		"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	},
}

// Check_4_2_4 ensures containers do not use hostPID
var Check_4_2_4 = CISCheck{
	ID:       "4.2.4",
	Section:  "4.2",
	Title:    "Minimize the admission of containers wishing to share the host process ID namespace",
	Severity: "HIGH",
	Description: "A container running in the host's PID namespace can inspect processes running outside the container and can be used to escalate privileges.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.PodSecurity.AllowHostPID {
			return false, "Containers with hostPID are allowed", []string{}
		}
		return true, "hostPID is blocked", []string{}
	},
	Remediation: "Set Pod Security Standard to 'baseline' or 'restricted'. Configure admission controller to deny hostPID. Set spec.hostPID: false in pod specifications.",
	References: []string{
		"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	},
}

// Check_4_2_5 ensures containers do not use hostIPC
var Check_4_2_5 = CISCheck{
	ID:       "4.2.5",
	Section:  "4.2",
	Title:    "Minimize the admission of containers wishing to share the host IPC namespace",
	Severity: "HIGH",
	Description: "A container running in the host's IPC namespace can access IPC resources on the host and potentially escalate privileges.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.PodSecurity.AllowHostIPC {
			return false, "Containers with hostIPC are allowed", []string{}
		}
		return true, "hostIPC is blocked", []string{}
	},
	Remediation: "Set Pod Security Standard to 'baseline' or 'restricted'. Configure admission controller to deny hostIPC. Set spec.hostIPC: false in pod specifications.",
	References: []string{
		"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	},
}

// Check_4_2_6 ensures AppArmor profiles are applied
var Check_4_2_6 = CISCheck{
	ID:       "4.2.6",
	Section:  "4.2",
	Title:    "Minimize the admission of containers with allowPrivilegeEscalation",
	Severity: "MEDIUM",
	Description: "A container running with the allowPrivilegeEscalation flag set to true may have processes that can gain more privileges than their parent.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.PodSecurity.AllowPrivilegeEscalation {
			return false, "Privilege escalation is allowed", []string{}
		}
		// Check AppArmor profile as secondary validation
		if config.PodSecurity.AppArmorProfile != "" && 
		   config.PodSecurity.AppArmorProfile != "runtime/default" && 
		   !strings.HasPrefix(config.PodSecurity.AppArmorProfile, "localhost/") {
			return false, "AppArmor profile not properly configured", []string{config.PodSecurity.AppArmorProfile}
		}
		return true, "Privilege escalation is blocked and AppArmor configured", []string{}
	},
	Remediation: "Set spec.securityContext.allowPrivilegeEscalation: false. Apply AppArmor profiles with annotation 'container.apparmor.security.beta.kubernetes.io/<container>: runtime/default'",
	References: []string{
		"https://kubernetes.io/docs/tutorials/security/apparmor/",
	},
}

// Check_4_2_7 ensures seccomp profiles are applied
var Check_4_2_7 = CISCheck{
	ID:       "4.2.7",
	Section:  "4.2",
	Title:    "Minimize the admission of root containers",
	Severity: "MEDIUM",
	Description: "Containers should run as a non-root user to minimize the impact of a container security vulnerability.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		// Check seccomp profile
		if config.PodSecurity.SeccompProfile == "" || 
		   config.PodSecurity.SeccompProfile == "Unconfined" {
			return false, "Seccomp profile not set or set to Unconfined", []string{config.PodSecurity.SeccompProfile}
		}
		if config.PodSecurity.SeccompProfile != "RuntimeDefault" && 
		   !strings.HasPrefix(config.PodSecurity.SeccompProfile, "Localhost/") {
			return false, "Seccomp profile not set to RuntimeDefault or Localhost", []string{config.PodSecurity.SeccompProfile}
		}
		return true, "Seccomp profile properly configured", []string{}
	},
	Remediation: "Set spec.securityContext.seccompProfile.type: RuntimeDefault or Localhost. For Pod Security Standard 'restricted', this is enforced automatically.",
	References: []string{
		"https://kubernetes.io/docs/tutorials/security/seccomp/",
	},
}

// Check_4_2_8 ensures containers do not run as root
var Check_4_2_8 = CISCheck{
	ID:       "4.2.8",
	Section:  "4.2",
	Title:    "Minimize the admission of containers with the NET_RAW capability",
	Severity: "MEDIUM",
	Description: "Containers run with a default set of capabilities. The NET_RAW capability can be used to create raw sockets which could be used for network packet spoofing.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if !config.PodSecurity.RunAsNonRoot || config.PodSecurity.PodsRunningAsRoot > 0 {
			affected := []string{}
			if config.PodSecurity.PodsRunningAsRoot > 0 {
				affected = append(affected, fmt.Sprintf("%d pods running as root detected", config.PodSecurity.PodsRunningAsRoot))
			}
			return false, "Containers running as root detected or runAsNonRoot not enforced", affected
		}
		return true, "All containers run as non-root", []string{}
	},
	Remediation: "Set spec.securityContext.runAsNonRoot: true in pod specifications. Set Pod Security Standard to 'restricted'. Ensure container images have USER directive set to non-root.",
	References: []string{
		"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
	},
}

// Check_4_2_9 ensures containers have read-only root filesystem
var Check_4_2_9 = CISCheck{
	ID:       "4.2.9",
	Section:  "4.2",
	Title:    "Minimize the admission of containers with added capabilities",
	Severity: "MEDIUM",
	Description: "Containers should drop all capabilities and only add back those that are required for proper operation.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if !config.PodSecurity.ReadOnlyRootFilesystem {
			return false, "Read-only root filesystem not enforced", []string{}
		}
		return true, "Read-only root filesystem enforced", []string{}
	},
	Remediation: "Set spec.containers[*].securityContext.readOnlyRootFilesystem: true. Use emptyDir or persistent volumes for writable directories.",
	References: []string{
		"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
	},
}

// Check_4_2_10 ensures CPU and memory limits are set
var Check_4_2_10 = CISCheck{
	ID:       "4.2.10",
	Section:  "4.2",
	Title:    "Minimize the admission of containers with capabilities assigned",
	Severity: "MEDIUM",
	Description: "Resource limits protect against denial of service attacks by preventing containers from consuming excessive resources.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if !config.PodSecurity.RequireResourceLimits || config.PodSecurity.PodsWithoutLimits > 0 {
			affected := []string{}
			if config.PodSecurity.PodsWithoutLimits > 0 {
				affected = append(affected, fmt.Sprintf("%d pods without resource limits detected", config.PodSecurity.PodsWithoutLimits))
			}
			return false, "CPU and memory limits not enforced on all containers", affected
		}
		return true, "All containers have resource limits", []string{}
	},
	Remediation: "Set spec.containers[*].resources.limits.cpu and spec.containers[*].resources.limits.memory. Create LimitRange to enforce defaults.",
	References: []string{
		"https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
	},
}

// Check_4_2_11 ensures capabilities are dropped
var Check_4_2_11 = CISCheck{
	ID:       "4.2.11",
	Section:  "4.2",
	Title:    "Minimize the admission of Windows HostProcess containers",
	Severity: "HIGH",
	Description: "Containers should drop all capabilities and only add back those required. The drop ALL pattern is the most secure.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if !config.PodSecurity.RequireDropAll {
			return false, "DROP ALL capabilities not enforced", []string{}
		}
		// Check if ALL is in dropped capabilities
		hasDropAll := false
		for _, cap := range config.PodSecurity.DroppedCapabilities {
			if cap == "ALL" {
				hasDropAll = true
				break
			}
		}
		if !hasDropAll {
			return false, "ALL capabilities not dropped", config.PodSecurity.DroppedCapabilities
		}
		return true, "ALL capabilities are dropped", []string{}
	},
	Remediation: "Set spec.containers[*].securityContext.capabilities.drop: ['ALL']. Only add back specific capabilities that are absolutely required.",
	References: []string{
		"https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container",
	},
}

// Check_4_2_12 ensures dangerous capabilities are not added
var Check_4_2_12 = CISCheck{
	ID:       "4.2.12",
	Section:  "4.2",
	Title:    "Minimize the admission of HostPath volumes",
	Severity: "HIGH",
	Description: "Certain capabilities like NET_ADMIN, SYS_ADMIN, SYS_MODULE should not be added to containers as they provide elevated privileges.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		dangerousCaps := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE", "PERFMON"}
		
		foundDangerous := []string{}
		for _, allowedCap := range config.PodSecurity.AllowedCapabilities {
			for _, dangerousCap := range dangerousCaps {
				if allowedCap == dangerousCap {
					foundDangerous = append(foundDangerous, allowedCap)
				}
			}
		}
		
		if len(foundDangerous) > 0 {
			return false, "Dangerous capabilities detected", foundDangerous
		}
		return true, "No dangerous capabilities added", []string{}
	},
	Remediation: "Remove dangerous capabilities from spec.containers[*].securityContext.capabilities.add. Never add SYS_ADMIN, NET_ADMIN, or SYS_MODULE.",
	References: []string{
		"https://man7.org/linux/man-pages/man7/capabilities.7.html",
	},
}

// GetSection42Checks returns all Section 4.2 checks
func GetSection42Checks() []CISCheck {
	return []CISCheck{
		Check_4_2_1,
		Check_4_2_2,
		Check_4_2_3,
		Check_4_2_4,
		Check_4_2_5,
		Check_4_2_6,
		Check_4_2_7,
		Check_4_2_8,
		Check_4_2_9,
		Check_4_2_10,
		Check_4_2_11,
		Check_4_2_12,
	}
}
package pcidss

// ControlMapping maps PCI-DSS requirements to Kubernetes controls and CIS checks
type ControlMapping struct {
	RequirementID      string
	KubernetesControls []string
	CISChecks          []string
	Description        string
}

// GetAllControlMappings returns mappings of all PCI-DSS requirements to K8s/CIS
func GetAllControlMappings() map[string]ControlMapping {
	return map[string]ControlMapping{
		"1.2.1": {
			RequirementID: "1.2.1",
			KubernetesControls: []string{
				"NetworkPolicy resources",
				"CNI with network policy support (Calico, Cilium, Weave)",
				"Default deny ingress/egress policies",
			},
			CISChecks: []string{"4.3.1", "4.3.2", "4.3.3"},
			Description: "Network segmentation via NetworkPolicies to control traffic between pods and namespaces",
		},
		"2.2.2": {
			RequirementID: "2.2.2",
			KubernetesControls: []string{
				"Disable default ServiceAccount",
				"Create dedicated ServiceAccounts per application",
				"Set automountServiceAccountToken: false",
			},
			CISChecks: []string{"4.1.5", "4.1.6"},
			Description: "Avoid default accounts by using application-specific ServiceAccounts",
		},
		"2.2.4": {
			RequirementID: "2.2.4",
			KubernetesControls: []string{
				"Pod Security Standards (PSS) - restricted level",
				"SecurityContext configuration",
				"Disable privileged containers",
				"Block hostNetwork, hostPID, hostIPC",
				"Drop ALL capabilities",
			},
			CISChecks: []string{"4.2.1", "4.2.3", "4.2.4", "4.2.5", "4.2.11", "4.2.12"},
			Description: "Secure system parameters through Pod Security Standards and SecurityContext restrictions",
		},
		"3.4.1": {
			RequirementID: "3.4.1",
			KubernetesControls: []string{
				"EncryptionConfiguration for etcd",
				"Secrets encryption at rest",
				"KMS provider integration",
			},
			CISChecks: []string{},
			Description: "Encrypt sensitive data at rest using Kubernetes EncryptionConfiguration",
		},
		"3.5.1": {
			RequirementID: "3.5.1",
			KubernetesControls: []string{
				"External Secrets Operator (ESO)",
				"HashiCorp Vault integration",
				"Cloud KMS (AWS KMS, Azure Key Vault, GCP KMS)",
			},
			CISChecks: []string{"4.4.2"},
			Description: "Centralized cryptographic key management using external secrets managers",
		},
		"3.6.1": {
			RequirementID: "3.6.1",
			KubernetesControls: []string{
				"Mount secrets as volumes (not environment variables)",
				"ReadOnly volume mounts",
				"Proper file permissions on secret volumes",
			},
			CISChecks: []string{"4.4.1"},
			Description: "Secure secret storage by mounting as files with restricted permissions",
		},
		"4.2.1": {
			RequirementID: "4.2.1",
			KubernetesControls: []string{
				"Service mesh with mTLS (Istio, Linkerd)",
				"Ingress TLS termination",
				"cert-manager for certificate automation",
			},
			CISChecks: []string{},
			Description: "Encrypt data in transit using TLS and mutual TLS",
		},
		"5.3.2": {
			RequirementID: "5.3.2",
			KubernetesControls: []string{
				"ICAP-based malware scanning",
				"Admission webhooks for image validation",
				"Container image scanning (Trivy, Clair, Anchore)",
			},
			CISChecks: []string{},
			Description: "Anti-malware protection through image scanning before deployment",
		},
		"6.3.2": {
			RequirementID: "6.3.2",
			KubernetesControls: []string{
				"SBOM generation (Software Bill of Materials)",
				"Image scanning with vulnerability databases",
				"Container registry with security scanning",
			},
			CISChecks: []string{},
			Description: "Maintain software inventory through container image scanning and SBOM",
		},
		"7.1.1": {
			RequirementID: "7.1.1",
			KubernetesControls: []string{
				"RBAC (Role-Based Access Control)",
				"Least privilege ServiceAccounts",
				"No cluster-admin usage except where required",
				"No wildcard permissions",
			},
			CISChecks: []string{"4.1.1", "4.1.2", "4.1.3", "4.1.4"},
			Description: "Access control through RBAC with least privilege principle",
		},
		"7.2.2": {
			RequirementID: "7.2.2",
			KubernetesControls: []string{
				"Role-based ServiceAccounts per application",
				"Namespace isolation",
				"Separate ServiceAccounts for different job functions",
			},
			CISChecks: []string{"4.1.5"},
			Description: "Job function-based access through dedicated ServiceAccounts",
		},
		"8.2.1": {
			RequirementID: "8.2.1",
			KubernetesControls: []string{
				"ServiceAccount token management",
				"Short-lived projected tokens",
				"Disable auto-mount of SA tokens",
			},
			CISChecks: []string{"4.1.6", "4.1.7"},
			Description: "Strong authentication through controlled ServiceAccount token usage",
		},
		"8.6.1": {
			RequirementID: "8.6.1",
			KubernetesControls: []string{
				"Dedicated ServiceAccounts per application",
				"ServiceAccount naming conventions",
				"Documentation of SA purposes",
			},
			CISChecks: []string{"4.1.5"},
			Description: "Managed application accounts through dedicated ServiceAccounts",
		},
		"10.2.1": {
			RequirementID: "10.2.1",
			KubernetesControls: []string{
				"Kubernetes audit logging enabled",
				"Comprehensive audit policy",
				"Audit log forwarding to SIEM",
			},
			CISChecks: []string{},
			Description: "Audit logging for anomaly detection and security monitoring",
		},
		"10.3.4": {
			RequirementID: "10.3.4",
			KubernetesControls: []string{
				"Audit log retention (90+ days)",
				"Centralized logging infrastructure",
				"Immutable log storage",
			},
			CISChecks: []string{},
			Description: "Protected audit logs with proper retention",
		},
		"11.4.2": {
			RequirementID: "11.4.2",
			KubernetesControls: []string{
				"NetworkPolicies for traffic filtering",
				"Service mesh for traffic inspection",
				"Runtime security monitoring (Falco)",
			},
			CISChecks: []string{"4.3.2", "4.3.3"},
			Description: "Intrusion detection through network policies and monitoring",
		},
	}
}

// GetMappingForRequirement returns the control mapping for a specific requirement
func GetMappingForRequirement(requirementID string) (ControlMapping, bool) {
	mappings := GetAllControlMappings()
	mapping, exists := mappings[requirementID]
	return mapping, exists
}

// GetCISChecksForRequirement returns CIS checks that map to a PCI-DSS requirement
func GetCISChecksForRequirement(requirementID string) []string {
	mapping, exists := GetMappingForRequirement(requirementID)
	if !exists {
		return []string{}
	}
	return mapping.CISChecks
}

// GetRequirementsForCISCheck returns PCI-DSS requirements that map to a CIS check
func GetRequirementsForCISCheck(cisCheckID string) []string {
	var requirements []string
	mappings := GetAllControlMappings()
	
	for reqID, mapping := range mappings {
		for _, cisCheck := range mapping.CISChecks {
			if cisCheck == cisCheckID {
				requirements = append(requirements, reqID)
				break
			}
		}
	}
	
	return requirements
}
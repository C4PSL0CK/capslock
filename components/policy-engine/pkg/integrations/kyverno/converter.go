package kyverno

import (
	"fmt"
	"strings"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// KyvernoConverter converts EAPE policies to Kyverno ClusterPolicies
type KyvernoConverter struct {
	// Configuration options
}

// NewKyvernoConverter creates a new Kyverno converter
func NewKyvernoConverter() *KyvernoConverter {
	return &KyvernoConverter{}
}

// ConvertPolicy converts an EAPE policy to Kyverno ClusterPolicy
func (kc *KyvernoConverter) ConvertPolicy(p *policy.PolicyTemplate) (*ConversionResult, error) {
	if p == nil {
		return nil, fmt.Errorf("policy is nil")
	}

	result := &ConversionResult{
		Policy: p,
		Errors: []error{},
	}

	// Generate ClusterPolicy
	clusterPolicy, err := kc.generateClusterPolicy(p)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return result, err
	}
	result.ClusterPolicy = clusterPolicy

	return result, nil
}

// generateClusterPolicy creates a Kyverno ClusterPolicy from a policy
func (kc *KyvernoConverter) generateClusterPolicy(p *policy.PolicyTemplate) (*ClusterPolicy, error) {
	policyName := kc.generatePolicyName(p)
	
	// Determine validation failure action based on scanning mode
	failureAction := kc.getFailureAction(p.IcapConfig.ScanningMode)

	// Generate rules
	rules := kc.generateRules(p)

	clusterPolicy := &ClusterPolicy{
		APIVersion: "kyverno.io/v1",
		Kind:       "ClusterPolicy",
		Metadata: ClusterPolicyMetadata{
			Name: policyName,
			Annotations: map[string]string{
				"policies.kyverno.io/title":       p.Name,
				"policies.kyverno.io/description": p.Description,
				"eape.policy":                     p.Name,
				"eape.version":                    p.Version,
				"eape.environment":                string(p.Environment),
			},
		},
		Spec: ClusterPolicySpec{
			ValidationFailureAction: failureAction,
			Background:              true,
			Rules:                   rules,
		},
	}

	return clusterPolicy, nil
}

// generateRules creates Kyverno rules based on policy settings
func (kc *KyvernoConverter) generateRules(p *policy.PolicyTemplate) []Rule {
	rules := []Rule{}

	// Rule 1: Security context validation
	securityRule := kc.generateSecurityContextRule(p)
	rules = append(rules, securityRule)

	// Rule 2: Resource limits (if max file size specified)
	if p.IcapConfig.MaxFileSize != "" {
		resourceRule := kc.generateResourceLimitRule(p)
		rules = append(rules, resourceRule)
	}

	// Add compliance-specific rules
	for _, standard := range p.ComplianceConfig.Standards {
		switch standard {
		case "pci-dss":
			rules = append(rules, kc.generatePCIDSSRule(p))
		case "soc2":
			rules = append(rules, kc.generateSOC2Rule(p))
		case "iso27001":
			rules = append(rules, kc.generateISO27001Rule(p))
		}
	}

	return rules
}

// generateSecurityContextRule creates a security context validation rule
func (kc *KyvernoConverter) generateSecurityContextRule(p *policy.PolicyTemplate) Rule {
	message := fmt.Sprintf("Container must run as non-root user (%s mode)", p.IcapConfig.ScanningMode)

	return Rule{
		Name: "require-run-as-nonroot",
		Match: MatchResources{
			Any: []ResourceFilter{
				{
					Resources: ResourceDescription{
						Kinds: []string{"Pod"},
						Selector: &LabelSelector{
							MatchLabels: map[string]string{
								"environment": string(p.Environment),
							},
						},
					},
				},
			},
		},
		Validate: &Validation{
			Message: message,
			Pattern: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"securityContext": map[string]interface{}{
								"runAsNonRoot": true,
							},
						},
					},
				},
			},
		},
	}
}

// generateResourceLimitRule creates a resource limit rule
func (kc *KyvernoConverter) generateResourceLimitRule(p *policy.PolicyTemplate) Rule {
	return Rule{
		Name: "enforce-resource-limits",
		Match: MatchResources{
			Any: []ResourceFilter{
				{
					Resources: ResourceDescription{
						Kinds: []string{"Pod"},
						Selector: &LabelSelector{
							MatchLabels: map[string]string{
								"environment": string(p.Environment),
							},
						},
					},
				},
			},
		},
		Validate: &Validation{
			Message: fmt.Sprintf("Containers must have resource limits (max file size: %s)", p.IcapConfig.MaxFileSize),
			Pattern: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"resources": map[string]interface{}{
								"limits": map[string]interface{}{
									"ephemeral-storage": "?(<=100Mi)",
								},
							},
						},
					},
				},
			},
		},
	}
}

// generatePCIDSSRule creates a PCI-DSS compliance rule
func (kc *KyvernoConverter) generatePCIDSSRule(p *policy.PolicyTemplate) Rule {
	return Rule{
		Name: "pci-dss-readonly-root-filesystem",
		Match: MatchResources{
			Any: []ResourceFilter{
				{
					Resources: ResourceDescription{
						Kinds: []string{"Pod"},
					},
				},
			},
		},
		Validate: &Validation{
			Message: "Container must have read-only root filesystem (PCI-DSS requirement)",
			Pattern: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"securityContext": map[string]interface{}{
								"readOnlyRootFilesystem": true,
							},
						},
					},
				},
			},
		},
	}
}

// generateSOC2Rule creates a SOC2 compliance rule
func (kc *KyvernoConverter) generateSOC2Rule(p *policy.PolicyTemplate) Rule {
	return Rule{
		Name: "soc2-require-data-classification",
		Match: MatchResources{
			Any: []ResourceFilter{
				{
					Resources: ResourceDescription{
						Kinds: []string{"Pod"},
					},
				},
			},
		},
		Validate: &Validation{
			Message: "Pod must have data-classification label (SOC2 requirement)",
			Pattern: map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]interface{}{
						"data-classification": "?*",
					},
				},
			},
		},
	}
}

// generateISO27001Rule creates an ISO27001 compliance rule
func (kc *KyvernoConverter) generateISO27001Rule(p *policy.PolicyTemplate) Rule {
	return Rule{
		Name: "iso27001-security-context",
		Match: MatchResources{
			Any: []ResourceFilter{
				{
					Resources: ResourceDescription{
						Kinds: []string{"Pod"},
					},
				},
			},
		},
		Validate: &Validation{
			Message: "Container must not run with privilege escalation (ISO27001)",
			Pattern: map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"securityContext": map[string]interface{}{
								"allowPrivilegeEscalation": false,
							},
						},
					},
				},
			},
		},
	}
}

// getFailureAction determines the failure action based on scanning mode
func (kc *KyvernoConverter) getFailureAction(scanningMode string) string {
	switch scanningMode {
	case "block":
		return "Enforce"
	case "warn":
		return "Audit"
	case "log-only":
		return "Audit"
	default:
		return "Audit"
	}
}

// generatePolicyName creates a policy name from EAPE policy
func (kc *KyvernoConverter) generatePolicyName(p *policy.PolicyTemplate) string {
	// Convert "dev-policy" to "eape-dev-policy"
	return "eape-" + strings.ToLower(p.Name)
}
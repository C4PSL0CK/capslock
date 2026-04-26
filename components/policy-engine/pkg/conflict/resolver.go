package conflict

import (
	"fmt"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// ResolutionStrategy selects how conflicts are resolved.
type ResolutionStrategy string

const (
	StrategyPrecedence       ResolutionStrategy = "precedence"
	StrategySecurityFirst    ResolutionStrategy = "security-first"
	StrategyEnvironmentAware ResolutionStrategy = "environment-aware"
	StrategyManual           ResolutionStrategy = "manual"
)

// ConflictType represents the type of conflict
type ConflictType string

const (
	ConflictTypeEnforcement   ConflictType = "enforcement"
	ConflictTypeCompliance    ConflictType = "compliance"
	ConflictTypeRiskLevel     ConflictType = "risk_level"
	ConflictTypeConfiguration ConflictType = "configuration"
)

// PolicyConflict represents a detected conflict between policies
type PolicyConflict struct {
	Type        ConflictType `json:"type"`
	Severity    string       `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Description string       `json:"description"`
	Policy1     string       `json:"policy_1"`
	Policy2     string       `json:"policy_2,omitempty"`
	Remediation string       `json:"remediation"`
}

// Resolver detects and resolves policy conflicts
type Resolver struct {
	resolutionStrategy string // "priority", "compliance-aware", "risk-based"
}

// NewResolver creates a new conflict resolver
func NewResolver() *Resolver {
	return &Resolver{
		resolutionStrategy: "compliance-aware",
	}
}

// DetectConflicts detects conflicts in a policy
func (r *Resolver) DetectConflicts(pol *policy.PolicyTemplate) []PolicyConflict {
	conflicts := []PolicyConflict{}

	// Check enforcement vs risk level conflict
	if pol.Enforcement.Mode == "strict" && pol.RiskLevel == "high" {
		conflicts = append(conflicts, PolicyConflict{
			Type:        ConflictTypeEnforcement,
			Severity:    "MEDIUM",
			Description: "Strict enforcement mode with high risk level may cause service disruptions",
			Policy1:     pol.Name,
			Remediation: "Consider using 'audit' mode first or lowering risk level",
		})
	}

	// Check compliance requirements vs configuration
	if len(pol.ComplianceConfig.Standards) > 0 {
		// Check if Pod Security Standard is set appropriately
		if contains(pol.ComplianceConfig.Standards, "pci-dss") && pol.PodSecurity.Standard != "restricted" {
			conflicts = append(conflicts, PolicyConflict{
				Type:        ConflictTypeCompliance,
				Severity:    "HIGH",
				Description: "PCI-DSS compliance requires 'restricted' Pod Security Standard",
				Policy1:     pol.Name,
				Remediation: "Set pod_security.standard to 'restricted'",
			})
		}

		// Check if network policies are required for compliance
		if contains(pol.ComplianceConfig.Standards, "cis") || contains(pol.ComplianceConfig.Standards, "pci-dss") {
			if !pol.Network.RequireNetworkPolicies {
				conflicts = append(conflicts, PolicyConflict{
					Type:        ConflictTypeCompliance,
					Severity:    "HIGH",
					Description: "CIS and PCI-DSS compliance require network policies",
					Policy1:     pol.Name,
					Remediation: "Set network.require_network_policies to true",
				})
			}
		}
	}

	// Check resource limits configuration
	if !pol.Resources.RequireResourceLimits && pol.TargetEnvironment == "production" {
		conflicts = append(conflicts, PolicyConflict{
			Type:        ConflictTypeConfiguration,
			Severity:    "MEDIUM",
			Description: "Production environment should require resource limits",
			Policy1:     pol.Name,
			Remediation: "Set resources.require_resource_limits to true",
		})
	}

	return conflicts
}

// ResolveConflictBetweenPolicies resolves conflicts between two policies
func (r *Resolver) ResolveConflictBetweenPolicies(policy1, policy2 *policy.PolicyTemplate) (*policy.PolicyTemplate, string, error) {
	switch r.resolutionStrategy {
	case "compliance-aware":
		return r.resolveByCompliance(policy1, policy2)
	case "priority":
		return r.resolveByPriority(policy1, policy2)
	case "risk-based":
		return r.resolveByRisk(policy1, policy2)
	default:
		return nil, "", fmt.Errorf("unknown resolution strategy: %s", r.resolutionStrategy)
	}
}

// resolveByCompliance prioritizes policy with better compliance coverage
func (r *Resolver) resolveByCompliance(policy1, policy2 *policy.PolicyTemplate) (*policy.PolicyTemplate, string, error) {
	score1 := r.calculateComplianceScore(policy1)
	score2 := r.calculateComplianceScore(policy2)

	if score1 > score2 {
		return policy1, fmt.Sprintf("Selected %s: better compliance coverage (%.2f vs %.2f)",
			policy1.Name, score1, score2), nil
	} else if score2 > score1 {
		return policy2, fmt.Sprintf("Selected %s: better compliance coverage (%.2f vs %.2f)",
			policy2.Name, score2, score1), nil
	}

	// If equal compliance scores, fall back to risk-based
	return r.resolveByRisk(policy1, policy2)
}

// resolveByPriority resolves based on explicit priority
func (r *Resolver) resolveByPriority(policy1, policy2 *policy.PolicyTemplate) (*policy.PolicyTemplate, string, error) {
	// Use environment as priority: prod > staging > dev
	priority1 := r.getEnvironmentPriority(policy1.TargetEnvironment)
	priority2 := r.getEnvironmentPriority(policy2.TargetEnvironment)

	if priority1 > priority2 {
		return policy1, fmt.Sprintf("Selected %s: higher priority (%s)",
			policy1.Name, policy1.TargetEnvironment), nil
	}
	return policy2, fmt.Sprintf("Selected %s: higher priority (%s)",
		policy2.Name, policy2.TargetEnvironment), nil
}

// resolveByRisk prioritizes lower risk policies
func (r *Resolver) resolveByRisk(policy1, policy2 *policy.PolicyTemplate) (*policy.PolicyTemplate, string, error) {
	risk1 := r.getRiskValue(policy1.RiskLevel)
	risk2 := r.getRiskValue(policy2.RiskLevel)

	if risk1 < risk2 {
		return policy1, fmt.Sprintf("Selected %s: lower risk (%s vs %s)",
			policy1.Name, policy1.RiskLevel, policy2.RiskLevel), nil
	}
	return policy2, fmt.Sprintf("Selected %s: lower risk (%s vs %s)",
		policy2.Name, policy2.RiskLevel, policy1.RiskLevel), nil
}

// calculateComplianceScore calculates a score based on compliance coverage
func (r *Resolver) calculateComplianceScore(pol *policy.PolicyTemplate) float64 {
	score := 0.0

	// Base score from number of compliance standards
	score += float64(len(pol.ComplianceConfig.Standards)) * 10.0

	// Bonus for critical standards
	if contains(pol.ComplianceConfig.Standards, "pci-dss") {
		score += 20.0
	}
	if contains(pol.ComplianceConfig.Standards, "cis") {
		score += 15.0
	}

	// Bonus for strict configurations
	if pol.PodSecurity.Standard == "restricted" {
		score += 10.0
	}
	if pol.Network.RequireNetworkPolicies {
		score += 5.0
	}
	if pol.Resources.RequireResourceLimits {
		score += 5.0
	}

	return score
}

// getEnvironmentPriority returns priority value for environment
func (r *Resolver) getEnvironmentPriority(env string) int {
	priorities := map[string]int{
		"production":  3,
		"prod":        3,
		"staging":     2,
		"stage":       2,
		"uat":         2,
		"development": 1,
		"dev":         1,
	}

	if priority, ok := priorities[env]; ok {
		return priority
	}
	return 0
}

// getRiskValue returns numeric value for risk level
func (r *Resolver) getRiskValue(risk string) int {
	values := map[string]int{
		"low":    1,
		"medium": 2,
		"high":   3,
	}

	if value, ok := values[risk]; ok {
		return value
	}
	return 2 // Default to medium
}

// SetResolutionStrategy sets the conflict resolution strategy
func (r *Resolver) SetResolutionStrategy(strategy string) {
	r.resolutionStrategy = strategy
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

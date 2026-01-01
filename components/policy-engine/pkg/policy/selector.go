package policy

import (
	"fmt"
	"sort"
)

// PolicyScore represents a scored policy template
type PolicyScore struct {
	Template         *PolicyTemplate
	EnvironmentFit   float64 // 0.0 to 1.0
	ComplianceFit    float64 // 0.0 to 1.0
	RiskAlignment    float64 // 0.0 to 1.0
	TotalScore       float64 // Weighted sum
	Reasoning        string  // Explanation of the score
}

// PolicySelector handles policy selection logic
type PolicySelector struct {
	policyManager *PolicyManager
	
	// Weights for scoring (must sum to 1.0)
	environmentWeight float64
	complianceWeight  float64
	riskWeight        float64
}

// NewPolicySelector creates a new policy selector with default weights
func NewPolicySelector(pm *PolicyManager) *PolicySelector {
	return &PolicySelector{
		policyManager:     pm,
		environmentWeight: 0.4, // 40% weight on environment match
		complianceWeight:  0.3, // 30% weight on compliance fit
		riskWeight:        0.3, // 30% weight on risk alignment
	}
}

// NewPolicySelectorWithWeights creates a selector with custom weights
func NewPolicySelectorWithWeights(pm *PolicyManager, envWeight, compWeight, riskWeight float64) (*PolicySelector, error) {
	// Validate weights sum to 1.0 (with small tolerance for floating point)
	sum := envWeight + compWeight + riskWeight
	if sum < 0.99 || sum > 1.01 {
		return nil, fmt.Errorf("weights must sum to 1.0, got %.2f", sum)
	}
	
	return &PolicySelector{
		policyManager:     pm,
		environmentWeight: envWeight,
		complianceWeight:  compWeight,
		riskWeight:        riskWeight,
	}, nil
}

// SelectPolicy selects the best policy template for the given environment context
func (ps *PolicySelector) SelectPolicy(envCtx *EnvironmentContext) (*PolicyTemplate, *PolicyScore, error) {
	if envCtx == nil {
		return nil, nil, fmt.Errorf("environment context is nil")
	}
	
	// Get candidate templates for this environment type
	candidates := ps.policyManager.GetTemplatesByEnvironment(envCtx.EnvironmentType)
	
	if len(candidates) == 0 {
		return nil, nil, fmt.Errorf("no policy templates found for environment: %s", envCtx.EnvironmentType)
	}
	
	// Score all candidates
	scores := make([]*PolicyScore, 0, len(candidates))
	for _, template := range candidates {
		score := ps.calculateScore(envCtx, template)
		scores = append(scores, score)
	}
	
	// Sort by total score (descending)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].TotalScore > scores[j].TotalScore
	})
	
	// Return the best match
	bestScore := scores[0]
	return bestScore.Template, bestScore, nil
}

// SelectPolicyWithScores returns the best policy along with all scored candidates
func (ps *PolicySelector) SelectPolicyWithScores(envCtx *EnvironmentContext) (*PolicyTemplate, []*PolicyScore, error) {
	if envCtx == nil {
		return nil, nil, fmt.Errorf("environment context is nil")
	}
	
	candidates := ps.policyManager.GetTemplatesByEnvironment(envCtx.EnvironmentType)
	
	if len(candidates) == 0 {
		return nil, nil, fmt.Errorf("no policy templates found for environment: %s", envCtx.EnvironmentType)
	}
	
	// Score all candidates
	scores := make([]*PolicyScore, 0, len(candidates))
	for _, template := range candidates {
		score := ps.calculateScore(envCtx, template)
		scores = append(scores, score)
	}
	
	// Sort by total score (descending)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].TotalScore > scores[j].TotalScore
	})
	
	return scores[0].Template, scores, nil
}

// calculateScore computes the fitness score for a template
func (ps *PolicySelector) calculateScore(envCtx *EnvironmentContext, template *PolicyTemplate) *PolicyScore {
	score := &PolicyScore{
		Template: template,
	}
	
	// Calculate individual fitness scores
	score.EnvironmentFit = ps.calculateEnvironmentFit(envCtx, template)
	score.ComplianceFit = ps.calculateComplianceFit(envCtx, template)
	score.RiskAlignment = ps.calculateRiskAlignment(envCtx, template)
	
	// Calculate weighted total
	score.TotalScore = (score.EnvironmentFit * ps.environmentWeight) +
		(score.ComplianceFit * ps.complianceWeight) +
		(score.RiskAlignment * ps.riskWeight)
	
	// Generate reasoning
	score.Reasoning = ps.generateReasoning(envCtx, score)
	
	return score
}

// calculateEnvironmentFit scores how well the template matches the environment
func (ps *PolicySelector) calculateEnvironmentFit(envCtx *EnvironmentContext, template *PolicyTemplate) float64 {
	// Exact match = 1.0
	if envCtx.EnvironmentType == template.Environment {
		return 1.0
	}
	
	// Partial match scenarios (fallback logic)
	// If we're looking for staging but only have dev/prod, prefer staging-like environments
	if envCtx.EnvironmentType == EnvironmentStaging {
		if template.Environment == EnvironmentDev {
			return 0.5 // Dev can work as staging fallback
		}
		if template.Environment == EnvironmentProd {
			return 0.3 // Prod is too strict for staging
		}
	}
	
	// If we're looking for dev but only have staging/prod
	if envCtx.EnvironmentType == EnvironmentDev {
		if template.Environment == EnvironmentStaging {
			return 0.6 // Staging can work as dev (slightly restrictive)
		}
	}
	
	// Otherwise, no match
	return 0.0
}

// calculateComplianceFit scores how well the template meets compliance requirements
func (ps *PolicySelector) calculateComplianceFit(envCtx *EnvironmentContext, template *PolicyTemplate) float64 {
	// If no compliance requirements, perfect fit
	if len(envCtx.ComplianceRequirements) == 0 {
		return 1.0
	}
	
	// Count how many requirements are met
	met := 0
	for _, required := range envCtx.ComplianceRequirements {
		for _, provided := range template.ComplianceConfig.Standards {
			if required == provided {
				met++
				break
			}
		}
	}
	
	// Return percentage of requirements met
	return float64(met) / float64(len(envCtx.ComplianceRequirements))
}

// calculateRiskAlignment scores how well the template aligns with risk tolerance
func (ps *PolicySelector) calculateRiskAlignment(envCtx *EnvironmentContext, template *PolicyTemplate) float64 {
	// Map scanning modes to risk levels
	scanningRisk := map[string]float64{
		"log-only": 1.0, // High risk tolerance (permissive)
		"warn":     0.5, // Medium risk tolerance
		"block":    0.0, // Low risk tolerance (strict)
	}
	
	// Map environment risk tolerance to expected risk level
	expectedRisk := map[string]float64{
		"high":    1.0, // Dev - expects log-only
		"medium":  0.5, // Staging - expects warn
		"low":     0.0, // Prod - expects block
		"unknown": 0.5, // Default to medium
	}
	
	templateRisk := scanningRisk[template.IcapConfig.ScanningMode]
	envRisk := expectedRisk[envCtx.RiskTolerance]
	
	// Calculate absolute difference
	diff := templateRisk - envRisk
	if diff < 0 {
		diff = -diff
	}
	
	// Perfect alignment (diff=0) = 1.0, opposite (diff=1.0) = 0.0
	return 1.0 - diff
}

// generateReasoning creates a human-readable explanation of the score
func (ps *PolicySelector) generateReasoning(envCtx *EnvironmentContext, score *PolicyScore) string {
	reasoning := fmt.Sprintf("Selected '%s' (score: %.2f)", 
		score.Template.Name, score.TotalScore)
	
	// Environment fit
	if score.EnvironmentFit == 1.0 {
		reasoning += fmt.Sprintf(" | Environment: perfect match (%s)", envCtx.EnvironmentType)
	} else if score.EnvironmentFit > 0.5 {
		reasoning += fmt.Sprintf(" | Environment: partial match (%.0f%%)", score.EnvironmentFit*100)
	} else {
		reasoning += " | Environment: weak match"
	}
	
	// Compliance fit
	if len(envCtx.ComplianceRequirements) > 0 {
		if score.ComplianceFit == 1.0 {
			reasoning += " | Compliance: all requirements met"
		} else {
			reasoning += fmt.Sprintf(" | Compliance: %.0f%% requirements met", score.ComplianceFit*100)
		}
	} else {
		reasoning += " | Compliance: none required"
	}
	
	// Risk alignment
	if score.RiskAlignment > 0.8 {
		reasoning += " | Risk: excellent alignment"
	} else if score.RiskAlignment > 0.5 {
		reasoning += " | Risk: good alignment"
	} else {
		reasoning += " | Risk: moderate alignment"
	}
	
	return reasoning
}
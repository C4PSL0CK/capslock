package conflict

import (
	"fmt"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// ConflictResolver resolves conflicts between policies
type ConflictResolver struct {
	strategy ResolutionStrategy
}

// NewConflictResolver creates a new conflict resolver with the given strategy
func NewConflictResolver(strategy ResolutionStrategy) *ConflictResolver {
	return &ConflictResolver{
		strategy: strategy,
	}
}

// ResolveConflicts resolves all conflicts in a report using the configured strategy
func (cr *ConflictResolver) ResolveConflicts(report *ConflictReport, envCtx *policy.EnvironmentContext) (*ConflictResolutionReport, error) {
	if report == nil {
		return nil, fmt.Errorf("conflict report is nil")
	}

	if len(report.Conflicts) == 0 {
		// No conflicts to resolve
		return &ConflictResolutionReport{
			Namespace:     report.Namespace,
			TotalResolved: 0,
			Resolutions:   []*Resolution{},
			GeneratedAt:   time.Now(),
		}, nil
	}

	resolutions := []*Resolution{}
	var finalPolicy *policy.PolicyTemplate

	for _, conflict := range report.Conflicts {
		resolution, err := cr.resolveConflict(conflict, envCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve conflict %s: %w", conflict.ID, err)
		}
		resolutions = append(resolutions, resolution)

		// Track the chosen policy (for final result)
		if finalPolicy == nil {
			finalPolicy = resolution.ChosenPolicy
		}
	}

	return &ConflictResolutionReport{
		Namespace:     report.Namespace,
		TotalResolved: len(resolutions),
		Resolutions:   resolutions,
		FinalPolicy:   finalPolicy,
		GeneratedAt:   time.Now(),
	}, nil
}

// resolveConflict resolves a single conflict using the configured strategy
func (cr *ConflictResolver) resolveConflict(conflict *Conflict, envCtx *policy.EnvironmentContext) (*Resolution, error) {
	switch cr.strategy {
	case StrategyPrecedence:
		return cr.resolvePrecedence(conflict)
	case StrategySecurityFirst:
		return cr.resolveSecurityFirst(conflict)
	case StrategyEnvironmentAware:
		return cr.resolveEnvironmentAware(conflict, envCtx)
	case StrategyManual:
		return cr.resolveManual(conflict)
	default:
		return nil, fmt.Errorf("unknown resolution strategy: %s", cr.strategy)
	}
}

// resolvePrecedence resolves conflicts by environment precedence (prod > staging > dev)
func (cr *ConflictResolver) resolvePrecedence(conflict *Conflict) (*Resolution, error) {
	if len(conflict.Policies) == 0 {
		return nil, fmt.Errorf("no policies in conflict")
	}

	// Define precedence order
	precedence := map[policy.EnvironmentType]int{
		policy.EnvironmentProd:    3, // Highest
		policy.EnvironmentStaging: 2,
		policy.EnvironmentDev:     1, // Lowest
		policy.EnvironmentUnknown: 0,
	}

	// Find policy with highest precedence
	var chosen *policy.PolicyTemplate
	var rejected []*policy.PolicyTemplate
	highestPrecedence := -1

	for _, p := range conflict.Policies {
		prec := precedence[p.Environment]
		if prec > highestPrecedence {
			if chosen != nil {
				rejected = append(rejected, chosen)
			}
			chosen = p
			highestPrecedence = prec
		} else {
			rejected = append(rejected, p)
		}
	}

	reason := fmt.Sprintf("Chose %s policy based on environment precedence (prod > staging > dev)", chosen.Environment)

	return &Resolution{
		ConflictID:       conflict.ID,
		Strategy:         StrategyPrecedence,
		ChosenPolicy:     chosen,
		RejectedPolicies: rejected,
		Reason:           reason,
		ResolvedAt:       time.Now(),
		ResolvedBy:       "system",
	}, nil
}

// resolveSecurityFirst resolves conflicts by choosing the most secure option
func (cr *ConflictResolver) resolveSecurityFirst(conflict *Conflict) (*Resolution, error) {
	if len(conflict.Policies) == 0 {
		return nil, fmt.Errorf("no policies in conflict")
	}

	// Security scoring based on scanning mode
	securityScore := map[string]int{
		"block":    3, // Most secure
		"warn":     2,
		"log-only": 1, // Least secure
	}

	var chosen *policy.PolicyTemplate
	var rejected []*policy.PolicyTemplate
	highestSecurity := -1

	for _, p := range conflict.Policies {
		score := securityScore[p.IcapConfig.ScanningMode]
		if score > highestSecurity {
			if chosen != nil {
				rejected = append(rejected, chosen)
			}
			chosen = p
			highestSecurity = score
		} else {
			rejected = append(rejected, p)
		}
	}

	reason := fmt.Sprintf("Chose policy with most secure scanning mode: %s", chosen.IcapConfig.ScanningMode)

	return &Resolution{
		ConflictID:       conflict.ID,
		Strategy:         StrategySecurityFirst,
		ChosenPolicy:     chosen,
		RejectedPolicies: rejected,
		Reason:           reason,
		ResolvedAt:       time.Now(),
		ResolvedBy:       "system",
	}, nil
}

// resolveEnvironmentAware resolves conflicts considering the environment context
func (cr *ConflictResolver) resolveEnvironmentAware(conflict *Conflict, envCtx *policy.EnvironmentContext) (*Resolution, error) {
	if len(conflict.Policies) == 0 {
		return nil, fmt.Errorf("no policies in conflict")
	}

	if envCtx == nil {
		return nil, fmt.Errorf("environment context is required for environment-aware resolution")
	}

	// Choose policy that matches the detected environment
	var chosen *policy.PolicyTemplate
	var rejected []*policy.PolicyTemplate

	for _, p := range conflict.Policies {
		if p.Environment == envCtx.EnvironmentType {
			chosen = p
		} else {
			rejected = append(rejected, p)
		}
	}

	// If no exact match, fall back to precedence
	if chosen == nil {
		return cr.resolvePrecedence(conflict)
	}

	reason := fmt.Sprintf("Chose policy matching detected environment: %s (confidence: %.2f)", 
		envCtx.EnvironmentType, envCtx.Confidence)

	return &Resolution{
		ConflictID:       conflict.ID,
		Strategy:         StrategyEnvironmentAware,
		ChosenPolicy:     chosen,
		RejectedPolicies: rejected,
		Reason:           reason,
		ResolvedAt:       time.Now(),
		ResolvedBy:       "system",
	}, nil
}

// resolveManual returns a resolution that requires manual intervention
func (cr *ConflictResolver) resolveManual(conflict *Conflict) (*Resolution, error) {
	if len(conflict.Policies) == 0 {
		return nil, fmt.Errorf("no policies in conflict")
	}

	// Don't actually resolve - just mark for manual review
	return &Resolution{
		ConflictID:       conflict.ID,
		Strategy:         StrategyManual,
		ChosenPolicy:     nil, // No automatic choice
		RejectedPolicies: conflict.Policies,
		Reason:           "Manual resolution required - please review and select policy",
		ResolvedAt:       time.Now(),
		ResolvedBy:       "pending",
	}, nil
}

// SetStrategy updates the resolution strategy
func (cr *ConflictResolver) SetStrategy(strategy ResolutionStrategy) {
	cr.strategy = strategy
}

// GetStrategy returns the current resolution strategy
func (cr *ConflictResolver) GetStrategy() ResolutionStrategy {
	return cr.strategy
}
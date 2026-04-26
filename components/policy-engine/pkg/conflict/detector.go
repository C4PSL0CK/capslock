package conflict

import (
	"fmt"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// Additional ConflictType constants for inter-policy conflicts.
const (
	ConflictScanningMode  ConflictType = "scanning_mode"
	ConflictEnvironment   ConflictType = "environment"
	ConflictCompliance    ConflictType = "compliance"
	ConflictResourceLimit ConflictType = "resource_limit"
	ConflictSecurityLevel ConflictType = "security_level"
)

// ConflictSeverity represents the severity of a detected conflict.
type ConflictSeverity string

const (
	SeverityCritical ConflictSeverity = "CRITICAL"
	SeverityHigh     ConflictSeverity = "HIGH"
	SeverityMedium   ConflictSeverity = "MEDIUM"
	SeverityLow      ConflictSeverity = "LOW"
)

// Conflict represents a conflict detected between two or more policy templates.
type Conflict struct {
	ID          string
	Type        ConflictType
	Severity    ConflictSeverity
	Description string
	Policies    []*policy.PolicyTemplate
	DetectedAt  time.Time
}

// ConflictReport summarises all detected conflicts.
type ConflictReport struct {
	TotalConflicts int
	Conflicts      []*Conflict
	GeneratedAt    time.Time
}

// ConflictResolution records a single resolved conflict.
type ConflictResolution struct {
	ConflictID       string
	Strategy         ResolutionStrategy
	ChosenPolicy     *policy.PolicyTemplate
	RejectedPolicies []*policy.PolicyTemplate
	Reason           string
}

// ResolutionReport summarises all resolutions.
type ResolutionReport struct {
	TotalResolved int
	Resolutions   []*ConflictResolution
	FinalPolicy   *policy.PolicyTemplate
	GeneratedAt   time.Time
}

// ConflictDetector detects conflicts between pairs of policy templates.
type ConflictDetector struct{}

// NewConflictDetector creates a new ConflictDetector.
func NewConflictDetector() *ConflictDetector {
	return &ConflictDetector{}
}

// DetectConflicts detects conflicts between all pairs of policy templates.
func (cd *ConflictDetector) DetectConflicts(templates []*policy.PolicyTemplate) (*ConflictReport, error) {
	report := &ConflictReport{GeneratedAt: time.Now()}

	for i := 0; i < len(templates); i++ {
		for j := i + 1; j < len(templates); j++ {
			a := templates[i]
			b := templates[j]

			// Scanning mode conflict
			if a.IcapConfig.ScanningMode != "" && b.IcapConfig.ScanningMode != "" &&
				a.IcapConfig.ScanningMode != b.IcapConfig.ScanningMode {
				report.Conflicts = append(report.Conflicts, &Conflict{
					ID:          fmt.Sprintf("%s-%s-scanning", a.Name, b.Name),
					Type:        ConflictScanningMode,
					Severity:    SeverityCritical,
					Description: fmt.Sprintf("Scanning mode conflict: %s uses %q, %s uses %q", a.Name, a.IcapConfig.ScanningMode, b.Name, b.IcapConfig.ScanningMode),
					Policies:    []*policy.PolicyTemplate{a, b},
					DetectedAt:  time.Now(),
				})
			}

			// Environment conflict
			if a.Environment != "" && b.Environment != "" && a.Environment != b.Environment {
				report.Conflicts = append(report.Conflicts, &Conflict{
					ID:          fmt.Sprintf("%s-%s-environment", a.Name, b.Name),
					Type:        ConflictEnvironment,
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Environment conflict: %s targets %q, %s targets %q", a.Name, a.Environment, b.Name, b.Environment),
					Policies:    []*policy.PolicyTemplate{a, b},
					DetectedAt:  time.Now(),
				})
			}

			// Compliance conflict
			if len(a.ComplianceConfig.Standards) != len(b.ComplianceConfig.Standards) {
				report.Conflicts = append(report.Conflicts, &Conflict{
					ID:          fmt.Sprintf("%s-%s-compliance", a.Name, b.Name),
					Type:        ConflictCompliance,
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Compliance conflict: %s has %d standards, %s has %d standards", a.Name, len(a.ComplianceConfig.Standards), b.Name, len(b.ComplianceConfig.Standards)),
					Policies:    []*policy.PolicyTemplate{a, b},
					DetectedAt:  time.Now(),
				})
			}

			// Resource limit conflict
			if a.IcapConfig.MaxFileSize != "" && b.IcapConfig.MaxFileSize != "" &&
				a.IcapConfig.MaxFileSize != b.IcapConfig.MaxFileSize {
				report.Conflicts = append(report.Conflicts, &Conflict{
					ID:          fmt.Sprintf("%s-%s-resource", a.Name, b.Name),
					Type:        ConflictResourceLimit,
					Severity:    SeverityMedium,
					Description: fmt.Sprintf("Resource limit conflict: %s max file size %q, %s max file size %q", a.Name, a.IcapConfig.MaxFileSize, b.Name, b.IcapConfig.MaxFileSize),
					Policies:    []*policy.PolicyTemplate{a, b},
					DetectedAt:  time.Now(),
				})
			}
		}
	}

	report.TotalConflicts = len(report.Conflicts)
	return report, nil
}

// ConflictResolver resolves a conflict report using a chosen strategy.
type ConflictResolver struct {
	strategy ResolutionStrategy
}

// NewConflictResolver creates a resolver with the given strategy.
func NewConflictResolver(strategy ResolutionStrategy) *ConflictResolver {
	return &ConflictResolver{strategy: strategy}
}

// GetStrategy returns the current resolution strategy.
func (cr *ConflictResolver) GetStrategy() ResolutionStrategy {
	return cr.strategy
}

// SetStrategy changes the resolution strategy.
func (cr *ConflictResolver) SetStrategy(strategy ResolutionStrategy) {
	cr.strategy = strategy
}

// ResolveConflicts resolves all conflicts in a report.
func (cr *ConflictResolver) ResolveConflicts(report *ConflictReport, envCtx *policy.EnvironmentContext) (*ResolutionReport, error) {
	if envCtx == nil {
		return nil, fmt.Errorf("environment context is required")
	}

	out := &ResolutionReport{GeneratedAt: time.Now()}

	for _, c := range report.Conflicts {
		res, err := cr.resolveConflict(c, envCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve conflict %s: %w", c.ID, err)
		}
		out.Resolutions = append(out.Resolutions, res)
		if res.ChosenPolicy != nil {
			out.FinalPolicy = res.ChosenPolicy
		}
	}

	out.TotalResolved = len(report.Conflicts)
	return out, nil
}

// resolveConflict resolves a single conflict using the configured strategy.
func (cr *ConflictResolver) resolveConflict(c *Conflict, envCtx *policy.EnvironmentContext) (*ConflictResolution, error) {
	if len(c.Policies) == 0 {
		return &ConflictResolution{
			ConflictID: c.ID,
			Strategy:   cr.strategy,
			Reason:     "no policies to resolve",
		}, nil
	}

	switch cr.strategy {
	case StrategyManual:
		return &ConflictResolution{
			ConflictID: c.ID,
			Strategy:   cr.strategy,
			Reason:     "manual review required",
		}, nil

	case StrategyPrecedence:
		return cr.resolveByPrecedence(c, envCtx)

	case StrategySecurityFirst:
		return cr.resolveBySecurityFirst(c, envCtx)

	case StrategyEnvironmentAware:
		return cr.resolveByEnvironmentAware(c, envCtx)

	default:
		return cr.resolveByPrecedence(c, envCtx)
	}
}

// environmentPriority returns a numeric priority for environment.
// prod=3, staging=2, dev=1, unknown/empty=0
func environmentPriority(env policy.Environment) int {
	switch env {
	case policy.EnvironmentProd:
		return 3
	case policy.EnvironmentStaging:
		return 2
	case policy.EnvironmentDev:
		return 1
	default:
		return 0
	}
}

// scanningModePriority returns a numeric priority for scanning mode.
// block=3, warn=2, log-only=1, other=0
func scanningModePriority(mode string) int {
	switch mode {
	case "block":
		return 3
	case "warn":
		return 2
	case "log-only":
		return 1
	default:
		return 0
	}
}

// resolveByPrecedence chooses the policy with the highest environment priority (prod > staging > dev).
func (cr *ConflictResolver) resolveByPrecedence(c *Conflict, envCtx *policy.EnvironmentContext) (*ConflictResolution, error) {
	chosen := c.Policies[0]
	var rejected []*policy.PolicyTemplate

	for _, p := range c.Policies[1:] {
		if environmentPriority(p.Environment) > environmentPriority(chosen.Environment) {
			rejected = append(rejected, chosen)
			chosen = p
		} else {
			rejected = append(rejected, p)
		}
	}

	return &ConflictResolution{
		ConflictID:       c.ID,
		Strategy:         cr.strategy,
		ChosenPolicy:     chosen,
		RejectedPolicies: rejected,
		Reason:           fmt.Sprintf("chose %s by environment precedence", chosen.Name),
	}, nil
}

// resolveBySecurityFirst chooses the policy with the strictest scanning mode.
func (cr *ConflictResolver) resolveBySecurityFirst(c *Conflict, envCtx *policy.EnvironmentContext) (*ConflictResolution, error) {
	chosen := c.Policies[0]
	var rejected []*policy.PolicyTemplate

	for _, p := range c.Policies[1:] {
		if scanningModePriority(p.IcapConfig.ScanningMode) > scanningModePriority(chosen.IcapConfig.ScanningMode) {
			rejected = append(rejected, chosen)
			chosen = p
		} else {
			rejected = append(rejected, p)
		}
	}

	return &ConflictResolution{
		ConflictID:       c.ID,
		Strategy:         cr.strategy,
		ChosenPolicy:     chosen,
		RejectedPolicies: rejected,
		Reason:           fmt.Sprintf("chose %s by strictest scanning mode", chosen.Name),
	}, nil
}

// resolveByEnvironmentAware chooses the policy whose environment matches the context.
// Falls back to precedence if no match is found.
func (cr *ConflictResolver) resolveByEnvironmentAware(c *Conflict, envCtx *policy.EnvironmentContext) (*ConflictResolution, error) {
	for _, p := range c.Policies {
		if p.Environment == envCtx.EnvironmentType {
			var rejected []*policy.PolicyTemplate
			for _, other := range c.Policies {
				if other != p {
					rejected = append(rejected, other)
				}
			}
			return &ConflictResolution{
				ConflictID:       c.ID,
				Strategy:         cr.strategy,
				ChosenPolicy:     p,
				RejectedPolicies: rejected,
				Reason:           fmt.Sprintf("chose %s matching environment %s", p.Name, envCtx.EnvironmentType),
			}, nil
		}
	}

	// Fall back to precedence
	return cr.resolveByPrecedence(c, envCtx)
}

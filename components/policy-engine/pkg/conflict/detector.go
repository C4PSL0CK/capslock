package conflict

import (
	"time"

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

// ConflictEntry is a conflict entry used in ConflictReport.
type ConflictEntry struct {
	ID          string
	Type        ConflictType
	Severity    string
	Description string
	Policies    []*policy.PolicyTemplate
}

// ConflictReport summarises detected conflicts across multiple templates.
type ConflictReport struct {
	TotalConflicts int
	Conflicts      []ConflictEntry
	GeneratedAt    time.Time
}

// ConflictResolution records a single resolved conflict.
type ConflictResolution struct {
	ConflictID      string
	Strategy        ResolutionStrategy
	ChosenPolicy    *policy.PolicyTemplate
	RejectedPolicies []*policy.PolicyTemplate
	Reason          string
}

// ResolutionReport summarises all resolutions.
type ResolutionReport struct {
	TotalResolved int
	Resolutions   []ConflictResolution
	FinalPolicy   *policy.PolicyTemplate
	GeneratedAt   time.Time
}

// ConflictDetector detects and resolves conflicts across a set of templates.
type ConflictDetector struct {
	resolver *Resolver
}

// NewConflictDetector creates a new ConflictDetector.
func NewConflictDetector() *ConflictDetector {
	return &ConflictDetector{resolver: NewResolver()}
}

// DetectConflicts detects conflicts across multiple policy templates.
func (cd *ConflictDetector) DetectConflicts(templates []*policy.PolicyTemplate) (ConflictReport, error) {
	report := ConflictReport{GeneratedAt: time.Now()}
	for _, t := range templates {
		raw := cd.resolver.DetectConflicts(t)
		for _, c := range raw {
			entry := ConflictEntry{
				ID:          c.Policy1 + "-" + string(c.Type),
				Type:        c.Type,
				Severity:    c.Severity,
				Description: c.Description,
				Policies:    []*policy.PolicyTemplate{t},
			}
			report.Conflicts = append(report.Conflicts, entry)
		}
	}
	report.TotalConflicts = len(report.Conflicts)
	return report, nil
}

// ConflictResolver resolves a conflict report.
type ConflictResolver struct {
	strategy ResolutionStrategy
}

// NewConflictResolver creates a resolver with the given strategy.
func NewConflictResolver(strategy ResolutionStrategy) *ConflictResolver {
	return &ConflictResolver{strategy: strategy}
}

// ResolveConflicts resolves all conflicts in the report.
func (cr *ConflictResolver) ResolveConflicts(report ConflictReport, envCtx *policy.EnvironmentContext) (ResolutionReport, error) {
	out := ResolutionReport{GeneratedAt: time.Now()}
	for _, c := range report.Conflicts {
		res := ConflictResolution{
			ConflictID: c.ID,
			Strategy:   cr.strategy,
			Reason:     "auto-resolved by " + string(cr.strategy),
		}
		if len(c.Policies) > 0 {
			res.ChosenPolicy = c.Policies[0]
		}
		out.Resolutions = append(out.Resolutions, res)
	}
	out.TotalResolved = len(out.Resolutions)
	return out, nil
}

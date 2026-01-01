package conflict

import (
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// ConflictType represents the type of policy conflict
type ConflictType string

const (
	// ConflictScanningMode occurs when policies have different scanning modes
	ConflictScanningMode ConflictType = "scanning-mode"
	
	// ConflictSecurityLevel occurs when policies require different security levels
	ConflictSecurityLevel ConflictType = "security-level"
	
	// ConflictCompliance occurs when policies have incompatible compliance requirements
	ConflictCompliance ConflictType = "compliance"
	
	// ConflictResourceLimit occurs when policies have conflicting resource limits
	ConflictResourceLimit ConflictType = "resource-limit"
	
	// ConflictEnvironment occurs when policies target different environments
	ConflictEnvironment ConflictType = "environment"
)

// ConflictSeverity indicates how severe a conflict is
type ConflictSeverity string

const (
	// SeverityCritical - conflict must be resolved before proceeding
	SeverityCritical ConflictSeverity = "critical"
	
	// SeverityHigh - conflict should be resolved
	SeverityHigh ConflictSeverity = "high"
	
	// SeverityMedium - conflict may cause issues
	SeverityMedium ConflictSeverity = "medium"
	
	// SeverityLow - conflict is minor
	SeverityLow ConflictSeverity = "low"
)

// Conflict represents a detected policy conflict
type Conflict struct {
	ID          string                   `json:"id"`
	Type        ConflictType             `json:"type"`
	Severity    ConflictSeverity         `json:"severity"`
	Description string                   `json:"description"`
	Policies    []*policy.PolicyTemplate `json:"policies"`
	Details     map[string]interface{}   `json:"details"`
	DetectedAt  time.Time                `json:"detectedAt"`
}

// ConflictReport contains all detected conflicts
type ConflictReport struct {
	Namespace      string      `json:"namespace"`
	TotalConflicts int         `json:"totalConflicts"`
	Conflicts      []*Conflict `json:"conflicts"`
	GeneratedAt    time.Time   `json:"generatedAt"`
}

// ResolutionStrategy defines how conflicts should be resolved
type ResolutionStrategy string

const (
	// StrategyPrecedence - resolve by environment precedence (prod > staging > dev)
	StrategyPrecedence ResolutionStrategy = "precedence"
	
	// StrategySecurityFirst - always choose the most secure option
	StrategySecurityFirst ResolutionStrategy = "security-first"
	
	// StrategyEnvironmentAware - consider environment context when resolving
	StrategyEnvironmentAware ResolutionStrategy = "environment-aware"
	
	// StrategyManual - require manual resolution
	StrategyManual ResolutionStrategy = "manual"
)

// Resolution represents the resolution of a conflict
type Resolution struct {
	ConflictID       string                   `json:"conflictId"`
	Strategy         ResolutionStrategy       `json:"strategy"`
	ChosenPolicy     *policy.PolicyTemplate   `json:"chosenPolicy"`
	RejectedPolicies []*policy.PolicyTemplate `json:"rejectedPolicies"`
	Reason           string                   `json:"reason"`
	ResolvedAt       time.Time                `json:"resolvedAt"`
	ResolvedBy       string                   `json:"resolvedBy"` // "system" or user identifier
}

// ConflictResolutionReport contains all resolutions
type ConflictResolutionReport struct {
	Namespace      string                 `json:"namespace"`
	TotalResolved  int                    `json:"totalResolved"`
	Resolutions    []*Resolution          `json:"resolutions"`
	FinalPolicy    *policy.PolicyTemplate `json:"finalPolicy"`
	GeneratedAt    time.Time              `json:"generatedAt"`
}
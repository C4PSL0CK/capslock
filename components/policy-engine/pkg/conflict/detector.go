package conflict

import (
	"fmt"
	"strings"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
	"github.com/google/uuid"
)

// ConflictDetector detects conflicts between policies
type ConflictDetector struct {
	// Could add configuration options here in the future
}

// NewConflictDetector creates a new conflict detector
func NewConflictDetector() *ConflictDetector {
	return &ConflictDetector{}
}

// DetectConflicts analyzes a set of policies and detects conflicts
func (cd *ConflictDetector) DetectConflicts(policies []*policy.PolicyTemplate) (*ConflictReport, error) {
	if len(policies) == 0 {
		return &ConflictReport{
			TotalConflicts: 0,
			Conflicts:      []*Conflict{},
			GeneratedAt:    time.Now(),
		}, nil
	}

	if len(policies) == 1 {
		// Single policy - no conflicts possible
		return &ConflictReport{
			TotalConflicts: 0,
			Conflicts:      []*Conflict{},
			GeneratedAt:    time.Now(),
		}, nil
	}

	conflicts := []*Conflict{}

	// Check for scanning mode conflicts
	scanningConflicts := cd.detectScanningModeConflicts(policies)
	conflicts = append(conflicts, scanningConflicts...)

	// Check for security level conflicts
	securityConflicts := cd.detectSecurityLevelConflicts(policies)
	conflicts = append(conflicts, securityConflicts...)

	// Check for compliance conflicts
	complianceConflicts := cd.detectComplianceConflicts(policies)
	conflicts = append(conflicts, complianceConflicts...)

	// Check for resource limit conflicts
	resourceConflicts := cd.detectResourceLimitConflicts(policies)
	conflicts = append(conflicts, resourceConflicts...)

	// Check for environment conflicts
	environmentConflicts := cd.detectEnvironmentConflicts(policies)
	conflicts = append(conflicts, environmentConflicts...)

	return &ConflictReport{
		TotalConflicts: len(conflicts),
		Conflicts:      conflicts,
		GeneratedAt:    time.Now(),
	}, nil
}

// detectScanningModeConflicts detects conflicts in scanning modes
func (cd *ConflictDetector) detectScanningModeConflicts(policies []*policy.PolicyTemplate) []*Conflict {
	conflicts := []*Conflict{}

	// Group policies by scanning mode
	modeMap := make(map[string][]*policy.PolicyTemplate)
	for _, p := range policies {
		mode := p.IcapConfig.ScanningMode
		modeMap[mode] = append(modeMap[mode], p)
	}

	// If we have more than one scanning mode, that's a conflict
	if len(modeMap) > 1 {
		// Determine severity based on the modes involved
		severity := cd.calculateScanningModeSeverity(modeMap)

		conflict := &Conflict{
			ID:          uuid.New().String(),
			Type:        ConflictScanningMode,
			Severity:    severity,
			Description: cd.generateScanningModeDescription(modeMap),
			Policies:    policies,
			Details: map[string]interface{}{
				"modes": extractModes(modeMap),
			},
			DetectedAt: time.Now(),
		}
		conflicts = append(conflicts, conflict)
	}

	return conflicts
}

// detectSecurityLevelConflicts detects conflicts in security levels
func (cd *ConflictDetector) detectSecurityLevelConflicts(policies []*policy.PolicyTemplate) []*Conflict {
	conflicts := []*Conflict{}

	// Check if policies require different security levels
	// This is inferred from environment types
	envTypes := make(map[policy.EnvironmentType]bool)
	for _, p := range policies {
		envTypes[p.Environment] = true
	}

	// If we have policies from different environments, there might be security conflicts
	if len(envTypes) > 1 {
		// Check for significant security level differences
		hasDev := envTypes[policy.EnvironmentDev]
		hasProd := envTypes[policy.EnvironmentProd]

		if hasDev && hasProd {
			conflict := &Conflict{
				ID:          uuid.New().String(),
				Type:        ConflictSecurityLevel,
				Severity:    SeverityHigh,
				Description: "Policies span from development (low security) to production (high security) environments",
				Policies:    policies,
				Details: map[string]interface{}{
					"environments": extractEnvironments(policies),
				},
				DetectedAt: time.Now(),
			}
			conflicts = append(conflicts, conflict)
		}
	}

	return conflicts
}

// detectComplianceConflicts detects conflicts in compliance requirements
func (cd *ConflictDetector) detectComplianceConflicts(policies []*policy.PolicyTemplate) []*Conflict {
	conflicts := []*Conflict{}

	// Check if policies have different compliance requirements
	complianceMap := make(map[string][]*policy.PolicyTemplate)

	for _, p := range policies {
		key := strings.Join(p.ComplianceConfig.Standards, ",")
		if key == "" {
			key = "none"
		}
		complianceMap[key] = append(complianceMap[key], p)
	}

	// If we have different compliance requirements, that might be a conflict
	if len(complianceMap) > 1 {
		// Check if one policy has requirements and another doesn't
		hasNone := false
		hasRequirements := false

		for key := range complianceMap {
			if key == "none" {
				hasNone = true
			} else {
				hasRequirements = true
			}
		}

		if hasNone && hasRequirements {
			conflict := &Conflict{
				ID:          uuid.New().String(),
				Type:        ConflictCompliance,
				Severity:    SeverityMedium,
				Description: "Some policies have compliance requirements while others don't",
				Policies:    policies,
				Details: map[string]interface{}{
					"complianceGroups": extractComplianceGroups(complianceMap),
				},
				DetectedAt: time.Now(),
			}
			conflicts = append(conflicts, conflict)
		}
	}

	return conflicts
}

// detectResourceLimitConflicts detects conflicts in resource limits
func (cd *ConflictDetector) detectResourceLimitConflicts(policies []*policy.PolicyTemplate) []*Conflict {
	conflicts := []*Conflict{}

	// Check for conflicting file size limits
	fileSizes := make(map[string][]*policy.PolicyTemplate)
	for _, p := range policies {
		size := p.IcapConfig.MaxFileSize
		if size == "" {
			size = "unlimited"
		}
		fileSizes[size] = append(fileSizes[size], p)
	}

	if len(fileSizes) > 1 {
		conflict := &Conflict{
			ID:          uuid.New().String(),
			Type:        ConflictResourceLimit,
			Severity:    SeverityLow,
			Description: "Policies have different maximum file size limits",
			Policies:    policies,
			Details: map[string]interface{}{
				"fileSizes": extractFileSizes(fileSizes),
			},
			DetectedAt: time.Now(),
		}
		conflicts = append(conflicts, conflict)
	}

	// Check for conflicting timeout settings
	timeouts := make(map[int][]*policy.PolicyTemplate)
	for _, p := range policies {
		timeouts[p.PerformanceConfig.Timeout] = append(timeouts[p.PerformanceConfig.Timeout], p)
	}

	if len(timeouts) > 1 {
		conflict := &Conflict{
			ID:          uuid.New().String(),
			Type:        ConflictResourceLimit,
			Severity:    SeverityLow,
			Description: "Policies have different timeout values",
			Policies:    policies,
			Details: map[string]interface{}{
				"timeouts": extractTimeouts(timeouts),
			},
			DetectedAt: time.Now(),
		}
		conflicts = append(conflicts, conflict)
	}

	return conflicts
}

// detectEnvironmentConflicts detects conflicts when multiple environments are targeted
func (cd *ConflictDetector) detectEnvironmentConflicts(policies []*policy.PolicyTemplate) []*Conflict {
	conflicts := []*Conflict{}

	// Check if policies target different environments
	envMap := make(map[policy.EnvironmentType][]*policy.PolicyTemplate)
	for _, p := range policies {
		envMap[p.Environment] = append(envMap[p.Environment], p)
	}

	// Multiple policies for same namespace but different environments = conflict
	if len(envMap) > 1 {
		conflict := &Conflict{
			ID:          uuid.New().String(),
			Type:        ConflictEnvironment,
			Severity:    SeverityCritical,
			Description: "Multiple policies target different environments for the same namespace",
			Policies:    policies,
			Details: map[string]interface{}{
				"environments": extractEnvironments(policies),
			},
			DetectedAt: time.Now(),
		}
		conflicts = append(conflicts, conflict)
	}

	return conflicts
}

// calculateScanningModeSeverity determines severity based on scanning modes
func (cd *ConflictDetector) calculateScanningModeSeverity(modeMap map[string][]*policy.PolicyTemplate) ConflictSeverity {
	// If we have both "log-only" and "block", that's critical
	hasLogOnly := len(modeMap["log-only"]) > 0
	hasBlock := len(modeMap["block"]) > 0

	if hasLogOnly && hasBlock {
		return SeverityCritical
	}

	// "warn" vs "block" or "log-only" vs "warn" is high severity
	hasWarn := len(modeMap["warn"]) > 0
	if (hasWarn && hasBlock) || (hasWarn && hasLogOnly) {
		return SeverityHigh
	}

	return SeverityMedium
}

// generateScanningModeDescription creates a description for scanning mode conflicts
func (cd *ConflictDetector) generateScanningModeDescription(modeMap map[string][]*policy.PolicyTemplate) string {
	modes := []string{}
	for mode := range modeMap {
		modes = append(modes, fmt.Sprintf("'%s'", mode))
	}
	return fmt.Sprintf("Conflicting scanning modes detected: %s", strings.Join(modes, ", "))
}

// Helper functions to extract details for conflict reports

func extractModes(modeMap map[string][]*policy.PolicyTemplate) []string {
	modes := []string{}
	for mode := range modeMap {
		modes = append(modes, mode)
	}
	return modes
}

func extractEnvironments(policies []*policy.PolicyTemplate) []string {
	envs := make(map[string]bool)
	result := []string{}
	for _, p := range policies {
		env := string(p.Environment)
		if !envs[env] {
			envs[env] = true
			result = append(result, env)
		}
	}
	return result
}

func extractComplianceGroups(complianceMap map[string][]*policy.PolicyTemplate) map[string]int {
	groups := make(map[string]int)
	for key, policies := range complianceMap {
		groups[key] = len(policies)
	}
	return groups
}

func extractFileSizes(fileSizes map[string][]*policy.PolicyTemplate) []string {
	sizes := []string{}
	for size := range fileSizes {
		sizes = append(sizes, size)
	}
	return sizes
}

func extractTimeouts(timeouts map[int][]*policy.PolicyTemplate) []int {
	vals := []int{}
	for timeout := range timeouts {
		vals = append(vals, timeout)
	}
	return vals
}
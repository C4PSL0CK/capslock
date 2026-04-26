package compliance

import (
	"fmt"
	"time"
)

// ComplianceValidator is the interface that all compliance framework validators must implement
type ComplianceValidator interface {
	// Validate runs compliance checks against a namespace configuration
	Validate(config interface{}) (*FrameworkReport, error)
	
	// GetFrameworkName returns the name of the compliance framework
	GetFrameworkName() string
	
	// GetFrameworkVersion returns the version of the compliance framework
	GetFrameworkVersion() string
	
	// GetTotalChecks returns the total number of checks in this framework
	GetTotalChecks() int
}

// ComplianceReport contains compliance validation results for all frameworks
type ComplianceReport struct {
	// Timestamp when the compliance check was performed
	Timestamp time.Time `json:"timestamp"`
	
	// Namespace being validated
	Namespace string `json:"namespace"`
	
	// CIS Kubernetes Benchmark report
	CIS *FrameworkReport `json:"cis,omitempty"`
	
	// PCI-DSS report
	PCIDSS *FrameworkReport `json:"pci_dss,omitempty"`
	
	// Overall compliance status (true if all required frameworks pass)
	OverallCompliant bool `json:"overall_compliant"`
	
	// Overall compliance score (0.0 to 1.0)
	OverallScore float64 `json:"overall_score"`
	
	// Total violations across all frameworks
	TotalViolations int `json:"total_violations"`
	
	// Summary message
	Summary string `json:"summary"`
}

// FrameworkReport contains compliance results for a single framework
type FrameworkReport struct {
	// Framework name (e.g., "CIS Kubernetes Benchmark v1.9")
	Framework string `json:"framework"`
	
	// Framework version
	Version string `json:"version"`
	
	// Whether the configuration is compliant with this framework
	Compatible bool `json:"compatible"`
	
	// Compliance score (0.0 to 1.0)
	Score float64 `json:"score"`
	
	// Total number of checks/requirements in this framework
	TotalChecks int `json:"total_checks"`
	
	// Number of checks that passed
	Passed int `json:"passed"`
	
	// Number of checks that failed
	Failed int `json:"failed"`
	
	// List of check IDs that passed
	PassedRules []string `json:"passed_rules"`
	
	// List of violations (failed checks)
	FailedRules []RuleViolation `json:"failed_rules"`
	
	// Breakdown by severity
	SeverityBreakdown SeverityBreakdown `json:"severity_breakdown"`
	
	// Timestamp of validation
	ValidatedAt time.Time `json:"validated_at"`
}

// RuleViolation represents a single failed compliance check
type RuleViolation struct {
	// Rule/Check identifier (e.g., "4.2.1", "Requirement 3.4")
	RuleID string `json:"rule_id"`
	
	// Section/Category (e.g., "4.2 - Pod Security", "Requirement 3")
	Section string `json:"section"`
	
	// Human-readable title
	Title string `json:"title"`
	
	// Severity level
	Severity string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	
	// Detailed description of the violation
	Description string `json:"description"`
	
	// Why this check failed
	Reason string `json:"reason"`
	
	// How to fix this violation
	Remediation string `json:"remediation"`
	
	// Links to official documentation
	References []string `json:"references,omitempty"`
	
	// Affected resources (pod names, service account names, etc.)
	AffectedResources []string `json:"affected_resources,omitempty"`
}

// SeverityBreakdown contains count of violations by severity
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// ComplianceScore represents a weighted compliance score
type ComplianceScore struct {
	// Raw score (0.0 to 1.0)
	RawScore float64 `json:"raw_score"`
	
	// Weighted score considering severity
	WeightedScore float64 `json:"weighted_score"`
	
	// Pass threshold (default 0.90 = 90%)
	PassThreshold float64 `json:"pass_threshold"`
	
	// Whether this score meets the pass threshold
	Passes bool `json:"passes"`
}

// RemediationGuidance provides detailed fix instructions
type RemediationGuidance struct {
	// Rule ID this guidance applies to
	RuleID string `json:"rule_id"`
	
	// Step-by-step instructions
	Steps []string `json:"steps"`
	
	// Example YAML configurations
	ExampleConfig string `json:"example_config,omitempty"`
	
	// kubectl commands to apply fixes
	KubectlCommands []string `json:"kubectl_commands,omitempty"`
	
	// Estimated time to remediate
	EstimatedTime string `json:"estimated_time,omitempty"`
	
	// Priority (how urgent is this fix)
	Priority string `json:"priority"` // IMMEDIATE, HIGH, MEDIUM, LOW
}

// AllRequirementsMet checks if all required frameworks pass
func (cr *ComplianceReport) AllRequirementsMet() bool {
	return cr.OverallCompliant
}

// TotalViolationsCount returns the total number of violations
func (cr *ComplianceReport) TotalViolationsCount() int {
	return cr.TotalViolations
}

// GetCriticalViolations returns all critical violations across frameworks
func (cr *ComplianceReport) GetCriticalViolations() []RuleViolation {
	var critical []RuleViolation
	
	if cr.CIS != nil {
		for _, violation := range cr.CIS.FailedRules {
			if violation.Severity == "CRITICAL" {
				critical = append(critical, violation)
			}
		}
	}
	
	if cr.PCIDSS != nil {
		for _, violation := range cr.PCIDSS.FailedRules {
			if violation.Severity == "CRITICAL" {
				critical = append(critical, violation)
			}
		}
	}
	
	return critical
}

// CalculateOverallScore calculates weighted average score across all frameworks
func (cr *ComplianceReport) CalculateOverallScore() {
	var totalScore float64
	var frameworkCount int
	
	if cr.CIS != nil {
		totalScore += cr.CIS.Score
		frameworkCount++
	}
	
	if cr.PCIDSS != nil {
		totalScore += cr.PCIDSS.Score
		frameworkCount++
	}
	
	if frameworkCount > 0 {
		cr.OverallScore = totalScore / float64(frameworkCount)
	} else {
		cr.OverallScore = 0.0
	}
	
	// Determine overall compliance (must meet 90% threshold)
	cr.OverallCompliant = cr.OverallScore >= 0.90
}

// CalculateTotalViolations sums violations across all frameworks
func (cr *ComplianceReport) CalculateTotalViolations() {
	total := 0
	
	if cr.CIS != nil {
		total += cr.CIS.Failed
	}
	
	if cr.PCIDSS != nil {
		total += cr.PCIDSS.Failed
	}
	
	cr.TotalViolations = total
}

// GenerateSummary creates a human-readable summary
func (cr *ComplianceReport) GenerateSummary() {
	if cr.OverallCompliant {
		cr.Summary = "All compliance requirements met. Configuration is compliant."
	} else {
		cr.Summary = "Compliance validation failed. " + 
			fmt.Sprintf("%d violations found. ", cr.TotalViolations) +
			"Review failed checks and apply remediations."
	}
}

// Helper function to create empty ComplianceReport
func NewComplianceReport(namespace string) *ComplianceReport {
	return &ComplianceReport{
		Timestamp:        time.Now(),
		Namespace:        namespace,
		OverallCompliant: false,
		OverallScore:     0.0,
		TotalViolations:  0,
	}
}

// Helper function to create FrameworkReport
func NewFrameworkReport(framework, version string, totalChecks int) *FrameworkReport {
	return &FrameworkReport{
		Framework:   framework,
		Version:     version,
		TotalChecks: totalChecks,
		Passed:      0,
		Failed:      0,
		PassedRules: []string{},
		FailedRules: []RuleViolation{},
		SeverityBreakdown: SeverityBreakdown{
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
		},
		ValidatedAt: time.Now(),
	}
}

// CalculateScore computes compliance score for a framework
func (fr *FrameworkReport) CalculateScore() {
	if fr.TotalChecks == 0 {
		fr.Score = 0.0
		return
	}
	
	fr.Score = float64(fr.Passed) / float64(fr.TotalChecks)
	
	// Determine compatibility (90% threshold)
	fr.Compatible = fr.Score >= 0.90
}

// AddPassedRule adds a passed check to the report
func (fr *FrameworkReport) AddPassedRule(ruleID string) {
	fr.PassedRules = append(fr.PassedRules, ruleID)
	fr.Passed++
}

// AddFailedRule adds a failed check to the report
func (fr *FrameworkReport) AddFailedRule(violation RuleViolation) {
	fr.FailedRules = append(fr.FailedRules, violation)
	fr.Failed++
	
	// Update severity breakdown
	switch violation.Severity {
	case "CRITICAL":
		fr.SeverityBreakdown.Critical++
	case "HIGH":
		fr.SeverityBreakdown.High++
	case "MEDIUM":
		fr.SeverityBreakdown.Medium++
	case "LOW":
		fr.SeverityBreakdown.Low++
	}
}
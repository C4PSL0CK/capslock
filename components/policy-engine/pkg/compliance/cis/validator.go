package cis

import (
	"fmt"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// CISValidator implements the ComplianceValidator interface for CIS Kubernetes Benchmark
type CISValidator struct {
	version string
	checks  []CISCheck
}

// NewCISValidator creates a new CIS Kubernetes Benchmark validator
func NewCISValidator() *CISValidator {
	return &CISValidator{
		version: "1.9",
		checks:  getAllCISChecks(),
	}
}

// Validate runs all CIS checks against the namespace configuration
func (v *CISValidator) Validate(config interface{}) (*compliance.FrameworkReport, error) {
	// Type assert to NamespaceConfig
	nsConfig, ok := config.(*detector.NamespaceConfig)
	if !ok {
		return nil, fmt.Errorf("invalid config type, expected *detector.NamespaceConfig")
	}

	// Create framework report
	report := compliance.NewFrameworkReport(
		"CIS Kubernetes Benchmark",
		"v1.9",
		len(v.checks),
	)

	// Run all checks
	for _, check := range v.checks {
		passed, message, affectedResources := check.Validator(nsConfig)

		if passed {
			// Check passed
			report.AddPassedRule(check.ID)
		} else {
			// Check failed - create violation
			violation := compliance.RuleViolation{
				RuleID:            check.ID,
				Section:           check.Section,
				Title:             check.Title,
				Severity:          check.Severity,
				Description:       check.Description,
				Reason:            message,
				Remediation:       check.Remediation,
				References:        check.References,
				AffectedResources: affectedResources,
			}
			report.AddFailedRule(violation)
		}
	}

	// Calculate overall score
	report.CalculateScore()

	return report, nil
}

// GetFrameworkName returns the framework name
func (v *CISValidator) GetFrameworkName() string {
	return "CIS Kubernetes Benchmark"
}

// GetFrameworkVersion returns the framework version
func (v *CISValidator) GetFrameworkVersion() string {
	return "v" + v.version
}

// GetTotalChecks returns the total number of checks
func (v *CISValidator) GetTotalChecks() int {
	return len(v.checks)
}

// getAllCISChecks returns all 28 CIS checks from sections 4.1-4.5
func getAllCISChecks() []CISCheck {
	var allChecks []CISCheck

	// Section 4.1: RBAC and Service Accounts (8 checks)
	allChecks = append(allChecks, GetSection41Checks()...)

	// Section 4.2: Pod Security Standards (12 checks)
	allChecks = append(allChecks, GetSection42Checks()...)

	// Section 4.3: Network Policies (3 checks)
	allChecks = append(allChecks, GetSection43Checks()...)

	// Section 4.4: Secrets Management (2 checks)
	allChecks = append(allChecks, GetSection44Checks()...)

	// Section 4.5: Namespace Configuration (3 checks)
	allChecks = append(allChecks, GetSection45Checks()...)

	return allChecks
}

// GetCheckByID returns a specific check by its ID
func (v *CISValidator) GetCheckByID(checkID string) (*CISCheck, error) {
	for _, check := range v.checks {
		if check.ID == checkID {
			return &check, nil
		}
	}
	return nil, fmt.Errorf("check %s not found", checkID)
}

// ValidateSection runs checks for a specific section only
func (v *CISValidator) ValidateSection(config *detector.NamespaceConfig, sectionID string) (*compliance.FrameworkReport, error) {
	// Filter checks by section
	var sectionChecks []CISCheck
	for _, check := range v.checks {
		if check.Section == sectionID {
			sectionChecks = append(sectionChecks, check)
		}
	}

	if len(sectionChecks) == 0 {
		return nil, fmt.Errorf("section %s not found or has no checks", sectionID)
	}

	// Create framework report for section
	report := compliance.NewFrameworkReport(
		fmt.Sprintf("CIS Kubernetes Benchmark - Section %s", sectionID),
		"v1.9",
		len(sectionChecks),
	)

	// Run section checks
	for _, check := range sectionChecks {
		passed, message, affectedResources := check.Validator(config)

		if passed {
			report.AddPassedRule(check.ID)
		} else {
			violation := compliance.RuleViolation{
				RuleID:            check.ID,
				Section:           check.Section,
				Title:             check.Title,
				Severity:          check.Severity,
				Description:       check.Description,
				Reason:            message,
				Remediation:       check.Remediation,
				References:        check.References,
				AffectedResources: affectedResources,
			}
			report.AddFailedRule(violation)
		}
	}

	// Calculate score
	report.CalculateScore()

	return report, nil
}

// GetSectionSummary returns a summary of all sections
func (v *CISValidator) GetSectionSummary() map[string]int {
	summary := make(map[string]int)

	for _, check := range v.checks {
		summary[check.Section]++
	}

	return summary
}
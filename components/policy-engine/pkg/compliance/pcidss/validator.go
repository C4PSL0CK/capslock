package pcidss

import (
	"fmt"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// PCIDSSValidator implements the ComplianceValidator interface for PCI-DSS
type PCIDSSValidator struct {
	version      string
	requirements []PCIDSSRequirement
}

// NewPCIDSSValidator creates a new PCI-DSS validator
func NewPCIDSSValidator() *PCIDSSValidator {
	return &PCIDSSValidator{
		version:      "4.0",
		requirements: GetAllPCIDSSRequirements(),
	}
}

// Validate runs all PCI-DSS checks against the namespace configuration
func (v *PCIDSSValidator) Validate(config interface{}) (*compliance.FrameworkReport, error) {
	// Type assert to NamespaceConfig
	nsConfig, ok := config.(*detector.NamespaceConfig)
	if !ok {
		return nil, fmt.Errorf("invalid config type, expected *detector.NamespaceConfig")
	}

	// Create framework report
	report := compliance.NewFrameworkReport(
		"PCI-DSS",
		"v4.0",
		len(v.requirements),
	)

	// Run all requirement checks
	for _, requirement := range v.requirements {
		passed, message, affectedResources := requirement.Validator(nsConfig)

		if passed {
			// Requirement passed
			report.AddPassedRule(requirement.ID)
		} else {
			// Requirement failed - create violation
			violation := compliance.RuleViolation{
				RuleID:            requirement.ID,
				Section:           requirement.ParentRequirement,
				Title:             requirement.Title,
				Severity:          requirement.Severity,
				Description:       requirement.Description,
				Reason:            message,
				Remediation:       requirement.Remediation,
				References:        requirement.References,
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
func (v *PCIDSSValidator) GetFrameworkName() string {
	return "PCI-DSS"
}

// GetFrameworkVersion returns the framework version
func (v *PCIDSSValidator) GetFrameworkVersion() string {
	return "v" + v.version
}

// GetTotalChecks returns the total number of requirements
func (v *PCIDSSValidator) GetTotalChecks() int {
	return len(v.requirements)
}

// ValidateRequirement validates a specific requirement by ID
func (v *PCIDSSValidator) ValidateRequirement(config *detector.NamespaceConfig, requirementID string) (*compliance.FrameworkReport, error) {
	// Find the specific requirement
	var targetRequirement *PCIDSSRequirement
	for i, req := range v.requirements {
		if req.ID == requirementID {
			targetRequirement = &v.requirements[i]
			break
		}
	}

	if targetRequirement == nil {
		return nil, fmt.Errorf("requirement %s not found", requirementID)
	}

	// Create report for single requirement
	report := compliance.NewFrameworkReport(
		fmt.Sprintf("PCI-DSS Requirement %s", requirementID),
		"v4.0",
		1,
	)

	// Run the requirement check
	passed, message, affectedResources := targetRequirement.Validator(config)

	if passed {
		report.AddPassedRule(targetRequirement.ID)
	} else {
		violation := compliance.RuleViolation{
			RuleID:            targetRequirement.ID,
			Section:           targetRequirement.ParentRequirement,
			Title:             targetRequirement.Title,
			Severity:          targetRequirement.Severity,
			Description:       targetRequirement.Description,
			Reason:            message,
			Remediation:       targetRequirement.Remediation,
			References:        targetRequirement.References,
			AffectedResources: affectedResources,
		}
		report.AddFailedRule(violation)
	}

	report.CalculateScore()
	return report, nil
}

// ValidateParentRequirement validates all sub-requirements under a parent requirement
func (v *PCIDSSValidator) ValidateParentRequirement(config *detector.NamespaceConfig, parentID string) (*compliance.FrameworkReport, error) {
	// Filter requirements by parent
	var parentRequirements []PCIDSSRequirement
	for _, req := range v.requirements {
		if req.ParentRequirement == parentID {
			parentRequirements = append(parentRequirements, req)
		}
	}

	if len(parentRequirements) == 0 {
		return nil, fmt.Errorf("no requirements found under parent %s", parentID)
	}

	// Create report for parent requirement
	report := compliance.NewFrameworkReport(
		fmt.Sprintf("PCI-DSS Requirement %s", parentID),
		"v4.0",
		len(parentRequirements),
	)

	// Run all sub-requirement checks
	for _, requirement := range parentRequirements {
		passed, message, affectedResources := requirement.Validator(config)

		if passed {
			report.AddPassedRule(requirement.ID)
		} else {
			violation := compliance.RuleViolation{
				RuleID:            requirement.ID,
				Section:           requirement.ParentRequirement,
				Title:             requirement.Title,
				Severity:          requirement.Severity,
				Description:       requirement.Description,
				Reason:            message,
				Remediation:       requirement.Remediation,
				References:        requirement.References,
				AffectedResources: affectedResources,
			}
			report.AddFailedRule(violation)
		}
	}

	report.CalculateScore()
	return report, nil
}

// GetRequirementsByParent returns all requirements grouped by parent requirement
func (v *PCIDSSValidator) GetRequirementsByParent() map[string][]PCIDSSRequirement {
	grouped := make(map[string][]PCIDSSRequirement)

	for _, req := range v.requirements {
		grouped[req.ParentRequirement] = append(grouped[req.ParentRequirement], req)
	}

	return grouped
}

// GetRequirementByID returns a specific requirement by ID
func (v *PCIDSSValidator) GetRequirementByID(requirementID string) (*PCIDSSRequirement, error) {
	for _, req := range v.requirements {
		if req.ID == requirementID {
			return &req, nil
		}
	}
	return nil, fmt.Errorf("requirement %s not found", requirementID)
}

// GetCriticalRequirements returns all requirements with CRITICAL severity
func (v *PCIDSSValidator) GetCriticalRequirements() []PCIDSSRequirement {
	var critical []PCIDSSRequirement
	for _, req := range v.requirements {
		if req.Severity == "CRITICAL" {
			critical = append(critical, req)
		}
	}
	return critical
}

// GetRequirementSummary returns a summary of requirements by parent
func (v *PCIDSSValidator) GetRequirementSummary() map[string]int {
	summary := make(map[string]int)

	for _, req := range v.requirements {
		summary[req.ParentRequirement]++
	}

	return summary
}
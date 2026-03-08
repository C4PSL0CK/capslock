package engine

import (
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance"
)

// WorkflowResult represents the complete result of policy application workflow
type WorkflowResult struct {
	// Namespace being processed
	Namespace string `json:"namespace"`

	// Detected environment
	Environment string `json:"environment"`

	// Detection confidence (0.0 to 1.0)
	Confidence float64 `json:"confidence"`

	// Selected policy name
	SelectedPolicy string `json:"selected_policy"`

	// Detected conflicts
	Conflicts []string `json:"conflicts,omitempty"`

	// Compliance validation report
	ComplianceReport *compliance.ComplianceReport `json:"compliance_report,omitempty"`

	// Workflow steps
	Steps []WorkflowStep `json:"steps"`

	// Overall success
	Success bool `json:"success"`

	// Error message if failed
	Error string `json:"error,omitempty"`

	// Timing
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// WorkflowStep represents a single step in the workflow
type WorkflowStep struct {
	// Step number (1, 2, 3, etc.)
	StepNumber int `json:"step_number"`

	// Step name
	Name string `json:"name"`

	// Status (completed, failed, warning, skipped)
	Status string `json:"status"`

	// Duration in seconds
	Duration float64 `json:"duration"`

	// Additional details
	Details string `json:"details,omitempty"`

	// Error message if failed
	Error string `json:"error,omitempty"`
}

// GetTotalDuration returns the total workflow duration
func (wr *WorkflowResult) GetTotalDuration() float64 {
	if wr.EndTime.IsZero() {
		return 0.0
	}
	return wr.EndTime.Sub(wr.StartTime).Seconds()
}

// GetStepByName returns a workflow step by name
func (wr *WorkflowResult) GetStepByName(name string) *WorkflowStep {
	for _, step := range wr.Steps {
		if step.Name == name {
			return &step
		}
	}
	return nil
}

// HasWarnings checks if any steps have warnings
func (wr *WorkflowResult) HasWarnings() bool {
	for _, step := range wr.Steps {
		if step.Status == "warning" {
			return true
		}
	}
	return false
}

// HasErrors checks if any steps have errors
func (wr *WorkflowResult) HasErrors() bool {
	for _, step := range wr.Steps {
		if step.Status == "failed" {
			return true
		}
	}
	return wr.Error != ""
}

// GetComplianceScore returns the overall compliance score
func (wr *WorkflowResult) GetComplianceScore() float64 {
	if wr.ComplianceReport == nil {
		return 0.0
	}
	return wr.ComplianceReport.OverallScore
}

// IsCompliant checks if the namespace is compliant
func (wr *WorkflowResult) IsCompliant() bool {
	if wr.ComplianceReport == nil {
		return false
	}
	return wr.ComplianceReport.OverallCompliant
}

// GetCriticalViolations returns all critical compliance violations
func (wr *WorkflowResult) GetCriticalViolations() []compliance.RuleViolation {
	if wr.ComplianceReport == nil {
		return []compliance.RuleViolation{}
	}
	return wr.ComplianceReport.GetCriticalViolations()
}

// ApplyResult is the result of ApplyPolicyToNamespace.
type ApplyResult struct {
	// Namespace the policy was applied to
	Namespace string `json:"namespace"`

	// DetectedEnvironment is the detected environment type string
	DetectedEnvironment string `json:"detected_environment"`

	// SelectedPolicy is the name of the chosen policy template
	SelectedPolicy string `json:"selected_policy"`

	// Steps records the workflow steps taken
	Steps []string `json:"steps"`

	// Success indicates whether the operation succeeded
	Success bool `json:"success"`

	// Error holds an error message if the operation failed
	Error string `json:"error,omitempty"`
}

// Status represents the deployment status of an applied policy.
type Status struct {
	Namespace  string    `json:"namespace"`
	PolicyName string    `json:"policy_name"`
	Status     string    `json:"status"`
	AppliedAt  time.Time `json:"applied_at"`
}

// AppliedPolicy is a summary of an applied policy.
type AppliedPolicy struct {
	Namespace  string    `json:"namespace"`
	PolicyName string    `json:"policy_name"`
	AppliedAt  time.Time `json:"applied_at"`
}
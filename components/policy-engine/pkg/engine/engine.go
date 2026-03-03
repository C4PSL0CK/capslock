package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance/cis"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance/pcidss"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/conflict"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
	"k8s.io/client-go/kubernetes"
)

// PolicyEngine orchestrates the policy application workflow
type PolicyEngine struct {
	clientset        *kubernetes.Clientset
	detector         *detector.Detector
	conflictResolver *conflict.Resolver
	cisValidator     *cis.CISValidator
	pcidssValidator  *pcidss.PCIDSSValidator
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(clientset *kubernetes.Clientset) *PolicyEngine {
	return &PolicyEngine{
		clientset:        clientset,
		detector:         detector.NewDetector(clientset),
		conflictResolver: conflict.NewResolver(),
		cisValidator:     cis.NewCISValidator(),
		pcidssValidator:  pcidss.NewPCIDSSValidator(),
	}
}

// GetDetector returns the detector instance
func (pe *PolicyEngine) GetDetector() *detector.Detector {
	return pe.detector
}

// ApplyPolicyToNamespace applies the appropriate policy to a namespace
func (pe *PolicyEngine) ApplyPolicyToNamespace(ctx context.Context, namespace string) (*WorkflowResult, error) {
	result := &WorkflowResult{
		Namespace: namespace,
		StartTime: time.Now(),
		Steps:     []WorkflowStep{},
		Success:   false,
	}

	// Step 1: Environment Detection
	stepStart := time.Now()
	environment, confidence, err := pe.detector.DetectEnvironment(ctx, namespace)
	if err != nil {
		result.Error = fmt.Sprintf("Environment detection failed: %v", err)
		result.EndTime = time.Now()
		return result, err
	}

	result.Environment = environment
	result.Confidence = confidence
	result.Steps = append(result.Steps, WorkflowStep{
		StepNumber: 1,
		Name:       "Environment Detection",
		Status:     "completed",
		Duration:   time.Since(stepStart).Seconds(),
		Details:    fmt.Sprintf("Detected: %s (confidence: %.2f%%)", environment, confidence*100),
	})

	// Step 2: Extract Namespace Configuration
	stepStart = time.Now()
	nsConfig, err := pe.detector.ExtractNamespaceConfig(ctx, namespace)
	if err != nil {
		result.Error = fmt.Sprintf("Config extraction failed: %v", err)
		result.EndTime = time.Now()
		return result, err
	}

	result.Steps = append(result.Steps, WorkflowStep{
		StepNumber: 2,
		Name:       "Configuration Extraction",
		Status:     "completed",
		Duration:   time.Since(stepStart).Seconds(),
		Details:    fmt.Sprintf("Extracted config for %d pods", nsConfig.PodSecurity.TotalPods),
	})

	// Step 3: Policy Selection
	stepStart = time.Now()
	selectedPolicy, err := pe.selectPolicy(environment, nsConfig)
	if err != nil {
		result.Error = fmt.Sprintf("Policy selection failed: %v", err)
		result.EndTime = time.Now()
		return result, err
	}

	result.SelectedPolicy = selectedPolicy.Name
	result.Steps = append(result.Steps, WorkflowStep{
		StepNumber: 3,
		Name:       "Policy Selection",
		Status:     "completed",
		Duration:   time.Since(stepStart).Seconds(),
		Details:    fmt.Sprintf("Selected: %s", selectedPolicy.Name),
	})

	// Step 4: Conflict Detection
	stepStart = time.Now()
	conflictsList := pe.conflictResolver.DetectConflicts(selectedPolicy)
	conflictStatus := "passed"
	conflictDetails := "No conflicts detected"

	if len(conflictsList) > 0 {
		conflictStatus = "warning"
		conflictDetails = fmt.Sprintf("Detected %d potential conflicts", len(conflictsList))
	}

	// Convert PolicyConflict to string for backward compatibility
	conflicts := []string{}
	for _, c := range conflictsList {
		conflicts = append(conflicts, c.Description)
	}
	result.Conflicts = conflicts

	result.Steps = append(result.Steps, WorkflowStep{
		StepNumber: 4,
		Name:       "Conflict Detection",
		Status:     conflictStatus,
		Duration:   time.Since(stepStart).Seconds(),
		Details:    conflictDetails,
	})

	// Step 5: Compliance Validation (NEW)
	stepStart = time.Now()
	complianceReport, err := pe.validateCompliance(ctx, nsConfig, selectedPolicy)
	if err != nil {
		result.Error = fmt.Sprintf("Compliance validation failed: %v", err)
		result.EndTime = time.Now()
		return result, err
	}

	result.ComplianceReport = complianceReport

	complianceStatus := "passed"
	if !complianceReport.OverallCompliant {
		complianceStatus = "failed"
	}

	result.Steps = append(result.Steps, WorkflowStep{
		StepNumber: 5,
		Name:       "Compliance Validation",
		Status:     complianceStatus,
		Duration:   time.Since(stepStart).Seconds(),
		Details:    fmt.Sprintf("Overall Score: %.1f%% | Violations: %d", complianceReport.OverallScore*100, complianceReport.TotalViolations),
	})

	// Fail workflow if compliance not met
	if !complianceReport.OverallCompliant {
		result.Error = fmt.Sprintf("Compliance validation failed: %d violations found", complianceReport.TotalViolations)
		result.Success = false
		result.EndTime = time.Now()
		return result, fmt.Errorf("compliance validation failed")
	}

	// Step 6: Policy Application
	stepStart = time.Now()
	if err := pe.applyPolicy(ctx, namespace, selectedPolicy); err != nil {
		result.Error = fmt.Sprintf("Policy application failed: %v", err)
		result.EndTime = time.Now()
		return result, err
	}

	result.Steps = append(result.Steps, WorkflowStep{
		StepNumber: 6,
		Name:       "Policy Application",
		Status:     "completed",
		Duration:   time.Since(stepStart).Seconds(),
		Details:    "Policy applied successfully",
	})

	// Mark as successful
	result.Success = true
	result.EndTime = time.Now()

	return result, nil
}

// validateCompliance runs compliance validation against the namespace config
func (pe *PolicyEngine) validateCompliance(ctx context.Context, nsConfig *detector.NamespaceConfig, selectedPolicy *policy.PolicyTemplate) (*compliance.ComplianceReport, error) {
	report := compliance.NewComplianceReport(nsConfig.Name)

	// Check which frameworks are required by the policy
	requiredFrameworks := selectedPolicy.Compliance.Standards

	// Run CIS validation if required
	if contains(requiredFrameworks, "cis") {
		cisReport, err := pe.cisValidator.Validate(nsConfig)
		if err != nil {
			return nil, fmt.Errorf("CIS validation failed: %w", err)
		}
		report.CIS = cisReport
	}

	// Run PCI-DSS validation if required
	if contains(requiredFrameworks, "pci-dss") {
		pcidssReport, err := pe.pcidssValidator.Validate(nsConfig)
		if err != nil {
			return nil, fmt.Errorf("PCI-DSS validation failed: %w", err)
		}
		report.PCIDSS = pcidssReport
	}

	// Calculate overall scores
	report.CalculateOverallScore()
	report.CalculateTotalViolations()
	report.GenerateSummary()

	return report, nil
}

// selectPolicy selects the appropriate policy based on environment and compliance needs
func (pe *PolicyEngine) selectPolicy(environment string, nsConfig *detector.NamespaceConfig) (*policy.PolicyTemplate, error) {
	// Load policy templates
	templates, err := policy.LoadPolicyTemplates()
	if err != nil {
		return nil, err
	}

	// Filter by environment
	var candidates []*policy.PolicyTemplate
	for _, template := range templates {
		if template.TargetEnvironment == environment {
			candidates = append(candidates, template)
		}
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no policy found for environment: %s", environment)
	}

	// If only one candidate, return it
	if len(candidates) == 1 {
		return candidates[0], nil
	}

	// Score candidates based on compliance requirements
	bestPolicy := candidates[0]
	bestScore := pe.scorePolicy(bestPolicy, nsConfig)

	for i := 1; i < len(candidates); i++ {
		score := pe.scorePolicy(candidates[i], nsConfig)
		if score > bestScore {
			bestScore = score
			bestPolicy = candidates[i]
		}
	}

	return bestPolicy, nil
}

// scorePolicy scores a policy based on how well it matches namespace requirements
func (pe *PolicyEngine) scorePolicy(policy *policy.PolicyTemplate, nsConfig *detector.NamespaceConfig) float64 {
	score := 0.0

	// Base score from environment match (already filtered, so this is 1.0)
	score += 1.0

	// Add compliance coverage score (30% weight)
	complianceScore := 0.0
	requiredCompliance := nsConfig.RequiredCompliance
	policyCompliance := policy.Compliance.Standards

	if len(requiredCompliance) > 0 {
		matchCount := 0
		for _, required := range requiredCompliance {
			if contains(policyCompliance, required) {
				matchCount++
			}
		}
		complianceScore = float64(matchCount) / float64(len(requiredCompliance))
	}
	score += complianceScore * 0.3

	// Add risk score (20% weight)
	riskScore := 0.0
	switch policy.RiskLevel {
	case "low":
		riskScore = 1.0
	case "medium":
		riskScore = 0.6
	case "high":
		riskScore = 0.3
	}
	score += riskScore * 0.2

	return score
}

// applyPolicy applies the selected policy to the namespace
func (pe *PolicyEngine) applyPolicy(ctx context.Context, namespace string, policy *policy.PolicyTemplate) error {
	// This is where you would actually apply the policy
	// For now, this is a placeholder

	// TODO: Generate Gatekeeper ConstraintTemplates
	// TODO: Generate Kyverno ClusterPolicies
	// TODO: Apply to cluster

	return nil
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
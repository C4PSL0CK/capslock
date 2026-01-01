package policy

import (
	"testing"
)

func TestNewPolicySelector(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	selector := NewPolicySelector(pm)
	if selector == nil {
		t.Fatal("NewPolicySelector returned nil")
	}

	// Check default weights
	if selector.environmentWeight != 0.4 {
		t.Errorf("Expected environment weight 0.4, got %.2f", selector.environmentWeight)
	}
	if selector.complianceWeight != 0.3 {
		t.Errorf("Expected compliance weight 0.3, got %.2f", selector.complianceWeight)
	}
	if selector.riskWeight != 0.3 {
		t.Errorf("Expected risk weight 0.3, got %.2f", selector.riskWeight)
	}
}

func TestNewPolicySelectorWithWeights(t *testing.T) {
	pm := NewPolicyManager()

	// Valid weights
	selector, err := NewPolicySelectorWithWeights(pm, 0.5, 0.3, 0.2)
	if err != nil {
		t.Errorf("Valid weights should not error: %v", err)
	}
	if selector == nil {
		t.Error("Selector should not be nil with valid weights")
	}

	// Invalid weights (don't sum to 1.0)
	_, err = NewPolicySelectorWithWeights(pm, 0.5, 0.5, 0.5)
	if err == nil {
		t.Error("Expected error for weights that don't sum to 1.0")
	}
}

func TestSelectPolicy_DevEnvironment(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	selector := NewPolicySelector(pm)

	// Create dev environment context
	envCtx := &EnvironmentContext{
		Namespace:              "dev-test",
		EnvironmentType:        EnvironmentDev,
		SecurityLevel:          SecurityLevelLow,
		RiskTolerance:          "high",
		ComplianceRequirements: []string{},
		Confidence:             0.95,
	}

	// Select policy
	template, score, err := selector.SelectPolicy(envCtx)
	if err != nil {
		t.Fatalf("SelectPolicy failed: %v", err)
	}

	// Should select dev-policy
	if template.Name != "dev-policy" {
		t.Errorf("Expected dev-policy, got %s", template.Name)
	}

	// Should have high environment fit
	if score.EnvironmentFit != 1.0 {
		t.Errorf("Expected environment fit 1.0, got %.2f", score.EnvironmentFit)
	}

	// Should have reasoning
	if score.Reasoning == "" {
		t.Error("Expected reasoning to be non-empty")
	}
}

func TestSelectPolicy_StagingEnvironment(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	selector := NewPolicySelector(pm)

	envCtx := &EnvironmentContext{
		Namespace:              "staging-test",
		EnvironmentType:        EnvironmentStaging,
		SecurityLevel:          SecurityLevelMedium,
		RiskTolerance:          "medium",
		ComplianceRequirements: []string{"iso27001", "soc2"},
		Confidence:             0.92,
	}

	template, score, err := selector.SelectPolicy(envCtx)
	if err != nil {
		t.Fatalf("SelectPolicy failed: %v", err)
	}

	if template.Name != "staging-policy" {
		t.Errorf("Expected staging-policy, got %s", template.Name)
	}

	if score.EnvironmentFit != 1.0 {
		t.Errorf("Expected environment fit 1.0, got %.2f", score.EnvironmentFit)
	}
}

func TestSelectPolicy_ProdEnvironment(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	selector := NewPolicySelector(pm)

	envCtx := &EnvironmentContext{
		Namespace:              "prod-test",
		EnvironmentType:        EnvironmentProd,
		SecurityLevel:          SecurityLevelHigh,
		RiskTolerance:          "low",
		ComplianceRequirements: []string{"iso27001", "soc2", "pci-dss"},
		Confidence:             0.98,
	}

	template, score, err := selector.SelectPolicy(envCtx)
	if err != nil {
		t.Fatalf("SelectPolicy failed: %v", err)
	}

	if template.Name != "prod-policy" {
		t.Errorf("Expected prod-policy, got %s", template.Name)
	}

	if score.EnvironmentFit != 1.0 {
		t.Errorf("Expected environment fit 1.0, got %.2f", score.EnvironmentFit)
	}
}

func TestSelectPolicy_NoCompliance(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	selector := NewPolicySelector(pm)

	// Dev environment with no compliance requirements
	envCtx := &EnvironmentContext{
		Namespace:              "dev-simple",
		EnvironmentType:        EnvironmentDev,
		SecurityLevel:          SecurityLevelLow,
		RiskTolerance:          "high",
		ComplianceRequirements: []string{},
		Confidence:             0.9,
	}

	template, score, err := selector.SelectPolicy(envCtx)
	if err != nil {
		t.Fatalf("SelectPolicy failed: %v", err)
	}

	// Should have perfect compliance fit (no requirements)
	if score.ComplianceFit != 1.0 {
		t.Errorf("Expected compliance fit 1.0 (no requirements), got %.2f", score.ComplianceFit)
	}

	if template.Name != "dev-policy" {
		t.Errorf("Expected dev-policy, got %s", template.Name)
	}
}

func TestSelectPolicy_NoTemplatesFound(t *testing.T) {
	pm := NewPolicyManager()
	// Don't load any templates

	selector := NewPolicySelector(pm)

	envCtx := &EnvironmentContext{
		EnvironmentType: EnvironmentDev,
	}

	_, _, err := selector.SelectPolicy(envCtx)
	if err == nil {
		t.Error("Expected error when no templates available")
	}
}

func TestSelectPolicy_NilContext(t *testing.T) {
	pm := NewPolicyManager()
	selector := NewPolicySelector(pm)

	_, _, err := selector.SelectPolicy(nil)
	if err == nil {
		t.Error("Expected error for nil context")
	}
}

func TestSelectPolicyWithScores(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	selector := NewPolicySelector(pm)

	envCtx := &EnvironmentContext{
		EnvironmentType:        EnvironmentDev,
		SecurityLevel:          SecurityLevelLow,
		RiskTolerance:          "high",
		ComplianceRequirements: []string{},
		Confidence:             0.95,
	}

	template, scores, err := selector.SelectPolicyWithScores(envCtx)
	if err != nil {
		t.Fatalf("SelectPolicyWithScores failed: %v", err)
	}

	// Should return best template
	if template.Name != "dev-policy" {
		t.Errorf("Expected dev-policy, got %s", template.Name)
	}

	// Should return all scores (at least 1)
	if len(scores) < 1 {
		t.Errorf("Expected at least 1 score, got %d", len(scores))
	}

	// First score should be the best
	if scores[0].Template.Name != template.Name {
		t.Error("First score should match returned template")
	}
}

func TestCalculateEnvironmentFit(t *testing.T) {
	pm := NewPolicyManager()
	selector := NewPolicySelector(pm)

	tests := []struct {
		envType      EnvironmentType
		templateEnv  EnvironmentType
		expectedFit  float64
		description  string
	}{
		{EnvironmentDev, EnvironmentDev, 1.0, "Exact match"},
		{EnvironmentStaging, EnvironmentStaging, 1.0, "Exact match"},
		{EnvironmentProd, EnvironmentProd, 1.0, "Exact match"},
		{EnvironmentStaging, EnvironmentDev, 0.5, "Staging using dev fallback"},
		{EnvironmentDev, EnvironmentStaging, 0.6, "Dev using staging fallback"},
		{EnvironmentStaging, EnvironmentProd, 0.3, "Staging using prod (not ideal)"},
	}

	for _, tt := range tests {
		envCtx := &EnvironmentContext{EnvironmentType: tt.envType}
		template := &PolicyTemplate{Environment: tt.templateEnv}

		fit := selector.calculateEnvironmentFit(envCtx, template)
		if fit != tt.expectedFit {
			t.Errorf("%s: expected fit %.1f, got %.1f", tt.description, tt.expectedFit, fit)
		}
	}
}

func TestCalculateComplianceFit(t *testing.T) {
	pm := NewPolicyManager()
	selector := NewPolicySelector(pm)

	// All requirements met
	envCtx := &EnvironmentContext{
		ComplianceRequirements: []string{"iso27001", "soc2"},
	}
	template := &PolicyTemplate{
		ComplianceConfig: ComplianceConfig{
			Standards: []string{"iso27001", "soc2", "pci-dss"},
		},
	}

	fit := selector.calculateComplianceFit(envCtx, template)
	if fit != 1.0 {
		t.Errorf("Expected compliance fit 1.0 (all met), got %.2f", fit)
	}

	// Partial match
	envCtx2 := &EnvironmentContext{
		ComplianceRequirements: []string{"iso27001", "soc2", "cis"},
	}
	template2 := &PolicyTemplate{
		ComplianceConfig: ComplianceConfig{
			Standards: []string{"iso27001"},
		},
	}

	fit2 := selector.calculateComplianceFit(envCtx2, template2)
	expected := 1.0 / 3.0
	if fit2 < expected-0.01 || fit2 > expected+0.01 {
		t.Errorf("Expected compliance fit ~%.2f (1/3 met), got %.2f", expected, fit2)
	}
}

func TestCalculateRiskAlignment(t *testing.T) {
	pm := NewPolicyManager()
	selector := NewPolicySelector(pm)

	tests := []struct {
		riskTolerance string
		scanningMode  string
		expectedAlign float64
		description   string
	}{
		{"high", "log-only", 1.0, "Dev: high risk + log-only = perfect"},
		{"medium", "warn", 1.0, "Staging: medium risk + warn = perfect"},
		{"low", "block", 1.0, "Prod: low risk + block = perfect"},
		{"high", "block", 0.0, "Dev with block mode = poor alignment"},
	}

	for _, tt := range tests {
		envCtx := &EnvironmentContext{RiskTolerance: tt.riskTolerance}
		template := &PolicyTemplate{
			IcapConfig: IcapConfiguration{
				ScanningMode: tt.scanningMode,
			},
		}

		align := selector.calculateRiskAlignment(envCtx, template)
		if align != tt.expectedAlign {
			t.Errorf("%s: expected alignment %.1f, got %.1f", 
				tt.description, tt.expectedAlign, align)
		}
	}
}
package kyverno

import (
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

func TestNewKyvernoConverter(t *testing.T) {
	converter := NewKyvernoConverter()
	if converter == nil {
		t.Fatal("NewKyvernoConverter returned nil")
	}
}

func TestConvertPolicy_DevPolicy(t *testing.T) {
	converter := NewKyvernoConverter()

	devPolicy := &policy.PolicyTemplate{
		Name:        "dev-policy",
		Version:     "1.0",
		Environment: policy.EnvironmentDev,
		Description: "Development policy",
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "log-only",
			MaxFileSize:  "100MB",
		},
		ComplianceConfig: policy.ComplianceConfig{
			Standards: []string{},
		},
	}

	result, err := converter.ConvertPolicy(devPolicy)
	if err != nil {
		t.Fatalf("ConvertPolicy failed: %v", err)
	}

	if result.ClusterPolicy == nil {
		t.Fatal("ClusterPolicy should not be nil")
	}

	if result.ClusterPolicy.Metadata.Name != "eape-dev-policy" {
		t.Errorf("Expected name 'eape-dev-policy', got '%s'", result.ClusterPolicy.Metadata.Name)
	}

	if result.ClusterPolicy.Spec.ValidationFailureAction != "Audit" {
		t.Errorf("Expected Audit for log-only mode, got '%s'", result.ClusterPolicy.Spec.ValidationFailureAction)
	}
}

func TestConvertPolicy_ProdPolicy(t *testing.T) {
	converter := NewKyvernoConverter()

	prodPolicy := &policy.PolicyTemplate{
		Name:        "prod-policy",
		Version:     "1.0",
		Environment: policy.EnvironmentProd,
		Description: "Production policy",
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "block",
		},
		ComplianceConfig: policy.ComplianceConfig{
			Standards: []string{"pci-dss", "soc2"},
		},
	}

	result, err := converter.ConvertPolicy(prodPolicy)
	if err != nil {
		t.Fatalf("ConvertPolicy failed: %v", err)
	}

	if result.ClusterPolicy.Spec.ValidationFailureAction != "Enforce" {
		t.Errorf("Expected Enforce for block mode, got '%s'", result.ClusterPolicy.Spec.ValidationFailureAction)
	}

	if len(result.ClusterPolicy.Spec.Rules) < 3 {
		t.Errorf("Expected at least 3 rules with compliance, got %d", len(result.ClusterPolicy.Spec.Rules))
	}
}

func TestGetFailureAction(t *testing.T) {
	converter := NewKyvernoConverter()

	tests := []struct {
		mode     string
		expected string
	}{
		{"block", "Enforce"},
		{"warn", "Audit"},
		{"log-only", "Audit"},
	}

	for _, tt := range tests {
		result := converter.getFailureAction(tt.mode)
		if result != tt.expected {
			t.Errorf("For mode '%s': expected '%s', got '%s'", tt.mode, tt.expected, result)
		}
	}
}

func TestGeneratePolicyName(t *testing.T) {
	converter := NewKyvernoConverter()

	p := &policy.PolicyTemplate{Name: "test-policy"}
	result := converter.generatePolicyName(p)

	expected := "eape-test-policy"
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}
}

func TestConvertPolicy_NilPolicy(t *testing.T) {
	converter := NewKyvernoConverter()

	_, err := converter.ConvertPolicy(nil)
	if err == nil {
		t.Error("Expected error for nil policy")
	}
}
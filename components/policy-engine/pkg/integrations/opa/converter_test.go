package opa

import (
	"strings"
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

func TestNewOPAConverter(t *testing.T) {
	converter := NewOPAConverter()
	if converter == nil {
		t.Fatal("NewOPAConverter returned nil")
	}
}

func TestConvertPolicy_DevPolicy(t *testing.T) {
	converter := NewOPAConverter()

	devPolicy := &policy.PolicyTemplate{
		Name:        "dev-policy",
		Version:     "1.0",
		Environment: policy.EnvironmentDev,
		Description: "Development environment policy",
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

	if result.Template == nil {
		t.Fatal("Template should not be nil")
	}

	if result.Constraint == nil {
		t.Fatal("Constraint should not be nil")
	}

	if result.Template.Metadata.Name != "eapedevpolicy" {
		t.Errorf("Expected template name 'eapedevpolicy', got '%s'", result.Template.Metadata.Name)
	}

	if result.Constraint.Kind != "EAPEDevPolicy" {
		t.Errorf("Expected constraint kind 'EAPEDevPolicy', got '%s'", result.Constraint.Kind)
	}
}

func TestConvertPolicy_ProdPolicy(t *testing.T) {
	converter := NewOPAConverter()

	prodPolicy := &policy.PolicyTemplate{
		Name:        "prod-policy",
		Version:     "1.0",
		Environment: policy.EnvironmentProd,
		Description: "Production environment policy",
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "block",
			MaxFileSize:  "50MB",
		},
		ComplianceConfig: policy.ComplianceConfig{
			Standards: []string{"pci-dss", "soc2"},
		},
	}

	result, err := converter.ConvertPolicy(prodPolicy)
	if err != nil {
		t.Fatalf("ConvertPolicy failed: %v", err)
	}

	if result.Template == nil {
		t.Fatal("Template should not be nil")
	}

	if result.Template.Metadata.Annotations["eape.environment"] != "prod" {
		t.Errorf("Expected environment annotation 'prod', got '%s'",
			result.Template.Metadata.Annotations["eape.environment"])
	}
}

func TestGenerateRegoPolicy_BlockMode(t *testing.T) {
	converter := NewOPAConverter()

	blockPolicy := &policy.PolicyTemplate{
		Name:        "block-policy",
		Environment: policy.EnvironmentProd,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "block",
		},
		ComplianceConfig: policy.ComplianceConfig{
			Standards: []string{},
		},
	}

	rego := converter.generateRegoPolicy(blockPolicy)

	if !strings.Contains(rego, "violation[{\"msg\": msg}]") {
		t.Error("Rego should contain violation rule for block mode")
	}

	if !strings.Contains(rego, "package eapepolicy") {
		t.Error("Rego should contain package declaration")
	}
}

func TestGenerateRegoPolicy_WarnMode(t *testing.T) {
	converter := NewOPAConverter()

	warnPolicy := &policy.PolicyTemplate{
		Name:        "warn-policy",
		Environment: policy.EnvironmentStaging,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "warn",
		},
		ComplianceConfig: policy.ComplianceConfig{
			Standards: []string{},
		},
	}

	rego := converter.generateRegoPolicy(warnPolicy)

	if !strings.Contains(rego, "warn[{\"msg\": msg}]") {
		t.Error("Rego should contain warn rule for warn mode")
	}
}

func TestGenerateRegoPolicy_LogOnlyMode(t *testing.T) {
	converter := NewOPAConverter()

	logPolicy := &policy.PolicyTemplate{
		Name:        "log-policy",
		Environment: policy.EnvironmentDev,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "log-only",
		},
		ComplianceConfig: policy.ComplianceConfig{
			Standards: []string{},
		},
	}

	rego := converter.generateRegoPolicy(logPolicy)

	if !strings.Contains(rego, "info[{\"msg\": msg}]") {
		t.Error("Rego should contain info rule for log-only mode")
	}
}

func TestGenerateRegoPolicy_WithCompliance(t *testing.T) {
	converter := NewOPAConverter()

	compliancePolicy := &policy.PolicyTemplate{
		Name:        "compliance-policy",
		Environment: policy.EnvironmentProd,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "block",
		},
		ComplianceConfig: policy.ComplianceConfig{
			Standards: []string{"pci-dss", "soc2"},
		},
	}

	rego := converter.generateRegoPolicy(compliancePolicy)

	if !strings.Contains(rego, "PCI-DSS") {
		t.Error("Rego should contain PCI-DSS compliance rule")
	}

	if !strings.Contains(rego, "SOC2") {
		t.Error("Rego should contain SOC2 compliance rule")
	}
}

func TestGenerateTemplateName(t *testing.T) {
	converter := NewOPAConverter()

	tests := []struct {
		policyName   string
		expectedName string
	}{
		{"dev-policy", "eapedevpolicy"},
		{"staging-policy", "eapestagingpolicy"},
		{"prod-policy", "eapeprodpolicy"},
	}

	for _, tt := range tests {
		p := &policy.PolicyTemplate{Name: tt.policyName}
		result := converter.generateTemplateName(p)
		if result != tt.expectedName {
			t.Errorf("For policy '%s': expected '%s', got '%s'",
				tt.policyName, tt.expectedName, result)
		}
	}
}

func TestGenerateKindName(t *testing.T) {
	converter := NewOPAConverter()

	tests := []struct {
		policyName   string
		expectedKind string
	}{
		{"dev-policy", "EAPEDevPolicy"},
		{"staging-policy", "EAPEStagingPolicy"},
		{"prod-policy", "EAPEProdPolicy"},
	}

	for _, tt := range tests {
		p := &policy.PolicyTemplate{Name: tt.policyName}
		result := converter.generateKindName(p)
		if result != tt.expectedKind {
			t.Errorf("For policy '%s': expected '%s', got '%s'",
				tt.policyName, tt.expectedKind, result)
		}
	}
}

func TestConvertPolicy_NilPolicy(t *testing.T) {
	converter := NewOPAConverter()

	_, err := converter.ConvertPolicy(nil)
	if err == nil {
		t.Error("Expected error for nil policy")
	}
}
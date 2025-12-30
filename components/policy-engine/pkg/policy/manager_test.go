package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewPolicyManager(t *testing.T) {
	pm := NewPolicyManager()
	if pm == nil {
		t.Fatal("NewPolicyManager returned nil")
	}
	if pm.templates == nil {
		t.Error("templates map is nil")
	}
	if pm.Count() != 0 {
		t.Errorf("Expected 0 templates, got %d", pm.Count())
	}
}

func TestLoadTemplates(t *testing.T) {
	pm := NewPolicyManager()

	// Load templates from the real templates directory
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Should have loaded 3 templates (dev, staging, prod)
	if pm.Count() != 3 {
		t.Errorf("Expected 3 templates, got %d", pm.Count())
	}

	// Verify template names
	names := pm.ListTemplates()
	expectedNames := map[string]bool{
		"dev-policy":     false,
		"staging-policy": false,
		"prod-policy":    false,
	}

	for _, name := range names {
		if _, exists := expectedNames[name]; exists {
			expectedNames[name] = true
		}
	}

	for name, found := range expectedNames {
		if !found {
			t.Errorf("Expected template '%s' not found", name)
		}
	}
}

func TestGetTemplate(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Get dev template
	template, err := pm.GetTemplate("dev-policy")
	if err != nil {
		t.Fatalf("Failed to get dev-policy: %v", err)
	}

	if template.Name != "dev-policy" {
		t.Errorf("Expected name 'dev-policy', got '%s'", template.Name)
	}

	if template.Environment != EnvironmentDev {
		t.Errorf("Expected environment 'dev', got '%s'", template.Environment)
	}

	// Try to get non-existent template
	_, err = pm.GetTemplate("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent template")
	}
}

func TestGetTemplatesByEnvironment(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Get dev templates
	devTemplates := pm.GetTemplatesByEnvironment(EnvironmentDev)
	if len(devTemplates) != 1 {
		t.Errorf("Expected 1 dev template, got %d", len(devTemplates))
	}

	// Get prod templates
	prodTemplates := pm.GetTemplatesByEnvironment(EnvironmentProd)
	if len(prodTemplates) != 1 {
		t.Errorf("Expected 1 prod template, got %d", len(prodTemplates))
	}

	// Get staging templates
	stagingTemplates := pm.GetTemplatesByEnvironment(EnvironmentStaging)
	if len(stagingTemplates) != 1 {
		t.Errorf("Expected 1 staging template, got %d", len(stagingTemplates))
	}
}

func TestLoadTemplates_EmptyDirectory(t *testing.T) {
	pm := NewPolicyManager()

	// Create a temporary empty directory
	tmpDir := t.TempDir()

	err := pm.LoadTemplates(tmpDir)
	if err == nil {
		t.Error("Expected error when loading from empty directory")
	}
}

func TestLoadTemplates_InvalidYAML(t *testing.T) {
	pm := NewPolicyManager()

	// Create temporary directory with invalid YAML
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.yaml")

	// Write invalid YAML
	err := os.WriteFile(invalidFile, []byte("invalid: yaml: content: [[["), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	err = pm.LoadTemplates(tmpDir)
	if err == nil {
		t.Error("Expected error when loading invalid YAML")
	}
}

func TestGetAllTemplates(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	templates := pm.GetAllTemplates()
	if len(templates) != 3 {
		t.Errorf("Expected 3 templates, got %d", len(templates))
	}
}

func TestValidateTemplate_Valid(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// All loaded templates should be valid
	for name, template := range pm.templates {
		err := pm.ValidateTemplate(template)
		if err != nil {
			t.Errorf("Template %s should be valid, got error: %v", name, err)
		}
	}
}

func TestValidateTemplate_MissingName(t *testing.T) {
	pm := NewPolicyManager()

	template := &PolicyTemplate{
		Version:     "1.0",
		Environment: EnvironmentDev,
	}

	err := pm.ValidateTemplate(template)
	if err == nil {
		t.Error("Expected error for missing name")
	}
}

func TestValidateTemplate_MissingVersion(t *testing.T) {
	pm := NewPolicyManager()

	template := &PolicyTemplate{
		Name:        "test",
		Environment: EnvironmentDev,
	}

	err := pm.ValidateTemplate(template)
	if err == nil {
		t.Error("Expected error for missing version")
	}
}

func TestValidateTemplate_InvalidEnvironment(t *testing.T) {
	pm := NewPolicyManager()

	template := &PolicyTemplate{
		Name:        "test",
		Version:     "1.0",
		Environment: "invalid",
	}

	err := pm.ValidateTemplate(template)
	if err == nil {
		t.Error("Expected error for invalid environment")
	}
}

func TestValidateTemplate_InvalidScanningMode(t *testing.T) {
	pm := NewPolicyManager()

	template := &PolicyTemplate{
		Name:        "test",
		Version:     "1.0",
		Environment: EnvironmentDev,
		IcapConfig: IcapConfiguration{
			ScanningMode: "invalid-mode",
		},
	}

	err := pm.ValidateTemplate(template)
	if err == nil {
		t.Error("Expected error for invalid scanning mode")
	}
}

func TestValidateTemplate_InvalidFileSize(t *testing.T) {
	pm := NewPolicyManager()

	template := &PolicyTemplate{
		Name:        "test",
		Version:     "1.0",
		Environment: EnvironmentDev,
		IcapConfig: IcapConfiguration{
			ScanningMode: "log-only",
			MaxFileSize:  "invalid-size",
		},
	}

	err := pm.ValidateTemplate(template)
	if err == nil {
		t.Error("Expected error for invalid file size format")
	}
}

func TestValidateTemplate_NegativeTimeout(t *testing.T) {
	pm := NewPolicyManager()

	template := &PolicyTemplate{
		Name:        "test",
		Version:     "1.0",
		Environment: EnvironmentDev,
		IcapConfig: IcapConfiguration{
			ScanningMode: "log-only",
		},
		PerformanceConfig: PerformanceConfig{
			Timeout:       -1,
			MaxConcurrent: 10,
		},
	}

	err := pm.ValidateTemplate(template)
	if err == nil {
		t.Error("Expected error for negative timeout")
	}
}

func TestValidateTemplate_InvalidComplianceStandard(t *testing.T) {
	pm := NewPolicyManager()

	template := &PolicyTemplate{
		Name:        "test",
		Version:     "1.0",
		Environment: EnvironmentProd,
		IcapConfig: IcapConfiguration{
			ScanningMode: "block",
		},
		PerformanceConfig: PerformanceConfig{
			Timeout:       30,
			MaxConcurrent: 10,
		},
		ComplianceConfig: ComplianceConfig{
			Standards: []string{"invalid-standard"},
		},
	}

	err := pm.ValidateTemplate(template)
	if err == nil {
		t.Error("Expected error for invalid compliance standard")
	}
}

func TestValidateAllTemplates(t *testing.T) {
	pm := NewPolicyManager()
	err := pm.LoadTemplates("../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// All templates should be valid
	err = pm.ValidateAllTemplates()
	if err != nil {
		t.Errorf("All templates should be valid, got error: %v", err)
	}
}

func TestValidateFileSizeFormat(t *testing.T) {
	validSizes := []string{"100MB", "50GB", "1TB", "500KB"}
	for _, size := range validSizes {
		err := validateFileSizeFormat(size)
		if err != nil {
			t.Errorf("Size %s should be valid, got error: %v", size, err)
		}
	}

	invalidSizes := []string{"100", "MB", "100 MB", "100MBX", "abcMB"}
	for _, size := range invalidSizes {
		err := validateFileSizeFormat(size)
		if err == nil {
			t.Errorf("Size %s should be invalid", size)
		}
	}
}
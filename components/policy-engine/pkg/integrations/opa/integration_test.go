package opa

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

func TestEndToEndConversion(t *testing.T) {
	// Create converter
	converter := NewOPAConverter()

	// Load a real policy template
	pm := policy.NewPolicyManager()
	err := pm.LoadTemplates("../../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Get dev policy
	devPolicy, err := pm.GetTemplate("dev-policy")
	if err != nil {
		t.Fatalf("Failed to get dev-policy: %v", err)
	}

	// Convert to OPA
	result, err := converter.ConvertPolicy(devPolicy)
	if err != nil {
		t.Fatalf("Failed to convert policy: %v", err)
	}

	// Verify conversion
	if result.Template == nil {
		t.Error("Template should not be nil")
	}

	if result.Constraint == nil {
		t.Error("Constraint should not be nil")
	}

	// Generate YAML files
	generator := NewResourceGenerator()
	tmpDir := t.TempDir()

	err = generator.GenerateYAML(result, tmpDir)
	if err != nil {
		t.Fatalf("Failed to generate YAML: %v", err)
	}

	// Verify files were created
	templatePath := filepath.Join(tmpDir, "dev-policy-template.yaml")
	constraintPath := filepath.Join(tmpDir, "dev-policy-constraint.yaml")

	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		t.Error("Template YAML file was not created")
	}

	if _, err := os.Stat(constraintPath); os.IsNotExist(err) {
		t.Error("Constraint YAML file was not created")
	}

	t.Logf("Generated OPA resources in: %s", tmpDir)
}

func TestGenerateAllPolicies(t *testing.T) {
	converter := NewOPAConverter()
	generator := NewResourceGenerator()

	// Load all templates
	pm := policy.NewPolicyManager()
	err := pm.LoadTemplates("../../../policies/templates")
	if err != nil {
		t.Fatalf("Failed to load templates: %v", err)
	}

	// Create output directory
	tmpDir := t.TempDir()

	// Convert each policy
	policies := pm.GetAllTemplates()
	for _, p := range policies {
		result, err := converter.ConvertPolicy(p)
		if err != nil {
			t.Errorf("Failed to convert %s: %v", p.Name, err)
			continue
		}

		err = generator.GenerateYAML(result, tmpDir)
		if err != nil {
			t.Errorf("Failed to generate YAML for %s: %v", p.Name, err)
			continue
		}

		t.Logf("Generated OPA resources for: %s", p.Name)
	}

	// Should have 6 files (3 policies × 2 files each)
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read output directory: %v", err)
	}

	if len(files) != 6 {
		t.Errorf("Expected 6 files, got %d", len(files))
	}
}
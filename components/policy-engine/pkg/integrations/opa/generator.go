package opa

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ResourceGenerator generates OPA YAML files
type ResourceGenerator struct {
	converter *OPAConverter
}

// NewResourceGenerator creates a new resource generator
func NewResourceGenerator() *ResourceGenerator {
	return &ResourceGenerator{
		converter: NewOPAConverter(),
	}
}

// GenerateYAML generates OPA YAML files for a policy
func (rg *ResourceGenerator) GenerateYAML(result *ConversionResult, outputDir string) error {
	if result == nil {
		return fmt.Errorf("conversion result is nil")
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate template YAML
	templatePath := filepath.Join(outputDir, fmt.Sprintf("%s-template.yaml", result.Policy.Name))
	if err := rg.writeTemplateYAML(result.Template, templatePath); err != nil {
		return fmt.Errorf("failed to write template YAML: %w", err)
	}

	// Generate constraint YAML
	constraintPath := filepath.Join(outputDir, fmt.Sprintf("%s-constraint.yaml", result.Policy.Name))
	if err := rg.writeConstraintYAML(result.Constraint, constraintPath); err != nil {
		return fmt.Errorf("failed to write constraint YAML: %w", err)
	}

	return nil
}

// writeTemplateYAML writes a ConstraintTemplate to YAML file
func (rg *ResourceGenerator) writeTemplateYAML(template *ConstraintTemplate, path string) error {
	data, err := yaml.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// writeConstraintYAML writes a Constraint to YAML file
func (rg *ResourceGenerator) writeConstraintYAML(constraint *Constraint, path string) error {
	data, err := yaml.Marshal(constraint)
	if err != nil {
		return fmt.Errorf("failed to marshal constraint: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
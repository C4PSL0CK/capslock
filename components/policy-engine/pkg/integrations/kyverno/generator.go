package kyverno

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ResourceGenerator generates Kyverno YAML files
type ResourceGenerator struct {
	converter *KyvernoConverter
}

// NewResourceGenerator creates a new resource generator
func NewResourceGenerator() *ResourceGenerator {
	return &ResourceGenerator{
		converter: NewKyvernoConverter(),
	}
}

// GenerateYAML generates Kyverno YAML file for a policy
func (rg *ResourceGenerator) GenerateYAML(result *ConversionResult, outputDir string) error {
	if result == nil {
		return fmt.Errorf("conversion result is nil")
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate ClusterPolicy YAML
	policyPath := filepath.Join(outputDir, fmt.Sprintf("%s-kyverno.yaml", result.Policy.Name))
	if err := rg.writeClusterPolicyYAML(result.ClusterPolicy, policyPath); err != nil {
		return fmt.Errorf("failed to write ClusterPolicy YAML: %w", err)
	}

	return nil
}

// writeClusterPolicyYAML writes a ClusterPolicy to YAML file
func (rg *ResourceGenerator) writeClusterPolicyYAML(policy *ClusterPolicy, path string) error {
	data, err := yaml.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}
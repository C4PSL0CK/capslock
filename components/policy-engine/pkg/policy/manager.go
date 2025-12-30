package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// PolicyManager manages policy templates
type PolicyManager struct {
	templates map[string]*PolicyTemplate
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		templates: make(map[string]*PolicyTemplate),
	}
}

// LoadTemplates loads policy templates from a directory
func (pm *PolicyManager) LoadTemplates(dir string) error {
	// Find all YAML files in the directory
	pattern := filepath.Join(dir, "*.yaml")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob pattern %s: %w", pattern, err)
	}

	// Also check for .yml extension
	patternYml := filepath.Join(dir, "*.yml")
	filesYml, err := filepath.Glob(patternYml)
	if err != nil {
		return fmt.Errorf("failed to glob pattern %s: %w", patternYml, err)
	}

	files = append(files, filesYml...)

	if len(files) == 0 {
		return fmt.Errorf("no policy templates found in directory: %s", dir)
	}

	// Load each template file
	for _, file := range files {
		template, err := pm.loadTemplateFile(file)
		if err != nil {
			return fmt.Errorf("failed to load template %s: %w", file, err)
		}

		// Store template by name
		pm.templates[template.Name] = template
	}

	return nil
}

// loadTemplateFile loads a single policy template from a file
func (pm *PolicyManager) loadTemplateFile(filename string) (*PolicyTemplate, error) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse YAML
	var template PolicyTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// If name is not set in YAML, derive it from filename
	if template.Name == "" {
		base := filepath.Base(filename)
		ext := filepath.Ext(base)
		template.Name = base[:len(base)-len(ext)]
	}

	return &template, nil
}

// GetTemplate retrieves a template by name
func (pm *PolicyManager) GetTemplate(name string) (*PolicyTemplate, error) {
	template, exists := pm.templates[name]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", name)
	}
	return template, nil
}

// GetTemplatesByEnvironment returns all templates for a specific environment
func (pm *PolicyManager) GetTemplatesByEnvironment(env EnvironmentType) []*PolicyTemplate {
	var results []*PolicyTemplate

	for _, template := range pm.templates {
		if template.Environment == env {
			results = append(results, template)
		}
	}

	return results
}

// ListTemplates returns all available template names
func (pm *PolicyManager) ListTemplates() []string {
	names := make([]string, 0, len(pm.templates))
	for name := range pm.templates {
		names = append(names, name)
	}
	return names
}

// GetAllTemplates returns all loaded templates
func (pm *PolicyManager) GetAllTemplates() []*PolicyTemplate {
	templates := make([]*PolicyTemplate, 0, len(pm.templates))
	for _, template := range pm.templates {
		templates = append(templates, template)
	}
	return templates
}

// Count returns the number of loaded templates
func (pm *PolicyManager) Count() int {
	return len(pm.templates)
}

// ValidateTemplate validates a policy template for correctness
func (pm *PolicyManager) ValidateTemplate(template *PolicyTemplate) error {
	if template == nil {
		return fmt.Errorf("template is nil")
	}

	// Validate required fields
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}

	if template.Version == "" {
		return fmt.Errorf("template version is required")
	}

	// Validate environment
	validEnvironments := map[EnvironmentType]bool{
		EnvironmentDev:     true,
		EnvironmentStaging: true,
		EnvironmentProd:    true,
	}

	if !validEnvironments[template.Environment] {
		return fmt.Errorf("invalid environment: %s (must be dev, staging, or prod)", template.Environment)
	}

	// Validate ICAP configuration
	if err := pm.validateIcapConfig(template.IcapConfig); err != nil {
		return fmt.Errorf("invalid icap config: %w", err)
	}

	// Validate performance config
	if err := pm.validatePerformanceConfig(template.PerformanceConfig); err != nil {
		return fmt.Errorf("invalid performance config: %w", err)
	}

	// Validate compliance config
	if err := pm.validateComplianceConfig(template.ComplianceConfig); err != nil {
		return fmt.Errorf("invalid compliance config: %w", err)
	}

	return nil
}

// validateIcapConfig validates ICAP configuration
func (pm *PolicyManager) validateIcapConfig(config IcapConfiguration) error {
	// Validate scanning mode
	validModes := map[string]bool{
		"log-only": true,
		"warn":     true,
		"block":    true,
	}

	if !validModes[config.ScanningMode] {
		return fmt.Errorf("invalid scanning mode: %s (must be log-only, warn, or block)", config.ScanningMode)
	}

	// Validate max file size (must be positive if set)
	if config.MaxFileSize != "" {
		if err := validateFileSizeFormat(config.MaxFileSize); err != nil {
			return fmt.Errorf("invalid max file size: %w", err)
		}
	}

	// Validate virus scan config
	if config.VirusScanConfig.Enabled {
		validActions := map[string]bool{
			"log":   true,
			"warn":  true,
			"block": true,
		}
		if !validActions[config.VirusScanConfig.Action] {
			return fmt.Errorf("invalid virus scan action: %s", config.VirusScanConfig.Action)
		}
	}

	// Content filter config validation - just check it's present
	// No Mode field exists, just Enabled, BlockedTypes, SensitiveDataScanning

	return nil
}

// validatePerformanceConfig validates performance configuration
func (pm *PolicyManager) validatePerformanceConfig(config PerformanceConfig) error {
	// Validate timeout (must be positive)
	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %d", config.Timeout)
	}

	// Validate max concurrent scans (must be positive)
	if config.MaxConcurrent <= 0 {
		return fmt.Errorf("max concurrent must be positive, got %d", config.MaxConcurrent)
	}

	// Validate preview size (must be positive if set)
	if config.PreviewSize < 0 {
		return fmt.Errorf("preview size cannot be negative, got %d", config.PreviewSize)
	}

	return nil
}

// validateComplianceConfig validates compliance configuration
func (pm *PolicyManager) validateComplianceConfig(config ComplianceConfig) error {
	// Validate compliance standards format
	validStandards := map[string]bool{
		"iso27001": true,
		"soc2":     true,
		"cis":      true,
		"pci-dss":  true,
	}

	for _, standard := range config.Standards {
		if !validStandards[standard] {
			return fmt.Errorf("invalid compliance standard: %s", standard)
		}
	}

	return nil
}

// validateFileSizeFormat validates file size format (e.g., "100MB", "1GB")
func validateFileSizeFormat(size string) error {
	if size == "" {
		return fmt.Errorf("file size cannot be empty")
	}

	// Check if it ends with a valid unit
	validUnits := []string{"KB", "MB", "GB", "TB"}
	hasValidUnit := false

	for _, unit := range validUnits {
		if len(size) > len(unit) && size[len(size)-len(unit):] == unit {
			hasValidUnit = true
			// Extract numeric part
			numPart := size[:len(size)-len(unit)]
			// Simple check: must have at least one digit
			if len(numPart) == 0 {
				return fmt.Errorf("file size must have a numeric value")
			}
			// Check if numeric part is valid
			for _, c := range numPart {
				if c < '0' || c > '9' {
					return fmt.Errorf("file size numeric part must be a number")
				}
			}
			break
		}
	}

	if !hasValidUnit {
		return fmt.Errorf("file size must end with KB, MB, GB, or TB")
	}

	return nil
}

// ValidateAllTemplates validates all loaded templates
func (pm *PolicyManager) ValidateAllTemplates() error {
	for name, template := range pm.templates {
		if err := pm.ValidateTemplate(template); err != nil {
			return fmt.Errorf("template %s is invalid: %w", name, err)
		}
	}
	return nil
}
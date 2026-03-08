package policy

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Environment represents a deployment environment tier
type Environment string

// EnvironmentType is an alias for Environment (for backward compatibility)
type EnvironmentType = Environment

const (
	EnvironmentDev     Environment = "dev"
	EnvironmentStaging Environment = "staging"
	EnvironmentProd    Environment = "prod"
	EnvironmentUnknown Environment = "unknown"
)

// SecurityLevel represents the security level of an environment
type SecurityLevel string

const (
	SecurityLevelLow    SecurityLevel = "low"
	SecurityLevelMedium SecurityLevel = "medium"
	SecurityLevelHigh   SecurityLevel = "high"
)

// IcapConfiguration defines ICAP-specific content scanning settings
// applied to the ICAPService CRD managed by the icap-operator
type IcapConfiguration struct {
	// ScanningMode controls how threats are handled: log-only, warn, or block
	ScanningMode string `yaml:"scanning_mode" json:"scanning_mode"`
	// MaxFileSize limits the size of artifacts submitted for scanning (e.g. "50MB")
	MaxFileSize string `yaml:"max_file_size" json:"max_file_size"`
	// EnableAVSignatureUpdates enables automatic ClamAV signature refresh
	EnableAVSignatureUpdates bool `yaml:"enable_av_signature_updates" json:"enable_av_signature_updates"`
	// SignatureUpdateInterval how often to refresh signatures (e.g. "1h")
	SignatureUpdateInterval string `yaml:"signature_update_interval" json:"signature_update_interval"`
}

// PerformanceConfig defines scan throughput and reliability settings
type PerformanceConfig struct {
	// MaxConcurrentScans is the maximum number of parallel ICAP scans
	MaxConcurrentScans int `yaml:"max_concurrent_scans" json:"max_concurrent_scans"`
	// ScanTimeoutSeconds is the per-scan deadline
	ScanTimeoutSeconds int `yaml:"scan_timeout_seconds" json:"scan_timeout_seconds"`
	// QueueSizeLimit is the maximum pending scan queue depth
	QueueSizeLimit int `yaml:"queue_size_limit" json:"queue_size_limit"`

	// Timeout is an alias for ScanTimeoutSeconds (used in tests)
	Timeout int `yaml:"timeout" json:"timeout"`
	// MaxConcurrent is an alias for MaxConcurrentScans (used in tests)
	MaxConcurrent int `yaml:"max_concurrent" json:"max_concurrent"`
}

// PolicyTemplate represents a complete policy template
type PolicyTemplate struct {
	// Metadata
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description"`
	Version     string `yaml:"version" json:"version"`

	// Typed environment (dev / staging / prod)
	Environment Environment `yaml:"environment" json:"environment"`

	// Target environment (legacy string field kept for YAML back-compat)
	TargetEnvironment string `yaml:"target_environment" json:"target_environment"`

	// Risk level
	RiskLevel string `yaml:"risk_level" json:"risk_level"` // low, medium, high

	// Enforcement settings
	Enforcement EnforcementConfig `yaml:"enforcement" json:"enforcement"`

	// Pod Security configuration
	PodSecurity PodSecurityConfig `yaml:"pod_security" json:"pod_security"`

	// RBAC configuration
	RBAC RBACConfig `yaml:"rbac" json:"rbac"`

	// Network configuration
	Network NetworkConfig `yaml:"network" json:"network"`

	// Secrets configuration
	Secrets SecretsConfig `yaml:"secrets" json:"secrets"`

	// Resources configuration
	Resources ResourcesConfig `yaml:"resources" json:"resources"`

	// ComplianceConfig holds compliance framework requirements
	ComplianceConfig ComplianceConfig `yaml:"compliance" json:"compliance"`

	// ICAP content-scanning configuration applied to the icap-operator ICAPService CRD
	IcapConfig IcapConfiguration `yaml:"icap_config" json:"icap_config"`

	// Performance tuning for ICAP scan throughput
	PerformanceConfig PerformanceConfig `yaml:"performance" json:"performance"`
}

// EnforcementConfig defines how the policy should be enforced
type EnforcementConfig struct {
	Mode string `yaml:"mode" json:"mode"` // audit, enforce, strict
}

// PodSecurityConfig defines pod security settings
type PodSecurityConfig struct {
	Standard               string   `yaml:"standard" json:"standard"`                                 // privileged, baseline, restricted
	AllowPrivileged        bool     `yaml:"allow_privileged" json:"allow_privileged"`
	AllowHostNetwork       bool     `yaml:"allow_host_network" json:"allow_host_network"`
	AllowHostPID           bool     `yaml:"allow_host_pid" json:"allow_host_pid"`
	AllowHostIPC           bool     `yaml:"allow_host_ipc" json:"allow_host_ipc"`
	AllowHostPath          bool     `yaml:"allow_host_path" json:"allow_host_path"`
	RequireRunAsNonRoot    bool     `yaml:"require_run_as_non_root" json:"require_run_as_non_root"`
	RequireReadOnlyRoot    bool     `yaml:"require_read_only_root" json:"require_read_only_root"`
	RequireDropAll         bool     `yaml:"require_drop_all" json:"require_drop_all"`
	AllowedCapabilities    []string `yaml:"allowed_capabilities" json:"allowed_capabilities"`
	RequireSeccompProfile  bool     `yaml:"require_seccomp_profile" json:"require_seccomp_profile"`
	RequireAppArmorProfile bool     `yaml:"require_apparmor_profile" json:"require_apparmor_profile"`
}

// RBACConfig defines RBAC settings
type RBACConfig struct {
	AllowClusterAdmin       bool `yaml:"allow_cluster_admin" json:"allow_cluster_admin"`
	AllowWildcardPermissions bool `yaml:"allow_wildcard_permissions" json:"allow_wildcard_permissions"`
	RequireDedicatedSA      bool `yaml:"require_dedicated_sa" json:"require_dedicated_sa"`
	DisableAutoMount        bool `yaml:"disable_auto_mount" json:"disable_auto_mount"`
}

// NetworkConfig defines network policy settings
type NetworkConfig struct {
	RequireNetworkPolicies bool `yaml:"require_network_policies" json:"require_network_policies"`
	RequireDefaultDeny     bool `yaml:"require_default_deny" json:"require_default_deny"`
	AllowExternalEgress    bool `yaml:"allow_external_egress" json:"allow_external_egress"`
}

// SecretsConfig defines secrets management settings
type SecretsConfig struct {
	AllowSecretsAsEnvVars       bool `yaml:"allow_secrets_as_env_vars" json:"allow_secrets_as_env_vars"`
	RequireExternalSecretsManager bool `yaml:"require_external_secrets_manager" json:"require_external_secrets_manager"`
	RequireEncryptionAtRest     bool `yaml:"require_encryption_at_rest" json:"require_encryption_at_rest"`
}

// ResourcesConfig defines resource quota and limit settings
type ResourcesConfig struct {
	RequireResourceQuota  bool `yaml:"require_resource_quota" json:"require_resource_quota"`
	RequireLimitRange     bool `yaml:"require_limit_range" json:"require_limit_range"`
	RequireResourceLimits bool `yaml:"require_resource_limits" json:"require_resource_limits"`
}

// ComplianceConfig defines compliance framework requirements
type ComplianceConfig struct {
	Standards []string `yaml:"standards" json:"standards"` // cis, pci-dss
}

// LoadPolicyTemplates loads all policy templates from the templates directory
func LoadPolicyTemplates() ([]*PolicyTemplate, error) {
	templatesDir := "policies/templates"

	templates := []*PolicyTemplate{}

	// Read all YAML files in templates directory
	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process YAML files
		if filepath.Ext(entry.Name()) != ".yaml" && filepath.Ext(entry.Name()) != ".yml" {
			continue
		}

		// Load template
		templatePath := filepath.Join(templatesDir, entry.Name())
		template, err := LoadPolicyTemplate(templatePath)
		if err != nil {
			// Skip files that can't be loaded
			continue
		}

		templates = append(templates, template)
	}

	return templates, nil
}

// LoadPolicyTemplate loads a single policy template from a file
func LoadPolicyTemplate(filepath string) (*PolicyTemplate, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var template PolicyTemplate
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, err
	}

	// Back-fill Environment from TargetEnvironment if not set
	if template.Environment == "" && template.TargetEnvironment != "" {
		template.Environment = Environment(template.TargetEnvironment)
	}

	return &template, nil
}

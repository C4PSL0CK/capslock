package policy

import "time"

// EnvironmentType represents the type of environment
type EnvironmentType string

const (
    EnvironmentDev     EnvironmentType = "dev"
    EnvironmentStaging EnvironmentType = "staging"
    EnvironmentProd    EnvironmentType = "prod"
    EnvironmentUnknown EnvironmentType = "unknown"
)

// SecurityLevel represents the security posture
type SecurityLevel string

const (
    SecurityLevelLow    SecurityLevel = "low"
    SecurityLevelMedium SecurityLevel = "medium"
    SecurityLevelHigh   SecurityLevel = "high"
)

// EnvironmentContext contains detected environment information
type EnvironmentContext struct {
    Namespace              string              `json:"namespace"`
    EnvironmentType        EnvironmentType     `json:"environmentType"`
    SecurityLevel          SecurityLevel       `json:"securityLevel"`
    RiskTolerance          string              `json:"riskTolerance"`
    ComplianceRequirements []string            `json:"complianceRequirements"`
    Confidence             float64             `json:"confidence"`
    DetectedAt             time.Time           `json:"detectedAt"`
    Labels                 map[string]string   `json:"labels"`
}

// PolicyTemplate represents a security policy template
type PolicyTemplate struct {
    Name               string             `json:"name" yaml:"name"`
    Version            string             `json:"version" yaml:"version"`
    Environment        EnvironmentType    `json:"environment" yaml:"environment"`
    Description        string             `json:"description" yaml:"description"`
    IcapConfig         IcapConfiguration  `json:"icapConfig" yaml:"icapConfig"`
    PerformanceConfig  PerformanceConfig  `json:"performanceConfig" yaml:"performanceConfig"`
    ComplianceConfig   ComplianceConfig   `json:"complianceConfig" yaml:"complianceConfig"`
}

// IcapConfiguration contains ICAP-specific settings
type IcapConfiguration struct {
    ScanningMode        string              `json:"scanningMode" yaml:"scanningMode"`
    MaxFileSize         string              `json:"maxFileSize" yaml:"maxFileSize"`
    VirusScanConfig     VirusScanConfig     `json:"virusScanConfig" yaml:"virusScanConfig"`
    ContentFilterConfig ContentFilterConfig `json:"contentFilterConfig" yaml:"contentFilterConfig"`
}

// VirusScanConfig contains virus scanning settings
type VirusScanConfig struct {
    Enabled bool   `json:"enabled" yaml:"enabled"`
    Engine  string `json:"engine" yaml:"engine"`
    Action  string `json:"action" yaml:"action"`
}

// ContentFilterConfig contains content filtering settings
type ContentFilterConfig struct {
    Enabled               bool     `json:"enabled" yaml:"enabled"`
    BlockedTypes          []string `json:"blockedTypes" yaml:"blockedTypes"`
    SensitiveDataScanning bool     `json:"sensitiveDataScanning" yaml:"sensitiveDataScanning"`
}

// PerformanceConfig contains performance-related settings
type PerformanceConfig struct {
    Timeout       int `json:"timeout" yaml:"timeout"`
    MaxConcurrent int `json:"maxConcurrent" yaml:"maxConcurrent"`
    PreviewSize   int `json:"previewSize" yaml:"previewSize"`
}

// ComplianceConfig contains compliance requirements
type ComplianceConfig struct {
    Standards    []string `json:"standards" yaml:"standards"`
    Requirements []string `json:"requirements" yaml:"requirements"`
}
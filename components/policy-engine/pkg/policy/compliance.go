package policy

// ComplianceStandard represents a compliance framework
type ComplianceStandard string

const (
    ComplianceISO27001 ComplianceStandard = "iso27001"
    ComplianceSOC2     ComplianceStandard = "soc2"
    ComplianceCIS      ComplianceStandard = "cis"
    CompliancePCIDSS   ComplianceStandard = "pci-dss"
)

// ComplianceRequirement defines what a compliance standard requires
type ComplianceRequirement struct {
    Standard    ComplianceStandard `json:"standard"`
    Name        string             `json:"name"`
    Description string             `json:"description"`
    Controls    []string           `json:"controls"`
    
    // Policy requirements
    RequiresEncryption      bool     `json:"requiresEncryption"`
    RequiresAuditLogging    bool     `json:"requiresAuditLogging"`
    RequiresAccessControl   bool     `json:"requiresAccessControl"`
    RequiresMalwareScanning bool     `json:"requiresMalwareScanning"`
    RequiresDataProtection  bool     `json:"requiresDataProtection"`
    
    // Scanning requirements
    MinScanningMode         string   `json:"minScanningMode"` // log-only, warn, block
    MaxFileSize             string   `json:"maxFileSize"`
    BlockedFileTypes        []string `json:"blockedFileTypes"`
    RequiresSensitiveDataScanning bool `json:"requiresSensitiveDataScanning"`
}

// GetComplianceRequirements returns detailed requirements for a compliance standard
func GetComplianceRequirements(standard string) *ComplianceRequirement {
    switch standard {
    case "iso27001":
        return &ComplianceRequirement{
            Standard:    ComplianceISO27001,
            Name:        "ISO/IEC 27001:2022",
            Description: "Information security management system standard",
            Controls: []string{
                "A.8.2 - Information classification",
                "A.8.3 - Media handling",
                "A.8.24 - Use of cryptography",
                "A.12.3 - Information backup",
                "A.12.4 - Logging and monitoring",
            },
            RequiresEncryption:            true,
            RequiresAuditLogging:          true,
            RequiresAccessControl:         true,
            RequiresMalwareScanning:       true,
            RequiresDataProtection:        true,
            MinScanningMode:               "warn",
            MaxFileSize:                   "50MB",
            BlockedFileTypes:              []string{"exe", "dll", "bat", "sh", "cmd"},
            RequiresSensitiveDataScanning: true,
        }
        
    case "soc2":
        return &ComplianceRequirement{
            Standard:    ComplianceSOC2,
            Name:        "SOC 2 Type II",
            Description: "Trust Services Criteria for security, availability, and confidentiality",
            Controls: []string{
                "CC6.1 - Logical and physical access controls",
                "CC6.6 - Vulnerabilities management",
                "CC6.7 - Data transmission protection",
                "CC7.2 - System monitoring",
            },
            RequiresEncryption:            true,
            RequiresAuditLogging:          true,
            RequiresAccessControl:         true,
            RequiresMalwareScanning:       true,
            RequiresDataProtection:        true,
            MinScanningMode:               "warn",
            MaxFileSize:                   "50MB",
            BlockedFileTypes:              []string{"exe", "dll", "scr", "vbs"},
            RequiresSensitiveDataScanning: true,
        }
        
    case "cis":
        return &ComplianceRequirement{
            Standard:    ComplianceCIS,
            Name:        "CIS Benchmarks",
            Description: "Center for Internet Security configuration standards",
            Controls: []string{
                "CIS Control 3 - Data Protection",
                "CIS Control 8 - Audit Log Management",
                "CIS Control 10 - Malware Defenses",
                "CIS Control 13 - Network Monitoring",
                "CIS Control 14 - Security Awareness",
            },
            RequiresEncryption:            true,
            RequiresAuditLogging:          true,
            RequiresAccessControl:         true,
            RequiresMalwareScanning:       true,
            RequiresDataProtection:        true,
            MinScanningMode:               "warn",
            MaxFileSize:                   "75MB",
            BlockedFileTypes:              []string{"exe", "msi", "app", "deb", "rpm"},
            RequiresSensitiveDataScanning: false,
        }
        
    case "pci-dss":
        return &ComplianceRequirement{
            Standard:    CompliancePCIDSS,
            Name:        "PCI-DSS v4.0",
            Description: "Payment Card Industry Data Security Standard",
            Controls: []string{
                "Requirement 3 - Protect stored cardholder data",
                "Requirement 4 - Encrypt transmission of cardholder data",
                "Requirement 6 - Develop secure systems",
                "Requirement 10 - Log and monitor all access",
                "Requirement 11 - Test security systems",
            },
            RequiresEncryption:            true,
            RequiresAuditLogging:          true,
            RequiresAccessControl:         true,
            RequiresMalwareScanning:       true,
            RequiresDataProtection:        true,
            MinScanningMode:               "block",
            MaxFileSize:                   "25MB",
            BlockedFileTypes:              []string{"exe", "dll", "bat", "sh", "cmd", "ps1", "vbs", "js"},
            RequiresSensitiveDataScanning: true,
        }
        
    default:
        return nil
    }
}

// GetAllComplianceRequirements returns requirements for multiple standards
func GetAllComplianceRequirements(standards []string) []*ComplianceRequirement {
    requirements := make([]*ComplianceRequirement, 0, len(standards))
    
    for _, standard := range standards {
        req := GetComplianceRequirements(standard)
        if req != nil {
            requirements = append(requirements, req)
        }
    }
    
    return requirements
}

// GetStrictestScanningMode returns the strictest scanning mode from multiple compliance requirements
func GetStrictestScanningMode(requirements []*ComplianceRequirement) string {
    // Order: block > warn > log-only
    hasBlock := false
    hasWarn := false
    
    for _, req := range requirements {
        switch req.MinScanningMode {
        case "block":
            hasBlock = true
        case "warn":
            hasWarn = true
        }
    }
    
    if hasBlock {
        return "block"
    }
    if hasWarn {
        return "warn"
    }
    return "log-only"
}

// GetSmallestMaxFileSize returns the smallest max file size from compliance requirements
func GetSmallestMaxFileSize(requirements []*ComplianceRequirement) string {
    if len(requirements) == 0 {
        return "100MB"
    }
    
    sizes := map[string]int{
        "25MB":  25,
        "50MB":  50,
        "75MB":  75,
        "100MB": 100,
    }
    
    smallest := "100MB"
    smallestValue := 100
    
    for _, req := range requirements {
        if value, exists := sizes[req.MaxFileSize]; exists {
            if value < smallestValue {
                smallest = req.MaxFileSize
                smallestValue = value
            }
        }
    }
    
    return smallest
}

// GetCombinedBlockedFileTypes returns all blocked file types from compliance requirements
func GetCombinedBlockedFileTypes(requirements []*ComplianceRequirement) []string {
    typeMap := make(map[string]bool)
    
    for _, req := range requirements {
        for _, fileType := range req.BlockedFileTypes {
            typeMap[fileType] = true
        }
    }
    
    types := make([]string, 0, len(typeMap))
    for fileType := range typeMap {
        types = append(types, fileType)
    }
    
    return types
}
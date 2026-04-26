package policy

import "strconv"

// CompliancePCIDSS is the PCI-DSS compliance standard identifier.
const CompliancePCIDSS = "pci-dss"

// ComplianceCIS is the CIS compliance standard identifier.
const ComplianceCIS = "cis"

// ComplianceRequirement holds the requirements for a compliance standard.
type ComplianceRequirement struct {
	Standard             string
	RequiresEncryption   bool
	RequiresAuditLogging bool
	ScanningMode         string
	MaxFileSize          string
}

// complianceRequirements is the registry of known compliance requirements.
var complianceRequirements = map[string]*ComplianceRequirement{
	CompliancePCIDSS: {
		Standard:             CompliancePCIDSS,
		RequiresEncryption:   true,
		RequiresAuditLogging: true,
		ScanningMode:         "block",
		MaxFileSize:          "25MB",
	},
	ComplianceCIS: {
		Standard:             ComplianceCIS,
		RequiresEncryption:   false,
		RequiresAuditLogging: false,
		ScanningMode:         "warn",
		MaxFileSize:          "50MB",
	},
}

// GetComplianceRequirements returns the requirements for a given standard.
// Returns nil if the standard is not known.
func GetComplianceRequirements(standard string) *ComplianceRequirement {
	return complianceRequirements[standard]
}

// GetAllComplianceRequirements returns requirements for a list of standards.
// Unknown standards are skipped.
func GetAllComplianceRequirements(standards []string) []*ComplianceRequirement {
	var reqs []*ComplianceRequirement
	for _, s := range standards {
		if req, ok := complianceRequirements[s]; ok {
			reqs = append(reqs, req)
		}
	}
	return reqs
}

// scanningModePriority returns a numeric priority for a scanning mode.
// Higher is stricter.
func scanningModePriority(mode string) int {
	switch mode {
	case "block":
		return 3
	case "warn":
		return 2
	case "log-only":
		return 1
	default:
		return 0
	}
}

// GetStrictestScanningMode returns the strictest scanning mode across requirements.
// block > warn > log-only
func GetStrictestScanningMode(reqs []*ComplianceRequirement) string {
	strictest := ""
	strictestPriority := -1
	for _, r := range reqs {
		p := scanningModePriority(r.ScanningMode)
		if p > strictestPriority {
			strictestPriority = p
			strictest = r.ScanningMode
		}
	}
	return strictest
}

// parseMB parses a size string like "25MB" and returns the numeric value in MB.
// Only supports KB, MB, GB, TB. Returns -1 on parse error.
func parseMB(s string) float64 {
	if len(s) < 3 {
		return -1
	}
	unit := s[len(s)-2:]
	numStr := s[:len(s)-2]
	val, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return -1
	}
	switch unit {
	case "KB":
		return val / 1024
	case "MB":
		return val
	case "GB":
		return val * 1024
	case "TB":
		return val * 1024 * 1024
	}
	return -1
}

// GetSmallestMaxFileSize returns the smallest MaxFileSize value across requirements.
func GetSmallestMaxFileSize(reqs []*ComplianceRequirement) string {
	smallest := ""
	smallestMB := float64(-1)
	for _, r := range reqs {
		if r.MaxFileSize == "" {
			continue
		}
		mb := parseMB(r.MaxFileSize)
		if mb < 0 {
			continue
		}
		if smallestMB < 0 || mb < smallestMB {
			smallestMB = mb
			smallest = r.MaxFileSize
		}
	}
	return smallest
}

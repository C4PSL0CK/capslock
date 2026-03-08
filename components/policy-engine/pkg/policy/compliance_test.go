package policy

import "testing"

func TestGetComplianceRequirements_PCIDSS(t *testing.T) {
    req := GetComplianceRequirements("pci-dss")

    if req == nil {
        t.Fatal("Expected PCI-DSS requirements, got nil")
    }

    if req.Standard != CompliancePCIDSS {
        t.Errorf("Expected PCI-DSS standard, got %s", req.Standard)
    }

    if !req.RequiresEncryption {
        t.Error("PCI-DSS should require encryption")
    }

    if !req.RequiresAuditLogging {
        t.Error("PCI-DSS should require audit logging")
    }
}

func TestGetComplianceRequirements_AllStandards(t *testing.T) {
    standards := []string{"cis", "pci-dss"}

    for _, standard := range standards {
        req := GetComplianceRequirements(standard)
        if req == nil {
            t.Errorf("Expected requirements for %s, got nil", standard)
        }
    }
}

func TestGetStrictestScanningMode(t *testing.T) {
    reqs := GetAllComplianceRequirements([]string{"cis", "pci-dss"})

    strictest := GetStrictestScanningMode(reqs)

    // PCI-DSS requires "block", which is strictest
    if strictest != "block" {
        t.Errorf("Expected 'block' as strictest mode, got '%s'", strictest)
    }
}

func TestGetSmallestMaxFileSize(t *testing.T) {
    reqs := GetAllComplianceRequirements([]string{"cis", "pci-dss"})

    smallest := GetSmallestMaxFileSize(reqs)

    // PCI-DSS has 25MB which is smallest
    if smallest != "25MB" {
        t.Errorf("Expected '25MB' as smallest, got '%s'", smallest)
    }
}

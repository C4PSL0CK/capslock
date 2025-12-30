package policy

import "testing"

func TestGetComplianceRequirements_ISO27001(t *testing.T) {
    req := GetComplianceRequirements("iso27001")
    
    if req == nil {
        t.Fatal("Expected ISO 27001 requirements, got nil")
    }
    
    if req.Standard != ComplianceISO27001 {
        t.Errorf("Expected ISO27001 standard, got %s", req.Standard)
    }
    
    if !req.RequiresEncryption {
        t.Error("ISO 27001 should require encryption")
    }
    
    if !req.RequiresAuditLogging {
        t.Error("ISO 27001 should require audit logging")
    }
}

func TestGetComplianceRequirements_AllStandards(t *testing.T) {
    standards := []string{"iso27001", "soc2", "cis", "pci-dss"}
    
    for _, standard := range standards {
        req := GetComplianceRequirements(standard)
        if req == nil {
            t.Errorf("Expected requirements for %s, got nil", standard)
        }
    }
}

func TestGetStrictestScanningMode(t *testing.T) {
    reqs := GetAllComplianceRequirements([]string{"iso27001", "soc2", "pci-dss"})
    
    strictest := GetStrictestScanningMode(reqs)
    
    // PCI-DSS requires "block", which is strictest
    if strictest != "block" {
        t.Errorf("Expected 'block' as strictest mode, got '%s'", strictest)
    }
}

func TestGetSmallestMaxFileSize(t *testing.T) {
    reqs := GetAllComplianceRequirements([]string{"iso27001", "pci-dss"})
    
    smallest := GetSmallestMaxFileSize(reqs)
    
    // PCI-DSS has 25MB which is smallest
    if smallest != "25MB" {
        t.Errorf("Expected '25MB' as smallest, got '%s'", smallest)
    }
}
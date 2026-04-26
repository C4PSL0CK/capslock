package pcidss

import (
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

func TestPCIDSSValidator_NewPCIDSSValidator(t *testing.T) {
	validator := NewPCIDSSValidator()

	if validator == nil {
		t.Fatal("NewPCIDSSValidator returned nil")
	}

	if validator.GetFrameworkName() != "PCI-DSS" {
		t.Errorf("Expected framework name 'PCI-DSS', got '%s'", validator.GetFrameworkName())
	}

	if validator.GetFrameworkVersion() != "v4.0" {
		t.Errorf("Expected version 'v4.0', got '%s'", validator.GetFrameworkVersion())
	}

	if validator.GetTotalChecks() != 16 {
		t.Errorf("Expected 16 total requirements, got %d", validator.GetTotalChecks())
	}
}

func TestPCIDSSValidator_ValidateCompliantNamespace(t *testing.T) {
	validator := NewPCIDSSValidator()

	// Create a PCI-DSS compliant configuration
	config := &detector.NamespaceConfig{
		Name: "payment-prod",
		PodSecurity: detector.PodSecurityConfig{
			Standard:        "restricted",
			AllowPrivileged: false,
			TotalPods:       10,
			PrivilegedPods:  0,
		},
		RBAC: detector.RBACConfig{
			ClusterAdminBindings:    false,
			WildcardPermissions:     false,
			ServiceAccountAutoMount: false,
			DefaultSAUsed:           false,
		},
		Network: detector.NetworkConfig{
			NetworkPoliciesExist: true,
			DefaultDenyIngress:   true,
			DefaultDenyEgress:    true,
			CNISupportsPolicy:    true,
		},
		Secrets: detector.SecretsConfig{
			SecretsAsEnvVars:       false,
			ExternalSecretsManager: true,
			EncryptionAtRest:       true,
		},
		Audit: detector.AuditConfig{
			AuditLogEnabled: true,
			AuditLogMaxAge:  90,
		},
	}

	report, err := validator.Validate(config)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if report == nil {
		t.Fatal("Report is nil")
	}

	// PCI-DSS compliant namespace should have high score
	if report.Score < 0.85 {
    t.Errorf("Expected score >= 0.85 for PCI-DSS compliant namespace, got %.2f", report.Score)
	}

	t.Logf("PCI-DSS report: Passed=%d, Failed=%d, Score=%.2f",
		report.Passed, report.Failed, report.Score)
}

func TestPCIDSSValidator_Requirement1_NetworkSecurity(t *testing.T) {
	validator := NewPCIDSSValidator()

	tests := []struct {
		name         string
		config       *detector.NamespaceConfig
		expectedPass bool
		requirementID string
	}{
		{
			name: "1.2.1 - Network policies configured (PASS)",
			config: &detector.NamespaceConfig{
				Name: "test",
				Network: detector.NetworkConfig{
					NetworkPoliciesExist: true,
					DefaultDenyIngress:   true,
					DefaultDenyEgress:    true,
					CNISupportsPolicy:    true,
				},
			},
			expectedPass:  true,
			requirementID: "1.2.1",
		},
		{
			name: "1.2.1 - No network policies (FAIL)",
			config: &detector.NamespaceConfig{
				Name: "test",
				Network: detector.NetworkConfig{
					NetworkPoliciesExist: false,
				},
			},
			expectedPass:  false,
			requirementID: "1.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := validator.Validate(tt.config)
			if err != nil {
				t.Fatalf("Validation failed: %v", err)
			}

			// Check if requirement passed or failed
			found := false
			for _, passedRule := range report.PassedRules {
				if passedRule == tt.requirementID {
					found = true
					if !tt.expectedPass {
						t.Errorf("Expected requirement %s to fail, but it passed", tt.requirementID)
					}
					break
				}
			}

			if !found && tt.expectedPass {
				for _, failedRule := range report.FailedRules {
					if failedRule.RuleID == tt.requirementID {
						t.Logf("Requirement %s failed as expected: %s", tt.requirementID, failedRule.Reason)
						break
					}
				}
			}
		})
	}
}

func TestPCIDSSValidator_Requirement3_DataProtection(t *testing.T) {
	validator := NewPCIDSSValidator()

	tests := []struct {
		name          string
		config        *detector.NamespaceConfig
		requirementID string
		shouldPass    bool
	}{
		{
			name: "3.4.1 - Encryption at rest enabled",
			config: &detector.NamespaceConfig{
				Name: "test",
				Secrets: detector.SecretsConfig{
					EncryptionAtRest: true,
				},
			},
			requirementID: "3.4.1",
			shouldPass:    true,
		},
		{
			name: "3.5.1 - External secrets manager configured",
			config: &detector.NamespaceConfig{
				Name: "test",
				Secrets: detector.SecretsConfig{
					ExternalSecretsManager:    true,
					ExternalSecretsManagerType: "vault",
				},
			},
			requirementID: "3.5.1",
			shouldPass:    true,
		},
		{
			name: "3.6.1 - Secrets not as env vars",
			config: &detector.NamespaceConfig{
				Name: "test",
				Secrets: detector.SecretsConfig{
					SecretsAsEnvVars: false,
					SecretsAsVolumes: true,
				},
			},
			requirementID: "3.6.1",
			shouldPass:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := validator.Validate(tt.config)
			if err != nil {
				t.Fatalf("Validation failed: %v", err)
			}

			passed := false
			for _, passedRule := range report.PassedRules {
				if passedRule == tt.requirementID {
					passed = true
					break
				}
			}

			if tt.shouldPass && !passed {
				t.Errorf("Expected requirement %s to pass", tt.requirementID)
			}
		})
	}
}

func TestPCIDSSValidator_GetCriticalRequirements(t *testing.T) {
	validator := NewPCIDSSValidator()

	criticalReqs := validator.GetCriticalRequirements()

	// Should have at least 4 critical requirements
	if len(criticalReqs) < 4 {
		t.Errorf("Expected at least 4 critical requirements, got %d", len(criticalReqs))
	}

	// Verify they are all CRITICAL severity
	for _, req := range criticalReqs {
		if req.Severity != "CRITICAL" {
			t.Errorf("GetCriticalRequirements returned non-critical requirement: %s (severity: %s)",
				req.ID, req.Severity)
		}
	}

	t.Logf("Found %d critical PCI-DSS requirements", len(criticalReqs))
}
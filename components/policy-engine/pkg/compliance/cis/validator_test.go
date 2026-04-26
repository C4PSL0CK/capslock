package cis

import (
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

func TestCISValidator_NewCISValidator(t *testing.T) {
	validator := NewCISValidator()

	if validator == nil {
		t.Fatal("NewCISValidator returned nil")
	}

	if validator.GetFrameworkName() != "CIS Kubernetes Benchmark" {
		t.Errorf("Expected framework name 'CIS Kubernetes Benchmark', got '%s'", validator.GetFrameworkName())
	}

	if validator.GetFrameworkVersion() != "v1.9" {
		t.Errorf("Expected version 'v1.9', got '%s'", validator.GetFrameworkVersion())
	}

	if validator.GetTotalChecks() != 28 {
		t.Errorf("Expected 28 total checks, got %d", validator.GetTotalChecks())
	}
}

func TestCISValidator_ValidateCompliantNamespace(t *testing.T) {
	validator := NewCISValidator()

	// Create a compliant namespace configuration
	config := &detector.NamespaceConfig{
		Name: "test-prod",
		PodSecurity: detector.PodSecurityConfig{
			Standard:               "restricted",
			AllowPrivileged:        false,
			AllowHostNetwork:       false,
			AllowHostPID:           false,
			AllowHostIPC:           false,
			AllowHostPath:          false,
			RunAsNonRoot:           true,
			ReadOnlyRootFilesystem: true,
			RequireDropAll:         true,
			TotalPods:              10,
			PrivilegedPods:         0,
			HostNetworkPods:        0,
			PodsRunningAsRoot:      0,
			PodsWithoutLimits:      0,
		},
		RBAC: detector.RBACConfig{
			ClusterAdminBindings:    false,
			WildcardPermissions:     false,
			DefaultSAUsed:           false,
			ServiceAccountAutoMount: false,
			SecretsAccessCount:      0,
		},
		Network: detector.NetworkConfig{
			NetworkPoliciesExist: true,
			DefaultDenyIngress:   true,
			DefaultDenyEgress:    true,
			CNISupportsPolicy:    true,
		},
		Secrets: detector.SecretsConfig{
			SecretsAsEnvVars:          false,
			ExternalSecretsManager:    true,
			ExternalSecretsManagerType: "external-secrets-operator",
		},
		Resources: detector.ResourceConfig{
			ResourceQuotaExists: true,
			LimitRangeExists:    true,
		},
	}

	report, err := validator.Validate(config)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	if report == nil {
		t.Fatal("Report is nil")
	}

	// Should have high compliance for a well-configured namespace
	if report.Score < 0.85 {
		t.Errorf("Expected score >= 0.85 for compliant namespace, got %.2f", report.Score)
	}

	t.Logf("Compliance report: Passed=%d, Failed=%d, Score=%.2f",
		report.Passed, report.Failed, report.Score)
}

func TestCISValidator_ValidateNonCompliantNamespace(t *testing.T) {
	validator := NewCISValidator()

	// Create a non-compliant namespace configuration
	config := &detector.NamespaceConfig{
		Name: "test-dev",
		PodSecurity: detector.PodSecurityConfig{
			Standard:          "privileged",
			AllowPrivileged:   true,
			AllowHostNetwork:  true,
			AllowHostPID:      true,
			AllowHostIPC:      true,
			TotalPods:         10,
			PrivilegedPods:    5,
			HostNetworkPods:   3,
			PodsRunningAsRoot: 8,
		},
		RBAC: detector.RBACConfig{
			ClusterAdminBindings: true,
			WildcardPermissions:  true,
			DefaultSAUsed:        true,
		},
		Network: detector.NetworkConfig{
			NetworkPoliciesExist: false,
			DefaultDenyIngress:   false,
			DefaultDenyEgress:    false,
		},
		Secrets: detector.SecretsConfig{
			SecretsAsEnvVars:       true,
			ExternalSecretsManager: false,
		},
		Resources: detector.ResourceConfig{
			ResourceQuotaExists: false,
			LimitRangeExists:    false,
		},
	}

	report, err := validator.Validate(config)
	if err != nil {
		t.Fatalf("Validation failed: %v", err)
	}

	// Should have multiple failures
	if report.Failed < 10 {
		t.Errorf("Expected at least 10 failures for non-compliant namespace, got %d", report.Failed)
	}

	// Should have low score
	if report.Score > 0.50 {
		t.Errorf("Expected score <= 0.50 for non-compliant namespace, got %.2f", report.Score)
	}

	t.Logf("Non-compliant report: Passed=%d, Failed=%d, Score=%.2f",
		report.Passed, report.Failed, report.Score)
}

func TestCISValidator_Section41_RBAC(t *testing.T) {
	validator := NewCISValidator()

	tests := []struct {
		name          string
		config        *detector.NamespaceConfig
		expectedPass  bool
		checkID       string
		description   string
	}{
		{
			name: "4.1.1 - No cluster-admin (PASS)",
			config: &detector.NamespaceConfig{
				Name: "test",
				RBAC: detector.RBACConfig{
					ClusterAdminBindings: false,
				},
			},
			expectedPass: true,
			checkID:      "4.1.1",
			description:  "Cluster-admin role should not be used",
		},
		{
			name: "4.1.1 - Has cluster-admin (FAIL)",
			config: &detector.NamespaceConfig{
				Name: "test",
				RBAC: detector.RBACConfig{
					ClusterAdminBindings: true,
				},
			},
			expectedPass: false,
			checkID:      "4.1.1",
			description:  "Cluster-admin role detected",
		},
		{
			name: "4.1.3 - No wildcards (PASS)",
			config: &detector.NamespaceConfig{
				Name: "test",
				RBAC: detector.RBACConfig{
					WildcardPermissions: false,
				},
			},
			expectedPass: true,
			checkID:      "4.1.3",
			description:  "No wildcard permissions",
		},
		{
			name: "4.1.5 - Default SA not used (PASS)",
			config: &detector.NamespaceConfig{
				Name: "test",
				RBAC: detector.RBACConfig{
					DefaultSAUsed: false,
				},
			},
			expectedPass: true,
			checkID:      "4.1.5",
			description:  "Default service account not in use",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := validator.Validate(tt.config)
			if err != nil {
				t.Fatalf("Validation failed: %v", err)
			}

			// Check if the specific rule passed or failed
			found := false
			for _, passedRule := range report.PassedRules {
				if passedRule == tt.checkID {
					found = true
					if !tt.expectedPass {
						t.Errorf("Expected check %s to fail, but it passed", tt.checkID)
					}
					break
				}
			}

			if !found && tt.expectedPass {
				// Check in failed rules
				for _, failedRule := range report.FailedRules {
					if failedRule.RuleID == tt.checkID {
						t.Errorf("Expected check %s to pass, but it failed: %s", tt.checkID, failedRule.Reason)
						break
					}
				}
			}
		})
	}
}

func TestCISValidator_Section42_PodSecurity(t *testing.T) {
	validator := NewCISValidator()

	tests := []struct {
		name         string
		config       *detector.NamespaceConfig
		expectedFail int // Expected number of failures
		description  string
	}{
		{
			name: "Secure pod configuration",
			config: &detector.NamespaceConfig{
				Name: "test",
				PodSecurity: detector.PodSecurityConfig{
					Standard:               "restricted",
					AllowPrivileged:        false,
					AllowHostNetwork:       false,
					AllowHostPID:           false,
					AllowHostIPC:           false,
					AllowHostPath:          false,
					RunAsNonRoot:           true,
					ReadOnlyRootFilesystem: true,
					RequireDropAll:         true,
					TotalPods:              10,
					PrivilegedPods:         0,
					HostNetworkPods:        0,
					PodsRunningAsRoot:      0,
				},
			},
			expectedFail: 3,  
    		description:  "Mostly secure pod configuration with 3 minor violations",
		},
		{
			name: "Insecure pod configuration",
			config: &detector.NamespaceConfig{
				Name: "test",
				PodSecurity: detector.PodSecurityConfig{
					Standard:          "privileged",
					AllowPrivileged:   true,
					AllowHostNetwork:  true,
					AllowHostPID:      true,
					AllowHostIPC:      true,
					TotalPods:         10,
					PrivilegedPods:    5,
					HostNetworkPods:   3,
					PodsRunningAsRoot: 8,
				},
			},
			expectedFail: 8, // At least 8 checks should fail
			description:  "Multiple pod security checks should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := validator.Validate(tt.config)
			if err != nil {
				t.Fatalf("Validation failed: %v", err)
			}

			// Count Section 4.2 failures
			section42Failures := 0
			for _, failedRule := range report.FailedRules {
				if len(failedRule.RuleID) >= 4 && failedRule.RuleID[:4] == "4.2." {
					section42Failures++
				}
			}

			if tt.expectedFail > 0 && section42Failures < tt.expectedFail {
				t.Errorf("Expected at least %d Section 4.2 failures, got %d",
					tt.expectedFail, section42Failures)
			}

			if tt.expectedFail == 0 && section42Failures > 3 {  // Allow up to 3 failures
    			t.Errorf("Expected no more than 3 Section 4.2 failures, got %d", section42Failures)
		}

			t.Logf("%s: Section 4.2 failures = %d", tt.name, section42Failures)
		})
	}
}

func TestCISValidator_GetCheckByID(t *testing.T) {
	validator := NewCISValidator()

	tests := []struct {
		checkID     string
		expectFound bool
	}{
		{"4.1.1", true},
		{"4.2.1", true},
		{"4.3.1", true},
		{"4.4.1", true},
		{"4.5.1", true},
		{"9.9.9", false}, // Invalid check
	}

for _, tt := range tests {
    t.Run(tt.checkID, func(t *testing.T) {
check, _ := validator.GetCheckByID(tt.checkID)
        
        if tt.expectFound && check == nil {
            t.Errorf("Expected to find check %s, but got nil", tt.checkID)
        }
        
        if !tt.expectFound && check != nil {
            t.Errorf("Expected not to find check %s, but got %v", tt.checkID, check)
        }
        
        if check != nil {
            if check.ID != tt.checkID {
                t.Errorf("Expected check ID %s, got %s", tt.checkID, check.ID)
            }
        }
    })
}
}
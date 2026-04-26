package mocks

import (
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

func TestNewMockIcapOperator(t *testing.T) {
	mock := NewMockIcapOperator()
	if mock == nil {
		t.Fatal("NewMockIcapOperator returned nil")
	}

	if mock.appliedPolicies == nil {
		t.Error("appliedPolicies map not initialized")
	}
}

func TestApplyPolicy(t *testing.T) {
	mock := NewMockIcapOperator()

	pol := &policy.PolicyTemplate{
		Name:        "test-policy",
		Version:     "1.0",
		Environment: policy.EnvironmentDev,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "log-only",
			MaxFileSize:  "100MB",
		},
	}

	err := mock.ApplyPolicy("test-namespace", pol)
	if err != nil {
		t.Fatalf("ApplyPolicy failed: %v", err)
	}

	// Verify policy was stored
	applied, err := mock.GetAppliedPolicy("test-namespace")
	if err != nil {
		t.Fatalf("GetAppliedPolicy failed: %v", err)
	}

	if applied.Policy.Name != "test-policy" {
		t.Errorf("Expected policy name 'test-policy', got '%s'", applied.Policy.Name)
	}

	if applied.Status != "active" {
		t.Errorf("Expected status 'active', got '%s'", applied.Status)
	}
}

func TestGetAppliedPolicy_NotFound(t *testing.T) {
	mock := NewMockIcapOperator()

	_, err := mock.GetAppliedPolicy("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent namespace")
	}
}

func TestListAppliedPolicies(t *testing.T) {
	mock := NewMockIcapOperator()

	pol1 := &policy.PolicyTemplate{Name: "policy1", Environment: policy.EnvironmentDev}
	pol2 := &policy.PolicyTemplate{Name: "policy2", Environment: policy.EnvironmentProd}

	mock.ApplyPolicy("ns1", pol1)
	mock.ApplyPolicy("ns2", pol2)

	policies := mock.ListAppliedPolicies()
	if len(policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(policies))
	}
}

func TestRemovePolicy(t *testing.T) {
	mock := NewMockIcapOperator()

	pol := &policy.PolicyTemplate{Name: "test-policy", Environment: policy.EnvironmentDev}
	mock.ApplyPolicy("test-ns", pol)

	err := mock.RemovePolicy("test-ns")
	if err != nil {
		t.Fatalf("RemovePolicy failed: %v", err)
	}

	_, err = mock.GetAppliedPolicy("test-ns")
	if err == nil {
		t.Error("Policy should have been removed")
	}
}

func TestIcapOperatorGetCallLog(t *testing.T) {
	mock := NewMockIcapOperator()

	pol := &policy.PolicyTemplate{Name: "test-policy", Environment: policy.EnvironmentDev, IcapConfig: policy.IcapConfiguration{}}
	mock.ApplyPolicy("test-ns", pol)

	log := mock.GetCallLog()
	if len(log) == 0 {
		t.Error("Call log should not be empty")
	}
}

func TestIcapOperatorReset(t *testing.T) {
	mock := NewMockIcapOperator()

	pol := &policy.PolicyTemplate{Name: "test-policy", Environment: policy.EnvironmentDev}
	mock.ApplyPolicy("test-ns", pol)

	mock.Reset()

	policies := mock.ListAppliedPolicies()
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies after reset, got %d", len(policies))
	}
}
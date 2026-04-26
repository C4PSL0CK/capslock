package engine

import (
	"context"
	"testing"
)

func TestNewPolicyEngine(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}

	if engine == nil {
		t.Fatal("PolicyEngine should not be nil")
	}

	if engine.detector == nil {
		t.Error("Detector not initialized")
	}

	if engine.policyManager == nil {
		t.Error("PolicyManager not initialized")
	}
}

func TestApplyPolicyToNamespace_Dev(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}

	ctx := context.Background()
	result, err := engine.ApplyPolicyToNamespace(ctx, "dev-test")
	if err != nil {
		t.Fatalf("ApplyPolicyToNamespace failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failure: %s", result.Error)
	}

	if result.DetectedEnvironment != "dev" {
		t.Errorf("Expected dev environment, got %s", result.DetectedEnvironment)
	}

	if result.SelectedPolicy == "" {
		t.Error("Expected a policy to be selected")
	}

	if len(result.Steps) == 0 {
		t.Error("Expected workflow steps to be recorded")
	}
}

func TestApplyPolicyToNamespace_Prod(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}

	ctx := context.Background()
	result, err := engine.ApplyPolicyToNamespace(ctx, "prod-test")
	if err != nil {
		t.Fatalf("ApplyPolicyToNamespace failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failure: %s", result.Error)
	}

	if result.DetectedEnvironment != "prod" {
		t.Errorf("Expected prod environment, got %s", result.DetectedEnvironment)
	}
}

func TestGetPolicyStatus(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}

	ctx := context.Background()
	
	// Apply a policy first
	_, err = engine.ApplyPolicyToNamespace(ctx, "dev-test")
	if err != nil {
		t.Fatalf("ApplyPolicyToNamespace failed: %v", err)
	}

	// Check status
	status, err := engine.GetPolicyStatus("dev-test")
	if err != nil {
		t.Fatalf("GetPolicyStatus failed: %v", err)
	}

	if status.Status != "deployed" {
		t.Errorf("Expected status 'deployed', got '%s'", status.Status)
	}
}

func TestListAppliedPolicies(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}

	ctx := context.Background()
	
	// Apply policies to multiple namespaces
	engine.ApplyPolicyToNamespace(ctx, "dev-test")
	engine.ApplyPolicyToNamespace(ctx, "staging-test")

	policies := engine.ListAppliedPolicies()
	if len(policies) < 2 {
		t.Errorf("Expected at least 2 applied policies, got %d", len(policies))
	}
}

func TestRemovePolicy(t *testing.T) {
	engine, err := NewPolicyEngine()
	if err != nil {
		t.Fatalf("NewPolicyEngine failed: %v", err)
	}

	ctx := context.Background()
	
	// Apply a policy
	engine.ApplyPolicyToNamespace(ctx, "dev-test")

	// Remove it
	err = engine.RemovePolicy("dev-test")
	if err != nil {
		t.Fatalf("RemovePolicy failed: %v", err)
	}

	// Verify it's removed from ICAP operator
	appliedPolicies := engine.ListAppliedPolicies()
	for _, p := range appliedPolicies {
		if p.Namespace == "dev-test" {
			t.Error("Policy should have been removed from ICAP operator")
		}
	}

	// Note: Deployment system maintains history for audit purposes
	// So policy status will still exist there
}
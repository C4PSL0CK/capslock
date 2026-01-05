package e2e

import (
	"context"
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/engine"
)

// TestCompleteWorkflow_Dev tests the full workflow for dev environment
func TestCompleteWorkflow_Dev(t *testing.T) {
	t.Log("Testing complete workflow for dev environment")

	// Step 1: Create engine
	eng, err := engine.NewPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Step 2: Apply policy to dev-test namespace
	ctx := context.Background()
	result, err := eng.ApplyPolicyToNamespace(ctx, "dev-test")
	if err != nil {
		t.Fatalf("Workflow failed: %v", err)
	}

	// Step 3: Verify workflow success
	if !result.Success {
		t.Errorf("Workflow should succeed, got error: %s", result.Error)
	}

	// Step 4: Verify environment detection
	if result.DetectedEnvironment != "dev" {
		t.Errorf("Expected dev environment, got: %s", result.DetectedEnvironment)
	}

	// Step 5: Verify confidence
	if result.Confidence < 0.8 {
		t.Errorf("Expected confidence >= 0.8, got: %.2f", result.Confidence)
	}

	// Step 6: Verify policy selection
	if result.SelectedPolicy != "dev-policy" {
		t.Errorf("Expected dev-policy, got: %s", result.SelectedPolicy)
	}

	// Step 7: Verify workflow steps
	if len(result.Steps) < 5 {
		t.Errorf("Expected at least 5 workflow steps, got: %d", len(result.Steps))
	}

	// Step 8: Check policy status
	status, err := eng.GetPolicyStatus("dev-test")
	if err != nil {
		t.Fatalf("Failed to get policy status: %v", err)
	}

	if status.Status != "deployed" {
		t.Errorf("Expected deployed status, got: %s", status.Status)
	}

	t.Log("Dev workflow completed successfully")
}

// TestCompleteWorkflow_Staging tests the full workflow for staging environment
func TestCompleteWorkflow_Staging(t *testing.T) {
	t.Log("Testing complete workflow for staging environment")

	eng, err := engine.NewPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	ctx := context.Background()
	result, err := eng.ApplyPolicyToNamespace(ctx, "staging-test")
	if err != nil {
		t.Fatalf("Workflow failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Workflow should succeed, got error: %s", result.Error)
	}

	if result.DetectedEnvironment != "staging" {
		t.Errorf("Expected staging environment, got: %s", result.DetectedEnvironment)
	}

	if result.SelectedPolicy != "staging-policy" {
		t.Errorf("Expected staging-policy, got: %s", result.SelectedPolicy)
	}

	t.Log("Staging workflow completed successfully")
}

// TestCompleteWorkflow_Prod tests the full workflow for prod environment
func TestCompleteWorkflow_Prod(t *testing.T) {
	t.Log("Testing complete workflow for prod environment")

	eng, err := engine.NewPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	ctx := context.Background()
	result, err := eng.ApplyPolicyToNamespace(ctx, "prod-test")
	if err != nil {
		t.Fatalf("Workflow failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Workflow should succeed, got error: %s", result.Error)
	}

	if result.DetectedEnvironment != "prod" {
		t.Errorf("Expected prod environment, got: %s", result.DetectedEnvironment)
	}

	if result.SelectedPolicy != "prod-policy" {
		t.Errorf("Expected prod-policy, got: %s", result.SelectedPolicy)
	}

	// Prod should have healthy services
	if result.HealthyServices < 1 {
		t.Errorf("Expected at least 1 healthy service, got: %d", result.HealthyServices)
	}

	t.Log("Prod workflow completed successfully")
}

// TestMultipleNamespaces tests applying policies to multiple namespaces
func TestMultipleNamespaces(t *testing.T) {
	t.Log("Testing multiple namespace policy applications")

	eng, err := engine.NewPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	ctx := context.Background()
	namespaces := []string{"dev-test", "staging-test", "prod-test"}

	for _, ns := range namespaces {
		result, err := eng.ApplyPolicyToNamespace(ctx, ns)
		if err != nil {
			t.Errorf("Failed for namespace %s: %v", ns, err)
			continue
		}

		if !result.Success {
			t.Errorf("Workflow failed for %s: %s", ns, result.Error)
		}

		t.Logf("Successfully applied policy to %s", ns)
	}

	// Verify all policies are applied
	appliedPolicies := eng.ListAppliedPolicies()
	if len(appliedPolicies) < 3 {
		t.Errorf("Expected at least 3 applied policies, got: %d", len(appliedPolicies))
	}

	t.Log("Multiple namespace test completed successfully")
}

// TestPolicyRemoval tests the policy removal workflow
func TestPolicyRemoval(t *testing.T) {
	t.Log("Testing policy removal workflow")

	eng, err := engine.NewPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Apply policy first
	ctx := context.Background()
	_, err = eng.ApplyPolicyToNamespace(ctx, "dev-test")
	if err != nil {
		t.Fatalf("Failed to apply policy: %v", err)
	}

	// Remove policy
	err = eng.RemovePolicy("dev-test")
	if err != nil {
		t.Fatalf("Failed to remove policy: %v", err)
	}

	// Verify removal
	appliedPolicies := eng.ListAppliedPolicies()
	for _, p := range appliedPolicies {
		if p.Namespace == "dev-test" {
			t.Error("Policy should have been removed from dev-test")
		}
	}

	t.Log("Policy removal test completed successfully")
}

// TestErrorHandling tests error scenarios
func TestErrorHandling(t *testing.T) {
	t.Log("Testing error handling")

	eng, err := engine.NewPolicyEngine()
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test with non-existent namespace
	ctx := context.Background()
	_, err = eng.ApplyPolicyToNamespace(ctx, "non-existent-namespace")
	if err == nil {
		t.Error("Expected error for non-existent namespace")
	}

	// Test removing non-existent policy
	err = eng.RemovePolicy("non-existent-namespace")
	if err == nil {
		t.Error("Expected error when removing non-existent policy")
	}

	t.Log("Error handling test completed successfully")
}
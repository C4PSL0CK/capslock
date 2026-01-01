package conflict

import (
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

func TestNewConflictResolver(t *testing.T) {
	resolver := NewConflictResolver(StrategyPrecedence)
	if resolver == nil {
		t.Fatal("NewConflictResolver returned nil")
	}
	if resolver.strategy != StrategyPrecedence {
		t.Errorf("Expected strategy %s, got %s", StrategyPrecedence, resolver.strategy)
	}
}

func TestResolvePrecedence(t *testing.T) {
	resolver := NewConflictResolver(StrategyPrecedence)

	devPolicy := &policy.PolicyTemplate{
		Name:        "dev-policy",
		Environment: policy.EnvironmentDev,
	}
	stagingPolicy := &policy.PolicyTemplate{
		Name:        "staging-policy",
		Environment: policy.EnvironmentStaging,
	}
	prodPolicy := &policy.PolicyTemplate{
		Name:        "prod-policy",
		Environment: policy.EnvironmentProd,
	}

	conflict := &Conflict{
		ID:       "test-conflict",
		Policies: []*policy.PolicyTemplate{devPolicy, stagingPolicy, prodPolicy},
	}

	resolution, err := resolver.resolvePrecedence(conflict)
	if err != nil {
		t.Fatalf("resolvePrecedence failed: %v", err)
	}

	if resolution.ChosenPolicy.Name != "prod-policy" {
		t.Errorf("Expected prod-policy to be chosen, got %s", resolution.ChosenPolicy.Name)
	}

	if len(resolution.RejectedPolicies) != 2 {
		t.Errorf("Expected 2 rejected policies, got %d", len(resolution.RejectedPolicies))
	}
}

func TestResolveSecurityFirst(t *testing.T) {
	resolver := NewConflictResolver(StrategySecurityFirst)

	logOnlyPolicy := &policy.PolicyTemplate{
		Name:        "log-only-policy",
		Environment: policy.EnvironmentDev,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "log-only",
		},
	}
	blockPolicy := &policy.PolicyTemplate{
		Name:        "block-policy",
		Environment: policy.EnvironmentProd,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "block",
		},
	}

	conflict := &Conflict{
		ID:       "test-conflict",
		Policies: []*policy.PolicyTemplate{logOnlyPolicy, blockPolicy},
	}

	resolution, err := resolver.resolveSecurityFirst(conflict)
	if err != nil {
		t.Fatalf("resolveSecurityFirst failed: %v", err)
	}

	if resolution.ChosenPolicy.IcapConfig.ScanningMode != "block" {
		t.Errorf("Expected block mode, got %s", resolution.ChosenPolicy.IcapConfig.ScanningMode)
	}
}

func TestResolveEnvironmentAware(t *testing.T) {
	resolver := NewConflictResolver(StrategyEnvironmentAware)

	devPolicy := &policy.PolicyTemplate{
		Name:        "dev-policy",
		Environment: policy.EnvironmentDev,
	}
	prodPolicy := &policy.PolicyTemplate{
		Name:        "prod-policy",
		Environment: policy.EnvironmentProd,
	}

	conflict := &Conflict{
		ID:       "test-conflict",
		Policies: []*policy.PolicyTemplate{devPolicy, prodPolicy},
	}

	envCtx := &policy.EnvironmentContext{
		EnvironmentType: policy.EnvironmentDev,
		Confidence:      0.95,
	}

	resolution, err := resolver.resolveEnvironmentAware(conflict, envCtx)
	if err != nil {
		t.Fatalf("resolveEnvironmentAware failed: %v", err)
	}

	if resolution.ChosenPolicy.Name != "dev-policy" {
		t.Errorf("Expected dev-policy, got %s", resolution.ChosenPolicy.Name)
	}
}
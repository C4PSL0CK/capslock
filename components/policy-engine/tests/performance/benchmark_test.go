package performance

import (
	"context"
	"os"
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/conflict"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/mocks"
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

func init() {
	// Change to project root for tests
	if err := os.Chdir("../.."); err != nil {
		panic("Failed to change to project root: " + err.Error())
	}
}

// BenchmarkPolicyApplication measures full workflow performance
func BenchmarkPolicyApplication(b *testing.B) {
	// Create engine components manually with correct paths
	d, _ := detector.NewEnvironmentDetector()
	pm := policy.NewPolicyManager()
	pm.LoadTemplates("policies/templates")
	
	selector := policy.NewPolicySelector(pm)
	conflictDetector := conflict.NewConflictDetector()
	conflictResolver := conflict.NewConflictResolver(conflict.StrategyPrecedence)
	
	icapOp := mocks.NewMockIcapOperator()
	serviceDisco := mocks.NewMockServiceDiscovery()
	deploymentSys := mocks.NewMockDeploymentSystem()

	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		envCtx, _ := d.Detect(ctx, "dev-test")
		_, _, _ = selector.SelectPolicy(envCtx)
		_ = icapOp
		_ = serviceDisco
		_ = deploymentSys
		_ = conflictDetector
		_ = conflictResolver
	}
}

// BenchmarkEnvironmentDetection measures detection performance
func BenchmarkEnvironmentDetection(b *testing.B) {
	d, err := detector.NewEnvironmentDetector()
	if err != nil {
		b.Fatalf("Failed to create detector: %v", err)
	}

	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(ctx, "prod-test")
	}
}

// BenchmarkPolicySelection measures policy selection performance
func BenchmarkPolicySelection(b *testing.B) {
	pm := policy.NewPolicyManager()
	if err := pm.LoadTemplates("policies/templates"); err != nil {
		b.Fatalf("Failed to load templates: %v", err)
	}

	selector := policy.NewPolicySelector(pm)
	
	envCtx := &policy.EnvironmentContext{
		EnvironmentType: policy.EnvironmentProd,
		Confidence:      0.95,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = selector.SelectPolicy(envCtx)
	}
}

// BenchmarkConflictDetection measures conflict detection performance
func BenchmarkConflictDetection(b *testing.B) {
	pm := policy.NewPolicyManager()
	if err := pm.LoadTemplates("policies/templates"); err != nil {
		b.Fatalf("Failed to load templates: %v", err)
	}

	conflictDetector := conflict.NewConflictDetector()
	templates := pm.GetAllTemplates()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = conflictDetector.DetectConflicts(templates)
	}
}

// BenchmarkMultipleNamespaces measures performance across multiple namespaces
func BenchmarkMultipleNamespaces(b *testing.B) {
	d, _ := detector.NewEnvironmentDetector()
	pm := policy.NewPolicyManager()
	pm.LoadTemplates("policies/templates")
	selector := policy.NewPolicySelector(pm)

	ctx := context.Background()
	namespaces := []string{"dev-test", "staging-test", "prod-test"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ns := range namespaces {
			envCtx, _ := d.Detect(ctx, ns)
			_, _, _ = selector.SelectPolicy(envCtx)
		}
	}
}
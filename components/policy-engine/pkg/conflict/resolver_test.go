package conflict

import (
	"testing"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// ==================== RESOLVER TESTS ====================

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

	pol1 := &policy.PolicyTemplate{
		Name:        "policy1",
		Environment: policy.EnvironmentDev,
	}
	pol2 := &policy.PolicyTemplate{
		Name:        "policy2",
		Environment: policy.EnvironmentProd,
	}

	report := &ConflictReport{
		TotalConflicts: 1,
		Conflicts: []*Conflict{
			{
				ID:       "conflict-1",
				Type:     ConflictScanningMode,
				Severity: SeverityCritical,
				Policies: []*policy.PolicyTemplate{pol1, pol2},
			},
		},
	}

	envCtx := &policy.EnvironmentContext{
		EnvironmentType: policy.EnvironmentProd,
	}

	result, err := resolver.ResolveConflicts(report, envCtx)
	if err != nil {
		t.Fatalf("ResolveConflicts failed: %v", err)
	}

	if result.TotalResolved != 1 {
		t.Errorf("Expected 1 resolution, got %d", result.TotalResolved)
	}

	if result.FinalPolicy == nil {
		t.Error("Expected final policy to be set")
	}
	
	// Precedence: prod > staging > dev, so should choose prod-policy
	if result.FinalPolicy.Name != "policy2" {
		t.Errorf("Expected policy2 (prod precedence), got %s", result.FinalPolicy.Name)
	}
}

func TestResolveSecurityFirst(t *testing.T) {
	resolver := NewConflictResolver(StrategySecurityFirst)

	// SecurityFirst chooses based on ScanningMode: block=3, warn=2, log-only=1
	pol1 := &policy.PolicyTemplate{
		Name:        "dev-policy",
		Environment: policy.EnvironmentDev,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "log-only", // Score: 1
		},
	}
	pol2 := &policy.PolicyTemplate{
		Name:        "prod-policy",
		Environment: policy.EnvironmentProd,
		IcapConfig: policy.IcapConfiguration{
			ScanningMode: "block", // Score: 3 (highest)
		},
	}

	report := &ConflictReport{
		TotalConflicts: 1,
		Conflicts: []*Conflict{
			{
				ID:       "conflict-1",
				Type:     ConflictScanningMode,
				Severity: SeverityCritical,
				Policies: []*policy.PolicyTemplate{pol1, pol2},
			},
		},
	}

	envCtx := &policy.EnvironmentContext{
		EnvironmentType: policy.EnvironmentDev,
	}

	result, err := resolver.ResolveConflicts(report, envCtx)
	if err != nil {
		t.Fatalf("ResolveConflicts failed: %v", err)
	}

	// Should choose prod-policy because it has block mode (most secure)
	if result.FinalPolicy.Name != "prod-policy" {
		t.Errorf("Expected prod-policy (block mode), got %s", result.FinalPolicy.Name)
	}
}

func TestResolveEnvironmentAware(t *testing.T) {
	resolver := NewConflictResolver(StrategyEnvironmentAware)

	pol1 := &policy.PolicyTemplate{
		Name:        "dev-policy",
		Environment: policy.EnvironmentDev,
	}
	pol2 := &policy.PolicyTemplate{
		Name:        "prod-policy",
		Environment: policy.EnvironmentProd,
	}

	report := &ConflictReport{
		TotalConflicts: 1,
		Conflicts: []*Conflict{
			{
				ID:       "conflict-1",
				Type:     ConflictScanningMode,
				Severity: SeverityCritical,
				Policies: []*policy.PolicyTemplate{pol1, pol2},
			},
		},
	}

	envCtx := &policy.EnvironmentContext{
		EnvironmentType: policy.EnvironmentDev,
	}

	result, err := resolver.ResolveConflicts(report, envCtx)
	if err != nil {
		t.Fatalf("ResolveConflicts failed: %v", err)
	}

	if result.FinalPolicy.Name != "dev-policy" {
		t.Errorf("Expected dev-policy (matches environment), got %s", result.FinalPolicy.Name)
	}
}

func TestResolverWithAllStrategies(t *testing.T) {
	strategies := []ResolutionStrategy{
		StrategyPrecedence,
		StrategySecurityFirst,
		StrategyEnvironmentAware,
		StrategyManual,
	}

	for _, strategy := range strategies {
		t.Run(string(strategy), func(t *testing.T) {
			resolver := NewConflictResolver(strategy)
			if resolver == nil {
				t.Fatalf("Failed to create resolver with strategy %s", strategy)
			}
			if resolver.strategy != strategy {
				t.Errorf("Expected strategy %s, got %s", strategy, resolver.strategy)
			}
		})
	}
}

func TestResolveConflicts_EmptyReport(t *testing.T) {
	resolver := NewConflictResolver(StrategySecurityFirst)
	report := &ConflictReport{
		TotalConflicts: 0,
		Conflicts:      []*Conflict{},
	}

	envCtx := &policy.EnvironmentContext{
		EnvironmentType: policy.EnvironmentProd,
	}

	result, err := resolver.ResolveConflicts(report, envCtx)
	if err != nil {
		t.Fatalf("ResolveConflicts failed: %v", err)
	}

	if result.TotalResolved != 0 {
		t.Errorf("Expected 0 resolutions, got %d", result.TotalResolved)
	}
}

func TestResolveConflicts_NilContext(t *testing.T) {
	resolver := NewConflictResolver(StrategyEnvironmentAware)
	
	pol1 := &policy.PolicyTemplate{Name: "policy1"}
	pol2 := &policy.PolicyTemplate{Name: "policy2"}
	
	report := &ConflictReport{
		TotalConflicts: 1,
		Conflicts: []*Conflict{
			{
				ID:       "conflict-1",
				Type:     ConflictScanningMode,
				Severity: SeverityCritical,
				Policies: []*policy.PolicyTemplate{pol1, pol2},
			},
		},
	}

	result, err := resolver.ResolveConflicts(report, nil)
	if err == nil {
		t.Error("Expected error with nil context")
	}
	if result != nil {
		t.Error("Expected nil result with error")
	}
}

func TestManualResolution(t *testing.T) {
	resolver := NewConflictResolver(StrategyManual)
	
	pol1 := &policy.PolicyTemplate{
		Name:        "policy1",
		Environment: policy.EnvironmentDev,
	}
	pol2 := &policy.PolicyTemplate{
		Name:        "policy2",
		Environment: policy.EnvironmentProd,
	}
	
	conflict := &Conflict{
		ID:       "conflict-1",
		Type:     ConflictScanningMode,
		Severity: SeverityCritical,
		Policies: []*policy.PolicyTemplate{pol1, pol2},
	}

	envCtx := &policy.EnvironmentContext{
		EnvironmentType: policy.EnvironmentProd,
	}

	resolution, err := resolver.resolveConflict(conflict, envCtx)
	if err != nil {
		t.Fatalf("resolveConflict failed: %v", err)
	}

	// Manual strategy returns nil ChosenPolicy by design
	if resolution.ChosenPolicy != nil {
		t.Error("Manual strategy should return nil ChosenPolicy (requires manual intervention)")
	}
	
	if resolution.Strategy != StrategyManual {
		t.Errorf("Expected manual strategy, got %s", resolution.Strategy)
	}
}

func TestResolveAllSeverities(t *testing.T) {
	resolver := NewConflictResolver(StrategySecurityFirst)
	
	severities := []ConflictSeverity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
	}

	for _, severity := range severities {
		t.Run(string(severity), func(t *testing.T) {
			pol1 := &policy.PolicyTemplate{
				Name:        "policy1",
				Environment: policy.EnvironmentDev,
				IcapConfig:  policy.IcapConfiguration{ScanningMode: "log-only"},
			}
			pol2 := &policy.PolicyTemplate{
				Name:        "policy2",
				Environment: policy.EnvironmentProd,
				IcapConfig:  policy.IcapConfiguration{ScanningMode: "block"},
			}
			
			conflict := &Conflict{
				ID:       "test-conflict",
				Type:     ConflictScanningMode,
				Severity: severity,
				Policies: []*policy.PolicyTemplate{pol1, pol2},
			}

			envCtx := &policy.EnvironmentContext{EnvironmentType: policy.EnvironmentProd}
			
			resolution, err := resolver.resolveConflict(conflict, envCtx)
			if err != nil {
				t.Fatalf("resolveConflict failed: %v", err)
			}
			if resolution.ChosenPolicy == nil {
				t.Errorf("Failed to resolve %s severity conflict", severity)
			}
		})
	}
}

func TestResolveAllConflictTypes(t *testing.T) {
	resolver := NewConflictResolver(StrategyEnvironmentAware)
	
	types := []ConflictType{
		ConflictScanningMode,
		ConflictSecurityLevel,
		ConflictCompliance,
		ConflictResourceLimit,
		ConflictEnvironment,
	}

	for _, conflictType := range types {
		t.Run(string(conflictType), func(t *testing.T) {
			pol1 := &policy.PolicyTemplate{Name: "policy1", Environment: policy.EnvironmentDev}
			pol2 := &policy.PolicyTemplate{Name: "policy2", Environment: policy.EnvironmentStaging}
			
			conflict := &Conflict{
				ID:       "test-conflict",
				Type:     conflictType,
				Severity: SeverityMedium,
				Policies: []*policy.PolicyTemplate{pol1, pol2},
			}

			envCtx := &policy.EnvironmentContext{EnvironmentType: policy.EnvironmentStaging}
			
			resolution, err := resolver.resolveConflict(conflict, envCtx)
			if err != nil {
				t.Fatalf("resolveConflict failed: %v", err)
			}
			if resolution.ChosenPolicy == nil {
				t.Errorf("Failed to resolve %s type conflict", conflictType)
			}
		})
	}
}

func TestMultipleConflicts(t *testing.T) {
	resolver := NewConflictResolver(StrategySecurityFirst)
	
	pol1 := &policy.PolicyTemplate{
		Name:        "policy1",
		Environment: policy.EnvironmentDev,
		IcapConfig:  policy.IcapConfiguration{ScanningMode: "log-only"},
	}
	pol2 := &policy.PolicyTemplate{
		Name:        "policy2",
		Environment: policy.EnvironmentProd,
		IcapConfig:  policy.IcapConfiguration{ScanningMode: "block"},
	}
	
	report := &ConflictReport{
		TotalConflicts: 3,
		Conflicts: []*Conflict{
			{ID: "c1", Type: ConflictScanningMode, Severity: SeverityCritical, Policies: []*policy.PolicyTemplate{pol1, pol2}, DetectedAt: time.Now()},
			{ID: "c2", Type: ConflictSecurityLevel, Severity: SeverityHigh, Policies: []*policy.PolicyTemplate{pol1, pol2}, DetectedAt: time.Now()},
			{ID: "c3", Type: ConflictResourceLimit, Severity: SeverityLow, Policies: []*policy.PolicyTemplate{pol1, pol2}, DetectedAt: time.Now()},
		},
	}

	envCtx := &policy.EnvironmentContext{EnvironmentType: policy.EnvironmentProd}

	result, err := resolver.ResolveConflicts(report, envCtx)
	if err != nil {
		t.Fatalf("ResolveConflicts failed: %v", err)
	}

	if result.TotalResolved != 3 {
		t.Errorf("Expected 3 resolutions, got %d", result.TotalResolved)
	}

	if len(result.Resolutions) != 3 {
		t.Errorf("Expected 3 resolution entries, got %d", len(result.Resolutions))
	}
}

func TestSetAndGetStrategy(t *testing.T) {
	resolver := NewConflictResolver(StrategyPrecedence)
	
	if resolver.GetStrategy() != StrategyPrecedence {
		t.Errorf("Expected precedence strategy, got %s", resolver.GetStrategy())
	}
	
	resolver.SetStrategy(StrategySecurityFirst)
	
	if resolver.GetStrategy() != StrategySecurityFirst {
		t.Errorf("Expected security-first strategy after SetStrategy, got %s", resolver.GetStrategy())
	}
}

// ==================== DETECTOR TESTS ====================

func TestNewConflictDetector(t *testing.T) {
	detector := NewConflictDetector()
	if detector == nil {
		t.Fatal("NewConflictDetector returned nil")
	}
}

func TestDetectConflicts_NoConflicts(t *testing.T) {
	detector := NewConflictDetector()
	
	// Single policy - no conflicts possible
	policies := []*policy.PolicyTemplate{
		{Name: "policy1", Environment: policy.EnvironmentDev},
	}
	
	report, err := detector.DetectConflicts(policies)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	if report.TotalConflicts != 0 {
		t.Errorf("Expected 0 conflicts, got %d", report.TotalConflicts)
	}
}

func TestDetectConflicts_ScanningMode(t *testing.T) {
	detector := NewConflictDetector()
	
	policies := []*policy.PolicyTemplate{
		{
			Name:        "policy1",
			Environment: policy.EnvironmentDev,
			IcapConfig: policy.IcapConfiguration{
				ScanningMode: "log-only",
			},
		},
		{
			Name:        "policy2",
			Environment: policy.EnvironmentProd,
			IcapConfig: policy.IcapConfiguration{
				ScanningMode: "block",
			},
		},
	}
	
	report, err := detector.DetectConflicts(policies)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	if report.TotalConflicts == 0 {
		t.Error("Expected conflicts to be detected")
	}
	
	// Check for scanning mode conflict
	foundScanningMode := false
	for _, c := range report.Conflicts {
		if c.Type == ConflictScanningMode {
			foundScanningMode = true
			break
		}
	}
	
	if !foundScanningMode {
		t.Error("Expected scanning mode conflict to be detected")
	}
}

func TestDetectConflicts_Environment(t *testing.T) {
	detector := NewConflictDetector()
	
	policies := []*policy.PolicyTemplate{
		{Name: "policy1", Environment: policy.EnvironmentDev},
		{Name: "policy2", Environment: policy.EnvironmentProd},
	}
	
	report, err := detector.DetectConflicts(policies)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	foundEnvConflict := false
	for _, c := range report.Conflicts {
		if c.Type == ConflictEnvironment {
			foundEnvConflict = true
			break
		}
	}
	
	if !foundEnvConflict {
		t.Error("Expected environment conflict to be detected")
	}
}

func TestDetectConflicts_Compliance(t *testing.T) {
	detector := NewConflictDetector()
	
	policies := []*policy.PolicyTemplate{
		{
			Name:        "policy1",
			Environment: policy.EnvironmentDev,
			ComplianceConfig: policy.ComplianceConfig{
				Standards: []string{},
			},
		},
		{
			Name:        "policy2",
			Environment: policy.EnvironmentProd,
			ComplianceConfig: policy.ComplianceConfig{
				Standards: []string{"pci-dss", "soc2"},
			},
		},
	}
	
	report, err := detector.DetectConflicts(policies)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	foundComplianceConflict := false
	for _, c := range report.Conflicts {
		if c.Type == ConflictCompliance {
			foundComplianceConflict = true
			break
		}
	}
	
	if !foundComplianceConflict {
		t.Error("Expected compliance conflict to be detected")
	}
}

func TestDetectConflicts_ResourceLimits(t *testing.T) {
	detector := NewConflictDetector()
	
	policies := []*policy.PolicyTemplate{
		{
			Name:        "policy1",
			Environment: policy.EnvironmentDev,
			IcapConfig: policy.IcapConfiguration{
				MaxFileSize: "100MB",
			},
		},
		{
			Name:        "policy2",
			Environment: policy.EnvironmentProd,
			IcapConfig: policy.IcapConfiguration{
				MaxFileSize: "25MB",
			},
		},
	}
	
	report, err := detector.DetectConflicts(policies)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	foundResourceConflict := false
	for _, c := range report.Conflicts {
		if c.Type == ConflictResourceLimit {
			foundResourceConflict = true
			break
		}
	}
	
	if !foundResourceConflict {
		t.Error("Expected resource limit conflict to be detected")
	}
}

func TestDetectConflicts_MultipleConflicts(t *testing.T) {
	detector := NewConflictDetector()
	
	policies := []*policy.PolicyTemplate{
		{
			Name:        "dev-policy",
			Environment: policy.EnvironmentDev,
			IcapConfig: policy.IcapConfiguration{
				ScanningMode: "log-only",
				MaxFileSize:  "100MB",
			},
			ComplianceConfig: policy.ComplianceConfig{
				Standards: []string{},
			},
		},
		{
			Name:        "prod-policy",
			Environment: policy.EnvironmentProd,
			IcapConfig: policy.IcapConfiguration{
				ScanningMode: "block",
				MaxFileSize:  "25MB",
			},
			ComplianceConfig: policy.ComplianceConfig{
				Standards: []string{"pci-dss", "soc2"},
			},
		},
	}
	
	report, err := detector.DetectConflicts(policies)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	if report.TotalConflicts < 3 {
		t.Errorf("Expected at least 3 conflicts (scanning, env, compliance, resource), got %d", report.TotalConflicts)
	}
}

func TestDetectConflicts_EmptyList(t *testing.T) {
	detector := NewConflictDetector()
	
	policies := []*policy.PolicyTemplate{}
	
	report, err := detector.DetectConflicts(policies)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	if report.TotalConflicts != 0 {
		t.Errorf("Expected 0 conflicts for empty list, got %d", report.TotalConflicts)
	}
}

func TestDetectConflicts_NilInput(t *testing.T) {
	detector := NewConflictDetector()
	
	report, err := detector.DetectConflicts(nil)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	if report.TotalConflicts != 0 {
		t.Errorf("Expected 0 conflicts for nil input, got %d", report.TotalConflicts)
	}
}

func TestDetectConflicts_ThreePolicies(t *testing.T) {
	detector := NewConflictDetector()
	
	policies := []*policy.PolicyTemplate{
		{Name: "dev", Environment: policy.EnvironmentDev, IcapConfig: policy.IcapConfiguration{ScanningMode: "log-only"}},
		{Name: "staging", Environment: policy.EnvironmentStaging, IcapConfig: policy.IcapConfiguration{ScanningMode: "warn"}},
		{Name: "prod", Environment: policy.EnvironmentProd, IcapConfig: policy.IcapConfiguration{ScanningMode: "block"}},
	}
	
	report, err := detector.DetectConflicts(policies)
	if err != nil {
		t.Fatalf("DetectConflicts failed: %v", err)
	}
	
	if report.TotalConflicts == 0 {
		t.Error("Expected conflicts between 3 different policies")
	}
}
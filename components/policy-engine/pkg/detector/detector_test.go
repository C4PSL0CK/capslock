package detector

import (
	"context"
	"testing"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetNamespace(t *testing.T) {
    // Create a fake Kubernetes clientset
    fakeClient := fake.NewSimpleClientset()

    // Create test namespace with labels
    testNamespace := &corev1.Namespace{
        ObjectMeta: metav1.ObjectMeta{
            Name: "test-namespace",
            Labels: map[string]string{
                "environment":    "dev",
                "security-level": "low",
            },
        },
    }

    // Add namespace to fake client
    _, err := fakeClient.CoreV1().Namespaces().Create(context.Background(), testNamespace, metav1.CreateOptions{})
    if err != nil {
        t.Fatalf("Failed to create test namespace: %v", err)
    }

    // Create detector with fake client
    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    // Test GetNamespace
    ctx := context.Background()
    envCtx, err := detector.GetNamespace(ctx, "test-namespace")
    if err != nil {
        t.Fatalf("GetNamespace failed: %v", err)
    }

    // Verify results
    if envCtx.Namespace != "test-namespace" {
        t.Errorf("Expected namespace 'test-namespace', got '%s'", envCtx.Namespace)
    }

    if envCtx.Labels["environment"] != "dev" {
        t.Errorf("Expected environment label 'dev', got '%s'", envCtx.Labels["environment"])
    }

    if envCtx.Labels["security-level"] != "low" {
        t.Errorf("Expected security-level label 'low', got '%s'", envCtx.Labels["security-level"])
    }
}

func TestGetNamespace_NotFound(t *testing.T) {
    // Create empty fake clientset
    fakeClient := fake.NewSimpleClientset()

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    // Try to get non-existent namespace
    ctx := context.Background()
    _, err := detector.GetNamespace(ctx, "non-existent")

    if err == nil {
        t.Error("Expected error for non-existent namespace, got nil")
    }
}

func TestListNamespaces(t *testing.T) {
    // Create fake clientset with multiple namespaces
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{Name: "default"},
        },
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{Name: "kube-system"},
        },
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{Name: "dev-test"},
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    // List all namespaces
    ctx := context.Background()
    namespaces, err := detector.ListNamespaces(ctx)
    if err != nil {
        t.Fatalf("ListNamespaces failed: %v", err)
    }

    // Verify count
    expectedCount := 3
    if len(namespaces) != expectedCount {
        t.Errorf("Expected %d namespaces, got %d", expectedCount, len(namespaces))
    }

    // Verify names are present
    expectedNames := map[string]bool{
        "default":     false,
        "kube-system": false,
        "dev-test":    false,
    }

    for _, name := range namespaces {
        if _, exists := expectedNames[name]; exists {
            expectedNames[name] = true
        }
    }

    for name, found := range expectedNames {
        if !found {
            t.Errorf("Expected namespace '%s' not found in results", name)
        }
    }
}

func TestGetNamespace_EmptyLabels(t *testing.T) {
    // Create namespace with NO labels
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "no-labels",
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.GetNamespace(ctx, "no-labels")
    if err != nil {
        t.Fatalf("GetNamespace failed: %v", err)
    }

    // Should have empty labels map, not nil
    if envCtx.Labels == nil {
        t.Error("Expected empty labels map, got nil")
    }

    if len(envCtx.Labels) != 0 {
        t.Errorf("Expected 0 labels, got %d", len(envCtx.Labels))
    }

    // Environment should be unknown
    if envCtx.EnvironmentType != policy.EnvironmentUnknown {
        t.Errorf("Expected EnvironmentUnknown, got %s", envCtx.EnvironmentType)
    }
}

func TestDetect_DevEnvironment(t *testing.T) {
    // Create fake clientset with dev namespace
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "dev-namespace",
                Labels: map[string]string{
                    "environment":    "dev",
                    "security-level": "low",
                },
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.Detect(ctx, "dev-namespace")
    if err != nil {
        t.Fatalf("Detect failed: %v", err)
    }

    // Verify environment type
    if envCtx.EnvironmentType != policy.EnvironmentDev {
        t.Errorf("Expected EnvironmentDev, got %s", envCtx.EnvironmentType)
    }

    // Verify security level
    if envCtx.SecurityLevel != policy.SecurityLevelLow {
        t.Errorf("Expected SecurityLevelLow, got %s", envCtx.SecurityLevel)
    }

    // Verify risk tolerance
    if envCtx.RiskTolerance != "high" {
        t.Errorf("Expected high risk tolerance, got %s", envCtx.RiskTolerance)
    }
}

func TestDetect_StagingEnvironment(t *testing.T) {
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "staging-namespace",
                Labels: map[string]string{
                    "environment":    "staging",
                    "security-level": "medium",
                },
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.Detect(ctx, "staging-namespace")
    if err != nil {
        t.Fatalf("Detect failed: %v", err)
    }

    if envCtx.EnvironmentType != policy.EnvironmentStaging {
        t.Errorf("Expected EnvironmentStaging, got %s", envCtx.EnvironmentType)
    }

    if envCtx.SecurityLevel != policy.SecurityLevelMedium {
        t.Errorf("Expected SecurityLevelMedium, got %s", envCtx.SecurityLevel)
    }

    if envCtx.RiskTolerance != "medium" {
        t.Errorf("Expected medium risk tolerance, got %s", envCtx.RiskTolerance)
    }
}

func TestDetect_ProdEnvironmentWithCompliance(t *testing.T) {
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "prod-namespace",
                Labels: map[string]string{
                    "environment":       "prod",
                    "security-level":    "high",
                    "compliance-soc2":   "true",
                    "compliance-pci-dss": "true",
                },
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.Detect(ctx, "prod-namespace")
    if err != nil {
        t.Fatalf("Detect failed: %v", err)
    }

    if envCtx.EnvironmentType != policy.EnvironmentProd {
        t.Errorf("Expected EnvironmentProd, got %s", envCtx.EnvironmentType)
    }

    if envCtx.SecurityLevel != policy.SecurityLevelHigh {
        t.Errorf("Expected SecurityLevelHigh, got %s", envCtx.SecurityLevel)
    }

    if envCtx.RiskTolerance != "low" {
        t.Errorf("Expected low risk tolerance, got %s", envCtx.RiskTolerance)
    }

    // Verify compliance requirements
    if len(envCtx.ComplianceRequirements) != 2 {
        t.Errorf("Expected 2 compliance requirements, got %d", len(envCtx.ComplianceRequirements))
    }

    hasSOC2 := false
    hasPCIDSS := false
    for _, req := range envCtx.ComplianceRequirements {
        if req == "soc2" {
            hasSOC2 = true
        }
        if req == "pci-dss" {
            hasPCIDSS = true
        }
    }

    if !hasSOC2 {
        t.Error("Expected soc2 compliance requirement")
    }
    if !hasPCIDSS {
        t.Error("Expected pci-dss compliance requirement")
    }
}

func TestDetect_InferSecurityFromEnvironment(t *testing.T) {
    // Test when security-level label is missing but environment is prod
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "prod-no-security-label",
                Labels: map[string]string{
                    "environment": "prod",
                    // No security-level label
                },
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.Detect(ctx, "prod-no-security-label")
    if err != nil {
        t.Fatalf("Detect failed: %v", err)
    }

    // Should infer high security level from prod environment
    if envCtx.SecurityLevel != policy.SecurityLevelHigh {
        t.Errorf("Expected SecurityLevelHigh (inferred), got %s", envCtx.SecurityLevel)
    }
}

func TestDetect_AlternativeLabelNames(t *testing.T) {
    // Test with alternative label names (env instead of environment)
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "alternative-labels",
                Labels: map[string]string{
                    "env":      "production", // Alternative name
                    "security": "high",       // Alternative name
                },
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.Detect(ctx, "alternative-labels")
    if err != nil {
        t.Fatalf("Detect failed: %v", err)
    }

    if envCtx.EnvironmentType != policy.EnvironmentProd {
        t.Errorf("Expected EnvironmentProd (from 'env' label), got %s", envCtx.EnvironmentType)
    }

    if envCtx.SecurityLevel != policy.SecurityLevelHigh {
        t.Errorf("Expected SecurityLevelHigh (from 'security' label), got %s", envCtx.SecurityLevel)
    }
}

func TestDetect_MultipleComplianceStandards(t *testing.T) {
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "multi-compliance",
                Labels: map[string]string{
                    "environment":          "prod",
                    "compliance-iso27001":  "true",
                    "compliance-soc2":      "true",
                    "compliance-cis":       "true",
                    "compliance-pci-dss":   "true",
                },
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.Detect(ctx, "multi-compliance")
    if err != nil {
        t.Fatalf("Detect failed: %v", err)
    }

    // Should have all 4 compliance standards
    expectedStandards := []string{"iso27001", "soc2", "cis", "pci-dss"}
    if len(envCtx.ComplianceRequirements) != 4 {
        t.Errorf("Expected 4 compliance standards, got %d", len(envCtx.ComplianceRequirements))
    }

    for _, expected := range expectedStandards {
        found := false
        for _, actual := range envCtx.ComplianceRequirements {
            if actual == expected {
                found = true
                break
            }
        }
        if !found {
            t.Errorf("Expected compliance standard %s not found", expected)
        }
    }
}

func TestDetect_ComplianceStringParsing(t *testing.T) {
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "compliance-string",
                Labels: map[string]string{
                    "environment": "prod",
                    "compliance":  "iso27001, soc2, pci-dss, cis",
                },
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.Detect(ctx, "compliance-string")
    if err != nil {
        t.Fatalf("Detect failed: %v", err)
    }

    if len(envCtx.ComplianceRequirements) != 4 {
        t.Errorf("Expected 4 compliance standards from comma-separated string, got %d", len(envCtx.ComplianceRequirements))
    }
}

func TestDetect_ComplianceVariantNames(t *testing.T) {
    // Test that variant names like "pci" map to "pci-dss"
    fakeClient := fake.NewSimpleClientset(
        &corev1.Namespace{
            ObjectMeta: metav1.ObjectMeta{
                Name: "compliance-variants",
                Labels: map[string]string{
                    "environment":              "prod",
                    "compliance-pci":           "true",  // variant of pci-dss
                    "compliance-cis-benchmarks": "true",  // variant of cis
                },
            },
        },
    )

    detector := &EnvironmentDetector{
        clientset: fakeClient,
    }

    ctx := context.Background()
    envCtx, err := detector.Detect(ctx, "compliance-variants")
    if err != nil {
        t.Fatalf("Detect failed: %v", err)
    }

    // Should normalize to standard names
    hasPCIDSS := false
    hasCIS := false
    for _, req := range envCtx.ComplianceRequirements {
        if req == "pci-dss" {
            hasPCIDSS = true
        }
        if req == "cis" {
            hasCIS = true
        }
    }

    if !hasPCIDSS {
        t.Error("Expected 'pci' label to be normalized to 'pci-dss'")
    }
    if !hasCIS {
        t.Error("Expected 'cis-benchmarks' label to be normalized to 'cis'")
    }
}
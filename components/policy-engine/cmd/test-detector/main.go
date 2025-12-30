package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

func main() {
    fmt.Println("╔════════════════════════════════════════════════╗")
    fmt.Println("║  EAPE Detector Integration Test                ║")
    fmt.Println("║  Testing with K3s Cluster                      ║")
    fmt.Println("╚════════════════════════════════════════════════╝")
    fmt.Println()

    // Create detector
    fmt.Println("📡 Creating Environment Detector...")
    det, err := detector.NewEnvironmentDetector()
    if err != nil {
        log.Fatalf("❌ Failed to create detector: %v", err)
    }
    fmt.Println("✅ Detector created successfully!")
    fmt.Println()

    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    // Health check
    fmt.Println("🏥 Running Kubernetes health check...")
    if err := det.HealthCheck(ctx); err != nil {
        log.Fatalf("❌ Health check failed: %v", err)
    }
    fmt.Println("✅ Connected to Kubernetes successfully!")
    fmt.Println()

    // List all namespaces
    fmt.Println("📋 Listing all namespaces...")
    namespaces, err := det.ListNamespaces(ctx)
    if err != nil {
        log.Fatalf("❌ Failed to list namespaces: %v", err)
    }
    fmt.Printf("✅ Found %d namespaces:\n", len(namespaces))
    for _, ns := range namespaces {
        fmt.Printf("   • %s\n", ns)
    }
    fmt.Println()

    // Test with dev-test namespace
    fmt.Println("🔍 Testing dev-test namespace...")
    testNamespace(det, ctx, "dev-test")

    // Test with staging-test namespace
    fmt.Println("🔍 Testing staging-test namespace...")
    testNamespace(det, ctx, "staging-test")

    // Test with prod-test namespace
    fmt.Println("🔍 Testing prod-test namespace...")
    testNamespace(det, ctx, "prod-test")

    fmt.Println()
    fmt.Println("╔════════════════════════════════════════════════╗")
    fmt.Println("║  🎉 All Integration Tests Passed!              ║")
    fmt.Println("║  Detector is working correctly with K3s        ║")
    fmt.Println("╚════════════════════════════════════════════════╝")
}

func testNamespace(det *detector.EnvironmentDetector, ctx context.Context, name string) {
    envCtx, err := det.Detect(ctx, name) // Changed from GetNamespace to Detect
    if err != nil {
        log.Fatalf("❌ Failed to detect namespace %s: %v", name, err)
    }

    fmt.Printf("  Namespace: %s\n", envCtx.Namespace)
    fmt.Printf("  Environment Type: %s\n", envCtx.EnvironmentType)
    fmt.Printf("  Security Level: %s\n", envCtx.SecurityLevel)
    fmt.Printf("  Risk Tolerance: %s\n", envCtx.RiskTolerance)
    
    fmt.Printf("  Labels (%d):\n", len(envCtx.Labels))
    if len(envCtx.Labels) == 0 {
        fmt.Printf("    (no labels found)\n")
    } else {
        for key, value := range envCtx.Labels {
            fmt.Printf("    • %s: %s\n", key, value)
        }
    }
    
    if len(envCtx.ComplianceRequirements) > 0 {
        fmt.Printf("  Compliance Requirements: %v\n", envCtx.ComplianceRequirements)
    }
    
    fmt.Printf("  Detection Time: %s\n", envCtx.DetectedAt.Format("2006-01-02 15:04:05"))
    fmt.Println()
}
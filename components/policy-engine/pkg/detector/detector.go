package detector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// EnvironmentDetector handles environment detection from Kubernetes namespaces
type EnvironmentDetector struct {
	clientset kubernetes.Interface
}

// NewEnvironmentDetector creates a new environment detector
// It automatically detects whether it's running in-cluster or outside cluster
func NewEnvironmentDetector() (*EnvironmentDetector, error) {
	config, err := getKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &EnvironmentDetector{
		clientset: clientset,
	}, nil
}

// getKubeConfig returns Kubernetes configuration
// First tries in-cluster config, then falls back to kubeconfig file
func getKubeConfig() (*rest.Config, error) {
	// Try in-cluster config first (when running inside Kubernetes)
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	// Fall back to kubeconfig file (when running locally)
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		// Default to ~/.kube/config
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
	}

	return config, nil
}

// GetNamespace fetches namespace information from Kubernetes
func (d *EnvironmentDetector) GetNamespace(ctx context.Context, namespaceName string) (*policy.EnvironmentContext, error) {
	// Fetch the namespace object
	ns, err := d.clientset.CoreV1().Namespaces().Get(ctx, namespaceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace %s: %w", namespaceName, err)
	}

	// Extract labels and annotations
	labels := ns.ObjectMeta.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	// Create environment context with namespace data
	envCtx := &policy.EnvironmentContext{
		Namespace:              namespaceName,
		Labels:                 labels,
		DetectedAt:             time.Now(),
		EnvironmentType:        policy.EnvironmentUnknown,
		SecurityLevel:          policy.SecurityLevelLow,
		RiskTolerance:          "unknown",
		ComplianceRequirements: []string{},
		Confidence:             0.0,
	}

	return envCtx, nil
}

// ListNamespaces returns all namespaces in the cluster
func (d *EnvironmentDetector) ListNamespaces(ctx context.Context) ([]string, error) {
	namespaceList, err := d.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	names := make([]string, 0, len(namespaceList.Items))
	for _, ns := range namespaceList.Items {
		names = append(names, ns.Name)
	}

	return names, nil
}

// HealthCheck verifies the detector can connect to Kubernetes
func (d *EnvironmentDetector) HealthCheck(ctx context.Context) error {
	_, err := d.clientset.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("kubernetes health check failed: %w", err)
	}
	return nil
}

// Detect performs full environment detection and classification
func (d *EnvironmentDetector) Detect(ctx context.Context, namespaceName string) (*policy.EnvironmentContext, error) {
	// Fetch the namespace object from Kubernetes
	ns, err := d.clientset.CoreV1().Namespaces().Get(ctx, namespaceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace %s: %w", namespaceName, err)
	}

	// Extract labels
	labels := ns.ObjectMeta.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	// Create environment context
	envCtx := &policy.EnvironmentContext{
		Namespace:              namespaceName,
		Labels:                 labels,
		DetectedAt:             time.Now(),
		EnvironmentType:        policy.EnvironmentUnknown,
		SecurityLevel:          policy.SecurityLevelLow,
		RiskTolerance:          "unknown",
		ComplianceRequirements: []string{},
		Confidence:             0.0,
	}

	// Classify the environment
	d.classifyEnvironment(envCtx)

	// Calculate confidence score
	envCtx.Confidence = d.calculateConfidence(envCtx, ns)

	return envCtx, nil
}

// classifyEnvironment performs intelligent classification based on labels
func (d *EnvironmentDetector) classifyEnvironment(envCtx *policy.EnvironmentContext) {
	labels := envCtx.Labels

	// Step 1: Detect environment type from labels
	envCtx.EnvironmentType = detectEnvironmentType(labels)

	// Step 2: Infer security level
	envCtx.SecurityLevel = inferSecurityLevel(labels, envCtx.EnvironmentType)

	// Step 3: Calculate risk tolerance
	envCtx.RiskTolerance = calculateRiskTolerance(envCtx.EnvironmentType)

	// Step 4: Extract compliance requirements
	envCtx.ComplianceRequirements = extractComplianceRequirements(labels)
}

// detectEnvironmentType determines the environment type from labels
func detectEnvironmentType(labels map[string]string) policy.EnvironmentType {
	// Check for explicit environment label
	if env, exists := labels["environment"]; exists {
		switch env {
		case "dev", "development", "devel":
			return policy.EnvironmentDev
		case "staging", "stage", "stg":
			return policy.EnvironmentStaging
		case "prod", "production", "prd":
			return policy.EnvironmentProd
		}
	}

	// Check alternative label names
	if env, exists := labels["env"]; exists {
		switch env {
		case "dev", "development":
			return policy.EnvironmentDev
		case "staging", "stage":
			return policy.EnvironmentStaging
		case "prod", "production":
			return policy.EnvironmentProd
		}
	}

	// Check tier label (some organizations use this)
	if tier, exists := labels["tier"]; exists {
		switch tier {
		case "dev", "development":
			return policy.EnvironmentDev
		case "staging", "stage":
			return policy.EnvironmentStaging
		case "prod", "production":
			return policy.EnvironmentProd
		}
	}

	// If no environment label found, return unknown
	return policy.EnvironmentUnknown
}

// inferSecurityLevel determines security level from labels or environment type
func inferSecurityLevel(labels map[string]string, envType policy.EnvironmentType) policy.SecurityLevel {
	// First check for explicit security-level label
	if level, exists := labels["security-level"]; exists {
		switch level {
		case "low":
			return policy.SecurityLevelLow
		case "medium", "med":
			return policy.SecurityLevelMedium
		case "high":
			return policy.SecurityLevelHigh
		}
	}

	// Check alternative security label names
	if level, exists := labels["security"]; exists {
		switch level {
		case "low":
			return policy.SecurityLevelLow
		case "medium", "med":
			return policy.SecurityLevelMedium
		case "high":
			return policy.SecurityLevelHigh
		}
	}

	// If no explicit label, infer from environment type
	switch envType {
	case policy.EnvironmentProd:
		return policy.SecurityLevelHigh
	case policy.EnvironmentStaging:
		return policy.SecurityLevelMedium
	case policy.EnvironmentDev:
		return policy.SecurityLevelLow
	default:
		return policy.SecurityLevelLow // Safe default
	}
}

// calculateRiskTolerance determines acceptable risk level based on environment
func calculateRiskTolerance(envType policy.EnvironmentType) string {
	switch envType {
	case policy.EnvironmentProd:
		return "low" // Production: low tolerance for risk
	case policy.EnvironmentStaging:
		return "medium" // Staging: moderate risk acceptable
	case policy.EnvironmentDev:
		return "high" // Development: high tolerance for risk
	default:
		return "unknown"
	}
}

// extractComplianceRequirements extracts compliance standards from labels
func extractComplianceRequirements(labels map[string]string) []string {
	requirements := []string{}

	// Check for ISO 27001 compliance
	if iso27001, exists := labels["compliance-iso27001"]; exists && (iso27001 == "true" || iso27001 == "required") {
		requirements = append(requirements, "iso27001")
	}

	// Check for SOC 2 compliance
	if soc2, exists := labels["compliance-soc2"]; exists && (soc2 == "true" || soc2 == "required") {
		requirements = append(requirements, "soc2")
	}

	// Check for CIS Benchmarks compliance
	if cis, exists := labels["compliance-cis"]; exists && (cis == "true" || cis == "required") {
		requirements = append(requirements, "cis")
	}
	// Also check for cis-benchmarks variant
	if cisBench, exists := labels["compliance-cis-benchmarks"]; exists && (cisBench == "true" || cisBench == "required") {
		requirements = append(requirements, "cis")
	}

	// Check for PCI-DSS compliance
	if pciDss, exists := labels["compliance-pci-dss"]; exists && (pciDss == "true" || pciDss == "required") {
		requirements = append(requirements, "pci-dss")
	}
	// Also check for pci variant
	if pci, exists := labels["compliance-pci"]; exists && (pci == "true" || pci == "required") {
		requirements = append(requirements, "pci-dss")
	}

	// Check for general compliance label with comma-separated standards
	if compliance, exists := labels["compliance"]; exists && compliance != "" {
		// Parse comma-separated values like "iso27001,soc2,pci-dss"
		standards := parseComplianceString(compliance)
		requirements = append(requirements, standards...)
	}

	// Remove duplicates
	requirements = uniqueStrings(requirements)

	return requirements
}

// parseComplianceString parses comma-separated compliance standards
func parseComplianceString(compliance string) []string {
	if compliance == "" {
		return []string{}
	}

	standards := []string{}
	parts := strings.Split(compliance, ",")

	for _, part := range parts {
		// Trim whitespace and convert to lowercase
		standard := strings.ToLower(strings.TrimSpace(part))

		// Normalize standard names
		switch standard {
		case "iso27001", "iso-27001", "iso 27001":
			standards = append(standards, "iso27001")
		case "soc2", "soc-2", "soc 2":
			standards = append(standards, "soc2")
		case "cis", "cis-benchmarks", "cis benchmarks":
			standards = append(standards, "cis")
		case "pci-dss", "pci", "pcidss", "pci dss":
			standards = append(standards, "pci-dss")
		}
	}

	return standards
}

// uniqueStrings removes duplicate strings from a slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// calculateConfidence determines how confident we are in the detection
// Returns a score from 0.0 to 1.0
func (d *EnvironmentDetector) calculateConfidence(envCtx *policy.EnvironmentContext, ns *v1.Namespace) float64 {
	var score float64 = 0.5 // Start with neutral confidence
	var factors int = 0

	labels := ns.Labels
	if labels == nil {
		labels = make(map[string]string)
	}

	// Factor 1: Direct environment label (most reliable)
	if val, exists := labels["environment"]; exists {
		normalized := strings.ToLower(strings.TrimSpace(val))
		envStr := string(envCtx.EnvironmentType)
		if normalized == envStr {
			score += 0.25
			factors++
		}
	}

	// Factor 2: Alternative environment labels
	altEnvLabels := []string{"env", "tier", "stage"}
	for _, label := range altEnvLabels {
		if val, exists := labels[label]; exists {
			// Normalize the value
			normalized := strings.ToLower(strings.TrimSpace(val))

			// Check if it matches detected environment
			envStr := string(envCtx.EnvironmentType)
			if normalized == envStr ||
				(normalized == "development" && envStr == "dev") ||
				(normalized == "devel" && envStr == "dev") ||
				(normalized == "production" && envStr == "prod") ||
				(normalized == "prd" && envStr == "prod") ||
				(normalized == "staging" && envStr == "staging") ||
				(normalized == "stg" && envStr == "staging") {
				score += 0.15
				factors++
				break
			}
		}
	}

	// Factor 3: Security level consistency
	if secLabel, exists := labels["security-level"]; exists {
		expectedSec := string(envCtx.SecurityLevel)
		if strings.ToLower(secLabel) == expectedSec {
			score += 0.15
			factors++
		} else {
			// Conflicting security level
			score -= 0.10
		}
	}

	// Factor 4: Compliance requirements (indicates production)
	if len(envCtx.ComplianceRequirements) > 0 {
		if envCtx.EnvironmentType == policy.EnvironmentProd {
			// Compliance + prod = good match
			score += 0.10
			factors++
		} else if envCtx.EnvironmentType == policy.EnvironmentDev {
			// Compliance + dev = unusual, lower confidence
			score -= 0.15
		}
	}

	// Factor 5: Multiple compliance standards = high confidence in production
	if len(envCtx.ComplianceRequirements) >= 2 && envCtx.EnvironmentType == policy.EnvironmentProd {
		score += 0.10
		factors++
	}

	// Factor 6: Risk tolerance alignment
	var alignmentBonus float64 = 0

	switch envCtx.EnvironmentType {
	case policy.EnvironmentDev:
		if envCtx.RiskTolerance == "high" {
			alignmentBonus = 0.05
		}
	case policy.EnvironmentStaging:
		if envCtx.RiskTolerance == "medium" {
			alignmentBonus = 0.05
		}
	case policy.EnvironmentProd:
		if envCtx.RiskTolerance == "low" {
			alignmentBonus = 0.05
		}
	}

	if alignmentBonus > 0 {
		score += alignmentBonus
		factors++
	}

	// Factor 7: Namespace name pattern matching (weak signal)
	nsName := strings.ToLower(ns.Name)
	envStr := string(envCtx.EnvironmentType)

	if strings.Contains(nsName, envStr) ||
		(strings.Contains(nsName, "prod") && envStr == "prod") ||
		(strings.Contains(nsName, "dev") && envStr == "dev") ||
		(strings.Contains(nsName, "stg") && envStr == "staging") ||
		(strings.Contains(nsName, "staging") && envStr == "staging") {
		score += 0.10
		factors++
	}

	// Penalty: If environment is "unknown", cap confidence at 0.4
	if envCtx.EnvironmentType == policy.EnvironmentUnknown {
		if score > 0.4 {
			score = 0.4
		}
	}

	// Penalty: Very few factors = uncertain detection
	if factors < 2 {
		score *= 0.8 // 20% penalty
	}

	// Bonus: Many confirming factors = very confident
	if factors >= 4 {
		score += 0.05
	}

	// Ensure score stays in valid range [0.0, 1.0]
	if score < 0.0 {
		score = 0.0
	}
	if score > 1.0 {
		score = 1.0
	}

	// Round to 2 decimal places
	return float64(int(score*100)) / 100
}
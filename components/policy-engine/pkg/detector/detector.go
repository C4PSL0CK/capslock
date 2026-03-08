package detector

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Detector is the main detector that coordinates all analyzers
type Detector struct {
	clientset       *kubernetes.Clientset
	configExtractor *ConfigExtractor
	podAnalyzer     *PodAnalyzer
	rbacAnalyzer    *RBACAnalyzer
	networkAnalyzer *NetworkAnalyzer
	secretsAnalyzer *SecretsAnalyzer
}

// NewDetector creates a new detector with all analyzers
func NewDetector(clientset *kubernetes.Clientset) *Detector {
	return &Detector{
		clientset:       clientset,
		configExtractor: NewConfigExtractor(clientset),
		podAnalyzer:     NewPodAnalyzer(clientset),
		rbacAnalyzer:    NewRBACAnalyzer(clientset),
		networkAnalyzer: NewNetworkAnalyzer(clientset),
		secretsAnalyzer: NewSecretsAnalyzer(clientset),
	}
}

// ExtractNamespaceConfig extracts complete namespace configuration
func (d *Detector) ExtractNamespaceConfig(ctx context.Context, namespace string) (*NamespaceConfig, error) {
	return d.configExtractor.ExtractNamespaceConfig(ctx, namespace)
}

// DetectEnvironment detects the environment type from namespace labels
func (d *Detector) DetectEnvironment(ctx context.Context, namespace string) (string, float64, error) {
	// Get namespace to read labels
	ns, err := d.clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return "", 0.0, fmt.Errorf("failed to get namespace: %w", err)
	}

	// Use 7-factor confidence algorithm
	environment, confidence := d.calculateEnvironmentWithConfidence(ns.Labels, namespace)

	return environment, confidence, nil
}

// calculateEnvironmentWithConfidence uses the 7-factor algorithm
func (d *Detector) calculateEnvironmentWithConfidence(labels map[string]string, namespaceName string) (string, float64) {
	weights := map[string]float64{
		"environment":            0.50,
		"env":                    0.20,
		"tier":                   0.15,
		"security-level":         0.10,
		"compliance-pci-dss":     0.04,
		"namespace-name-pattern": 0.01,
	}

	scores := map[string]float64{
		"dev":     0.0,
		"staging": 0.0,
		"prod":    0.0,
	}

	// Factor 1: Direct environment label (weight: 0.50)
	if env, ok := labels["environment"]; ok {
		normalizedEnv := normalizeEnvironment(env)
		scores[normalizedEnv] += weights["environment"]
	}

	// Factor 2: Secondary env label (weight: 0.20)
	if env, ok := labels["env"]; ok {
		normalizedEnv := normalizeEnvironment(env)
		scores[normalizedEnv] += weights["env"]
	}

	// Factor 3: Tier label (weight: 0.15)
	if tier, ok := labels["tier"]; ok {
		switch strings.ToLower(tier) {
		case "production", "prod":
			scores["prod"] += weights["tier"]
		case "staging", "uat", "stage":
			scores["staging"] += weights["tier"]
		case "development", "dev":
			scores["dev"] += weights["tier"]
		}
	}

	// Factor 4: Security level (weight: 0.10)
	if secLevel, ok := labels["security-level"]; ok {
		switch strings.ToLower(secLevel) {
		case "high", "critical":
			scores["prod"] += weights["security-level"]
		case "medium":
			scores["staging"] += weights["security-level"]
		case "low":
			scores["dev"] += weights["security-level"]
		}
	}

	// Factor 5: PCI-DSS compliance (weight: 0.02)
	if _, ok := labels["compliance-pci-dss"]; ok {
		scores["prod"] += weights["compliance-pci-dss"]
	}
	if pciDss, ok := labels["pci-dss"]; ok && strings.ToLower(pciDss) == "true" {
		scores["prod"] += weights["compliance-pci-dss"]
	}

	// Factor 6: Namespace name pattern (weight: 0.01)
	lowerName := strings.ToLower(namespaceName)
	if strings.Contains(lowerName, "prod") || strings.Contains(lowerName, "production") {
		scores["prod"] += weights["namespace-name-pattern"]
	} else if strings.Contains(lowerName, "stag") || strings.Contains(lowerName, "uat") {
		scores["staging"] += weights["namespace-name-pattern"]
	} else if strings.Contains(lowerName, "dev") || strings.Contains(lowerName, "development") {
		scores["dev"] += weights["namespace-name-pattern"]
	}

	// Find highest score
	maxEnv := "dev"
	maxScore := scores["dev"]
	for env, score := range scores {
		if score > maxScore {
			maxScore = score
			maxEnv = env
		}
	}

	// If no labels at all, default to dev with low confidence
	if maxScore == 0.0 {
		return "dev", 0.10
	}

	return maxEnv, maxScore
}

// normalizeEnvironment normalizes environment strings to standard values
func normalizeEnvironment(env string) string {
	env = strings.ToLower(strings.TrimSpace(env))

	switch env {
	case "production", "prod", "prd":
		return "prod"
	case "staging", "stage", "stg", "uat":
		return "staging"
	case "development", "dev", "devel":
		return "dev"
	default:
		// If unknown, try to infer from partial match
		if strings.Contains(env, "prod") {
			return "prod"
		}
		if strings.Contains(env, "stag") || strings.Contains(env, "uat") {
			return "staging"
		}
		if strings.Contains(env, "dev") {
			return "dev"
		}
		return "dev" // Default to dev for unknown
	}
}

// CalculateConfidence calculates just the confidence score
func (d *Detector) CalculateConfidence(labels map[string]string, namespaceName string) float64 {
	_, confidence := d.calculateEnvironmentWithConfidence(labels, namespaceName)
	return confidence
}

// AnalyzePodSecurity analyzes pod security for a namespace
func (d *Detector) AnalyzePodSecurity(ctx context.Context, namespace string) (*PodSecuritySummary, error) {
	return d.podAnalyzer.AnalyzePodSecurity(ctx, namespace)
}

// AnalyzeRBAC analyzes RBAC configuration for a namespace
func (d *Detector) AnalyzeRBAC(ctx context.Context, namespace string) (*RBACSecuritySummary, error) {
	return d.rbacAnalyzer.AnalyzeRBAC(ctx, namespace)
}

// AnalyzeNetworkPolicies analyzes network policies for a namespace
func (d *Detector) AnalyzeNetworkPolicies(ctx context.Context, namespace string) (*NetworkSecuritySummary, error) {
	return d.networkAnalyzer.AnalyzeNetworkPolicies(ctx, namespace)
}

// AnalyzeSecrets analyzes secrets usage for a namespace
func (d *Detector) AnalyzeSecrets(ctx context.Context, namespace string) (*SecretsSecuritySummary, error) {
	return d.secretsAnalyzer.AnalyzeSecrets(ctx, namespace)
}

// CheckPodSecurityStandard checks if pods meet a specific Pod Security Standard
func (d *Detector) CheckPodSecurityStandard(ctx context.Context, namespace string, standard string) (bool, []string, error) {
	return d.podAnalyzer.CheckPodSecurityStandard(ctx, namespace, standard)
}

// CheckLeastPrivilege checks if RBAC follows least privilege principle
func (d *Detector) CheckLeastPrivilege(ctx context.Context, namespace string) (bool, []string, error) {
	return d.rbacAnalyzer.CheckLeastPrivilege(ctx, namespace)
}

// CheckNetworkSegmentation checks if proper network segmentation is in place
func (d *Detector) CheckNetworkSegmentation(ctx context.Context, namespace string) (bool, []string, error) {
	return d.networkAnalyzer.CheckNetworkSegmentation(ctx, namespace)
}

// CheckSecretsManagement checks if secrets are properly managed
func (d *Detector) CheckSecretsManagement(ctx context.Context, namespace string) (bool, []string, error) {
	return d.secretsAnalyzer.CheckSecretsManagement(ctx, namespace)
}
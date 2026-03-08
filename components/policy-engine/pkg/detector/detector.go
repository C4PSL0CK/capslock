package detector

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// Detector is the main detector that coordinates all analyzers
type Detector struct {
	clientset          kubernetes.Interface
	configExtractor    *ConfigExtractor
	podAnalyzer        *PodAnalyzer
	rbacAnalyzer       *RBACAnalyzer
	networkAnalyzer    *NetworkAnalyzer
	secretsAnalyzer    *SecretsAnalyzer
	clusterDetector    *ClusterCharacteristicDetector
}

// NewDetector creates a new detector with all analyzers
func NewDetector(clientset kubernetes.Interface) *Detector {
	return &Detector{
		clientset:       clientset,
		configExtractor: NewConfigExtractor(clientset),
		podAnalyzer:     NewPodAnalyzer(clientset),
		rbacAnalyzer:    NewRBACAnalyzer(clientset),
		networkAnalyzer: NewNetworkAnalyzer(clientset),
		secretsAnalyzer: NewSecretsAnalyzer(clientset),
		clusterDetector: NewClusterCharacteristicDetector(clientset),
	}
}

// GetNamespace fetches a namespace and returns its EnvironmentContext.
func (d *Detector) GetNamespace(ctx context.Context, namespace string) (*policy.EnvironmentContext, error) {
	ns, err := d.clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get namespace %q: %w", namespace, err)
	}

	labels := ns.Labels
	if labels == nil {
		labels = map[string]string{}
	}

	// Determine environment type from labels or namespace name
	envType := policy.EnvironmentUnknown

	if env, ok := labels["environment"]; ok {
		envType = normalizeEnv(env)
	} else if env, ok := labels["app.kubernetes.io/environment"]; ok {
		envType = normalizeEnv(env)
	} else {
		// Infer from namespace name
		lower := strings.ToLower(namespace)
		if strings.Contains(lower, "prod") {
			envType = policy.EnvironmentProd
		} else if strings.Contains(lower, "staging") || strings.Contains(lower, "stage") {
			envType = policy.EnvironmentStaging
		} else if strings.Contains(lower, "dev") {
			envType = policy.EnvironmentDev
		}
	}

	// Determine security level
	secLevel := policy.SecurityLevelLow
	if sl, ok := labels["security-level"]; ok {
		switch strings.ToLower(sl) {
		case "low":
			secLevel = policy.SecurityLevelLow
		case "medium":
			secLevel = policy.SecurityLevelMedium
		case "high":
			secLevel = policy.SecurityLevelHigh
		}
	} else {
		// Infer from environment
		switch envType {
		case policy.EnvironmentProd:
			secLevel = policy.SecurityLevelHigh
		case policy.EnvironmentStaging:
			secLevel = policy.SecurityLevelMedium
		default:
			secLevel = policy.SecurityLevelLow
		}
	}

	return &policy.EnvironmentContext{
		Namespace:       namespace,
		EnvironmentType: envType,
		SecurityLevel:   secLevel,
		Labels:          labels,
		DetectedAt:      time.Now(),
	}, nil
}

// normalizeEnv maps a raw environment label value to a typed Environment.
func normalizeEnv(env string) policy.Environment {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "prod", "production", "prd":
		return policy.EnvironmentProd
	case "staging", "stage", "stg", "uat":
		return policy.EnvironmentStaging
	case "dev", "development", "devel":
		return policy.EnvironmentDev
	default:
		return policy.EnvironmentUnknown
	}
}

// ExtractNamespaceConfig extracts complete namespace configuration
func (d *Detector) ExtractNamespaceConfig(ctx context.Context, namespace string) (*NamespaceConfig, error) {
	return d.configExtractor.ExtractNamespaceConfig(ctx, namespace)
}

// DetectClusterCharacteristics returns cloud provider and environment signals
// derived from node labels and taints.
func (d *Detector) DetectClusterCharacteristics(ctx context.Context) (*ClusterCharacteristics, error) {
	return d.clusterDetector.Detect(ctx)
}

// DetectEnvironment detects the environment type from namespace labels and
// cluster characteristics (node labels/taints, cloud provider).
func (d *Detector) DetectEnvironment(ctx context.Context, namespace string) (string, float64, error) {
	ns, err := d.clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return "", 0.0, fmt.Errorf("failed to get namespace: %w", err)
	}

	env, confidence := d.calculateEnvironmentWithConfidence(ns.Labels, namespace)

	// Factor 7: boost confidence from cluster characteristics
	cc, _ := d.clusterDetector.Detect(ctx)
	if cc != nil && cc.SuggestedEnvironment == env && cc.Confidence > 0 {
		confidence = min1(confidence+cc.Confidence, 1.0)
	}

	return env, confidence, nil
}

func min1(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
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
	maxEnv := ""
	maxScore := 0.0
	for env, score := range scores {
		if score > maxScore {
			maxScore = score
			maxEnv = env
		}
	}

	// If no labels at all, default to unknown with low confidence
	if maxScore == 0.0 {
		return "unknown", 0.05
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

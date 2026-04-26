package detector

import (
	"context"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// EnvironmentDetector is an alias for Detector, used by the API handlers.
type EnvironmentDetector = Detector

// NewEnvironmentDetector creates a Detector using in-cluster config or ~/.kube/config.
func NewEnvironmentDetector() (*EnvironmentDetector, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		cfg, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			return nil, err
		}
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return NewDetector(clientset), nil
}

// HealthCheck verifies that the Kubernetes API server is reachable.
func (d *Detector) HealthCheck(ctx context.Context) error {
	_, err := d.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	return err
}

// ListNamespaces returns the names of all namespaces.
func (d *Detector) ListNamespaces(ctx context.Context) ([]string, error) {
	list, err := d.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	names := make([]string, len(list.Items))
	for i, ns := range list.Items {
		names[i] = ns.Name
	}
	return names, nil
}

// Detect detects the environment for a namespace and returns a full EnvironmentContext.
func (d *Detector) Detect(ctx context.Context, namespace string) (*policy.EnvironmentContext, error) {
	ns, err := d.clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	labels := ns.Labels
	if labels == nil {
		labels = map[string]string{}
	}

	// ─── Detect environment type ───────────────────────────────────────────────
	envType := detectEnvironmentType(labels, namespace)

	// ─── Calculate confidence ─────────────────────────────────────────────────
	confidence := calculateConfidence(labels, namespace, envType)

	// ─── Security level ───────────────────────────────────────────────────────
	secLevel := detectSecurityLevel(labels, envType)

	// ─── Risk tolerance ───────────────────────────────────────────────────────
	riskTolerance := detectRiskTolerance(envType)

	// ─── Compliance requirements ──────────────────────────────────────────────
	compliance := detectComplianceRequirements(labels)

	// Factor 7: cluster characteristics (node labels / taints / cloud provider)
	cc, _ := d.clusterDetector.Detect(ctx)
	if cc != nil && string(envType) == cc.SuggestedEnvironment && cc.Confidence > 0 {
		confidence += cc.Confidence
		if confidence > 1.0 {
			confidence = 1.0
		}
	}

	return &policy.EnvironmentContext{
		Namespace:              namespace,
		EnvironmentType:        envType,
		SecurityLevel:          secLevel,
		RiskTolerance:          riskTolerance,
		ComplianceRequirements: compliance,
		Confidence:             confidence,
		Labels:                 labels,
		DetectedAt:             time.Now(),
	}, nil
}

// calculateConfidence returns a confidence score in [0, 1] based on available signals.
//
// Weights:
//   - Valid primary env label (environment / env / app.k8s.io/environment): 0.6
//   - Namespace name confirms detected environment: 0.2
//   - security-level / security label present: 0.2
//   - Each compliance label: 0.1 (capped at 0.2 total from compliance)
//   - Sum is capped at 1.0
//
// Invalid or unknown env label values contribute 0 to confidence.
func calculateConfidence(labels map[string]string, namespace string, envType policy.Environment) float64 {
	if envType == policy.EnvironmentUnknown {
		// Namespace-name-only detection contributes low confidence
		lower := strings.ToLower(namespace)
		if strings.Contains(lower, "prod") ||
			strings.Contains(lower, "staging") ||
			strings.Contains(lower, "stage") ||
			strings.Contains(lower, "dev") {
			return 0.3 // low confidence from name only
		}
		return 0.0
	}

	score := 0.0

	// +0.6 for a valid primary environment label
	for _, key := range []string{"environment", "app.kubernetes.io/environment", "env"} {
		if val, ok := labels[key]; ok {
			if normalizeEnvStr(val) == envType {
				score += 0.6
			}
			break
		}
	}

	// +0.2 if the namespace name contains the environment name (confirming the label)
	lower := strings.ToLower(namespace)
	envStr := string(envType)
	if strings.Contains(lower, envStr) ||
		(envType == policy.EnvironmentStaging && (strings.Contains(lower, "stag") || strings.Contains(lower, "stage"))) {
		score += 0.2
	}

	// +0.2 for a security-level / security label
	for _, key := range []string{"security-level", "security"} {
		if _, ok := labels[key]; ok {
			score += 0.2
			break
		}
	}

	// +0.1 per compliance label (capped at 0.2)
	complianceScore := 0.0
	for label := range labels {
		if strings.HasPrefix(label, "compliance-") {
			complianceScore += 0.1
		}
	}
	if complianceScore > 0.2 {
		complianceScore = 0.2
	}
	score += complianceScore

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// detectEnvironmentType resolves the environment from labels and namespace name.
func detectEnvironmentType(labels map[string]string, namespaceName string) policy.Environment {
	// Check primary labels
	for _, key := range []string{"environment", "app.kubernetes.io/environment", "env"} {
		if val, ok := labels[key]; ok {
			e := normalizeEnvStr(val)
			if e != policy.EnvironmentUnknown {
				return e
			}
			// explicit invalid value → unknown
			return policy.EnvironmentUnknown
		}
	}

	// Infer from namespace name
	lower := strings.ToLower(namespaceName)
	if strings.Contains(lower, "prod") {
		return policy.EnvironmentProd
	}
	if strings.Contains(lower, "staging") || strings.Contains(lower, "stage") || strings.Contains(lower, "stag") {
		return policy.EnvironmentStaging
	}
	if strings.Contains(lower, "dev") {
		return policy.EnvironmentDev
	}

	return policy.EnvironmentUnknown
}

// normalizeEnvStr converts a raw string to an Environment constant.
func normalizeEnvStr(s string) policy.Environment {
	switch strings.ToLower(strings.TrimSpace(s)) {
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

// detectSecurityLevel resolves security level from labels or environment.
func detectSecurityLevel(labels map[string]string, envType policy.Environment) policy.SecurityLevel {
	for _, key := range []string{"security-level", "security"} {
		if val, ok := labels[key]; ok {
			switch strings.ToLower(val) {
			case "high", "critical":
				return policy.SecurityLevelHigh
			case "medium":
				return policy.SecurityLevelMedium
			case "low":
				return policy.SecurityLevelLow
			}
		}
	}

	// Infer from environment
	switch envType {
	case policy.EnvironmentProd:
		return policy.SecurityLevelHigh
	case policy.EnvironmentStaging:
		return policy.SecurityLevelMedium
	default:
		return policy.SecurityLevelLow
	}
}

// detectRiskTolerance maps environment to risk tolerance string.
func detectRiskTolerance(envType policy.Environment) string {
	switch envType {
	case policy.EnvironmentProd:
		return "low"
	case policy.EnvironmentStaging:
		return "medium"
	default:
		return "high"
	}
}

// detectComplianceRequirements collects compliance standards from namespace labels.
// Supports both individual labels (compliance-pci-dss: true) and comma-separated
// values (compliance: "pci-dss, cis").
func detectComplianceRequirements(labels map[string]string) []string {
	var reqs []string

	// Individual compliance labels: compliance-<standard>: true
	complianceLabelPrefixes := map[string]string{
		"pci-dss": "pci-dss",
		"pci":     "pci-dss",
		"cis":     "cis",
		"cis-benchmarks": "cis",
	}

	for label, val := range labels {
		if !strings.HasPrefix(label, "compliance-") {
			continue
		}
		if strings.ToLower(val) != "true" {
			continue
		}
		suffix := strings.TrimPrefix(label, "compliance-")
		if normalized, ok := complianceLabelPrefixes[suffix]; ok {
			reqs = append(reqs, normalized)
		}
	}

	// Comma-separated compliance label: compliance: "pci-dss, cis"
	if compStr, ok := labels["compliance"]; ok {
		parts := strings.Split(compStr, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			switch strings.ToLower(part) {
			case "pci-dss", "pci":
				reqs = append(reqs, "pci-dss")
			case "cis", "cis-benchmarks":
				reqs = append(reqs, "cis")
			}
		}
	}

	return reqs
}

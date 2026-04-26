package detector

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// CloudProvider identifies the underlying cloud/infrastructure platform.
type CloudProvider string

const (
	CloudProviderAWS     CloudProvider = "aws"
	CloudProviderGCP     CloudProvider = "gcp"
	CloudProviderAzure   CloudProvider = "azure"
	CloudProviderOnPrem  CloudProvider = "on-prem"
	CloudProviderUnknown CloudProvider = "unknown"
)

// ClusterCharacteristics holds detected cluster-level signals.
type ClusterCharacteristics struct {
	// Cloud / infrastructure provider
	CloudProvider CloudProvider `json:"cloud_provider"`

	// True when node taints indicate a production-grade cluster
	HasProdTaints bool `json:"has_prod_taint"`

	// True when node taints indicate a staging-grade cluster
	HasStagingTaints bool `json:"has_staging_taint"`

	// True when node labels indicate a development cluster
	HasDevLabels bool `json:"has_dev_labels"`

	// Confidence contribution [0,1] from cluster characteristics alone
	Confidence float64 `json:"confidence"`

	// Which environment the cluster characteristics point to ("prod","staging","dev","")
	SuggestedEnvironment string `json:"suggested_environment"`
}

// ClusterCharacteristicDetector detects environment signals from cluster-level
// node labels and taints.
type ClusterCharacteristicDetector struct {
	clientset kubernetes.Interface
}

// NewClusterCharacteristicDetector creates a new detector.
func NewClusterCharacteristicDetector(clientset kubernetes.Interface) *ClusterCharacteristicDetector {
	return &ClusterCharacteristicDetector{clientset: clientset}
}

// Detect lists cluster nodes and extracts environment signals from their
// labels and taints.
func (c *ClusterCharacteristicDetector) Detect(ctx context.Context) (*ClusterCharacteristics, error) {
	if c == nil || c.clientset == nil {
		return &ClusterCharacteristics{CloudProvider: CloudProviderUnknown}, nil
	}
	nodes, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return &ClusterCharacteristics{
			CloudProvider:        CloudProviderUnknown,
			SuggestedEnvironment: "",
			Confidence:           0,
		}, nil // non-fatal: return empty result
	}

	result := &ClusterCharacteristics{}

	prodSignals := 0
	stagingSignals := 0
	devSignals := 0

	for _, node := range nodes.Items {
		labels := node.Labels

		// ── Cloud provider detection ────────────────────────────────────────
		if result.CloudProvider == "" || result.CloudProvider == CloudProviderUnknown {
			result.CloudProvider = detectCloudProvider(labels)
		}

		// ── Environment signals from node labels ────────────────────────────
		for k, v := range labels {
			kl := strings.ToLower(k)
			vl := strings.ToLower(v)

			// Direct environment label on node
			if kl == "environment" || kl == "env" || kl == "tier" {
				switch normalizeEnvironment(vl) {
				case "prod":
					prodSignals++
				case "staging":
					stagingSignals++
				case "dev":
					devSignals++
					result.HasDevLabels = true
				}
			}

			// EKS / GKE node-group names that embed env hints
			if kl == "eks.amazonaws.com/nodegroup" ||
				kl == "cloud.google.com/gke-nodepool" ||
				kl == "kubernetes.azure.com/agentpool" {
				nv := normalizeEnvironment(vl)
				switch nv {
				case "prod":
					prodSignals++
				case "staging":
					stagingSignals++
				case "dev":
					devSignals++
				}
			}
		}

		// ── Environment signals from node taints ────────────────────────────
		for _, taint := range node.Spec.Taints {
			kl := strings.ToLower(taint.Key)
			vl := strings.ToLower(taint.Value)

			if kl == "environment" || kl == "env" || kl == "tier" || kl == "dedicated" {
				switch normalizeEnvironment(vl) {
				case "prod":
					prodSignals++
					result.HasProdTaints = true
				case "staging":
					stagingSignals++
					result.HasStagingTaints = true
				case "dev":
					devSignals++
					result.HasDevLabels = true
				}
			}
		}
	}

	if result.CloudProvider == "" {
		result.CloudProvider = CloudProviderUnknown
	}

	// ── Determine suggested environment and confidence ──────────────────────
	total := prodSignals + stagingSignals + devSignals
	if total == 0 {
		result.SuggestedEnvironment = ""
		result.Confidence = 0
		return result, nil
	}

	switch {
	case prodSignals >= stagingSignals && prodSignals >= devSignals:
		result.SuggestedEnvironment = "prod"
		result.Confidence = float64(prodSignals) / float64(total) * 0.3
	case stagingSignals >= prodSignals && stagingSignals >= devSignals:
		result.SuggestedEnvironment = "staging"
		result.Confidence = float64(stagingSignals) / float64(total) * 0.3
	default:
		result.SuggestedEnvironment = "dev"
		result.Confidence = float64(devSignals) / float64(total) * 0.3
	}

	return result, nil
}

// detectCloudProvider returns the cloud provider inferred from node labels.
func detectCloudProvider(labels map[string]string) CloudProvider {
	for k := range labels {
		kl := strings.ToLower(k)
		switch {
		case strings.HasPrefix(kl, "eks.amazonaws.com") ||
			strings.HasPrefix(kl, "alpha.eksctl.io") ||
			k == "node.kubernetes.io/instance-type" && isAWSInstanceType(labels[k]):
			return CloudProviderAWS
		case strings.HasPrefix(kl, "cloud.google.com") ||
			strings.HasPrefix(kl, "container.googleapis.com"):
			return CloudProviderGCP
		case strings.HasPrefix(kl, "kubernetes.azure.com") ||
			strings.HasPrefix(kl, "agentpool"):
			return CloudProviderAzure
		}
	}

	// topology region/zone hints
	if region, ok := labels["topology.kubernetes.io/region"]; ok {
		rl := strings.ToLower(region)
		switch {
		case strings.HasPrefix(rl, "us-") || strings.HasPrefix(rl, "eu-") || strings.HasPrefix(rl, "ap-"):
			// ambiguous between AWS and GCP — check zone
			if zone, ok := labels["topology.kubernetes.io/zone"]; ok {
				if strings.Contains(zone, "-") && len(zone) > 10 {
					return CloudProviderGCP // GCP zones are longer
				}
				return CloudProviderAWS
			}
		case strings.HasPrefix(rl, "eastus") || strings.HasPrefix(rl, "westus") ||
			strings.HasPrefix(rl, "northeurope") || strings.HasPrefix(rl, "westeurope"):
			return CloudProviderAzure
		}
	}

	return CloudProviderOnPrem
}

// isAWSInstanceType checks whether a value looks like an EC2 instance type.
func isAWSInstanceType(v string) bool {
	// EC2 instance types: t3.medium, m5.large, c5.xlarge, r6i.2xlarge …
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return false
	}
	prefix := strings.ToLower(parts[0])
	awsPrefixes := []string{"t2", "t3", "t3a", "t4g", "m4", "m5", "m5a", "m6i", "m6a",
		"c4", "c5", "c5a", "c6i", "c6a", "r4", "r5", "r5a", "r6i",
		"p3", "p4", "g4", "g5", "inf1", "x1", "x2"}
	for _, p := range awsPrefixes {
		if prefix == p {
			return true
		}
	}
	return false
}

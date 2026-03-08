package detector

import (
	"context"
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

// Detect detects the environment for a namespace and returns an EnvironmentContext.
func (d *Detector) Detect(ctx context.Context, namespace string) (*policy.EnvironmentContext, error) {
	envType, confidence, err := d.DetectEnvironment(ctx, namespace)
	if err != nil {
		return nil, err
	}

	ns, err := d.clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	labels := map[string]string{}
	if err == nil {
		labels = ns.Labels
	}

	return &policy.EnvironmentContext{
		Namespace:       namespace,
		EnvironmentType: policy.Environment(envType),
		SecurityLevel:   "standard",
		RiskTolerance:   "medium",
		Confidence:      confidence,
		Labels:          labels,
		DetectedAt:      time.Now(),
	}, nil
}

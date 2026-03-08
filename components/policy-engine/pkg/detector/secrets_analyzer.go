package detector

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// SecretsAnalyzer analyzes secrets usage
type SecretsAnalyzer struct {
	clientset kubernetes.Interface
}

// NewSecretsAnalyzer creates a new secrets analyzer
func NewSecretsAnalyzer(clientset kubernetes.Interface) *SecretsAnalyzer {
	return &SecretsAnalyzer{
		clientset: clientset,
	}
}

// SecretsSecuritySummary contains secrets analysis
type SecretsSecuritySummary struct {
	TotalSecrets             int
	OpaqueSecrets            int
	TLSSecrets               int
	DockerConfigSecrets      int
	ServiceAccountTokens     int
	SecretsAsEnvVars         bool
	PodsWithSecretsAsEnv     int
	SecretsAsVolumes         bool
	PodsWithSecretsAsVolumes int
	ExternalSecretsManager   bool
	ExternalManagerType      string
	EncryptionAtRest         bool
}

// AnalyzeSecrets analyzes secrets usage in a namespace
func (sa *SecretsAnalyzer) AnalyzeSecrets(ctx context.Context, namespace string) (*SecretsSecuritySummary, error) {
	secrets, err := sa.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	summary := &SecretsSecuritySummary{
		TotalSecrets: len(secrets.Items),
	}

	// Analyze secret types
	for _, secret := range secrets.Items {
		switch secret.Type {
		case corev1.SecretTypeOpaque:
			summary.OpaqueSecrets++
		case corev1.SecretTypeTLS:
			summary.TLSSecrets++
		case corev1.SecretTypeDockerConfigJson:
			summary.DockerConfigSecrets++
		case corev1.SecretTypeServiceAccountToken:
			summary.ServiceAccountTokens++
		}
	}

	// Analyze pod secret usage
	pods, err := sa.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		podUsesSecretsAsEnv := false
		podUsesSecretsAsVolume := false

		// Check environment variables
		for _, container := range pod.Spec.Containers {
			for _, env := range container.Env {
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					podUsesSecretsAsEnv = true
					summary.SecretsAsEnvVars = true
					break
				}
			}
			if podUsesSecretsAsEnv {
				break
			}
		}

		// Check volumes
		for _, volume := range pod.Spec.Volumes {
			if volume.Secret != nil {
				podUsesSecretsAsVolume = true
				summary.SecretsAsVolumes = true
				break
			}
		}

		if podUsesSecretsAsEnv {
			summary.PodsWithSecretsAsEnv++
		}
		if podUsesSecretsAsVolume {
			summary.PodsWithSecretsAsVolumes++
		}
	}

	// Check for External Secrets Operator
	externalSecrets, _ := sa.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=external-secrets",
	})
	if len(externalSecrets.Items) > 0 {
		summary.ExternalSecretsManager = true
		summary.ExternalManagerType = "external-secrets-operator"
	}

	// Encryption at rest check (simplified - would need API server inspection)
	summary.EncryptionAtRest = false

	return summary, nil
}

// CheckSecretsManagement checks if secrets are properly managed
func (sa *SecretsAnalyzer) CheckSecretsManagement(ctx context.Context, namespace string) (bool, []string, error) {
	summary, err := sa.AnalyzeSecrets(ctx, namespace)
	if err != nil {
		return false, nil, err
	}

	violations := []string{}

	if summary.SecretsAsEnvVars {
		violations = append(violations, "Secrets used as environment variables")
	}
	if !summary.ExternalSecretsManager && summary.TotalSecrets > 5 {
		violations = append(violations, "No external secrets manager detected")
	}
	if !summary.EncryptionAtRest {
		violations = append(violations, "Encryption at rest not verified")
	}

	return len(violations) == 0, violations, nil
}
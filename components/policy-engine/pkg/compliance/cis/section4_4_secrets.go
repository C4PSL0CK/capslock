package cis

import (
	"fmt"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// Section 4.4: Secrets Management (2 checks)

// Check_4_4_1 ensures secrets are not stored as environment variables
var Check_4_4_1 = CISCheck{
	ID:       "4.4.1",
	Section:  "4.4",
	Title:    "Prefer using Secrets as files over Secrets as environment variables",
	Severity: "MEDIUM",
	Description: "Secrets stored as environment variables can be exposed through logs, crash dumps, and other diagnostic outputs. Prefer mounting secrets as files.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if config.Secrets.SecretsAsEnvVars {
			affected := []string{}
			if config.Secrets.PodsWithSecretsAsEnv > 0 {
				affected = append(affected, fmt.Sprintf("%d pods with secrets as env vars", config.Secrets.PodsWithSecretsAsEnv))
			}
			return false, "Secrets are being used as environment variables", affected
		}
		return true, "Secrets are not used as environment variables", []string{}
	},
	Remediation: "Mount secrets as volumes instead of environment variables. Use spec.volumes with secret type and spec.containers[*].volumeMounts. Remove spec.containers[*].env[*].valueFrom.secretKeyRef.",
	References: []string{
		"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets",
		"https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod",
	},
}

// Check_4_4_2 ensures external secrets manager is used
var Check_4_4_2 = CISCheck{
	ID:       "4.4.2",
	Section:  "4.4",
	Title:    "Consider external secret storage",
	Severity: "LOW",
	Description: "Consider the use of an external secrets storage and management system instead of using Kubernetes Secrets directly. This provides additional security controls and audit capabilities.",
	Validator: func(config *detector.NamespaceConfig) (bool, string, []string) {
		if !config.Secrets.ExternalSecretsManager {
			return false, "No external secrets manager detected", []string{}
		}
		return true, "External secrets manager in use", []string{config.Secrets.ExternalSecretsManagerType}
	},
	Remediation: "Implement external secrets management using HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager, or External Secrets Operator (ESO).",
	References: []string{
		"https://external-secrets.io/",
		"https://www.vaultproject.io/docs/platform/k8s",
	},
}

// GetSection44Checks returns all Section 4.4 checks
func GetSection44Checks() []CISCheck {
	return []CISCheck{
		Check_4_4_1,
		Check_4_4_2,
	}
}
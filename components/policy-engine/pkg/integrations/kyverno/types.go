package kyverno

import (
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// ClusterPolicy represents a Kyverno ClusterPolicy
type ClusterPolicy struct {
	APIVersion string                `yaml:"apiVersion"`
	Kind       string                `yaml:"kind"`
	Metadata   ClusterPolicyMetadata `yaml:"metadata"`
	Spec       ClusterPolicySpec     `yaml:"spec"`
}

// ClusterPolicyMetadata contains metadata for the policy
type ClusterPolicyMetadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// ClusterPolicySpec defines the policy specification
type ClusterPolicySpec struct {
	ValidationFailureAction string `yaml:"validationFailureAction"`
	Background              bool   `yaml:"background"`
	Rules                   []Rule `yaml:"rules"`
}

// Rule represents a Kyverno policy rule
type Rule struct {
	Name         string          `yaml:"name"`
	Match        MatchResources  `yaml:"match"`
	Validate     *Validation     `yaml:"validate,omitempty"`
	VerifyImages []VerifyImage   `yaml:"verifyImages,omitempty"`
}

// MatchResources defines what resources the rule applies to
type MatchResources struct {
	Any []ResourceFilter `yaml:"any,omitempty"`
}

// ResourceFilter defines resource matching criteria
type ResourceFilter struct {
	Resources ResourceDescription `yaml:"resources"`
}

// ResourceDescription describes Kubernetes resources
type ResourceDescription struct {
	Kinds      []string       `yaml:"kinds,omitempty"`
	Namespaces []string       `yaml:"namespaces,omitempty"`
	Selector   *LabelSelector `yaml:"selector,omitempty"`
}

// LabelSelector defines label-based selection
type LabelSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels,omitempty"`
}

// Validation defines validation rules
type Validation struct {
	Message string                 `yaml:"message"`
	Pattern map[string]interface{} `yaml:"pattern,omitempty"`
	Deny    *Deny                  `yaml:"deny,omitempty"`
}

// Deny defines denial conditions
type Deny struct {
	Conditions []Condition `yaml:"conditions,omitempty"`
}

// Condition defines a validation condition
type Condition struct {
	Key      string      `yaml:"key"`
	Operator string      `yaml:"operator"`
	Value    interface{} `yaml:"value,omitempty"`
}

// VerifyImage defines image verification rules
type VerifyImage struct {
	ImageReferences []string   `yaml:"imageReferences"`
	Attestors       []Attestor `yaml:"attestors,omitempty"`
}

// Attestor defines image attestation requirements
type Attestor struct {
	Count   int             `yaml:"count,omitempty"`
	Entries []AttestorEntry `yaml:"entries,omitempty"`
}

// AttestorEntry defines an attestor entry
type AttestorEntry struct {
	Keys *Keys `yaml:"keys,omitempty"`
}

// Keys defines public keys for verification
type Keys struct {
	PublicKeys string `yaml:"publicKeys,omitempty"`
}

// ConversionResult contains the result of policy conversion
type ConversionResult struct {
	ClusterPolicy *ClusterPolicy
	Policy        *policy.PolicyTemplate
	Errors        []error
}
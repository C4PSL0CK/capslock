package opa

import (
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// ConstraintTemplate represents an OPA Gatekeeper ConstraintTemplate
type ConstraintTemplate struct {
	APIVersion string                       `yaml:"apiVersion"`
	Kind       string                       `yaml:"kind"`
	Metadata   ConstraintTemplateMetadata   `yaml:"metadata"`
	Spec       ConstraintTemplateSpec       `yaml:"spec"`
}

// ConstraintTemplateMetadata contains metadata for the template
type ConstraintTemplateMetadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// ConstraintTemplateSpec defines the constraint template specification
type ConstraintTemplateSpec struct {
	CRD     CRDSpec    `yaml:"crd"`
	Targets []Target   `yaml:"targets"`
}

// CRDSpec defines the Custom Resource Definition
type CRDSpec struct {
	Spec CRDSpecDetails `yaml:"spec"`
}

// CRDSpecDetails contains CRD details
type CRDSpecDetails struct {
	Names      CRDNames                 `yaml:"names"`
	Validation CRDValidation            `yaml:"validation,omitempty"`
}

// CRDNames defines the CRD names
type CRDNames struct {
	Kind       string   `yaml:"kind"`
	ListKind   string   `yaml:"listKind,omitempty"`
	Plural     string   `yaml:"plural,omitempty"`
	Singular   string   `yaml:"singular,omitempty"`
	ShortNames []string `yaml:"shortNames,omitempty"`
}

// CRDValidation defines validation schema
type CRDValidation struct {
	OpenAPIV3Schema OpenAPIV3Schema `yaml:"openAPIV3Schema,omitempty"`
}

// OpenAPIV3Schema defines the OpenAPI schema
type OpenAPIV3Schema struct {
	Type       string                        `yaml:"type"`
	Properties map[string]OpenAPIV3Property `yaml:"properties,omitempty"`
}

// OpenAPIV3Property defines a property in the schema
type OpenAPIV3Property struct {
	Type        string `yaml:"type,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// Target defines the Rego policy target
type Target struct {
	Target string `yaml:"target"`
	Rego   string `yaml:"rego"`
}

// Constraint represents an OPA Gatekeeper Constraint instance
type Constraint struct {
	APIVersion string             `yaml:"apiVersion"`
	Kind       string             `yaml:"kind"`
	Metadata   ConstraintMetadata `yaml:"metadata"`
	Spec       ConstraintSpec     `yaml:"spec"`
}

// ConstraintMetadata contains metadata for the constraint
type ConstraintMetadata struct {
	Name string `yaml:"name"`
}

// ConstraintSpec defines the constraint specification
type ConstraintSpec struct {
	Match      MatchSpec              `yaml:"match,omitempty"`
	Parameters map[string]interface{} `yaml:"parameters,omitempty"`
}

// MatchSpec defines what resources the constraint applies to
type MatchSpec struct {
	Kinds              []KindSpec        `yaml:"kinds,omitempty"`
	Namespaces         []string          `yaml:"namespaces,omitempty"`
	ExcludedNamespaces []string          `yaml:"excludedNamespaces,omitempty"`
	LabelSelector      map[string]string `yaml:"labelSelector,omitempty"`
}

// KindSpec defines a Kubernetes resource kind
type KindSpec struct {
	APIGroups []string `yaml:"apiGroups"`
	Kinds     []string `yaml:"kinds"`
}

// ConversionResult contains the result of policy conversion
type ConversionResult struct {
	Template   *ConstraintTemplate
	Constraint *Constraint
	Policy     *policy.PolicyTemplate
	Errors     []error
}
package opa

import (
	"fmt"
	"strings"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/policy"
)

// OPAConverter converts EAPE policies to OPA Gatekeeper resources
type OPAConverter struct {
	// Configuration options can be added here
}

// NewOPAConverter creates a new OPA converter
func NewOPAConverter() *OPAConverter {
	return &OPAConverter{}
}

// ConvertPolicy converts an EAPE policy to OPA ConstraintTemplate and Constraint
func (oc *OPAConverter) ConvertPolicy(p *policy.PolicyTemplate) (*ConversionResult, error) {
	if p == nil {
		return nil, fmt.Errorf("policy is nil")
	}

	result := &ConversionResult{
		Policy: p,
		Errors: []error{},
	}

	// Generate ConstraintTemplate
	template, err := oc.generateConstraintTemplate(p)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return result, err
	}
	result.Template = template

	// Generate Constraint instance
	constraint, err := oc.generateConstraint(p, template)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return result, err
	}
	result.Constraint = constraint

	return result, nil
}

// generateConstraintTemplate creates an OPA ConstraintTemplate from a policy
func (oc *OPAConverter) generateConstraintTemplate(p *policy.PolicyTemplate) (*ConstraintTemplate, error) {
	// Generate template name from policy name
	templateName := oc.generateTemplateName(p)
	kindName := oc.generateKindName(p)

	// Generate Rego policy code
	regoCode := oc.generateRegoPolicy(p)

	template := &ConstraintTemplate{
		APIVersion: "templates.gatekeeper.sh/v1",
		Kind:       "ConstraintTemplate",
		Metadata: ConstraintTemplateMetadata{
			Name: templateName,
			Annotations: map[string]string{
				"description":     p.Description,
				"eape.policy":     p.Name,
				"eape.version":    p.Version,
				"eape.environment": string(p.Environment),
			},
		},
		Spec: ConstraintTemplateSpec{
			CRD: CRDSpec{
				Spec: CRDSpecDetails{
					Names: CRDNames{
						Kind:   kindName,
						Plural: strings.ToLower(kindName) + "s",
					},
					Validation: CRDValidation{
						OpenAPIV3Schema: OpenAPIV3Schema{
							Type: "object",
							Properties: map[string]OpenAPIV3Property{
								"maxFileSize": {
									Type:        "string",
									Description: "Maximum file size for ICAP scanning",
								},
								"scanningMode": {
									Type:        "string",
									Description: "Scanning mode: log-only, warn, or block",
								},
							},
						},
					},
				},
			},
			Targets: []Target{
				{
					Target: "admission.k8s.gatekeeper.sh",
					Rego:   regoCode,
				},
			},
		},
	}

	return template, nil
}

// generateConstraint creates a Constraint instance from a policy
func (oc *OPAConverter) generateConstraint(p *policy.PolicyTemplate, template *ConstraintTemplate) (*Constraint, error) {
	constraintName := oc.generateConstraintName(p)
	kindName := template.Spec.CRD.Spec.Names.Kind

	constraint := &Constraint{
		APIVersion: "constraints.gatekeeper.sh/v1beta1",
		Kind:       kindName,
		Metadata: ConstraintMetadata{
			Name: constraintName,
		},
		Spec: ConstraintSpec{
			Match: MatchSpec{
				Kinds: []KindSpec{
					{
						APIGroups: []string{""},
						Kinds:     []string{"Pod"},
					},
				},
				Namespaces: []string{}, // Apply to all namespaces
				LabelSelector: map[string]string{
					"environment": string(p.Environment),
				},
			},
			Parameters: map[string]interface{}{
				"maxFileSize":  p.IcapConfig.MaxFileSize,
				"scanningMode": p.IcapConfig.ScanningMode,
			},
		},
	}

	return constraint, nil
}

// generateRegoPolicy generates Rego policy code for the template
func (oc *OPAConverter) generateRegoPolicy(p *policy.PolicyTemplate) string {
	// Generate Rego code based on policy settings
	var rego strings.Builder

	rego.WriteString("package eapepolicy\n\n")

	// Add violation rule based on scanning mode
	switch p.IcapConfig.ScanningMode {
	case "block":
		rego.WriteString(`violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container %v must run as non-root user (block mode)", [container.name])
}

`)
	case "warn":
		rego.WriteString(`warn[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container %v should run as non-root user (warn mode)", [container.name])
}

`)
	case "log-only":
		rego.WriteString(`info[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container %v is running as root (log-only mode)", [container.name])
}

`)
	}

	// Add file size check if specified
	if p.IcapConfig.MaxFileSize != "" {
		rego.WriteString(fmt.Sprintf(`violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  container.resources.limits.ephemeral-storage
  exceeds_limit(container.resources.limits.ephemeral-storage, "%s")
  msg := sprintf("Container %%v exceeds maximum file size limit", [container.name])
}

exceeds_limit(value, limit) {
  # File size comparison logic would go here
  true
}

`, p.IcapConfig.MaxFileSize))
	}

	// Add compliance-specific rules
	for _, standard := range p.Compliance.Standards {
		switch standard {
		case "pci-dss":
			rego.WriteString(`violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("Container %v must have read-only root filesystem (PCI-DSS requirement)", [container.name])
}

`)
		case "cis":
			// CIS rules are covered by the base security context rules above
		}
	}

	return rego.String()
}

// generateTemplateName creates a template name from policy name
func (oc *OPAConverter) generateTemplateName(p *policy.PolicyTemplate) string {
	// Convert "dev-policy" to "eapedevpolicy"
	name := strings.ReplaceAll(p.Name, "-", "")
	return "eape" + strings.ToLower(name)
}

// generateKindName creates a CRD kind name from policy name
func (oc *OPAConverter) generateKindName(p *policy.PolicyTemplate) string {
	// Convert "dev-policy" to "EAPEDevPolicy"
	parts := strings.Split(p.Name, "-")
	var result string
	for _, part := range parts {
		result += strings.Title(part)
	}
	return "EAPE" + result
}

// generateConstraintName creates a constraint name from policy name
func (oc *OPAConverter) generateConstraintName(p *policy.PolicyTemplate) string {
	// Convert "dev-policy" to "eape-dev-constraint"
	return "eape-" + p.Name + "-constraint"
}
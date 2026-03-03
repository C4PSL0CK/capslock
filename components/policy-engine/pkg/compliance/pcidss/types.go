package pcidss

import (
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// PCIDSSRequirement represents a single PCI-DSS requirement
type PCIDSSRequirement struct {
	// Requirement identifier (e.g., "1.2.1", "3.4.1")
	ID string
	
	// Parent requirement (e.g., "1", "3")
	ParentRequirement string
	
	// Human-readable title
	Title string
	
	// Severity level
	Severity string // CRITICAL, HIGH, MEDIUM, LOW
	
	// Detailed description
	Description string
	
	// Kubernetes controls that satisfy this requirement
	KubernetesControls []string
	
	// CIS checks that map to this requirement
	MappedCISChecks []string
	
	// Validation function
	Validator func(config *detector.NamespaceConfig) (bool, string, []string)
	
	// Remediation guidance
	Remediation string
	
	// Official PCI-DSS references
	References []string
}

// PCIDSSRequirementGroup represents a group of related requirements
type PCIDSSRequirementGroup struct {
	// Parent requirement ID (e.g., "1", "2", "3")
	ID string
	
	// Group title
	Title string
	
	// All requirements in this group
	Requirements []PCIDSSRequirement
}
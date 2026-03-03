package cis

import (
	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/detector"
)

// CISCheck represents a single CIS Kubernetes Benchmark check
type CISCheck struct {
	// Check identifier (e.g., "4.2.1")
	ID string
	
	// Section identifier (e.g., "4.2")
	Section string
	
	// Human-readable title
	Title string
	
	// Severity level
	Severity string // CRITICAL, HIGH, MEDIUM, LOW
	
	// Detailed description of what this check validates
	Description string
	
	// Validation function that checks if the configuration passes
	// Returns: (passed bool, message string, affectedResources []string)
	Validator func(config *detector.NamespaceConfig) (bool, string, []string)
	
	// Remediation guidance - how to fix if check fails
	Remediation string
	
	// References to official documentation
	References []string
}

// CISSection represents a section of the CIS Benchmark
type CISSection struct {
	// Section identifier (e.g., "4.1", "4.2")
	ID string
	
	// Section title
	Title string
	
	// All checks in this section
	Checks []CISCheck
}

// CISBenchmark represents the full CIS Kubernetes Benchmark
type CISBenchmark struct {
	// Benchmark version
	Version string
	
	// All sections
	Sections []CISSection
}
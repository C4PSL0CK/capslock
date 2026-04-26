package cis

import (
	"fmt"

	"github.com/C4PSL0CK/capslock/components/policy-engine/pkg/compliance"
)

// CalculateWeightedScore calculates a weighted compliance score based on severity
func CalculateWeightedScore(report *compliance.FrameworkReport) *compliance.ComplianceScore {
	if report.TotalChecks == 0 {
		return &compliance.ComplianceScore{
			RawScore:      0.0,
			WeightedScore: 0.0,
			PassThreshold: 0.90,
			Passes:        false,
		}
	}

	// Severity weights
	const (
		criticalWeight = 4.0
		highWeight     = 3.0
		mediumWeight   = 2.0
		lowWeight      = 1.0
	)

	// Calculate total possible weighted points
	totalWeightedPoints := 0.0
	earnedWeightedPoints := 0.0

	// Count checks by severity
	severityCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	// Process passed rules (all contribute full weighted points)
	for _, ruleID := range report.PassedRules {
		severity := getSeverityForRule(ruleID)
		severityCounts[severity]++

		weight := getWeightForSeverity(severity)
		totalWeightedPoints += weight
		earnedWeightedPoints += weight
	}

	// Process failed rules (contribute to total but not earned)
	for _, violation := range report.FailedRules {
		severity := violation.Severity
		severityCounts[severity]++

		weight := getWeightForSeverity(severity)
		totalWeightedPoints += weight
		// Don't add to earnedWeightedPoints since it failed
	}

	// Calculate weighted score
	weightedScore := 0.0
	if totalWeightedPoints > 0 {
		weightedScore = earnedWeightedPoints / totalWeightedPoints
	}

	// Raw score (simple pass/fail ratio)
	rawScore := float64(report.Passed) / float64(report.TotalChecks)

	return &compliance.ComplianceScore{
		RawScore:      rawScore,
		WeightedScore: weightedScore,
		PassThreshold: 0.90,
		Passes:        weightedScore >= 0.90,
	}
}

// getWeightForSeverity returns the numeric weight for a severity level
func getWeightForSeverity(severity string) float64 {
	switch severity {
	case "CRITICAL":
		return 4.0
	case "HIGH":
		return 3.0
	case "MEDIUM":
		return 2.0
	case "LOW":
		return 1.0
	default:
		return 1.0
	}
}

// getSeverityForRule returns the severity for a given rule ID
func getSeverityForRule(ruleID string) string {
	// Map of rule IDs to their severity
	severityMap := map[string]string{
		// Section 4.1 - RBAC
		"4.1.1": "HIGH",
		"4.1.2": "HIGH",
		"4.1.3": "MEDIUM",
		"4.1.4": "MEDIUM",
		"4.1.5": "MEDIUM",
		"4.1.6": "MEDIUM",
		"4.1.7": "HIGH",
		"4.1.8": "MEDIUM",

		// Section 4.2 - Pod Security
		"4.2.1":  "CRITICAL",
		"4.2.2":  "HIGH",
		"4.2.3":  "HIGH",
		"4.2.4":  "HIGH",
		"4.2.5":  "HIGH",
		"4.2.6":  "MEDIUM",
		"4.2.7":  "MEDIUM",
		"4.2.8":  "MEDIUM",
		"4.2.9":  "MEDIUM",
		"4.2.10": "MEDIUM",
		"4.2.11": "HIGH",
		"4.2.12": "HIGH",

		// Section 4.3 - Network
		"4.3.1": "HIGH",
		"4.3.2": "MEDIUM",
		"4.3.3": "MEDIUM",

		// Section 4.4 - Secrets
		"4.4.1": "MEDIUM",
		"4.4.2": "LOW",

		// Section 4.5 - Namespace
		"4.5.1": "LOW",
		"4.5.2": "LOW",
		"4.5.3": "LOW",
	}

	severity, exists := severityMap[ruleID]
	if !exists {
		return "MEDIUM" // Default to medium if not found
	}
	return severity
}

// CalculateSectionScores calculates scores per section
func CalculateSectionScores(report *compliance.FrameworkReport) map[string]float64 {
	sectionScores := make(map[string]float64)
	sectionCounts := make(map[string]int)
	sectionPassed := make(map[string]int)

	// Count passed rules per section
	for _, ruleID := range report.PassedRules {
		section := getSectionForRule(ruleID)
		sectionCounts[section]++
		sectionPassed[section]++
	}

	// Count failed rules per section
	for _, violation := range report.FailedRules {
		section := getSectionForRule(violation.RuleID)
		sectionCounts[section]++
	}

	// Calculate scores
	for section, total := range sectionCounts {
		passed := sectionPassed[section]
		if total > 0 {
			sectionScores[section] = float64(passed) / float64(total)
		} else {
			sectionScores[section] = 0.0
		}
	}

	return sectionScores
}

// getSectionForRule returns the section ID for a rule
func getSectionForRule(ruleID string) string {
	// Extract section from rule ID (e.g., "4.2.1" -> "4.2")
	if len(ruleID) >= 3 {
		return ruleID[:3]
	}
	return "unknown"
}

// GetComplianceLevel returns a human-readable compliance level
func GetComplianceLevel(score float64) string {
	switch {
	case score >= 0.95:
		return "Excellent"
	case score >= 0.90:
		return "Good"
	case score >= 0.75:
		return "Fair"
	case score >= 0.50:
		return "Poor"
	default:
		return "Critical"
	}
}

// GetPriorityViolations returns violations sorted by priority
func GetPriorityViolations(report *compliance.FrameworkReport) map[string][]compliance.RuleViolation {
	priorityMap := make(map[string][]compliance.RuleViolation)

	for _, violation := range report.FailedRules {
		severity := violation.Severity
		priorityMap[severity] = append(priorityMap[severity], violation)
	}

	return priorityMap
}

// EstimateRemediationTime estimates total time to fix all violations
func EstimateRemediationTime(report *compliance.FrameworkReport) string {
	// Time estimates in minutes
	timeMap := map[string]int{
		"CRITICAL": 45,
		"HIGH":     30,
		"MEDIUM":   20,
		"LOW":      15,
	}

	totalMinutes := 0
	for _, violation := range report.FailedRules {
		if time, exists := timeMap[violation.Severity]; exists {
			totalMinutes += time
		}
	}

	hours := totalMinutes / 60
	minutes := totalMinutes % 60

	if hours > 0 {
		return fmt.Sprintf("%d hours %d minutes", hours, minutes)
	}
	return fmt.Sprintf("%d minutes", minutes)
}

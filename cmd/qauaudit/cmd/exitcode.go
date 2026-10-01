// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the QAU Security Audit tool.
package cmd

import (
	"github.com/quantaureum/qau/audit"
)

// Exit codes for CI/CD integration
const (
	// ExitSuccess indicates the audit completed successfully with no findings above threshold
	ExitSuccess = 0
	// ExitFindingsAboveThreshold indicates findings were found at or above the fail severity
	ExitFindingsAboveThreshold = 1
	// ExitConfigError indicates a configuration error
	ExitConfigError = 2
	// ExitScanError indicates a scan execution error
	ExitScanError = 3
	// ExitReportError indicates a report generation error
	ExitReportError = 4
)

// ExitCodeCalculator calculates exit codes based on findings and configuration
type ExitCodeCalculator struct {
	failSeverity audit.SeverityLevel
}

// NewExitCodeCalculator creates a new exit code calculator
func NewExitCodeCalculator(failSeverity audit.SeverityLevel) *ExitCodeCalculator {
	return &ExitCodeCalculator{
		failSeverity: failSeverity,
	}
}

// Calculate determines the exit code based on findings
func (c *ExitCodeCalculator) Calculate(findings []audit.Finding) int {
	if len(findings) == 0 {
		return ExitSuccess
	}

	severityOrder := getSeverityOrder()
	failOrder, ok := severityOrder[c.failSeverity]
	if !ok {
		failOrder = 1 // Default to HIGH
	}

	for _, f := range findings {
		order, ok := severityOrder[f.Severity]
		if !ok {
			continue
		}
		if order <= failOrder {
			return ExitFindingsAboveThreshold
		}
	}

	return ExitSuccess
}

// HasFindingsAboveThreshold checks if any findings are at or above the threshold
func (c *ExitCodeCalculator) HasFindingsAboveThreshold(findings []audit.Finding) bool {
	return c.Calculate(findings) == ExitFindingsAboveThreshold
}

// CountFindingsAboveThreshold counts findings at or above the threshold
func (c *ExitCodeCalculator) CountFindingsAboveThreshold(findings []audit.Finding) int {
	severityOrder := getSeverityOrder()
	failOrder, ok := severityOrder[c.failSeverity]
	if !ok {
		failOrder = 1 // Default to HIGH
	}

	count := 0
	for _, f := range findings {
		order, ok := severityOrder[f.Severity]
		if !ok {
			continue
		}
		if order <= failOrder {
			count++
		}
	}

	return count
}

// getSeverityOrder returns the severity ordering map
func getSeverityOrder() map[audit.SeverityLevel]int {
	return map[audit.SeverityLevel]int{
		audit.SeverityCritical: 0,
		audit.SeverityHigh:     1,
		audit.SeverityMedium:   2,
		audit.SeverityLow:      3,
		audit.SeverityInfo:     4,
	}
}

// SeverityAtOrAbove checks if severity1 is at or above severity2
func SeverityAtOrAbove(severity1, severity2 audit.SeverityLevel) bool {
	order := getSeverityOrder()
	o1, ok1 := order[severity1]
	o2, ok2 := order[severity2]
	if !ok1 || !ok2 {
		return false
	}
	return o1 <= o2
}

// GetHighestSeverity returns the highest severity from a list of findings
func GetHighestSeverity(findings []audit.Finding) audit.SeverityLevel {
	if len(findings) == 0 {
		return audit.SeverityInfo
	}

	order := getSeverityOrder()
	highest := audit.SeverityInfo
	highestOrder := order[highest]

	for _, f := range findings {
		o, ok := order[f.Severity]
		if ok && o < highestOrder {
			highest = f.Severity
			highestOrder = o
		}
	}

	return highest
}

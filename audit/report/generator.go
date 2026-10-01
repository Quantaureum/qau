// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"context"
	"sort"
	"time"

	"github.com/quantaureum/qau/audit"
)

// ReportGenerator aggregates findings from all scanners and generates unified reports
type ReportGenerator struct {
	version   string
	reporters map[ReportFormat]Reporter
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(version string) *ReportGenerator {
	g := &ReportGenerator{
		version:   version,
		reporters: make(map[ReportFormat]Reporter),
	}
	// Register default reporters
	g.reporters[FormatJSON] = NewJSONReporter(version)
	g.reporters[FormatHTML] = NewHTMLReporter(version)
	g.reporters[FormatSARIF] = NewSARIFReporter(version)
	return g
}

// RegisterReporter adds a reporter for a specific format
func (g *ReportGenerator) RegisterReporter(format ReportFormat, reporter Reporter) {
	g.reporters[format] = reporter
}

// GetReporter returns the reporter for a specific format
func (g *ReportGenerator) GetReporter(format ReportFormat) (Reporter, bool) {
	r, ok := g.reporters[format]
	return r, ok
}

// GenerateReport creates a unified report from multiple scan results
func (g *ReportGenerator) GenerateReport(ctx context.Context, results []*audit.ScanResult, targetPath string) (*AuditReport, error) {
	startTime := time.Now()

	report := &AuditReport{
		Timestamp: time.Now().UTC(),
		Findings:  make([]audit.Finding, 0),
		Metadata: ReportMetadata{
			Version:     g.version,
			GeneratedBy: "qau-security-audit",
			TargetPath:  targetPath,
			Scanners:    make([]string, 0, len(results)),
		},
	}

	var totalDuration time.Duration
	for _, result := range results {
		if result == nil {
			continue
		}
		report.Metadata.Scanners = append(report.Metadata.Scanners, result.Scanner)
		totalDuration += result.Duration
		report.Findings = append(report.Findings, result.Findings...)
	}

	// Sort findings by severity (Critical first)
	sortFindingsBySeverity(report.Findings)

	// Calculate summary
	report.Summary = calculateSummary(report.Findings)
	report.Duration = time.Since(startTime) + totalDuration

	return report, nil
}

// sortFindingsBySeverity sorts findings by severity level (Critical > High > Medium > Low > Info)
func sortFindingsBySeverity(findings []audit.Finding) {
	severityOrder := map[audit.SeverityLevel]int{
		audit.SeverityCritical: 0,
		audit.SeverityHigh:     1,
		audit.SeverityMedium:   2,
		audit.SeverityLow:      3,
		audit.SeverityInfo:     4,
	}

	sort.Slice(findings, func(i, j int) bool {
		orderI, okI := severityOrder[findings[i].Severity]
		orderJ, okJ := severityOrder[findings[j].Severity]
		if !okI {
			orderI = 5
		}
		if !okJ {
			orderJ = 5
		}
		return orderI < orderJ
	})
}

// calculateSummary computes the report summary from findings
func calculateSummary(findings []audit.Finding) ReportSummary {
	summary := ReportSummary{
		TotalFindings: len(findings),
	}

	for _, f := range findings {
		switch f.Severity {
		case audit.SeverityCritical:
			summary.CriticalCount++
		case audit.SeverityHigh:
			summary.HighCount++
		case audit.SeverityMedium:
			summary.MediumCount++
		case audit.SeverityLow:
			summary.LowCount++
		case audit.SeverityInfo:
			summary.InfoCount++
		}

		if f.Status == audit.StatusFixed {
			summary.FixedCount++
		}
	}

	return summary
}

// CategorizeFindings groups findings by category
func CategorizeFindings(findings []audit.Finding) map[string][]audit.Finding {
	categories := make(map[string][]audit.Finding)
	for _, f := range findings {
		categories[f.Category] = append(categories[f.Category], f)
	}
	return categories
}

// FilterBySeverity returns findings at or above the specified severity level
func FilterBySeverity(findings []audit.Finding, minSeverity audit.SeverityLevel) []audit.Finding {
	severityOrder := map[audit.SeverityLevel]int{
		audit.SeverityCritical: 0,
		audit.SeverityHigh:     1,
		audit.SeverityMedium:   2,
		audit.SeverityLow:      3,
		audit.SeverityInfo:     4,
	}

	minOrder, ok := severityOrder[minSeverity]
	if !ok {
		minOrder = 4
	}

	filtered := make([]audit.Finding, 0)
	for _, f := range findings {
		order, ok := severityOrder[f.Severity]
		if !ok {
			order = 5
		}
		if order <= minOrder {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// CountBySeverity returns counts for each severity level
func CountBySeverity(findings []audit.Finding) map[audit.SeverityLevel]int {
	counts := make(map[audit.SeverityLevel]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// HasCriticalFindings checks if there are any critical severity findings
func HasCriticalFindings(findings []audit.Finding) bool {
	for _, f := range findings {
		if f.Severity == audit.SeverityCritical {
			return true
		}
	}
	return false
}

// HasHighOrAboveFindings checks if there are any high or critical severity findings
func HasHighOrAboveFindings(findings []audit.Finding) bool {
	for _, f := range findings {
		if f.Severity == audit.SeverityCritical || f.Severity == audit.SeverityHigh {
			return true
		}
	}
	return false
}

// DeduplicateFindings removes duplicate findings based on their ID.
// If multiple findings have the same ID, only the first occurrence is kept.
// This ensures that no two findings in the result have the same ID.
// Requirements: 7.3
func DeduplicateFindings(findings []audit.Finding) []audit.Finding {
	if len(findings) == 0 {
		return findings
	}

	seen := make(map[string]bool)
	result := make([]audit.Finding, 0, len(findings))

	for _, f := range findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			result = append(result, f)
		}
	}

	return result
}

// DeduplicateFindingsByContent removes duplicate findings based on content similarity.
// Two findings are considered duplicates if they have the same:
// - File location
// - Start line
// - Category
// - Severity
// The finding with the more detailed description is kept.
// Requirements: 7.3
func DeduplicateFindingsByContent(findings []audit.Finding) []audit.Finding {
	if len(findings) == 0 {
		return findings
	}

	type contentKey struct {
		File      string
		StartLine int
		Category  string
		Severity  audit.SeverityLevel
	}

	seen := make(map[contentKey]int) // maps to index in result
	result := make([]audit.Finding, 0, len(findings))

	for _, f := range findings {
		key := contentKey{
			File:      f.Location.File,
			StartLine: f.Location.StartLine,
			Category:  f.Category,
			Severity:  f.Severity,
		}

		if existingIdx, exists := seen[key]; exists {
			// Keep the finding with more detailed description
			if len(f.Description) > len(result[existingIdx].Description) {
				result[existingIdx] = f
			}
		} else {
			seen[key] = len(result)
			result = append(result, f)
		}
	}

	return result
}

// MergeRelatedFindings groups related findings and merges them.
// Related findings are those with the same category and file.
// Returns a map of merged findings grouped by category.
// Requirements: 7.3
func MergeRelatedFindings(findings []audit.Finding) map[string][]audit.Finding {
	grouped := make(map[string][]audit.Finding)

	for _, f := range findings {
		key := f.Category
		grouped[key] = append(grouped[key], f)
	}

	return grouped
}

// GenerateReportWithDeduplication creates a unified report with deduplication applied.
// This method first deduplicates by ID, then by content similarity.
// Requirements: 7.3
func (g *ReportGenerator) GenerateReportWithDeduplication(ctx context.Context, results []*audit.ScanResult, targetPath string) (*AuditReport, error) {
	report, err := g.GenerateReport(ctx, results, targetPath)
	if err != nil {
		return nil, err
	}

	// Apply deduplication
	report.Findings = DeduplicateFindings(report.Findings)
	report.Findings = DeduplicateFindingsByContent(report.Findings)

	// Recalculate summary after deduplication
	report.Summary = calculateSummary(report.Findings)

	return report, nil
}

// CountDuplicates returns the number of duplicate findings that would be removed.
// This is useful for reporting how many duplicates were found.
func CountDuplicates(findings []audit.Finding) int {
	if len(findings) == 0 {
		return 0
	}

	seen := make(map[string]bool)
	duplicates := 0

	for _, f := range findings {
		if seen[f.ID] {
			duplicates++
		} else {
			seen[f.ID] = true
		}
	}

	return duplicates
}

// HasDuplicates checks if there are any duplicate findings by ID.
func HasDuplicates(findings []audit.Finding) bool {
	if len(findings) == 0 {
		return false
	}

	seen := make(map[string]bool)
	for _, f := range findings {
		if seen[f.ID] {
			return true
		}
		seen[f.ID] = true
	}

	return false
}

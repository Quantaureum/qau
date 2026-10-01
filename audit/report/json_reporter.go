// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/quantaureum/qau/audit"
)

// JSONReporter generates JSON format reports
// Requirements: 6.2, 6.3, 6.4, 8.4
type JSONReporter struct {
	version string
	indent  bool
}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter(version string) *JSONReporter {
	return &JSONReporter{
		version: version,
		indent:  true,
	}
}

// NewJSONReporterWithOptions creates a JSON reporter with options
func NewJSONReporterWithOptions(version string, indent bool) *JSONReporter {
	return &JSONReporter{
		version: version,
		indent:  indent,
	}
}

// Format returns the report format
func (r *JSONReporter) Format() ReportFormat {
	return FormatJSON
}

// Generate creates a report from scan results
// Requirements: 6.1, 6.2, 6.3, 6.4
func (r *JSONReporter) Generate(results []*audit.ScanResult) (*AuditReport, error) {
	report := &AuditReport{
		Timestamp: time.Now().UTC(),
		Findings:  make([]audit.Finding, 0),
		Metadata: ReportMetadata{
			Version:     r.version,
			GeneratedBy: "qau-security-audit",
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
	report.Duration = totalDuration

	// Calculate summary
	report.Summary = r.calculateSummary(report.Findings)

	return report, nil
}

// calculateSummary computes the report summary from findings
func (r *JSONReporter) calculateSummary(findings []audit.Finding) ReportSummary {
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

// Write outputs the report to a writer
// Requirements: 8.4
func (r *JSONReporter) Write(report *AuditReport, w io.Writer) error {
	encoder := json.NewEncoder(w)
	if r.indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(report)
}

// WriteBytes returns the report as JSON bytes
func (r *JSONReporter) WriteBytes(report *AuditReport) ([]byte, error) {
	if r.indent {
		return json.MarshalIndent(report, "", "  ")
	}
	return json.Marshal(report)
}

// IsValidJSON checks if the report can be marshaled to valid JSON
func IsValidJSON(report *AuditReport) bool {
	if report == nil {
		return false
	}
	_, err := json.Marshal(report)
	return err == nil
}

// HasRequiredFields checks if the report has all required fields
// Requirements: 8.4
func HasRequiredFields(report *AuditReport) bool {
	if report == nil {
		return false
	}
	// Required fields: timestamp, summary, findings array
	return !report.Timestamp.IsZero() && report.Findings != nil
}

// ValidateReport checks if a report is valid and complete
func ValidateReport(report *AuditReport) error {
	if report == nil {
		return &ReportValidationError{Field: "report", Message: "report is nil"}
	}
	if report.Timestamp.IsZero() {
		return &ReportValidationError{Field: "timestamp", Message: "timestamp is missing"}
	}
	if report.Findings == nil {
		return &ReportValidationError{Field: "findings", Message: "findings array is nil"}
	}
	return nil
}

// ReportValidationError represents a validation error
type ReportValidationError struct {
	Field   string
	Message string
}

func (e *ReportValidationError) Error() string {
	return "report validation error: " + e.Field + " - " + e.Message
}

// ValidateJSONOutput validates that the JSON output is valid and contains required fields
// Property 16: JSON Output Validity
// Requirements: 8.4
func ValidateJSONOutput(jsonData []byte) error {
	var report AuditReport
	if err := json.Unmarshal(jsonData, &report); err != nil {
		return &ReportValidationError{Field: "json", Message: "invalid JSON: " + err.Error()}
	}
	return ValidateReport(&report)
}

// ParseJSONReport parses JSON data into an AuditReport
func ParseJSONReport(jsonData []byte) (*AuditReport, error) {
	var report AuditReport
	if err := json.Unmarshal(jsonData, &report); err != nil {
		return nil, err
	}
	return &report, nil
}

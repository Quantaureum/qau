// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/quantaureum/qau/audit"
)

// SARIF version constant
const SARIFVersion = "2.1.0"

// SARIFSchema is the JSON schema URI for SARIF 2.1.0
const SARIFSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

// SARIFReporter generates SARIF format reports for IDE integration and GitHub code scanning
// Requirements: 8.4
type SARIFReporter struct {
	version string
	indent  bool
}

// NewSARIFReporter creates a new SARIF reporter
func NewSARIFReporter(version string) *SARIFReporter {
	return &SARIFReporter{
		version: version,
		indent:  true,
	}
}

// NewSARIFReporterWithOptions creates a SARIF reporter with options
func NewSARIFReporterWithOptions(version string, indent bool) *SARIFReporter {
	return &SARIFReporter{
		version: version,
		indent:  indent,
	}
}

// Format returns the report format
func (r *SARIFReporter) Format() ReportFormat {
	return FormatSARIF
}

// SARIFLog is the root SARIF object
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of a static analysis tool
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool describes the analysis tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the primary tool component
type SARIFDriver struct {
	Name           string                     `json:"name"`
	Version        string                     `json:"version"`
	InformationURI string                     `json:"informationUri,omitempty"`
	Rules          []SARIFReportingDescriptor `json:"rules,omitempty"`
}

// SARIFReportingDescriptor describes a rule
type SARIFReportingDescriptor struct {
	ID                   string                       `json:"id"`
	Name                 string                       `json:"name,omitempty"`
	ShortDescription     *SARIFMultiformatMessage     `json:"shortDescription,omitempty"`
	FullDescription      *SARIFMultiformatMessage     `json:"fullDescription,omitempty"`
	HelpURI              string                       `json:"helpUri,omitempty"`
	Help                 *SARIFMultiformatMessage     `json:"help,omitempty"`
	DefaultConfiguration *SARIFReportingConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any               `json:"properties,omitempty"`
}

// SARIFReportingConfiguration describes the default configuration for a rule
type SARIFReportingConfiguration struct {
	Level string `json:"level,omitempty"`
}

// SARIFMultiformatMessage is a message with multiple formats
type SARIFMultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFResult represents a single result from the analysis
type SARIFResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex,omitempty"`
	Level      string          `json:"level"`
	Message    SARIFMessage    `json:"message"`
	Locations  []SARIFLocation `json:"locations,omitempty"`
	Fixes      []SARIFFix      `json:"fixes,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

// SARIFMessage is a message associated with a result
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location in source code
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation represents a physical location in a file
type SARIFPhysicalLocation struct {
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation represents the location of an artifact
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFRegion represents a region within an artifact
type SARIFRegion struct {
	StartLine   int                   `json:"startLine,omitempty"`
	EndLine     int                   `json:"endLine,omitempty"`
	StartColumn int                   `json:"startColumn,omitempty"`
	EndColumn   int                   `json:"endColumn,omitempty"`
	Snippet     *SARIFArtifactContent `json:"snippet,omitempty"`
}

// SARIFArtifactContent represents the content of an artifact
type SARIFArtifactContent struct {
	Text string `json:"text,omitempty"`
}

// SARIFFix represents a proposed fix for a result
type SARIFFix struct {
	Description     *SARIFMessage         `json:"description,omitempty"`
	ArtifactChanges []SARIFArtifactChange `json:"artifactChanges,omitempty"`
}

// SARIFArtifactChange represents a change to an artifact
type SARIFArtifactChange struct {
	ArtifactLocation *SARIFArtifactLocation `json:"artifactLocation,omitempty"`
	Replacements     []SARIFReplacement     `json:"replacements,omitempty"`
}

// SARIFReplacement represents a replacement in an artifact
type SARIFReplacement struct {
	DeletedRegion   *SARIFRegion          `json:"deletedRegion,omitempty"`
	InsertedContent *SARIFArtifactContent `json:"insertedContent,omitempty"`
}

// SARIFInvocation represents an invocation of the tool
type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

// Generate creates a report from scan results
// Requirements: 6.1, 8.4
func (r *SARIFReporter) Generate(results []*audit.ScanResult) (*AuditReport, error) {
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
	report.Summary = calculateSummaryForSARIF(report.Findings)

	return report, nil
}

// calculateSummaryForSARIF computes the report summary from findings
func calculateSummaryForSARIF(findings []audit.Finding) ReportSummary {
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

// Write outputs the report to a writer in SARIF format
// Requirements: 8.4
func (r *SARIFReporter) Write(report *AuditReport, w io.Writer) error {
	sarifLog := r.convertToSARIF(report)
	encoder := json.NewEncoder(w)
	if r.indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(sarifLog)
}

// WriteBytes returns the report as SARIF JSON bytes
func (r *SARIFReporter) WriteBytes(report *AuditReport) ([]byte, error) {
	sarifLog := r.convertToSARIF(report)
	if r.indent {
		return json.MarshalIndent(sarifLog, "", "  ")
	}
	return json.Marshal(sarifLog)
}

// convertToSARIF converts an AuditReport to SARIF format
func (r *SARIFReporter) convertToSARIF(report *AuditReport) *SARIFLog {
	// Build rules from unique finding IDs
	rulesMap := make(map[string]int)
	rules := make([]SARIFReportingDescriptor, 0)

	for _, f := range report.Findings {
		if _, exists := rulesMap[f.ID]; !exists {
			rulesMap[f.ID] = len(rules)
			rules = append(rules, r.findingToRule(f))
		}
	}

	// Build results
	results := make([]SARIFResult, 0, len(report.Findings))
	for _, f := range report.Findings {
		ruleIndex := rulesMap[f.ID]
		results = append(results, r.findingToResult(f, ruleIndex))
	}

	// Build invocation
	invocations := []SARIFInvocation{
		{
			ExecutionSuccessful: true,
			StartTimeUTC:        report.Timestamp.Add(-report.Duration).Format(time.RFC3339),
			EndTimeUTC:          report.Timestamp.Format(time.RFC3339),
		},
	}

	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "qau-security-audit",
						Version:        r.version,
						InformationURI: "https://github.com/quantaureum/qau",
						Rules:          rules,
					},
				},
				Results:     results,
				Invocations: invocations,
			},
		},
	}
}

// findingToRule converts a Finding to a SARIF rule descriptor
func (r *SARIFReporter) findingToRule(f audit.Finding) SARIFReportingDescriptor {
	rule := SARIFReportingDescriptor{
		ID:   f.ID,
		Name: f.Title,
		ShortDescription: &SARIFMultiformatMessage{
			Text: f.Title,
		},
		FullDescription: &SARIFMultiformatMessage{
			Text: f.Description,
		},
		DefaultConfiguration: &SARIFReportingConfiguration{
			Level: severityToSARIFLevel(f.Severity),
		},
		Properties: make(map[string]any),
	}

	// Add CWE if present
	if f.CWE != "" {
		rule.Properties["cwe"] = f.CWE
	}

	// Add category
	if f.Category != "" {
		rule.Properties["category"] = f.Category
	}

	// Add help with remediation steps
	if f.Remediation.Description != "" {
		helpText := f.Remediation.Description
		if len(f.Remediation.Steps) > 0 {
			helpText += "\n\nRemediation Steps:\n"
			for i, step := range f.Remediation.Steps {
				helpText += "\n" + string(rune('1'+i)) + ". " + step
			}
		}
		rule.Help = &SARIFMultiformatMessage{
			Text: helpText,
		}
	}

	// Add references as helpUri
	if len(f.References) > 0 {
		rule.HelpURI = f.References[0]
	}

	return rule
}

// findingToResult converts a Finding to a SARIF result
func (r *SARIFReporter) findingToResult(f audit.Finding, ruleIndex int) SARIFResult {
	result := SARIFResult{
		RuleID:    f.ID,
		RuleIndex: ruleIndex,
		Level:     severityToSARIFLevel(f.Severity),
		Message: SARIFMessage{
			Text: f.Description,
		},
		Properties: make(map[string]any),
	}

	// Add location
	if f.Location.File != "" {
		location := SARIFLocation{
			PhysicalLocation: &SARIFPhysicalLocation{
				ArtifactLocation: &SARIFArtifactLocation{
					URI:       f.Location.File,
					URIBaseID: "%SRCROOT%",
				},
			},
		}

		// Add region if line numbers are present
		if f.Location.StartLine > 0 {
			region := &SARIFRegion{
				StartLine: f.Location.StartLine,
			}
			if f.Location.EndLine > 0 {
				region.EndLine = f.Location.EndLine
			}
			if f.Location.Column > 0 {
				region.StartColumn = f.Location.Column
			}
			if f.Location.Snippet != "" {
				region.Snippet = &SARIFArtifactContent{
					Text: f.Location.Snippet,
				}
			}
			location.PhysicalLocation.Region = region
		}

		result.Locations = []SARIFLocation{location}
	}

	// Add properties
	if f.CVE != "" {
		result.Properties["cve"] = f.CVE
	}
	if f.Effort != "" {
		result.Properties["effort"] = string(f.Effort)
	}
	if f.Status != "" {
		result.Properties["status"] = string(f.Status)
	}

	// Add fix if code fix is available
	if f.Remediation.CodeFix != "" && f.Location.File != "" {
		result.Fixes = []SARIFFix{
			{
				Description: &SARIFMessage{
					Text: f.Remediation.Description,
				},
				ArtifactChanges: []SARIFArtifactChange{
					{
						ArtifactLocation: &SARIFArtifactLocation{
							URI: f.Location.File,
						},
						Replacements: []SARIFReplacement{
							{
								InsertedContent: &SARIFArtifactContent{
									Text: f.Remediation.CodeFix,
								},
							},
						},
					},
				},
			},
		}
	}

	return result
}

// severityToSARIFLevel converts audit severity to SARIF level
func severityToSARIFLevel(severity audit.SeverityLevel) string {
	switch severity {
	case audit.SeverityCritical:
		return "error"
	case audit.SeverityHigh:
		return "error"
	case audit.SeverityMedium:
		return "warning"
	case audit.SeverityLow:
		return "note"
	case audit.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// IsValidSARIF checks if the report can be converted to valid SARIF
func IsValidSARIF(report *AuditReport) bool {
	if report == nil {
		return false
	}
	reporter := NewSARIFReporter("1.0.0")
	_, err := reporter.WriteBytes(report)
	return err == nil
}

// ValidateSARIFOutput validates that the SARIF output is valid
func ValidateSARIFOutput(sarifData []byte) error {
	var sarifLog SARIFLog
	if err := json.Unmarshal(sarifData, &sarifLog); err != nil {
		return &ReportValidationError{Field: "sarif", Message: "invalid SARIF JSON: " + err.Error()}
	}

	// Validate required fields
	if sarifLog.Version == "" {
		return &ReportValidationError{Field: "version", Message: "SARIF version is missing"}
	}
	if sarifLog.Schema == "" {
		return &ReportValidationError{Field: "$schema", Message: "SARIF schema is missing"}
	}
	if len(sarifLog.Runs) == 0 {
		return &ReportValidationError{Field: "runs", Message: "SARIF runs array is empty"}
	}

	return nil
}

// ParseSARIFReport parses SARIF data into a SARIFLog
func ParseSARIFReport(sarifData []byte) (*SARIFLog, error) {
	var sarifLog SARIFLog
	if err := json.Unmarshal(sarifData, &sarifLog); err != nil {
		return nil, err
	}
	return &sarifLog, nil
}

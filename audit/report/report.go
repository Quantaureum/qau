// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"io"
	"time"

	"github.com/quantaureum/qau/audit"
)

// ReportFormat defines output format
type ReportFormat string

const (
	FormatJSON  ReportFormat = "json"
	FormatHTML  ReportFormat = "html"
	FormatSARIF ReportFormat = "sarif"
)

// ReportSummary provides overview statistics
type ReportSummary struct {
	TotalFindings      int `json:"total_findings"`
	CriticalCount      int `json:"critical_count"`
	HighCount          int `json:"high_count"`
	MediumCount        int `json:"medium_count"`
	LowCount           int `json:"low_count"`
	InfoCount          int `json:"info_count"`
	FixedCount         int `json:"fixed_count"`
	DependencyCount    int `json:"dependency_count"`
	VulnerableDepCount int `json:"vulnerable_dep_count"`
}

// ReportMetadata contains report metadata
type ReportMetadata struct {
	Version     string   `json:"version"`
	GeneratedBy string   `json:"generated_by"`
	TargetPath  string   `json:"target_path"`
	Scanners    []string `json:"scanners"`
}

// OWASPCategory represents OWASP Top 10 2021 categories
type OWASPCategory string

const (
	OWASPA01 OWASPCategory = "A01:2021-Broken Access Control"
	OWASPA02 OWASPCategory = "A02:2021-Cryptographic Failures"
	OWASPA03 OWASPCategory = "A03:2021-Injection"
	OWASPA04 OWASPCategory = "A04:2021-Insecure Design"
	OWASPA05 OWASPCategory = "A05:2021-Security Misconfiguration"
	OWASPA06 OWASPCategory = "A06:2021-Vulnerable and Outdated Components"
	OWASPA07 OWASPCategory = "A07:2021-Identification and Authentication Failures"
	OWASPA08 OWASPCategory = "A08:2021-Software and Data Integrity Failures"
	OWASPA09 OWASPCategory = "A09:2021-Security Logging and Monitoring Failures"
	OWASPA10 OWASPCategory = "A10:2021-Server-Side Request Forgery"
)

// AuditReport is the complete audit report
type AuditReport struct {
	Timestamp time.Time       `json:"timestamp"`
	Duration  time.Duration   `json:"duration"`
	Summary   ReportSummary   `json:"summary"`
	Findings  []audit.Finding `json:"findings"`
	Metadata  ReportMetadata  `json:"metadata"`
}

// Reporter generates audit reports
type Reporter interface {
	// Generate creates a report from scan results
	Generate(results []*audit.ScanResult) (*AuditReport, error)
	// Write outputs the report to a writer
	Write(report *AuditReport, w io.Writer) error
	// Format returns the report format
	Format() ReportFormat
}

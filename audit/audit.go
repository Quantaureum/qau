// Quantaureum Node source, version 1.0.0.
// Package audit provides security vulnerability scanning and auditing for QAU.
// It includes scanners for dependencies, cryptography, input validation,
// key management, and network security.
package audit

import (
	"context"
	"time"
)

// SeverityLevel defines finding severity
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "CRITICAL"
	SeverityHigh     SeverityLevel = "HIGH"
	SeverityMedium   SeverityLevel = "MEDIUM"
	SeverityLow      SeverityLevel = "LOW"
	SeverityInfo     SeverityLevel = "INFO"
)

// EffortLevel estimates remediation effort
type EffortLevel string

const (
	EffortTrivial  EffortLevel = "TRIVIAL"  // < 1 hour
	EffortLow      EffortLevel = "LOW"      // 1-4 hours
	EffortMedium   EffortLevel = "MEDIUM"   // 1-2 days
	EffortHigh     EffortLevel = "HIGH"     // 3-5 days
	EffortCritical EffortLevel = "CRITICAL" // > 1 week
)

// FindingStatus tracks remediation status
type FindingStatus string

const (
	StatusOpen     FindingStatus = "OPEN"
	StatusFixed    FindingStatus = "FIXED"
	StatusAccepted FindingStatus = "ACCEPTED"
	StatusFalsePos FindingStatus = "FALSE_POSITIVE"
)

// Location identifies where the finding was detected
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Column    int    `json:"column,omitempty"`
	Function  string `json:"function,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
}

// Remediation provides fix guidance
type Remediation struct {
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	CodeFix     string   `json:"code_fix,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Finding represents a security finding
type Finding struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    SeverityLevel `json:"severity"`
	Category    string        `json:"category"`
	Location    Location      `json:"location"`
	Remediation Remediation   `json:"remediation"`
	References  []string      `json:"references"`
	CWE         string        `json:"cwe,omitempty"`
	CVE         string        `json:"cve,omitempty"`
	Effort      EffortLevel   `json:"effort"`
	Status      FindingStatus `json:"status"`
}

// IsComplete checks if a Finding has all required fields populated
func (f *Finding) IsComplete() bool {
	return f.ID != "" &&
		f.Title != "" &&
		f.Description != "" &&
		f.Severity != "" &&
		f.Category != "" &&
		f.Location.File != "" &&
		f.Location.StartLine > 0 &&
		f.Remediation.Description != "" &&
		len(f.Remediation.Steps) > 0 &&
		f.Effort != "" &&
		f.Status != ""
}

// HasValidSeverity checks if the severity is a valid value
func (f *Finding) HasValidSeverity() bool {
	switch f.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

// HasValidEffort checks if the effort is a valid value
func (f *Finding) HasValidEffort() bool {
	switch f.Effort {
	case EffortTrivial, EffortLow, EffortMedium, EffortHigh, EffortCritical:
		return true
	default:
		return false
	}
}

// HasValidStatus checks if the status is a valid value
func (f *Finding) HasValidStatus() bool {
	switch f.Status {
	case StatusOpen, StatusFixed, StatusAccepted, StatusFalsePos:
		return true
	default:
		return false
	}
}

// ScanTarget represents the target of a security scan
type ScanTarget struct {
	RootPath    string         `json:"root_path"`
	Modules     []string       `json:"modules"`
	IncludeTest bool           `json:"include_test"`
	Config      map[string]any `json:"config"`
}

// ScanResult contains findings from a scanner
type ScanResult struct {
	Scanner   string        `json:"scanner"`
	Findings  []Finding     `json:"findings"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
	Error     string        `json:"error,omitempty"`
}

// Scanner interface for all security scanners
type Scanner interface {
	// Name returns the scanner's name
	Name() string
	// Scan performs the security scan on the target
	Scan(ctx context.Context, target *ScanTarget) (*ScanResult, error)
	// Severity returns the default severity level for this scanner
	Severity() SeverityLevel
}

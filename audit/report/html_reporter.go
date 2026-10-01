// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"fmt"
	"html"
	"html/template"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/quantaureum/qau/audit"
)

// HTMLReporter generates HTML format reports
type HTMLReporter struct {
	version  string
	template *template.Template
}

// NewHTMLReporter creates a new HTML reporter
func NewHTMLReporter(version string) *HTMLReporter {
	tmpl := template.Must(template.New("report").Funcs(template.FuncMap{
		"severityClass":  severityClass,
		"formatDuration": formatDuration,
		"formatTime":     formatTime,
		"severityBadge":  severityBadge,
		"effortBadge":    effortBadge,
		"statusBadge":    statusBadge,
		"escapeHTML":     template.HTMLEscapeString,
		"joinStrings":    strings.Join,
		"percentOf":      percentOf,
		"safeURL":        safeURL,
		"owaspCategory": func(f audit.Finding) OWASPCategory {
			return ClassifyFinding(&f)
		},
		"owaspDescription": GetOWASPCategoryDescription,
	}).Parse(getHTMLTemplate()))

	return &HTMLReporter{
		version:  version,
		template: tmpl,
	}
}

// Format returns the report format
func (r *HTMLReporter) Format() ReportFormat {
	return FormatHTML
}

// Generate creates a report from scan results
func (r *HTMLReporter) Generate(results []*audit.ScanResult) (*AuditReport, error) {
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

	sortFindingsBySeverity(report.Findings)
	report.Summary = calculateSummary(report.Findings)

	return report, nil
}

// Write outputs the report to a writer
func (r *HTMLReporter) Write(report *AuditReport, w io.Writer) error {
	return r.template.Execute(w, report)
}

func severityClass(severity audit.SeverityLevel) string {
	switch severity {
	case audit.SeverityCritical:
		return "severity-critical"
	case audit.SeverityHigh:
		return "severity-high"
	case audit.SeverityMedium:
		return "severity-medium"
	case audit.SeverityLow:
		return "severity-low"
	case audit.SeverityInfo:
		return "severity-info"
	default:
		return "severity-unknown"
	}
}

func severityBadge(severity audit.SeverityLevel) template.HTML {
	class := severityClass(severity)
	return template.HTML(fmt.Sprintf("<span class=\"badge %s\">%s</span>", html.EscapeString(class), html.EscapeString(string(severity)))) // #nosec G203 -- HTML output properly escaped via html.EscapeString
}

func effortBadge(effort audit.EffortLevel) template.HTML {
	classes := map[audit.EffortLevel]string{
		audit.EffortTrivial:  "effort-trivial",
		audit.EffortLow:      "effort-low",
		audit.EffortMedium:   "effort-medium",
		audit.EffortHigh:     "effort-high",
		audit.EffortCritical: "effort-critical",
	}
	class := classes[effort]
	if class == "" {
		class = "effort-unknown"
	}
	return template.HTML(fmt.Sprintf("<span class=\"badge %s\">%s</span>", html.EscapeString(class), html.EscapeString(string(effort)))) // #nosec G203 -- HTML output properly escaped via html.EscapeString
}

func statusBadge(status audit.FindingStatus) template.HTML {
	classes := map[audit.FindingStatus]string{
		audit.StatusOpen:     "status-open",
		audit.StatusFixed:    "status-fixed",
		audit.StatusAccepted: "status-accepted",
		audit.StatusFalsePos: "status-false-positive",
	}
	class := classes[status]
	if class == "" {
		class = "status-unknown"
	}
	return template.HTML(fmt.Sprintf("<span class=\"badge %s\">%s</span>", html.EscapeString(class), html.EscapeString(string(status)))) // #nosec G203 -- HTML output properly escaped via html.EscapeString
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%.1fm", d.Minutes())
}

func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05 UTC")
}

func percentOf(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

// safeURL validates and sanitizes a URL for safe use in href attributes.
// Only http, https, and mailto protocols are allowed.
// This prevents XSS attacks via javascript: or data: URLs.
// FIX: GO-2026-4603 - XSS in html/template URLs
func safeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "#invalid-url"
	}
	// Only allow safe protocols
	switch u.Scheme {
	case "http", "https", "mailto":
		return rawURL
	default:
		return "#blocked-url"
	}
}

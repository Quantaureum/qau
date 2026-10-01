// Quantaureum Node source, version 1.0.0.
// Package report provides audit report generation functionality.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/quantaureum/qau/audit"
)

// AlertSeverity defines the severity level of an alert
type AlertSeverity string

const (
	AlertSeverityCritical AlertSeverity = "CRITICAL"
	AlertSeverityHigh     AlertSeverity = "HIGH"
	AlertSeverityMedium   AlertSeverity = "MEDIUM"
	AlertSeverityLow      AlertSeverity = "LOW"
)

// ThresholdConfig defines severity thresholds for generating alerts.
// When finding counts exceed these thresholds, alerts are generated.
// Requirements: 11.4
type ThresholdConfig struct {
	// Global thresholds apply to all scanners
	Global SeverityThresholds `json:"global"`
	// PerScanner thresholds override global for specific scanners
	PerScanner map[string]SeverityThresholds `json:"per_scanner,omitempty"`
	// BlockOnCritical blocks the build when critical findings exceed threshold
	BlockOnCritical bool `json:"block_on_critical"`
	// BlockOnHigh blocks the build when high findings exceed threshold
	BlockOnHigh bool `json:"block_on_high"`
}

// SeverityThresholds defines maximum allowed findings per severity level.
// A value of -1 means no limit (disabled).
// A value of 0 means any finding at that level triggers an alert.
type SeverityThresholds struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// DefaultThresholdConfig returns sensible default thresholds
func DefaultThresholdConfig() *ThresholdConfig {
	return &ThresholdConfig{
		Global: SeverityThresholds{
			Critical: 0,  // Any critical finding triggers alert
			High:     5,  // More than 5 high findings triggers alert
			Medium:   20, // More than 20 medium findings triggers alert
			Low:      -1, // No limit on low findings
			Info:     -1, // No limit on info findings
			Total:    50, // More than 50 total findings triggers alert
		},
		PerScanner:      make(map[string]SeverityThresholds),
		BlockOnCritical: true,
		BlockOnHigh:     false,
	}
}

// NewThresholdConfig creates a threshold config with custom values
func NewThresholdConfig(critical, high, medium, low, info, total int) *ThresholdConfig {
	return &ThresholdConfig{
		Global: SeverityThresholds{
			Critical: critical,
			High:     high,
			Medium:   medium,
			Low:      low,
			Info:     info,
			Total:    total,
		},
		PerScanner:      make(map[string]SeverityThresholds),
		BlockOnCritical: critical == 0,
		BlockOnHigh:     high == 0,
	}
}

// SetScannerThreshold sets a custom threshold for a specific scanner
func (c *ThresholdConfig) SetScannerThreshold(scanner string, thresholds SeverityThresholds) {
	if c.PerScanner == nil {
		c.PerScanner = make(map[string]SeverityThresholds)
	}
	c.PerScanner[scanner] = thresholds
}

// GetThresholdForScanner returns the threshold for a specific scanner.
// If no scanner-specific threshold exists, returns the global threshold.
func (c *ThresholdConfig) GetThresholdForScanner(scanner string) SeverityThresholds {
	if c.PerScanner != nil {
		if t, ok := c.PerScanner[scanner]; ok {
			return t
		}
	}
	return c.Global
}

// IsThresholdEnabled checks if a threshold is enabled (not -1)
func (t SeverityThresholds) IsThresholdEnabled(severity audit.SeverityLevel) bool {
	switch severity {
	case audit.SeverityCritical:
		return t.Critical >= 0
	case audit.SeverityHigh:
		return t.High >= 0
	case audit.SeverityMedium:
		return t.Medium >= 0
	case audit.SeverityLow:
		return t.Low >= 0
	case audit.SeverityInfo:
		return t.Info >= 0
	default:
		return false
	}
}

// GetThreshold returns the threshold value for a severity level
func (t SeverityThresholds) GetThreshold(severity audit.SeverityLevel) int {
	switch severity {
	case audit.SeverityCritical:
		return t.Critical
	case audit.SeverityHigh:
		return t.High
	case audit.SeverityMedium:
		return t.Medium
	case audit.SeverityLow:
		return t.Low
	case audit.SeverityInfo:
		return t.Info
	default:
		return -1
	}
}

// LoadThresholdConfig loads threshold configuration from a JSON file
func LoadThresholdConfig(path string) (*ThresholdConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, err
	}

	var config ThresholdConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	if config.PerScanner == nil {
		config.PerScanner = make(map[string]SeverityThresholds)
	}

	return &config, nil
}

// SaveThresholdConfig saves threshold configuration to a JSON file
func (c *ThresholdConfig) SaveThresholdConfig(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Alert represents a threshold violation alert.
// Generated when finding counts exceed configured thresholds.
// Requirements: 11.4
type Alert struct {
	ID              string          `json:"id"`
	Timestamp       time.Time       `json:"timestamp"`
	Severity        AlertSeverity   `json:"severity"`
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	Scanner         string          `json:"scanner,omitempty"`
	ThresholdType   string          `json:"threshold_type"`
	ThresholdValue  int             `json:"threshold_value"`
	ActualValue     int             `json:"actual_value"`
	Exceeded        bool            `json:"exceeded"`
	Recommendations []string        `json:"recommendations"`
	Findings        []audit.Finding `json:"findings,omitempty"`
	ShouldBlock     bool            `json:"should_block"`
}

// AlertResult contains all alerts generated from an audit
type AlertResult struct {
	Timestamp    time.Time `json:"timestamp"`
	ReportID     string    `json:"report_id,omitempty"`
	Alerts       []Alert   `json:"alerts"`
	TotalAlerts  int       `json:"total_alerts"`
	BlockBuild   bool      `json:"block_build"`
	BlockReasons []string  `json:"block_reasons,omitempty"`
}

// AlertGenerator generates alerts based on threshold configuration.
// It evaluates audit results against configured thresholds and
// produces actionable alerts when thresholds are exceeded.
// Requirements: 11.4
type AlertGenerator struct {
	mu     sync.RWMutex
	config *ThresholdConfig
}

// NewAlertGenerator creates a new alert generator with the given config
func NewAlertGenerator(config *ThresholdConfig) *AlertGenerator {
	if config == nil {
		config = DefaultThresholdConfig()
	}
	return &AlertGenerator{
		config: config,
	}
}

// GetConfig returns the current threshold configuration
func (g *AlertGenerator) GetConfig() *ThresholdConfig {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.config
}

// SetConfig updates the threshold configuration
func (g *AlertGenerator) SetConfig(config *ThresholdConfig) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.config = config
}

// GenerateAlerts evaluates an audit report against thresholds and generates alerts.
// Returns an AlertResult containing all generated alerts and block status.
// Requirements: 11.4
func (g *AlertGenerator) GenerateAlerts(report *AuditReport) (*AlertResult, error) {
	if report == nil {
		return nil, errors.New("report cannot be nil")
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	result := &AlertResult{
		Timestamp:    time.Now().UTC(),
		Alerts:       make([]Alert, 0),
		BlockReasons: make([]string, 0),
	}

	// Check global thresholds
	globalAlerts := g.checkThresholds("", report.Summary, report.Findings, g.config.Global)
	result.Alerts = append(result.Alerts, globalAlerts...)

	// Check per-scanner thresholds if configured
	if len(g.config.PerScanner) > 0 {
		scannerFindings := groupFindingsByScanner(report.Findings)
		for scanner, thresholds := range g.config.PerScanner {
			findings := scannerFindings[scanner]
			summary := calculateSummaryFromFindings(findings)
			scannerAlerts := g.checkThresholds(scanner, summary, findings, thresholds)
			result.Alerts = append(result.Alerts, scannerAlerts...)
		}
	}

	result.TotalAlerts = len(result.Alerts)

	// Determine if build should be blocked
	for _, alert := range result.Alerts {
		if alert.ShouldBlock {
			result.BlockBuild = true
			result.BlockReasons = append(result.BlockReasons, alert.Title)
		}
	}

	return result, nil
}

// checkThresholds evaluates findings against thresholds and generates alerts
func (g *AlertGenerator) checkThresholds(scanner string, summary ReportSummary, findings []audit.Finding, thresholds SeverityThresholds) []Alert {
	alerts := make([]Alert, 0)
	prefix := "Global"
	if scanner != "" {
		prefix = fmt.Sprintf("Scanner '%s'", scanner)
	}

	// Check critical threshold
	if thresholds.Critical >= 0 && summary.CriticalCount > thresholds.Critical {
		alert := g.createAlert(
			scanner,
			AlertSeverityCritical,
			fmt.Sprintf("%s: Critical findings threshold exceeded", prefix),
			fmt.Sprintf("Found %d critical findings, threshold is %d", summary.CriticalCount, thresholds.Critical),
			"critical",
			thresholds.Critical,
			summary.CriticalCount,
			filterFindingsBySeverity(findings, audit.SeverityCritical),
			g.config.BlockOnCritical,
		)
		alerts = append(alerts, alert)
	}

	// Check high threshold
	if thresholds.High >= 0 && summary.HighCount > thresholds.High {
		alert := g.createAlert(
			scanner,
			AlertSeverityHigh,
			fmt.Sprintf("%s: High findings threshold exceeded", prefix),
			fmt.Sprintf("Found %d high severity findings, threshold is %d", summary.HighCount, thresholds.High),
			"high",
			thresholds.High,
			summary.HighCount,
			filterFindingsBySeverity(findings, audit.SeverityHigh),
			g.config.BlockOnHigh,
		)
		alerts = append(alerts, alert)
	}

	// Check medium threshold
	if thresholds.Medium >= 0 && summary.MediumCount > thresholds.Medium {
		alert := g.createAlert(
			scanner,
			AlertSeverityMedium,
			fmt.Sprintf("%s: Medium findings threshold exceeded", prefix),
			fmt.Sprintf("Found %d medium severity findings, threshold is %d", summary.MediumCount, thresholds.Medium),
			"medium",
			thresholds.Medium,
			summary.MediumCount,
			filterFindingsBySeverity(findings, audit.SeverityMedium),
			false,
		)
		alerts = append(alerts, alert)
	}

	// Check low threshold
	if thresholds.Low >= 0 && summary.LowCount > thresholds.Low {
		alert := g.createAlert(
			scanner,
			AlertSeverityLow,
			fmt.Sprintf("%s: Low findings threshold exceeded", prefix),
			fmt.Sprintf("Found %d low severity findings, threshold is %d", summary.LowCount, thresholds.Low),
			"low",
			thresholds.Low,
			summary.LowCount,
			nil, // Don't include low severity findings in alert
			false,
		)
		alerts = append(alerts, alert)
	}

	// Check total threshold
	if thresholds.Total >= 0 && summary.TotalFindings > thresholds.Total {
		alert := g.createAlert(
			scanner,
			AlertSeverityMedium,
			fmt.Sprintf("%s: Total findings threshold exceeded", prefix),
			fmt.Sprintf("Found %d total findings, threshold is %d", summary.TotalFindings, thresholds.Total),
			"total",
			thresholds.Total,
			summary.TotalFindings,
			nil,
			false,
		)
		alerts = append(alerts, alert)
	}

	return alerts
}

// createAlert creates an alert with recommendations
func (g *AlertGenerator) createAlert(scanner string, severity AlertSeverity, title, description, thresholdType string, threshold, actual int, findings []audit.Finding, shouldBlock bool) Alert {
	alert := Alert{
		ID:              generateAlertID(scanner, thresholdType),
		Timestamp:       time.Now().UTC(),
		Severity:        severity,
		Title:           title,
		Description:     description,
		Scanner:         scanner,
		ThresholdType:   thresholdType,
		ThresholdValue:  threshold,
		ActualValue:     actual,
		Exceeded:        actual > threshold,
		Recommendations: generateRecommendations(severity, thresholdType, actual-threshold),
		Findings:        findings,
		ShouldBlock:     shouldBlock,
	}
	return alert
}

// generateAlertID creates a unique alert identifier
func generateAlertID(scanner, thresholdType string) string {
	timestamp := time.Now().UnixNano()
	if scanner == "" {
		return fmt.Sprintf("alert-global-%s-%d", thresholdType, timestamp)
	}
	return fmt.Sprintf("alert-%s-%s-%d", scanner, thresholdType, timestamp)
}

// generateRecommendations creates actionable recommendations based on alert type
func generateRecommendations(severity AlertSeverity, thresholdType string, exceededBy int) []string {
	recommendations := make([]string, 0)

	switch severity {
	case AlertSeverityCritical:
		recommendations = append(recommendations,
			"Immediately review and address all critical findings",
			"Critical findings may indicate severe security vulnerabilities",
			"Consider blocking deployment until critical issues are resolved",
			"Assign dedicated resources to remediate critical findings",
		)
	case AlertSeverityHigh:
		recommendations = append(recommendations,
			"Prioritize remediation of high severity findings",
			"Review findings for potential security impact",
			"Create tickets for tracking high severity issues",
			"Consider security review before deployment",
		)
	case AlertSeverityMedium:
		recommendations = append(recommendations,
			"Schedule remediation of medium severity findings",
			"Include findings in sprint planning",
			"Review for patterns that may indicate systemic issues",
		)
	case AlertSeverityLow:
		recommendations = append(recommendations,
			"Address low severity findings during regular maintenance",
			"Consider automated fixes where applicable",
		)
	}

	if thresholdType == "total" {
		recommendations = append(recommendations,
			fmt.Sprintf("Total findings exceeded threshold by %d", exceededBy),
			"Consider increasing code review coverage",
			"Review development practices to reduce finding generation",
		)
	}

	return recommendations
}

// Helper functions

// groupFindingsByScanner groups findings by their source scanner
func groupFindingsByScanner(findings []audit.Finding) map[string][]audit.Finding {
	grouped := make(map[string][]audit.Finding)
	for _, f := range findings {
		grouped[f.Category] = append(grouped[f.Category], f)
	}
	return grouped
}

// calculateSummaryFromFindings calculates a summary from a slice of findings
func calculateSummaryFromFindings(findings []audit.Finding) ReportSummary {
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
	}
	return summary
}

// filterFindingsBySeverity returns findings matching the specified severity
func filterFindingsBySeverity(findings []audit.Finding, severity audit.SeverityLevel) []audit.Finding {
	filtered := make([]audit.Finding, 0)
	for _, f := range findings {
		if f.Severity == severity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// CheckThresholds is a convenience function to check thresholds without creating an AlertGenerator
func CheckThresholds(report *AuditReport, config *ThresholdConfig) (*AlertResult, error) {
	generator := NewAlertGenerator(config)
	return generator.GenerateAlerts(report)
}

// HasExceededThresholds checks if any thresholds have been exceeded
func HasExceededThresholds(result *AlertResult) bool {
	return result != nil && len(result.Alerts) > 0
}

// ShouldBlockBuild checks if the build should be blocked based on alerts
func ShouldBlockBuild(result *AlertResult) bool {
	return result != nil && result.BlockBuild
}

// GetCriticalAlerts returns only critical severity alerts
func GetCriticalAlerts(result *AlertResult) []Alert {
	if result == nil {
		return nil
	}
	critical := make([]Alert, 0)
	for _, a := range result.Alerts {
		if a.Severity == AlertSeverityCritical {
			critical = append(critical, a)
		}
	}
	return critical
}

// GetBlockingAlerts returns alerts that should block the build
func GetBlockingAlerts(result *AlertResult) []Alert {
	if result == nil {
		return nil
	}
	blocking := make([]Alert, 0)
	for _, a := range result.Alerts {
		if a.ShouldBlock {
			blocking = append(blocking, a)
		}
	}
	return blocking
}

// FormatAlertSummary creates a human-readable summary of alerts
func FormatAlertSummary(result *AlertResult) string {
	if result == nil || len(result.Alerts) == 0 {
		return "No threshold alerts generated"
	}

	summary := fmt.Sprintf("Generated %d alert(s):\n", result.TotalAlerts)
	for _, alert := range result.Alerts {
		summary += fmt.Sprintf("  - [%s] %s (exceeded by %d)\n",
			alert.Severity, alert.Title, alert.ActualValue-alert.ThresholdValue)
	}

	if result.BlockBuild {
		summary += fmt.Sprintf("\nBuild blocked due to: %v\n", result.BlockReasons)
	}

	return summary
}

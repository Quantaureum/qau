// Quantaureum Node source, version 1.0.0.
// Package config provides audit configuration management.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quantaureum/qau/audit"
	"github.com/quantaureum/qau/audit/report"
)

// AuditConfig defines audit configuration
type AuditConfig struct {
	// Target configuration
	RootPath     string   `json:"root_path"`
	IncludePaths []string `json:"include_paths"`
	ExcludePaths []string `json:"exclude_paths"`

	// Scanner configuration
	EnabledScanners []string       `json:"enabled_scanners"`
	ScannerConfigs  map[string]any `json:"scanner_configs"`

	// Severity thresholds
	MinSeverity    audit.SeverityLevel `json:"min_severity"`
	FailOnSeverity audit.SeverityLevel `json:"fail_on_severity"`

	// Output configuration
	OutputFormat report.ReportFormat `json:"output_format"`
	OutputPath   string              `json:"output_path"`

	// CI/CD configuration
	CIMode       bool   `json:"ci_mode"`
	BaselineFile string `json:"baseline_file"`
}

// DefaultConfig returns a default audit configuration
func DefaultConfig() *AuditConfig {
	return &AuditConfig{
		RootPath:     ".",
		IncludePaths: []string{},
		ExcludePaths: []string{"vendor", "node_modules", ".git"},
		EnabledScanners: []string{
			// Core security scanners
			"dependency", "crypto", "validation", "keymanagement", "network",
			// Static analysis
			"static",
			// Blockchain-specific scanners
			"blockchain", "economics", "p2p",
		},
		ScannerConfigs: make(map[string]any),
		MinSeverity:    audit.SeverityInfo,
		FailOnSeverity: audit.SeverityHigh,
		OutputFormat:   report.FormatJSON,
		OutputPath:     "audit-report.json",
		CIMode:         false,
		BaselineFile:   "",
	}
}

// Validate checks if the configuration is valid
func (c *AuditConfig) Validate() error {
	if c.RootPath == "" {
		return fmt.Errorf("root_path is required")
	}

	// Validate severity levels
	if !isValidSeverity(c.MinSeverity) {
		return fmt.Errorf("invalid min_severity: %s", c.MinSeverity)
	}
	if !isValidSeverity(c.FailOnSeverity) {
		return fmt.Errorf("invalid fail_on_severity: %s", c.FailOnSeverity)
	}

	// Validate output format
	if !isValidFormat(c.OutputFormat) {
		return fmt.Errorf("invalid output_format: %s", c.OutputFormat)
	}

	return nil
}

// isValidSeverity checks if a severity level is valid
func isValidSeverity(s audit.SeverityLevel) bool {
	switch s {
	case audit.SeverityCritical, audit.SeverityHigh, audit.SeverityMedium,
		audit.SeverityLow, audit.SeverityInfo:
		return true
	default:
		return false
	}
}

// isValidFormat checks if a report format is valid
func isValidFormat(f report.ReportFormat) bool {
	switch f {
	case report.FormatJSON, report.FormatHTML, report.FormatSARIF:
		return true
	default:
		return false
	}
}

// LoadFromFile loads configuration from a JSON or YAML file
func LoadFromFile(path string) (*AuditConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return loadJSON(data)
	case ".yaml", ".yml":
		return loadYAML(data)
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", ext)
	}
}

// loadJSON parses JSON configuration
func loadJSON(data []byte) (*AuditConfig, error) {
	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config: %w", err)
	}
	return config, nil
}

// loadYAML parses YAML configuration (simplified - converts basic YAML to JSON)
func loadYAML(data []byte) (*AuditConfig, error) {
	// Convert simple YAML to JSON for parsing
	// This handles basic key: value pairs and arrays
	jsonData := convertSimpleYAMLToJSON(data)
	return loadJSON(jsonData)
}

// convertSimpleYAMLToJSON converts basic YAML syntax to JSON
// Supports: key: value, key: [array], indented objects
func convertSimpleYAMLToJSON(yamlData []byte) []byte {
	lines := strings.Split(string(yamlData), "\n")
	var result strings.Builder
	result.WriteString("{")

	first := true
	for _, line := range lines {
		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Parse key: value
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if !first {
			result.WriteString(",")
		}
		first = false

		result.WriteString(fmt.Sprintf(`"%s":`, key))

		// Handle different value types
		if value == "" {
			result.WriteString("null")
		} else if strings.HasPrefix(value, "[") {
			// Array - pass through
			result.WriteString(value)
		} else if value == "true" || value == "false" {
			// Boolean
			result.WriteString(value)
		} else if _, err := fmt.Sscanf(value, "%d", new(int)); err == nil {
			// Integer
			result.WriteString(value)
		} else if strings.HasPrefix(value, `"`) {
			// Already quoted string
			result.WriteString(value)
		} else {
			// Unquoted string - quote it
			result.WriteString(fmt.Sprintf(`"%s"`, value))
		}
	}

	result.WriteString("}")
	return []byte(result.String())
}

// SaveToFile saves configuration to a JSON file
func (c *AuditConfig) SaveToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Merge merges another config into this one (other takes precedence)
func (c *AuditConfig) Merge(other *AuditConfig) {
	if other == nil {
		return
	}

	if other.RootPath != "" {
		c.RootPath = other.RootPath
	}
	if len(other.IncludePaths) > 0 {
		c.IncludePaths = other.IncludePaths
	}
	if len(other.ExcludePaths) > 0 {
		c.ExcludePaths = other.ExcludePaths
	}
	if len(other.EnabledScanners) > 0 {
		c.EnabledScanners = other.EnabledScanners
	}
	if other.MinSeverity != "" {
		c.MinSeverity = other.MinSeverity
	}
	if other.FailOnSeverity != "" {
		c.FailOnSeverity = other.FailOnSeverity
	}
	if other.OutputFormat != "" {
		c.OutputFormat = other.OutputFormat
	}
	if other.OutputPath != "" {
		c.OutputPath = other.OutputPath
	}
	if other.BaselineFile != "" {
		c.BaselineFile = other.BaselineFile
	}
	c.CIMode = other.CIMode

	// Merge scanner configs
	for k, v := range other.ScannerConfigs {
		c.ScannerConfigs[k] = v
	}
}

// IsScannerEnabled checks if a scanner is enabled
func (c *AuditConfig) IsScannerEnabled(name string) bool {
	for _, s := range c.EnabledScanners {
		if s == name {
			return true
		}
	}
	return false
}

// GetScannerConfig returns the configuration for a specific scanner
func (c *AuditConfig) GetScannerConfig(name string) (any, bool) {
	config, ok := c.ScannerConfigs[name]
	return config, ok
}

// ApplyEnvironmentOverrides applies environment variable overrides to the config
// Environment variables use the prefix QAU_AUDIT_ followed by the config key in uppercase
// Examples:
//   - QAU_AUDIT_ROOT_PATH=/path/to/scan
//   - QAU_AUDIT_OUTPUT_FORMAT=html
//   - QAU_AUDIT_CI_MODE=true
//   - QAU_AUDIT_MIN_SEVERITY=high
//   - QAU_AUDIT_ENABLED_SCANNERS=crypto,validation,static
func (c *AuditConfig) ApplyEnvironmentOverrides() {
	const prefix = "QAU_AUDIT_"

	// Root path
	if val := os.Getenv(prefix + "ROOT_PATH"); val != "" {
		c.RootPath = val
	}

	// Output format
	if val := os.Getenv(prefix + "OUTPUT_FORMAT"); val != "" {
		c.OutputFormat = report.ReportFormat(strings.ToLower(val))
	}

	// Output path
	if val := os.Getenv(prefix + "OUTPUT_PATH"); val != "" {
		c.OutputPath = val
	}

	// CI mode
	if val := os.Getenv(prefix + "CI_MODE"); val != "" {
		c.CIMode = strings.ToLower(val) == "true" || val == "1"
	}

	// Min severity
	if val := os.Getenv(prefix + "MIN_SEVERITY"); val != "" {
		c.MinSeverity = parseSeverityFromString(val)
	}

	// Fail on severity
	if val := os.Getenv(prefix + "FAIL_ON_SEVERITY"); val != "" {
		c.FailOnSeverity = parseSeverityFromString(val)
	}

	// Enabled scanners (comma-separated)
	if val := os.Getenv(prefix + "ENABLED_SCANNERS"); val != "" {
		c.EnabledScanners = strings.Split(val, ",")
		// Trim whitespace from each scanner name
		for i, s := range c.EnabledScanners {
			c.EnabledScanners[i] = strings.TrimSpace(s)
		}
	}

	// Baseline file
	if val := os.Getenv(prefix + "BASELINE_FILE"); val != "" {
		c.BaselineFile = val
	}
}

// parseSeverityFromString converts a string to SeverityLevel
func parseSeverityFromString(s string) audit.SeverityLevel {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return audit.SeverityCritical
	case "HIGH":
		return audit.SeverityHigh
	case "MEDIUM":
		return audit.SeverityMedium
	case "LOW":
		return audit.SeverityLow
	case "INFO":
		return audit.SeverityInfo
	default:
		return audit.SeverityInfo
	}
}

// LoadConfigWithOverrides loads config from file and applies environment overrides
func LoadConfigWithOverrides(path string) (*AuditConfig, error) {
	var cfg *AuditConfig
	var err error

	if path != "" {
		cfg, err = LoadFromFile(path)
		if err != nil {
			return nil, err
		}
	} else {
		cfg = DefaultConfig()
	}

	// Apply environment variable overrides
	cfg.ApplyEnvironmentOverrides()

	return cfg, nil
}

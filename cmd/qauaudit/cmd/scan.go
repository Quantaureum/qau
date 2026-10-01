// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the QAU Security Audit tool.
package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/quantaureum/qau/audit"
	"github.com/quantaureum/qau/audit/config"
	"github.com/quantaureum/qau/audit/report"
	"github.com/quantaureum/qau/audit/scanner"
)

// newScanCmd creates the scan command
func newScanCmd(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Run security audit scan",
		Long: `Run a comprehensive security audit scan on the specified path.

The scan will analyze the codebase for security vulnerabilities including:
  - Known CVEs in dependencies
  - Cryptographic weaknesses
  - Input validation issues
  - Key management problems
  - Network security concerns

By default, all scanners are enabled. Use --scanners to select specific ones.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runScan(version),
	}

	// Scan-specific flags
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: stdout for JSON, audit-report.html for HTML)")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "json", "Output format: json, html, sarif")
	cmd.Flags().StringSliceVarP(&scanners, "scanners", "s", nil, "Scanners to run (comma-separated): dependency,crypto,validation,keymanagement,network")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "info", "Minimum severity to report: critical,high,medium,low,info")
	cmd.Flags().StringVar(&failOnSeverity, "fail-on", "high", "Fail (exit non-zero) on findings at or above this severity")
	cmd.Flags().BoolVar(&ciMode, "ci", false, "CI mode: return non-zero exit code on findings above threshold")
	cmd.Flags().StringVar(&baselineFile, "baseline", "", "Baseline file for comparison (only report new findings)")
	cmd.Flags().BoolVar(&fastMode, "fast", false, "Fast mode: run only quick scanners (crypto, validation) for pre-commit hooks")

	return cmd
}

// runScan executes the security audit scan
func runScan(version string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		// Determine target path
		target := "."
		if len(args) > 0 {
			target = args[0]
		}

		// Load configuration
		cfg := loadConfig()
		cfg.RootPath = target

		// Override config with command-line flags
		applyFlags(cfg)

		// Validate configuration
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Print scan info if verbose
		if verbose {
			printScanInfo(cfg)
		}

		// Run the scan
		results, err := runScanners(ctx, cfg)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		// Generate report
		generator := report.NewReportGenerator(version)
		auditReport, err := generator.GenerateReport(ctx, results, cfg.RootPath)
		if err != nil {
			return fmt.Errorf("failed to generate report: %w", err)
		}

		// Apply baseline filtering if specified
		if cfg.BaselineFile != "" {
			auditReport, err = applyBaseline(auditReport, cfg.BaselineFile)
			if err != nil {
				return fmt.Errorf("failed to apply baseline: %w", err)
			}
		}

		// Filter by minimum severity
		auditReport.Findings = report.FilterBySeverity(auditReport.Findings, cfg.MinSeverity)
		auditReport.Summary = recalculateSummary(auditReport.Findings)

		// Output report
		if err := outputReport(auditReport, cfg, generator); err != nil {
			return fmt.Errorf("failed to output report: %w", err)
		}

		// Set exit code for CI mode
		if cfg.CIMode {
			calculator := NewExitCodeCalculator(cfg.FailOnSeverity)
			exitCode = calculator.Calculate(auditReport.Findings)

			if verbose && exitCode != ExitSuccess {
				count := calculator.CountFindingsAboveThreshold(auditReport.Findings)
				fmt.Printf("\nCI Mode: Found %d findings at or above %s severity\n", count, cfg.FailOnSeverity)
			}
		}

		// Print summary if verbose
		if verbose {
			printSummary(auditReport)
		}

		return nil
	}
}

// loadConfig loads configuration from file or returns default
// Also applies environment variable overrides
func loadConfig() *config.AuditConfig {
	cfg, err := config.LoadConfigWithOverrides(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load config file: %v, using defaults\n", err)
		cfg = config.DefaultConfig()
		cfg.ApplyEnvironmentOverrides()
	}
	return cfg
}

// applyFlags applies command-line flags to configuration
func applyFlags(cfg *config.AuditConfig) {
	if outputPath != "" {
		cfg.OutputPath = outputPath
	}
	if outputFormat != "" {
		cfg.OutputFormat = report.ReportFormat(strings.ToLower(outputFormat))
	}
	if len(scanners) > 0 {
		cfg.EnabledScanners = expandScannerGroups(scanners)
	}
	// Fast mode overrides scanners to use only quick scanners
	if fastMode {
		cfg.EnabledScanners = []string{"crypto", "validation", "static"}
	}
	if minSeverity != "" {
		cfg.MinSeverity = parseSeverity(minSeverity)
	}
	if failOnSeverity != "" {
		cfg.FailOnSeverity = parseSeverity(failOnSeverity)
	}
	cfg.CIMode = ciMode
	if baselineFile != "" {
		cfg.BaselineFile = baselineFile
	}
}

// expandScannerGroups expands scanner group names to individual scanners
func expandScannerGroups(scannerList []string) []string {
	// Define scanner groups
	groups := map[string][]string{
		"all": {
			"dependency", "crypto", "validation", "keymanagement", "network",
			"static", "blockchain", "economics", "p2p",
		},
		"core": {
			"dependency", "crypto", "validation", "keymanagement", "network",
		},
		"blockchain": {
			"blockchain", "economics", "p2p",
		},
		"fast": {
			"crypto", "validation", "static",
		},
	}

	result := make([]string, 0)
	seen := make(map[string]bool)

	for _, s := range scannerList {
		// Check if it's a group name
		if group, isGroup := groups[strings.ToLower(s)]; isGroup {
			for _, scanner := range group {
				if !seen[scanner] {
					result = append(result, scanner)
					seen[scanner] = true
				}
			}
		} else {
			// Individual scanner
			if !seen[s] {
				result = append(result, s)
				seen[s] = true
			}
		}
	}

	return result
}

// parseSeverity converts string to SeverityLevel
func parseSeverity(s string) audit.SeverityLevel {
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

// runScanners executes all enabled scanners
func runScanners(ctx context.Context, cfg *config.AuditConfig) ([]*audit.ScanResult, error) {
	target := &audit.ScanTarget{
		RootPath:    cfg.RootPath,
		IncludeTest: false,
		Config:      cfg.ScannerConfigs,
	}

	var results []*audit.ScanResult
	availableScanners := getAvailableScanners()

	for _, name := range cfg.EnabledScanners {
		scannerFactory, ok := availableScanners[name]
		if !ok {
			if verbose {
				fmt.Fprintf(os.Stderr, "Warning: unknown scanner '%s', skipping\n", name)
			}
			continue
		}

		if verbose {
			fmt.Printf("Running scanner: %s\n", name)
		}

		s := scannerFactory()
		result, err := s.Scan(ctx, target)
		if err != nil {
			// Log error but continue with other scanners
			if verbose {
				fmt.Fprintf(os.Stderr, "Warning: scanner '%s' failed: %v\n", name, err)
			}
			result = &audit.ScanResult{
				Scanner:   name,
				Findings:  []audit.Finding{},
				Timestamp: time.Now(),
				Error:     err.Error(),
			}
		}
		results = append(results, result)
	}

	return results, nil
}

// getAvailableScanners returns a map of scanner factories
func getAvailableScanners() map[string]func() audit.Scanner {
	return map[string]func() audit.Scanner{
		// Core scanners
		"dependency":    func() audit.Scanner { return scanner.NewDependencyScanner(nil) }, // nil uses default/offline CVE DB
		"crypto":        func() audit.Scanner { return scanner.NewCryptoScanner() },
		"validation":    func() audit.Scanner { return scanner.NewValidationScanner() },
		"keymanagement": func() audit.Scanner { return scanner.NewKeyManagementScanner() },
		"network":       func() audit.Scanner { return scanner.NewNetworkScanner() },
		// Static analysis scanner
		"static": func() audit.Scanner { return scanner.NewStaticScanner() },
		// Blockchain-specific scanners
		"blockchain": func() audit.Scanner { return scanner.NewBlockchainScanner() },
		"economics":  func() audit.Scanner { return scanner.NewEconomicsScanner() },
		"p2p":        func() audit.Scanner { return scanner.NewP2PSecurityScanner() },
	}
}

// applyBaseline filters out findings that exist in the baseline
func applyBaseline(auditReport *report.AuditReport, baselinePath string) (*report.AuditReport, error) {
	baseline, err := report.LoadBaseline(baselinePath)
	if err != nil {
		return nil, err
	}

	newFindings := make([]audit.Finding, 0)
	for _, f := range auditReport.Findings {
		if !baseline.Contains(f) {
			newFindings = append(newFindings, f)
		}
	}

	auditReport.Findings = newFindings
	auditReport.Summary = recalculateSummary(newFindings)
	return auditReport, nil
}

// recalculateSummary recalculates the summary from findings
func recalculateSummary(findings []audit.Finding) report.ReportSummary {
	summary := report.ReportSummary{
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

// outputReport writes the report to the specified output
func outputReport(auditReport *report.AuditReport, cfg *config.AuditConfig, generator *report.ReportGenerator) error {
	reporter, ok := generator.GetReporter(cfg.OutputFormat)
	if !ok {
		return fmt.Errorf("unsupported output format: %s", cfg.OutputFormat)
	}

	// Determine output destination
	var output *os.File
	var err error

	if cfg.OutputPath == "" || cfg.OutputPath == "-" {
		output = os.Stdout
	} else {
		output, err = os.Create(cfg.OutputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	}

	return reporter.Write(auditReport, output)
}

// printScanInfo prints scan configuration info
func printScanInfo(cfg *config.AuditConfig) {
	fmt.Println("QAU Security Audit")
	fmt.Println("==================")
	fmt.Printf("Target: %s\n", cfg.RootPath)
	fmt.Printf("Scanners: %s\n", strings.Join(cfg.EnabledScanners, ", "))
	fmt.Printf("Min Severity: %s\n", cfg.MinSeverity)
	fmt.Printf("Fail On: %s\n", cfg.FailOnSeverity)
	fmt.Printf("Output Format: %s\n", cfg.OutputFormat)
	if cfg.BaselineFile != "" {
		fmt.Printf("Baseline: %s\n", cfg.BaselineFile)
	}
	fmt.Println()
}

// printSummary prints the audit summary
func printSummary(auditReport *report.AuditReport) {
	fmt.Println()
	fmt.Println("Audit Summary")
	fmt.Println("=============")
	fmt.Printf("Duration: %s\n", auditReport.Duration)
	fmt.Printf("Total Findings: %d\n", auditReport.Summary.TotalFindings)
	fmt.Printf("  Critical: %d\n", auditReport.Summary.CriticalCount)
	fmt.Printf("  High: %d\n", auditReport.Summary.HighCount)
	fmt.Printf("  Medium: %d\n", auditReport.Summary.MediumCount)
	fmt.Printf("  Low: %d\n", auditReport.Summary.LowCount)
	fmt.Printf("  Info: %d\n", auditReport.Summary.InfoCount)
}

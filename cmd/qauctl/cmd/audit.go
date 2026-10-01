// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
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

var (
	// Audit command flags
	auditOutputPath     string
	auditOutputFormat   string
	auditScanners       []string
	auditMinSeverity    string
	auditFailOnSeverity string
	auditCIMode         bool
	auditBaselineFile   string
	auditTimeout        time.Duration
	auditFastMode       bool
)

// newAuditCmd creates the audit command for qauctl
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit [path]",
		Short: "Run security audit on the codebase",
		Long: `Run a comprehensive security audit scan on the specified path.

The audit command provides the same functionality as the standalone qauaudit tool,
integrated into qauctl for convenience.

Available scanner groups:
  all        - Run all scanners
  core       - Core security scanners (dependency, crypto, validation, keymanagement, network)
  blockchain - Blockchain-specific scanners (blockchain, economics, p2p)
  fast       - Quick scanners for pre-commit (crypto, validation, static)

Examples:
  # Run full audit with default settings
  qauctl audit

  # Run audit with specific scanners
  qauctl audit --scanners dependency,crypto

  # Run blockchain-specific audit
  qauctl audit --scanners blockchain

  # Run in CI mode (returns non-zero exit code on findings)
  qauctl audit --ci --fail-on high

  # Generate HTML report
  qauctl audit --format html --output report.html`,
		Args: cobra.MaximumNArgs(1),
		RunE: runAudit,
	}

	// Audit-specific flags
	cmd.Flags().StringVarP(&auditOutputPath, "output", "o", "", "Output file path (default: stdout for JSON)")
	cmd.Flags().StringVarP(&auditOutputFormat, "format", "f", "json", "Output format: json, html, sarif")
	cmd.Flags().StringSliceVarP(&auditScanners, "scanners", "s", nil, "Scanners to run (comma-separated or group name)")
	cmd.Flags().StringVar(&auditMinSeverity, "min-severity", "info", "Minimum severity to report: critical,high,medium,low,info")
	cmd.Flags().StringVar(&auditFailOnSeverity, "fail-on", "high", "Fail (exit non-zero) on findings at or above this severity")
	cmd.Flags().BoolVar(&auditCIMode, "ci", false, "CI mode: return non-zero exit code on findings above threshold")
	cmd.Flags().StringVar(&auditBaselineFile, "baseline", "", "Baseline file for comparison (only report new findings)")
	cmd.Flags().DurationVar(&auditTimeout, "timeout", 30*time.Minute, "Scan timeout duration")
	cmd.Flags().BoolVar(&auditFastMode, "fast", false, "Fast mode: run only quick scanners")

	// Add subcommands
	cmd.AddCommand(newAuditListCmd())
	cmd.AddCommand(newAuditBaselineCmd())

	return cmd
}

// runAudit executes the security audit scan
func runAudit(cmd *cobra.Command, args []string) error {
	// Determine target path
	target := "."
	if len(args) > 0 {
		target = args[0]
	}

	// Load configuration with environment overrides
	cfg, err := config.LoadConfigWithOverrides(configFile)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Warning: failed to load config file: %v, using defaults\n", err)
		}
		cfg = config.DefaultConfig()
		cfg.ApplyEnvironmentOverrides()
	}
	cfg.RootPath = target

	// Apply command-line flags
	applyAuditFlags(cfg)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()

	// Print scan info if verbose
	if verbose {
		printAuditInfo(cfg)
	}

	// Run the scan
	results, err := runAuditScanners(ctx, cfg)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Generate report
	generator := report.NewReportGenerator("1.0.0")
	auditReport, err := generator.GenerateReport(ctx, results, cfg.RootPath)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Apply baseline filtering if specified
	if cfg.BaselineFile != "" {
		auditReport, err = applyAuditBaseline(auditReport, cfg.BaselineFile)
		if err != nil {
			return fmt.Errorf("failed to apply baseline: %w", err)
		}
	}

	// Filter by minimum severity
	auditReport.Findings = report.FilterBySeverity(auditReport.Findings, cfg.MinSeverity)
	auditReport.Summary = recalculateAuditSummary(auditReport.Findings)

	// Output report
	if err := outputAuditReport(auditReport, cfg, generator); err != nil {
		return fmt.Errorf("failed to output report: %w", err)
	}

	// Handle CI mode exit code
	if cfg.CIMode {
		exitCode := calculateExitCode(auditReport.Findings, cfg.FailOnSeverity)
		if exitCode != 0 {
			if verbose {
				count := countFindingsAboveThreshold(auditReport.Findings, cfg.FailOnSeverity)
				fmt.Printf("\nCI Mode: Found %d findings at or above %s severity\n", count, cfg.FailOnSeverity)
			}
			os.Exit(exitCode)
		}
	}

	// Print summary if verbose
	if verbose {
		printAuditSummary(auditReport)
	}

	return nil
}

// applyAuditFlags applies command-line flags to configuration
func applyAuditFlags(cfg *config.AuditConfig) {
	if auditOutputPath != "" {
		cfg.OutputPath = auditOutputPath
	}
	if auditOutputFormat != "" {
		cfg.OutputFormat = report.ReportFormat(strings.ToLower(auditOutputFormat))
	}
	if len(auditScanners) > 0 {
		cfg.EnabledScanners = expandAuditScannerGroups(auditScanners)
	}
	if auditFastMode {
		cfg.EnabledScanners = []string{"crypto", "validation", "static"}
	}
	if auditMinSeverity != "" {
		cfg.MinSeverity = parseAuditSeverity(auditMinSeverity)
	}
	if auditFailOnSeverity != "" {
		cfg.FailOnSeverity = parseAuditSeverity(auditFailOnSeverity)
	}
	cfg.CIMode = auditCIMode
	if auditBaselineFile != "" {
		cfg.BaselineFile = auditBaselineFile
	}
}

// expandAuditScannerGroups expands scanner group names to individual scanners
func expandAuditScannerGroups(scannerList []string) []string {
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
		if group, isGroup := groups[strings.ToLower(s)]; isGroup {
			for _, scanner := range group {
				if !seen[scanner] {
					result = append(result, scanner)
					seen[scanner] = true
				}
			}
		} else {
			if !seen[s] {
				result = append(result, s)
				seen[s] = true
			}
		}
	}

	return result
}

// parseAuditSeverity converts string to SeverityLevel
func parseAuditSeverity(s string) audit.SeverityLevel {
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

// runAuditScanners executes all enabled scanners
func runAuditScanners(ctx context.Context, cfg *config.AuditConfig) ([]*audit.ScanResult, error) {
	target := &audit.ScanTarget{
		RootPath:    cfg.RootPath,
		IncludeTest: false,
		Config:      cfg.ScannerConfigs,
	}

	var results []*audit.ScanResult
	availableScanners := getAuditScanners()

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

// getAuditScanners returns a map of scanner factories
func getAuditScanners() map[string]func() audit.Scanner {
	return map[string]func() audit.Scanner{
		"dependency":    func() audit.Scanner { return scanner.NewDependencyScanner(nil) },
		"crypto":        func() audit.Scanner { return scanner.NewCryptoScanner() },
		"validation":    func() audit.Scanner { return scanner.NewValidationScanner() },
		"keymanagement": func() audit.Scanner { return scanner.NewKeyManagementScanner() },
		"network":       func() audit.Scanner { return scanner.NewNetworkScanner() },
		"static":        func() audit.Scanner { return scanner.NewStaticScanner() },
		"blockchain":    func() audit.Scanner { return scanner.NewBlockchainScanner() },
		"economics":     func() audit.Scanner { return scanner.NewEconomicsScanner() },
		"p2p":           func() audit.Scanner { return scanner.NewP2PSecurityScanner() },
	}
}

// applyAuditBaseline filters out findings that exist in the baseline
func applyAuditBaseline(auditReport *report.AuditReport, baselinePath string) (*report.AuditReport, error) {
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
	auditReport.Summary = recalculateAuditSummary(newFindings)
	return auditReport, nil
}

// recalculateAuditSummary recalculates the summary from findings
func recalculateAuditSummary(findings []audit.Finding) report.ReportSummary {
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

// outputAuditReport writes the report to the specified output
func outputAuditReport(auditReport *report.AuditReport, cfg *config.AuditConfig, generator *report.ReportGenerator) error {
	reporter, ok := generator.GetReporter(cfg.OutputFormat)
	if !ok {
		return fmt.Errorf("unsupported output format: %s", cfg.OutputFormat)
	}

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

// calculateExitCode determines exit code based on findings and threshold
func calculateExitCode(findings []audit.Finding, threshold audit.SeverityLevel) int {
	for _, f := range findings {
		if severityAtOrAbove(f.Severity, threshold) {
			return 1
		}
	}
	return 0
}

// countFindingsAboveThreshold counts findings at or above the threshold
func countFindingsAboveThreshold(findings []audit.Finding, threshold audit.SeverityLevel) int {
	count := 0
	for _, f := range findings {
		if severityAtOrAbove(f.Severity, threshold) {
			count++
		}
	}
	return count
}

// severityAtOrAbove checks if severity is at or above threshold
func severityAtOrAbove(severity, threshold audit.SeverityLevel) bool {
	severityOrder := map[audit.SeverityLevel]int{
		audit.SeverityCritical: 5,
		audit.SeverityHigh:     4,
		audit.SeverityMedium:   3,
		audit.SeverityLow:      2,
		audit.SeverityInfo:     1,
	}
	return severityOrder[severity] >= severityOrder[threshold]
}

// printAuditInfo prints scan configuration info
func printAuditInfo(cfg *config.AuditConfig) {
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

// printAuditSummary prints the audit summary
func printAuditSummary(auditReport *report.AuditReport) {
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

// newAuditListCmd creates the audit list-scanners subcommand
func newAuditListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-scanners",
		Short: "List available security scanners",
		Long:  `List all available security scanners with their descriptions.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Available Security Scanners")
			fmt.Println("===========================")
			fmt.Println()
			fmt.Println("[Core Security]")
			fmt.Println("  dependency      Scans Go dependencies for known CVEs")
			fmt.Println("  crypto          Audits cryptographic implementations")
			fmt.Println("  validation      Checks input validation")
			fmt.Println("  keymanagement   Audits key storage and TLS configuration")
			fmt.Println("  network         Analyzes network security")
			fmt.Println()
			fmt.Println("[Static Analysis]")
			fmt.Println("  static          Static code analysis (nil pointers, type conversions, etc.)")
			fmt.Println()
			fmt.Println("[Blockchain Security]")
			fmt.Println("  blockchain      Blockchain vulnerabilities (double-signing, tx ordering, etc.)")
			fmt.Println("  economics       Tokenomics audit (rewards, slashing, overflow)")
			fmt.Println("  p2p             P2P network security (eclipse, Sybil, replay)")
			fmt.Println()
			fmt.Println("Scanner Groups: all, core, blockchain, fast")
		},
	}
}

// newAuditBaselineCmd creates the audit baseline subcommand
func newAuditBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage audit baselines",
		Long:  `Manage audit baselines for tracking remediation progress.`,
	}

	cmd.AddCommand(newAuditBaselineCreateCmd())
	return cmd
}

// newAuditBaselineCreateCmd creates the baseline create subcommand
func newAuditBaselineCreateCmd() *cobra.Command {
	var inputFile string
	var outputFile string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a baseline from an audit report",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("input file is required")
			}
			if outputFile == "" {
				outputFile = "baseline.json"
			}

			data, err := os.ReadFile(inputFile) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
			if err != nil {
				return fmt.Errorf("failed to read input file: %w", err)
			}

			auditReport, err := report.ParseJSONReport(data)
			if err != nil {
				return fmt.Errorf("failed to parse audit report: %w", err)
			}

			baseline := report.NewBaseline(auditReport.Findings)
			if err := baseline.Save(outputFile); err != nil {
				return fmt.Errorf("failed to save baseline: %w", err)
			}

			fmt.Printf("Created baseline with %d findings: %s\n", len(auditReport.Findings), outputFile)
			return nil
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input audit report file (JSON)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "baseline.json", "Output baseline file")
	cmd.MarkFlagRequired("input") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck

	return cmd
}

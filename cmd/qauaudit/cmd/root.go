// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the QAU Security Audit tool.
package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	configFile     string
	outputPath     string
	outputFormat   string
	scanners       []string
	minSeverity    string
	failOnSeverity string
	ciMode         bool
	baselineFile   string
	verbose        bool
	timeout        time.Duration
	fastMode       bool

	// Exit code for CI mode
	exitCode int
)

// GetExitCode returns the exit code set by the audit
func GetExitCode() int {
	return exitCode
}

// NewRootCmd creates the root command for qauaudit
func NewRootCmd(version, commit string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "qauaudit",
		Short: "QAU Security Audit Tool",
		Long: `qauaudit is a security vulnerability scanner for the QAU blockchain.

It provides comprehensive security scanning including:
  - Dependency vulnerability scanning (CVE detection)
  - Cryptographic implementation auditing
  - Input validation analysis
  - Key management security checks
  - Network and consensus security auditing

Examples:
  # Run full audit with default settings
  qauaudit scan

  # Run audit with specific scanners
  qauaudit scan --scanners dependency,crypto

  # Run in CI mode (returns non-zero exit code on findings)
  qauaudit scan --ci --fail-on high

  # Generate HTML report
  qauaudit scan --format html --output report.html

  # Compare against baseline
  qauaudit scan --baseline baseline.json`,
		Version: fmt.Sprintf("%s (commit: %s)", version, commit),
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Configuration file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Minute, "Scan timeout duration")

	// Add subcommands
	rootCmd.AddCommand(newScanCmd(version))
	rootCmd.AddCommand(newBaselineCmd())
	rootCmd.AddCommand(newListScannersCmd())

	return rootCmd
}

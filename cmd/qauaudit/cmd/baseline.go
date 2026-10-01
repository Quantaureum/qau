// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the QAU Security Audit tool.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/quantaureum/qau/audit/report"
)

// newBaselineCmd creates the baseline command
func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Manage audit baselines",
		Long: `Manage audit baselines for tracking remediation progress.

Baselines allow you to:
  - Save current findings as a reference point
  - Compare new scans against the baseline
  - Track only new vulnerabilities in CI/CD`,
	}

	cmd.AddCommand(newBaselineCreateCmd())
	cmd.AddCommand(newBaselineCompareCmd())

	return cmd
}

// newBaselineCreateCmd creates the baseline create subcommand
func newBaselineCreateCmd() *cobra.Command {
	var inputFile string
	var outputFile string
	var description string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a baseline from an audit report",
		Long: `Create a baseline file from an existing audit report.

The baseline can then be used with 'qauaudit scan --baseline' to only
report new findings that don't exist in the baseline.

Requirements: 4.5
- WHEN comparing scan results THEN the system SHALL support baseline comparison to identify new findings`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("input file is required")
			}
			if outputFile == "" {
				outputFile = "baseline.json"
			}

			// Load the audit report
			auditReport, err := loadAuditReport(inputFile)
			if err != nil {
				return fmt.Errorf("failed to load audit report: %w", err)
			}

			// Create baseline from findings
			baseline := report.NewBaseline(auditReport.Findings)
			if description != "" {
				baseline.Description = description
			}

			// Save baseline
			if err := baseline.Save(outputFile); err != nil {
				return fmt.Errorf("failed to save baseline: %w", err)
			}

			if verbose {
				fmt.Printf("Created baseline with %d findings: %s\n", len(auditReport.Findings), outputFile)
				if description != "" {
					fmt.Printf("Description: %s\n", description)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input audit report file (JSON)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "baseline.json", "Output baseline file")
	cmd.Flags().StringVarP(&description, "description", "d", "", "Description for the baseline")
	cmd.MarkFlagRequired("input") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck

	return cmd
}

// newBaselineCompareCmd creates the baseline compare subcommand
func newBaselineCompareCmd() *cobra.Command {
	var baselineFile string
	var reportFile string

	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Compare an audit report against a baseline",
		Long: `Compare an audit report against a baseline to identify new findings.

This is useful for reviewing what vulnerabilities have been introduced
since the baseline was created.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if baselineFile == "" || reportFile == "" {
				return fmt.Errorf("both baseline and report files are required")
			}

			// Load baseline
			baseline, err := report.LoadBaseline(baselineFile)
			if err != nil {
				return fmt.Errorf("failed to load baseline: %w", err)
			}

			// Load audit report
			auditReport, err := loadAuditReport(reportFile)
			if err != nil {
				return fmt.Errorf("failed to load audit report: %w", err)
			}

			// Find new findings
			newFindings := 0
			fixedFindings := 0

			for _, f := range auditReport.Findings {
				if !baseline.Contains(f) {
					newFindings++
					if verbose {
						fmt.Printf("NEW: [%s] %s - %s\n", f.Severity, f.ID, f.Title)
					}
				}
			}

			// Check for fixed findings (in baseline but not in report)
			for _, bf := range baseline.Findings {
				found := false
				for _, f := range auditReport.Findings {
					if bf.ID == f.ID && bf.Location.File == f.Location.File {
						found = true
						break
					}
				}
				if !found {
					fixedFindings++
					if verbose {
						fmt.Printf("FIXED: [%s] %s - %s\n", bf.Severity, bf.ID, bf.Title)
					}
				}
			}

			fmt.Printf("\nComparison Summary:\n")
			fmt.Printf("  Baseline findings: %d\n", len(baseline.Findings))
			fmt.Printf("  Current findings: %d\n", len(auditReport.Findings))
			fmt.Printf("  New findings: %d\n", newFindings)
			fmt.Printf("  Fixed findings: %d\n", fixedFindings)

			// Return non-zero if there are new findings in CI mode
			if ciMode && newFindings > 0 {
				exitCode = 1
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&baselineFile, "baseline", "b", "", "Baseline file")
	cmd.Flags().StringVarP(&reportFile, "report", "r", "", "Audit report file to compare")
	cmd.MarkFlagRequired("baseline") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	cmd.MarkFlagRequired("report")   // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck

	return cmd
}

// loadAuditReport loads an audit report from a JSON file
func loadAuditReport(path string) (*report.AuditReport, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, err
	}

	return report.ParseJSONReport(data)
}

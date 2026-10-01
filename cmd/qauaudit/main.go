// Quantaureum Node source, version 1.0.0.
// Package main provides the CLI entry point for QAU Security Audit.
package main

import (
	"fmt"
	"os"

	"github.com/quantaureum/qau/cmd/qauaudit/cmd"
)

var (
	version = "1.0.0"
	commit  = "unknown"
)

func main() {
	rootCmd := cmd.NewRootCmd(version, commit)
	exitCode := 0
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		exitCode = 1
	}
	// Check if we need to exit with a specific code from the audit
	if cmd.GetExitCode() != 0 {
		exitCode = cmd.GetExitCode()
	}
	os.Exit(exitCode)
}

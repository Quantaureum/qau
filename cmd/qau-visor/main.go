// Quantaureum Node source, version 1.0.0.
// Package main provides the qau-visor process manager for Quantaureum nodes.
//
// qau-visor manages the lifecycle of the qaud node process, providing:
//   - Process supervision (auto-restart on crash)
//   - Zero-downtime upgrades with Dilithium3 signature verification
//   - Automatic rollback on upgrade failure
//   - Version management with atomic symlink switching
//
// Inspired by Hyperliquid's Visor, adapted for Quantaureum's post-quantum
// cryptography (Dilithium3 signatures instead of GPG).
package main

import (
	"fmt"
	"os"

	"github.com/quantaureum/qau/cmd/qau-visor/cmd"
)

var (
	version   = "0.1.0"
	gitCommit = "unknown"
	buildTime = "unknown"
)

func main() {
	rootCmd := cmd.NewRootCmd(version, gitCommit, buildTime)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

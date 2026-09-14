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
	"github.com/quantaureum/qau/internal/version"
)

func main() {
	rootCmd := cmd.NewRootCmd(version.Version, version.GitCommit, version.BuildTime)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

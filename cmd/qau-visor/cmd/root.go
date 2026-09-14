// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qau-visor process manager.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	visorConfigPath string
	qaudBinaryPath  string
	dataDir         string
	verbose         bool
)

// NewRootCmd creates the root command for qau-visor.
func NewRootCmd(version, gitCommit, buildTime string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "qau-visor",
		Short: "Quantaureum node process manager",
		Long: `qau-visor manages the lifecycle of the qaud node process.

Features:
  - Process supervision with automatic restart on crash
  - Zero-downtime upgrades with Dilithium3 signature verification
  - Automatic rollback on upgrade failure
  - Version management with atomic symlink switching

Inspired by Hyperliquid's Visor, adapted for post-quantum cryptography.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, gitCommit, buildTime),
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&visorConfigPath, "config", "/etc/quantaureum/visor.json", "Visor configuration file path")
	rootCmd.PersistentFlags().StringVar(&qaudBinaryPath, "binary", "/usr/local/bin/qaud", "Path to qaud binary (or symlink)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "datadir", "/var/lib/quantaureum", "Quantaureum data directory")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Add subcommands
	rootCmd.AddCommand(newStartCmd())
	rootCmd.AddCommand(newStopCmd())
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newUpgradeCmd())
	rootCmd.AddCommand(newRollbackCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show visor and managed qaud version info",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("qau-visor version: %s\n", cmd.Root().Version)
			return nil
		},
	}
}

// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	rpcAddr    string
	dataDir    string
	configFile string
	verbose    bool
	// AUDIT (2026) HIGH-14: allow plaintext http:// for sensitive ops
	// only when explicitly requested. Defaults to false (fail-closed).
	insecureRPC bool
)

// NewRootCmd creates the root command.
func NewRootCmd(version, commit, buildTime string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "qauctl",
		Short: "Quantaureum CLI management tool",
		Long: `qauctl is a command-line tool for managing Quantaureum nodes.

It provides commands for:
  - Node status and information queries
  - Configuration management
  - Key management (generate, import, export)
  - Backup and restore operations
  - Performance analysis`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, buildTime),
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&rpcAddr, "rpc", "http://localhost:8545", "RPC server address")
	rootCmd.PersistentFlags().StringVar(&dataDir, "datadir", "./data", "Data directory")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Configuration file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	// AUDIT (2026) HIGH-14: --insecure allows plaintext http:// for
	// commands that transmit private keys or passwords. Without this flag,
	// such commands reject non-https URLs (except localhost).
	rootCmd.PersistentFlags().BoolVar(&insecureRPC, "insecure", false, "Allow plaintext http:// for sensitive RPC operations (key import/unlock)")

	// Add subcommands
	rootCmd.AddCommand(newStatusCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newKeyCmd())
	rootCmd.AddCommand(newBackupCmd())
	rootCmd.AddCommand(newRestoreCmd())
	rootCmd.AddCommand(newPerfCmd())
	rootCmd.AddCommand(newValidatorCmd())
	rootCmd.AddCommand(newAccountRemoteCmd())
	rootCmd.AddCommand(newGenesisCmd())
	rootCmd.AddCommand(newContractCmd())
	rootCmd.AddCommand(newTxCmd())

	return rootCmd
}

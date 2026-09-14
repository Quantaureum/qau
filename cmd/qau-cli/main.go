// Quantaureum Node source, version 1.0.0.
// Package main implements the Quantaureum Command Line Interface (CLI) tool.
// This tool provides developers with a comprehensive interface to interact with the Quantaureum blockchain.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/quantaureum/qau/internal/version"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "qau-cli",
	Short: "Quantaureum Command Line Interface",
	Long: `Quantaureum CLI is a comprehensive tool for interacting with the Quantaureum blockchain.

This tool provides developers with utilities for account management, transaction processing,
smart contract deployment, network monitoring, and more.`,
	Version: version.String(),
}

// VersionCmd represents the version command
var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of qau-cli",
	Long:  `All software has versions. This is qau-cli's.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("qau-cli version %s\n", version.Version)
		fmt.Printf("Build Time: %s\n", version.BuildTime)
		fmt.Printf("Git Commit: %s\n", version.GitCommit)
	},
}

func main() {
	// Add version command
	RootCmd.AddCommand(VersionCmd)

	// Add account commands
	RootCmd.AddCommand(newAccountCmd())

	// Add transaction commands
	RootCmd.AddCommand(newTransactionCmd())

	// Add contract commands
	RootCmd.AddCommand(newContractCmd())

	// Add blockchain commands
	RootCmd.AddCommand(newBlockchainCmd())

	// Add node commands
	RootCmd.AddCommand(newNodeCmd())

	// Add network commands
	RootCmd.AddCommand(newNetworkCmd())

	// Execute the root command
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

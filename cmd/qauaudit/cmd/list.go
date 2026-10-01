// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the QAU Security Audit tool.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ScannerInfo describes a scanner
type ScannerInfo struct {
	Name        string
	Description string
	Category    string
}

// newListScannersCmd creates the list-scanners command
func newListScannersCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-scanners",
		Short: "List available security scanners",
		Long:  `List all available security scanners with their descriptions.`,
		Run: func(cmd *cobra.Command, args []string) {
			scanners := []ScannerInfo{
				// Core Security Scanners
				{
					Name:        "dependency",
					Description: "Scans Go dependencies for known CVEs using govulncheck",
					Category:    "Core Security",
				},
				{
					Name:        "crypto",
					Description: "Audits cryptographic implementations (Dilithium, Kyber, secp256k1, Blake2b)",
					Category:    "Core Security",
				},
				{
					Name:        "validation",
					Description: "Checks input validation (RLP, P2P messages, transactions, GraphQL)",
					Category:    "Core Security",
				},
				{
					Name:        "keymanagement",
					Description: "Audits key storage, rotation, and TLS configuration",
					Category:    "Core Security",
				},
				{
					Name:        "network",
					Description: "Analyzes network security (TLS, authentication, rate limiting)",
					Category:    "Core Security",
				},
				// Static Analysis
				{
					Name:        "static",
					Description: "Static code analysis (nil pointers, type conversions, error handling, race conditions)",
					Category:    "Static Analysis",
				},
				// Blockchain-Specific Scanners
				{
					Name:        "blockchain",
					Description: "Blockchain vulnerabilities (double-signing, tx ordering, state atomicity, nonce handling)",
					Category:    "Blockchain Security",
				},
				{
					Name:        "economics",
					Description: "Tokenomics audit (reward calculations, slashing, integer overflow, validator integrity)",
					Category:    "Blockchain Security",
				},
				{
					Name:        "p2p",
					Description: "P2P network security (eclipse attacks, Sybil resistance, message replay, DoS)",
					Category:    "Blockchain Security",
				},
			}

			fmt.Println("Available Security Scanners")
			fmt.Println("===========================")
			fmt.Println()

			currentCategory := ""
			for _, s := range scanners {
				if s.Category != currentCategory {
					if currentCategory != "" {
						fmt.Println()
					}
					fmt.Printf("[%s]\n", s.Category)
					currentCategory = s.Category
				}
				fmt.Printf("  %-15s %s\n", s.Name, s.Description)
			}

			fmt.Println()
			fmt.Println("Scanner Groups:")
			fmt.Println("  all        - Run all scanners")
			fmt.Println("  core       - Core security scanners (dependency, crypto, validation, keymanagement, network)")
			fmt.Println("  blockchain - Blockchain-specific scanners (blockchain, economics, p2p)")
			fmt.Println("  fast       - Quick scanners for pre-commit (crypto, validation, static)")
			fmt.Println()
			fmt.Println("Usage: qauaudit scan --scanners <scanner1>,<scanner2>")
			fmt.Println("       qauaudit scan --scanners all")
			fmt.Println("       qauaudit scan --scanners blockchain")
		},
	}
}

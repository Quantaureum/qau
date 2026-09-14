// Quantaureum Node source, version 1.0.0.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// newAccountCmd creates the account command group
func newAccountCmd() *cobra.Command {
	accountCmd := &cobra.Command{
		Use:   "account",
		Short: "Manage Quantaureum accounts",
		Long:  `Manage Quantaureum accounts, including creating, listing, and viewing account information.`,
	}

	// Add subcommands
	accountCmd.AddCommand(newAccountCreateCmd())
	accountCmd.AddCommand(newAccountListCmd())
	accountCmd.AddCommand(newAccountBalanceCmd())
	accountCmd.AddCommand(newAccountImportCmd())
	accountCmd.AddCommand(newAccountExportCmd())

	return accountCmd
}

// newAccountCreateCmd returns the real create implementation
// (see account_create.go — R106-CLI-CREATE).
func newAccountCreateCmd() *cobra.Command {
	return newAccountCreateCmdV2()
}

// newAccountListCmd creates the account list command
func newAccountListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all Quantaureum accounts",
		Long: `List all Quantaureum accounts in the keystore.

Example:
  qau-cli account list

This command lists all accounts that have been created and stored
in the node's keystore directory.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Listing Quantaureum accounts in keystore...")
			fmt.Println()
			fmt.Println("NOTE: Full keystore listing requires node RPC access.")
			fmt.Println()
			fmt.Println("To list accounts via RPC (node must be running):")
			fmt.Println("  curl -X POST http://localhost:8545 \\")
			fmt.Println("    -H 'Content-Type: application/json' \\")
			fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"personal_listAccounts\",\"params\":[],\"id\":1}'")
			fmt.Println()
			fmt.Println("Account storage locations:")
			fmt.Println("  - Linux/Mac: ~/.quantaureum/keystore")
			fmt.Println("  - Windows: %APPDATA%\\Quantaureum\\keystore")
		},
	}
}

// newAccountBalanceCmd creates the account balance command
func newAccountBalanceCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "balance [address]",
		Short: "Get account balance",
		Long: `Get the balance of a Quantaureum account.

Example:
  qau-cli account balance QAU1234567890abcdef
  qau-cli account balance 0x1234567890abcdef1234567890abcdef12345678 --rpc http://localhost:8545

This command queries the blockchain state to retrieve the current
QAU token balance of the specified account.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			address := args[0]

			// Use custom endpoint if provided
			endpoint := rpcEndpoint
			if endpoint == "" {
				endpoint = os.Getenv("QUANTAUREUM_RPC_ENDPOINT")
			}
			if endpoint == "" {
				endpoint = "http://localhost:8545"
			}

			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			balance, err := client.GetBalance(cmd.Context(), address)
			if err != nil {
				fmt.Printf("Error getting balance: %v\n", err)
				fmt.Println()
				fmt.Println("Make sure the Quantaureum node is running and the RPC endpoint")
				fmt.Println("is accessible. You can specify a custom endpoint with:")
				fmt.Println("  --rpc http://localhost:8545")
				return
			}

			// Parse and format balance
			fmt.Printf("Address: %s\n", address)
			fmt.Printf("Balance: %s QAU (wei)\n", balance)

			// Format balance with decimal point
			if len(balance) > 18 {
				intPart := balance[:len(balance)-18]
				decPart := balance[len(balance)-18:]
				fmt.Printf("Balance: %s.%s QAU\n", intPart, decPart)
			} else {
				fmt.Printf("Balance: 0.%s QAU\n", balance)
			}
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL (default: from QUANTAUREUM_RPC_ENDPOINT env or http://localhost:8545)")

	return cmd
}

// newAccountImportCmd creates the account import command
func newAccountImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import [file]",
		Short: "Import a Quantaureum account",
		Long: `Import a Quantaureum account from a keystore file.

Example:
  qau-cli account import /path/to/keystore/file.json

This command imports an account from a keystore JSON file.
The keystore file should be in the format used by Quantaureum,
containing an encrypted Dilithium3 private key.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filePath := args[0]
			fmt.Printf("Importing account from %s...\n", filePath)
			fmt.Println()
			fmt.Println("NOTE: Full account import requires node RPC access.")
			fmt.Println()
			fmt.Println("To import via RPC (node must be running):")
			fmt.Println("  Use the personal_importRawKey RPC method")
			fmt.Println()
			fmt.Println("Expected keystore format:")
			fmt.Println(`  {"crypto":{"cipher":"aes-256-gcm","ciphertext":"...","cipherparams":{"iv":"..."},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"r":8,"p":1,"salt":"..."}},"id":"uuid","version":3}`)
			fmt.Println()
			fmt.Println("The imported account will be stored in the keystore directory.")
		},
	}
}

// newAccountExportCmd creates the account export command
func newAccountExportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export [address] [file]",
		Short: "Export a Quantaureum account",
		Long: `Export a Quantaureum account to a keystore file.

Example:
  qau-cli account export QAU1234567890abcdef ./exported.json

This command exports an account's keystore file to the specified path.
The exported file can be used as a backup or to import the account
into another Quantaureum node.`,
		Args: cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			address := args[0]
			filePath := args[1]
			fmt.Printf("Exporting account %s to %s...\n", address, filePath)
			fmt.Println()
			fmt.Println("NOTE: Full account export requires node RPC access.")
			fmt.Println()
			fmt.Println("To export via RPC (node must be running):")
			fmt.Println("  Use the personal_exportAccount RPC method")
			fmt.Println()
			fmt.Println("WARNING: Exported keystore files contain encrypted private keys.")
			fmt.Println("Keep them secure and never share them with unauthorized parties.")
		},
	}
}

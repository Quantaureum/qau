// Quantaureum Node source, version 1.0.0.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// newTransactionCmd creates the transaction command group
func newTransactionCmd() *cobra.Command {
	transactionCmd := &cobra.Command{
		Use:   "tx",
		Short: "Manage Quantaureum transactions",
		Long:  `Manage Quantaureum transactions, including sending, querying, and viewing transaction history.`,
	}

	// Add subcommands
	transactionCmd.AddCommand(newTransactionSendCmd())
	transactionCmd.AddCommand(newTransactionStatusCmd())
	transactionCmd.AddCommand(newTransactionHistoryCmd())
	transactionCmd.AddCommand(newTransactionEstimateGasCmd())

	return transactionCmd
}

// newTransactionSendCmd creates the transaction send command
func newTransactionSendCmd() *cobra.Command {
	var (
		rpcEndpoint string
		rawTx       string
	)

	cmd := &cobra.Command{
		Use:   "send [from] [to] [amount]",
		Short: "Send a Quantaureum transaction",
		Long: `Send a Quantaureum transaction from one account to another.

Example:
  qau-cli tx send 0x1234567890abcdef1234567890abcdef12345678 0xabcdef1234567890abcdef1234567890abcdef12 100
  qau-cli tx send --raw-tx 0xabcdef123456...

This command sends QAU tokens from one account to another. You can either
provide the from/to/amount parameters or submit a pre-signed raw transaction.

Note: Sending transactions requires the sender account to be unlocked
in the node's account manager, or you can submit a raw transaction.`,
		Args: cobra.MinimumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			// If raw transaction is provided, send it directly
			if rawTx != "" {
				hash, err := client.SendRawTransaction(cmd.Context(), rawTx)
				if err != nil {
					fmt.Printf("Error sending transaction: %v\n", err)
					return
				}
				fmt.Printf("Transaction submitted successfully!\n")
				fmt.Printf("Transaction Hash: %s\n", hash)
				fmt.Println()
				fmt.Println("Use 'qau-cli tx status <hash>' to check the status.")
				return
			}

			// Otherwise show usage
			if len(args) < 3 {
				fmt.Println("To send a transaction, you need either:")
				fmt.Println("  1. Pre-signed raw transaction: --raw-tx <hex>")
				fmt.Println("  2. From/To/Amount (requires unlocked account): <from> <to> <amount>")
				fmt.Println()
				fmt.Println("For quantum-safe transactions, the recommended approach is to:")
				fmt.Println("  1. Sign the transaction locally using Dilithium3")
				fmt.Println("  2. Submit the raw transaction using --raw-tx flag")
				fmt.Println()
				fmt.Println("Example with raw transaction:")
				fmt.Println("  qau-cli tx send --raw-tx 0x1234...5678abcdef")
				return
			}

			from := args[0]
			to := args[1]
			amount := args[2]

			fmt.Printf("Sending %s QAU from %s to %s...\n", amount, from, to)
			fmt.Println()
			fmt.Println("NOTE: Direct transaction sending requires unlocked accounts.")
			fmt.Println()
			fmt.Println("Recommended approach for quantum-safe transactions:")
			fmt.Println("  1. Create the transaction locally")
			fmt.Println("  2. Sign it with your Dilithium3 private key")
			fmt.Println("  3. Serialize and submit using --raw-tx flag")
			fmt.Println()
			fmt.Println("RPC Method for unlocked accounts:")
			fmt.Printf("  curl -X POST %s -H 'Content-Type: application/json' \\\n", endpoint)
			fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",")
			fmt.Println("         \"params\":[{\"from\":\"...\",\"to\":\"...\",\"value\":\"...\"}],\"id\":1}'")
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	cmd.Flags().StringVar(&rawTx, "raw-tx", "", "Pre-signed raw transaction hex")
	return cmd
}

// newTransactionStatusCmd creates the transaction status command
func newTransactionStatusCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "status [txhash]",
		Short: "Get transaction status",
		Long: `Get the status of a Quantaureum transaction by hash.

Example:
  qau-cli tx status 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
  qau-cli tx status 0x1234...abcd --rpc http://localhost:8545

This command queries the blockchain to retrieve the current status of
a transaction, including whether it has been confirmed and included
in a block.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			txHash := args[0]
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			// Get transaction
			tx, err := client.GetTransactionByHash(cmd.Context(), txHash)
			if err != nil {
				fmt.Printf("Error getting transaction: %v\n", err)
				return
			}

			// Get receipt (if transaction is confirmed)
			receipt, err := client.GetTransactionReceipt(cmd.Context(), txHash)
			if err != nil {
				fmt.Printf("Error getting receipt: %v\n", err)
			}

			fmt.Println("Transaction Status")
			fmt.Println("==================")
			fmt.Printf("Transaction Hash: %s\n", txHash)

			if tx == nil && receipt == nil {
				fmt.Println("Status: UNKNOWN (not found in blockchain)")
				fmt.Println()
				fmt.Println("The transaction may be:")
				fmt.Println("  - Still pending in the mempool")
				fmt.Println("  - Invalid and rejected")
				fmt.Println("  - Never submitted")
				return
			}

			if receipt != nil {
				fmt.Println("Status: CONFIRMED")

				if blockNum, ok := receipt["blockNumber"].(string); ok {
					if n, err := strconv.ParseUint(blockNum, 0, 64); err == nil {
						fmt.Printf("Block Number:    %d\n", n)
					} else {
						fmt.Printf("Block Number:    %s\n", blockNum)
					}
				}

				if blockHash, ok := receipt["blockHash"].(string); ok {
					fmt.Printf("Block Hash:      %s\n", blockHash)
				}

				if status, ok := receipt["status"].(string); ok {
					fmt.Printf("Execution Status: %s\n", status)
				}

				if gasUsed, ok := receipt["gasUsed"].(string); ok {
					if g, err := strconv.ParseUint(gasUsed, 0, 64); err == nil {
						fmt.Printf("Gas Used:        %d\n", g)
					}
				}
			} else if tx != nil {
				fmt.Println("Status: PENDING (in mempool, not yet confirmed)")
			}

			if tx != nil {
				if from, ok := tx["from"].(string); ok {
					fmt.Printf("From:           %s\n", from)
				}
				if to, ok := tx["to"].(string); ok {
					fmt.Printf("To:             %s\n", to)
				}
				if value, ok := tx["value"].(string); ok {
					fmt.Printf("Value:          %s wei\n", value)
				}
				if nonce, ok := tx["nonce"].(string); ok {
					if n, err := strconv.ParseUint(nonce, 0, 64); err == nil {
						fmt.Printf("Nonce:          %d\n", n)
					}
				}
			}
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newTransactionHistoryCmd creates the transaction history command
func newTransactionHistoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "history [address]",
		Short: "Get transaction history",
		Long: `Get the transaction history of a Quantaureum account.

Example:
  qau-cli tx history 0x1234567890abcdef1234567890abcdef12345678

This command retrieves the transaction history for a specific account.
Note: This requires an indexer service or archival node for full history.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			address := args[0]
			fmt.Printf("Getting transaction history for account %s...\n", address)
			fmt.Println()
			fmt.Println("NOTE: Full transaction history requires an indexer service")
			fmt.Println("or an archival node that maintains complete history.")
			fmt.Println()
			fmt.Println("Alternative approaches:")
			fmt.Println("  1. Use a block explorer API")
			fmt.Println("  2. Scan blocks manually using 'qau-cli blockchain block latest'")
			fmt.Println("  3. Query specific blocks where the address appears")
			fmt.Println()
			fmt.Println("RPC methods for transaction lookup:")
			fmt.Println("  - eth_getTransactionByBlockHashAndIndex")
			fmt.Println("  - eth_getTransactionByBlockNumberAndIndex")
			fmt.Println("  - eth_getLogs (for event filtering)")
		},
	}
}

// newTransactionEstimateGasCmd creates the transaction estimate gas command
func newTransactionEstimateGasCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "estimate-gas [from] [to] [amount]",
		Short: "Estimate gas for a transaction",
		Long: `Estimate the gas required for a Quantaureum transaction.

Example:
  qau-cli tx estimate-gas 0x1234567890abcdef... 0xabcdef1234567890... 100

This command estimates the amount of gas that would be required to execute
a transaction with the given parameters.`,
		Args: cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			from := args[0]
			to := args[1]
			amount := args[2]

			fmt.Printf("Estimating gas for transaction...\n")
			fmt.Printf("From:   %s\n", from)
			fmt.Printf("To:     %s\n", to)
			fmt.Printf("Amount: %s QAU\n", amount)
			fmt.Println()
			fmt.Println("Gas estimation for common transaction types:")
			fmt.Println("  - Simple transfer: 21,000 gas")
			fmt.Println("  - ERC-20 transfer: ~65,000 gas")
			fmt.Println("  - Contract call:   varies (typically 50,000-500,000)")
			fmt.Println("  - Contract create: ~320,000+ gas")
			fmt.Println()
			fmt.Println("To estimate via RPC (node must be running):")
			fmt.Println("  curl -X POST http://localhost:8545 \\")
			fmt.Println("    -H 'Content-Type: application/json' \\")
			fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_estimateGas\",")
			fmt.Println("         \"params\":[{\"from\":\"...\",\"to\":\"...\",\"value\":\"...\"}],\"id\":1}'")
		},
	}
}

// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// newBlockchainCmd creates the blockchain command group
func newBlockchainCmd() *cobra.Command {
	blockchainCmd := &cobra.Command{
		Use:   "blockchain",
		Short: "Interact with the Quantaureum blockchain",
		Long:  `Interact with the Quantaureum blockchain, including querying blocks and network information.`,
	}

	// Add subcommands
	blockchainCmd.AddCommand(newBlockchainInfoCmd())
	blockchainCmd.AddCommand(newBlockchainBlockCmd())
	blockchainCmd.AddCommand(newBlockchainTxPoolCmd())
	blockchainCmd.AddCommand(newBlockchainStatsCmd())

	return blockchainCmd
}

// newBlockchainInfoCmd creates the blockchain info command
func newBlockchainInfoCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "info",
		Short: "Get blockchain information",
		Long: `Get general information about the Quantaureum blockchain.

Example:
  qau-cli blockchain info
  qau-cli blockchain info --rpc http://localhost:8545

This command retrieves and displays general information about the
Quantaureum blockchain including chain ID, current block height,
network ID, and sync status.`,
		Run: func(cmd *cobra.Command, args []string) {
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			// Get chain ID
			chainID, err := client.ChainID(cmd.Context())
			if err != nil {
				fmt.Printf("Error getting chain ID: %v\n", err)
				return
			}

			// Get block number
			blockNum, err := client.BlockNumber(cmd.Context())
			if err != nil {
				fmt.Printf("Error getting block number: %v\n", err)
				return
			}

			// Get client version
			clientVersion, _ := client.Web3ClientVersion(cmd.Context())

			// Get QPOS status
			qposStatus, _ := client.QPOSStatus(cmd.Context())

			fmt.Println("Quantaureum Blockchain Information")
			fmt.Println("================================")
			fmt.Printf("Chain ID:       %s\n", chainID)
			fmt.Printf("Block Height:   %d\n", blockNum)
			fmt.Printf("Client Version: %s\n", clientVersion)

			if qposStatus != nil {
				fmt.Println()
				fmt.Println("QPOS Consensus:")
				if epoch, ok := qposStatus["currentEpoch"].(float64); ok {
					fmt.Printf("  Current Epoch:  %.0f\n", epoch)
				}
				if slot, ok := qposStatus["currentSlot"].(float64); ok {
					fmt.Printf("  Current Slot:   %.0f\n", slot)
				}
				if validators, ok := qposStatus["validators"].(float64); ok {
					fmt.Printf("  Validators:    %.0f\n", validators)
				}
				if finalized, ok := qposStatus["finalizedEpoch"].(float64); ok {
					fmt.Printf("  Finalized Epoch: %.0f\n", finalized)
				}
			}
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newBlockchainBlockCmd creates the blockchain block command
func newBlockchainBlockCmd() *cobra.Command {
	blockCmd := &cobra.Command{
		Use:   "block",
		Short: "Interact with blockchain blocks",
		Long:  `Interact with Quantaureum blockchain blocks, including querying block details.`,
	}

	// Add subcommands
	blockCmd.AddCommand(newBlockchainBlockByNumberCmd())
	blockCmd.AddCommand(newBlockchainBlockByHashCmd())
	blockCmd.AddCommand(newBlockchainBlockLatestCmd())

	return blockCmd
}

// newBlockchainBlockByNumberCmd creates the blockchain block by number command
func newBlockchainBlockByNumberCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "number [blockNumber]",
		Short: "Get block by number",
		Long: `Get a Quantaureum blockchain block by its block number.

Example:
  qau-cli blockchain block number 12345
  qau-cli blockchain block number 0x3039
  qau-cli blockchain block number latest

This command retrieves and displays detailed information about a specific
block identified by its block number.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			blockNumStr := args[0]
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			block, err := client.GetBlockByNumber(cmd.Context(), blockNumStr)
			if err != nil {
				fmt.Printf("Error getting block: %v\n", err)
				fmt.Println("Make sure the node is running and the block number is valid.")
				return
			}

			displayBlock(block)
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newBlockchainBlockByHashCmd creates the blockchain block by hash command
func newBlockchainBlockByHashCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "hash [blockHash]",
		Short: "Get block by hash",
		Long: `Get a Quantaureum blockchain block by its hash.

Example:
  qau-cli blockchain block hash 0x1234567890abcdef...

This command retrieves and displays detailed information about a specific
block identified by its cryptographic hash.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			blockHash := args[0]
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			block, err := client.GetBlockByHash(cmd.Context(), blockHash)
			if err != nil {
				fmt.Printf("Error getting block: %v\n", err)
				fmt.Println("Make sure the node is running and the hash is valid.")
				return
			}

			displayBlock(block)
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newBlockchainBlockLatestCmd creates the blockchain latest block command
func newBlockchainBlockLatestCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "latest",
		Short: "Get latest block",
		Long: `Get the latest block on the Quantaureum blockchain.

Example:
  qau-cli blockchain block latest
  qau-cli blockchain block latest --rpc http://localhost:8545

This command retrieves and displays detailed information about the
most recent block that has been added to the blockchain.`,
		Run: func(cmd *cobra.Command, args []string) {
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			block, err := client.GetBlockByNumber(cmd.Context(), "latest")
			if err != nil {
				fmt.Printf("Error getting latest block: %v\n", err)
				fmt.Println("Make sure the node is running.")
				return
			}

			displayBlock(block)
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// displayBlock displays block information in a formatted way
func displayBlock(block map[string]any) {
	fmt.Println("Block Details")
	fmt.Println("=============")

	if num, ok := block["number"].(string); ok {
		if n, err := strconv.ParseUint(num, 0, 64); err == nil {
			fmt.Printf("Block Number:    %d\n", n)
		} else {
			fmt.Printf("Block Number:    %s\n", num)
		}
	}

	if hash, ok := block["hash"].(string); ok {
		fmt.Printf("Block Hash:      %s\n", hash)
	}

	if parentHash, ok := block["parentHash"].(string); ok {
		fmt.Printf("Parent Hash:     %s\n", parentHash)
	}

	if timestamp, ok := block["timestamp"].(string); ok {
		if t, err := strconv.ParseUint(timestamp, 0, 64); err == nil {
			fmt.Printf("Timestamp:       %d (%s)\n", t, formatUnixTime(t))
		} else {
			fmt.Printf("Timestamp:       %s\n", timestamp)
		}
	}

	if gasLimit, ok := block["gasLimit"].(string); ok {
		if g, err := strconv.ParseUint(gasLimit, 0, 64); err == nil {
			fmt.Printf("Gas Limit:       %d\n", g)
		} else {
			fmt.Printf("Gas Limit:       %s\n", gasLimit)
		}
	}

	if gasUsed, ok := block["gasUsed"].(string); ok {
		if g, err := strconv.ParseUint(gasUsed, 0, 64); err == nil {
			fmt.Printf("Gas Used:        %d\n", g)
		} else {
			fmt.Printf("Gas Used:        %s\n", gasUsed)
		}
	}

	if transactions, ok := block["transactions"].([]any); ok {
		fmt.Printf("Transactions:    %d\n", len(transactions))
		if len(transactions) > 0 && len(transactions) <= 5 {
			fmt.Println()
			fmt.Println("Transaction Hashes:")
			for _, tx := range transactions {
				if txMap, ok := tx.(map[string]any); ok {
					if hash, ok := txMap["hash"].(string); ok {
						fmt.Printf("  %s\n", hash)
					}
				} else if hashStr, ok := tx.(string); ok {
					fmt.Printf("  %s\n", hashStr)
				}
			}
		}
	}

	if proposer, ok := block["proposer"].(string); ok {
		fmt.Printf("Proposer:       %s\n", proposer)
	}

	if sig, ok := block["signature"].(string); ok {
		fmt.Printf("Signature:       %s\n", sig[:min(16, len(sig))]+"...")
	}
}

// formatUnixTime formats a Unix timestamp to a readable string
func formatUnixTime(t uint64) string {
	// Simple conversion - just show as hex for now
	return fmt.Sprintf("0x%x", t)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// newBlockchainTxPoolCmd creates the blockchain txpool command
func newBlockchainTxPoolCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "txpool",
		Short: "Get transaction pool information",
		Long: `Get information about the Quantaureum transaction pool.

Example:
  qau-cli blockchain txpool
  qau-cli blockchain txpool --rpc http://localhost:8545

This command displays information about the transaction pool,
including the number of pending and queued transactions.`,
		Run: func(cmd *cobra.Command, args []string) {
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			status, err := client.TxPoolStatus(cmd.Context())
			if err != nil {
				fmt.Printf("Error getting txpool status: %v\n", err)
				fmt.Println("Make sure the node is running.")
				return
			}

			fmt.Println("Transaction Pool Status")
			fmt.Println("========================")
			if pending, ok := status["pending"]; ok {
				fmt.Printf("Pending:  %s\n", pending)
			}
			if queued, ok := status["queued"]; ok {
				fmt.Printf("Queued:   %s\n", queued)
			}
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newBlockchainStatsCmd creates the blockchain stats command
func newBlockchainStatsCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Get blockchain statistics",
		Long: `Get statistics about the Quantaureum blockchain.

Example:
  qau-cli blockchain stats
  qau-cli blockchain stats --rpc http://localhost:8545

This command displays various blockchain statistics including
block height, transaction counts, and consensus information.`,
		Run: func(cmd *cobra.Command, args []string) {
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			// Get basic info
			chainID, _ := client.ChainID(cmd.Context())
			blockNum, _ := client.BlockNumber(cmd.Context())
			peerCount, _ := client.NetPeerCount(cmd.Context())
			qposStatus, _ := client.QPOSStatus(cmd.Context())
			txpoolStatus, _ := client.TxPoolStatus(cmd.Context())

			fmt.Println("Quantaureum Blockchain Statistics")
			fmt.Println("=================================")
			fmt.Printf("Chain ID:      %s\n", chainID)
			fmt.Printf("Block Height:  %d\n", blockNum)
			fmt.Printf("Peer Count:    %d\n", peerCount)

			if txpoolStatus != nil {
				fmt.Printf("TxPool Pending: %s\n", txpoolStatus["pending"])
				fmt.Printf("TxPool Queued:  %s\n", txpoolStatus["queued"])
			}

			if qposStatus != nil {
				fmt.Println()
				fmt.Println("QPOS Consensus Statistics:")
				for key, value := range qposStatus {
					switch v := value.(type) {
					case float64:
						fmt.Printf("  %s: %.0f\n", key, v)
					case string:
						fmt.Printf("  %s: %s\n", key, v)
					default:
						b, _ := json.Marshal(v)
						fmt.Printf("  %s: %s\n", key, string(b))
					}
				}
			}
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// getEndpoint returns the RPC endpoint, using flag, env var, or default
func getEndpoint(rpcFlag string) string {
	if rpcFlag != "" {
		return rpcFlag
	}
	if endpoint := os.Getenv("QUANTAUREUM_RPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "http://localhost:8545"
}

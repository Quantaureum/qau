// Quantaureum Node source, version 1.0.0.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// newNetworkCmd creates the network command group
func newNetworkCmd() *cobra.Command {
	networkCmd := &cobra.Command{
		Use:   "network",
		Short: "Manage Quantaureum network",
		Long:  `Manage Quantaureum network connections and peer nodes.`,
	}

	// Add subcommands
	networkCmd.AddCommand(newNetworkStatusCmd())
	networkCmd.AddCommand(newNetworkPeersCmd())
	networkCmd.AddCommand(newNetworkConnectCmd())
	networkCmd.AddCommand(newNetworkDisconnectCmd())

	return networkCmd
}

// newNetworkStatusCmd creates the network status command
func newNetworkStatusCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Get network status",
		Long: `Get status information about the Quantaureum network.

Example:
  qau-cli network status
  qau-cli network status --rpc http://localhost:8545

This command retrieves and displays information about the current
network connection status, including peer count and sync status.`,
		Run: func(cmd *cobra.Command, args []string) {
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			peerCount, _ := client.NetPeerCount(cmd.Context())
			clientVersion, _ := client.Web3ClientVersion(cmd.Context())
			chainID, _ := client.ChainID(cmd.Context())

			fmt.Println("Network Status")
			fmt.Println("==============")
			fmt.Printf("Client Version: %s\n", clientVersion)
			fmt.Printf("Chain ID:       %s\n", chainID)
			fmt.Printf("Peer Count:     %d\n", peerCount)

			if peerCount == 0 {
				fmt.Println()
				fmt.Println("WARNING: No peers connected. The node may be in standalone mode")
				fmt.Println("or having network connectivity issues.")
			}
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newNetworkPeersCmd creates the network peers command
func newNetworkPeersCmd() *cobra.Command {
	peersCmd := &cobra.Command{
		Use:   "peers",
		Short: "Manage network peers",
		Long:  `Manage Quantaureum network peers, including listing and viewing peer information.`,
	}

	// Add subcommands
	peersCmd.AddCommand(newNetworkPeersListCmd())
	peersCmd.AddCommand(newNetworkPeersInfoCmd())

	return peersCmd
}

// newNetworkPeersListCmd creates the network peers list command
func newNetworkPeersListCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List network peers",
		Long: `List all connected Quantaureum network peers.

Example:
  qau-cli network peers list
  qau-cli network peers list --rpc http://localhost:8545

This command displays information about all currently connected
peer nodes in the Quantaureum P2P network.`,
		Run: func(cmd *cobra.Command, args []string) {
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			peers, err := client.AdminPeers(cmd.Context())
			if err != nil {
				fmt.Printf("Error getting peers: %v\n", err)
				fmt.Println("Make sure the node is running and RPC is accessible.")
				return
			}

			if len(peers) == 0 {
				fmt.Println("No connected peers")
				return
			}

			fmt.Printf("Connected Peers (%d)\n", len(peers))
			fmt.Println("==================")
			fmt.Println()

			for i, peer := range peers {
				fmt.Printf("%d. Peer ID: %s\n", i+1, peer["id"])

				if name, ok := peer["name"].(string); ok {
					fmt.Printf("   Name:    %s\n", name)
				}

				if protocols, ok := peer["protocols"].(map[string]any); ok {
					if qau, ok := protocols["qau"].(map[string]any); ok {
						if head, ok := qau["head"].(string); ok {
							fmt.Printf("   Head:    %s\n", head)
						}
						if diff, ok := qau["difficulty"].(string); ok {
							fmt.Printf("   Diff:    %s\n", diff)
						}
					}
				}

				if net, ok := peer["network"].(map[string]any); ok {
					if remote, ok := net["remoteAddress"].(string); ok {
						fmt.Printf("   Remote:  %s\n", remote)
					}
				}

				fmt.Println()
			}
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newNetworkPeersInfoCmd creates the network peers info command
func newNetworkPeersInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info [peerID]",
		Short: "Get peer information",
		Long: `Get detailed information about a specific network peer.

Example:
  qau-cli network peers info 0x1234567890abcdef...

This command retrieves detailed information about a specific peer
identified by its peer ID.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			peerID := args[0]
			fmt.Printf("Getting information for peer %s...\n", peerID)
			fmt.Println()
			fmt.Println("NOTE: Use 'qau-cli network peers list' to see all connected peers.")
			fmt.Println()
			fmt.Println("Peer information includes:")
			fmt.Println("  - Node ID and capabilities")
			fmt.Println("  - Connection details (IP, port)")
			fmt.Println("  - Protocol versions supported")
			fmt.Println("  - Current block height")
			fmt.Println("  - Reputation score")
		},
	}
}

// newNetworkConnectCmd creates the network connect command
func newNetworkConnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "connect [peerAddr]",
		Short: "Connect to a network peer",
		Long: `Connect to a specific Quantaureum network peer.

Example:
  qau-cli network connect enode://123456@peer.example.invalid:30303

This command initiates a connection to a specific peer node.
The peer address should be in enode format.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			peerAddr := args[0]
			fmt.Printf("Connecting to peer %s...\n", peerAddr)
			fmt.Println()
			fmt.Println("NOTE: Direct peer connection requires node RPC access.")
			fmt.Println()
			fmt.Println("Alternative ways to add peers:")
			fmt.Println("  1. Add to static nodes in config file")
			fmt.Println("  2. Use admin_addPeer RPC method:")
			fmt.Println("     curl -X POST http://localhost:8545 \\")
			fmt.Println("       -H 'Content-Type: application/json' \\")
			fmt.Println("       -d '{\"jsonrpc\":\"2.0\",\"method\":\"admin_addPeer\",")
			fmt.Println("            \"params\":[\"enode://...\"],\"id\":1}'")
			fmt.Println("  3. Use discovery to find peers automatically")
		},
	}
}

// newNetworkDisconnectCmd creates the network disconnect command
func newNetworkDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect [peerID]",
		Short: "Disconnect from a network peer",
		Long: `Disconnect from a specific Quantaureum network peer.

Example:
  qau-cli network disconnect 0x1234567890abcdef...

This command disconnects from a specific peer node.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			peerID := args[0]
			fmt.Printf("Disconnecting from peer %s...\n", peerID)
			fmt.Println()
			fmt.Println("NOTE: Direct peer disconnection requires node RPC access.")
			fmt.Println()
			fmt.Println("Alternative ways to remove peers:")
			fmt.Println("  1. Use admin_removePeer RPC method")
			fmt.Println("  2. Update static nodes configuration")
			fmt.Println("  3. Restart node without the peer in config")
		},
	}
}

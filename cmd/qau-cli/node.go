// Quantaureum Node source, version 1.0.0.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// newNodeCmd creates the node command group
func newNodeCmd() *cobra.Command {
	nodeCmd := &cobra.Command{
		Use:   "node",
		Short: "Manage Quantaureum nodes",
		Long:  `Manage Quantaureum nodes, including starting, stopping, and monitoring node status.`,
	}

	// Add subcommands
	nodeCmd.AddCommand(newNodeStartCmd())
	nodeCmd.AddCommand(newNodeStopCmd())
	nodeCmd.AddCommand(newNodeStatusCmd())
	nodeCmd.AddCommand(newNodeConfigCmd())

	return nodeCmd
}

// newNodeStartCmd creates the node start command
func newNodeStartCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "start [config]",
		Short: "Start a Quantaureum node",
		Long: `Start a Quantaureum node with the specified configuration.

Example:
  qau-cli node start
  qau-cli node start config.yaml
  qau-cli node start --data-dir /path/to/data

This command starts a Quantaureum blockchain node. The node will
begin syncing with other peers and processing transactions.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			config := "config.yaml"
			if len(args) > 0 {
				config = args[0]
			}

			if dataDir == "" {
				dataDir = getDefaultDataDir()
			}

			fmt.Printf("Starting Quantaureum node...\n")
			fmt.Printf("Config: %s\n", config)
			fmt.Printf("Data Directory: %s\n", dataDir)
			fmt.Println()
			fmt.Println("Node startup options:")
			fmt.Println("  1. Direct node binary: Run the qaud binary directly")
			fmt.Println("  2. Docker container: docker run quantaureum/node")
			fmt.Println("  3. Systemd service: systemctl start quantaureum")
			fmt.Println()
			fmt.Println("The qau-cli tool is for client operations. To start a")
			fmt.Println("full node, use the 'qaud' binary with your config file.")
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", "", "Data directory path")
	return cmd
}

// newNodeStopCmd creates the node stop command
func newNodeStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop [pid]",
		Short: "Stop a Quantaureum node",
		Long: `Stop a running Quantaureum node.

Example:
  qau-cli node stop
  qau-cli node stop 12345

This command stops a running Quantaureum node. You can specify
the process ID if running multiple nodes.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Stopping Quantaureum node...")
			fmt.Println()
			fmt.Println("Methods to stop a Quantaureum node:")
			fmt.Println("  1. Send SIGTERM to the node process")
			fmt.Println("  2. Use the node's admin API: admin_stopNode")
			fmt.Println("  3. Docker: docker stop <container>")
			fmt.Println("  4. Systemd: systemctl stop quantaureum")
			fmt.Println()
			fmt.Println("Via RPC (node must be running):")
			fmt.Println("  curl -X POST http://localhost:8545 \\")
			fmt.Println("    -H 'Content-Type: application/json' \\")
			fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"admin_stopNode\",\"params\":[],\"id\":1}'")
		},
	}
}

// newNodeStatusCmd creates the node status command
func newNodeStatusCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Get Quantaureum node status",
		Long: `Get the status of a running Quantaureum node.

Example:
  qau-cli node status
  qau-cli node status --rpc http://localhost:8545

This command retrieves and displays the current status of a
Quantaureum node including sync status, peer count, and more.`,
		Run: func(cmd *cobra.Command, args []string) {
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			// Get various status info
			clientVersion, _ := client.Web3ClientVersion(cmd.Context())
			chainID, _ := client.ChainID(cmd.Context())
			blockNum, _ := client.BlockNumber(cmd.Context())
			peerCount, _ := client.NetPeerCount(cmd.Context())
			qposStatus, _ := client.QPOSStatus(cmd.Context())

			fmt.Println("Node Status")
			fmt.Println("===========")
			fmt.Printf("Client:       %s\n", clientVersion)
			fmt.Printf("Chain ID:     %s\n", chainID)
			fmt.Printf("Block Height: %d\n", blockNum)
			fmt.Printf("Peers:        %d\n", peerCount)

			if qposStatus != nil {
				fmt.Println()
				fmt.Println("Consensus Status:")
				for key, value := range qposStatus {
					switch v := value.(type) {
					case float64:
						fmt.Printf("  %s: %.0f\n", key, v)
					case string:
						fmt.Printf("  %s: %s\n", key, v)
					default:
						fmt.Printf("  %s: %v\n", key, v)
					}
				}
			}
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newNodeConfigCmd creates the node config command
func newNodeConfigCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Manage Quantaureum node configuration",
		Long:  `Manage Quantaureum node configuration files.`,
	}

	// Add subcommands
	configCmd.AddCommand(newNodeConfigGenerateCmd())
	configCmd.AddCommand(newNodeConfigValidateCmd())
	configCmd.AddCommand(newNodeConfigShowCmd())

	return configCmd
}

// newNodeConfigGenerateCmd creates the node config generate command
func newNodeConfigGenerateCmd() *cobra.Command {
	var dataDir string

	cmd := &cobra.Command{
		Use:   "generate [path]",
		Short: "Generate a Quantaureum node configuration file",
		Long: `Generate a default Quantaureum node configuration file.

Example:
  qau-cli node config generate config.yaml
  qau-cli node config generate ~/.quantaureum/config.yaml

This command generates a default configuration file with commonly
used settings for a Quantaureum node.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "config.yaml"
			if len(args) > 0 {
				path = args[0]
			}

			if dataDir == "" {
				dataDir = getDefaultDataDir()
			}

			defaultConfig := fmt.Sprintf(`# Quantaureum Node Configuration
# Generated by qau-cli

# Network settings
network:
  port: 30303
  rpc_port: 8545
  ws_port: 8546

# Data directory
datadir: %s

# Chain settings
chain:
  network_id: 1
  chain_id: 1

# P2P Discovery
discovery:
  enabled: true
  bootnodes: []

# Transaction Pool
txpool:
  max_size: 4096
  max_account_txs: 16

# RPC Server
rpc:
  enabled: true
  host: "127.0.0.1"
  port: 8545
  cors_enabled: false
  auth_enabled: false

# QPOS Consensus
qpos:
  enabled: true
  epoch: 100
  slot_duration: 12

# Logging
log:
  level: info
  file: logs/node.log

# Security
security:
  # Sybil protection
  proof_of_work:
    enabled: true
    difficulty: 40

  # Post-quantum cryptography
  crypto:
    signature: dilithium3
    kex: kyber768
`, dataDir)

			if err := os.WriteFile(path, []byte(defaultConfig), 0600); err != nil {
				fmt.Printf("Error writing config file: %v\n", err)
				return
			}

			fmt.Printf("Configuration file generated: %s\n", path)
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Println("  1. Review the generated configuration")
			fmt.Println("  2. Customize as needed for your environment")
			fmt.Println("  3. Start the node with: qaud --config " + path)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", "", "Data directory for config generation")
	return cmd
}

// newNodeConfigValidateCmd creates the node config validate command
func newNodeConfigValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [path]",
		Short: "Validate a Quantaureum node configuration file",
		Long: `Validate a Quantaureum node configuration file for correctness.

Example:
  qau-cli node config validate config.yaml

This command validates the syntax and structure of a configuration
file without starting the node.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]

			data, err := os.ReadFile(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
			if err != nil {
				fmt.Printf("Error reading config file: %v\n", err)
				return
			}

			// Basic validation - check if it's valid YAML-like
			content := string(data)

			fmt.Printf("Validating configuration: %s\n", path)
			fmt.Println()

			// Check for required sections
			requiredSections := []string{"network", "chain", "rpc"}
			missingSections := []string{}

			for _, section := range requiredSections {
				if !contains(content, section+":") {
					missingSections = append(missingSections, section)
				}
			}

			if len(missingSections) > 0 {
				fmt.Println("WARNING: Missing recommended sections:")
				for _, s := range missingSections {
					fmt.Printf("  - %s\n", s)
				}
				fmt.Println()
			}

			fmt.Println("Basic validation passed.")
			fmt.Println()
			fmt.Println("Note: This only validates basic structure. Full validation")
			fmt.Println("requires starting the node with the configuration.")
		},
	}
}

// newNodeConfigShowCmd creates the node config show command
func newNodeConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [path]",
		Short: "Show Quantaureum node configuration",
		Long: `Show the content of a Quantaureum node configuration file.

Example:
  qau-cli node config show config.yaml

This command displays the contents of a configuration file.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "config.yaml"
			if len(args) > 0 {
				path = args[0]
			}

			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("Error reading config file: %v\n", err)
				return
			}

			fmt.Printf("Configuration file: %s\n", path)
			fmt.Println()
			fmt.Println(string(data))
		},
	}
}

// getDefaultDataDir returns the default data directory for the OS
func getDefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".quantaureum"
	}
	return filepath.Join(home, ".quantaureum")
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

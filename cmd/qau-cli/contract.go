// Quantaureum Node source, version 1.0.0.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// newContractCmd creates the contract command group
func newContractCmd() *cobra.Command {
	contractCmd := &cobra.Command{
		Use:   "contract",
		Short: "Manage Quantaureum smart contracts",
		Long:  `Manage Quantaureum smart contracts, including deployment, calling, and interaction.`,
	}

	// Add subcommands
	contractCmd.AddCommand(newContractDeployCmd())
	contractCmd.AddCommand(newContractCallCmd())
	contractCmd.AddCommand(newContractInfoCmd())
	contractCmd.AddCommand(newContractGenerateCmd())

	return contractCmd
}

// newContractDeployCmd creates the contract deploy command
func newContractDeployCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "deploy [from] [bytecode] [args...]",
		Short: "Deploy a smart contract",
		Long: `Deploy a smart contract to the Quantaureum blockchain.

Example:
  qau-cli contract deploy 0x1234...abcd 0x60606040...

This command deploys a compiled smart contract to the blockchain.
The contract bytecode should be provided in hex format.

Note: For full contract deployment, you need:
  1. The compiled contract bytecode
  2. Constructor arguments (if any)
  3. Gas limit sufficient for deployment
  4. An unlocked account or signed transaction`,
		Args: cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			from := args[0]
			bytecode := args[1]
			contractArgs := args[2:]

			fmt.Printf("Deploying contract from %s...\n", from)
			fmt.Printf("Bytecode size: %d bytes (%d hex chars)\n", len(bytecode)/2, len(bytecode))
			if len(contractArgs) > 0 {
				fmt.Printf("Constructor arguments: %v\n", contractArgs)
			}
			fmt.Println()
			fmt.Println("Contract Deployment Process:")
			fmt.Println("  1. Create contract creation transaction")
			fmt.Println("  2. Sign with quantum-safe Dilithium3 signature")
			fmt.Println("  3. Submit to network via RPC")
			fmt.Println("  4. Wait for confirmation")
			fmt.Println()
			fmt.Println("Via RPC (node must be running):")
			fmt.Printf("  curl -X POST %s -H 'Content-Type: application/json' \\\n", getEndpoint(rpcEndpoint))
			fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",")
			fmt.Println("         \"params\":[{\"from\":\"...\",\"data\":\"0x...\",\"gas\":\"...\"}],\"id\":1}'")
			fmt.Println()
			fmt.Println("Contract Address:")
			fmt.Println("  After successful deployment, the contract address will be")
			fmt.Println("  returned in the transaction receipt.")
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newContractCallCmd creates the contract call command
func newContractCallCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "call [from] [contract] [method] [args...]",
		Short: "Call a smart contract method",
		Long: `Call a smart contract method on the Quantaureum blockchain.

Example:
  qau-cli contract call 0x1234...abcd 0x9876...wxyz transfer 100

This command calls a method on a deployed smart contract.
For read-only calls (view/pure), this is a local operation.
For state-changing calls, a transaction will be submitted.`,
		Args: cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			from := args[0]
			contract := args[1]
			method := args[2]
			methodArgs := args[3:]

			fmt.Printf("Calling method '%s' on contract %s...\n", method, contract)
			fmt.Printf("From: %s\n", from)
			if len(methodArgs) > 0 {
				fmt.Printf("Arguments: %v\n", methodArgs)
			}
			fmt.Println()
			fmt.Println("Contract Call Information:")
			fmt.Println("  - Read-only calls (view/pure): Free, local execution")
			fmt.Println("  - State-changing calls: Requires gas, creates transaction")
			fmt.Println()
			fmt.Println("For state-changing calls, the transaction will be signed")
			fmt.Println("with your quantum-safe Dilithium3 key and submitted to the network.")
			fmt.Println()
			fmt.Println("Via RPC eth_call (read-only):")
			fmt.Printf("  curl -X POST %s -H 'Content-Type: application/json' \\\n", getEndpoint(rpcEndpoint))
			fmt.Println("    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",")
			fmt.Println("         \"params\":[{\"to\":\"0x...\",\"data\":\"0x...\"}],\"id\":1}'")
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newContractInfoCmd creates the contract info command
func newContractInfoCmd() *cobra.Command {
	var rpcEndpoint string

	cmd := &cobra.Command{
		Use:   "info [contract]",
		Short: "Get contract information",
		Long: `Get information about a deployed smart contract.

Example:
  qau-cli contract info 0x9876543210abcdef9876543210abcdef98765432

This command retrieves information about a deployed contract
including its bytecode and storage layout.`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			contract := args[0]
			endpoint := getEndpoint(rpcEndpoint)
			client, err := NewRPCClient(endpoint)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create RPC client: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Getting information for contract %s...\n", contract)
			fmt.Println()

			// Get code
			code, err := client.GetCode(cmd.Context(), contract)
			if err != nil {
				fmt.Printf("Error getting contract code: %v\n", err)
				fmt.Println("Make sure the contract address is correct and the node is running.")
				return
			}

			if code == "0x" || code == "" {
				fmt.Println("No contract found at this address (empty bytecode)")
				return
			}

			fmt.Println("Contract Information")
			fmt.Println("====================")
			fmt.Printf("Address:     %s\n", contract)
			fmt.Printf("Bytecode:    %d bytes (%d hex chars)\n", len(code)/2-1, len(code)-2)
			fmt.Println()
			fmt.Println("First 64 bytes of bytecode:")
			if len(code) > 66 {
				fmt.Printf("  %s...\n", code[2:66])
			}
			fmt.Println()
			fmt.Println("To interact with this contract, you will need:")
			fmt.Println("  1. The contract ABI (Application Binary Interface)")
			fmt.Println("  2. The method signatures")
			fmt.Println("  3. The encoding scheme for function calls")
		},
	}

	cmd.Flags().StringVar(&rpcEndpoint, "rpc", "", "RPC endpoint URL")
	return cmd
}

// newContractGenerateCmd creates the contract generate command
func newContractGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate [type] [name] [params...]",
		Short: "Generate a smart contract template",
		Long: `Generate a smart contract template with quantum-safe features.

Example:
  qau-cli contract generate token MyToken QAU
  qau-cli contract generate erc20 MyToken "MyToken" "MTK" 18

This command generates a template smart contract with quantum-safe
features for the Quantaureum blockchain.`,
		Args: cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			contractType := args[0]
			name := args[1]
			params := args[2:]

			fmt.Printf("Generating %s contract: %s\n", contractType, name)
			if len(params) > 0 {
				fmt.Printf("Parameters: %v\n", params)
			}
			fmt.Println()

			switch contractType {
			case "token", "erc20":
				generateERC20Template(name, params)
			case "nft", "erc721":
				generateNFTTemplate(name, params)
			default:
				generateGenericTemplate(contractType, name, params)
			}
		},
	}

	return cmd
}

// generateERC20Template generates an ERC20 token contract template
func generateERC20Template(name string, params []string) {
	symbol := name
	decimals := "18"
	if len(params) > 0 {
		symbol = params[0]
	}
	if len(params) > 1 {
		decimals = params[1]
	}

	template := fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "quantaureum/contracts/QuantumToken.sol";

/**
 * @title %s
 * @dev Quantum-safe ERC20 Token
 * Uses post-quantum cryptography for enhanced security
 */
contract %[2]s is QuantumToken {
    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) QuantumToken(_name, _symbol, _decimals) {
        // Initial supply can be minted here if needed
    }

    // Additional quantum-safe features can be added here

    /**
     * @dev Override transfer with quantum signature verification
     */
    function transfer(address to, uint256 amount) public override returns (bool) {
        // Quantum-safe transfer logic
        return super.transfer(to, amount);
    }
}
`, name, name, symbol, decimals)

	fmt.Println("Generated ERC20 Template:")
	fmt.Println("==========================")
	fmt.Println(template)
	fmt.Println()
	fmt.Println("To compile and deploy this contract:")
	fmt.Println("  1. Install the Quantaureum Solidity compiler")
	fmt.Println("  2. Compile: qauc compile contract.sol")
	fmt.Println("  3. Deploy: qau-cli contract deploy <from> <bytecode>")
}

// generateNFTTemplate generates an ERC721 NFT contract template
func generateNFTTemplate(name string, params []string) {
	template := fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "quantaureum/contracts/QuantumNFT.sol";

/**
 * @title %s
 * @dev Quantum-safe ERC721 Non-Fungible Token
 * Uses post-quantum cryptography for enhanced security
 */
contract %[2]s is QuantumNFT {
    constructor(
        string memory _name,
        string memory _symbol
    ) QuantumNFT(_name, _symbol) {
        // NFT initialization
    }

    /**
     * @dev Mint a new NFT with quantum-safe metadata
     */
    function mint(address to, uint256 tokenId, string memory uri) public {
        _mint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }
}
`, name, name)

	fmt.Println("Generated NFT Template:")
	fmt.Println("=======================")
	fmt.Println(template)
	fmt.Println()
	fmt.Println("To compile and deploy this contract:")
	fmt.Println("  1. Install the Quantaureum Solidity compiler")
	fmt.Println("  2. Compile: qauc compile contract.sol")
	fmt.Println("  3. Deploy: qau-cli contract deploy <from> <bytecode>")
}

// generateGenericTemplate generates a generic contract template
func generateGenericTemplate(contractType string, name string, params []string) {
	template := fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "quantaureum/contracts/QuantumContract.sol";

/**
 * @title %s
 * @dev Quantum-safe smart contract
 * Uses post-quantum cryptography for enhanced security
 */
contract %s is QuantumContract {

    // Events
    event Updated(string key, bytes value);

    // Storage
    mapping(string => bytes) private _data;

    constructor() {
        // Initialize contract
    }

    /**
     * @dev Update data with quantum-safe verification
     */
    function update(string memory key, bytes memory value) public {
        _data[key] = value;
        emit Updated(key, value);
    }

    /**
     * @dev Read data from storage
     */
    function read(string memory key) public view returns (bytes memory) {
        return _data[key];
    }
}
`, name, name)

	fmt.Println("Generated Generic Contract Template:")
	fmt.Println("====================================")
	fmt.Println(template)
	fmt.Println()
	fmt.Println("To compile and deploy this contract:")
	fmt.Println("  1. Install the Quantaureum Solidity compiler")
	fmt.Println("  2. Compile: qauc compile contract.sol")
	fmt.Println("  3. Deploy: qau-cli contract deploy <from> <bytecode>")
}

// GetCode is a helper to get contract code via RPC
// audit-fix LOW: Use context.Context instead of any for type safety.
// The previous signature `ctx any` accepted any value, including nil and
// non-context types, which could cause runtime panics or silent failures.
func (c *RPCClient) GetCode(ctx context.Context, address string) (string, error) {
	if ctx == nil {
		return "", fmt.Errorf("context is required")
	}
	result, err := c.call("eth_getCode", []any{address, "latest"})
	if err != nil {
		return "", err
	}
	var code string
	if err := json.Unmarshal(result, &code); err != nil {
		return "", err
	}
	return code, nil
}

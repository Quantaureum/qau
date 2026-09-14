// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newContractCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contract",
		Short: "Deploy and interact with smart contracts",
		Long: `Deploy smart contracts and call contract methods via RPC.

Supports deploying any contract from bytecode, including LinearVesting contracts
with constructor arguments (beneficiary, cliff, start, duration, totalAmount).

Private keys are never handled directly — use account-remote import/unlock first.

Example:
  # Deploy a LinearVesting contract
  qauctl contract deploy ./contract.hex http://rpc.example.invalid:8545 \
    --from 0x08036632ada4ff720fbb5e4b8e226358280954cb \
    --constructor "beneficiary=0xdF6F...,cliff=+3600,start=now,duration=7200,amount=1000qau"

  # Call a contract method (releasable())
  qauctl contract call 0xContractAddress 0x86d1a69f http://rpc.example.invalid:8545 \
    --from 0x08036632ada4ff720fbb5e4b8e226358280954cb`,
	}

	cmd.AddCommand(newContractDeployCmd())
	cmd.AddCommand(newContractCallCmd())

	return cmd
}

func newContractDeployCmd() *cobra.Command {
	var (
		fromAddr      string
		gas           string
		gasPrice      string
		value         string
		constructor   string
		vestingCliff  int64
		vestingDur    int64
		vestingAmount string
		vestingBenef  string
	)

	cmd := &cobra.Command{
		Use:   "deploy <bytecode-file> <rpc-url>",
		Short: "Deploy a smart contract",
		Long: `Deploy a smart contract from a bytecode hex file.

The bytecode file should contain the compiled contract hex (without 0x prefix).
Constructor arguments can be provided via --constructor for generic contracts,
or via --vesting-* flags for LinearVesting contracts.

For LinearVesting contracts, use the --vesting-* flags:
  --vesting-beneficiary  Beneficiary address (0x...)
  --vesting-cliff        Cliff duration in seconds from now (e.g. 3600 for 1 hour)
  --vesting-duration     Total vesting duration in seconds (e.g. 7200 for 2 hours)
  --vesting-amount       Total amount in QAU (e.g. 1000)

The account must be unlocked first using 'qauctl account-remote unlock'.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deployContract(args[0], args[1], fromAddr, gas, gasPrice, value, constructor, vestingBenef, vestingCliff, vestingDur, vestingAmount)
		},
	}

	cmd.Flags().StringVar(&fromAddr, "from", "", "Sender address (must be unlocked)")
	cmd.Flags().StringVar(&gas, "gas", "0x400000", "Gas limit (hex)")
	cmd.Flags().StringVar(&gasPrice, "gas-price", "0x1", "Gas price (hex)")
	cmd.Flags().StringVar(&value, "value", "0x0", "Value to send (hex)")
	cmd.Flags().StringVar(&constructor, "constructor", "", "Constructor args as key=value pairs (generic)")

	// LinearVesting-specific flags
	cmd.Flags().StringVar(&vestingBenef, "vesting-beneficiary", "", "LinearVesting: beneficiary address")
	cmd.Flags().Int64Var(&vestingCliff, "vesting-cliff", 0, "LinearVesting: cliff duration in seconds from now")
	cmd.Flags().Int64Var(&vestingDur, "vesting-duration", 0, "LinearVesting: total duration in seconds")
	cmd.Flags().StringVar(&vestingAmount, "vesting-amount", "", "LinearVesting: total amount in QAU (e.g. 1000)")

	return cmd
}

func newContractCallCmd() *cobra.Command {
	var (
		fromAddr string
	)

	cmd := &cobra.Command{
		Use:   "call <contract-address> <calldata-hex> <rpc-url>",
		Short: "Call a contract method (read-only)",
		Long: `Call a smart contract method via eth_call (read-only, no transaction).

The calldata should include the function selector + encoded arguments.

Example:
  # Call releasable()
  qauctl contract call 0xContractAddr 0x86d1a69f http://rpc.example.invalid:8545 --from 0xMyAddr

  # Call release()
  qauctl contract call 0xContractAddr 0x15e4167e http://rpc.example.invalid:8545 --from 0xMyAddr`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return callContract(args[0], args[1], args[2], fromAddr)
		},
	}

	cmd.Flags().StringVar(&fromAddr, "from", "", "Caller address")

	return cmd
}

func deployContract(bytecodeFile, rpcURL, fromAddr, gas, gasPrice, value, constructor, vestingBenef string, vestingCliff, vestingDur int64, vestingAmount string) error {
	if fromAddr == "" {
		return fmt.Errorf("--from address is required")
	}

	// Read bytecode
	bytecodeHex, err := os.ReadFile(bytecodeFile)
	if err != nil {
		return fmt.Errorf("failed to read bytecode file: %w", err)
	}
	bytecodeStr := strings.TrimSpace(string(bytecodeHex))

	// Build constructor args
	var constructorArgs string

	if vestingBenef != "" || vestingCliff > 0 || vestingDur > 0 || vestingAmount != "" {
		// LinearVesting constructor
		constructorArgs, err = buildVestingConstructorArgs(vestingBenef, vestingCliff, vestingDur, vestingAmount)
		if err != nil {
			return err
		}
	} else if constructor != "" {
		return fmt.Errorf("generic constructor args not yet implemented, use --vesting-* flags for LinearVesting")
	}

	// Full deploy data
	deployData := "0x" + bytecodeStr + constructorArgs

	fmt.Printf("Deploying contract...\n")
	fmt.Printf("  From:       %s\n", fromAddr)
	fmt.Printf("  Bytecode:   %s (%d bytes)\n", bytecodeFile, len(bytecodeStr)/2)
	fmt.Printf("  Gas:        %s\n", gas)

	// Get current nonce for the from address
	nonceResult, err := rpcCall("eth_getTransactionCount", []any{fromAddr, "latest"})
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}
	var nonceHex string
	if err := json.Unmarshal(nonceResult, &nonceHex); err != nil {
		return fmt.Errorf("failed to parse nonce: %w", err)
	}
	fmt.Printf("  Nonce:      %s\n", nonceHex)

	// Send transaction
	result, err := rpcCall("eth_sendTransaction", []any{
		map[string]any{
			"from":     fromAddr,
			"data":     deployData,
			"gas":      gas,
			"gasPrice": gasPrice,
			"value":    value,
			"nonce":    nonceHex,
		},
	})
	if err != nil {
		return fmt.Errorf("RPC call failed: %w", err)
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return fmt.Errorf("failed to parse RPC response: %w", err)
	}

	fmt.Printf("\nTransaction submitted!\n")
	fmt.Printf("  TxHash: %s\n", txHash)

	// Wait for receipt
	fmt.Println("\nWaiting for receipt...")
	var contractAddr string
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		receiptResult, err := rpcCall("eth_getTransactionReceipt", []any{txHash})
		if err != nil {
			continue
		}

		var receipt struct {
			ContractAddress string `json:"contractAddress"`
			Status          string `json:"status"`
			BlockNumber     string `json:"blockNumber"`
		}
		if err := json.Unmarshal(receiptResult, &receipt); err != nil {
			continue
		}

		if receipt.ContractAddress != "" && receipt.ContractAddress != "0x0000000000000000000000000000000000000000" {
			contractAddr = receipt.ContractAddress
			fmt.Printf("\nContract deployed successfully!\n")
			fmt.Printf("  Contract: %s\n", contractAddr)
			fmt.Printf("  Block:    %s\n", receipt.BlockNumber)
			fmt.Printf("  Status:   %s\n", receipt.Status)
			break
		}
	}

	if contractAddr == "" {
		fmt.Println("\nWarning: Could not confirm contract deployment. Check manually with eth_getTransactionReceipt.")
	}

	return nil
}

func callContract(contractAddr, calldata, rpcURL, fromAddr string) error {
	params := map[string]any{
		"to":   contractAddr,
		"data": calldata,
	}
	if fromAddr != "" {
		params["from"] = fromAddr
	}

	result, err := rpcCall("eth_call", []any{params, "latest"})
	if err != nil {
		return fmt.Errorf("RPC call failed: %w", err)
	}

	var returnData string
	if err := json.Unmarshal(result, &returnData); err != nil {
		return fmt.Errorf("failed to parse RPC response: %w", err)
	}

	fmt.Printf("Contract: %s\n", contractAddr)
	fmt.Printf("Calldata: %s\n", calldata)
	fmt.Printf("Return:   %s\n", returnData)

	// Try to interpret the return value
	if len(returnData) > 2 {
		// Remove 0x prefix
		hexStr := strings.TrimPrefix(returnData, "0x")
		if len(hexStr) == 64 {
			// uint256 result
			val := new(big.Int)
			val.SetString(hexStr, 16)
			fmt.Printf("Decoded:  %s\n", val.String())
			// Try to convert from wei to QAU
			qau := new(big.Float).Quo(new(big.Float).SetInt(val), big.NewFloat(1e18))
			fmt.Printf("As QAU:   %.6f\n", qau)
		} else if hexStr == "" {
			fmt.Println("Decoded:  (empty - likely REVERT)")
		}
	}

	return nil
}

// buildVestingConstructorArgs builds the constructor arguments for LinearVesting contract.
func buildVestingConstructorArgs(beneficiary string, cliffDuration, totalDuration int64, amountQAU string) (string, error) {
	if beneficiary == "" {
		return "", fmt.Errorf("--vesting-beneficiary is required")
	}
	if cliffDuration <= 0 {
		return "", fmt.Errorf("--vesting-cliff must be > 0")
	}
	if totalDuration <= 0 {
		return "", fmt.Errorf("--vesting-duration must be > 0")
	}
	if amountQAU == "" {
		return "", fmt.Errorf("--vesting-amount is required")
	}

	// Get current block timestamp
	blockResult, err := rpcCall("eth_blockNumber", nil)
	if err != nil {
		return "", fmt.Errorf("failed to get block number: %w", err)
	}

	var blockHex string
	if err := json.Unmarshal(blockResult, &blockHex); err != nil {
		return "", fmt.Errorf("failed to parse block number: %w", err)
	}

	blockResult2, err := rpcCall("eth_getBlockByNumber", []any{blockHex, false})
	if err != nil {
		return "", fmt.Errorf("failed to get block: %w", err)
	}

	var blockInfo struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(blockResult2, &blockInfo); err != nil {
		return "", fmt.Errorf("failed to parse block: %w", err)
	}

	timestamp := new(big.Int)
	timestamp.SetString(strings.TrimPrefix(blockInfo.Timestamp, "0x"), 16)

	startTime := timestamp
	cliffDurationBig := big.NewInt(cliffDuration) // Relative: QASM does start + cliff internally
	duration := big.NewInt(totalDuration)

	// Parse amount in QAU to wei
	amountFloat := new(big.Float)
	amountFloat.SetString(amountQAU)
	weiFloat := new(big.Float).Mul(amountFloat, big.NewFloat(1e18))
	amountWei := new(big.Int)
	weiFloat.Int(amountWei)

	// Encode constructor args: beneficiary, start, cliff, duration, totalAmount
	// IMPORTANT: Order must match QASM init code CALLDATALOAD offsets!
	// Slot 0=beneficiary(offset-0xA0), Slot 1=start(offset-0x80), Slot 2=cliff(offset-0x60), Slot 3=duration(offset-0x40), Slot 5=totalAmount(offset-0x20)
	// Each is 32 bytes (uint256), beneficiary is address left-padded to 32 bytes
	benefArgs, err := encodeAddress(beneficiary)
	if err != nil {
		return "", err
	}

	startArgs := encodeUint256(startTime)
	cliffArgs := encodeUint256(cliffDurationBig)
	durArgs := encodeUint256(duration)
	amtArgs := encodeUint256(amountWei)

	fmt.Printf("Constructor args:\n")
	fmt.Printf("  Beneficiary: %s\n", beneficiary)
	fmt.Printf("  Start:       %s\n", startTime.String())
	fmt.Printf("  Cliff:       %s (relative, QASM adds start+cliff internally)\n", cliffDurationBig.String())
	fmt.Printf("  Duration:    %s (%ds)\n", duration.String(), totalDuration)
	fmt.Printf("  Amount:      %s QAU (%s wei)\n", amountQAU, amountWei.String())

	// CORRECT ORDER: beneficiary, start, cliff, duration, totalAmount
	return benefArgs + startArgs + cliffArgs + durArgs + amtArgs, nil
}

// encodeAddress encodes an Ethereum-style address as a 32-byte hex string (left-padded).
func encodeAddress(addr string) (string, error) {
	addr = strings.TrimPrefix(addr, "0x")
	addr = strings.TrimPrefix(addr, "0X")
	addr = strings.ToLower(addr)

	addrBytes, err := hex.DecodeString(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address: %w", err)
	}

	if len(addrBytes) != 20 {
		return "", fmt.Errorf("invalid address length: %d bytes", len(addrBytes))
	}

	padded := make([]byte, 32)
	copy(padded[12:], addrBytes) // Right-align in 32 bytes

	return hex.EncodeToString(padded), nil
}

// encodeUint256 encodes a big.Int as a 32-byte hex string.
func encodeUint256(val *big.Int) string {
	padded := make([]byte, 32)
	bytes := val.Bytes()
	copy(padded[32-len(bytes):], bytes)
	return hex.EncodeToString(padded)
}

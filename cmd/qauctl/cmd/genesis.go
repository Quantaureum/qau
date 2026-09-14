// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/quantaureum/qau/crypto"
	"github.com/spf13/cobra"
)

// GenesisValidator represents a validator entry in genesis.json.
type GenesisValidator struct {
	Address     string `json:"address"`
	Stake       string `json:"stake"`
	Commission  int    `json:"commission"`
	PublicKey   string `json:"publicKey"`
	Description string `json:"description"`
}

// GenesisAlloc represents a pre-allocation entry in genesis.json.
// Used only for parsing the INPUT alloc.json file (array of {address, balance}).
type GenesisAlloc struct {
	Address string `json:"address"`
	Balance string `json:"balance"`
}

// GenesisConfig represents the full genesis.json structure.
// BUG FIX (R8 2026-07-19): Alloc was previously []GenesisAlloc (array),
// but the node's node.GenesisConfig.Alloc is map[string]GenesisAccount.
// This mismatch caused "json: cannot unmarshal array into Go struct field
// Genesis.alloc of type map[string]node.GenesisAccount" on node startup.
// Changed to map so qauctl genesis generate produces node-loadable JSON.
type GenesisConfig struct {
	ChainID    uint64                    `json:"chainId"`
	NetworkID  uint64                    `json:"networkId"`
	Validators []GenesisValidator        `json:"validators"`
	Alloc      map[string]map[string]any `json:"alloc"`
	Timestamp  int64                     `json:"timestamp"`
	GasLimit   uint64                    `json:"gasLimit"`
}

func newGenesisCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "genesis",
		Short: "Generate and manage genesis configuration",
		Long: `Generate genesis.json from validator key files and allocation configuration.

This tool reads validator private key files to derive addresses and public keys,
then generates a complete genesis.json. Private key content is never displayed.

Example:
  qauctl genesis generate --validator-keys ./keys/validator_1.key,./keys/validator_2.key,./keys/validator_3.key \
    --alloc ./alloc.json \
    --output ./genesis.json \
    --chain-id 1668`,
	}

	cmd.AddCommand(newGenesisGenerateCmd())
	cmd.AddCommand(newGenesisShowValidatorsCmd())

	return cmd
}

func newGenesisGenerateCmd() *cobra.Command {
	var (
		validatorKeys string
		allocFile     string
		outputFile    string
		chainID       uint64
		networkID     uint64
		stake         string
		commission    int
		gasLimit      uint64
		timestamp     int64
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate genesis.json from validator keys",
		Long: `Generate a genesis.json file from validator key files.

Reads each validator key file to derive the address and public key,
then creates a complete genesis configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateGenesis(validatorKeys, allocFile, outputFile, chainID, networkID, stake, commission, gasLimit, timestamp)
		},
	}

	cmd.Flags().StringVar(&validatorKeys, "validator-keys", "", "Comma-separated list of validator key file paths")
	cmd.Flags().StringVar(&allocFile, "alloc", "", "Pre-allocation JSON file (array of {address, balance})")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "genesis.json", "Output file path")
	cmd.Flags().Uint64Var(&chainID, "chain-id", 1668, "Chain ID (1668=mainnet, 1669=testnet)")
	cmd.Flags().Uint64Var(&networkID, "network-id", 1668, "Network ID")
	cmd.Flags().StringVar(&stake, "stake", "30000000000000000000000", "Default validator stake (in wei)")
	cmd.Flags().IntVar(&commission, "commission", 100, "Default validator commission (basis points)")
	cmd.Flags().Uint64Var(&gasLimit, "gas-limit", 0x800000, "Block gas limit")
	// R8 2026-07-19 FIX: Default timestamp to 1700000000 (matches node's
	// MainnetGenesisTimestamp/TestnetGenesisTimestamp/DevnetGenesisTimestamp
	// constant). Previously defaulted to 0, causing node to reject genesis
	// with "genesis timestamp 0 is too old (minimum: 2023-01-01)".
	cmd.Flags().Int64Var(&timestamp, "timestamp", 1700000000, "Genesis block timestamp (must be >= 2023-01-01)")

	return cmd
}

func newGenesisShowValidatorsCmd() *cobra.Command {
	var validatorKeys string

	cmd := &cobra.Command{
		Use:   "show-validators",
		Short: "Show validator info from key files",
		Long: `Read validator key files and display the derived addresses and public keys.
Private key content is never displayed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showValidators(validatorKeys)
		},
	}

	cmd.Flags().StringVar(&validatorKeys, "validator-keys", "", "Comma-separated list of validator key file paths")

	return cmd
}

func generateGenesis(validatorKeys, allocFile, outputFile string, chainID, networkID uint64, stake string, commission int, gasLimit uint64, timestamp int64) error {
	if validatorKeys == "" {
		return fmt.Errorf("--validator-keys is required")
	}

	// Parse validator key files
	keyFiles := strings.Split(validatorKeys, ",")
	validators := make([]GenesisValidator, 0, len(keyFiles))

	for i, keyFile := range keyFiles {
		keyFile = strings.TrimSpace(keyFile)
		if keyFile == "" {
			continue
		}

		_, address, err := readAndValidateKeyFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read validator key file %s: %w", keyFile, err)
		}

		// Read public key from the key file
		pubKeyHex, err := readPublicKeyFromKeyFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read public key from %s: %w", keyFile, err)
		}

		validator := GenesisValidator{
			Address:     fmt.Sprintf("0x%x", address),
			Stake:       stake,
			Commission:  commission,
			PublicKey:   pubKeyHex,
			Description: fmt.Sprintf("Validator %d", i+1),
		}
		validators = append(validators, validator)

		fmt.Printf("Validator %d: address=0x%x (from %s)\n", i+1, address, filepath.Base(keyFile))
	}

	// Parse allocation file if provided (input is array of {address, balance}).
	allocMap := make(map[string]map[string]any)
	if allocFile != "" {
		allocData, err := os.ReadFile(allocFile)
		if err != nil {
			return fmt.Errorf("failed to read alloc file: %w", err)
		}
		var allocs []GenesisAlloc
		if err := json.Unmarshal(allocData, &allocs); err != nil {
			return fmt.Errorf("failed to parse alloc file: %w", err)
		}
		// Convert array input to map output (node.GenesisConfig expects map).
		for _, a := range allocs {
			allocMap[a.Address] = map[string]any{
				"balance": a.Balance,
				"nonce":   0,
			}
		}
	}

	// Build genesis config
	genesis := GenesisConfig{
		ChainID:    chainID,
		NetworkID:  networkID,
		Validators: validators,
		Alloc:      allocMap,
		Timestamp:  timestamp,
		GasLimit:   gasLimit,
	}

	// Write to file
	data, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal genesis: %w", err)
	}

	if err := os.WriteFile(outputFile, data, 0600); err != nil { // G306: genesis may embed validator keys, owner-only
		return fmt.Errorf("failed to write genesis file: %w", err)
	}

	fmt.Printf("\nGenesis file written to %s\n", outputFile)
	fmt.Printf("  Chain ID:    %d\n", chainID)
	fmt.Printf("  Validators:  %d\n", len(validators))
	fmt.Printf("  Allocations: %d\n", len(allocMap))

	return nil
}

func showValidators(validatorKeys string) error {
	if validatorKeys == "" {
		return fmt.Errorf("--validator-keys is required")
	}

	keyFiles := strings.Split(validatorKeys, ",")

	fmt.Println("Validator Information:")
	fmt.Println("=====================")

	for i, keyFile := range keyFiles {
		keyFile = strings.TrimSpace(keyFile)
		if keyFile == "" {
			continue
		}

		_, address, err := readAndValidateKeyFile(keyFile)
		if err != nil {
			fmt.Printf("  [%d] ERROR: %v\n", i+1, err)
			continue
		}

		pubKeyHex, _ := readPublicKeyFromKeyFile(keyFile)

		fmt.Printf("  [%d] File:     %s\n", i+1, filepath.Base(keyFile))
		fmt.Printf("      Address:  0x%x\n", address)
		if pubKeyHex != "" {
			fmt.Printf("      PublicKey: %s...%s\n", pubKeyHex[:16], pubKeyHex[len(pubKeyHex)-8:])
		}
		fmt.Println()
	}

	return nil
}

// readPublicKeyFromKeyFile reads the public key hex from a key file.
// R8 2026-07-19 FIX: When the key file is in `dilithium3:hex_priv:hex_pub`
// format, read the embedded public key directly instead of re-deriving it
// from the private key. PrivateKeyFromBytes + PublicKey() can produce
// truncated/incorrect output on certain key encodings (observed 990 bytes
// instead of the expected 1952), causing genesis validation failures
// (`publicKey length 990 does not match Dilithium3 size 1952`).
func readPublicKeyFromKeyFile(keyFile string) (string, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}

	content := strings.TrimSpace(string(data))

	if strings.HasPrefix(content, "dilithium3:") || strings.HasPrefix(content, "DILITHIUM3:") {
		hexStr := strings.TrimPrefix(content, "dilithium3:")
		hexStr = strings.TrimPrefix(hexStr, "DILITHIUM3:")
		hexStr = strings.TrimSpace(hexStr)

		// R92-KEYSEP: separator-agnostic split (':' / '+' / none). See
		// splitDilithium3KeyHex in validator.go for the full rationale.
		privKeyHex, pubKeyHex, splitErr := splitDilithium3KeyHex(hexStr)
		if splitErr != nil {
			return "", splitErr
		}

		// FAST PATH: key file already contains the public key.
		// Trust the embedded public key — it was generated alongside the private
		// key by the same keygen tool and is the authoritative source.
		if pubKeyHex != "" {
			return pubKeyHex, nil
		}

		// SLOW PATH: only private key in file (dilithium3:priv), derive pub.
		keyBytes, err := hex.DecodeString(privKeyHex)
		if err != nil {
			return "", err
		}

		if len(keyBytes) > crypto.Dilithium3PrivateKeySize {
			keyBytes = keyBytes[:crypto.Dilithium3PrivateKeySize]
		}

		privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
		if err != nil {
			return "", err
		}

		pubKey := privKey.PublicKey()
		return hex.EncodeToString(pubKey.Bytes()), nil
	}

	return "", fmt.Errorf("unsupported key format for public key extraction")
}

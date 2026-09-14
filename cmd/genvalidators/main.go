// Quantaureum Node source, version 1.0.0.
// genvalidators generates real Dilithium3 quantum validator accounts.
//
// It creates keystore files, updates genesis-quantum.json and quantum-accounts.json
// with addresses derived from actual Dilithium3 public keys.
//
// Usage:
//
//	go run ./cmd/genvalidators
//	go run ./cmd/genvalidators --light   # faster scrypt for dev
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quantaureum/qau/accounts"
	"github.com/quantaureum/qau/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Constants
const (
	chainID          = 1668
	validatorBalance = "32000000000000000000" // 32 QAU in wei
	validatorBalQAU  = "32"
)

// ----- JSON output types -----

type genesisAlloc struct {
	Balance string `json:"balance"`
	Nonce   int    `json:"nonce"`
}

type genesisValidator struct {
	Address   string `json:"address"`
	PublicKey string `json:"publicKey"`
}

type genesisConfig struct {
	ChainID    int                     `json:"chainId"`
	NetworkID  int                     `json:"networkId"`
	Timestamp  int64                   `json:"timestamp"`
	GasLimit   int                     `json:"gasLimit"`
	ExtraData  string                  `json:"extraData"`
	Alloc      map[string]genesisAlloc `json:"alloc"`
	Validators []genesisValidator      `json:"validators"`
}

type accountEntry struct {
	Index      int    `json:"index"`
	Address    string `json:"address"`
	HexAddress string `json:"hexAddress"`
	PublicKey  string `json:"publicKey"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	Balance    string `json:"balance"`
	BalanceQAU string `json:"balanceQAU"`
}

type accountsConfig struct {
	GeneratedAt    string         `json:"generatedAt"`
	ChainID        int            `json:"chainId"`
	Network        string         `json:"network"`
	Accounts       []accountEntry `json:"accounts"`
	TotalSupply    string         `json:"totalSupply"`
	TotalSupplyQAU string         `json:"totalSupplyQAU"`
	Note           string         `json:"note"`
}

type publicKeyInfo struct {
	Version   string    `json:"version"`
	Address   string    `json:"address"`
	PublicKey string    `json:"publicKey"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"createdAt"`
}

// ----- CLI flags -----

var (
	password  string
	outputDir string
	light     bool
	count     int
	rootDir   string
)

func main() {
	cmd := &cobra.Command{
		Use:   "genvalidators",
		Short: "Generate Dilithium3 quantum validator accounts",
		Long: `Generate real Dilithium3 quantum validator keypairs.

Output:
  validators/validator-N/wallet.json  - encrypted keystore
  validators/validator-N/public.json  - public key info
  genesis/dev.json                    - genesis block config
  accounts/quantum-accounts.json      - account mapping`,
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVarP(&password, "password", "p", "", "deprecated and rejected; use QAU_KEYSTORE_PASSWORD or the interactive prompt")
	cmd.Flags().MarkDeprecated("password", "command-line passwords are rejected; use QAU_KEYSTORE_PASSWORD or the interactive prompt")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "validators", "keystore output directory")
	cmd.Flags().BoolVar(&light, "light", false, "use light scrypt parameters (dev/test only)")
	cmd.Flags().IntVarP(&count, "count", "n", 3, "number of validators")
	cmd.Flags().StringVar(&rootDir, "root", ".", "project root directory")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("password") {
		return fmt.Errorf("--password is insecure because process listings expose argv; use QAU_KEYSTORE_PASSWORD or the interactive prompt")
	}

	if password == "" {
		password = os.Getenv("QAU_KEYSTORE_PASSWORD")
	}
	if password == "" {
		pw, err := promptPassword("Enter keystore password (min 8 chars): ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		if len(pw) < 8 {
			return fmt.Errorf("password too short; need at least 8 chars")
		}
		confirm, err := promptPassword("Confirm password: ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		if pw != confirm {
			return fmt.Errorf("passwords do not match")
		}
		password = pw
	}

	// Select keystore params
	ksParams := accounts.DefaultKeystoreParams()
	if light {
		ksParams = accounts.LightKeystoreParams()
		fmt.Println("⚡ Using light scrypt parameters (dev only)")
	}

	fmt.Printf("\n=== Generating %d Dilithium3 quantum validators ===\n\n", count)

	// Generate validators
	type validatorData struct {
		account *accounts.Account
		keyPair *crypto.KeyPair
	}
	validators := make([]validatorData, count)

	for i := 0; i < count; i++ {
		fmt.Printf("[%d/%d] generating Dilithium3 keypair...\n", i+1, count)

		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("key generation failed: %w", err)
		}

		account, err := accounts.NewAccountFromPrivateKey(keyPair.Private)
		if err != nil {
			return fmt.Errorf("account creation failed: %w", err)
		}

		validators[i] = validatorData{account: account, keyPair: keyPair}

		fmt.Printf("       address: %s\n", account.Address.String())
		fmt.Printf("       Hex:  %s\n", account.Address.ToHexAddress())
		fmt.Printf("       public key: %s...(%d bytes)\n",
			hex.EncodeToString(account.PublicKey.Bytes()[:16]),
			len(account.PublicKey.Bytes()))
	}

	// Export keystores
	fmt.Printf("\nEncrypting and saving keystore...\n")
	for i, v := range validators {
		dir := filepath.Join(rootDir, outputDir, fmt.Sprintf("validator-%d", i+1))
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		// Export encrypted keystore
		ksData, err := accounts.ExportKeystoreWithParams(v.account, password, ksParams)
		if err != nil {
			return fmt.Errorf("keystore export failed: %w", err)
		}
		walletPath := filepath.Join(dir, "wallet.json")
		if err := os.WriteFile(walletPath, ksData, 0600); err != nil {
			return fmt.Errorf("failed to write keystore: %w", err)
		}

		// Save public key info
		pubInfo := publicKeyInfo{
			Version:   "1.0.0",
			Address:   v.account.Address.String(),
			PublicKey: hex.EncodeToString(v.account.PublicKey.Bytes()),
			Algorithm: "Dilithium3",
			CreatedAt: time.Now().UTC(),
		}
		pubData, _ := json.MarshalIndent(pubInfo, "", "  ")
		pubPath := filepath.Join(dir, "public.json")
		if err := os.WriteFile(pubPath, pubData, 0600); err != nil {
			return fmt.Errorf("failed to write public key: %w", err)
		}

		fmt.Printf("  ✅ Validator %d → %s\n", i+1, walletPath)
	}

	// Generate genesis-quantum.json
	fmt.Printf("\nGenerating genesis config...\n")
	genesis := genesisConfig{
		ChainID:    chainID,
		NetworkID:  chainID,
		Timestamp:  time.Now().Unix(),
		GasLimit:   30000000,
		ExtraData:  "Quantaureum Genesis Block - Dilithium3 Validators",
		Alloc:      make(map[string]genesisAlloc),
		Validators: make([]genesisValidator, count),
	}

	for i, v := range validators {
		hexAddr := v.account.Address.ToHexAddress()
		pubKeyHex := hex.EncodeToString(v.account.PublicKey.Bytes())

		genesis.Alloc[hexAddr] = genesisAlloc{
			Balance: validatorBalance,
			Nonce:   0,
		}
		genesis.Validators[i] = genesisValidator{
			Address:   hexAddr,
			PublicKey: pubKeyHex,
		}
	}

	genesisPath := filepath.Join(rootDir, "configs", "genesis-quantum.json")
	genesisData, _ := json.MarshalIndent(genesis, "", "  ")
	if err := os.WriteFile(genesisPath, genesisData, 0600); err != nil {
		return fmt.Errorf("failed to write genesis config: %w", err)
	}
	fmt.Printf("  ✅ %s\n", genesisPath)

	// Generate quantum-accounts.json
	fmt.Printf("\nGenerating account mapping...\n")
	now := time.Now().UTC()
	totalWei := "96000000000000000000" // 3 * 32 QAU

	acctEntries := make([]accountEntry, count)
	for i, v := range validators {
		acctEntries[i] = accountEntry{
			Index:      i,
			Address:    v.account.Address.String(),
			HexAddress: v.account.Address.ToHexAddress(),
			PublicKey:  hex.EncodeToString(v.account.PublicKey.Bytes()),
			Name:       fmt.Sprintf("Validator %d", i+1),
			Role:       "Validator",
			Balance:    validatorBalance,
			BalanceQAU: validatorBalQAU,
		}
	}

	acctConfig := accountsConfig{
		GeneratedAt:    now.Format(time.RFC3339),
		ChainID:        chainID,
		Network:        "Quantaureum Mainnet",
		Accounts:       acctEntries,
		TotalSupply:    totalWei,
		TotalSupplyQAU: fmt.Sprintf("%d", count*32),
		Note:           fmt.Sprintf("%d validator accounts using Dilithium3 quantum signatures; keys generated by the genvalidators tool", count),
	}

	acctPath := filepath.Join(rootDir, "accounts", "quantum-accounts.json")
	if err := os.MkdirAll(filepath.Dir(acctPath), 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	acctData, _ := json.MarshalIndent(acctConfig, "", "  ")
	if err := os.WriteFile(acctPath, acctData, 0600); err != nil {
		return fmt.Errorf("failed to write account mapping: %w", err)
	}
	fmt.Printf("  ✅ %s\n", acctPath)

	// Summary
	fmt.Printf("\n")
	fmt.Println(strings.Repeat("═", 60))
	fmt.Printf("✅ Successfully generated %d Dilithium3 quantum validators\n", count)
	fmt.Println(strings.Repeat("═", 60))
	fmt.Println()
	for i, v := range validators {
		fmt.Printf("  Validator %d: %s\n", i+1, v.account.Address.String())
	}
	fmt.Println()
	fmt.Println("Output files:")
	fmt.Printf("  Keystore:  %s/validator-*/wallet.json\n", filepath.Join(rootDir, outputDir))
	fmt.Printf("  Genesis:   %s\n", genesisPath)
	fmt.Printf("  Accounts:  %s\n", acctPath)
	fmt.Println()
	fmt.Println("⚠️  Keep the keystore password safe — losing it makes validator private keys unrecoverable!")

	return nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- stdin fd is always a small positive int
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

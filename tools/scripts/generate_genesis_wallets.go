// Quantaureum Node source, version 1.0.0.
// Batch-generate genesis allocation wallets
// Generates the genesis allocation addresses required by the QAU project
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
)

type ColdWalletPublic struct {
	Version     string    `json:"version"`
	Address     string    `json:"address"`
	PublicKey   string    `json:"public_key"`
	Algorithm   string    `json:"algorithm"`
	CreatedAt   time.Time `json:"created_at"`
	Description string    `json:"description,omitempty"`
}

type GenesisWallet struct {
	Name       string `json:"name"`
	Purpose    string `json:"purpose"`
	Amount     string `json:"amount"`
	Percentage string `json:"percentage"`
	LockPeriod string `json:"lock_period"`
	Address    string `json:"address"`
	WalletPath string `json:"wallet_path"`
}

var walletConfigs = []struct {
	Name       string
	Purpose    string
	Amount     string
	Percentage string
	LockPeriod string
}{
	// {"private_sale", "Private sale reserve", "14,400,000 QAU", "20%", "TBD"}, // cancelled
	{"team_advisors", "Team & advisors", "10,800,000 QAU", "15%", "4y, 1y locked"},
	{"ecosystem_fund", "Ecosystem fund", "10,800,000 QAU", "15%", "4y vesting"},
	{"community_airdrop", "Community airdrop", "7,200,000 QAU", "10%", "none"},
	// {"development_fund", "Development fund", "7,200,000 QAU", "10%", "3y vesting"}, // cancelled
	{"validator_incentive", "Validator incentive pool", "20,000,000 QAU", "20%", "5y vesting"},
	{"foundation_reserve", "Foundation reserve", "8,000,000 QAU", "8%", "4y vesting"},
}

func main() {
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("  Quantaureum genesis allocation wallet batch generator")
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println()

	// read the password
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run generate_genesis_wallets.go <password>")
		fmt.Println("The password must be at least 12 characters")
		os.Exit(1)
	}
	password := os.Args[1]
	if len(password) < 12 {
		fmt.Println("Error: the password must be at least 12 characters")
		os.Exit(1)
	}

	// create the output directory
	baseDir := filepath.Join("..", "keys", "genesis_wallets")
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		fmt.Printf("Error: failed to create the output directory: %v\n", err)
		os.Exit(1)
	}

	var results []GenesisWallet

	for i, cfg := range walletConfigs {
		fmt.Printf("[%d/7] generating %s wallet...\n", i+1, cfg.Purpose)

		walletDir := filepath.Join(baseDir, cfg.Name)
		if err := os.MkdirAll(walletDir, 0700); err != nil {
			fmt.Printf("Error: failed to create the wallet directory: %v\n", err)
			os.Exit(1)
		}

		// generate the keypair
		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			fmt.Printf("  ❌ key generation failed: %v\n", err)
			continue
		}

		// create the account
		account, err := accounts.NewAccountFromPrivateKey(keyPair.Private)
		if err != nil {
			fmt.Printf("  ❌ account creation failed: %v\n", err)
			continue
		}

		// export the encrypted wallet
		data, err := accounts.ExportKeystoreWithParams(account, password, accounts.DefaultKeystoreParams())
		if err != nil {
			fmt.Printf("  ❌ wallet encryption failed: %v\n", err)
			continue
		}

		// save the wallet file
		walletPath := filepath.Join(walletDir, "wallet.json")
		if err := os.WriteFile(walletPath, data, 0600); err != nil { // #nosec G703
			fmt.Printf("  ❌ failed to save the wallet: %v\n", err)
			continue
		}

		// save the public key info
		pub := ColdWalletPublic{
			Version:     "1.0.0",
			Address:     account.Address.String(),
			PublicKey:   hex.EncodeToString(keyPair.Public.Bytes()),
			Algorithm:   "Dilithium3",
			CreatedAt:   time.Now().UTC(),
			Description: cfg.Purpose,
		}
		pubData, _ := json.MarshalIndent(pub, "", "  ")
		// R59-G306 [MEDIUM] FIX: public.json permissions 0644 → 0600.
		// Previously world-readable, exposing derived addresses and public key metadata.
		// 0600 ensures only the owner can read the file.
		if err := os.WriteFile(filepath.Join(walletDir, "public.json"), pubData, 0600); err != nil {
			fmt.Printf("  ❌ failed to save the public key info: %v\n", err)
			continue
		}

		fmt.Printf("  ✅ address: %s\n", account.Address.String())

		results = append(results, GenesisWallet{
			Name:       cfg.Name,
			Purpose:    cfg.Purpose,
			Amount:     cfg.Amount,
			Percentage: cfg.Percentage,
			LockPeriod: cfg.LockPeriod,
			Address:    account.Address.String(),
			WalletPath: walletDir,
		})
	}

	// generate the summary report
	fmt.Println()
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println("  Done!")
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println()

	// save the summary JSON
	summaryPath := filepath.Join(baseDir, "genesis_addresses.json")
	summaryData, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(summaryPath, summaryData, 0600); err != nil {
		fmt.Printf("Error: failed to write the summary file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Summary file: %s\n\n", summaryPath)

	// print a Markdown table
	fmt.Println("## Genesis allocation address list")
	fmt.Println()
	fmt.Println("| Purpose | Address | Amount | Share | Lock |")
	fmt.Println("|------|------|------|------|--------|")
	for _, w := range results {
		fmt.Printf("| %s | `%s` | %s | %s | %s |\n",
			w.Purpose, w.Address, w.Amount, w.Percentage, w.LockPeriod)
	}

	fmt.Println()
	fmt.Println("⚠️ Important notes:")
	fmt.Println("1. Back up the keys/genesis_wallets directory to secure offline storage")
	fmt.Println("2. Remember the password — losing it makes the wallets unrecoverable")
	fmt.Println("3. Update the addresses in genesis/dev.json")
}

// Quantaureum Node source, version 1.0.0.
// Package node provides development account management for testing.
package node

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// DevAccount represents a development test account
type DevAccount struct {
	Address    string `json:"address"`
	PrivateKey string `json:"-"`
	PublicKey  string `json:"public_key"`
	Balance    string `json:"balance"`
}

// DevAccounts holds all development accounts
type DevAccounts struct {
	Accounts []*DevAccount `json:"accounts"`
}

// devAccountsFile is the file to store dev accounts
const devAccountsFile = "dev_accounts.json"

// InitDevAccounts initializes development accounts for testing
// Returns the accounts and their initial balances
func InitDevAccounts(dataDir string, count int) ([]*DevAccount, map[types.Address]*big.Int, error) {
	accountsPath := filepath.Join(dataDir, devAccountsFile)

	// Try to load existing accounts
	if accounts, err := loadDevAccounts(accountsPath); err == nil && len(accounts.Accounts) >= count {
		balances := make(map[types.Address]*big.Int)
		for _, acc := range accounts.Accounts {
			addr := parseHexAddress(acc.Address)
			balance, _ := new(big.Int).SetString("20000000000000000000000000", 10) // 20M QAU
			balances[addr] = balance
		}
		return accounts.Accounts, balances, nil
	}

	// Generate new accounts
	accounts := &DevAccounts{
		Accounts: make([]*DevAccount, 0, count),
	}
	balances := make(map[types.Address]*big.Int)

	for i := 0; i < count; i++ {
		// R8 2026-07-19 FIX: Use deterministic seed so all nodes generate
		// the same dev accounts. Previously used crypto.GenerateKeyPair()
		// (random), causing each node to have different dev accounts and
		// different stateRoots, breaking consensus on testnet.
		// The seed is derived from a fixed domain separator + account index,
		// NOT from the dataDir (which differs per node).
		seed := make([]byte, 32)
		copy(seed[:], []byte("QUANTAUREUM-DEV-ACCOUNT-SEED")) // 27 bytes + 5 zero pad
		binary.BigEndian.PutUint64(seed[24:], uint64(i))      // append index at bytes 24-31

		keyPair, err := crypto.GenerateKeyPairFromSeed(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
		}

		addr := keyPair.Public.Address()
		balance, _ := new(big.Int).SetString("20000000000000000000000000", 10) // 20M QAU

		acc := &DevAccount{
			Address:    "0x" + hex.EncodeToString(addr[:]),
			PrivateKey: "0x" + hex.EncodeToString(keyPair.Private.Bytes()),
			PublicKey:  "0x" + hex.EncodeToString(keyPair.Public.Bytes()),
			Balance:    balance.String(),
		}

		accounts.Accounts = append(accounts.Accounts, acc)
		balances[addr] = balance
	}

	// Save accounts
	if err := saveDevAccounts(accountsPath, accounts); err != nil {
		return nil, nil, fmt.Errorf("failed to save dev accounts: %w", err)
	}

	return accounts.Accounts, balances, nil
}

// loadDevAccounts loads dev accounts from file
func loadDevAccounts(path string) (*DevAccounts, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path from dataDir + constant filename, not user input
	if err != nil {
		return nil, err
	}

	var accounts DevAccounts
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}

	return &accounts, nil
}

// saveDevAccounts saves dev accounts to file
func saveDevAccounts(path string, accounts *DevAccounts) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	// audit-fix L-2: use 0700 since directory contains private key files
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// H-5 FIX: Warn if the accounts file might be tracked by version control.
	// Dev account private keys are stored in plaintext and must NEVER be committed.
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		fmt.Fprintf(os.Stderr, "WARNING: dev_accounts.json is in a git-tracked directory! "+
			"Private keys should NEVER be committed to version control. "+
			"Add %s to .gitignore immediately.\n", path)
	}

	data, err := json.MarshalIndent(accounts, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600) // Restricted permissions for private keys
}

// parseHexAddress parses a hex address string
func parseHexAddress(s string) types.Address {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	bytes, _ := hex.DecodeString(s)
	return types.BytesToAddress(bytes)
}

// GetDevAccountByIndex returns a dev account by index
func GetDevAccountByIndex(dataDir string, index int) (*DevAccount, error) {
	accountsPath := filepath.Join(dataDir, devAccountsFile)
	accounts, err := loadDevAccounts(accountsPath)
	if err != nil {
		return nil, err
	}

	if index < 0 || index >= len(accounts.Accounts) {
		return nil, fmt.Errorf("account index out of range")
	}

	return accounts.Accounts[index], nil
}

// PrintDevAccounts prints dev accounts info.
// audit-fix R7-Info-2: use structured logger instead of fmt.Printf to keep
// output routed through the logging pipeline.
func PrintDevAccounts(accounts []*DevAccount) {
	nodeLog.Info("=== Development Test Accounts ===")
	nodeLog.Warn("These accounts are for development only! Never use these private keys on mainnet!")

	for i, acc := range accounts {
		// SECURITY FIX: Never log private keys - only log address for identification
		nodeLog.Info("Account %d: Address=%s  Balance=%s QAU",
			i+1, acc.Address, acc.Balance)
	}
}

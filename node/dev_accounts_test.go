// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ── parseHexAddress ──

func TestParseHexAddress_WithPrefix(t *testing.T) {
	addr := parseHexAddress("0x1234567890123456789012345678901234567890")
	if addr.IsEmpty() {
		t.Error("expected non-empty address")
	}
}

func TestParseHexAddress_WithoutPrefix(t *testing.T) {
	addr := parseHexAddress("1234567890123456789012345678901234567890")
	if addr.IsEmpty() {
		t.Error("expected non-empty address")
	}
}

func TestParseHexAddress_UppercasePrefix(t *testing.T) {
	addr := parseHexAddress("0X1234567890123456789012345678901234567890")
	if addr.IsEmpty() {
		t.Error("expected non-empty address with 0X prefix")
	}
}

func TestParseHexAddress_Empty(t *testing.T) {
	addr := parseHexAddress("")
	if !addr.IsEmpty() {
		t.Error("expected empty address for empty string")
	}
}

func TestParseHexAddress_InvalidHex(t *testing.T) {
	addr := parseHexAddress("not-hex")
	// Should return zero address without panicking
	_ = addr
}

// ── InitDevAccounts ──

func TestInitDevAccounts(t *testing.T) {
	dataDir := t.TempDir()

	accounts, balances, err := InitDevAccounts(dataDir, 3)
	if err != nil {
		t.Fatalf("InitDevAccounts failed: %v", err)
	}
	if len(accounts) != 3 {
		t.Errorf("expected 3 accounts, got %d", len(accounts))
	}
	if len(balances) != 3 {
		t.Errorf("expected 3 balances, got %d", len(balances))
	}

	// Verify each account has an address and balance
	for i, acc := range accounts {
		if acc.Address == "" {
			t.Errorf("account %d has empty address", i)
		}
		if acc.Balance == "" {
			t.Errorf("account %d has empty balance", i)
		}
	}
}

func TestInitDevAccounts_Persistence(t *testing.T) {
	dataDir := t.TempDir()

	// First call creates accounts
	accounts1, _, err := InitDevAccounts(dataDir, 2)
	if err != nil {
		t.Fatalf("first InitDevAccounts failed: %v", err)
	}

	// Second call should load the same accounts
	accounts2, _, err := InitDevAccounts(dataDir, 2)
	if err != nil {
		t.Fatalf("second InitDevAccounts failed: %v", err)
	}

	if len(accounts1) != len(accounts2) {
		t.Errorf("expected same number of accounts, got %d and %d", len(accounts1), len(accounts2))
	}

	for i := range accounts1 {
		if accounts1[i].Address != accounts2[i].Address {
			t.Errorf("account %d address mismatch: %s vs %s", i, accounts1[i].Address, accounts2[i].Address)
		}
	}
}

func TestInitDevAccounts_BalanceAmount(t *testing.T) {
	dataDir := t.TempDir()

	_, balances, err := InitDevAccounts(dataDir, 1)
	if err != nil {
		t.Fatalf("InitDevAccounts failed: %v", err)
	}

	for addr, balance := range balances {
		if addr.IsEmpty() {
			t.Error("expected non-empty address in balances")
		}
		if balance.Cmp(big.NewInt(0)) <= 0 {
			t.Errorf("expected positive balance, got %s", balance.String())
		}
	}
}

// ── loadDevAccounts ──

func TestLoadDevAccounts_NonexistentFile(t *testing.T) {
	_, err := loadDevAccounts("/nonexistent/path/dev_accounts.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadDevAccounts_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "dev_accounts.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := loadDevAccounts(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadDevAccounts_ValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "dev_accounts.json")
	jsonData := `{"accounts":[{"address":"0x1234567890123456789012345678901234567890","public_key":"0xabc","balance":"1000"}]}`
	os.WriteFile(path, []byte(jsonData), 0644)

	accounts, err := loadDevAccounts(path)
	if err != nil {
		t.Fatalf("loadDevAccounts failed: %v", err)
	}
	if len(accounts.Accounts) != 1 {
		t.Errorf("expected 1 account, got %d", len(accounts.Accounts))
	}
}

// ── saveDevAccounts ──

func TestSaveDevAccounts(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "subdir", "dev_accounts.json")

	accounts := &DevAccounts{
		Accounts: []*DevAccount{
			{Address: "0x1234", PublicKey: "0xabc", Balance: "1000"},
		},
	}

	err := saveDevAccounts(path, accounts)
	if err != nil {
		t.Fatalf("saveDevAccounts failed: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("file was not created")
	}
}

func TestSaveDevAccounts_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "dev_accounts.json")

	original := &DevAccounts{
		Accounts: []*DevAccount{
			{Address: "0x1234567890123456789012345678901234567890", PublicKey: "0xabcdef", Balance: "999999"},
		},
	}

	err := saveDevAccounts(path, original)
	if err != nil {
		t.Fatalf("saveDevAccounts failed: %v", err)
	}

	loaded, err := loadDevAccounts(path)
	if err != nil {
		t.Fatalf("loadDevAccounts failed: %v", err)
	}

	if len(loaded.Accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(loaded.Accounts))
	}
	if loaded.Accounts[0].Address != original.Accounts[0].Address {
		t.Errorf("address mismatch: %s vs %s", loaded.Accounts[0].Address, original.Accounts[0].Address)
	}
}

// ── GetDevAccountByIndex ──

func TestGetDevAccountByIndex(t *testing.T) {
	dataDir := t.TempDir()

	// First initialize accounts
	_, _, err := InitDevAccounts(dataDir, 5)
	if err != nil {
		t.Fatalf("InitDevAccounts failed: %v", err)
	}

	// Get account by index
	acc, err := GetDevAccountByIndex(dataDir, 0)
	if err != nil {
		t.Fatalf("GetDevAccountByIndex failed: %v", err)
	}
	if acc == nil {
		t.Fatal("expected non-nil account")
	}
}

func TestGetDevAccountByIndex_OutOfRange(t *testing.T) {
	dataDir := t.TempDir()

	_, _, err := InitDevAccounts(dataDir, 2)
	if err != nil {
		t.Fatalf("InitDevAccounts failed: %v", err)
	}

	_, err = GetDevAccountByIndex(dataDir, 10)
	if err == nil {
		t.Error("expected error for out of range index")
	}
}

func TestGetDevAccountByIndex_NegativeIndex(t *testing.T) {
	dataDir := t.TempDir()

	_, _, err := InitDevAccounts(dataDir, 2)
	if err != nil {
		t.Fatalf("InitDevAccounts failed: %v", err)
	}

	_, err = GetDevAccountByIndex(dataDir, -1)
	if err == nil {
		t.Error("expected error for negative index")
	}
}

func TestGetDevAccountByIndex_NoAccounts(t *testing.T) {
	dataDir := t.TempDir()

	_, err := GetDevAccountByIndex(dataDir, 0)
	if err == nil {
		t.Error("expected error when no accounts file exists")
	}
}

// ── DevAccount struct ──

func TestDevAccount_Fields(t *testing.T) {
	acc := &DevAccount{
		Address:    "0x1234567890123456789012345678901234567890",
		PrivateKey: "0xabc",
		PublicKey:  "0xdef",
		Balance:    "1000000",
	}
	if acc.Address != "0x1234567890123456789012345678901234567890" {
		t.Errorf("unexpected address: %s", acc.Address)
	}
	if acc.Balance != "1000000" {
		t.Errorf("unexpected balance: %s", acc.Balance)
	}
}

// ── hex encoding validation ──

func TestParseHexAddress_RoundTrip(t *testing.T) {
	original := types.BytesToAddress([]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90})
	hexStr := "0x" + hex.EncodeToString(original[:])
	parsed := parseHexAddress(hexStr)
	if parsed != original {
		t.Errorf("round-trip failed: %x != %x", original, parsed)
	}
}

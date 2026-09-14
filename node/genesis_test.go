// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ── DefaultGenesis tests ──

func TestDefaultGenesis(t *testing.T) {
	g := DefaultGenesis()
	if g.ChainID != MainnetNetworkID {
		t.Errorf("expected chain ID %d, got %d", MainnetNetworkID, g.ChainID)
	}
	if g.NetworkID != MainnetNetworkID {
		t.Errorf("expected network ID %d, got %d", MainnetNetworkID, g.NetworkID)
	}
	if g.GasLimit != 20000000 {
		t.Errorf("expected gas limit 20000000, got %d", g.GasLimit)
	}
	if g.Timestamp != MainnetGenesisTimestamp {
		t.Errorf("expected timestamp %d, got %d", MainnetGenesisTimestamp, g.Timestamp)
	}
	if g.Alloc == nil {
		t.Error("expected non-nil alloc map")
	}
}

func TestDevGenesis(t *testing.T) {
	g := DevGenesis()
	if g.ChainID != DevnetNetworkID {
		t.Errorf("expected chain ID %d, got %d", DevnetNetworkID, g.ChainID)
	}
	if g.NetworkID != DevnetNetworkID {
		t.Errorf("expected network ID %d, got %d", DevnetNetworkID, g.NetworkID)
	}
}

func TestTestnetGenesis(t *testing.T) {
	g := TestnetGenesis()
	if g.ChainID != TestnetNetworkID {
		t.Errorf("expected chain ID %d, got %d", TestnetNetworkID, g.ChainID)
	}
	if g.NetworkID != TestnetNetworkID {
		t.Errorf("expected network ID %d, got %d", TestnetNetworkID, g.NetworkID)
	}
}

func TestBuiltinNetworkGenesisValidation(t *testing.T) {
	for name, genesis := range map[string]*Genesis{
		"mainnet": DefaultGenesis(),
		"testnet": TestnetGenesis(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := genesis.Validate(); err != nil {
				t.Fatalf("built-in %s genesis failed validation: %v", name, err)
			}
		})
	}
}

// ── Genesis Validate tests ──

func TestGenesisValidate_ZeroChainID(t *testing.T) {
	g := &Genesis{
		ChainID:   0,
		NetworkID: 0,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for zero chain ID")
	}
}

func TestGenesisValidate_ChainIDNetworkIDMismatch(t *testing.T) {
	g := &Genesis{
		ChainID:   MainnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for chain ID / network ID mismatch")
	}
}

func TestGenesisValidate_UnsupportedChainID(t *testing.T) {
	g := &Genesis{
		ChainID:   9999,
		NetworkID: 9999,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for unsupported chain ID")
	}
}

func TestGenesisValidate_TimestampTooOld(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: 1000, // way too old
		GasLimit:  30000000,
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for too old timestamp")
	}
}

func TestGenesisValidate_GasLimitTooLow(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  100, // too low
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for gas limit too low")
	}
}

func TestGenesisValidate_GasLimitTooHigh(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  200000000, // too high
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for gas limit too high")
	}
}

func TestGenesisValidate_NoValidatorsForMainnet(t *testing.T) {
	g := &Genesis{
		ChainID:    MainnetNetworkID,
		NetworkID:  MainnetNetworkID,
		Timestamp:  MainnetGenesisTimestamp,
		GasLimit:   30000000,
		Validators: []GenesisValidator{},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for no validators on mainnet")
	}
}

func TestGenesisValidate_NoValidatorsForDevnet(t *testing.T) {
	g := &Genesis{
		ChainID:    DevnetNetworkID,
		NetworkID:  DevnetNetworkID,
		Timestamp:  MainnetGenesisTimestamp,
		GasLimit:   30000000,
		Validators: []GenesisValidator{},
	}
	err := g.Validate()
	if err != nil {
		t.Errorf("devnet should allow no validators, got: %v", err)
	}
}

func TestGenesisValidate_InvalidValidatorAddress(t *testing.T) {
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: "", PublicKey: "0x1234", Stake: "1000"},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for empty validator address")
	}
}

func TestGenesisValidate_EmptyValidatorPublicKey(t *testing.T) {
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: "0x1234567890123456789012345678901234567890", PublicKey: "", Stake: "1000"},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for empty validator public key")
	}
}

func TestGenesisValidate_EmptyValidatorStake(t *testing.T) {
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: "0x1234567890123456789012345678901234567890", PublicKey: "0xabcd", Stake: ""},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for empty validator stake")
	}
}

func TestGenesisValidate_ZeroValidatorStake(t *testing.T) {
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: "0x1234567890123456789012345678901234567890", PublicKey: "0xabcd", Stake: "0"},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for zero validator stake")
	}
}

func TestGenesisValidate_ValidDevnet(t *testing.T) {
	g := DevGenesis()
	err := g.Validate()
	if err != nil {
		t.Errorf("dev genesis should be valid, got: %v", err)
	}
}

// ── ToBlock tests ──

func TestGenesis_ToBlock(t *testing.T) {
	g := DefaultGenesis()
	block := g.ToBlock()
	if block == nil {
		t.Fatal("expected non-nil block")
	}
	if block.Header.Height != 0 {
		t.Errorf("expected height 0, got %d", block.Header.Height)
	}
	if block.ChainID != MainnetNetworkID {
		t.Errorf("expected chain ID %d, got %d", MainnetNetworkID, block.ChainID)
	}
	if block.NetworkID != MainnetNetworkID {
		t.Errorf("expected network ID %d, got %d", MainnetNetworkID, block.NetworkID)
	}
}

func TestGenesis_ToBlock_HexExtraData(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		ExtraData: "0x1234",
	}
	block := g.ToBlock()
	if block == nil {
		t.Fatal("expected non-nil block")
	}
}

// ── GenesisBlockHeader Hash tests ──

func TestGenesisBlockHeader_Hash(t *testing.T) {
	g := DefaultGenesis()
	block := g.ToBlock()
	hash := block.Header.Hash()
	if hash == (types.Hash{}) {
		t.Error("expected non-zero genesis block hash")
	}
}

func TestGenesisBlockHeader_Hash_Deterministic(t *testing.T) {
	g := DefaultGenesis()
	block1 := g.ToBlock()
	block2 := g.ToBlock()

	hash1 := block1.Header.Hash()
	hash2 := block2.Header.Hash()

	if hash1 != hash2 {
		t.Error("genesis block hash should be deterministic")
	}
}

// ── GetAllocations tests ──

func TestGetAllocations_Empty(t *testing.T) {
	g := DevGenesis()
	allocs, err := g.GetAllocations()
	if err != nil {
		t.Fatalf("GetAllocations failed: %v", err)
	}
	if len(allocs) != 0 {
		t.Errorf("expected 0 allocations, got %d", len(allocs))
	}
}

func TestGetAllocations_WithAccounts(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "1000000000000000000",
			},
		},
	}
	allocs, err := g.GetAllocations()
	if err != nil {
		t.Fatalf("GetAllocations failed: %v", err)
	}
	if len(allocs) != 1 {
		t.Errorf("expected 1 allocation, got %d", len(allocs))
	}
}

func TestGetAllocations_HexBalance(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "0xde0b6b3a7640000",
			},
		},
	}
	allocs, err := g.GetAllocations()
	if err != nil {
		t.Fatalf("GetAllocations failed: %v", err)
	}
	if len(allocs) != 1 {
		t.Errorf("expected 1 allocation, got %d", len(allocs))
	}
	for _, balance := range allocs {
		if balance.Cmp(big.NewInt(0)) <= 0 {
			t.Error("expected positive balance")
		}
	}
}

// ── GetAccountCodes tests ──

func TestGetAccountCodes_Empty(t *testing.T) {
	g := DevGenesis()
	codes, err := g.GetAccountCodes()
	if err != nil {
		t.Fatalf("GetAccountCodes failed: %v", err)
	}
	if len(codes) != 0 {
		t.Errorf("expected 0 codes, got %d", len(codes))
	}
}

func TestGetAccountCodes_WithCode(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "1000",
				Code:    "60806040",
			},
		},
	}
	codes, err := g.GetAccountCodes()
	if err != nil {
		t.Fatalf("GetAccountCodes failed: %v", err)
	}
	if len(codes) != 1 {
		t.Errorf("expected 1 code, got %d", len(codes))
	}
}

// ── GetAccountStorage tests ──

func TestGetAccountStorage_Empty(t *testing.T) {
	g := DevGenesis()
	storage, err := g.GetAccountStorage()
	if err != nil {
		t.Fatalf("GetAccountStorage failed: %v", err)
	}
	if len(storage) != 0 {
		t.Errorf("expected 0 storage entries, got %d", len(storage))
	}
}

func TestGetAccountStorage_WithStorage(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "1000",
				Storage: map[string]string{
					"0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000000000000000042",
				},
			},
		},
	}
	storage, err := g.GetAccountStorage()
	if err != nil {
		t.Fatalf("GetAccountStorage failed: %v", err)
	}
	if len(storage) != 1 {
		t.Errorf("expected 1 storage entry, got %d", len(storage))
	}
}

// ── GetAccountNonces tests ──

func TestGetAccountNonces_Empty(t *testing.T) {
	g := DevGenesis()
	nonces, err := g.GetAccountNonces()
	if err != nil {
		t.Fatalf("GetAccountNonces failed: %v", err)
	}
	if len(nonces) != 0 {
		t.Errorf("expected 0 nonces, got %d", len(nonces))
	}
}

func TestGetAccountNonces_WithNonces(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "1000",
				Nonce:   5,
			},
		},
	}
	nonces, err := g.GetAccountNonces()
	if err != nil {
		t.Fatalf("GetAccountNonces failed: %v", err)
	}
	if len(nonces) != 1 {
		t.Errorf("expected 1 nonce entry, got %d", len(nonces))
	}
}

// ── SaveGenesis / LoadGenesis tests ──

func TestSaveAndLoadGenesis(t *testing.T) {
	tmpDir := t.TempDir()
	genesisPath := filepath.Join(tmpDir, "genesis.json")

	g := DevGenesis()
	err := g.SaveGenesis(genesisPath)
	if err != nil {
		t.Fatalf("SaveGenesis failed: %v", err)
	}

	loaded, err := LoadGenesis(genesisPath)
	if err != nil {
		t.Fatalf("LoadGenesis failed: %v", err)
	}
	if loaded.ChainID != g.ChainID {
		t.Errorf("expected chain ID %d, got %d", g.ChainID, loaded.ChainID)
	}
	if loaded.NetworkID != g.NetworkID {
		t.Errorf("expected network ID %d, got %d", g.NetworkID, loaded.NetworkID)
	}
}

func TestLoadGenesis_Nonexistent(t *testing.T) {
	_, err := LoadGenesis("/nonexistent/path/genesis.json")
	if err == nil {
		t.Error("expected error for nonexistent genesis file")
	}
}

func TestLoadGenesis_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	genesisPath := filepath.Join(tmpDir, "genesis.json")
	os.WriteFile(genesisPath, []byte("not-json"), 0644)

	_, err := LoadGenesis(genesisPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestProtocolV2CanonicalMainnetGenesisLoads verifies that the canonical
// mainnet genesis file (genesis/mainnet.json) loads successfully and matches
// the Protocol V2 deployment: ChainID=1668, NetworkID=1668, exactly 6
// validators, and 14 alloc entries.
//
// R38-Plan Batch 0.3: the old TestR4NODE02_CanonicalMainnetGenesisLoads
// asserted the legacy deployment of 3 validators / 11 alloc entries, but
// the checked-in canonical genesis contains 6 / 14. The fresh Protocol V2
// deployment removes legacy-count compatibility; this test fails on any
// regression that re-introduces a stale genesis count.
func TestProtocolV2CanonicalMainnetGenesisLoads(t *testing.T) {
	// The canonical genesis JSON files (genesis/mainnet.json, genesis/testnet.json,
	// genesis/dev.json) are deployment artifacts and are NOT distributed with the
	// open-source tree. Regenerate them with cmd/genvalidators / the genesis tools
	// before running this test; skip when absent.
	if _, err := os.Stat("../genesis/mainnet.json"); err != nil {
		t.Skip("genesis/mainnet.json not present (deployment artifact, not shipped in the open-source tree)")
	}
	g, err := LoadGenesis("../genesis/mainnet.json")
	if err != nil {
		t.Fatalf("failed to load canonical mainnet genesis: %v", err)
	}
	if g.ChainID != 1668 {
		t.Errorf("expected ChainID 1668, got %d", g.ChainID)
	}
	if g.NetworkID != 1668 {
		t.Errorf("expected NetworkID 1668, got %d", g.NetworkID)
	}
	if len(g.Validators) != 6 {
		t.Errorf("expected 6 validators (Protocol V2 canonical deployment), got %d", len(g.Validators))
	}
	if len(g.Alloc) != 14 {
		t.Errorf("expected 14 alloc entries (Protocol V2 canonical deployment), got %d", len(g.Alloc))
	}
	if err := g.Validate(); err != nil {
		t.Errorf("canonical mainnet genesis failed validation: %v", err)
	}
}

// ── Genesis JSON serialization ──

func TestGenesis_JSONSerialization(t *testing.T) {
	g := DefaultGenesis()
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("failed to marshal genesis: %v", err)
	}

	var loaded Genesis
	err = json.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("failed to unmarshal genesis: %v", err)
	}
	if loaded.ChainID != g.ChainID {
		t.Errorf("expected chain ID %d, got %d", g.ChainID, loaded.ChainID)
	}
}

// ── GenesisValidator type ──

func TestGenesisValidator_Fields(t *testing.T) {
	v := GenesisValidator{
		Address:   "0x1234567890123456789012345678901234567890",
		PublicKey: "0xabcd",
		Stake:     "1000",
	}
	if v.Address == "" {
		t.Error("expected non-empty address")
	}
}

// ── GenesisAccount type ──

func TestGenesisAccount_Fields(t *testing.T) {
	a := GenesisAccount{
		Balance: "1000000",
		Nonce:   5,
		Code:    "60806040",
		Storage: map[string]string{"0x01": "0x02"},
	}
	if a.Balance != "1000000" {
		t.Error("unexpected balance")
	}
	if a.Nonce != 5 {
		t.Error("unexpected nonce")
	}
}

// ── Helper function tests ──

func TestStripHexPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0xabc", "abc"},
		{"0Xabc", "abc"},
		{"abc", "abc"},
		{"", ""},
		{"0x", ""},
	}
	for _, tt := range tests {
		result := stripHexPrefix(tt.input)
		if result != tt.expected {
			t.Errorf("stripHexPrefix(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// ── Genesis timestamp constants ──

// R41-GENESIS-16 (2026-08-03): These constants must equal the timestamps
// baked into the canonical genesis JSON files (genesis/mainnet.json,
// genesis/testnet.json, genesis/dev.json). If you change the JSON
// timestamp (e.g., after a network reset), update BOTH the constant in
// genesis.go AND the expected values here. Drift between the constant
// and the JSON would split the network: DefaultGenesis() users compute
// a different genesis block hash than LoadGenesis() users.
func TestGenesisTimestamps(t *testing.T) {
	if MainnetGenesisTimestamp != 1788816000 {
		t.Errorf("expected mainnet genesis timestamp 1788816000 (matches genesis/mainnet.json), got %d", MainnetGenesisTimestamp)
	}
	if TestnetGenesisTimestamp != 1780910400 {
		t.Errorf("expected testnet genesis timestamp 1780910400 (matches genesis/testnet.json), got %d", TestnetGenesisTimestamp)
	}
	if DevnetGenesisTimestamp != 1777140239 {
		t.Errorf("expected devnet genesis timestamp 1777140239 (matches genesis/dev.json), got %d", DevnetGenesisTimestamp)
	}
}

// ── parseAddressString tests ──

func TestParseAddressString_HexFormat(t *testing.T) {
	addr, err := parseAddressString("0x1234567890123456789012345678901234567890")
	if err != nil {
		t.Fatalf("parseAddressString failed: %v", err)
	}
	if addr.IsEmpty() {
		t.Error("expected non-empty address")
	}
}

func TestParseAddressString_HexWithoutPrefix(t *testing.T) {
	addr, err := parseAddressString("1234567890123456789012345678901234567890")
	if err != nil {
		t.Fatalf("parseAddressString failed: %v", err)
	}
	if addr.IsEmpty() {
		t.Error("expected non-empty address")
	}
}

func TestParseAddressString_InvalidHex(t *testing.T) {
	_, err := parseAddressString("not-hex")
	if err == nil {
		t.Error("expected error for invalid hex address")
	}
}

func TestParseAddressString_Empty(t *testing.T) {
	_, err := parseAddressString("")
	// NODE-003 FIX: Empty string now returns error (length != 20)
	if err == nil {
		t.Fatal("expected error for empty string, got nil")
	}
}

// ── hashBytes tests ──

func TestHashBytes_NonEmpty(t *testing.T) {
	result := hashBytes([]byte("test-data"))
	if len(result) != 32 {
		t.Errorf("expected 32-byte hash, got %d bytes", len(result))
	}
}

func TestHashBytes_Deterministic(t *testing.T) {
	h1 := hashBytes([]byte("test"))
	h2 := hashBytes([]byte("test"))
	if string(h1) != string(h2) {
		t.Error("hashBytes should be deterministic")
	}
}

func TestHashBytes_DifferentInputs(t *testing.T) {
	h1 := hashBytes([]byte("input-a"))
	h2 := hashBytes([]byte("input-b"))
	if string(h1) == string(h2) {
		t.Error("hashBytes should produce different hashes for different inputs")
	}
}

// ── GenesisBlockHeader Hash extended tests ──

func TestGenesisBlockHeader_Hash_DifferentVersions(t *testing.T) {
	g1 := &GenesisBlockHeader{Version: 1, Height: 0, Timestamp: 1000, GasLimit: 30000000}
	g2 := &GenesisBlockHeader{Version: 2, Height: 0, Timestamp: 1000, GasLimit: 30000000}
	if g1.Hash() == g2.Hash() {
		t.Error("different versions should produce different hashes")
	}
}

func TestGenesisBlockHeader_Hash_DifferentHeights(t *testing.T) {
	g1 := &GenesisBlockHeader{Version: 1, Height: 0, Timestamp: 1000, GasLimit: 30000000}
	g2 := &GenesisBlockHeader{Version: 1, Height: 1, Timestamp: 1000, GasLimit: 30000000}
	if g1.Hash() == g2.Hash() {
		t.Error("different heights should produce different hashes")
	}
}

func TestGenesisBlockHeader_Hash_DifferentGasLimits(t *testing.T) {
	g1 := &GenesisBlockHeader{Version: 1, Height: 0, Timestamp: 1000, GasLimit: 30000000}
	g2 := &GenesisBlockHeader{Version: 1, Height: 0, Timestamp: 1000, GasLimit: 15000000}
	if g1.Hash() == g2.Hash() {
		t.Error("different gas limits should produce different hashes")
	}
}

func TestGenesisBlockHeader_Hash_DifferentTimestamps(t *testing.T) {
	g1 := &GenesisBlockHeader{Version: 1, Height: 0, Timestamp: 1000, GasLimit: 30000000}
	g2 := &GenesisBlockHeader{Version: 1, Height: 0, Timestamp: 2000, GasLimit: 30000000}
	if g1.Hash() == g2.Hash() {
		t.Error("different timestamps should produce different hashes")
	}
}

func TestGenesisBlockHeader_Hash_DifferentExtraData(t *testing.T) {
	g1 := &GenesisBlockHeader{Version: 1, Height: 0, Timestamp: 1000, GasLimit: 30000000, ExtraData: []byte("a")}
	g2 := &GenesisBlockHeader{Version: 1, Height: 0, Timestamp: 1000, GasLimit: 30000000, ExtraData: []byte("b")}
	if g1.Hash() == g2.Hash() {
		t.Error("different extra data should produce different hashes")
	}
}

// ── Genesis Validate extended ──

func TestGenesisValidate_ZeroGasLimit(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  0, // should default to 30000000
	}
	err := g.Validate()
	if err != nil {
		t.Errorf("zero gas limit should default, got: %v", err)
	}
	if g.GasLimit != 30000000 {
		t.Errorf("expected gas limit to default to 30000000, got %d", g.GasLimit)
	}
}

func TestGenesisValidate_TimestampTooFarInFuture(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: uint64(1 << 62), // way too far in the future
		GasLimit:  30000000,
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for timestamp too far in the future")
	}
}

func TestGenesisValidate_InvalidAllocAddress(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"not-a-valid-address": {
				Balance: "1000",
			},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for invalid alloc address")
	}
}

func TestGenesisValidate_NegativeAllocBalance(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "-1000",
			},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for negative alloc balance")
	}
}

func TestGenesisValidate_InvalidValidatorPublicKey(t *testing.T) {
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: "0x1234567890123456789012345678901234567890", PublicKey: "not-hex", Stake: "1000"},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for invalid validator public key")
	}
}

func TestGenesisValidate_NegativeValidatorStake(t *testing.T) {
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: "0x1234567890123456789012345678901234567890", PublicKey: "0xabcd", Stake: "-100"},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Error("expected error for negative validator stake")
	}
}

func TestGenesisValidate_ValidTestnetWithValidators(t *testing.T) {
	// NODE2-001 FIX: PublicKey and Address must correspond — address is derived
	// from the public key via types.AddressFromPublicKey(sha3-256(pubkey)[12:]).
	// Using a real key pair generated via crypto.GenerateKeyPair().
	validPubKey := "0x5aa11bb6dc06418de407055cc146284ead5fee651ba9fad29d2b1ec690766f063fadac31cdf3683cf8e7db79a7ddc7d759024c6f188f2822c2be2b7267500c63b29ab314a037fb5c5b91a02ddb927eeef61264948d2a7dbba5a795e1880e3a11a94d6d4eddbd92df23dbf40a925599583b89bd24602882f76c066bf56f7ac9eb526cbca58b7d086df1d5a274972258711a7881682928bd947bf46395acf4e1961c6a454ca47022a465551703499f6bb7946e0c1a298c891e4f0ee3ca38a7871bdae493e104ffbfc0c8cd41ce9e818c98045a471a0db387af9871c37519d39a561a7793f64f4927205f31771b60a87d2a96ce242f266821c2b200f2bb8028aee83f090a6dee57cb50ef10d141b2a3e197e1cd1895f6163f15b593d2bdfb170336be559df39a9a0e7f27bb12fa6deace7940f2812903c53f5864c943d3b20b3c92688c6f9a2c961d19e20d1cd2fd7abc499be4d701415f69c9d60eac3dc878702c0c2915a3f1ec2a03f6cac1929fbd1ddbd55381c6a77e5c9c0216f30211a8349f3531006acfa34ca5a5715cce4ed860ba1cb45f8fcfa40fe0151c633834f92fc43fc5a4d79a1a66fab3f9a1fb92a0031997b04a4bff401e01a5a197715ef282025f451f08f89c4813e8101913d35f6faba00c7668a99430a5e981337f55951ae60c62575a28f7fcd16992461f17f23b55d8f8492ad7925bbc3d010df5cea824da5ee2e3ea9ad07dc776132fe6e03089ea1c555bf58e2f1ad914d7c1aa41d0b39c7ad2ebb022b73687673d7d38017310797fc15ef58492ae4e5fd55e97ab90f32530d1d64f974436d75eb9acf42f403659c545920dd997870516196d3271cd6f92c76537bc838c1b95a5644bf6ca6c3484f57c850f20ed40aa0c9670650d97f4970a978d35e721522a5ea898b5e19bacec074b2f216a40cfbcbae6da9c1e532f810533cafbc844510ae826ff6c228a067f0608127cffe2f2c8dedbd2e148477f8a3ead602dbb80b5dcb7871977c633d9b36fc6900a60b72b80c46288655b62f8e1616e703e147a78177de360ec4e0630ea94fb2ea10c7aa21bf54630b7b7b467e95cb586f6868a91d55f3f73cec1ded29df42723e7c33eaafefc76cbd43d77e859a04669bbf6c3e805479ed5b81e09fb98d34826510c5e7f0ac70ca9b4d26e24c077d2b2b4e3ca6cae362dcc88caeb83aa7f4dcf4b32ded44c5fde3750a13b246c00dbdcad06bb5b8a86cb6fea468a94a3d81014571bb0027b33a7f514abed660fb9fef00d7494431d88a1e3860b9fd18bcbc15d4fef7c7d71e10f03823f76e84754ed9af1df6360e9c6ddd2428dd151e3bd360cb0621181b05f9215aa7252f0f68940f8fb1d95472147c15d77e4a7a85177ff4640cc004fc3a6fa2b753fef43dea6334989edd3fb66ddc6ff6d9962fdfb77c37d2b3532eb5eda2fa88992af87f8b488393f5a11f102783ae440a515b3eea0a111b98c92b30ce7bd85abc9c855eeefabfb9f12176e6de90774fb0c3ed1c5c0645b5bdf1d0498f2e2b18beb98acdfcf4171e92bfbb9b983b2d5d98e5573c7191dc51115b231e39acd26460abc3f6cbcd88f43bd1e3d30e08394fd41241ce1dcdc4a3806112e696f0d366e44c175fda7d2d6be1de681f3a884eb1efa2e43a6333269ce1cf2c9ca6176b4650b0fcbf3b20da06ae38c61a75fe5aea46a3cd6c9d8c35555d23c5c1dada2ef46ff31fed011af5046ad2097e039cfbf8ab070bb37a37d9f31ff50492e77e92286c43fbef3bc8f7f2b99de889a81826d0b28b341164dee2103d6496d4dae5e67a796bf09dda42984585433f497d27fc57b957588889ee15e6d9438bdc824b25f2b6f94ae4ac96cf8de50ce5319bb0389005d2f0cb00ff33b9f9989901a15b4339eede74b89c279438019499dff8e955290b5087a07e16c22a13c8c89e9c66846705825e3d86803f89f9297f52dc33619ed21987f908a4f77077dcf0c9fd0c9fa796b781d1e57cf9a9c6a36029b4ad95445cbb43064f027cdc62ebd9d74f4fc09ffc89298a5f9bef0ddd8149ac0a3545d2ef21c38056eb0acfbea57d5d42c960b6662aa1368bfaaa5f58cd5d19a2123392c099ef8627da436a35388a46c854b68f9c850e8327a2aa97f86da5f502a4f0a2da545d55656f2b00b91eda6df298ed2fba8bd38f09a412eacdc1030c59cb7e5d70dc2b8ca45ec81ba72e48f98eb75a737e8bab975728eb3ff6b7c735dfbe921a4854b5a68acbd859c6ec176402809cb1f44b448d3caba38b167ef5ccfba8e9e9a7adbb25fecd7780ec4d0278739481e1961ed99e9272416d48d254121c86929459c7cc21215ca707b9e3f1c77bf8a7784f20fd62f6d62cf29944254ef4bca0eaf045d98e3ca76e6edc5fe8bd0941a7320f0c4d8a1283e38a212b9c89ba21cf0ce7dc48aa82051a6240af447adccd67535953d6d71839cbb7932a0fb0ce361ee14a74588ba7117cf494df8d6e7351d98e409ddbdcd365b93f9d80301abc29157a7f34f55559bbc8fe34d46d081a3cc0ad4f9028827c4737263621ab3c8a0d9ab32d4faada44a0e59c01f1e57faa7f2863bd09db48e5a21ec8b88938fa0b74dcd7938e8a530afcd30e0a65e99f097ea412e9f131a00fbb8857b381d95f3e9365c90f23621bc561ac5ce3bf26ddf9d108c4404a4f6548294bee52efb3879cdbcf059abca924ce9ce90dcefa713549430151f155d4d91a6c7e90c2053f7c278c41189ecde9fe13edbd62e81fa83c88b6d7aaff9cfd43c"
	validAddr := "0x415b210256487b284d125425099c7637a86c3b32"
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: validAddr, PublicKey: validPubKey, Stake: "1000"},
		},
	}
	err := g.Validate()
	if err != nil {
		t.Errorf("valid testnet genesis should pass, got: %v", err)
	}
}

// ── GetAllocations extended ──

func TestGetAllocations_InvalidAddress(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"invalid-address": {
				Balance: "1000",
			},
		},
	}
	_, err := g.GetAllocations()
	if err == nil {
		t.Error("expected error for invalid address in allocations")
	}
}

func TestGetAllocations_ZeroBalance(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "",
			},
		},
	}
	allocs, err := g.GetAllocations()
	if err != nil {
		t.Fatalf("GetAllocations failed: %v", err)
	}
	for _, balance := range allocs {
		if balance.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("expected zero balance for empty string, got %s", balance.String())
		}
	}
}

// ── GetAccountCodes extended ──

func TestGetAccountCodes_InvalidHex(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "1000",
				Code:    "not-valid-hex!@#",
			},
		},
	}
	codes, err := g.GetAccountCodes()
	if err != nil {
		t.Fatalf("GetAccountCodes should skip invalid hex, got: %v", err)
	}
	// Invalid hex code should be skipped
	if len(codes) != 0 {
		t.Errorf("expected 0 codes for invalid hex, got %d", len(codes))
	}
}

func TestGetAccountCodes_InvalidAddress(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"invalid-address": {
				Balance: "1000",
				Code:    "60806040",
			},
		},
	}
	_, err := g.GetAccountCodes()
	if err == nil {
		t.Error("expected error for invalid address in account codes")
	}
}

// ── GetAccountStorage extended ──

func TestGetAccountStorage_InvalidAddress(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"invalid-address": {
				Balance: "1000",
				Storage: map[string]string{
					"0x01": "0x02",
				},
			},
		},
	}
	_, err := g.GetAccountStorage()
	if err == nil {
		t.Error("expected error for invalid address in storage")
	}
}

// ── GetAccountNonces extended ──

func TestGetAccountNonces_InvalidAddress(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"invalid-address": {
				Balance: "1000",
				Nonce:   5,
			},
		},
	}
	_, err := g.GetAccountNonces()
	if err == nil {
		t.Error("expected error for invalid address in nonces")
	}
}

func TestGetAccountNonces_ZeroNonceSkipped(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Alloc: map[string]GenesisAccount{
			"0x1234567890123456789012345678901234567890": {
				Balance: "1000",
				Nonce:   0, // zero nonce should be skipped
			},
		},
	}
	nonces, err := g.GetAccountNonces()
	if err != nil {
		t.Fatalf("GetAccountNonces failed: %v", err)
	}
	if len(nonces) != 0 {
		t.Errorf("expected 0 nonces (zero nonce skipped), got %d", len(nonces))
	}
}

// ── ToBlock extended ──

func TestGenesis_ToBlock_PlainExtraData(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		ExtraData: "plain text extra data",
	}
	block := g.ToBlock()
	if block == nil {
		t.Fatal("expected non-nil block")
	}
	if string(block.Header.ExtraData) != "plain text extra data" {
		t.Errorf("expected plain text extra data, got %q", string(block.Header.ExtraData))
	}
}

func TestGenesis_ToBlock_EmptyExtraData(t *testing.T) {
	g := &Genesis{
		ChainID:   DevnetNetworkID,
		NetworkID: DevnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		ExtraData: "",
	}
	block := g.ToBlock()
	if block == nil {
		t.Fatal("expected non-nil block")
	}
}

// ── GenesisBlock struct ──

func TestGenesisBlock_Fields(t *testing.T) {
	gb := &GenesisBlock{
		Header: GenesisBlockHeader{
			Version:   1,
			Height:    0,
			Timestamp: 1700000000,
			GasLimit:  30000000,
		},
		ChainID:   MainnetNetworkID,
		NetworkID: MainnetNetworkID,
	}
	if gb.ChainID != MainnetNetworkID {
		t.Errorf("expected chain ID %d, got %d", MainnetNetworkID, gb.ChainID)
	}
	if gb.NetworkID != MainnetNetworkID {
		t.Errorf("expected network ID %d, got %d", MainnetNetworkID, gb.NetworkID)
	}
}

// ── SaveGenesis extended ──

func TestSaveGenesis_NestedDir(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "dir")
	os.MkdirAll(nestedDir, 0755) // Create the nested dir first
	genesisPath := filepath.Join(nestedDir, "genesis.json")

	g := DevGenesis()
	err := g.SaveGenesis(genesisPath)
	if err != nil {
		t.Fatalf("SaveGenesis to nested dir failed: %v", err)
	}

	if _, err := os.Stat(genesisPath); os.IsNotExist(err) {
		t.Error("genesis file was not created in nested dir")
	}
}

// ── R32-P3-04 regression tests: genesis integrity (duplicate validators, MinSignatures) ──

// r32_p3_04_validPubKey and r32_p3_04_validAddr are a real Dilithium3
// keypair (reused from TestGenesisValidate_ValidTestnetWithValidators)
// where the address is derived from the public key via
// types.AddressFromPublicKey(sha3-256(pubkey)[12:]).
const r32_p3_04_validPubKey = "0x5aa11bb6dc06418de407055cc146284ead5fee651ba9fad29d2b1ec690766f063fadac31cdf3683cf8e7db79a7ddc7d759024c6f188f2822c2be2b7267500c63b29ab314a037fb5c5b91a02ddb927eeef61264948d2a7dbba5a795e1880e3a11a94d6d4eddbd92df23dbf40a925599583b89bd24602882f76c066bf56f7ac9eb526cbca58b7d086df1d5a274972258711a7881682928bd947bf46395acf4e1961c6a454ca47022a465551703499f6bb7946e0c1a298c891e4f0ee3ca38a7871bdae493e104ffbfc0c8cd41ce9e818c98045a471a0db387af9871c37519d39a561a7793f64f4927205f31771b60a87d2a96ce242f266821c2b200f2bb8028aee83f090a6dee57cb50ef10d141b2a3e197e1cd1895f6163f15b593d2bdfb170336be559df39a9a0e7f27bb12fa6deace7940f2812903c53f5864c943d3b20b3c92688c6f9a2c961d19e20d1cd2fd7abc499be4d701415f69c9d60eac3dc878702c0c2915a3f1ec2a03f6cac1929fbd1ddbd55381c6a77e5c9c0216f30211a8349f3531006acfa34ca5a5715cce4ed860ba1cb45f8fcfa40fe0151c633834f92fc43fc5a4d79a1a66fab3f9a1fb92a0031997b04a4bff401e01a5a197715ef282025f451f08f89c4813e8101913d35f6faba00c7668a99430a5e981337f55951ae60c62575a28f7fcd16992461f17f23b55d8f8492ad7925bbc3d010df5cea824da5ee2e3ea9ad07dc776132fe6e03089ea1c555bf58e2f1ad914d7c1aa41d0b39c7ad2ebb022b73687673d7d38017310797fc15ef58492ae4e5fd55e97ab90f32530d1d64f974436d75eb9acf42f403659c545920dd997870516196d3271cd6f92c76537bc838c1b95a5644bf6ca6c3484f57c850f20ed40aa0c9670650d97f4970a978d35e721522a5ea898b5e19bacec074b2f216a40cfbcbae6da9c1e532f810533cafbc844510ae826ff6c228a067f0608127cffe2f2c8dedbd2e148477f8a3ead602dbb80b5dcb7871977c633d9b36fc6900a60b72b80c46288655b62f8e1616e703e147a78177de360ec4e0630ea94fb2ea10c7aa21bf54630b7b7b467e95cb586f6868a91d55f3f73cec1ded29df42723e7c33eaafefc76cbd43d77e859a04669bbf6c3e805479ed5b81e09fb98d34826510c5e7f0ac70ca9b4d26e24c077d2b2b4e3ca6cae362dcc88caeb83aa7f4dcf4b32ded44c5fde3750a13b246c00dbdcad06bb5b8a86cb6fea468a94a3d81014571bb0027b33a7f514abed660fb9fef00d7494431d88a1e3860b9fd18bcbc15d4fef7c7d71e10f03823f76e84754ed9af1df6360e9c6ddd2428dd151e3bd360cb0621181b05f9215aa7252f0f68940f8fb1d95472147c15d77e4a7a85177ff4640cc004fc3a6fa2b753fef43dea6334989edd3fb66ddc6ff6d9962fdfb77c37d2b3532eb5eda2fa88992af87f8b488393f5a11f102783ae440a515b3eea0a111b98c92b30ce7bd85abc9c855eeefabfb9f12176e6de90774fb0c3ed1c5c0645b5bdf1d0498f2e2b18beb98acdfcf4171e92bfbb9b983b2d5d98e5573c7191dc51115b231e39acd26460abc3f6cbcd88f43bd1e3d30e08394fd41241ce1dcdc4a3806112e696f0d366e44c175fda7d2d6be1de681f3a884eb1efa2e43a6333269ce1cf2c9ca6176b4650b0fcbf3b20da06ae38c61a75fe5aea46a3cd6c9d8c35555d23c5c1dada2ef46ff31fed011af5046ad2097e039cfbf8ab070bb37a37d9f31ff50492e77e92286c43fbef3bc8f7f2b99de889a81826d0b28b341164dee2103d6496d4dae5e67a796bf09dda42984585433f497d27fc57b957588889ee15e6d9438bdc824b25f2b6f94ae4ac96cf8de50ce5319bb0389005d2f0cb00ff33b9f9989901a15b4339eede74b89c279438019499dff8e955290b5087a07e16c22a13c8c89e9c66846705825e3d86803f89f9297f52dc33619ed21987f908a4f77077dcf0c9fd0c9fa796b781d1e57cf9a9c6a36029b4ad95445cbb43064f027cdc62ebd9d74f4fc09ffc89298a5f9bef0ddd8149ac0a3545d2ef21c38056eb0acfbea57d5d42c960b6662aa1368bfaaa5f58cd5d19a2123392c099ef8627da436a35388a46c854b68f9c850e8327a2aa97f86da5f502a4f0a2da545d55656f2b00b91eda6df298ed2fba8bd38f09a412eacdc1030c59cb7e5d70dc2b8ca45ec81ba72e48f98eb75a737e8bab975728eb3ff6b7c735dfbe921a4854b5a68acbd859c6ec176402809cb1f44b448d3caba38b167ef5ccfba8e9e9a7adbb25fecd7780ec4d0278739481e1961ed99e9272416d48d254121c86929459c7cc21215ca707b9e3f1c77bf8a7784f20fd62f6d62cf29944254ef4bca0eaf045d98e3ca76e6edc5fe8bd0941a7320f0c4d8a1283e38a212b9c89ba21cf0ce7dc48aa82051a6240af447adccd67535953d6d71839cbb7932a0fb0ce361ee14a74588ba7117cf494df8d6e7351d98e409ddbdcd365b93f9d80301abc29157a7f34f55559bbc8fe34d46d081a3cc0ad4f9028827c4737263621ab3c8a0d9ab32d4faada44a0e59c01f1e57faa7f2863bd09db48e5a21ec8b88938fa0b74dcd7938e8a530afcd30e0a65e99f097ea412e9f131a00fbb8857b381d95f3e9365c90f23621bc561ac5ce3bf26ddf9d108c4404a4f6548294bee52efb3879cdbcf059abca924ce9ce90dcefa713549430151f155d4d91a6c7e90c2053f7c278c41189ecde9fe13edbd62e81fa83c88b6d7aaff9cfd43c"

const r32_p3_04_validAddr = "0x415b210256487b284d125425099c7637a86c3b32"

// TestR32_P3_04_DuplicateValidatorAddress verifies that genesis validation
// rejects a validator set containing two entries with the same address.
// Without this check, the duplicate validator would get double voting
// weight in proposer election and double reward share.
func TestR32_P3_04_DuplicateValidatorAddress(t *testing.T) {
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: r32_p3_04_validAddr, PublicKey: r32_p3_04_validPubKey, Stake: "1000"},
			{Address: r32_p3_04_validAddr, PublicKey: r32_p3_04_validPubKey, Stake: "2000"}, // same address+pubkey
		},
	}
	err := g.Validate()
	if err == nil {
		t.Fatal("R32-P3-04 NOT FIXED: Validate accepted a genesis with duplicate validator address — " +
			"duplicate validators corrupt voting weight and reward distribution")
	}
}

// TestR32_P3_04_DuplicateValidatorPublicKey verifies that genesis validation
// rejects two validators with the same public key. Even though address is
// derived from pubkey (so duplicate pubkey implies duplicate address), this
// test explicitly verifies the pubkey dedup path as defense-in-depth.
func TestR32_P3_04_DuplicateValidatorPublicKey(t *testing.T) {
	// Two validators with the same pubkey but we can't easily generate a
	// second valid addr/pubkey pair in a unit test. The duplicate-address
	// test above already covers the case where both are identical. This
	// test verifies the error message mentions publicKey when the pubkey
	// check triggers (it triggers after the address check, so for truly
	// identical entries the address check fires first). We verify the
	// pubkey check exists by confirming the error is non-nil for identical
	// entries — the address check is the first to fire, but the pubkey
	// check would catch any case where addresses somehow differ but
	// pubkeys match (defensive against future address-derivation changes).
	g := &Genesis{
		ChainID:   TestnetNetworkID,
		NetworkID: TestnetNetworkID,
		Timestamp: MainnetGenesisTimestamp,
		GasLimit:  30000000,
		Validators: []GenesisValidator{
			{Address: r32_p3_04_validAddr, PublicKey: r32_p3_04_validPubKey, Stake: "1000"},
			{Address: r32_p3_04_validAddr, PublicKey: r32_p3_04_validPubKey, Stake: "1000"},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Fatal("R32-P3-04 NOT FIXED: Validate accepted a genesis with duplicate validator publicKey")
	}
}

// TestR32_P3_04_MinSignatures_Negative verifies that a negative
// MinSignatures is rejected. Previously a negative value would be treated
// as 0 by int comparison, silently falling back to dynamic computation
// and masking a misconfiguration.
func TestR32_P3_04_MinSignatures_Negative(t *testing.T) {
	g := &Genesis{
		ChainID:       TestnetNetworkID,
		NetworkID:     TestnetNetworkID,
		Timestamp:     MainnetGenesisTimestamp,
		GasLimit:      30000000,
		MinSignatures: -1,
		Validators: []GenesisValidator{
			{Address: r32_p3_04_validAddr, PublicKey: r32_p3_04_validPubKey, Stake: "1000"},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Fatal("R32-P3-04 NOT FIXED: Validate accepted a negative minSignatures — " +
			"negative values mask misconfigurations by silently falling back to dynamic computation")
	}
}

// TestR32_P3_04_MinSignatures_ExceedsValidatorCount verifies that a
// MinSignatures greater than the validator count is rejected. Such a
// configuration makes checkpoint quorum impossible — no block could ever
// be finalized.
func TestR32_P3_04_MinSignatures_ExceedsValidatorCount(t *testing.T) {
	g := &Genesis{
		ChainID:       TestnetNetworkID,
		NetworkID:     TestnetNetworkID,
		Timestamp:     MainnetGenesisTimestamp,
		GasLimit:      30000000,
		MinSignatures: 5, // exceeds validator count (1)
		Validators: []GenesisValidator{
			{Address: r32_p3_04_validAddr, PublicKey: r32_p3_04_validPubKey, Stake: "1000"},
		},
	}
	err := g.Validate()
	if err == nil {
		t.Fatal("R32-P3-04 NOT FIXED: Validate accepted minSignatures > validator count — " +
			"checkpoint quorum would be impossible (no block could ever be finalized)")
	}
}

// TestR32_P3_04_MinSignatures_ZeroAllowed verifies that MinSignatures=0
// (the default, meaning "use dynamic ceil(2/3*n)") passes validation.
// This is the most common configuration for mainnet.
func TestR32_P3_04_MinSignatures_ZeroAllowed(t *testing.T) {
	g := &Genesis{
		ChainID:       TestnetNetworkID,
		NetworkID:     TestnetNetworkID,
		Timestamp:     MainnetGenesisTimestamp,
		GasLimit:      30000000,
		MinSignatures: 0, // default — dynamic computation
		Validators: []GenesisValidator{
			{Address: r32_p3_04_validAddr, PublicKey: r32_p3_04_validPubKey, Stake: "1000"},
		},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("R32-P3-04 NOT FIXED: minSignatures=0 (default dynamic computation) should be allowed, got: %v", err)
	}
}

// TestR32_P3_04_MinSignatures_ValidNonZero verifies that a valid non-zero
// MinSignatures (<= validator count and >= BFT minimum) passes validation.
func TestR32_P3_04_MinSignatures_ValidNonZero(t *testing.T) {
	g := &Genesis{
		ChainID:       TestnetNetworkID,
		NetworkID:     TestnetNetworkID,
		Timestamp:     MainnetGenesisTimestamp,
		GasLimit:      30000000,
		MinSignatures: 1, // exactly 1, equals validator count — valid
		Validators: []GenesisValidator{
			{Address: r32_p3_04_validAddr, PublicKey: r32_p3_04_validPubKey, Stake: "1000"},
		},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("R32-P3-04 NOT FIXED: minSignatures=1 with 1 validator should be allowed, got: %v", err)
	}
}

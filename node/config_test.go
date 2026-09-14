// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Config tests ──

func TestDefaultConfig_Fields(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Name != "qau-node" {
		t.Errorf("expected name 'qau-node', got '%s'", cfg.Name)
	}
	if cfg.NetworkID != MainnetNetworkID {
		t.Errorf("expected network ID %d, got %d", MainnetNetworkID, cfg.NetworkID)
	}
	if cfg.RPCAddr != "127.0.0.1:8545" {
		t.Errorf("expected RPC addr '127.0.0.1:8545', got '%s'", cfg.RPCAddr)
	}
	if cfg.MaxGasLimit != 30000000 {
		t.Errorf("expected max gas limit 30000000, got %d", cfg.MaxGasLimit)
	}
	if cfg.CacheSize != 512 {
		t.Errorf("expected cache size 512, got %d", cfg.CacheSize)
	}
}

func TestDevConfig_Fields(t *testing.T) {
	cfg := DevConfig()
	if cfg.NetworkID != DevnetNetworkID {
		t.Errorf("expected network ID %d, got %d", DevnetNetworkID, cfg.NetworkID)
	}
	if !cfg.DevMode {
		t.Error("expected dev mode to be true")
	}
	if cfg.BlockInterval != 3 {
		t.Errorf("expected block interval 3, got %d", cfg.BlockInterval)
	}
	if !cfg.DevAutoUnlockAccounts {
		t.Error("expected auto unlock accounts to be true in dev config")
	}
}

func TestTestnetConfig_Fields(t *testing.T) {
	cfg := TestnetConfig()
	if cfg.NetworkID != TestnetNetworkID {
		t.Errorf("expected network ID %d, got %d", TestnetNetworkID, cfg.NetworkID)
	}
}

func TestNetworkIDs(t *testing.T) {
	if MainnetNetworkID != 1668 {
		t.Errorf("expected mainnet ID 1668, got %d", MainnetNetworkID)
	}
	if TestnetNetworkID != 1669 {
		t.Errorf("expected testnet ID 1669, got %d", TestnetNetworkID)
	}
	if DevnetNetworkID != 1333 {
		t.Errorf("expected devnet ID 1333, got %d", DevnetNetworkID)
	}
}

// ── Config Validate tests ──

func TestConfigValidate_DevModeOnMainnet(t *testing.T) {
	cfg := &Config{
		DevMode:   true,
		Network:   NetworkMainnet,
		NetworkID: MainnetNetworkID,
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for dev mode on mainnet")
	}
}

// TestConfigValidate_DAOnMainnet verifies the DA- mainnet hard guard:
// Danksharding/DA committee must NOT be enabled on mainnet because KZG
// commitments and opening proofs are hash placeholders, not real polynomial
// commitments. Enabling DA on mainnet would give false availability guarantees.
// AUDIT (2026) DA-FIX (CRITICAL)
func TestConfigValidate_DAOnMainnet(t *testing.T) {
	cfg := &Config{
		Danksharding: DankshardingNodeConfig{Enabled: true},
		NetworkID:    MainnetNetworkID,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for danksharding enabled on mainnet (DA-)")
	}
	if !strings.Contains(err.Error(), "DA-") {
		t.Errorf("error should reference DA-, got: %v", err)
	}
	if !strings.Contains(err.Error(), "mainnet") {
		t.Errorf("error should mention mainnet, got: %v", err)
	}
}

// TestConfigValidate_DAOnTestnetAllowed verifies DA is allowed on testnet
// (the hard guard is mainnet-only — testnet/devnet can experiment with DA).
func TestConfigValidate_DAOnTestnetAllowed(t *testing.T) {
	cfg := &Config{
		Danksharding: DankshardingNodeConfig{Enabled: true},
		NetworkID:    TestnetNetworkID,
		DataDir:      t.TempDir(),
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("danksharding on testnet should be allowed, got: %v", err)
	}
}

// TestConfigValidate_DADisabledOnMainnetAllowed verifies that DA disabled on
// mainnet is the only valid mainnet DA configuration.
func TestConfigValidate_DADisabledOnMainnetAllowed(t *testing.T) {
	cfg := &Config{
		Danksharding: DankshardingNodeConfig{Enabled: false},
		NetworkID:    MainnetNetworkID,
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("danksharding disabled on mainnet should be allowed, got: %v", err)
	}
}

// TestConfigValidate_DAOnDevnetAllowed verifies DA is allowed on devnet.
func TestConfigValidate_DAOnDevnetAllowed(t *testing.T) {
	cfg := &Config{
		Danksharding: DankshardingNodeConfig{Enabled: true},
		NetworkID:    DevnetNetworkID,
		DataDir:      t.TempDir(),
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("danksharding on devnet should be allowed, got: %v", err)
	}
}

func TestConfigValidate_DevModeOnTestnet(t *testing.T) {
	cfg := &Config{
		DevMode:   true,
		NetworkID: TestnetNetworkID,
		DataDir:   t.TempDir(),
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("dev mode on testnet should be allowed, got: %v", err)
	}
}

func TestConfigValidate_Defaults(t *testing.T) {
	cfg := &Config{
		NetworkID: TestnetNetworkID,
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	expectedDataDir, _ := filepath.Abs("./data")
	if cfg.DataDir != expectedDataDir {
		t.Errorf("expected default DataDir '%s', got '%s'", expectedDataDir, cfg.DataDir)
	}
	if cfg.MaxPeers != 50 {
		t.Errorf("expected default MaxPeers 50, got %d", cfg.MaxPeers)
	}
	if cfg.CacheSize != 512 {
		t.Errorf("expected default CacheSize 512, got %d", cfg.CacheSize)
	}
	if cfg.MaxGasLimit != 30000000 {
		t.Errorf("expected default MaxGasLimit 30000000, got %d", cfg.MaxGasLimit)
	}
}

func TestConfigValidate_ZeroNetworkID(t *testing.T) {
	cfg := &Config{
		NetworkID: 0,
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.NetworkID != MainnetNetworkID {
		t.Errorf("expected NetworkID to default to %d, got %d", MainnetNetworkID, cfg.NetworkID)
	}
}

func TestConfigValidate_NodeDBPath(t *testing.T) {
	cfg := &Config{
		DataDir:   "/tmp/test-data",
		NetworkID: TestnetNetworkID,
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	absDataDir, _ := filepath.Abs("/tmp/test-data")
	if cfg.NodeDBPath != filepath.Join(absDataDir, "nodes") {
		t.Errorf("expected NodeDBPath to be auto-derived, got '%s'", cfg.NodeDBPath)
	}
}

func TestConfigValidate_KeyRotation(t *testing.T) {
	cfg := &Config{
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.KeyRotation.RotationInterval != 30 {
		t.Errorf("expected default rotation interval 30, got %d", cfg.KeyRotation.RotationInterval)
	}
	if cfg.KeyRotation.MaxKeyAge != 90 {
		t.Errorf("expected default max key age 90, got %d", cfg.KeyRotation.MaxKeyAge)
	}
}

func TestConfigValidate_TLSCertRotation(t *testing.T) {
	cfg := &Config{
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.TLSCertRotation.Organization != "Quantaureum" {
		t.Errorf("expected default organization 'Quantaureum', got '%s'", cfg.TLSCertRotation.Organization)
	}
	if cfg.TLSCertRotation.ValidityDuration != 365 {
		t.Errorf("expected default validity duration 365, got %d", cfg.TLSCertRotation.ValidityDuration)
	}
}

// ── ResolveNetworkConfig tests ──

func TestResolveNetworkConfig_Dev(t *testing.T) {
	cfg := &Config{Network: NetworkDev}
	ResolveNetworkConfig(cfg)
	if cfg.NetworkID != DevnetNetworkID {
		t.Errorf("expected devnet ID %d, got %d", DevnetNetworkID, cfg.NetworkID)
	}
	if !cfg.DevMode {
		t.Error("expected dev mode")
	}
	if !cfg.DevBlocks {
		t.Error("expected dev blocks")
	}
	if cfg.BlockInterval != 3 {
		t.Errorf("expected block interval 3, got %d", cfg.BlockInterval)
	}
}

func TestResolveNetworkConfig_Testnet(t *testing.T) {
	cfg := &Config{Network: NetworkTestnet}
	ResolveNetworkConfig(cfg)
	if cfg.NetworkID != TestnetNetworkID {
		t.Errorf("expected testnet ID %d, got %d", TestnetNetworkID, cfg.NetworkID)
	}
	if cfg.DevMode {
		t.Error("testnet must not enable dev mode")
	}
}

func TestResolveNetworkConfig_Mainnet(t *testing.T) {
	cfg := &Config{Network: NetworkMainnet}
	ResolveNetworkConfig(cfg)
	if cfg.NetworkID != MainnetNetworkID {
		t.Errorf("expected mainnet ID %d, got %d", MainnetNetworkID, cfg.NetworkID)
	}
	if cfg.DevMode {
		t.Error("mainnet should not have dev mode")
	}
}

func TestResolveNetworkConfig_Custom(t *testing.T) {
	cfg := &Config{Network: "custom"}
	ResolveNetworkConfig(cfg)
	// Custom network should not change anything
}

// ── SaveConfig / LoadConfig tests ──

func TestSaveAndLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	cfg := DevConfig()
	cfg.DataDir = tmpDir

	err := cfg.SaveConfig(cfgPath)
	if err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.Name != cfg.Name {
		t.Errorf("expected name '%s', got '%s'", cfg.Name, loaded.Name)
	}
	if loaded.NetworkID != cfg.NetworkID {
		t.Errorf("expected network ID %d, got %d", cfg.NetworkID, loaded.NetworkID)
	}
}

func TestLoadConfig_Nonexistent(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(cfgPath, []byte("not-json"), 0644)

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// ── Config JSON serialization ──

func TestConfig_JSONSerialization(t *testing.T) {
	cfg := DefaultConfig()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	var loaded Config
	err = json.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}
	if loaded.Name != cfg.Name {
		t.Errorf("expected name '%s', got '%s'", cfg.Name, loaded.Name)
	}
}

// ── Sub-config types ──

func TestParallelExecutionConfig(t *testing.T) {
	cfg := ParallelExecutionConfig{
		Enabled:    true,
		NumWorkers: 4,
		MaxRetries: 3,
	}
	if !cfg.Enabled {
		t.Error("expected enabled")
	}
}

func TestCacheOptConfig(t *testing.T) {
	cfg := CacheOptConfig{
		L1MaxSize:   1024,
		L1MaxMemory: 64 * 1024 * 1024,
		TTLSeconds:  300,
	}
	if cfg.L1MaxSize != 1024 {
		t.Error("unexpected L1MaxSize")
	}
}

func TestPruningOptConfig(t *testing.T) {
	cfg := PruningOptConfig{
		Enabled:         true,
		RetentionBlocks: 1000,
		BatchSize:       100,
	}
	if !cfg.Enabled {
		t.Error("expected enabled")
	}
}

func TestKeyRotationConfig(t *testing.T) {
	cfg := KeyRotationConfig{
		Enabled:          true,
		KeyDir:           "./keys",
		RotationInterval: 30,
		MaxKeyAge:        90,
	}
	if !cfg.Enabled {
		t.Error("expected enabled")
	}
}

func TestTLSCertRotationConfig(t *testing.T) {
	cfg := TLSCertRotationConfig{
		Enabled:          true,
		CertDir:          "./certs",
		Organization:     "Quantaureum",
		CommonName:       "node.quantaureum.local",
		ValidityDuration: 365,
		RenewalThreshold: 30,
	}
	if !cfg.Enabled {
		t.Error("expected enabled")
	}
}

func TestAlertingNodeConfig(t *testing.T) {
	cfg := AlertingNodeConfig{
		Enabled:    true,
		ConfigFile: "configs/alerting.json",
	}
	if !cfg.Enabled {
		t.Error("expected enabled")
	}
}

// ── Network name constants ──

func TestNetworkNames(t *testing.T) {
	if NetworkDev != "dev" {
		t.Errorf("expected 'dev', got '%s'", NetworkDev)
	}
	if NetworkTestnet != "testnet" {
		t.Errorf("expected 'testnet', got '%s'", NetworkTestnet)
	}
	if NetworkMainnet != "mainnet" {
		t.Errorf("expected 'mainnet', got '%s'", NetworkMainnet)
	}
}

// ── Extended Config Validate tests ──

func TestConfigValidate_NegativeMaxPeers(t *testing.T) {
	cfg := &Config{
		NetworkID: TestnetNetworkID,
		DataDir:   t.TempDir(),
		MaxPeers:  -1,
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.MaxPeers != 50 {
		t.Errorf("expected MaxPeers to default to 50, got %d", cfg.MaxPeers)
	}
}

func TestConfigValidate_ZeroCacheSize(t *testing.T) {
	cfg := &Config{
		NetworkID: TestnetNetworkID,
		DataDir:   t.TempDir(),
		CacheSize: 0,
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.CacheSize != 512 {
		t.Errorf("expected CacheSize to default to 512, got %d", cfg.CacheSize)
	}
}

func TestConfigValidate_ZeroMaxGasLimit(t *testing.T) {
	cfg := &Config{
		NetworkID:   TestnetNetworkID,
		DataDir:     t.TempDir(),
		MaxGasLimit: 0,
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.MaxGasLimit != 30000000 {
		t.Errorf("expected MaxGasLimit to default to 30000000, got %d", cfg.MaxGasLimit)
	}
}

func TestConfigValidate_EmptyDataDir(t *testing.T) {
	cfg := &Config{
		NetworkID: TestnetNetworkID,
		DataDir:   "",
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	expectedDataDir, _ := filepath.Abs("./data")
	if cfg.DataDir != expectedDataDir {
		t.Errorf("expected default DataDir '%s', got '%s'", expectedDataDir, cfg.DataDir)
	}
}

// TestConfigValidate_CORS_WildcardRejectedOnMainnet (P2P-R11-M04).
// Verifies that "*" is rejected on mainnet at config-validation time.
// The runtime CORS handler silently replaces "*" with mainnetDefaultOrigins,
// but a validation-time rejection catches operator misconfiguration at
// startup instead of papering over it.
func TestConfigValidate_CORS_WildcardRejectedOnMainnet(t *testing.T) {
	cfg := &Config{
		NetworkID:      MainnetNetworkID,
		DataDir:        t.TempDir(),
		AllowedOrigins: []string{"*"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate with wildcard CORS on mainnet should fail, got nil")
	}
	if !strings.Contains(err.Error(), "allowedOrigins") || !strings.Contains(err.Error(), "*") {
		t.Errorf("error message should mention allowedOrigins and *, got: %v", err)
	}
}

// TestConfigValidate_CORS_WildcardRejectedOnTestnet (P2P-R11-M04).
// Verifies that "*" is also rejected on testnet (the runtime path only
// substituted on mainnet, so testnet had no protection before this fix).
func TestConfigValidate_CORS_WildcardRejectedOnTestnet(t *testing.T) {
	cfg := &Config{
		NetworkID:      TestnetNetworkID,
		DataDir:        t.TempDir(),
		AllowedOrigins: []string{"https://example.com", "*"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate with wildcard CORS on testnet should fail, got nil")
	}
}

// TestConfigValidate_CORS_WildcardAllowedOnDevnet (P2P-R11-M04).
// Verifies that "*" is allowed on devnet for local-development DX.
// Devnet is isolated from mainnet state and tokens have no value, so the
// CSRF risk is acceptable for the convenience of arbitrary localhost ports.
func TestConfigValidate_CORS_WildcardAllowedOnDevnet(t *testing.T) {
	cfg := &Config{
		NetworkID:      DevnetNetworkID,
		DataDir:        t.TempDir(),
		AllowedOrigins: []string{"*"},
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate with wildcard CORS on devnet should succeed, got: %v", err)
	}
}

// TestConfigValidate_CORS_ExplicitOriginsAllowed (P2P-R11-M04).
// Verifies that explicitly-listed origins are accepted on all networks.
func TestConfigValidate_CORS_ExplicitOriginsAllowed(t *testing.T) {
	for _, networkID := range []uint64{MainnetNetworkID, TestnetNetworkID, DevnetNetworkID} {
		cfg := &Config{
			NetworkID:      networkID,
			DataDir:        t.TempDir(),
			AllowedOrigins: []string{"https://quantaureum.com", "https://lzadmin.quantaureum.com"},
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Validate with explicit origins on networkId=%d should succeed, got: %v", networkID, err)
		}
	}
}

func TestConfigValidate_KeyRotationBackupDir(t *testing.T) {
	cfg := &Config{
		NetworkID: TestnetNetworkID,
		DataDir:   t.TempDir(),
		KeyRotation: KeyRotationConfig{
			BackupEnabled: true,
			BackupDir:     "", // should auto-derive
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.KeyRotation.BackupDir == "" {
		t.Error("expected auto-derived backup dir for key rotation")
	}
}

func TestConfigValidate_TLSCertRotationBackupDir(t *testing.T) {
	cfg := &Config{
		NetworkID: TestnetNetworkID,
		DataDir:   t.TempDir(),
		TLSCertRotation: TLSCertRotationConfig{
			BackupEnabled: true,
			BackupDir:     "", // should auto-derive
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.TLSCertRotation.BackupDir == "" {
		t.Error("expected auto-derived backup dir for TLS cert rotation")
	}
}

func TestConfigValidate_TLSCertRotationDefaults(t *testing.T) {
	cfg := &Config{
		NetworkID: TestnetNetworkID,
		DataDir:   t.TempDir(),
		TLSCertRotation: TLSCertRotationConfig{
			ValidityDuration: 0,
			RenewalThreshold: 0,
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.TLSCertRotation.ValidityDuration != 365 {
		t.Errorf("expected default ValidityDuration 365, got %d", cfg.TLSCertRotation.ValidityDuration)
	}
	if cfg.TLSCertRotation.RenewalThreshold != 30 {
		t.Errorf("expected default RenewalThreshold 30, got %d", cfg.TLSCertRotation.RenewalThreshold)
	}
}

// ── ResolveNetworkConfig extended ──

func TestResolveNetworkConfig_DevGenesisFile(t *testing.T) {
	cfg := &Config{Network: NetworkDev}
	ResolveNetworkConfig(cfg)
	if cfg.GenesisFile != "" {
		t.Errorf("expected built-in dev genesis, got '%s'", cfg.GenesisFile)
	}
}

func TestResolveNetworkConfig_TestnetGenesisFile(t *testing.T) {
	cfg := &Config{Network: NetworkTestnet}
	ResolveNetworkConfig(cfg)
	if cfg.GenesisFile != "" {
		t.Errorf("expected built-in testnet genesis, got '%s'", cfg.GenesisFile)
	}
}

func TestResolveNetworkConfig_MainnetGenesisFile(t *testing.T) {
	cfg := &Config{Network: NetworkMainnet}
	ResolveNetworkConfig(cfg)
	if cfg.GenesisFile != "" {
		t.Errorf("expected built-in mainnet genesis, got '%s'", cfg.GenesisFile)
	}
}

func TestResolveNetworkConfig_DevPreservesExistingGenesisFile(t *testing.T) {
	cfg := &Config{Network: NetworkDev, GenesisFile: "custom.json"}
	ResolveNetworkConfig(cfg)
	if cfg.GenesisFile != "custom.json" {
		t.Errorf("expected custom genesis file to be preserved, got '%s'", cfg.GenesisFile)
	}
}

func TestResolveNetworkConfig_TestnetBlockInterval(t *testing.T) {
	cfg := &Config{Network: NetworkTestnet}
	ResolveNetworkConfig(cfg)
	if cfg.BlockInterval != 12 {
		t.Errorf("expected testnet block interval 12, got %d", cfg.BlockInterval)
	}
}

func TestResolveNetworkConfig_DevAutoUnlock(t *testing.T) {
	cfg := &Config{Network: NetworkDev}
	ResolveNetworkConfig(cfg)
	if !cfg.DevAutoUnlockAccounts {
		t.Error("expected DevAutoUnlockAccounts to be true for dev network")
	}
}

func TestResolveNetworkConfig_TestnetAutoUnlock(t *testing.T) {
	// SECURITY (audit 2026-06-14, M6): testnet must NOT enable
	// DevAutoUnlockAccounts. Auto-unlock keeps keys in memory without a
	// password, which is unsafe on a publicly reachable testnet. DevMode
	// is also disabled; only NetworkDev enables development behavior.
	cfg := &Config{Network: NetworkTestnet}
	ResolveNetworkConfig(cfg)
	if cfg.DevAutoUnlockAccounts {
		t.Error("DevAutoUnlockAccounts must be false for testnet (M6 security fix)")
	}
	if cfg.DevMode {
		t.Error("DevMode must be false for testnet")
	}

	// Only the local dev network enables auto-unlock.
	devCfg := &Config{Network: NetworkDev}
	ResolveNetworkConfig(devCfg)
	if !devCfg.DevAutoUnlockAccounts {
		t.Error("expected DevAutoUnlockAccounts to be true for dev network")
	}
}

func TestResolveNetworkConfig_DevLogLevel(t *testing.T) {
	cfg := &Config{Network: NetworkDev}
	ResolveNetworkConfig(cfg)
	if cfg.LogLevel != "debug" {
		t.Errorf("expected debug log level for dev, got '%s'", cfg.LogLevel)
	}
}

func TestResolveNetworkConfig_TestnetLogLevel(t *testing.T) {
	cfg := &Config{Network: NetworkTestnet}
	ResolveNetworkConfig(cfg)
	if cfg.LogLevel != "debug" {
		t.Errorf("expected debug log level for testnet, got '%s'", cfg.LogLevel)
	}
}

// ── SaveConfig extended ──

func TestSaveConfig_NestedDir(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "nested", "dir", "config.json")

	cfg := DevConfig()
	cfg.DataDir = tmpDir

	err := cfg.SaveConfig(cfgPath)
	if err != nil {
		t.Fatalf("SaveConfig to nested dir failed: %v", err)
	}

	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		t.Error("config file was not created in nested dir")
	}
}

// ── LoadConfig with password file ──

func TestLoadConfig_WithPasswordFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create password file
	pwdPath := filepath.Join(tmpDir, "password.txt")
	os.WriteFile(pwdPath, []byte("my-secret-password\n"), 0600)

	// Create config file
	cfg := DevConfig()
	cfg.DataDir = tmpDir
	cfg.ValidatorPasswordFile = pwdPath
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg.SaveConfig(cfgPath)

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.ValidatorKeyPassword != "my-secret-password" {
		t.Errorf("expected password from file, got '%s'", loaded.ValidatorKeyPassword)
	}
}

func TestLoadConfig_WithEmptyPasswordFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create empty password file
	pwdPath := filepath.Join(tmpDir, "password.txt")
	os.WriteFile(pwdPath, []byte(""), 0600)

	// Create config file
	cfg := DevConfig()
	cfg.DataDir = tmpDir
	cfg.ValidatorPasswordFile = pwdPath
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg.SaveConfig(cfgPath)

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Error("expected error for empty password file")
	}
}

func TestLoadConfig_WithNonexistentPasswordFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create config file pointing to nonexistent password file
	cfg := DevConfig()
	cfg.DataDir = tmpDir
	cfg.ValidatorPasswordFile = "/nonexistent/password.txt"
	cfgPath := filepath.Join(tmpDir, "config.json")
	cfg.SaveConfig(cfgPath)

	_, err := LoadConfig(cfgPath)
	if err == nil {
		t.Error("expected error for nonexistent password file")
	}
}

// ── P1-5: DankshardingNodeConfig tests ──

// TestDefaultDankshardingNodeConfig_FailClosed verifies that the default DA
// config is disabled (fail-closed). Operators must explicitly opt in.
func TestDefaultDankshardingNodeConfig_FailClosed(t *testing.T) {
	cfg := DefaultDankshardingNodeConfig()
	if cfg.Enabled {
		t.Error("default DankshardingNodeConfig should be disabled (fail-closed)")
	}
}

// TestDefaultConfig_HasDankshardingDefault verifies that DefaultConfig()
// populates the Danksharding field with the fail-closed default.
func TestDefaultConfig_HasDankshardingDefault(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Danksharding.Enabled {
		t.Error("DefaultConfig Danksharding should be disabled by default")
	}
}

// TestLoadConfig_DankshardingDisabledByDefault verifies that a config file
// without a "danksharding" section results in DA disabled.
func TestLoadConfig_DankshardingDisabledByDefault(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := DevConfig()
	cfg.DataDir = tmpDir
	cfgPath := filepath.Join(tmpDir, "config.json")
	if err := cfg.SaveConfig(cfgPath); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.Danksharding.Enabled {
		t.Error("DA should be disabled when config file has no danksharding section")
	}
}

// TestLoadConfig_DankshardingEnabled verifies that a config file with
// "danksharding": {"enabled": true} correctly loads the DA config.
func TestLoadConfig_DankshardingEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	jsonData := `{
		"name": "test-node",
		"networkId": 1669,
		"dataDir": "` + strings.ReplaceAll(tmpDir, "\\", "\\\\") + `",
		"danksharding": {
			"enabled": true,
			"experimental": false,
			"committeeSize": 128,
			"subnetCount": 16
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(jsonData), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if !loaded.Danksharding.Enabled {
		t.Error("expected Danksharding.Enabled=true")
	}
	if loaded.Danksharding.Experimental {
		t.Error("expected Danksharding.Experimental=false")
	}
	if loaded.Danksharding.CommitteeSize != 128 {
		t.Errorf("expected CommitteeSize=128, got %d", loaded.Danksharding.CommitteeSize)
	}
	if loaded.Danksharding.SubnetCount != 16 {
		t.Errorf("expected SubnetCount=16, got %d", loaded.Danksharding.SubnetCount)
	}
}

// TestDankshardingNodeConfig_ToDankshardingConfig verifies the conversion to
// core.DankshardingConfig preserves all fields.
func TestDankshardingNodeConfig_ToDankshardingConfig(t *testing.T) {
	src := DankshardingNodeConfig{
		Enabled:        true,
		Experimental:   false,
		WarningMessage: "custom warning",
	}
	got := src.ToDankshardingConfig()
	if !got.Enabled {
		t.Error("Enabled not preserved")
	}
	if got.Experimental {
		t.Error("Experimental not preserved")
	}
	if got.WarningMessage != "custom warning" {
		t.Errorf("WarningMessage not preserved: got '%s'", got.WarningMessage)
	}
}

// TestDankshardingNodeConfig_ToDACommitteeConfig verifies the conversion to
// consensus.DACommitteeConfig preserves Enabled and CommitteeSize.
func TestDankshardingNodeConfig_ToDACommitteeConfig(t *testing.T) {
	src := DankshardingNodeConfig{
		Enabled:       true,
		CommitteeSize: 256,
	}
	got := src.ToDACommitteeConfig()
	if !got.Enabled {
		t.Error("Enabled not preserved")
	}
	if got.Size != 256 {
		t.Errorf("CommitteeSize not preserved: got %d", got.Size)
	}
}

// ── Config with all defaults ──

func TestDefaultConfig_AllFields(t *testing.T) {
	cfg := DefaultConfig()
	// Verify key defaults are set
	if cfg.ListenAddr != "127.0.0.1:9000" {
		t.Errorf("expected ListenAddr '127.0.0.1:9000', got '%s'", cfg.ListenAddr)
	}
	if cfg.RPCAddr != "127.0.0.1:8545" {
		t.Errorf("expected RPCAddr '127.0.0.1:8545', got '%s'", cfg.RPCAddr)
	}
	if cfg.WSAddr != "127.0.0.1:8546" {
		t.Errorf("expected WSAddr '127.0.0.1:8546', got '%s'", cfg.WSAddr)
	}
	if cfg.MetricsAddr != "127.0.0.1:9090" {
		t.Errorf("expected MetricsAddr '127.0.0.1:9090', got '%s'", cfg.MetricsAddr)
	}
	if cfg.ShutdownTimeout != 30 {
		t.Errorf("expected ShutdownTimeout 30, got %d", cfg.ShutdownTimeout)
	}
	// TSS-/ (2026-07-16): DefaultConfig() no longer sets TSS
	// threshold/totalShares because the default NetworkID is mainnet,
	// and mainnet requires pre-generated shares + distributed mode for
	// multi-share configs. TSS defaults are set in DevConfig() and
	// TestnetConfig() instead (trusted dealer DKG allowed on non-mainnet).
	if cfg.TSSThreshold != 0 {
		t.Errorf("expected TSSThreshold 0 (not set in DefaultConfig for mainnet safety), got %d", cfg.TSSThreshold)
	}
	if cfg.TSSTotalShares != 0 {
		t.Errorf("expected TSSTotalShares 0 (not set in DefaultConfig for mainnet safety), got %d", cfg.TSSTotalShares)
	}
}

// TestDevConfig_AllFields verifies that DevConfig sets TSS defaults
// (trusted dealer DKG is allowed on devnet).
func TestDevConfig_AllFields(t *testing.T) {
	cfg := DevConfig()
	if cfg.TSSThreshold != 2 {
		t.Errorf("expected DevConfig TSSThreshold 2, got %d", cfg.TSSThreshold)
	}
	if cfg.TSSTotalShares != 3 {
		t.Errorf("expected DevConfig TSSTotalShares 3, got %d", cfg.TSSTotalShares)
	}
}

// TestTestnetConfig_AllFields verifies that TestnetConfig sets TSS defaults
// (trusted dealer DKG is allowed on testnet).
func TestTestnetConfig_AllFields(t *testing.T) {
	cfg := TestnetConfig()
	if cfg.TSSThreshold != 2 {
		t.Errorf("expected TestnetConfig TSSThreshold 2, got %d", cfg.TSSThreshold)
	}
	if cfg.TSSTotalShares != 3 {
		t.Errorf("expected TestnetConfig TSSTotalShares 3, got %d", cfg.TSSTotalShares)
	}
}

// ── P1-6: ShardingNodeConfig tests ──

func TestDefaultShardingNodeConfig_Values(t *testing.T) {
	cfg := DefaultShardingNodeConfig()
	if cfg.MaxCount != 64 {
		t.Errorf("expected MaxCount 64, got %d", cfg.MaxCount)
	}
	if cfg.BlockSize != 1<<20 {
		t.Errorf("expected BlockSize %d (1MB), got %d", 1<<20, cfg.BlockSize)
	}
	if cfg.Interval != 12 {
		t.Errorf("expected Interval 12, got %d", cfg.Interval)
	}
	if cfg.MinValidators != 3 {
		t.Errorf("expected MinValidators 3, got %d", cfg.MinValidators)
	}
	if cfg.SlotResolverMode != "" {
		t.Errorf("expected SlotResolverMode empty (1:1), got %q", cfg.SlotResolverMode)
	}
}

func TestDefaultConfig_HasShardingDefault(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Sharding.MaxCount != 64 {
		t.Errorf("expected Sharding.MaxCount 64, got %d", cfg.Sharding.MaxCount)
	}
	if cfg.Sharding.MinValidators != 3 {
		t.Errorf("expected Sharding.MinValidators 3, got %d", cfg.Sharding.MinValidators)
	}
}

func TestShardingNodeConfig_EffectiveDefaults(t *testing.T) {
	// Zero-value config should fall back to documented defaults.
	cfg := ShardingNodeConfig{}
	if cfg.EffectiveMaxCount() != 64 {
		t.Errorf("expected effective MaxCount 64, got %d", cfg.EffectiveMaxCount())
	}
	if cfg.EffectiveBlockSize() != 1<<20 {
		t.Errorf("expected effective BlockSize %d, got %d", 1<<20, cfg.EffectiveBlockSize())
	}
	if cfg.EffectiveInterval() != 12 {
		t.Errorf("expected effective Interval 12, got %d", cfg.EffectiveInterval())
	}
	if cfg.EffectiveMinValidators() != 3 {
		t.Errorf("expected effective MinValidators 3, got %d", cfg.EffectiveMinValidators())
	}
}

func TestShardingNodeConfig_EffectiveOverrides(t *testing.T) {
	cfg := ShardingNodeConfig{
		MaxCount:      128,
		BlockSize:     2 << 20,
		Interval:      6,
		MinValidators: 5,
	}
	if cfg.EffectiveMaxCount() != 128 {
		t.Errorf("expected effective MaxCount 128, got %d", cfg.EffectiveMaxCount())
	}
	if cfg.EffectiveBlockSize() != 2<<20 {
		t.Errorf("expected effective BlockSize %d, got %d", 2<<20, cfg.EffectiveBlockSize())
	}
	if cfg.EffectiveInterval() != 6 {
		t.Errorf("expected effective Interval 6, got %d", cfg.EffectiveInterval())
	}
	if cfg.EffectiveMinValidators() != 5 {
		t.Errorf("expected effective MinValidators 5, got %d", cfg.EffectiveMinValidators())
	}
}

func TestLoadConfig_ShardingCustom(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	jsonData := `{
		"name": "test-node",
		"networkId": 1669,
		"dataDir": "` + strings.ReplaceAll(tmpDir, "\\", "\\\\") + `",
		"sharding": {
			"maxCount": 32,
			"blockSize": 524288,
			"interval": 6,
			"minValidators": 4,
			"slotResolverMode": "linear"
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(jsonData), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.Sharding.MaxCount != 32 {
		t.Errorf("expected MaxCount 32, got %d", loaded.Sharding.MaxCount)
	}
	if loaded.Sharding.BlockSize != 524288 {
		t.Errorf("expected BlockSize 524288, got %d", loaded.Sharding.BlockSize)
	}
	if loaded.Sharding.Interval != 6 {
		t.Errorf("expected Interval 6, got %d", loaded.Sharding.Interval)
	}
	if loaded.Sharding.MinValidators != 4 {
		t.Errorf("expected MinValidators 4, got %d", loaded.Sharding.MinValidators)
	}
	if loaded.Sharding.SlotResolverMode != "linear" {
		t.Errorf("expected SlotResolverMode 'linear', got %q", loaded.Sharding.SlotResolverMode)
	}
}

func TestLoadConfig_ShardingOmittedUsesDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	jsonData := `{
		"name": "test-node",
		"networkId": 1669,
		"dataDir": "` + strings.ReplaceAll(tmpDir, "\\", "\\\\") + `"
	}`
	if err := os.WriteFile(cfgPath, []byte(jsonData), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	// When "sharding" section is omitted, Go's json.Unmarshal leaves the
	// struct at its zero value. Effective* methods should still return
	// documented defaults.
	if loaded.Sharding.EffectiveMaxCount() != 64 {
		t.Errorf("expected effective MaxCount 64, got %d", loaded.Sharding.EffectiveMaxCount())
	}
	if loaded.Sharding.EffectiveMinValidators() != 3 {
		t.Errorf("expected effective MinValidators 3, got %d", loaded.Sharding.EffectiveMinValidators())
	}
}

func TestConfig_JSONSerialization_Sharding(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Sharding.MaxCount = 48
	cfg.Sharding.SlotResolverMode = "linear"
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}
	if loaded.Sharding.MaxCount != 48 {
		t.Errorf("expected MaxCount 48, got %d", loaded.Sharding.MaxCount)
	}
	if loaded.Sharding.SlotResolverMode != "linear" {
		t.Errorf("expected SlotResolverMode 'linear', got %q", loaded.Sharding.SlotResolverMode)
	}
}

// ── TSS- Trusted Dealer DKG mainnet hard guard ──
//
// AUDIT (2026) TSS-FIX (HIGH). The current DKG implementation
// (wallet/tss/qtd.GenerateDKGShares*) is NOT a real distributed DKG — it
// generates the COMPLETE Dilithium3 private key in a single process via
// mode3.NewKeyFromSeed before splitting. On mainnet, the node MUST NOT
// invoke the trusted dealer path at startup; it must import pre-generated
// shares via TSSKeyShareFile instead.

// TestConfigValidate_TSS_R5_03_TrustedDealerOnMainnetBlocked verifies the
// primary mainnet hard guard: when TSSKeyShareFile and TSSGroupKeyFile are
// both empty AND any TSS share/threshold is configured, mainnet MUST refuse
// to start. This prevents the node from falling through to GenerateKeyShares()
// at startup and running any runtime DKG (distributed or trusted-dealer).
//
// TSS- (2026-07-17): The error message now references TSS- (the
// current finding that supersedes TSS-). The guard condition is
// unchanged — mainnet must still import pre-generated shares.
func TestConfigValidate_TSS_R5_03_TrustedDealerOnMainnetBlocked(t *testing.T) {
	cfg := &Config{
		NetworkID:      MainnetNetworkID,
		TSSTotalShares: 3,
		TSSThreshold:   2,
		// TSSKeyShareFile and TSSGroupKeyFile intentionally empty.
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for runtime DKG on mainnet (TSS-)")
	}
	// TSS- supersedes TSS-; accept either prefix for forward/backward compat.
	if !strings.Contains(err.Error(), "TSS-") && !strings.Contains(err.Error(), "TSS-") {
		t.Errorf("error should reference TSS- (or legacy TSS-), got: %v", err)
	}
	if !strings.Contains(err.Error(), "mainnet") {
		t.Errorf("error should mention mainnet, got: %v", err)
	}
	if !strings.Contains(err.Error(), "tssKeyShareFile") {
		t.Errorf("error should mention tssKeyShareFile remediation, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_03_TrustedDealerThresholdOnlyOnMainnetBlocked
// verifies the guard triggers when only TSSThreshold is set (without
// TSSTotalShares). The predicate is `TSSTotalShares > 0 || TSSThreshold > 0`.
func TestConfigValidate_TSS_R5_03_TrustedDealerThresholdOnlyOnMainnetBlocked(t *testing.T) {
	cfg := &Config{
		NetworkID:    MainnetNetworkID,
		TSSThreshold: 2, // TotalShares=0 but Threshold>0 still indicates TSS intent
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for threshold-only TSS config on mainnet (TSS-)")
	}
	if !strings.Contains(err.Error(), "TSS-") && !strings.Contains(err.Error(), "TSS-") {
		t.Errorf("error should reference TSS- (or legacy TSS-), got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_03_WithShareFileAllowedOnMainnet verifies that
// providing TSSKeyShareFile on mainnet bypasses the  guard — this is
// the supported production path (pre-generated shares from offline ceremony).
// Also sets TSSDistributedMode=true to satisfy the  guard (multi-share
// must use distributed mode on mainnet).
func TestConfigValidate_TSS_R5_03_WithShareFileAllowedOnMainnet(t *testing.T) {
	cfg := &Config{
		NetworkID:          MainnetNetworkID,
		TSSTotalShares:     3,
		TSSThreshold:       2,
		TSSKeyShareFile:    "/var/lib/quantaureum/tss/share.enc",
		TSSDistributedMode: true, // satisfy
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("expected mainnet with tssKeyShareFile to be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_03_WithGroupKeyFileAllowedOnMainnet verifies
// that providing TSSGroupKeyFile alone (without TSSKeyShareFile) also
// bypasses the  guard. TSSGroupKeyFile is sufficient because it
// indicates the operator has performed an offline ceremony.
// Also sets TSSDistributedMode=true to satisfy the  guard.
func TestConfigValidate_TSS_R5_03_WithGroupKeyFileAllowedOnMainnet(t *testing.T) {
	cfg := &Config{
		NetworkID:          MainnetNetworkID,
		TSSTotalShares:     3,
		TSSThreshold:       2,
		TSSGroupKeyFile:    "/var/lib/quantaureum/tss/groupkey.bin",
		TSSDistributedMode: true, // satisfy
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("expected mainnet with tssGroupKeyFile to be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_03_NoTSSConfigOnMainnetAllowed verifies that
// a mainnet config with no TSS configuration at all (TotalShares=0 AND
// Threshold=0) is allowed — the guard only fires when the operator has
// expressed TSS intent but failed to provide pre-generated key material.
func TestConfigValidate_TSS_R5_03_NoTSSConfigOnMainnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID: MainnetNetworkID,
		// TSSTotalShares=0, TSSThreshold=0 → TSS not configured.
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("expected mainnet with no TSS config to be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_03_TrustedDealerOnTestnetAllowed verifies the
// hard guard is mainnet-only — testnet may run trusted dealer DKG for
// development/testing convenience.
func TestConfigValidate_TSS_R5_03_TrustedDealerOnTestnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID:      TestnetNetworkID,
		DataDir:        t.TempDir(),
		TSSTotalShares: 3,
		TSSThreshold:   2,
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("trusted dealer DKG on testnet should be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_03_TrustedDealerOnDevnetAllowed verifies the
// hard guard is mainnet-only — devnet may run trusted dealer DKG.
func TestConfigValidate_TSS_R5_03_TrustedDealerOnDevnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID:      DevnetNetworkID,
		DataDir:        t.TempDir(),
		TSSTotalShares: 3,
		TSSThreshold:   2,
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("trusted dealer DKG on devnet should be allowed, got: %v", err)
	}
}

// ── TSS- Single-node-all-shares local mode mainnet hard guard ──
//
// AUDIT (2026) TSS-FIX (HIGH). When TSSDistributedMode=false AND
// TSSTotalShares > 1, the node loads ALL threshold shares into a single
// TSSManager — cryptographically equivalent to single-key signing. On
// mainnet, multi-share threshold signing MUST use TSSDistributedMode=true.

// TestConfigValidate_TSS_R5_04_LocalModeMultiShareOnMainnetBlocked verifies
// the primary mainnet hard guard: local mode + TotalShares > 1 must be
// rejected on mainnet.
func TestConfigValidate_TSS_R5_04_LocalModeMultiShareOnMainnetBlocked(t *testing.T) {
	cfg := &Config{
		NetworkID:          MainnetNetworkID,
		TSSDistributedMode: false,
		TSSTotalShares:     3,
		TSSThreshold:       2,
		TSSKeyShareFile:    "/var/lib/quantaureum/tss/share.enc", // satisfy
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for local mode + multi-share on mainnet (TSS-)")
	}
	if !strings.Contains(err.Error(), "TSS-") {
		t.Errorf("error should reference TSS-, got: %v", err)
	}
	if !strings.Contains(err.Error(), "mainnet") {
		t.Errorf("error should mention mainnet, got: %v", err)
	}
	if !strings.Contains(err.Error(), "tssDistributedMode") {
		t.Errorf("error should mention tssDistributedMode remediation, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_04_DistributedModeOnMainnetAllowed verifies
// that distributed mode + multi-share is allowed on mainnet — this is the
// secure production configuration (P2P multi-party threshold signing).
func TestConfigValidate_TSS_R5_04_DistributedModeOnMainnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID:          MainnetNetworkID,
		TSSDistributedMode: true,
		TSSTotalShares:     3,
		TSSThreshold:       2,
		TSSKeyShareFile:    "/var/lib/quantaureum/tss/share.enc", // satisfy
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("distributed mode + multi-share on mainnet should be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_04_SingleShareOnMainnetAllowed verifies that
// the degenerate single-share case (TotalShares=1) is permitted on mainnet
// even in local mode — this is honest about being single-signer and does
// not claim false threshold security.
func TestConfigValidate_TSS_R5_04_SingleShareOnMainnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID:          MainnetNetworkID,
		TSSDistributedMode: false,
		TSSTotalShares:     1,
		TSSThreshold:       1,
		TSSKeyShareFile:    "/var/lib/quantaureum/tss/share.enc", // satisfy
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("single-share local mode on mainnet should be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_04_LocalModeMultiShareWithUnsafeEnvVarAllowed
// verifies the defense-in-depth escape hatch: setting
// QAU_ALLOW_UNSAFE_LOCAL_TSS=1 allows local mode + multi-share on mainnet.
// This is for operator acknowledgement of risk, not a production setting.
// Uses t.Setenv for automatic env var restoration.
func TestConfigValidate_TSS_R5_04_LocalModeMultiShareWithUnsafeEnvVarAllowed(t *testing.T) {
	t.Setenv("QAU_ALLOW_UNSAFE_LOCAL_TSS", "1")

	cfg := &Config{
		NetworkID:          MainnetNetworkID,
		TSSDistributedMode: false,
		TSSTotalShares:     3,
		TSSThreshold:       2,
		TSSKeyShareFile:    "/var/lib/quantaureum/tss/share.enc", // satisfy
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("local mode + multi-share with QAU_ALLOW_UNSAFE_LOCAL_TSS=1 should be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_04_LocalModeMultiShareOnTestnetAllowed verifies
// the hard guard is mainnet-only — testnet may use local mode for
// development convenience without setting the escape-hatch env var.
func TestConfigValidate_TSS_R5_04_LocalModeMultiShareOnTestnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID:          TestnetNetworkID,
		DataDir:            t.TempDir(),
		TSSDistributedMode: false,
		TSSTotalShares:     3,
		TSSThreshold:       2,
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("local mode + multi-share on testnet should be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSS_R5_04_LocalModeMultiShareOnDevnetAllowed verifies
// the hard guard is mainnet-only — devnet may use local mode.
func TestConfigValidate_TSS_R5_04_LocalModeMultiShareOnDevnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID:          DevnetNetworkID,
		DataDir:            t.TempDir(),
		TSSDistributedMode: false,
		TSSTotalShares:     3,
		TSSThreshold:       2,
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("local mode + multi-share on devnet should be allowed, got: %v", err)
	}
}

// ── TSSDistributedDKG switch (Task 5) ──

// TestDefaultConfig_TSSDistributedDKG_DefaultOff verifies the runtime
// distributed DKG switch defaults to OFF so existing node behavior is
// completely unchanged when the operator does not opt in.
func TestDefaultConfig_TSSDistributedDKG_DefaultOff(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.TSSDistributedDKG {
		t.Error("TSSDistributedDKG must default to false (off) to preserve existing behavior")
	}
}

// TestConfigValidate_TSSDistributedDKG_MainnetBlocked verifies the hard
// guard: mainnet (NetworkID==1668) permanently disables runtime distributed
// DKG. Enabling the switch on mainnet must fail config validation.
func TestConfigValidate_TSSDistributedDKG_MainnetBlocked(t *testing.T) {
	cfg := &Config{
		NetworkID:         MainnetNetworkID,
		TSSDistributedDKG: true,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error enabling TSSDistributedDKG on mainnet")
	}
	if !strings.Contains(err.Error(), "mainnet") {
		t.Errorf("error should mention mainnet, got: %v", err)
	}
}

// TestConfigValidate_TSSDistributedDKG_TestnetAllowed verifies the switch is
// permitted on testnet (the hard guard is mainnet-only).
func TestConfigValidate_TSSDistributedDKG_TestnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID:          TestnetNetworkID,
		DataDir:            t.TempDir(),
		TSSDistributedMode: true,
		TSSDistributedDKG:  true,
		TSSTotalShares:     3,
		TSSThreshold:       2,
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("TSSDistributedDKG on testnet should be allowed, got: %v", err)
	}
}

// TestConfigValidate_TSSDistributedDKG_DevnetAllowed verifies the switch is
// permitted on devnet.
func TestConfigValidate_TSSDistributedDKG_DevnetAllowed(t *testing.T) {
	cfg := &Config{
		NetworkID:          DevnetNetworkID,
		DataDir:            t.TempDir(),
		TSSDistributedMode: true,
		TSSDistributedDKG:  true,
		TSSTotalShares:     3,
		TSSThreshold:       2,
	}
	err := cfg.Validate()
	if err != nil {
		t.Errorf("TSSDistributedDKG on devnet should be allowed, got: %v", err)
	}
}

// TestConfig_JSONSerialization_TSSDistributedDKG verifies the switch
// serializes to/from JSON so it can be configured via the node config file.
func TestConfig_JSONSerialization_TSSDistributedDKG(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TSSDistributedDKG = true

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(data), `"tssDistributedDKG":true`) {
		t.Errorf("marshaled config missing tssDistributedDKG:true, got: %s", string(data))
	}

	var decoded Config
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if !decoded.TSSDistributedDKG {
		t.Error("decoded TSSDistributedDKG = false, want true")
	}
}

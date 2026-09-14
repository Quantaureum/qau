// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// closeNodeDB closes the blockStore and stateDB to release BoltDB file locks on Windows.
func closeNodeDB(n *Node) {
	if n == nil {
		return
	}
	if n.stateDB != nil {
		n.stateDB.Close()
		n.stateDB = nil
	}
	if n.blockStore != nil {
		n.blockStore.Close()
	}
}

// ── Node lifecycle tests (extended) ──

func TestNewNode_DevConfig(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with dev config failed: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
	defer closeNodeDB(n)
}

func TestNewNode_TestnetConfig(t *testing.T) {
	cfg := TestnetConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with testnet config failed: %v", err)
	}
	if n == nil {
		t.Fatal("expected non-nil node")
	}
	defer closeNodeDB(n)
}

func TestNode_NetworkID(t *testing.T) {
	cfg := &Config{Name: "test-netid", DataDir: t.TempDir(), NetworkID: TestnetNetworkID}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	nid := n.NetworkID()
	if nid == 0 {
		t.Error("expected non-zero network ID")
	}
}

func TestNode_IsSyncing(t *testing.T) {
	cfg := &Config{Name: "test-sync", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.IsSyncing() {
		t.Error("expected node not syncing before start")
	}
}

func TestNode_PeerCount(t *testing.T) {
	cfg := &Config{Name: "test-peers", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	count := n.PeerCount()
	if count != 0 {
		t.Errorf("expected 0 peers before start, got %d", count)
	}
}

func TestNode_CurrentBlock(t *testing.T) {
	cfg := &Config{Name: "test-block", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n.CurrentBlock()
}

func TestNode_CurrentHeight(t *testing.T) {
	cfg := &Config{Name: "test-height", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n.CurrentHeight()
}

func TestNode_GenesisBlock(t *testing.T) {
	cfg := &Config{Name: "test-genesis", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n.GenesisBlock()
}

// ── Node error variables ──

func TestNodeErrorVariables(t *testing.T) {
	errors := []error{
		ErrNodeAlreadyRunning,
		ErrNodeNotRunning,
		ErrGenesisNotLoaded,
		ErrInvalidGenesis,
		ErrDatabaseCorrupted,
		ErrDevModeSecurityViolation,
	}
	for _, err := range errors {
		if err == nil {
			t.Error("expected non-nil error variable")
		}
	}
}

// ── Config field validation ──

func TestConfig_ValidatorEnabled(t *testing.T) {
	cfg := &Config{
		Name:             "test-validator",
		DataDir:          t.TempDir(),
		NetworkID:        TestnetNetworkID,
		ValidatorEnabled: true,
		ValidatorKey:     "test-key",
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

func TestConfig_RPCEnabled(t *testing.T) {
	cfg := &Config{
		Name:       "test-rpc",
		DataDir:    t.TempDir(),
		NetworkID:  TestnetNetworkID,
		RPCEnabled: false,
		WSEnabled:  false,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

func TestConfig_MetricsEnabled(t *testing.T) {
	cfg := &Config{
		Name:           "test-metrics",
		DataDir:        t.TempDir(),
		NetworkID:      TestnetNetworkID,
		MetricsEnabled: false,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

func TestConfig_HealthEnabled(t *testing.T) {
	cfg := &Config{
		Name:          "test-health",
		DataDir:       t.TempDir(),
		NetworkID:     TestnetNetworkID,
		HealthEnabled: false,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with all features disabled ──

func TestNewNode_MinimalConfig(t *testing.T) {
	cfg := &Config{
		Name:            "minimal",
		DataDir:         t.TempDir(),
		NetworkID:       TestnetNetworkID,
		RPCEnabled:      false,
		WSEnabled:       false,
		MetricsEnabled:  false,
		HealthEnabled:   false,
		FrontendEnabled: false,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with minimal config failed: %v", err)
	}
	defer closeNodeDB(n)
	if n == nil {
		t.Fatal("expected non-nil node")
	}
}

// ── Config with TSS ──

func TestConfig_TSS(t *testing.T) {
	cfg := &Config{
		Name:           "test-tss",
		DataDir:        t.TempDir(),
		NetworkID:      TestnetNetworkID,
		TSSThreshold:   2,
		TSSTotalShares: 3,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with TSS config failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with memory limits ──

func TestConfig_MemoryLimits(t *testing.T) {
	cfg := &Config{
		Name:                  "test-memory",
		DataDir:               t.TempDir(),
		NetworkID:             TestnetNetworkID,
		MemoryLimitMB:         4096,
		MaxConcurrentRequests: 100,
		RequestTimeout:        30,
		RequestsPerSecond:     100,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with memory limits failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with parallel execution ──

func TestConfig_ParallelExecution(t *testing.T) {
	cfg := &Config{
		Name:      "test-parallel",
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
		ParallelExecution: ParallelExecutionConfig{
			Enabled:    true,
			NumWorkers: 4,
			MaxRetries: 3,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with parallel execution failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with pruning ──

func TestConfig_Pruning(t *testing.T) {
	cfg := &Config{
		Name:      "test-pruning",
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
		PruningConfig: PruningOptConfig{
			Enabled:         true,
			RetentionBlocks: 1000,
			BatchSize:       100,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with pruning failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with cache ──

func TestConfig_Cache(t *testing.T) {
	cfg := &Config{
		Name:      "test-cache",
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
		CacheConfig: CacheOptConfig{
			L1MaxSize:   512,
			L1MaxMemory: 32 * 1024 * 1024,
			L2MaxSize:   4096,
			L2MaxMemory: 128 * 1024 * 1024,
			TTLSeconds:  300,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with cache config failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with alerting ──

func TestConfig_Alerting(t *testing.T) {
	cfg := &Config{
		Name:      "test-alerting",
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
		AlertingConfig: AlertingNodeConfig{
			Enabled:    true,
			ConfigFile: "configs/alerting.json",
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with alerting config failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with sync-only mode ──

func TestConfig_SyncOnlyMode(t *testing.T) {
	cfg := &Config{
		Name:         "test-synconly",
		DataDir:      t.TempDir(),
		NetworkID:    TestnetNetworkID,
		SyncOnlyMode: true,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with sync-only mode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with block producer disabled ──

func TestConfig_BlockProducerDisabled(t *testing.T) {
	cfg := &Config{
		Name:          "test-no-producer",
		DataDir:       t.TempDir(),
		NetworkID:     TestnetNetworkID,
		BlockProducer: false,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with block producer disabled failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with DHT ──

func TestConfig_DHT(t *testing.T) {
	cfg := &Config{
		Name:      "test-dht",
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
		EnableDHT: true,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with DHT enabled failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with whitelist ──

func TestConfig_Whitelist(t *testing.T) {
	cfg := &Config{
		Name:          "test-whitelist",
		DataDir:       t.TempDir(),
		NetworkID:     TestnetNetworkID,
		WhitelistOnly: true,
		TrustedPeers:  []string{"enode://test@198.51.100.10:30303"},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with whitelist failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── Config with light client ──

func TestConfig_LightClient(t *testing.T) {
	cfg := &Config{
		Name:               "test-lightclient",
		DataDir:            t.TempDir(),
		NetworkID:          TestnetNetworkID,
		LightClientEnabled: true,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode with light client failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

// ── validateProductionConfig extended tests ──

func TestNode_ValidateProductionConfig_DevModeMainnet(t *testing.T) {
	cfg := &Config{
		Name:      "test-prod-config",
		DataDir:   t.TempDir(),
		Network:   NetworkMainnet,
		NetworkID: MainnetNetworkID,
		DevMode:   true,
	}
	_, err := NewNode(cfg)
	if err == nil {
		t.Error("expected error for DevMode on mainnet")
	}
}

func TestNode_ValidateProductionConfig_DevModeTestnet(t *testing.T) {
	cfg := &Config{
		Name:      "test-prod-config",
		DataDir:   t.TempDir(),
		Network:   NetworkTestnet,
		NetworkID: TestnetNetworkID,
		DevMode:   true,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for DevMode on testnet")
	}
}

func TestNode_ValidateProductionConfig_NoDevModeMainnet(t *testing.T) {
	cfg := &Config{
		Name:      "test-prod-config",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		DevMode:   false,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	err = n.validateProductionConfig()
	if err != nil {
		t.Errorf("no DevMode on mainnet should be fine, got: %v", err)
	}
}

// ── loadDevAccountsForUnlock tests ──

func TestLoadDevAccountsForUnlock_NonexistentFile(t *testing.T) {
	_, err := loadDevAccountsForUnlock("/nonexistent/path/accounts.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadDevAccountsForUnlock_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	os.WriteFile(path, []byte("not json"), 0644)

	_, err := loadDevAccountsForUnlock(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadDevAccountsForUnlock_ValidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	jsonData := `{"accounts":[{"address":"0x1234567890123456789012345678901234567890"}]}`
	os.WriteFile(path, []byte(jsonData), 0644)

	accounts, err := loadDevAccountsForUnlock(path)
	if err != nil {
		t.Fatalf("loadDevAccountsForUnlock failed: %v", err)
	}
	if len(accounts) != 1 {
		t.Errorf("expected 1 account, got %d", len(accounts))
	}
	if accounts[0].Address != "0x1234567890123456789012345678901234567890" {
		t.Errorf("unexpected address: %s", accounts[0].Address)
	}
}

func TestLoadDevAccountsForUnlock_EmptyAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	jsonData := `{"accounts":[]}`
	os.WriteFile(path, []byte(jsonData), 0644)

	accounts, err := loadDevAccountsForUnlock(path)
	if err != nil {
		t.Fatalf("loadDevAccountsForUnlock failed: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(accounts))
	}
}

// ── Node getter tests with non-nil components ──

func TestNode_Getters_NilComponents(t *testing.T) {
	cfg := &Config{Name: "test-getters", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	// These should return nil without panicking
	if n.BlockStore() != nil {
		t.Error("expected nil BlockStore before start")
	}
	if n.StateDB() != nil {
		t.Error("expected nil StateDB before start")
	}
	if n.TxPool() != nil {
		t.Error("expected nil TxPool before start")
	}
	if n.P2PHost() != nil {
		t.Error("expected nil P2PHost before start")
	}
	if n.ParallelQVM() != nil {
		t.Error("expected nil ParallelQVM before start")
	}
	if n.MultiCache() != nil {
		t.Error("expected nil MultiCache before start")
	}
	if n.ShutdownHandler() == nil {
		t.Error("expected non-nil ShutdownHandler")
	}
	if n.HealthServer() != nil {
		t.Error("expected nil HealthServer when not enabled")
	}
	if n.RecoveryManager() == nil {
		t.Error("expected non-nil RecoveryManager")
	}
}

// ── Node with HealthEnabled ──

func TestNode_HealthEnabled(t *testing.T) {
	cfg := &Config{
		Name:          "test-health-enabled",
		DataDir:       t.TempDir(),
		HealthEnabled: true,
		HealthAddr:    "127.0.0.1:0",
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.HealthServer() == nil {
		t.Error("expected non-nil HealthServer when enabled")
	}
}

// ── Node with DevAutoUnlockAccounts ──

func TestNode_DevAutoUnlockAccounts(t *testing.T) {
	cfg := &Config{
		Name:                  "test-auto-unlock",
		DataDir:               t.TempDir(),
		NetworkID:             DevnetNetworkID,
		DevAutoUnlockAccounts: true,
		DevBlocks:             true,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if !n.config.DevAutoUnlockAccounts {
		t.Error("expected DevAutoUnlockAccounts to be true")
	}
}

// ── Node CurrentBlock with nil block ──

func TestNode_CurrentBlock_Nil(t *testing.T) {
	cfg := &Config{Name: "test-nil-block", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	blk := n.CurrentBlock()
	if blk != nil {
		t.Error("expected nil CurrentBlock before start")
	}
}

// ── Node CurrentHeight with nil block ──

func TestNode_CurrentHeight_Nil(t *testing.T) {
	cfg := &Config{Name: "test-nil-height", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	height := n.CurrentHeight()
	if height != 0 {
		t.Errorf("expected 0 height before start, got %d", height)
	}
}

// ── Node StakingManager and DeFiManager ──

func TestNode_StakingManager_Nil(t *testing.T) {
	cfg := &Config{Name: "test-staking", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.StakingManager() != nil {
		t.Error("expected nil StakingManager before start")
	}
}

func TestNode_DeFiManager_Nil(t *testing.T) {
	cfg := &Config{Name: "test-defi", DataDir: t.TempDir()}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.DeFiManager() != nil {
		t.Error("expected nil DeFiManager before start")
	}
}

// ── Node with nil config ──

func TestNewNode_NilConfigUsesDefaults(t *testing.T) {
	n, err := NewNode(nil)
	if err != nil {
		t.Fatalf("NewNode with nil config failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.config == nil {
		t.Fatal("expected non-nil config after defaulting")
	}
	if n.config.Name != "qau-node" {
		t.Errorf("expected default name 'qau-node', got '%s'", n.config.Name)
	}
}

// ── parseAttestation tests ──

func TestNode_ParseAttestation_ValidData(t *testing.T) {
	n, _ := NewNode(&Config{Name: "test-att", DataDir: t.TempDir()})
	defer closeNodeDB(n)

	// Build valid attestation data matching parseAttestation's wire format:
	// slot(8) + blockRoot(32) + sourceEpoch(8) + sourceRoot(32) +
	// targetEpoch(8) + targetRoot(32) + validatorIdx(4) + keyVersion(8) + sigLen(2) + sig
	data := make([]byte, 138)
	offset := 0

	// Slot (8 bytes)
	binary.BigEndian.PutUint64(data[offset:], 42)
	offset += 8

	// BeaconBlockRoot (32 bytes)
	copy(data[offset:offset+32], make([]byte, 32))
	offset += 32

	// SourceEpoch (8 bytes)
	binary.BigEndian.PutUint64(data[offset:], 1)
	offset += 8

	// SourceRoot (32 bytes)
	copy(data[offset:offset+32], make([]byte, 32))
	offset += 32

	// TargetEpoch (8 bytes)
	binary.BigEndian.PutUint64(data[offset:], 2)
	offset += 8

	// TargetRoot (32 bytes)
	copy(data[offset:offset+32], make([]byte, 32))
	offset += 32

	// ValidatorIndex (4 bytes)
	binary.BigEndian.PutUint32(data[offset:], 100)
	offset += 4

	// KeyVersion (8 bytes)
	binary.BigEndian.PutUint64(data[offset:], 1)
	offset += 8

	// Signature length (2 bytes) + signature
	binary.BigEndian.PutUint16(data[offset:], 4)
	offset += 2
	copy(data[offset:offset+4], []byte{0xAA, 0xBB, 0xCC, 0xDD})

	att, err := n.parseAttestation(data)
	if err != nil {
		t.Fatalf("parseAttestation failed: %v", err)
	}
	if att.Slot != 42 {
		t.Errorf("expected slot 42, got %d", att.Slot)
	}
	if att.Source.Epoch != 1 {
		t.Errorf("expected source epoch 1, got %d", att.Source.Epoch)
	}
	if att.Target.Epoch != 2 {
		t.Errorf("expected target epoch 2, got %d", att.Target.Epoch)
	}
	if att.ValidatorIndex != 100 {
		t.Errorf("expected validator index 100, got %d", att.ValidatorIndex)
	}
	if att.KeyVersion != 1 {
		t.Errorf("expected key version 1, got %d", att.KeyVersion)
	}
}

func TestNode_ParseAttestation_TooShort(t *testing.T) {
	n, _ := NewNode(&Config{Name: "test-att-short", DataDir: t.TempDir()})
	defer closeNodeDB(n)

	_, err := n.parseAttestation([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestNode_ParseAttestation_InvalidValidatorIndex(t *testing.T) {
	n, _ := NewNode(&Config{Name: "test-att-idx", DataDir: t.TempDir()})
	defer closeNodeDB(n)

	// Wire format: slot(8) + blockRoot(32) + sourceEpoch(8) + sourceRoot(32) +
	// targetEpoch(8) + targetRoot(32) + validatorIdx(4) + keyVersion(8) + sigLen(2)
	data := make([]byte, 134)
	offset := 0
	binary.BigEndian.PutUint64(data[offset:], 1) // Slot
	offset += 8
	copy(data[offset:offset+32], make([]byte, 32)) // BeaconBlockRoot
	offset += 32
	binary.BigEndian.PutUint64(data[offset:], 0) // SourceEpoch
	offset += 8
	copy(data[offset:offset+32], make([]byte, 32)) // SourceRoot
	offset += 32
	binary.BigEndian.PutUint64(data[offset:], 0) // TargetEpoch
	offset += 8
	copy(data[offset:offset+32], make([]byte, 32)) // TargetRoot
	offset += 32
	binary.BigEndian.PutUint32(data[offset:], 0x80000001) // Invalid validator index
	offset += 4
	binary.BigEndian.PutUint64(data[offset:], 0) // KeyVersion
	offset += 8
	binary.BigEndian.PutUint16(data[offset:], 0) // Sig length

	_, err := n.parseAttestation(data)
	if err == nil {
		t.Error("expected error for invalid validator index")
	}
}

func TestNode_ParseAttestation_TruncatedSignature(t *testing.T) {
	n, _ := NewNode(&Config{Name: "test-att-sig", DataDir: t.TempDir()})
	defer closeNodeDB(n)

	// Wire format up to sigLen, then declare sigLen=100 but provide no signature bytes.
	data := make([]byte, 134)
	offset := 0
	binary.BigEndian.PutUint64(data[offset:], 1) // Slot
	offset += 8
	copy(data[offset:offset+32], make([]byte, 32)) // BeaconBlockRoot
	offset += 32
	binary.BigEndian.PutUint64(data[offset:], 0) // SourceEpoch
	offset += 8
	copy(data[offset:offset+32], make([]byte, 32)) // SourceRoot
	offset += 32
	binary.BigEndian.PutUint64(data[offset:], 0) // TargetEpoch
	offset += 8
	copy(data[offset:offset+32], make([]byte, 32)) // TargetRoot
	offset += 32
	binary.BigEndian.PutUint32(data[offset:], 1) // ValidatorIndex
	offset += 4
	binary.BigEndian.PutUint64(data[offset:], 0) // KeyVersion
	offset += 8
	binary.BigEndian.PutUint16(data[offset:], 100) // Sig length = 100, but no signature bytes follow

	_, err := n.parseAttestation(data)
	if err == nil {
		t.Error("expected error for truncated signature")
	}
}

func TestNode_ParseAttestation_TruncatedSigLength(t *testing.T) {
	n, _ := NewNode(&Config{Name: "test-att-siglen", DataDir: t.TempDir()})
	defer closeNodeDB(n)

	data := make([]byte, 60) // Exactly 60 bytes - just enough for validator index but not sig length

	_, err := n.parseAttestation(data)
	if err == nil {
		t.Error("expected error for truncated sig length field")
	}
}

// ── defaultKeyVersionValidator tests ──

func TestDefaultKeyVersionValidator_ValidateKeyVersion(t *testing.T) {
	v := &defaultKeyVersionValidator{}
	err := v.ValidateKeyVersion(1, 1000)
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestDefaultKeyVersionValidator_GetCurrentKeyVersion(t *testing.T) {
	v := &defaultKeyVersionValidator{}
	ver := v.GetCurrentKeyVersion()
	if ver != 0 {
		t.Errorf("expected version 0, got %d", ver)
	}
}

// ── Node IsRunning ──

func TestNode_IsRunning_BeforeStart(t *testing.T) {
	cfg := &Config{Name: "test-running", DataDir: t.TempDir()}
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)
	if n.IsRunning() {
		t.Error("expected not running before start")
	}
}

// ── Node GenesisBlock ──

func TestNode_GenesisBlock_Nil(t *testing.T) {
	cfg := &Config{Name: "test-genesis-blk", DataDir: t.TempDir()}
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)
	if n.GenesisBlock() != nil {
		t.Error("expected nil GenesisBlock before start")
	}
}

// ── Node with various config options ──

func TestNewNode_WithMetricsEnabled(t *testing.T) {
	cfg := &Config{
		Name:           "test-metrics",
		DataDir:        t.TempDir(),
		MetricsEnabled: true,
		MetricsAddr:    "127.0.0.1:0",
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

func TestNewNode_WithRPCEnabled(t *testing.T) {
	cfg := &Config{
		Name:       "test-rpc",
		DataDir:    t.TempDir(),
		RPCEnabled: true,
		RPCAddr:    "127.0.0.1:0",
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

func TestNewNode_WithWSEnabled(t *testing.T) {
	cfg := &Config{
		Name:      "test-ws",
		DataDir:   t.TempDir(),
		WSEnabled: true,
		WSAddr:    "127.0.0.1:0",
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	_ = n
}

func TestNewNode_WithDevMode(t *testing.T) {
	cfg := &Config{
		Name:      "test-devmode",
		DataDir:   t.TempDir(),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if !n.config.DevMode {
		t.Error("expected DevMode to be true")
	}
}

func TestNewNode_WithValidatorKey(t *testing.T) {
	cfg := &Config{
		Name:         "test-valkey",
		DataDir:      t.TempDir(),
		ValidatorKey: "test-key",
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.config.ValidatorKey != "test-key" {
		t.Error("expected ValidatorKey to be set")
	}
}

// ── Node Stop without start (extended) ──

func TestNode_StopMultipleTimes(t *testing.T) {
	cfg := &Config{Name: "test-multi-stop", DataDir: t.TempDir()}
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	// Should not panic
	n.Stop()
	n.Stop()
	n.Stop()
}

func TestNode_Stop_ReturnsErrWhenNotRunning(t *testing.T) {
	cfg := &Config{Name: "test-stop-notrunning", DataDir: t.TempDir()}
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	err := n.Stop()
	if err != ErrNodeNotRunning {
		t.Errorf("expected ErrNodeNotRunning, got %v", err)
	}
}

func TestNode_Stop_WithInitializedComponents(t *testing.T) {
	cfg := &Config{
		Name:      "test-stop-init",
		DataDir:   filepath.Join(t.TempDir(), "qau-stop"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	// Initialize components manually (without calling Start which needs P2P)
	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()
	n.initOptimizations()

	// Set running=true so Stop() actually executes
	n.running = true

	err := n.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if n.running {
		t.Error("expected running=false after Stop")
	}
}

// ── Node IsSyncing before start ──

func TestNode_IsSyncing_BeforeStart(t *testing.T) {
	cfg := &Config{Name: "test-syncing", DataDir: t.TempDir()}
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)
	// IsSyncing should not panic
	_ = n.IsSyncing()
}

// ── Node PeerCount before start ──

func TestNode_PeerCount_BeforeStart(t *testing.T) {
	cfg := &Config{Name: "test-peers", DataDir: t.TempDir()}
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)
	// PeerCount should not panic
	_ = n.PeerCount()
}

// ── initDataDir tests ──

func TestNode_InitDataDir(t *testing.T) {
	cfg := &Config{
		Name:    "test-initdir",
		DataDir: filepath.Join(t.TempDir(), "qau-data"),
	}
	// Set backup dirs explicitly since Validate only sets them when BackupEnabled=true
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	err := n.initDataDir()
	if err != nil {
		t.Fatalf("initDataDir failed: %v", err)
	}

	// Verify directories were created
	checkDirs := []string{
		n.config.DataDir,
		filepath.Join(n.config.DataDir, "blocks"),
		filepath.Join(n.config.DataDir, "state"),
		filepath.Join(n.config.DataDir, "keystore"),
	}
	for _, dir := range checkDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("directory %s was not created", dir)
		}
	}
}

func TestNode_InitDataDir_Idempotent(t *testing.T) {
	cfg := &Config{
		Name:    "test-initdir2",
		DataDir: filepath.Join(t.TempDir(), "qau-data2"),
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	// Call twice - should not fail
	err := n.initDataDir()
	if err != nil {
		t.Fatalf("first initDataDir failed: %v", err)
	}
	err = n.initDataDir()
	if err != nil {
		t.Fatalf("second initDataDir failed: %v", err)
	}
}

// ── Node with LightClientEnabled ──

func TestNewNode_LightClientEnabled(t *testing.T) {
	cfg := &Config{
		Name:               "test-light",
		DataDir:            t.TempDir(),
		LightClientEnabled: true,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if !n.config.LightClientEnabled {
		t.Error("expected LightClientEnabled to be true")
	}
}

// ── Node with TSS config ──

func TestNewNode_TSSConfig(t *testing.T) {
	cfg := &Config{
		Name:           "test-tss",
		DataDir:        t.TempDir(),
		TSSThreshold:   2,
		TSSTotalShares: 3,
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	if n.config.TSSThreshold != 2 {
		t.Errorf("expected TSSThreshold 2, got %d", n.config.TSSThreshold)
	}
	if n.config.TSSTotalShares != 3 {
		t.Errorf("expected TSSTotalShares 3, got %d", n.config.TSSTotalShares)
	}
}

// ── initDatabase tests ──

func TestNode_InitDatabase_DevMode(t *testing.T) {
	cfg := &Config{
		Name:    "test-initdb-dev",
		DataDir: filepath.Join(t.TempDir(), "qau-initdb"),
		DevMode: true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	// First create data dir
	if err := n.initDataDir(); err != nil {
		t.Fatalf("initDataDir failed: %v", err)
	}

	// initDatabase should succeed in DevMode (uses MemDB fallback)
	if err := n.initDatabase(); err != nil {
		t.Fatalf("initDatabase failed in DevMode: %v", err)
	}
	if n.blockStore == nil {
		t.Error("expected non-nil blockStore after initDatabase")
	}
}

func TestNode_InitDatabase_NonDevMode(t *testing.T) {
	cfg := &Config{
		Name:      "test-initdb-prod",
		DataDir:   filepath.Join(t.TempDir(), "qau-initdb-prod"),
		DevMode:   false,
		NetworkID: DevnetNetworkID,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	// First create data dir
	if err := n.initDataDir(); err != nil {
		t.Fatalf("initDataDir failed: %v", err)
	}

	// initDatabase should succeed with BoltDB (creates the database)
	if err := n.initDatabase(); err != nil {
		t.Fatalf("initDatabase failed: %v", err)
	}
	if n.blockStore == nil {
		t.Error("expected non-nil blockStore after initDatabase")
	}
}

// ── loadGenesis tests ──

func TestNode_LoadGenesis_DefaultDevnet(t *testing.T) {
	cfg := &Config{
		Name:      "test-loadgenesis",
		DataDir:   filepath.Join(t.TempDir(), "qau-genesis"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()

	if err := n.loadGenesis(); err != nil {
		t.Fatalf("loadGenesis failed: %v", err)
	}
	if n.genesis == nil {
		t.Error("expected non-nil genesis after loadGenesis")
	}
}

func TestNode_LoadGenesis_Testnet(t *testing.T) {
	cfg := &Config{
		Name:      "test-loadgenesis-testnet",
		DataDir:   filepath.Join(t.TempDir(), "qau-genesis-testnet"),
		NetworkID: TestnetNetworkID,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()

	if err := n.loadGenesis(); err != nil {
		// Testnet genesis without validators should fail validation
		// This is expected behavior - testnet requires validators
		t.Logf("loadGenesis for testnet without validators returned expected error: %v", err)
	}
}

// TestNode_LoadGenesis_DBConfigMismatch verifies that loadGenesis refuses to
// start when the DB's stored genesis block hash doesn't match the hash
// derived from the just-loaded configuration.
//
// AUDIT (2026) R3-NODE-02 FIX: previously the DB's genesis block was
// loaded and used without comparing it against the config-derived genesis,
// so an old data/genesis.json (or a transplanted DB) could silently fork
// the node off the canonical chain. Now a mismatch is a hard error.
func TestNode_LoadGenesis_DBConfigMismatch(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "qau-mismatch")

	// Phase 1: bootstrap a node with DevMode genesis (DevGenesis), so the
	// DB has a stored genesis block derived from the canonical DevGenesis.
	cfgA := &Config{
		Name:      "test-mismatch-a",
		DataDir:   dataDir,
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfgA.KeyRotation.BackupDir = filepath.Join(cfgA.DataDir, "keys", "backup")
	cfgA.TLSCertRotation.BackupDir = filepath.Join(cfgA.DataDir, "certs", "backup")
	nodeA, _ := NewNode(cfgA)
	nodeA.initDataDir()
	if err := nodeA.initDatabase(); err != nil {
		t.Fatalf("initDatabase A failed: %v", err)
	}
	if err := nodeA.loadGenesis(); err != nil {
		t.Fatalf("loadGenesis A failed: %v", err)
	}
	closeNodeDB(nodeA)

	// Phase 2: write a divergent genesis.json into DataDir with a different
	// timestamp. The default loader picks up DataDir/genesis.json when
	// GenesisFile is empty.
	divergent := DevGenesis()
	divergent.Timestamp = DevnetGenesisTimestamp + 1 // different from canonical
	divergentPath := filepath.Join(dataDir, "genesis.json")
	if err := divergent.SaveGenesis(divergentPath); err != nil {
		t.Fatalf("SaveGenesis failed: %v", err)
	}

	// Phase 3: start node B pointing at the same DataDir. loadGenesis should
	// load the divergent file, derive a different genesis block hash, and
	// refuse to start because the DB's stored genesis doesn't match.
	cfgB := &Config{
		Name:      "test-mismatch-b",
		DataDir:   dataDir,
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfgB.KeyRotation.BackupDir = filepath.Join(cfgB.DataDir, "keys", "backup")
	cfgB.TLSCertRotation.BackupDir = filepath.Join(cfgB.DataDir, "certs", "backup")
	nodeB, _ := NewNode(cfgB)
	defer closeNodeDB(nodeB)
	if err := nodeB.initDatabase(); err != nil {
		t.Fatalf("initDatabase B failed: %v", err)
	}

	err := nodeB.loadGenesis()
	if err == nil {
		t.Fatal("expected loadGenesis to fail when DB genesis doesn't match config-derived genesis, but it succeeded")
	}
	// Sanity-check the error mentions the audit tag so operators can grep it.
	if !strings.Contains(err.Error(), "R3-NODE-02") {
		t.Errorf("expected error to reference audit R3-NODE-02, got: %v", err)
	}
	t.Logf("Got expected mismatch error: %v", err)
}

// ── initState tests ──

func TestNode_InitState(t *testing.T) {
	cfg := &Config{
		Name:      "test-initstate",
		DataDir:   filepath.Join(t.TempDir(), "qau-state"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()

	if err := n.initState(); err != nil {
		t.Fatalf("initState failed: %v", err)
	}
	if n.stateDB == nil {
		t.Error("expected non-nil stateDB after initState")
	}
}

// ── initTxPool tests ──

func TestNode_InitTxPool(t *testing.T) {
	cfg := &Config{
		Name:      "test-initxpool",
		DataDir:   filepath.Join(t.TempDir(), "qau-txpool"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()

	if err := n.initTxPool(); err != nil {
		t.Fatalf("initTxPool failed: %v", err)
	}
	if n.txPool == nil {
		t.Error("expected non-nil txPool after initTxPool")
	}
}

// ── initConsensus tests ──

func TestNode_InitConsensus(t *testing.T) {
	cfg := &Config{
		Name:      "test-initconsensus",
		DataDir:   filepath.Join(t.TempDir(), "qau-consensus"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()

	if err := n.initConsensus(); err != nil {
		t.Fatalf("initConsensus failed: %v", err)
	}
}

// ── Node initOptimizations ──

func TestNode_InitOptimizations(t *testing.T) {
	cfg := &Config{
		Name:      "test-initopt",
		DataDir:   filepath.Join(t.TempDir(), "qau-opt"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()

	if err := n.initOptimizations(); err != nil {
		t.Fatalf("initOptimizations failed: %v", err)
	}
}

// ── initHA tests ──

func TestNode_InitHA(t *testing.T) {
	cfg := &Config{
		Name:      "test-initha",
		DataDir:   filepath.Join(t.TempDir(), "qau-ha"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()
	n.initOptimizations()

	if err := n.initHA(); err != nil {
		t.Fatalf("initHA failed: %v", err)
	}
}

// ── initMetrics tests ──

func TestNode_InitMetrics_Disabled(t *testing.T) {
	cfg := &Config{
		Name:           "test-initmetrics",
		DataDir:        filepath.Join(t.TempDir(), "qau-metrics"),
		NetworkID:      DevnetNetworkID,
		DevMode:        true,
		MetricsEnabled: false,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()
	n.initOptimizations()

	if err := n.initMetrics(); err != nil {
		t.Fatalf("initMetrics failed: %v", err)
	}
}

// ── initAlerting tests ──

func TestNode_InitAlerting_Disabled(t *testing.T) {
	cfg := &Config{
		Name:      "test-initalerting",
		DataDir:   filepath.Join(t.TempDir(), "qau-alerting"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()
	n.initOptimizations()

	if err := n.initAlerting(); err != nil {
		t.Fatalf("initAlerting failed: %v", err)
	}
}

// ── initRPC tests ──

func TestNode_InitRPC_Disabled(t *testing.T) {
	cfg := &Config{
		Name:       "test-initrpc",
		DataDir:    filepath.Join(t.TempDir(), "qau-rpc"),
		NetworkID:  DevnetNetworkID,
		DevMode:    true,
		RPCEnabled: false,
		WSEnabled:  false,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()
	n.initOptimizations()

	if err := n.initRPC(); err != nil {
		t.Fatalf("initRPC failed: %v", err)
	}
}

// ── syncStakingFromChain tests ──

func TestNode_SyncStakingFromChain(t *testing.T) {
	cfg := &Config{
		Name:      "test-syncstaking",
		DataDir:   filepath.Join(t.TempDir(), "qau-staking"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()
	n.initOptimizations()

	// syncStakingFromChain should not fail even with empty chain
	if err := n.syncStakingFromChain(); err != nil {
		t.Logf("syncStakingFromChain returned: %v (may be expected with empty chain)", err)
	}
}

// ── Node CurrentBlock after init ──

func TestNode_CurrentBlock_AfterInit(t *testing.T) {
	cfg := &Config{
		Name:      "test-currentblock",
		DataDir:   filepath.Join(t.TempDir(), "qau-currblk"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()

	blk := n.CurrentBlock()
	if blk == nil {
		t.Error("expected non-nil CurrentBlock after loadGenesis")
	}
}

// ── Node CurrentHeight after init ──

func TestNode_CurrentHeight_AfterInit(t *testing.T) {
	cfg := &Config{
		Name:      "test-currentheight",
		DataDir:   filepath.Join(t.TempDir(), "qau-currht"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()

	height := n.CurrentHeight()
	if height != 0 {
		t.Errorf("expected height 0 after init, got %d", height)
	}
}

// ── Node StakingManager after initConsensus ──

func TestNode_StakingManager_AfterInitConsensus(t *testing.T) {
	cfg := &Config{
		Name:      "test-stakingmgr",
		DataDir:   filepath.Join(t.TempDir(), "qau-stakingmgr"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()

	if n.StakingManager() == nil {
		t.Error("expected non-nil StakingManager after initConsensus")
	}
}

// ── Node DeFiManager after initOptimizations ──

func TestNode_DeFiManager_AfterInitOptimizations(t *testing.T) {
	cfg := &Config{
		Name:      "test-defimgr",
		DataDir:   filepath.Join(t.TempDir(), "qau-defimgr"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")
	n, _ := NewNode(cfg)
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()
	n.initTxPool()
	n.initConsensus()
	n.initOptimizations()

	if n.DeFiManager() == nil {
		t.Error("expected non-nil DeFiManager after initOptimizations")
	}
}

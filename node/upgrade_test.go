// Quantaureum Node source, version 1.0.0.
// Package node — tests for upgrade/fork scheduling wiring (NODE-R2-04).
package node

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/upgrade"
)

// TestDefaultUpgradeNodeConfig verifies the default upgrade config is
// enabled with migrations active. NODE-R2-04: the default must be
// Enabled=true so the subsystem is active out of the box.
func TestDefaultUpgradeNodeConfig(t *testing.T) {
	cfg := DefaultUpgradeNodeConfig()
	if !cfg.Enabled {
		t.Error("expected default UpgradeNodeConfig.Enabled=true")
	}
	if !cfg.RunMigrations {
		t.Error("expected default UpgradeNodeConfig.RunMigrations=true")
	}
	if cfg.ChainConfigFile != "" {
		t.Errorf("expected empty default ChainConfigFile, got %q", cfg.ChainConfigFile)
	}
}

// TestDefaultConfig_IncludesUpgrade verifies DefaultConfig populates the
// Upgrade field with the default config. NODE-R2-04: previously the
// Upgrade field was zero-valued (Enabled=false), so the subsystem was
// silently disabled even though the package was fully implemented.
func TestDefaultConfig_IncludesUpgrade(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Upgrade.Enabled {
		t.Error("expected DefaultConfig.Upgrade.Enabled=true")
	}
	if !cfg.Upgrade.RunMigrations {
		t.Error("expected DefaultConfig.Upgrade.RunMigrations=true")
	}
}

// TestInitUpgrade_Disabled verifies that when Upgrade.Enabled=false,
// initUpgrade is a no-op (forkManager and migrationManager stay nil).
func TestInitUpgrade_Disabled(t *testing.T) {
	cfg := &Config{
		Name:      "test-upgrade-disabled",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:       false,
			RunMigrations: true,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	// Set up a minimal blockStore so initUpgrade could run if it were enabled.
	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = MainnetNetworkID

	if err := n.initUpgrade(); err != nil {
		t.Fatalf("initUpgrade failed: %v", err)
	}
	if n.forkManager != nil {
		t.Error("expected nil forkManager when upgrade disabled")
	}
	if n.migrationManager != nil {
		t.Error("expected nil migrationManager when upgrade disabled")
	}
}

// TestInitUpgrade_RunsMigrations verifies initUpgrade runs pending
// database migrations on a fresh MemDB and creates a MigrationManager.
// NODE-R2-04: previously migrations never ran because the upgrade
// package was not wired into the node startup path.
func TestInitUpgrade_RunsMigrations(t *testing.T) {
	cfg := &Config{
		Name:      "test-upgrade-migrations",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:       true,
			RunMigrations: true,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	// Set up a minimal blockStore with MemDB (fresh, no prior migrations).
	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = MainnetNetworkID

	if err := n.initUpgrade(); err != nil {
		t.Fatalf("initUpgrade failed: %v", err)
	}

	// MigrationManager should be created.
	if n.migrationManager == nil {
		t.Fatal("expected non-nil migrationManager after initUpgrade")
	}

	// After migration, the current version should be CurrentMigrationVersion.
	version, err := n.migrationManager.GetCurrentVersion()
	if err != nil {
		t.Fatalf("GetCurrentVersion failed: %v", err)
	}
	if version != upgrade.CurrentMigrationVersion {
		t.Errorf("expected migration version %d, got %d",
			upgrade.CurrentMigrationVersion, version)
	}

	// NeedsMigration should now be false.
	needs, err := n.migrationManager.NeedsMigration()
	if err != nil {
		t.Fatalf("NeedsMigration failed: %v", err)
	}
	if needs {
		t.Error("expected NeedsMigration=false after running migrations")
	}
}

// TestInitUpgrade_CreatesForkManager verifies initUpgrade creates a
// ForkManager from the built-in default chain config. NODE-R2-04:
// previously ForkManager was never created, so hard forks could not
// be scheduled or queried.
func TestInitUpgrade_CreatesForkManager(t *testing.T) {
	cfg := &Config{
		Name:      "test-upgrade-forkmgr",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:       true,
			RunMigrations: false, // skip migrations to isolate fork manager test
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = MainnetNetworkID

	if err := n.initUpgrade(); err != nil {
		t.Fatalf("initUpgrade failed: %v", err)
	}

	if n.forkManager == nil {
		t.Fatal("expected non-nil forkManager after initUpgrade")
	}

	// Mainnet default config has only the Genesis fork at height 0.
	rules := n.forkManager.GetRulesAtHeight(0)
	if rules == nil {
		t.Fatal("expected non-nil rules at height 0")
	}

	// ForkGenesis should be active at height 0.
	if !n.forkManager.IsForkActive(upgrade.ForkGenesis, 0) {
		t.Error("expected ForkGenesis active at height 0")
	}
}

// TestInitUpgrade_TestnetForkSchedule verifies the testnet default chain
// config includes the Quantum fork at height 100000. NODE-R2-04: this
// confirms the fork schedule is actually loaded and queryable.
func TestInitUpgrade_TestnetForkSchedule(t *testing.T) {
	cfg := &Config{
		Name:      "test-upgrade-testnet",
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:       true,
			RunMigrations: false,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = TestnetNetworkID

	if err := n.initUpgrade(); err != nil {
		t.Fatalf("initUpgrade failed: %v", err)
	}

	if n.forkManager == nil {
		t.Fatal("expected non-nil forkManager after initUpgrade")
	}

	// Testnet config has Genesis at 0 and Quantum at 100000.
	if !n.forkManager.IsForkActive(upgrade.ForkGenesis, 0) {
		t.Error("expected ForkGenesis active at height 0")
	}
	if n.forkManager.IsForkActive(upgrade.ForkQuantum, 99999) {
		t.Error("expected ForkQuantum NOT active at height 99999")
	}
	if !n.forkManager.IsForkActive(upgrade.ForkQuantum, 100000) {
		t.Error("expected ForkQuantum active at height 100000")
	}

	// Rules at height 100000 should differ from genesis rules
	// (Quantum fork enables Verkle).
	rulesPreFork := n.forkManager.GetRulesAtHeight(99999)
	rulesPostFork := n.forkManager.GetRulesAtHeight(100000)
	if rulesPreFork == nil || rulesPostFork == nil {
		t.Fatal("expected non-nil rules")
	}
	if !rulesPostFork.EnableVerkle {
		t.Error("expected EnableVerkle=true after Quantum fork at height 100000")
	}
}

// TestInitUpgrade_CustomChainConfigFile verifies initUpgrade loads a
// chain config from a custom JSON file when ChainConfigFile is set.
func TestInitUpgrade_CustomChainConfigFile(t *testing.T) {
	// Write a minimal chain config to a temp file.
	// Use the testnet config as a template so it's a valid config.
	cc := upgrade.TestnetConfig()
	tmpDir := t.TempDir()
	ccPath := filepath.Join(tmpDir, "chain_config.json")
	if err := cc.SaveChainConfig(ccPath); err != nil {
		t.Fatalf("SaveChainConfig failed: %v", err)
	}

	cfg := &Config{
		Name:      "test-upgrade-custom",
		DataDir:   t.TempDir(),
		NetworkID: TestnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:         true,
			RunMigrations:   false,
			ChainConfigFile: ccPath,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = TestnetNetworkID

	if err := n.initUpgrade(); err != nil {
		t.Fatalf("initUpgrade failed: %v", err)
	}

	if n.forkManager == nil {
		t.Fatal("expected non-nil forkManager after initUpgrade with custom config")
	}

	// The custom config is the testnet config, so Quantum fork should be
	// active at height 100000.
	if !n.forkManager.IsForkActive(upgrade.ForkQuantum, 100000) {
		t.Error("expected ForkQuantum active at height 100000 with custom testnet config")
	}
}

// TestInitUpgrade_CustomChainConfigFile_InvalidPath verifies initUpgrade
// returns an error when ChainConfigFile points to a non-existent file.
func TestInitUpgrade_CustomChainConfigFile_InvalidPath(t *testing.T) {
	cfg := &Config{
		Name:      "test-upgrade-invalid-path",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:         true,
			RunMigrations:   false,
			ChainConfigFile: "/nonexistent/path/to/chain_config.json",
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = MainnetNetworkID

	err = n.initUpgrade()
	if err == nil {
		t.Fatal("expected error from initUpgrade with invalid chain config path")
	}
}

// TestInitUpgrade_DefaultChainConfig verifies defaultChainConfig returns
// the correct built-in config for each NetworkID.
func TestInitUpgrade_DefaultChainConfig(t *testing.T) {
	tests := []struct {
		name      string
		networkID uint64
		wantChain uint64
		wantForks int // minimum number of forks
	}{
		{"mainnet", MainnetNetworkID, 1668, 1},
		{"testnet", TestnetNetworkID, 1669, 2}, // Genesis + Quantum
		{"devnet", DevnetNetworkID, 1333, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Name:      "test-default-cc-" + tt.name,
				DataDir:   t.TempDir(),
				NetworkID: tt.networkID,
				Upgrade: UpgradeNodeConfig{
					Enabled:       true,
					RunMigrations: false,
				},
			}
			n, err := NewNode(cfg)
			if err != nil {
				t.Fatalf("NewNode failed: %v", err)
			}
			defer closeNodeDB(n)

			cc := n.defaultChainConfig()
			if cc.ChainID != tt.wantChain {
				t.Errorf("network=%s: expected ChainID=%d, got %d",
					tt.name, tt.wantChain, cc.ChainID)
			}
			if len(cc.ForkSchedule) < tt.wantForks {
				t.Errorf("network=%s: expected at least %d forks, got %d",
					tt.name, tt.wantForks, len(cc.ForkSchedule))
			}
		})
	}
}

// TestForkManager_Getter verifies the ForkManager getter returns the
// initialized fork manager (or nil when disabled).
func TestForkManager_Getter(t *testing.T) {
	// Disabled config → nil.
	cfg := &Config{
		Name:      "test-getter-disabled",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		Upgrade:   UpgradeNodeConfig{Enabled: false},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = MainnetNetworkID
	if err := n.initUpgrade(); err != nil {
		t.Fatalf("initUpgrade failed: %v", err)
	}
	if n.ForkManager() != nil {
		t.Error("expected nil ForkManager() when disabled")
	}

	// Enabled config → non-nil.
	cfg2 := &Config{
		Name:      "test-getter-enabled",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:       true,
			RunMigrations: false,
		},
	}
	n2, err := NewNode(cfg2)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n2)
	n2.blockStore = block.NewBlockStore(db.NewMemDB())
	n2.chainID = MainnetNetworkID
	if err := n2.initUpgrade(); err != nil {
		t.Fatalf("initUpgrade failed: %v", err)
	}
	if n2.ForkManager() == nil {
		t.Error("expected non-nil ForkManager() when enabled")
	}
}

// TestMigrationManager_Getter verifies the MigrationManager getter returns
// the initialized migration manager (or nil when disabled).
func TestMigrationManager_Getter(t *testing.T) {
	cfg := &Config{
		Name:      "test-migration-getter",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:       true,
			RunMigrations: true,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = MainnetNetworkID
	if err := n.initUpgrade(); err != nil {
		t.Fatalf("initUpgrade failed: %v", err)
	}
	if n.MigrationManager() == nil {
		t.Error("expected non-nil MigrationManager() when enabled")
	}
}

// TestInitUpgrade_Idempotent verifies calling initUpgrade twice does not
// cause errors or duplicate migrations. NODE-R2-04: idempotency is
// important because Start() may be retried after a transient failure.
func TestInitUpgrade_Idempotent(t *testing.T) {
	cfg := &Config{
		Name:      "test-upgrade-idempotent",
		DataDir:   t.TempDir(),
		NetworkID: MainnetNetworkID,
		Upgrade: UpgradeNodeConfig{
			Enabled:       true,
			RunMigrations: true,
		},
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)
	n.blockStore = block.NewBlockStore(db.NewMemDB())
	n.chainID = MainnetNetworkID

	// First call runs the migration.
	if err := n.initUpgrade(); err != nil {
		t.Fatalf("first initUpgrade failed: %v", err)
	}
	version1, _ := n.migrationManager.GetCurrentVersion()

	// Second call should not error — NeedsMigration returns false.
	if err := n.initUpgrade(); err != nil {
		t.Fatalf("second initUpgrade failed: %v", err)
	}
	version2, _ := n.migrationManager.GetCurrentVersion()

	if version1 != version2 {
		t.Errorf("expected idempotent migration version %d, got %d", version1, version2)
	}
}

// TestInitUpgrade_PersistsAcrossRestart simulates a node restart to verify
// migrations persist in the database. NODE-R2-04: this is the key property
// — migrations must be durable so they don't re-run on every startup.
func TestInitUpgrade_PersistsAcrossRestart(t *testing.T) {
	// Use a real BoltDB so the migration version persists.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "blocks")
	boltDB, err := db.NewBoltDB(dbPath)
	if err != nil {
		t.Fatalf("NewBoltDB failed: %v", err)
	}

	// First "startup": run migrations.
	mm1 := upgrade.NewMigrationManager(boltDB)
	needs, err := mm1.NeedsMigration()
	if err != nil {
		t.Fatalf("NeedsMigration failed: %v", err)
	}
	if !needs {
		t.Fatal("expected NeedsMigration=true on fresh database")
	}
	if err := mm1.Migrate(); err != nil && err != upgrade.ErrNoMigrationNeeded {
		t.Fatalf("Migrate failed: %v", err)
	}

	// Close and reopen the database to simulate a restart.
	boltDB.Close()
	boltDB2, err := db.NewBoltDB(dbPath)
	if err != nil {
		t.Fatalf("NewBoltDB (reopen) failed: %v", err)
	}
	defer boltDB2.Close()

	// Second "startup": migrations should not be needed.
	mm2 := upgrade.NewMigrationManager(boltDB2)
	needs2, err := mm2.NeedsMigration()
	if err != nil {
		t.Fatalf("NeedsMigration (restart) failed: %v", err)
	}
	if needs2 {
		t.Error("expected NeedsMigration=false after restart (migrations should persist)")
	}

	version, _ := mm2.GetCurrentVersion()
	if version != upgrade.CurrentMigrationVersion {
		t.Errorf("expected persisted version %d, got %d",
			upgrade.CurrentMigrationVersion, version)
	}
}

// Ensure the test binary doesn't fail on Windows when temp dirs have
// backslashes — filepath.Join handles this correctly.
var _ = os.PathSeparator

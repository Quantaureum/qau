// Quantaureum Node source, version 1.0.0.
package node

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/bridge"
)

// TestParseChainURLPairs verifies parsing of comma-separated "chainID=value"
// pairs into a map. Covers P0-3 environment variable override parsing.
func TestParseChainURLPairs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		base    map[bridge.ChainID]string
		wantLen int
		wantQAU string
		wantEth string
	}{
		{
			name:    "two pairs from empty base",
			input:   "quantaureum=http://localhost:8545,ethereum=http://localhost:8546",
			base:    nil,
			wantLen: 2,
			wantQAU: "http://localhost:8545",
			wantEth: "http://localhost:8546",
		},
		{
			name:    "single pair",
			input:   "quantaureum=http://127.0.0.1:8545",
			base:    nil,
			wantLen: 1,
			wantQAU: "http://127.0.0.1:8545",
		},
		{
			name:    "merge into existing base",
			input:   "ethereum=http://localhost:8546",
			base:    map[bridge.ChainID]string{"quantaureum": "http://existing:8545"},
			wantLen: 2,
			wantQAU: "http://existing:8545",
			wantEth: "http://localhost:8546",
		},
		{
			name:    "override existing base value",
			input:   "quantaureum=http://new:8545",
			base:    map[bridge.ChainID]string{"quantaureum": "http://old:8545"},
			wantLen: 1,
			wantQAU: "http://new:8545",
		},
		{
			name:    "empty input returns base unchanged",
			input:   "",
			base:    map[bridge.ChainID]string{"quantaureum": "http://localhost:8545"},
			wantLen: 1,
			wantQAU: "http://localhost:8545",
		},
		{
			name:    "skip malformed pairs (no equals sign)",
			input:   "quantaureum=http://localhost:8545,badpair",
			base:    nil,
			wantLen: 1,
			wantQAU: "http://localhost:8545",
		},
		{
			name:    "skip pairs with empty chainID",
			input:   "=http://localhost:8545",
			base:    nil,
			wantLen: 0,
		},
		{
			name:    "skip pairs with empty value",
			input:   "quantaureum=",
			base:    nil,
			wantLen: 0,
		},
		{
			name:    "trim whitespace",
			input:   " quantaureum = http://localhost:8545 , ethereum = http://localhost:8546 ",
			base:    nil,
			wantLen: 2,
			wantQAU: "http://localhost:8545",
			wantEth: "http://localhost:8546",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseChainURLPairs(tt.input, tt.base)
			if len(result) != tt.wantLen {
				t.Fatalf("len(result) = %d, want %d; result=%v", len(result), tt.wantLen, result)
			}
			if tt.wantQAU != "" {
				if got := result["quantaureum"]; got != tt.wantQAU {
					t.Errorf("result[quantaureum] = %q, want %q", got, tt.wantQAU)
				}
			}
			if tt.wantEth != "" {
				if got := result["ethereum"]; got != tt.wantEth {
					t.Errorf("result[ethereum] = %q, want %q", got, tt.wantEth)
				}
			}
		})
	}
}

// TestBuildBridgeConfig_Defaults verifies that when the config file has no
// "bridge" section, buildBridgeConfig returns DefaultBridgeConfig() values.
func TestBuildBridgeConfig_Defaults(t *testing.T) {
	n := &Node{config: &Config{}}
	cfg := n.buildBridgeConfig()

	if cfg == nil {
		t.Fatal("buildBridgeConfig returned nil")
	}
	// DefaultBridgeConfig values.
	if cfg.GasLimit != 2000000 {
		t.Errorf("GasLimit = %d, want 2000000", cfg.GasLimit)
	}
	if cfg.ConfirmationsRequired != 10 {
		t.Errorf("ConfirmationsRequired = %d, want 10", cfg.ConfirmationsRequired)
	}
	if cfg.MessageExpiration != 3600*24 {
		t.Errorf("MessageExpiration = %d, want %d", cfg.MessageExpiration, 3600*24)
	}
	if cfg.PollingInterval != 15*time.Second {
		t.Errorf("PollingInterval = %v, want %v", cfg.PollingInterval, 15*time.Second)
	}
	if cfg.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", cfg.MaxRetries)
	}
	if len(cfg.NodeURLs) != 0 {
		t.Errorf("NodeURLs len = %d, want 0 (empty config should have no adapters)", len(cfg.NodeURLs))
	}
	if cfg.InitializerAddress != "" {
		t.Errorf("InitializerAddress = %q, want empty", cfg.InitializerAddress)
	}
}

// TestBuildBridgeConfig_FromConfig verifies that bridge config fields are
// loaded from n.config.Bridge (the config file's "bridge" section).
func TestBuildBridgeConfig_FromConfig(t *testing.T) {
	n := &Node{
		config: &Config{
			Bridge: BridgeNodeConfig{
				NodeURLs: map[string]string{
					"quantaureum": "http://localhost:8545",
					"ethereum":    "http://localhost:8546",
				},
				BridgeContractAddresses: map[string]string{
					"quantaureum": "0xBridgeQau",
					"ethereum":    "0xBridgeEth",
				},
				GasLimit:              5000000,
				ConfirmationsRequired: 20,
				MessageExpiration:     7200,
				PollingInterval:       30,
				MaxRetries:            10,
				InitializerAddress:    "0xInitializer",
			},
		},
	}
	cfg := n.buildBridgeConfig()

	if len(cfg.NodeURLs) != 2 {
		t.Fatalf("NodeURLs len = %d, want 2", len(cfg.NodeURLs))
	}
	if got := cfg.NodeURLs["quantaureum"]; got != "http://localhost:8545" {
		t.Errorf("NodeURLs[quantaureum] = %q, want http://localhost:8545", got)
	}
	if got := cfg.NodeURLs["ethereum"]; got != "http://localhost:8546" {
		t.Errorf("NodeURLs[ethereum] = %q, want http://localhost:8546", got)
	}
	if len(cfg.BridgeContractAddresses) != 2 {
		t.Fatalf("BridgeContractAddresses len = %d, want 2", len(cfg.BridgeContractAddresses))
	}
	if got := cfg.BridgeContractAddresses["quantaureum"]; got != "0xBridgeQau" {
		t.Errorf("BridgeContractAddresses[quantaureum] = %q, want 0xBridgeQau", got)
	}
	if cfg.GasLimit != 5000000 {
		t.Errorf("GasLimit = %d, want 5000000", cfg.GasLimit)
	}
	if cfg.ConfirmationsRequired != 20 {
		t.Errorf("ConfirmationsRequired = %d, want 20", cfg.ConfirmationsRequired)
	}
	if cfg.MessageExpiration != 7200 {
		t.Errorf("MessageExpiration = %d, want 7200", cfg.MessageExpiration)
	}
	if cfg.PollingInterval != 30*time.Second {
		t.Errorf("PollingInterval = %v, want %v", cfg.PollingInterval, 30*time.Second)
	}
	if cfg.MaxRetries != 10 {
		t.Errorf("MaxRetries = %d, want 10", cfg.MaxRetries)
	}
	if cfg.InitializerAddress != "0xInitializer" {
		t.Errorf("InitializerAddress = %q, want 0xInitializer", cfg.InitializerAddress)
	}
}

// TestBuildBridgeConfig_EnvOverrides verifies that environment variables take
// highest priority, overriding both defaults and config file values.
func TestBuildBridgeConfig_EnvOverrides(t *testing.T) {
	// Set env vars (clean up after test).
	os.Setenv("QAU_BRIDGE_NODE_URLS", "quantaureum=http://env-qau:8545,ethereum=http://env-eth:8546")
	os.Setenv("QAU_BRIDGE_CONTRACT_ADDRESSES", "quantaureum=0xEnvQau,ethereum=0xEnvEth")
	os.Setenv("QAU_BRIDGE_INITIALIZER_ADDRESS", "0xEnvInitializer")
	defer func() {
		os.Unsetenv("QAU_BRIDGE_NODE_URLS")
		os.Unsetenv("QAU_BRIDGE_CONTRACT_ADDRESSES")
		os.Unsetenv("QAU_BRIDGE_INITIALIZER_ADDRESS")
	}()

	// Config file also has values — env should win.
	n := &Node{
		config: &Config{
			Bridge: BridgeNodeConfig{
				NodeURLs: map[string]string{
					"quantaureum": "http://config-qau:8545",
				},
				InitializerAddress: "0xConfigInitializer",
			},
		},
	}
	cfg := n.buildBridgeConfig()

	// Env URL should override config URL for quantaureum, and add ethereum.
	if got := cfg.NodeURLs["quantaureum"]; got != "http://env-qau:8545" {
		t.Errorf("NodeURLs[quantaureum] = %q, want http://env-qau:8545 (env override)", got)
	}
	if got := cfg.NodeURLs["ethereum"]; got != "http://env-eth:8546" {
		t.Errorf("NodeURLs[ethereum] = %q, want http://env-eth:8546 (env override)", got)
	}
	if got := cfg.BridgeContractAddresses["quantaureum"]; got != "0xEnvQau" {
		t.Errorf("BridgeContractAddresses[quantaureum] = %q, want 0xEnvQau (env override)", got)
	}
	if cfg.InitializerAddress != "0xEnvInitializer" {
		t.Errorf("InitializerAddress = %q, want 0xEnvInitializer (env override)", cfg.InitializerAddress)
	}
}

// TestBuildBridgeConfig_ZeroValuesKeepDefaults verifies that zero-valued
// scalar fields in the config do not override the defaults.
func TestBuildBridgeConfig_ZeroValuesKeepDefaults(t *testing.T) {
	n := &Node{
		config: &Config{
			Bridge: BridgeNodeConfig{
				// Only set NodeURLs, leave all scalar fields as zero.
				NodeURLs: map[string]string{
					"quantaureum": "http://localhost:8545",
				},
			},
		},
	}
	cfg := n.buildBridgeConfig()

	// NodeURLs should be loaded from config.
	if len(cfg.NodeURLs) != 1 {
		t.Fatalf("NodeURLs len = %d, want 1", len(cfg.NodeURLs))
	}
	// Scalar fields should keep defaults (zero values don't override).
	if cfg.GasLimit != 2000000 {
		t.Errorf("GasLimit = %d, want 2000000 (default)", cfg.GasLimit)
	}
	if cfg.ConfirmationsRequired != 10 {
		t.Errorf("ConfirmationsRequired = %d, want 10 (default)", cfg.ConfirmationsRequired)
	}
	if cfg.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5 (default)", cfg.MaxRetries)
	}
}

// TestLoadConfig_BridgeSection verifies that a JSON config file with a "bridge"
// section is correctly loaded into Config.Bridge.
//
// DoD 1: node config contains a `bridge` section and LoadConfig parses it correctly.
func TestLoadConfig_BridgeSection(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	// Write a config file that includes a "bridge" section.
	jsonContent := `{
		"name": "test-node",
		"networkId": 1333,
		"bridge": {
			"nodeUrls": {
				"quantaureum": "http://127.0.0.1:8545",
				"ethereum": "http://localhost:8546"
			},
			"bridgeContractAddresses": {
				"quantaureum": "0xBridgeQau",
				"ethereum": "0xBridgeEth"
			},
			"gasLimit": 3000000,
			"confirmationsRequired": 15,
			"messageExpiration": 7200,
			"pollingInterval": 30,
			"maxRetries": 8,
			"initializerAddress": "0xTestInitializer"
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(jsonContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Verify the bridge section was loaded.
	if len(cfg.Bridge.NodeURLs) != 2 {
		t.Fatalf("Bridge.NodeURLs len = %d, want 2", len(cfg.Bridge.NodeURLs))
	}
	if got := cfg.Bridge.NodeURLs["quantaureum"]; got != "http://127.0.0.1:8545" {
		t.Errorf("Bridge.NodeURLs[quantaureum] = %q, want http://127.0.0.1:8545", got)
	}
	if got := cfg.Bridge.NodeURLs["ethereum"]; got != "http://localhost:8546" {
		t.Errorf("Bridge.NodeURLs[ethereum] = %q, want http://localhost:8546", got)
	}
	if got := cfg.Bridge.BridgeContractAddresses["quantaureum"]; got != "0xBridgeQau" {
		t.Errorf("Bridge.BridgeContractAddresses[quantaureum] = %q, want 0xBridgeQau", got)
	}
	if cfg.Bridge.GasLimit != 3000000 {
		t.Errorf("Bridge.GasLimit = %d, want 3000000", cfg.Bridge.GasLimit)
	}
	if cfg.Bridge.ConfirmationsRequired != 15 {
		t.Errorf("Bridge.ConfirmationsRequired = %d, want 15", cfg.Bridge.ConfirmationsRequired)
	}
	if cfg.Bridge.MessageExpiration != 7200 {
		t.Errorf("Bridge.MessageExpiration = %d, want 7200", cfg.Bridge.MessageExpiration)
	}
	if cfg.Bridge.PollingInterval != 30 {
		t.Errorf("Bridge.PollingInterval = %d, want 30", cfg.Bridge.PollingInterval)
	}
	if cfg.Bridge.MaxRetries != 8 {
		t.Errorf("Bridge.MaxRetries = %d, want 8", cfg.Bridge.MaxRetries)
	}
	if cfg.Bridge.InitializerAddress != "0xTestInitializer" {
		t.Errorf("Bridge.InitializerAddress = %q, want 0xTestInitializer", cfg.Bridge.InitializerAddress)
	}

	// Verify buildBridgeConfig uses the loaded values.
	n := &Node{config: cfg}
	bc := n.buildBridgeConfig()
	if bc.GasLimit != 3000000 {
		t.Errorf("buildBridgeConfig: GasLimit = %d, want 3000000", bc.GasLimit)
	}
	if len(bc.NodeURLs) != 2 {
		t.Errorf("buildBridgeConfig: NodeURLs len = %d, want 2", len(bc.NodeURLs))
	}
	if bc.InitializerAddress != "0xTestInitializer" {
		t.Errorf("buildBridgeConfig: InitializerAddress = %q, want 0xTestInitializer", bc.InitializerAddress)
	}
}

// TestLoadConfig_NoBridgeSection verifies backward compatibility: a config
// file without a "bridge" section loads successfully with an empty BridgeNodeConfig.
func TestLoadConfig_NoBridgeSection(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	jsonContent := `{
		"name": "test-node-no-bridge",
		"networkId": 1333
	}`
	if err := os.WriteFile(cfgPath, []byte(jsonContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Bridge section should be zero-valued (no adapters).
	if len(cfg.Bridge.NodeURLs) != 0 {
		t.Errorf("Bridge.NodeURLs len = %d, want 0 (no bridge section)", len(cfg.Bridge.NodeURLs))
	}
	if cfg.Bridge.GasLimit != 0 {
		t.Errorf("Bridge.GasLimit = %d, want 0 (no bridge section)", cfg.Bridge.GasLimit)
	}

	// buildBridgeConfig should fall back to defaults.
	n := &Node{config: cfg}
	bc := n.buildBridgeConfig()
	if bc.GasLimit != 2000000 {
		t.Errorf("buildBridgeConfig: GasLimit = %d, want 2000000 (default)", bc.GasLimit)
	}
}

// TestBuildBridgeConfig_SkipsEmptyURLs verifies that empty URLs in the config
// are skipped, so bridge.Initialize() doesn't fail with "empty node URL".
// This allows config files to use "" as a placeholder for unconfigured chains.
func TestBuildBridgeConfig_SkipsEmptyURLs(t *testing.T) {
	n := &Node{
		config: &Config{
			Bridge: BridgeNodeConfig{
				NodeURLs: map[string]string{
					"quantaureum": "http://127.0.0.1:8545",
					"ethereum":    "", // placeholder, should be skipped
					"polygon":     "", // placeholder, should be skipped
				},
				BridgeContractAddresses: map[string]string{
					"quantaureum": "0xBridgeQau",
					"ethereum":    "0xBridgeEth", // should be skipped (no URL for ethereum)
				},
			},
		},
	}
	cfg := n.buildBridgeConfig()

	// Only quantaureum should have a URL.
	if len(cfg.NodeURLs) != 1 {
		t.Fatalf("NodeURLs len = %d, want 1 (empty URLs should be skipped)", len(cfg.NodeURLs))
	}
	if _, exists := cfg.NodeURLs["ethereum"]; exists {
		t.Error("NodeURLs[ethereum] should not exist (empty URL skipped)")
	}
	if _, exists := cfg.NodeURLs["polygon"]; exists {
		t.Error("NodeURLs[polygon] should not exist (empty URL skipped)")
	}

	// Contract addresses only for chains with a URL.
	if len(cfg.BridgeContractAddresses) != 1 {
		t.Fatalf("BridgeContractAddresses len = %d, want 1", len(cfg.BridgeContractAddresses))
	}
	if _, exists := cfg.BridgeContractAddresses["ethereum"]; exists {
		t.Error("BridgeContractAddresses[ethereum] should not exist (no URL for ethereum)")
	}
}

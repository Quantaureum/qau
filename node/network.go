// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/quantaureum/qau/types"
)

const (
	MainnetGenesisHash = "94e178e6faec5ed2c51e109b9d465c613620df245fee665fa77a28158b33e506"
	TestnetGenesisHash = "6e0fdada5beaaf93ed556b82a0daa405b28cb56e3eda2609b820e92683768384"
)

// Bootnode enodes are DEPLOYMENT TOPOLOGY (real server IPs + node identity
// keys) and are intentionally NOT hard-coded here: they are supplied
// per-deployment through the config's "bootstrapPeers" field, and running
// nodes discover peers through the persisted nodes file and UDP discovery.
// R33 topology cleanup (2026-11-01): the previously hard-coded enodes were
// dead data — NetworkPresetByName has no production callers — and were
// removed; operators maintain their real bootnode list out of band.
var mainnetBootnodes = []string{}

var testnetBootnodes = []string{}

// NetworkPreset describes the client's built-in network identity.
type NetworkPreset struct {
	Name                string
	NetworkID           uint64
	ChainID             uint64
	ExpectedGenesisHash string
	HasBuiltInGenesis   bool
	DefaultBootnodes    []string
}

// NetworkPresetByName resolves a network name to its built-in preset.
func NetworkPresetByName(name string) (NetworkPreset, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case NetworkMainnet:
		return NetworkPreset{
			Name:                NetworkMainnet,
			NetworkID:           MainnetNetworkID,
			ChainID:             MainnetNetworkID,
			ExpectedGenesisHash: MainnetGenesisHash,
			HasBuiltInGenesis:   true,
			DefaultBootnodes:    mainnetBootnodes,
		}, true
	case NetworkTestnet:
		return NetworkPreset{
			Name:                NetworkTestnet,
			NetworkID:           TestnetNetworkID,
			ChainID:             TestnetNetworkID,
			ExpectedGenesisHash: TestnetGenesisHash,
			HasBuiltInGenesis:   true,
			DefaultBootnodes:    testnetBootnodes,
		}, true
	case NetworkDev:
		return NetworkPreset{
			Name:      NetworkDev,
			NetworkID: DevnetNetworkID,
			ChainID:   DevnetNetworkID,
		}, true
	default:
		return NetworkPreset{}, false
	}
}

// BuiltInGenesis returns the public genesis embedded in the client.
func BuiltInGenesis(network string) (*Genesis, error) {
	preset, ok := NetworkPresetByName(network)
	if !ok || !preset.HasBuiltInGenesis {
		return nil, fmt.Errorf("network %q has no built-in genesis", network)
	}

	switch preset.Name {
	case NetworkMainnet:
		return mainnetGenesis(), nil
	case NetworkTestnet:
		return testnetGenesis(), nil
	default:
		return nil, fmt.Errorf("network %q has no built-in genesis", network)
	}
}

func decodeGenesisHash(value string) (types.Hash, error) {
	raw := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	bytes, err := hex.DecodeString(raw)
	if err != nil || len(bytes) != types.HashLength {
		return types.Hash{}, fmt.Errorf("invalid 32-byte genesis hash %q", value)
	}
	return types.BytesToHash(bytes), nil
}

// ValidateGenesisForNetwork enforces the canonical genesis for named presets.
// Empty network names retain the legacy custom-network behavior.
func ValidateGenesisForNetwork(network string, genesis *Genesis) error {
	if genesis == nil {
		return fmt.Errorf("genesis is nil")
	}

	preset, ok := NetworkPresetByName(network)
	if !ok {
		return nil
	}

	if genesis.ChainID != preset.ChainID {
		return fmt.Errorf("genesis chainId %d does not match %s chainId %d", genesis.ChainID, preset.Name, preset.ChainID)
	}
	if genesis.NetworkID != 0 && genesis.NetworkID != preset.NetworkID {
		return fmt.Errorf("genesis networkId %d does not match %s networkId %d", genesis.NetworkID, preset.Name, preset.NetworkID)
	}

	if !preset.HasBuiltInGenesis {
		return nil
	}

	expected, err := decodeGenesisHash(preset.ExpectedGenesisHash)
	if err != nil {
		return err
	}
	if genesis.ConfigurationHash() != expected {
		return fmt.Errorf("genesis configuration hash mismatch for %s: expected %s, got %s",
			preset.Name, expected.String(), genesis.ConfigurationHash().String())
	}

	builtIn, err := BuiltInGenesis(preset.Name)
	if err != nil {
		return err
	}
	if genesis.MinSignatures != builtIn.MinSignatures {
		return fmt.Errorf("genesis minSignatures %d does not match the %s value %d",
			genesis.MinSignatures, preset.Name, builtIn.MinSignatures)
	}

	return nil
}

// LoadGenesisForConfig selects the built-in or external genesis for a config.
// It returns nil for a custom network with no explicit genesis file; the node
// then applies its legacy data-directory fallback.
func LoadGenesisForConfig(cfg *Config) (*Genesis, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}

	preset, isPreset := NetworkPresetByName(cfg.Network)
	if isPreset && preset.HasBuiltInGenesis && cfg.GenesisFile == "" {
		return BuiltInGenesis(preset.Name)
	}

	if cfg.GenesisFile != "" {
		genesis, err := LoadGenesis(cfg.GenesisFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load genesis from %s: %w", cfg.GenesisFile, err)
		}
		if err := ValidateGenesisForNetwork(cfg.Network, genesis); err != nil {
			return nil, fmt.Errorf("invalid genesis for network %q: %w", cfg.Network, err)
		}
		if cfg.NetworkID != 0 && genesis.NetworkID != 0 && cfg.NetworkID != genesis.NetworkID {
			return nil, fmt.Errorf("config networkId %d conflicts with genesis networkId %d", cfg.NetworkID, genesis.NetworkID)
		}
		return genesis, nil
	}

	if preset.Name == NetworkDev {
		return DevGenesis(), nil
	}

	return nil, nil
}

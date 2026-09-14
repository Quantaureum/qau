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

var mainnetBootnodes = []string{
	"enode://65b6dcc0aeb5e0458996d3c6934a36c5213caf8074e4153c3f9e0f5f225789f7@163.192.142.82:9000",
	"enode://3ef6a7c05e64d2218ce250ae345c05bee2836b3dd24843f6840b1c26773875a1@217.142.189.163:9000",
	"enode://d552745f67d0dfebe9b407a2fad4ff5340ce6273e4d7920ff7080115be9186f1@149.118.59.251:9000",
	"enode://57879ea427537fd3690ed35353a32d1e87035f696995cd4da5126cb2fee05d3d@149.118.61.186:9000",
	"enode://ebf49fb21426f10430e48bf513f07750dc88dfa15c1d65d322b9f922ff1d61da@149.118.62.16:9000",
	"enode://949dcd8f80c032022d2bb7836afc1de9628c49d2f3325131d45d73d5908451e5@149.118.55.2:9000",
}

var testnetBootnodes = []string{
	"enode://a885858e043178c7c6f6a50471612391bcd2637a0ac2aa149a6eff4f12c0915f@149.118.53.59:9000",
}

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

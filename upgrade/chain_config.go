// Quantaureum Node source, version 1.0.0.
// Package upgrade implements the upgrade mechanism for Quantaureum blockchain.
package upgrade

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

// ChainConfig errors
var (
	ErrInvalidChainConfig = errors.New("invalid chain configuration")
	ErrForkScheduleEmpty  = errors.New("fork schedule is empty")
	ErrIncompatibleFork   = errors.New("incompatible fork configuration")
)

// ChainConfig represents the chain configuration including fork schedule
type ChainConfig struct {
	// ChainID is the unique identifier for this chain
	ChainID uint64 `json:"chainId"`

	// NetworkName is the human-readable network name
	NetworkName string `json:"networkName"`

	// ForkSchedule contains the scheduled forks
	ForkSchedule []*ForkScheduleEntry `json:"forkSchedule"`

	// MinCompatibleVersion is the minimum compatible client version
	MinCompatibleVersion string `json:"minCompatibleVersion,omitempty"`

	// DeprecatedForks contains forks that are no longer active but kept for compatibility
	DeprecatedForks []ForkID `json:"deprecatedForks,omitempty"`

	// mu protects concurrent access
	mu sync.RWMutex `json:"-"`
}

// ForkScheduleEntry represents a scheduled fork
type ForkScheduleEntry struct {
	ForkID           ForkID     `json:"forkId"`
	Name             string     `json:"name"`
	ActivationHeight uint64     `json:"activationHeight"`
	Description      string     `json:"description"`
	Rules            *ForkRules `json:"rules,omitempty"`

	// BackwardCompatible indicates if this fork maintains backward compatibility
	BackwardCompatible bool `json:"backwardCompatible,omitempty"`

	// RequiredVersion is the minimum client version required for this fork
	RequiredVersion string `json:"requiredVersion,omitempty"`

	// Deprecated indicates if this fork is deprecated
	Deprecated bool `json:"deprecated,omitempty"`
}

// MainnetConfig returns the mainnet chain configuration
func MainnetConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:     1668, // SECURITY (audit NODE-05): was 1 (Ethereum mainnet) — Quantaureum mainnet is 1668
		NetworkName: "Quantaureum Mainnet",
		ForkSchedule: []*ForkScheduleEntry{
			{
				ForkID:           ForkGenesis,
				Name:             "Genesis",
				ActivationHeight: 0,
				Description:      "Initial network launch",
				Rules:            DefaultForkRules(),
			},
		},
	}
}

// TestnetConfig returns the testnet chain configuration
func TestnetConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:     1669,
		NetworkName: "Quantaureum Testnet",
		ForkSchedule: []*ForkScheduleEntry{
			{
				ForkID:           ForkGenesis,
				Name:             "Genesis",
				ActivationHeight: 0,
				Description:      "Initial network launch",
				Rules:            DefaultForkRules(),
			},
			{
				ForkID:           ForkQuantum,
				Name:             "Quantum",
				ActivationHeight: 100000,
				Description:      "Post-quantum cryptography upgrade",
				Rules: &ForkRules{
					MaxBlockGas:             50000000,
					MinGasPrice:             1000000000,
					BlockTime:               12,
					MaxTxSize:               262144, // 256KB
					ValidatorMinStake:       1000000000000000000,
					SlashingPenalty:         1000,
					EnableParallelExecution: false,
					EnableVerkle:            true,
				},
			},
		},
	}
}

// DevnetConfig returns the devnet chain configuration
func DevnetConfig() *ChainConfig {
	return &ChainConfig{
		ChainID:     1333, // SECURITY (audit NODE-05): was 3 (Ropsten legacy) — Quantaureum devnet is 1333
		NetworkName: "Quantaureum Devnet",
		ForkSchedule: []*ForkScheduleEntry{
			{
				ForkID:           ForkGenesis,
				Name:             "Genesis",
				ActivationHeight: 0,
				Description:      "Initial network launch",
				Rules: &ForkRules{
					MaxBlockGas:             100000000,
					MinGasPrice:             0,
					BlockTime:               12,     // P3-LOCALNET FIX: must match consensus.SlotDuration (12s). Was 1, causing block_validator's maxTime = parent.ts + slotGap*1 + 15 to be far smaller than block_producer's slot-derived timestamp (slotGap*12) → every block rejected as "timestamp in future" on sync.
					MaxTxSize:               524288, // 512KB
					ValidatorMinStake:       1000000000000000,
					SlashingPenalty:         500,
					EnableParallelExecution: true,
					EnableVerkle:            true,
				},
			},
		},
	}
}

// LoadChainConfig loads chain configuration from a file.
//
// SECURITY (audit NODE-05): The previous implementation just unmarshaled JSON
// and returned the result without sorting the fork schedule or validating the
// config. A malformed or attacker-supplied config file could leave ForkSchedule
// unsorted (breaking GetForkAtHeight/GetRulesAtHeight, which assume ascending
// order) or carry an invalid ChainID / missing genesis fork. We now sort the
// schedule defensively and run Validate() before returning.
func LoadChainConfig(path string) (*ChainConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return nil, err
	}

	var config ChainConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Sort fork schedule by activation height so GetForkAtHeight / GetRulesAtHeight
	// (which scan linearly assuming ascending order) work correctly even if the
	// file was hand-edited out of order.
	sort.Slice(config.ForkSchedule, func(i, j int) bool {
		return config.ForkSchedule[i].ActivationHeight < config.ForkSchedule[j].ActivationHeight
	})

	// Validate the loaded configuration (ChainID != 0, genesis at height 0,
	// no duplicate fork IDs, ascending heights).
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidChainConfig, err)
	}

	return &config, nil
}

// SaveChainConfig saves chain configuration to a file
func (c *ChainConfig) SaveChainConfig(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// ToForkManager creates a ForkManager from the chain configuration.
//
// R40-P1-05 (2026-08-03): acquire `c.mu.RLock` while iterating `ForkSchedule`.
// `ChainConfig` is constructed once at startup and, in practice, isn't
// mutated afterward — but without a read lock here, ANY future setter that
// rewrites / appends to `ForkSchedule` would race this iteration (data race
// on the slice header / element pointers). The RLock is cheap (uncontended
// on the read-only hot path) and closes the race mechanically via
// `go test -race` instead of relying on a convention nobody enforces.
func (c *ChainConfig) ToForkManager() *ForkManager {
	c.mu.RLock()
	defer c.mu.RUnlock()

	fm := &ForkManager{
		forks:       make(map[ForkID]*Fork),
		sortedForks: make([]*Fork, 0),
	}

	for _, entry := range c.ForkSchedule {
		fork := &Fork{
			ID:               entry.ForkID,
			Name:             entry.Name,
			ActivationHeight: entry.ActivationHeight,
			Description:      entry.Description,
			Rules:            entry.Rules,
		}
		if fork.Rules == nil {
			fork.Rules = DefaultForkRules()
		}
		fm.forks[fork.ID] = fork
		fm.sortedForks = append(fm.sortedForks, fork)
	}

	return fm
}

// GetForkAtHeight returns the fork entry active at the given height
func (c *ChainConfig) GetForkAtHeight(height uint64) *ForkScheduleEntry {
	var active *ForkScheduleEntry
	for _, entry := range c.ForkSchedule {
		if height >= entry.ActivationHeight {
			active = entry
		}
	}
	return active
}

// AddFork adds a new fork to the schedule
func (c *ChainConfig) AddFork(entry *ForkScheduleEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ForkSchedule = append(c.ForkSchedule, entry)
	// Sort by activation height
	sort.Slice(c.ForkSchedule, func(i, j int) bool {
		return c.ForkSchedule[i].ActivationHeight < c.ForkSchedule[j].ActivationHeight
	})
}

// RemoveFork removes a fork from the schedule by ID
func (c *ChainConfig) RemoveFork(forkID ForkID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, entry := range c.ForkSchedule {
		if entry.ForkID == forkID {
			c.ForkSchedule = append(c.ForkSchedule[:i], c.ForkSchedule[i+1:]...)
			return true
		}
	}
	return false
}

// GetForkByID returns a fork entry by its ID
func (c *ChainConfig) GetForkByID(forkID ForkID) *ForkScheduleEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, entry := range c.ForkSchedule {
		if entry.ForkID == forkID {
			return entry
		}
	}
	return nil
}

// GetRulesAtHeight returns the consensus rules active at the given height
func (c *ChainConfig) GetRulesAtHeight(height uint64) *ForkRules {
	entry := c.GetForkAtHeight(height)
	if entry == nil || entry.Rules == nil {
		return DefaultForkRules()
	}
	return entry.Rules
}

// IsBackwardCompatible checks if the chain config is backward compatible at the given height
func (c *ChainConfig) IsBackwardCompatible(height uint64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, entry := range c.ForkSchedule {
		if height >= entry.ActivationHeight && !entry.BackwardCompatible {
			return false
		}
	}
	return true
}

// GetRequiredVersion returns the minimum required client version at the given height
func (c *ChainConfig) GetRequiredVersion(height uint64) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var requiredVersion string
	for _, entry := range c.ForkSchedule {
		if height >= entry.ActivationHeight && entry.RequiredVersion != "" {
			requiredVersion = entry.RequiredVersion
		}
	}
	return requiredVersion
}

// Validate validates the chain configuration
func (c *ChainConfig) Validate() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.ChainID == 0 {
		return ErrInvalidChainConfig
	}

	if len(c.ForkSchedule) == 0 {
		return ErrForkScheduleEmpty
	}

	// Check for duplicate fork IDs
	seen := make(map[ForkID]bool)
	for _, entry := range c.ForkSchedule {
		if seen[entry.ForkID] {
			return ErrInvalidChainConfig
		}
		seen[entry.ForkID] = true
	}

	// Check that forks are sorted by activation height
	for i := 1; i < len(c.ForkSchedule); i++ {
		if c.ForkSchedule[i].ActivationHeight < c.ForkSchedule[i-1].ActivationHeight {
			return ErrInvalidChainConfig
		}
	}

	// Check that genesis fork exists at height 0
	if len(c.ForkSchedule) > 0 && c.ForkSchedule[0].ActivationHeight != 0 {
		return ErrInvalidChainConfig
	}

	return nil
}

// Clone creates a deep copy of the chain configuration
func (c *ChainConfig) Clone() *ChainConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	clone := &ChainConfig{
		ChainID:              c.ChainID,
		NetworkName:          c.NetworkName,
		MinCompatibleVersion: c.MinCompatibleVersion,
		ForkSchedule:         make([]*ForkScheduleEntry, len(c.ForkSchedule)),
		DeprecatedForks:      make([]ForkID, len(c.DeprecatedForks)),
	}

	for i, entry := range c.ForkSchedule {
		clone.ForkSchedule[i] = &ForkScheduleEntry{
			ForkID:             entry.ForkID,
			Name:               entry.Name,
			ActivationHeight:   entry.ActivationHeight,
			Description:        entry.Description,
			BackwardCompatible: entry.BackwardCompatible,
			RequiredVersion:    entry.RequiredVersion,
			Deprecated:         entry.Deprecated,
		}
		if entry.Rules != nil {
			clone.ForkSchedule[i].Rules = entry.Rules.Clone()
		}
	}

	copy(clone.DeprecatedForks, c.DeprecatedForks)

	return clone
}

// GetUpcomingForks returns forks that will activate after the given height
func (c *ChainConfig) GetUpcomingForks(height uint64) []*ForkScheduleEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var upcoming []*ForkScheduleEntry
	for _, entry := range c.ForkSchedule {
		if entry.ActivationHeight > height && !entry.Deprecated {
			upcoming = append(upcoming, entry)
		}
	}
	return upcoming
}

// GetActiveForks returns all forks active at the given height
func (c *ChainConfig) GetActiveForks(height uint64) []*ForkScheduleEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var active []*ForkScheduleEntry
	for _, entry := range c.ForkSchedule {
		if height >= entry.ActivationHeight && !entry.Deprecated {
			active = append(active, entry)
		}
	}
	return active
}

// NextForkHeight returns the next fork activation height after the given height
// Returns 0 if no upcoming forks
func (c *ChainConfig) NextForkHeight(height uint64) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, entry := range c.ForkSchedule {
		if entry.ActivationHeight > height && !entry.Deprecated {
			return entry.ActivationHeight
		}
	}
	return 0
}

// IsForkActive checks if a specific fork is active at the given height
func (c *ChainConfig) IsForkActive(forkID ForkID, height uint64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, entry := range c.ForkSchedule {
		if entry.ForkID == forkID {
			return height >= entry.ActivationHeight && !entry.Deprecated
		}
	}
	return false
}

// DeprecateFork marks a fork as deprecated
func (c *ChainConfig) DeprecateFork(forkID ForkID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, entry := range c.ForkSchedule {
		if entry.ForkID == forkID {
			entry.Deprecated = true
			c.DeprecatedForks = append(c.DeprecatedForks, forkID)
			return true
		}
	}
	return false
}

// IsCompatibleWith checks if this chain config is compatible with another
func (c *ChainConfig) IsCompatibleWith(other *ChainConfig) bool {
	if c.ChainID != other.ChainID {
		return false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Check that all non-deprecated forks in this config exist in the other
	for _, entry := range c.ForkSchedule {
		if entry.Deprecated {
			continue
		}
		found := false
		for _, otherEntry := range other.ForkSchedule {
			if entry.ForkID == otherEntry.ForkID &&
				entry.ActivationHeight == otherEntry.ActivationHeight {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// MergeWith merges another chain config into this one
// New forks from other are added, existing forks are updated
func (c *ChainConfig) MergeWith(other *ChainConfig) error {
	if c.ChainID != other.ChainID {
		return ErrIncompatibleFork
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, otherEntry := range other.ForkSchedule {
		found := false
		for i, entry := range c.ForkSchedule {
			if entry.ForkID == otherEntry.ForkID {
				// Update existing fork
				c.ForkSchedule[i] = otherEntry
				found = true
				break
			}
		}
		if !found {
			// Add new fork
			c.ForkSchedule = append(c.ForkSchedule, otherEntry)
		}
	}

	// Sort by activation height
	sort.Slice(c.ForkSchedule, func(i, j int) bool {
		return c.ForkSchedule[i].ActivationHeight < c.ForkSchedule[j].ActivationHeight
	})

	return nil
}

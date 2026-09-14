// Quantaureum Node source, version 1.0.0.
// Package consensus — Phase 4.1: Shard Network Activation
//
// Activates 64 shards for 200K node support. Uses the existing ShardManager
// infrastructure (shard.go) to distribute validators across shards.
//
// Target: 64 shards × ~3000 validators each = ~192K validators
// This keeps individual shard attestation data manageable while scaling
// the total network to 200K full nodes.
package consensus

import (
	"fmt"

	"github.com/quantaureum/qau/types"
)

// ShardActivationConfig holds configuration for shard network activation.
type ShardActivationConfig struct {
	ShardCount    int             // Number of shards (default: 64)
	MinValidators int             // Minimum validators per shard (default: ShardMinValidators)
	Validators    []types.Address // All validator addresses to distribute
	Seed          types.Hash      // Randomness seed for deterministic assignment
}

// DefaultShardActivationConfig returns the default configuration for 64-shard activation.
//
// SHRD-R5-09 (2026-07-17): The seed is left zero. Callers MUST set a
// high-entropy seed (e.g., from the main-chain QPOS epoch seed / random
// beacon) BEFORE invoking ActivateShardNetwork. A zero seed makes the
// shuffle completely predictable, allowing validators to pre-compute
// their shard assignments and collude. ActivateShardNetwork now rejects
// a zero seed to enforce this requirement.
func DefaultShardActivationConfig(validators []types.Address) ShardActivationConfig {
	var seed types.Hash
	return ShardActivationConfig{
		ShardCount:    64,
		MinValidators: ShardMinValidators,
		Validators:    validators,
		Seed:          seed,
	}
}

// ActivateShardNetwork initializes all shards and distributes validators.
// This is the main entry point for Phase 4 shard activation.
// Returns the number of created shards and per-shard validator counts.
//
// SHRD-R5-05 (2026-07-16): Shards are created in ShardStatusInitializing
// (NOT Active). The caller must subsequently register validator public keys,
// inject an election verifier, and call ActivateShard for each shard before
// it can produce/accept blocks. This method verifies that shards were
// created with validators assigned, but does NOT verify they are Active —
// that is the caller's responsibility (use ActivateShard + IsShardNetworkActive).
func (sm *ShardManager) ActivateShardNetwork(config ShardActivationConfig) (activatedShards int, validatorsPerShard map[uint64]int, err error) {
	if config.ShardCount <= 0 || config.ShardCount > ShardMaxCount {
		return 0, nil, fmt.Errorf("invalid shard count %d: must be 1-%d", config.ShardCount, ShardMaxCount)
	}

	// SHRD-R5-09 (2026-07-17): Reject zero seed. A zero seed makes the
	// Fisher-Yates shuffle completely predictable, allowing validators to
	// pre-compute their shard assignments and collude (the exact attack
	// the shuffle is meant to prevent). Callers MUST set a high-entropy
	// seed from the main-chain random beacon (e.g., QPOS epoch seed).
	var zeroSeed types.Hash
	if config.Seed == zeroSeed {
		return 0, nil, fmt.Errorf("shard activation rejected: zero seed is not allowed (use main-chain epoch seed for unpredictability)")
	}

	totalValidators := len(config.Validators)
	minRequired := config.ShardCount * config.MinValidators
	if totalValidators < minRequired {
		return 0, nil, fmt.Errorf("insufficient validators: need %d for %d shards, have %d",
			minRequired, config.ShardCount, totalValidators)
	}

	// Use existing AssignValidatorsToShards for deterministic distribution
	if err := sm.AssignValidatorsToShards(config.Validators, config.ShardCount, config.Seed); err != nil {
		return 0, nil, fmt.Errorf("failed to assign validators to shards: %w", err)
	}

	// Verify all shards were created with validators assigned.
	// SHRD-R5-05: Shards are in Initializing state (not Active) — the caller
	// must register pubkeys, inject verifier, and call ActivateShard.
	validatorsPerShard = make(map[uint64]int, config.ShardCount)
	for i := 1; i <= config.ShardCount; i++ {
		shardID := uint64(i)
		chain, err := sm.GetShard(shardID)
		if err != nil {
			return activatedShards, validatorsPerShard, fmt.Errorf("shard %d not found after assignment: %w", shardID, err)
		}

		if chain.Status() != ShardStatusInitializing && chain.Status() != ShardStatusActive {
			return activatedShards, validatorsPerShard, fmt.Errorf("shard %d has unexpected status: %s", shardID, chain.Status())
		}

		validators := chain.Validators()
		validatorsPerShard[shardID] = len(validators)
		activatedShards++
	}

	return activatedShards, validatorsPerShard, nil
}

// GetShardStats returns statistics about the shard network.
func (sm *ShardManager) GetShardStats() ShardNetworkStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := ShardNetworkStats{
		TotalShards: len(sm.shards),
	}

	for _, chain := range sm.shards {
		chain.mu.RLock()
		status := chain.status
		validatorCount := len(chain.validators)
		latestHeight := chain.latest
		chain.mu.RUnlock()

		switch status {
		case ShardStatusActive:
			stats.ActiveShards++
			stats.TotalValidators += validatorCount
		case ShardStatusInitializing:
			stats.InitializingShards++
		case ShardStatusInactive:
			stats.InactiveShards++
		}

		if latestHeight > stats.HighestShardHeight {
			stats.HighestShardHeight = latestHeight
		}
		stats.TotalBlocks += latestHeight
	}

	if stats.ActiveShards > 0 {
		stats.AvgValidatorsPerShard = stats.TotalValidators / stats.ActiveShards
	}

	return stats
}

// ShardNetworkStats holds aggregate statistics about the shard network.
type ShardNetworkStats struct {
	TotalShards           int
	ActiveShards          int
	InactiveShards        int
	InitializingShards    int
	TotalValidators       int
	AvgValidatorsPerShard int
	HighestShardHeight    uint64
	TotalBlocks           uint64
}

// IsShardNetworkActive returns true if all shards are active.
func (sm *ShardManager) IsShardNetworkActive() bool {
	stats := sm.GetShardStats()
	return stats.TotalShards > 0 && stats.ActiveShards == stats.TotalShards
}

// RouteCrossShardMessage routes a cross-shard message through the relay system.
// This is a high-level convenience method for cross-shard communication.
func (sm *ShardManager) RouteCrossShardMessage(msg *CrossShardMessage, txHash types.Hash) (*CrossShardReceipt, error) {
	if msg == nil {
		return nil, ErrCrossMsgInvalid
	}

	// Verify source shard is active
	srcShard, err := sm.GetShard(msg.SourceShard)
	if err != nil {
		return nil, fmt.Errorf("source shard %d not found: %w", msg.SourceShard, err)
	}
	if srcShard.Status() != ShardStatusActive {
		return nil, fmt.Errorf("source shard %d is not active", msg.SourceShard)
	}

	// Verify destination shard is active
	destShard, err := sm.GetShard(msg.DestShard)
	if err != nil {
		return nil, ErrCrossMsgDestInactive
	}
	if destShard.Status() != ShardStatusActive {
		return nil, ErrCrossMsgDestInactive
	}

	return sm.RelayCrossShardMessage(msg.SourceShard, msg.DestShard, msg, txHash)
}

// ShardCount returns the number of shards in the network.
func (sm *ShardManager) ShardCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.shards)
}

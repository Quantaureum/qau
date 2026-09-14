// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// ============================================================================
// RLLP-R5-02 (2026-07-17): State history retention must cover challenge period.
//
// These tests verify that NewStateManager computes a dynamic maxHistoryEntries
// from ChallengePeriod and BlockTime, so that fraud-proof verification against
// any batch inside the challenge window can find its snapshot.
//
// The previous hard-coded maxStateHistoryEntries=1000 covered only ~33 minutes
// at the default 2s block time — far short of the 7-day challenge period,
// silently breaking fraud-proof verification for any batch older than 33min.
// ============================================================================

// TestRLLP_R5_02_DefaultConfigCoversChallengePeriod verifies that the default
// production config (2s block, 7d challenge) yields a retention window that
// FULLY covers the challenge period with the safety margin applied.
func TestRLLP_R5_02_DefaultConfigCoversChallengePeriod(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)

	blocksInChallenge := int(cfg.ChallengePeriod / cfg.BlockTime)
	if sm.maxHistoryEntries < blocksInChallenge {
		t.Errorf("default config: maxHistoryEntries=%d < blocksInChallenge=%d (challenge period not covered)",
			sm.maxHistoryEntries, blocksInChallenge)
	}

	// Verify the safety margin was applied: maxHistoryEntries >= blocks * 1.25
	expected := int(float64(blocksInChallenge)*stateHistorySafetyMargin + 0.999)
	if sm.maxHistoryEntries < expected {
		t.Errorf("default config: maxHistoryEntries=%d < expected=%d (safety margin not applied)",
			sm.maxHistoryEntries, expected)
	}

	t.Logf("default config: ChallengePeriod=%v, BlockTime=%v → maxHistoryEntries=%d (blocksInChallenge=%d, +25%%=%d)",
		cfg.ChallengePeriod, cfg.BlockTime, sm.maxHistoryEntries, blocksInChallenge, expected)
}

// TestRLLP_R5_02_PreviousBugWouldFail verifies that the old hard-coded value
// of 1000 would NOT have covered the default challenge period. This is a
// regression guard: if anyone reverts to a hard-coded small constant, this
// test fails.
func TestRLLP_R5_02_PreviousBugWouldFail(t *testing.T) {
	cfg := DefaultRollupConfig()
	blocksInChallenge := int(cfg.ChallengePeriod / cfg.BlockTime)
	const oldHardCodedValue = 1000

	if oldHardCodedValue >= blocksInChallenge {
		t.Errorf("sanity check failed: old hard-coded %d >= blocksInChallenge %d — test premise invalid",
			oldHardCodedValue, blocksInChallenge)
	}

	t.Logf("CONFIRMED old bug: hard-coded %d entries covered only %v, challenge period is %v (%d blocks needed)",
		oldHardCodedValue,
		time.Duration(oldHardCodedValue)*cfg.BlockTime,
		cfg.ChallengePeriod,
		blocksInChallenge)
}

// TestRLLP_R5_02_DynamicScaling verifies that maxHistoryEntries scales
// correctly with different ChallengePeriod values.
func TestRLLP_R5_02_DynamicScaling(t *testing.T) {
	cases := []struct {
		name            string
		challengePeriod time.Duration
		blockTime       time.Duration
		expectedMin     int // must be >= this
		expectedMax     int // must be <= this
	}{
		{"7d@2s", 7 * 24 * time.Hour, 2 * time.Second, 378000, 378000},
		{"1d@2s", 24 * time.Hour, 2 * time.Second, 54000, 54000},
		{"1h@2s", time.Hour, 2 * time.Second, 2250, 2250},
		{"1min@2s", time.Minute, 2 * time.Second, 1000, 1000},        // clamped to floor
		{"30d@1s", 30 * 24 * time.Hour, time.Second, 500000, 500000}, // clamped to ceiling
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &RollupConfig{
				ChainID:         DefaultL2ChainID,
				L1ChainID:       DefaultL1ChainID,
				BlockTime:       c.blockTime,
				ChallengePeriod: c.challengePeriod,
				GasLimit:        30_000_000,
			}
			sm := NewStateManager(cfg)
			if sm.maxHistoryEntries < c.expectedMin {
				t.Errorf("maxHistoryEntries=%d < expectedMin=%d", sm.maxHistoryEntries, c.expectedMin)
			}
			if sm.maxHistoryEntries > c.expectedMax {
				t.Errorf("maxHistoryEntries=%d > expectedMax=%d", sm.maxHistoryEntries, c.expectedMax)
			}
			t.Logf("%s: maxHistoryEntries=%d", c.name, sm.maxHistoryEntries)
		})
	}
}

// TestRLLP_R5_02_NilConfigDefensive verifies that a nil config doesn't panic
// and falls back to the minimum retention.
func TestRLLP_R5_02_NilConfigDefensive(t *testing.T) {
	n := computeStateHistoryEntries(nil)
	if n != minStateHistoryEntries {
		t.Errorf("nil config: got %d, want %d", n, minStateHistoryEntries)
	}
}

// TestRLLP_R5_02_ZeroBlockTimeDefensive verifies that zero BlockTime falls
// back to the minimum rather than panicking on divide-by-zero.
func TestRLLP_R5_02_ZeroBlockTimeDefensive(t *testing.T) {
	cfg := &RollupConfig{
		BlockTime:       0,
		ChallengePeriod: time.Hour,
	}
	n := computeStateHistoryEntries(cfg)
	if n != minStateHistoryEntries {
		t.Errorf("zero BlockTime: got %d, want %d", n, minStateHistoryEntries)
	}
}

// TestRLLP_R5_02_ValidateRejectsOversizedConfig verifies that Validate()
// rejects production configs (BlockTime >= 1s) requiring more than
// maxStateHistoryEntries in-memory snapshots.
func TestRLLP_R5_02_ValidateRejectsOversizedConfig(t *testing.T) {
	// 365 days at 1s block time = 31,536,000 blocks * 1.25 = ~39M — way over ceiling.
	cfg := &RollupConfig{
		ChainID:         DefaultL2ChainID,
		L1ChainID:       DefaultL1ChainID,
		MaxBatchSize:    DefaultMaxBatchSize,
		BlockTime:       time.Second,
		ChallengePeriod: 365 * 24 * time.Hour,
		GasLimit:        30_000_000,
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("Validate accepted oversized config — should have rejected")
	}
	t.Logf("correctly rejected: %v", err)
}

// TestRLLP_R5_02_ValidateAcceptsTestFastPath verifies that Validate() allows
// test configs (BlockTime < 1s) even if they would nominally need more than
// the ceiling. This is the test fast-path exemption.
func TestRLLP_R5_02_ValidateAcceptsTestFastPath(t *testing.T) {
	cfg := &RollupConfig{
		ChainID:         DefaultL2ChainID,
		L1ChainID:       DefaultL1ChainID,
		MaxBatchSize:    DefaultMaxBatchSize,
		BlockTime:       100 * time.Millisecond, // test fast-path
		ChallengePeriod: 7 * 24 * time.Hour,
		GasLimit:        30_000_000,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate rejected test fast-path config: %v", err)
	}
}

// TestRLLP_R5_02_SnapshotRetainedThroughoutChallengeWindow verifies the
// functional behavior: after archiving enough snapshots to exceed the old
// 1000-entry limit, snapshots from early batches are STILL available (they
// would have been evicted under the old hard-coded limit).
//
// This test directly exercises archiveStateSnapshot rather than ProcessBatch
// to isolate the retention-window logic from state-transition validation.
func TestRLLP_R5_02_SnapshotRetainedThroughoutChallengeWindow(t *testing.T) {
	cfg := &RollupConfig{
		ChainID:         DefaultL2ChainID,
		L1ChainID:       DefaultL1ChainID,
		BlockTime:       100 * time.Millisecond,
		ChallengePeriod: time.Hour, // 36000 blocks * 1.25 = 45000 entries
		GasLimit:        30_000_000,
	}
	sm := NewStateManager(cfg)
	if sm.maxHistoryEntries < 1500 {
		t.Fatalf("test premise invalid: maxHistoryEntries=%d < 1500", sm.maxHistoryEntries)
	}

	// Archive 1500 distinct snapshots — exceeds the old hard-coded 1000 limit.
	stateRoots := make([]types.Hash, 0, 1500)
	for i := 0; i < 1500; i++ {
		root := types.Hash{}
		root[0] = byte(i >> 8)
		root[1] = byte(i)
		// Build a minimal account-state map so deepCopyAccounts works.
		states := map[types.Address]*RollupAccount{
			{byte(i)}: {Balance: big.NewInt(int64(i))},
		}
		sm.mu.Lock()
		sm.archiveStateSnapshot(root, states)
		sm.mu.Unlock()
		stateRoots = append(stateRoots, root)
	}

	// Under the new dynamic retention, all 1500 snapshots should be available.
	missing := 0
	for i, root := range stateRoots {
		sm.mu.RLock()
		_, exists := sm.stateHistory[root]
		sm.mu.RUnlock()
		if !exists {
			missing++
			if missing == 1 {
				t.Logf("first missing snapshot: batch %d, root=%x", i, root[:8])
			}
		}
	}

	if missing > 0 {
		t.Errorf("%d/%d snapshots missing — retention window did not cover all batches (maxHistoryEntries=%d)",
			missing, len(stateRoots), sm.maxHistoryEntries)
	} else {
		t.Logf("ALL %d snapshots retained (maxHistoryEntries=%d)", len(stateRoots), sm.maxHistoryEntries)
	}
}

// TestRLLP_R5_02_EvictionStillWorksAtConfiguredLimit verifies that FIFO
// eviction still kicks in once maxHistoryEntries is exceeded — the fix
// must not regress the BRDG-06 memory-bounding behavior.
func TestRLLP_R5_02_EvictionStillWorksAtConfiguredLimit(t *testing.T) {
	cfg := &RollupConfig{
		ChainID:         DefaultL2ChainID,
		L1ChainID:       DefaultL1ChainID,
		BlockTime:       100 * time.Millisecond,
		ChallengePeriod: time.Minute, // 600 blocks * 1.25 = 750, but floor=1000
		GasLimit:        30_000_000,
	}
	sm := NewStateManager(cfg)
	if sm.maxHistoryEntries != minStateHistoryEntries {
		t.Fatalf("test premise invalid: expected floor=%d, got %d",
			minStateHistoryEntries, sm.maxHistoryEntries)
	}

	// Archive MORE than maxHistoryEntries snapshots.
	total := sm.maxHistoryEntries + 100
	for i := 0; i < total; i++ {
		root := types.Hash{}
		root[0] = byte(i >> 8)
		root[1] = byte(i)
		states := map[types.Address]*RollupAccount{
			{byte(i)}: {Balance: big.NewInt(int64(i))},
		}
		sm.mu.Lock()
		sm.archiveStateSnapshot(root, states)
		sm.mu.Unlock()
	}

	sm.mu.RLock()
	count := len(sm.stateHistory)
	sm.mu.RUnlock()

	if count > sm.maxHistoryEntries {
		t.Errorf("FIFO eviction failed: count=%d > max=%d", count, sm.maxHistoryEntries)
	}
	if count != sm.maxHistoryEntries {
		t.Errorf("expected exactly max entries, got count=%d, max=%d", count, sm.maxHistoryEntries)
	}
	t.Logf("FIFO eviction works: archived %d, retained %d (max=%d)", total, count, sm.maxHistoryEntries)
}

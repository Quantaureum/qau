// Quantaureum Node source, version 1.0.0.
package consensus

// Shard health checker tests (P3-2, 2026-07-15)
//
// Verifies that the health checker correctly reports shard status, detects
// stalled block production, and flags cross-shard message backlog.

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestShardHealthChecker_Empty verifies that a nil/empty manager returns a
// healthy report with zero shards.
func TestShardHealthChecker_Empty(t *testing.T) {
	// Nil manager — should return healthy, zero shards.
	c := NewShardHealthChecker(nil)
	report := c.Check(time.Now())
	if report.Status != ShardHealthOK {
		t.Errorf("nil manager status: got %s, want ok", report.Status)
	}
	if report.ShardCount != 0 {
		t.Errorf("nil manager shard count: got %d, want 0", report.ShardCount)
	}

	// Empty manager — should also return healthy, zero shards.
	sm := NewShardManager(nil)
	c2 := NewShardHealthChecker(sm)
	report2 := c2.Check(time.Now())
	if report2.Status != ShardHealthOK {
		t.Errorf("empty manager status: got %s, want ok", report2.Status)
	}
	if report2.ShardCount != 0 {
		t.Errorf("empty manager shard count: got %d, want 0", report2.ShardCount)
	}
}

// TestShardHealthChecker_HealthyShard verifies that an active shard with
// recent blocks and no message backlog reports as healthy.
func TestShardHealthChecker_HealthyShard(t *testing.T) {
	sm := NewShardManager(nil)
	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard: %v", err)
	}
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard: %v", err)
	}

	// Manually inject a block with a recent timestamp so the shard is not stalled.
	now := time.Now()
	chain.mu.Lock()
	chain.blocks[1] = &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:   chain.shardID,
			Height:    1,
			Timestamp: uint64(now.Unix()),
		},
	}
	chain.latest = 1
	chain.mu.Unlock()

	c := NewShardHealthChecker(sm)
	report := c.Check(now)
	if report.Status != ShardHealthOK {
		t.Errorf("healthy shard: got status %s, want ok", report.Status)
	}
	if report.ActiveCount != 1 {
		t.Errorf("active count: got %d, want 1", report.ActiveCount)
	}
	if len(report.Shards) != 1 {
		t.Fatalf("shards: got %d, want 1", len(report.Shards))
	}
	if report.Shards[0].IsStalled {
		t.Errorf("shard should not be stalled")
	}
	if report.Shards[0].MsgBacklogLevel != "ok" {
		t.Errorf("backlog level: got %s, want ok", report.Shards[0].MsgBacklogLevel)
	}
}

// TestShardHealthChecker_StalledShard verifies that an active shard with no
// recent blocks is flagged as stalled (unhealthy).
func TestShardHealthChecker_StalledShard(t *testing.T) {
	cfg := DefaultShardHealthConfig()
	cfg.StalledSlotThreshold = 1 // 1 slot = 12s, anything older is stalled
	cfg.SlotInterval = time.Duration(ShardBlockInterval) * time.Second

	sm := NewShardManager(nil)
	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard: %v", err)
	}
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard: %v", err)
	}

	// Inject a block with an old timestamp (1 hour ago).
	now := time.Now()
	oldTime := now.Add(-1 * time.Hour)
	chain.mu.Lock()
	chain.blocks[1] = &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:   chain.shardID,
			Height:    1,
			Timestamp: uint64(oldTime.Unix()),
		},
	}
	chain.latest = 1
	chain.mu.Unlock()

	c := NewShardHealthCheckerWithConfig(sm, cfg)
	report := c.Check(now)
	if report.Status != ShardHealthUnhealthy {
		t.Errorf("stalled shard: got status %s, want unhealthy", report.Status)
	}
	if len(report.Shards) != 1 || !report.Shards[0].IsStalled {
		t.Errorf("shard should be flagged as stalled")
	}
}

// TestShardHealthChecker_MessageBacklog verifies that elevated pending
// messages trigger warn/critical backlog levels.
func TestShardHealthChecker_MessageBacklog(t *testing.T) {
	cfg := DefaultShardHealthConfig()
	cfg.PendingMsgWarnThreshold = 5
	cfg.PendingMsgCriticalThreshold = 10

	sm := NewShardManager(nil)
	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard: %v", err)
	}
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard: %v", err)
	}

	// Inject a recent block so staleness doesn't trigger.
	now := time.Now()
	chain.mu.Lock()
	chain.blocks[1] = &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:   chain.shardID,
			Height:    1,
			Timestamp: uint64(now.Unix()),
		},
	}
	chain.latest = 1

	// Add 7 pending messages — should trigger "warn" (5 <= 7 < 10).
	chain.pendingMsgs = make([]*CrossShardMessage, 7)
	for i := range chain.pendingMsgs {
		chain.pendingMsgs[i] = &CrossShardMessage{
			ID:          types.Hash{byte(i)},
			SourceShard: chain.shardID,
			DestShard:   2,
		}
	}
	chain.mu.Unlock()

	c := NewShardHealthCheckerWithConfig(sm, cfg)
	report := c.Check(now)
	if report.Status != ShardHealthDegraded {
		t.Errorf("warn backlog: got status %s, want degraded", report.Status)
	}
	if report.Shards[0].MsgBacklogLevel != "warn" {
		t.Errorf("backlog level: got %s, want warn", report.Shards[0].MsgBacklogLevel)
	}

	// Add more messages to trigger "critical".
	chain.mu.Lock()
	chain.pendingMsgs = make([]*CrossShardMessage, 15)
	for i := range chain.pendingMsgs {
		chain.pendingMsgs[i] = &CrossShardMessage{
			ID:          types.Hash{byte(i)},
			SourceShard: chain.shardID,
			DestShard:   2,
		}
	}
	chain.mu.Unlock()

	report2 := c.Check(now)
	if report2.Status != ShardHealthUnhealthy {
		t.Errorf("critical backlog: got status %s, want unhealthy", report2.Status)
	}
	if report2.Shards[0].MsgBacklogLevel != "critical" {
		t.Errorf("backlog level: got %s, want critical", report2.Shards[0].MsgBacklogLevel)
	}
}

// TestShardHealthChecker_InitializingShard verifies that an initializing
// shard (not yet active) is reported without stall/backlog checks.
func TestShardHealthChecker_InitializingShard(t *testing.T) {
	sm := NewShardManager(nil)
	validators := generateShardAddrs(t, 3)
	_, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard: %v", err)
	}
	// Don't activate — shard stays in Initializing state.

	c := NewShardHealthChecker(sm)
	report := c.Check(time.Now())
	if report.Status != ShardHealthOK {
		t.Errorf("initializing shard: got status %s, want ok (no active shards to check)", report.Status)
	}
	if report.ActiveCount != 0 {
		t.Errorf("active count: got %d, want 0", report.ActiveCount)
	}
	if len(report.Shards) != 1 {
		t.Fatalf("shards: got %d, want 1", len(report.Shards))
	}
	if report.Shards[0].Status != "Initializing" {
		t.Errorf("shard status: got %s, want Initializing", report.Shards[0].Status)
	}
	if report.Shards[0].IsStalled {
		t.Errorf("initializing shard should not be flagged as stalled")
	}
}

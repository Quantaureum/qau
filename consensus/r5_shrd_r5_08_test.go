// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestR5_SHRD_R5_08_StalledDetectedViaReceivedAt verifies that the health
// checker uses the local ReceivedAt timestamp (not the proposer-self-reported
// header timestamp) for stalled detection. A proposer could forge future or
// rolling header timestamps to keep stalledDuration below the threshold
// forever — ReceivedAt is stamped by the node's own clock and cannot be forged.
func TestR5_SHRD_R5_08_StalledDetectedViaReceivedAt(t *testing.T) {
	cfg := DefaultShardHealthConfig()
	cfg.StalledSlotThreshold = 1 // 1 slot = 12s
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

	// Inject a block with a FORGED FUTURE header timestamp (1 hour in the
	// future), but a REAL old ReceivedAt (1 hour ago). The proposer tries
	// to hide the stall by forging the header timestamp.
	now := time.Now()
	futureTime := now.Add(1 * time.Hour)     // proposer-forged
	oldReceivedAt := now.Add(-1 * time.Hour) // node's real receive time
	chain.mu.Lock()
	chain.blocks[1] = &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:   chain.shardID,
			Height:    1,
			Timestamp: uint64(futureTime.Unix()), // forged future timestamp
		},
		ReceivedAt: oldReceivedAt.UnixNano(), // real old receive time
	}
	chain.latest = 1
	chain.mu.Unlock()

	c := NewShardHealthCheckerWithConfig(sm, cfg)
	report := c.Check(now)
	if report.Status != ShardHealthUnhealthy {
		t.Errorf("SHRD-R5-08: forged header timestamp should not bypass stall detection; got status %s, want unhealthy",
			report.Status)
	}
	if len(report.Shards) != 1 || !report.Shards[0].IsStalled {
		t.Errorf("SHRD-R5-08: shard should be flagged as stalled based on ReceivedAt")
	}
}

// TestR5_SHRD_R5_08_HealthyWithRecentReceivedAt verifies that a block with
// a recent ReceivedAt is NOT flagged as stalled, even if the header timestamp
// is old. This confirms the fix doesn't break the happy path.
func TestR5_SHRD_R5_08_HealthyWithRecentReceivedAt(t *testing.T) {
	cfg := DefaultShardHealthConfig()
	cfg.StalledSlotThreshold = 5 // 5 slots = 60s
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

	// Block with OLD header timestamp but RECENT ReceivedAt.
	// Health checker should use ReceivedAt and NOT flag as stalled.
	now := time.Now()
	oldHeaderTime := now.Add(-24 * time.Hour)     // very old header timestamp
	recentReceivedAt := now.Add(-5 * time.Second) // recent receive time
	chain.mu.Lock()
	chain.blocks[1] = &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:   chain.shardID,
			Height:    1,
			Timestamp: uint64(oldHeaderTime.Unix()),
		},
		ReceivedAt: recentReceivedAt.UnixNano(),
	}
	chain.latest = 1
	chain.mu.Unlock()

	c := NewShardHealthCheckerWithConfig(sm, cfg)
	report := c.Check(now)
	if report.Status != ShardHealthOK {
		t.Errorf("SHRD-R5-08: recent ReceivedAt should not trigger stall; got status %s, want ok", report.Status)
	}
	if len(report.Shards) != 1 && report.Shards[0].IsStalled {
		t.Errorf("SHRD-R5-08: shard should NOT be stalled with recent ReceivedAt")
	}
}

// TestR5_SHRD_R5_08_FallbackToHeaderTimestamp verifies that when ReceivedAt
// is zero (e.g., block loaded from store on restart, or pre-fix blocks),
// the health checker falls back to the header timestamp. This preserves
// backward compatibility.
func TestR5_SHRD_R5_08_FallbackToHeaderTimestamp(t *testing.T) {
	cfg := DefaultShardHealthConfig()
	cfg.StalledSlotThreshold = 1
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

	// Block with ReceivedAt=0 (legacy) and old header timestamp.
	now := time.Now()
	oldTime := now.Add(-1 * time.Hour)
	chain.mu.Lock()
	chain.blocks[1] = &ShardBlock{
		Header: &ShardBlockHeader{
			ShardID:   chain.shardID,
			Height:    1,
			Timestamp: uint64(oldTime.Unix()),
		},
		ReceivedAt: 0, // legacy: no local receive time
	}
	chain.latest = 1
	chain.mu.Unlock()

	c := NewShardHealthCheckerWithConfig(sm, cfg)
	report := c.Check(now)
	if report.Status != ShardHealthUnhealthy {
		t.Errorf("SHRD-R5-08: fallback to header timestamp should detect stall; got status %s, want unhealthy",
			report.Status)
	}
	if len(report.Shards) != 1 || !report.Shards[0].IsStalled {
		t.Errorf("SHRD-R5-08: shard should be stalled via header timestamp fallback")
	}
}

// TestR5_SHRD_R5_08_ProposeBlockStampsReceivedAt verifies that ProposeBlock
// stamps the ReceivedAt field with the local clock. This ensures blocks
// produced locally (not just received via P2P) are also protected.
func TestR5_SHRD_R5_08_ProposeBlockStampsReceivedAt(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	before := time.Now().UnixNano()
	block, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}
	after := time.Now().UnixNano()

	if block.ReceivedAt == 0 {
		t.Fatal("SHRD-R5-08: ProposeBlock should stamp ReceivedAt with local time")
	}
	if block.ReceivedAt < before || block.ReceivedAt > after {
		t.Errorf("SHRD-R5-08: ReceivedAt %d should be between %d and %d",
			block.ReceivedAt, before, after)
	}
}

// TestR5_SHRD_R5_08_ReceiveBlockStampsReceivedAt verifies that ReceiveBlock
// stamps the ReceivedAt field. This is the P2P-receive path — the most
// important path for stall detection (a remote proposer forging timestamps).
func TestR5_SHRD_R5_08_ReceiveBlockStampsReceivedAt(t *testing.T) {
	validators := generateShardAddrs(t, 3)
	chain := NewShardChain(1, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)

	// First propose a block to establish a parent.
	parent, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}

	// Build a child block to receive via ReceiveBlock.
	childHeader := &ShardBlockHeader{
		ShardID:      chain.shardID,
		Height:       2,
		ParentHash:   computeShardBlockHash(parent.Header),
		StateRoot:    chain.ComputeStateRoot(2, computeShardBlockHash(parent.Header), types.Hash{}, types.Hash{}),
		TxRoot:       computeTxRoot(nil),
		CrossMsgRoot: computeCrossMsgRoot(nil),
		Timestamp:    uint64(time.Now().Unix()),
		Proposer:     validators[1],
	}
	childHeader.Signature = signShardBlock(validators[1], childHeader)

	childBlock := &ShardBlock{
		Header:    childHeader,
		Txs:       nil,
		CrossMsgs: nil,
	}

	before := time.Now().UnixNano()
	if err := chain.ReceiveBlock(childBlock); err != nil {
		t.Fatalf("ReceiveBlock failed: %v", err)
	}
	after := time.Now().UnixNano()

	stored, err := chain.GetBlock(2)
	if err != nil {
		t.Fatalf("SHRD-R5-08: block 2 not found after ReceiveBlock: %v", err)
	}
	if stored.ReceivedAt == 0 {
		t.Fatal("SHRD-R5-08: ReceiveBlock should stamp ReceivedAt with local time")
	}
	if stored.ReceivedAt < before || stored.ReceivedAt > after {
		t.Errorf("SHRD-R5-08: ReceivedAt %d should be between %d and %d",
			stored.ReceivedAt, before, after)
	}
}

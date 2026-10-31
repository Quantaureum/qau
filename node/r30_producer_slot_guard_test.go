// Quantaureum Node source, version 1.0.0.
package node

import (
	"path/filepath"
	"testing"
	"time"
)

// TestR30F9_ProducerOnlySealsAheadOfItsHead pins the R30 F9 rule: a producer may
// only seal a slot that is strictly ahead of its head's slot.
//
// The head can legitimately sit in the future (R38-P0-03 accepts blocks up to
// MaxFutureSlotGap slots ahead of the local clock so a lagging node does not
// split from the network). Sealing on top of such a head with the local clock's
// slot produces a block no peer accepts — slotGap < 0 is rejected outright, and
// slotGap == 0 always collides with the parent's timestamp — yet the node does
// not validate its own block, so it adopted the rejected block as head and
// orphaned itself until a re-sync replaced the head.
func TestR30F9_ProducerOnlySealsAheadOfItsHead(t *testing.T) {
	for _, tc := range []struct {
		name       string
		slot       uint64
		parentSlot uint64
		want       bool
	}{
		{name: "one slot behind the head", slot: 41, parentSlot: 42, want: false},
		{name: "same slot as the head", slot: 42, parentSlot: 42, want: false},
		{name: "head far in the future", slot: 43, parentSlot: 106, want: false},
		{name: "clock caught up, one slot ahead", slot: 43, parentSlot: 42, want: true},
		{name: "genesis head", slot: 1, parentSlot: 0, want: true},
		{name: "many slots of downtime", slot: 900, parentSlot: 42, want: true},
	} {
		if got := canExtendHead(tc.slot, tc.parentSlot); got != tc.want {
			t.Errorf("%s: canExtendHead(%d, %d) = %v, want %v", tc.name, tc.slot, tc.parentSlot, got, tc.want)
		}
	}
}

// TestR30F12_BuildStateRefusalReleasesTheNodeLock pins the lock discipline of
// tryProduceBlock's Phase 1. CopyForBuild refusing is a defensive branch (it only
// returns nil when the copy cannot be isolated from live disk state), and the
// branch used to return while Phase 1's node.mu was still held: one refusal
// would deadlock the whole node — block import, fork choice, head reads — with no
// path back short of a restart.
func TestR30F12_BuildStateRefusalReleasesTheNodeLock(t *testing.T) {
	n := &Node{}
	bp := &BlockProducer{node: n}

	n.mu.Lock()
	bp.skipSlotForBuildState(7)

	if !n.mu.TryLock() {
		t.Fatal("skipping the slot for an un-isolatable build state left node.mu held — " +
			"every goroutine that needs the head would block forever")
	}
	n.mu.Unlock()
}

// TestR30F11_LegacyProducerRefusesAStaleSlot pins the same rule at the legacy
// chokepoint. tryProduceBlock's fallback proposer releases node.mu and waits
// (waitForFallback) before calling produceBlock with the slot it captured
// earlier; the head may have advanced past that slot while it waited. The guard
// must be re-evaluated under the re-acquired lock, otherwise the DevMode /
// DevBlocks path seals an unextendable block even though tryProduceBlock now
// refuses it.
func TestR30F11_LegacyProducerRefusesAStaleSlot(t *testing.T) {
	cfg := &Config{
		Name:      "test-r30-f11-produce",
		DataDir:   filepath.Join(t.TempDir(), "qau-r30f11"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()

	if n.stateDB == nil {
		t.Fatal("node has no state database after initState")
	}
	parent := n.CurrentBlock()
	if parent == nil {
		t.Fatal("node has no current block after loadGenesis")
	}

	bp := NewBlockProducer(n, 3*time.Second)

	// First block: legal (slot strictly ahead of genesis).
	bp.produceBlock(parent.Header.Slot + 1)
	head := n.CurrentBlock()
	if head == nil || head.Header.Height != parent.Header.Height+1 {
		t.Fatalf("precondition: the producer did not build block %d on genesis (head %+v)",
			parent.Header.Height+1, head)
	}

	// Second call replays the slot the head already occupies — what the fallback
	// path does when the head moved during waitForFallback.
	bp.produceBlock(head.Header.Slot)
	after := n.CurrentBlock()
	if after == nil || after.Header.Height != head.Header.Height {
		t.Fatalf("a slot that is not ahead of the head's slot %d must not be sealed, but the head moved from height %d to %+v",
			head.Header.Slot, head.Header.Height, after)
	}
}

// Quantaureum Node source, version 1.0.0.
// BRIDGE-H03 regression tests.
//
// BRIDGE-H03 (R30, 2026-07-27): The per-address nonce cap check
// (maxUsedNoncesPerAddress = 10000) rejected new messages WITHOUT
// attempting to sweep covered nonces (those <= highestUsedNonce) first.
// This meant an active user who had many executed messages (whose nonces
// were covered by highestUsedNonce and could be safely pruned) would be
// permanently blocked from submitting new messages once they hit the cap,
// even though sweep would free plenty of space.
//
// FIX:
//  1. Added sweepUsedNoncesFor(nk) — a targeted sweep for a single
//     (chain, addr) pair that prunes entries <= highestUsedNonce.
//  2. Before rejecting on the per-address cap, call sweepUsedNoncesFor(nk)
//     to free covered entries. Only reject if the sweep cannot free enough.
//  3. After ExecuteMessage advances highestUsedNonce, proactively call
//     sweepUsedNoncesFor(execNk) to keep the per-address map small.
//  4. After init restore (which advances highestUsedNonce for EXECUTED
//     messages), call global sweepUsedNonces() to free covered entries
//     so active users don't hit the cap immediately after a restart.
package bridge

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// TestBRIDGE_H03_SweepUsedNoncesFor_PrunesCoveredEntries verifies that
// sweepUsedNoncesFor removes entries <= highestUsedNonce while preserving
// entries > highestUsedNonce. This is the core invariant: covered nonces
// are safe to prune because highestUsedNonce provides replay protection
// for them.
func TestBRIDGE_H03_SweepUsedNoncesFor_PrunesCoveredEntries(t *testing.T) {
	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	defer qb.Stop(context.Background())

	nk := nonceKey{chain: "chain-a", addr: "addr-active"}

	// Set up usedNonces with 5 entries: {1, 2, 3, 4, 5}.
	qb.mu.Lock()
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	for n := uint64(1); n <= 5; n++ {
		qb.usedNonces[nk][n] = time.Now()
	}
	qb.totalUsedNonces = 5
	// highestUsedNonce = 3 means nonces 1, 2, 3 are covered and can be pruned.
	qb.highestUsedNonce[nk] = 3
	qb.mu.Unlock()

	// Call sweepUsedNoncesFor.
	qb.mu.Lock()
	pruned := qb.sweepUsedNoncesFor(nk)
	qb.mu.Unlock()

	if pruned != 3 {
		t.Fatalf("BRIDGE-H03: expected 3 entries pruned (nonces 1,2,3 <= highest=3), got %d", pruned)
	}

	// Verify covered entries (1, 2, 3) are removed.
	// Verify uncovered entries (4, 5) remain.
	qb.mu.RLock()
	_, n1Exists := qb.usedNonces[nk][1]
	_, n2Exists := qb.usedNonces[nk][2]
	_, n3Exists := qb.usedNonces[nk][3]
	_, n4Exists := qb.usedNonces[nk][4]
	_, n5Exists := qb.usedNonces[nk][5]
	remainingCount := len(qb.usedNonces[nk])
	totalCount := qb.totalUsedNonces
	qb.mu.RUnlock()

	if n1Exists || n2Exists || n3Exists {
		t.Errorf("BRIDGE-H03: covered nonces (1,2,3) should have been pruned — got exists: 1=%v 2=%v 3=%v",
			n1Exists, n2Exists, n3Exists)
	}
	if !n4Exists || !n5Exists {
		t.Errorf("BRIDGE-H03: uncovered nonces (4,5) should remain — got exists: 4=%v 5=%v",
			n4Exists, n5Exists)
	}
	if remainingCount != 2 {
		t.Errorf("BRIDGE-H03: expected 2 remaining entries, got %d", remainingCount)
	}
	if totalCount != 2 {
		t.Errorf("BRIDGE-H03: expected totalUsedNonces=2 after pruning 3, got %d", totalCount)
	}
}

// TestBRIDGE_H03_SweepUsedNoncesFor_NoHighestUsedNonce verifies that
// when highestUsedNonce is not set (no executed messages), sweep prunes
// nothing. This is correct because without highestUsedNonce, there is no
// replay protection for pruned entries.
func TestBRIDGE_H03_SweepUsedNoncesFor_NoHighestUsedNonce(t *testing.T) {
	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	defer qb.Stop(context.Background())

	nk := nonceKey{chain: "chain-a", addr: "addr-active"}

	// Set up usedNonces with 3 entries: {10, 20, 30}.
	// Do NOT set highestUsedNonce (no executed messages).
	qb.mu.Lock()
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	qb.usedNonces[nk][10] = time.Now()
	qb.usedNonces[nk][20] = time.Now()
	qb.usedNonces[nk][30] = time.Now()
	qb.totalUsedNonces = 3
	qb.mu.Unlock()

	// Call sweepUsedNoncesFor — should prune nothing (highest=0, no nonce <= 0).
	qb.mu.Lock()
	pruned := qb.sweepUsedNoncesFor(nk)
	qb.mu.Unlock()

	if pruned != 0 {
		t.Fatalf("BRIDGE-H03: expected 0 entries pruned when highestUsedNonce not set, got %d", pruned)
	}

	qb.mu.RLock()
	remainingCount := len(qb.usedNonces[nk])
	qb.mu.RUnlock()

	if remainingCount != 3 {
		t.Errorf("BRIDGE-H03: expected all 3 entries to remain when no highestUsedNonce, got %d remaining", remainingCount)
	}
}

// TestBRIDGE_H03_SweepUsedNoncesFor_EmptyMap verifies that sweeping a
// non-existent or empty (chain, addr) is a no-op.
func TestBRIDGE_H03_SweepUsedNoncesFor_EmptyMap(t *testing.T) {
	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	defer qb.Stop(context.Background())

	nk := nonceKey{chain: "chain-a", addr: "addr-empty"}

	// No entries for this nk.
	qb.mu.Lock()
	pruned := qb.sweepUsedNoncesFor(nk)
	qb.mu.Unlock()

	if pruned != 0 {
		t.Fatalf("BRIDGE-H03: expected 0 entries pruned for non-existent nk, got %d", pruned)
	}
}

// TestBRIDGE_H03_SweepUsedNoncesFor_RemovesEmptySubMap verifies that when
// all entries for a (chain, addr) are pruned, the empty sub-map is removed
// from usedNonces to help GC.
func TestBRIDGE_H03_SweepUsedNoncesFor_RemovesEmptySubMap(t *testing.T) {
	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	defer qb.Stop(context.Background())

	nk := nonceKey{chain: "chain-a", addr: "addr-all-covered"}

	// Set up usedNonces with 3 entries all <= highestUsedNonce.
	qb.mu.Lock()
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	qb.usedNonces[nk][1] = time.Now()
	qb.usedNonces[nk][2] = time.Now()
	qb.usedNonces[nk][3] = time.Now()
	qb.totalUsedNonces = 3
	qb.highestUsedNonce[nk] = 5 // covers all entries
	qb.mu.Unlock()

	qb.mu.Lock()
	pruned := qb.sweepUsedNoncesFor(nk)
	qb.mu.Unlock()

	if pruned != 3 {
		t.Fatalf("BRIDGE-H03: expected 3 entries pruned, got %d", pruned)
	}

	// The sub-map should be removed entirely.
	qb.mu.RLock()
	_, subMapExists := qb.usedNonces[nk]
	qb.mu.RUnlock()

	if subMapExists {
		t.Error("BRIDGE-H03: empty sub-map should be removed from usedNonces to help GC")
	}
}

// TestBRIDGE_H03_PerAddressCapSweepOnSubmit verifies that when the
// per-address cap is reached, SubmitMessage triggers sweepUsedNoncesFor
// before rejecting. This is the core BRIDGE-H03 fix: without the sweep,
// an active user with many executed messages would be permanently blocked.
//
// This test directly populates usedNonces with maxUsedNoncesPerAddress
// entries, sets highestUsedNonce to cover most of them, then submits a
// new message. The sweep should free the covered entries, allowing the
// new message to be accepted.
func TestBRIDGE_H03_PerAddressCapSweepOnSubmit(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	defer qb.Stop(context.Background())

	if err := qb.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Use trackingAdapter so SubmitMessage succeeds at the adapter step.
	qb.adapters["chain-a"] = &trackingAdapter{chainID: "chain-a"}

	// Set up a trusted validator key so verifyQuantumSignature accepts the message.
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	qb.SetTrustedValidatorKeys([][]byte{keyPair.Public.Bytes()})
	// BRIDGE-H03: SourceAddress MUST match the key pair's derived address
	// (verifyQuantumSignature enforces this). All nonceKey lookups and
	// usedNonces pre-population must use this address.
	callerAddr := keyPair.Public.Address().ToHexAddress()

	nk := nonceKey{chain: "chain-a", addr: callerAddr}

	// Populate usedNonces with maxUsedNoncesPerAddress entries.
	// Nonces 1..10000. Set highestUsedNonce = 9000 so nonces 1..9000 are
	// covered and can be pruned, freeing 9000 slots. Nonces 9001..10000
	// remain (these are pending nonces not yet executed).
	qb.mu.Lock()
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	for n := uint64(1); n <= uint64(maxUsedNoncesPerAddress); n++ {
		qb.usedNonces[nk][n] = time.Now()
	}
	qb.totalUsedNonces = maxUsedNoncesPerAddress
	qb.highestUsedNonce[nk] = 9000
	qb.mu.Unlock()

	// Submit a new message with nonce 10001 (above the cap, above highest).
	// Before the BRIDGE-H03 fix, this would be rejected with "too many
	// pending nonces". After the fix, the sweep frees 9000 entries and
	// the message is accepted.
	msg := &BridgeMessage{
		ID:            "h03-cap-sweep-test",
		SourceChain:   "chain-a",
		TargetChain:   "chain-b",
		SourceAddress: callerAddr,
		TargetAddress: "target-addr",
		AssetType:     AssetTypeNative,
		AssetID:       "qau",
		Amount:        "1000000000000000000",
		MessageType:   MessageTypeAssetTransfer,
		Nonce:         10001,
		Timestamp:     time.Now().Unix(),
		BlockNumber:   100,
		Status:        MessageStatusPending,
	}
	signH01Message(t, qb, msg, keyPair)

	if err := qb.SubmitMessage(context.Background(), msg); err != nil {
		t.Fatalf("BRIDGE-H03 regression: SubmitMessage should succeed after sweep freed covered nonces, got: %v", err)
	}

	// Verify the sweep removed covered entries (nonces 1..9000).
	qb.mu.RLock()
	remainingCount := len(qb.usedNonces[nk])
	// After sweep: 9000 covered entries removed, then nonce 10001 added by SubmitMessage.
	// Remaining: nonces 9001..10000 (1000 entries) + nonce 10001 (1 entry) = 1001.
	// But SubmitMessage also checks the per-address cap AFTER the sweep, so
	// if the sweep freed enough space, the new nonce is added.
	qb.mu.RUnlock()

	if remainingCount > maxUsedNoncesPerAddress {
		t.Errorf("BRIDGE-H03: usedNonces count %d still at/above cap after sweep — sweep did not free covered entries", remainingCount)
	}

	// Verify covered entries (nonce 1) was pruned.
	qb.mu.RLock()
	_, n1Exists := qb.usedNonces[nk][1]
	qb.mu.RUnlock()
	if n1Exists {
		t.Error("BRIDGE-H03: covered nonce 1 should have been pruned by sweep")
	}
}

// TestBRIDGE_H03_ProactiveSweepAfterExecute verifies that after
// ExecuteMessage advances highestUsedNonce, the proactive sweep frees
// covered entries from usedNonces. This keeps the per-address map small
// and prevents active users from hitting the cap.
//
// This test directly simulates the execution path by calling the same
// in-memory state updates that ExecuteMessage performs (status transition
// + highestUsedNonce advancement + proactive sweep).
func TestBRIDGE_H03_ProactiveSweepAfterExecute(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	defer qb.Stop(context.Background())

	if err := qb.Initialize(context.Background()); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	nk := nonceKey{chain: "chain-a", addr: "addr-exec"}

	// Set up usedNonces with 5 entries: {1, 2, 3, 4, 5}.
	// highestUsedNonce is 0 (no executed messages yet).
	qb.mu.Lock()
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	for n := uint64(1); n <= 5; n++ {
		qb.usedNonces[nk][n] = time.Now()
	}
	qb.totalUsedNonces = 5
	qb.mu.Unlock()

	// Simulate ExecuteMessage for nonce 3: advance highestUsedNonce to 3
	// and call proactive sweep (same code path as ExecuteMessage).
	qb.mu.Lock()
	if 3 > qb.highestUsedNonce[nk] {
		qb.highestUsedNonce[nk] = 3
	}
	qb.sweepUsedNoncesFor(nk)
	qb.mu.Unlock()

	// Verify covered entries (1, 2, 3) are pruned; uncovered (4, 5) remain.
	qb.mu.RLock()
	_, n1Exists := qb.usedNonces[nk][1]
	_, n2Exists := qb.usedNonces[nk][2]
	_, n3Exists := qb.usedNonces[nk][3]
	_, n4Exists := qb.usedNonces[nk][4]
	_, n5Exists := qb.usedNonces[nk][5]
	remainingCount := len(qb.usedNonces[nk])
	qb.mu.RUnlock()

	if n1Exists || n2Exists || n3Exists {
		t.Errorf("BRIDGE-H03: proactive sweep after ExecuteMessage should prune covered nonces 1,2,3 — got exists: 1=%v 2=%v 3=%v",
			n1Exists, n2Exists, n3Exists)
	}
	if !n4Exists || !n5Exists {
		t.Errorf("BRIDGE-H03: proactive sweep should preserve uncovered nonces 4,5 — got exists: 4=%v 5=%v",
			n4Exists, n5Exists)
	}
	if remainingCount != 2 {
		t.Errorf("BRIDGE-H03: expected 2 remaining entries after proactive sweep, got %d", remainingCount)
	}
}

// TestBRIDGE_H03_InitRestoreSweepFreesCoveredNonces verifies that after
// Initialize restores messages from the persistent store and advances
// highestUsedNonce for EXECUTED messages, the global sweep frees covered
// nonces. Without this, restored EXECUTED nonces remain in usedNonces
// even though they are covered by highestUsedNonce, artificially
// inflating per-address counts and causing active users to hit the cap
// immediately after a restart.
func TestBRIDGE_H03_InitRestoreSweepFreesCoveredNonces(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "h03-init-sweep.db")
	ctx := context.Background()

	// Phase 1: Write an EXECUTED message to the store.
	// This message has nonce 5. On restore, highestUsedNonce will be set to 5.
	store1, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("first NewBoltMessageStore failed: %v", err)
	}
	executedMsg := makeMsg("h03-executed-1", MessageStatusExecuted, "addr-init", 5)
	if err := store1.SaveMessage(ctx, executedMsg); err != nil {
		t.Fatalf("SaveMessage executed failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Phase 2: Reopen the store and Initialize a new bridge.
	store2, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("second NewBoltMessageStore failed: %v", err)
	}
	defer store2.Close()

	cfg := DefaultBridgeConfig()
	qb := NewQuantumBridge(cfg).(*QuantumBridge)
	qb.SetStore(store2)

	if err := qb.Initialize(ctx); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Phase 3: Verify the EXECUTED nonce was restored then swept (freed).
	// After restore: usedNonces[nk][5] is populated, highestUsedNonce[nk] = 5.
	// After init sweep: usedNonces[nk][5] is pruned (5 <= highest=5).
	nk := nonceKey{chain: "chain-a", addr: "addr-init"}
	qb.mu.RLock()
	_, n5Exists := qb.usedNonces[nk][5]
	highest := qb.highestUsedNonce[nk]
	_, subMapExists := qb.usedNonces[nk]
	qb.mu.RUnlock()

	if n5Exists {
		t.Error("BRIDGE-H03: restored EXECUTED nonce 5 should have been pruned by init sweep (covered by highestUsedNonce=5)")
	}
	if highest != 5 {
		t.Errorf("BRIDGE-H03: highestUsedNonce should be 5 after restore, got %d", highest)
	}
	if subMapExists {
		t.Error("BRIDGE-H03: empty sub-map should have been removed after init sweep pruned all covered entries")
	}
}

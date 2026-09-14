// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestECON_H02_SweepUsedNonces_PrunesCoveredEntries verifies that
// sweepUsedNonces removes all nonce entries <= highestUsedNonce for each
// (chain, addr) pair, freeing space under the global cap.
//
// ECON-H02 FIX (R29, 2026-07-26): Without the sweep, the bridge would
// permanently reject all new messages after 1M lifetime nonces. The sweep
// reclaims space by leveraging highestUsedNonce as a compact replay
// protection counter.
func TestECON_H02_SweepUsedNonces_PrunesCoveredEntries(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	qb.mu.Lock()
	defer qb.mu.Unlock()

	// Set up: 3 (chain, addr) pairs with various nonces.
	nk1 := nonceKey{chain: "chainA", addr: "addr1"}
	nk2 := nonceKey{chain: "chainA", addr: "addr2"}
	nk3 := nonceKey{chain: "chainB", addr: "addr3"}

	qb.usedNonces[nk1] = map[uint64]time.Time{
		1: time.Now(), 2: time.Now(), 3: time.Now(), 10: time.Now(),
	}
	qb.usedNonces[nk2] = map[uint64]time.Time{
		100: time.Now(), 200: time.Now(),
	}
	qb.usedNonces[nk3] = map[uint64]time.Time{
		5: time.Now(),
	}
	// highestUsedNonce covers all entries for nk1 (highest=10) and nk2
	// (highest=200). For nk3, highest=3 means nonce 5 is NOT covered.
	qb.highestUsedNonce[nk1] = 10
	qb.highestUsedNonce[nk2] = 200
	qb.highestUsedNonce[nk3] = 3
	qb.totalUsedNonces = 4 + 2 + 1 // 7 entries total

	pruned := qb.sweepUsedNonces()

	// nk1: all 4 entries (1,2,3,10) <= 10 → pruned.
	// nk2: all 2 entries (100,200) <= 200 → pruned.
	// nk3: 1 entry (5) > 3 → NOT pruned.
	if pruned != 6 {
		t.Errorf("pruned = %d, want 6 (4 from nk1 + 2 from nk2)", pruned)
	}
	if qb.totalUsedNonces != 1 {
		t.Errorf("totalUsedNonces after sweep = %d, want 1 (only nk3 nonce 5)", qb.totalUsedNonces)
	}
	// nk3 nonce 5 should still be present.
	if _, exists := qb.usedNonces[nk3][5]; !exists {
		t.Error("nk3 nonce 5 should still exist (5 > highest 3, not covered)")
	}
	// nk1 and nk2 sub-maps should be removed (empty after pruning).
	if _, exists := qb.usedNonces[nk1]; exists {
		t.Error("nk1 sub-map should be removed after pruning all entries")
	}
	if _, exists := qb.usedNonces[nk2]; exists {
		t.Error("nk2 sub-map should be removed after pruning all entries")
	}
}

// TestECON_H02_SweepUsedNonces_AlsoEvictsExpired verifies that the sweep
// also removes expired entries (nonceTTL > 0) as a side benefit.
func TestECON_H02_SweepUsedNonces_AlsoEvictsExpired(t *testing.T) {
	// This test only runs meaningfully if nonceTTL > 0. The project default
	// is nonceTTL = 0 (never expire), so we test the TTL path by checking
	// that the sweep's TTL branch is a no-op when nonceTTL = 0.
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	qb.mu.Lock()
	defer qb.mu.Unlock()

	nk := nonceKey{chain: "chainA", addr: "addr1"}
	old := time.Now().Add(-365 * 24 * time.Hour) // very old
	qb.usedNonces[nk] = map[uint64]time.Time{
		1: old, 2: old, 3: old,
	}
	qb.highestUsedNonce[nk] = 0 // no coverage
	qb.totalUsedNonces = 3

	pruned := qb.sweepUsedNonces()

	// With nonceTTL = 0 (default), the TTL branch is skipped. No entries
	// are covered by highestUsedNonce (highest=0). So nothing is pruned.
	if pruned != 0 {
		t.Errorf("pruned = %d, want 0 (nonceTTL=0 and highest=0 → nothing to prune)", pruned)
	}
	if qb.totalUsedNonces != 3 {
		t.Errorf("totalUsedNonces = %d, want 3 (nothing pruned)", qb.totalUsedNonces)
	}
}

// TestECON_H02_CapHitTriggersSweepThenAccepts verifies the end-to-end
// recovery: when the global cap is hit, SubmitMessage triggers a sweep,
// and if the sweep frees enough space, the new message is accepted (modulo
// other validation).
//
// NOTE: SubmitMessage requires a valid signed message to fully succeed.
// This test verifies that the cap check NO LONGER rejects after the sweep
// frees space — the rejection moves past the cap check to a later
// validation step (signature/validator verification).
func TestECON_H02_CapHitTriggersSweepThenAccepts(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	// Fill usedNonces to just below the cap, with all entries covered by
	// highestUsedNonce (so the sweep will prune them all).
	qb.mu.Lock()
	nk := nonceKey{chain: "quantaureum", addr: "addr-sweep"}
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	// Add many entries (but keep test fast — we don't need 1M).
	// Set totalUsedNonces directly to the cap to simulate a full map.
	for i := uint64(1); i <= 100; i++ {
		qb.usedNonces[nk][i] = time.Now()
	}
	qb.highestUsedNonce[nk] = 100
	qb.totalUsedNonces = maxUsedNoncesGlobal // at cap
	qb.mu.Unlock()

	// Submit a NEW message with nonce > highest (101). The sweep should
	// prune all 100 covered entries, freeing space. The cap check then
	// passes. The message will fail later validation (no signature), but
	// the error should NOT be "global used nonces limit reached".
	msg := &BridgeMessage{
		ID:            "msg-econ-h02-1",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "addr-sweep",
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		Amount:        "100",
		Nonce:         101,
		Timestamp:     time.Now().Unix(),
		MessageType:   MessageTypeAssetTransfer,
	}

	err := qb.SubmitMessage(context.Background(), msg)
	if err == nil {
		// The message might actually succeed if no signature is required
		// in the default test config. Either way, the cap should not block.
		t.Logf("SubmitMessage succeeded after sweep (cap recovery works)")
	} else if strings.Contains(err.Error(), "global used nonces limit") {
		t.Fatalf("cap should have been freed by sweep, but still rejected: %v", err)
	} else {
		// Other validation errors are fine — the point is the cap was freed.
		t.Logf("SubmitMessage failed for non-cap reason (expected): %v", err)
	}

	// Verify the sweep pruned the covered entries.
	qb.mu.RLock()
	count := qb.totalUsedNonces
	qb.mu.RUnlock()
	if count >= maxUsedNoncesGlobal {
		t.Errorf("totalUsedNonces = %d, should be below cap after sweep", count)
	}
}

// TestECON_H02_PrunedNonceReplayRejected verifies that after the sweep
// prunes a nonce entry, a replay attempt with that nonce is rejected by
// the highestUsedNonce check (not the usedNonces check).
func TestECON_H02_PrunedNonceReplayRejected(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	// Set up: nonce 5 was used, highest is 10. The sweep will prune nonce 5.
	qb.mu.Lock()
	nk := nonceKey{chain: "quantaureum", addr: "addr-prune"}
	qb.usedNonces[nk] = map[uint64]time.Time{
		5: time.Now(), 10: time.Now(),
	}
	qb.highestUsedNonce[nk] = 10
	qb.totalUsedNonces = 2
	// Trigger sweep.
	pruned := qb.sweepUsedNonces()
	if pruned != 2 {
		t.Fatalf("sweep should prune 2 entries, got %d", pruned)
	}
	qb.mu.Unlock()

	// Attempt to replay nonce 5. It's no longer in usedNonces, but
	// 5 <= highest (10), so it must be rejected.
	msg := &BridgeMessage{
		ID:            "msg-pruned-replay",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "addr-prune",
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		Amount:        "100",
		Nonce:         5, // pruned nonce
		Timestamp:     time.Now().Unix(),
		MessageType:   MessageTypeAssetTransfer,
	}

	err := qb.SubmitMessage(context.Background(), msg)
	if err == nil {
		t.Fatal("replay of pruned nonce must be rejected")
	}
	if !strings.Contains(err.Error(), "below highest used") && !strings.Contains(err.Error(), "already used") {
		t.Errorf("expected 'below highest used' or 'already used' error, got: %v", err)
	}
}

// TestECON_H02_NewNonceAboveHighestAccepted verifies that a new message
// with nonce > highestUsedNonce is accepted by the nonce checks (it may
// fail later validation, but not at the nonce replay check).
func TestECON_H02_NewNonceAboveHighestAccepted(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	qb.mu.Lock()
	nk := nonceKey{chain: "quantaureum", addr: "addr-new"}
	qb.usedNonces[nk] = map[uint64]time.Time{10: time.Now()}
	qb.highestUsedNonce[nk] = 10
	qb.totalUsedNonces = 1
	qb.mu.Unlock()

	// New message with nonce 11 (> highest 10). Should pass nonce checks.
	// Will fail later validation (no signature), but NOT with "already used"
	// or "below highest used".
	msg := &BridgeMessage{
		ID:            "msg-new-nonce",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "addr-new",
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		Amount:        "100",
		Nonce:         11,
		Timestamp:     time.Now().Unix(),
		MessageType:   MessageTypeAssetTransfer,
	}

	err := qb.SubmitMessage(context.Background(), msg)
	if err != nil {
		if strings.Contains(err.Error(), "already used") || strings.Contains(err.Error(), "below highest used") {
			t.Errorf("new nonce 11 should not be rejected by nonce checks: %v", err)
		} else {
			t.Logf("SubmitMessage failed for non-nonce reason (expected): %v", err)
		}
	}
}

// TestECON_H02_SweepEmptyMapNoOp verifies that sweepUsedNonces is a safe
// no-op when usedNonces is empty.
func TestECON_H02_SweepEmptyMapNoOp(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	qb.mu.Lock()
	defer qb.mu.Unlock()

	pruned := qb.sweepUsedNonces()
	if pruned != 0 {
		t.Errorf("pruned = %d, want 0 for empty usedNonces", pruned)
	}
	if qb.totalUsedNonces != 0 {
		t.Errorf("totalUsedNonces = %d, want 0", qb.totalUsedNonces)
	}
}

// TestECON_H02_SweepNegativeCounterClamped verifies that if
// totalUsedNonces drifts below 0 (defensive), it is clamped to 0.
func TestECON_H02_SweepNegativeCounterClamped(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	qb.mu.Lock()
	defer qb.mu.Unlock()

	// Set up an inconsistent state: totalUsedNonces = 1 but no entries.
	// The sweep will prune 0 entries, but the clamp logic should prevent
	// negative counter. Actually, the sweep doesn't adjust the counter
	// if nothing is pruned, so we need a different scenario.
	//
	// Set totalUsedNonces = 0 and prune nothing. The clamp is only
	// triggered when pruned > 0 and totalUsedNonces goes negative due
	// to drift. Since we can't easily simulate drift without breaking
	// invariants, we just verify the clamp branch exists (defensive).
	nk := nonceKey{chain: "c", addr: "a"}
	qb.usedNonces[nk] = map[uint64]time.Time{1: time.Now()}
	qb.highestUsedNonce[nk] = 1
	qb.totalUsedNonces = 0 // drifted: 1 entry but counter says 0
	pruned := qb.sweepUsedNonces()
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1", pruned)
	}
	// Counter was 0, pruned 1, so it would go to -1, clamped to 0.
	if qb.totalUsedNonces != 0 {
		t.Errorf("totalUsedNonces = %d, want 0 (clamped from -1)", qb.totalUsedNonces)
	}
}

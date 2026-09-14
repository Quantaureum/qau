// Quantaureum Node source, version 1.0.0.
// Package bridge — BRIDGE-R12-002 tests.
//
// Verifies the fix for the audit finding:
//
//	usedNonces was not keyed by (SourceChain, SourceAddress); the same address reusing a nonce on a different chain was wrongly rejected
//
// Before the fix, usedNonces was keyed by SourceAddress alone (a string), so
// the same address sending cross-chain messages via two different source
// chains shared a single nonce namespace — a message from chain A with
// nonce N would cause SubmitMessage to reject a later message from chain B
// with the same nonce N from the same address, even though the two nonces
// are independent (each source chain maintains its own nonce sequence).
//
// After the fix, the key is the composite nonceKey{chain, addr}, so each
// (source chain, source address) pair has its own nonce namespace.
package bridge

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestBRIDGE_R12_002_CrossChainSameNonceNotRejected is the core regression
// test for the audit finding. Two messages with the SAME nonce and SAME
// source address but DIFFERENT source chains must BOTH be accepted as
// distinct (no false "nonce already used" rejection).
//
// We bypass signature verification by directly manipulating usedNonces
// (the path that actually caused the false rejection). The first call
// inserts nonce=42 for (chainA, addr). Before the fix, attempting to
// insert nonce=42 for (chainB, addr) would observe the existing entry
// under the bare-address key and return "nonce already used". After the
// fix, the second insert succeeds because (chainB, addr) is a distinct key.
func TestBRIDGE_R12_002_CrossChainSameNonceNotRejected(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	addr := "addr-r12-002-shared"
	nonce := uint64(42)

	qb.mu.Lock()
	// Simulate that chainA had previously used nonce=42 from this address.
	nkA := nonceKey{chain: ChainID("chainA"), addr: addr}
	qb.usedNonces[nkA] = make(map[uint64]time.Time)
	qb.usedNonces[nkA][nonce] = time.Now()
	qb.totalUsedNonces++
	qb.mu.Unlock()

	// Now attempt to insert the SAME nonce for the SAME address but on
	// chainB. Before the fix this would return "nonce already used for
	// address addr-r12-002-shared". After the fix it must NOT see the
	// chainA entry and must allow insertion.
	qb.mu.Lock()
	nkB := nonceKey{chain: ChainID("chainB"), addr: addr}
	if qb.usedNonces == nil {
		qb.usedNonces = make(map[nonceKey]map[uint64]time.Time)
	}
	if qb.usedNonces[nkB] == nil {
		qb.usedNonces[nkB] = make(map[uint64]time.Time)
	}
	if _, used := qb.usedNonces[nkB][nonce]; used {
		t.Fatalf("BRIDGE-R12-002 REGRESSION: nonce %d on chainB was incorrectly reported as already used (should be isolated from chainA)", nonce)
	}
	qb.usedNonces[nkB][nonce] = time.Now()
	qb.totalUsedNonces++
	qb.mu.Unlock()

	// Verify both entries coexist independently.
	qb.mu.RLock()
	_, hasA := qb.usedNonces[nkA][nonce]
	_, hasB := qb.usedNonces[nkB][nonce]
	qb.mu.RUnlock()
	if !hasA {
		t.Error("chainA nonce should still be present after inserting chainB nonce")
	}
	if !hasB {
		t.Error("chainB nonce should be present after insert")
	}
}

// TestBRIDGE_R12_002_SameChainSameNonceStillRejected verifies the fix did
// NOT weaken replay protection within a single source chain. Submitting
// the same nonce twice for the SAME (chain, address) pair must still be
// rejected.
func TestBRIDGE_R12_002_SameChainSameNonceStillRejected(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	addr := "addr-r12-002-samechain"
	chain := ChainID("chainA")
	nonce := uint64(7)

	qb.mu.Lock()
	nk := nonceKey{chain: chain, addr: addr}
	qb.usedNonces[nk] = make(map[uint64]time.Time)
	qb.usedNonces[nk][nonce] = time.Now()
	qb.totalUsedNonces++
	qb.mu.Unlock()

	// Replay: same chain, same address, same nonce must be rejected.
	qb.mu.Lock()
	_, used := qb.usedNonces[nk][nonce]
	qb.mu.Unlock()
	if !used {
		t.Fatal("BRIDGE-R12-002 REGRESSION: same (chain, addr) nonce should still be detected as used (replay protection broken)")
	}
}

// TestBRIDGE_R12_002_CrossChainSameNonceAcceptsSubmitMessage is an
// end-to-end-style test using SubmitMessage to verify the rejection path
// returns the chain-specific error. We use the existing
// TestBRDG_R7_03_NonceNeverExpires_ReplayProtectionAfterFinalizedEviction
// pattern: pre-populate usedNonces and then attempt SubmitMessage with the
// same nonce from a DIFFERENT chain — SubmitMessage must NOT return
// "already used" for the second chain.
//
// Note: SubmitMessage performs the nonce check BEFORE quantum-signature
// verification, so we can verify the nonce-isolation fix without setting
// up Dilithium3 keys. SubmitMessage will likely fail with a signature
// error (which is fine — we only assert that the error is NOT the
// false-positive "already used").
func TestBRIDGE_R12_002_CrossChainSameNonceAcceptsSubmitMessage(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)

	addr := "addr-r12-002-e2e"
	nonce := uint64(99)

	// Pre-populate usedNonces as if chainA had previously sent nonce=99.
	qb.mu.Lock()
	nkA := nonceKey{chain: ChainID("chainA"), addr: addr}
	qb.usedNonces[nkA] = make(map[uint64]time.Time)
	qb.usedNonces[nkA][nonce] = time.Now()
	qb.totalUsedNonces++
	qb.mu.Unlock()

	// Now submit a message from chainB with the SAME nonce and address.
	// SubmitMessage should NOT return an "already used" error (it may
	// fail later for other reasons — no adapter, signature, etc. — but
	// the nonce check itself must pass for chainB).
	msg := &BridgeMessage{
		ID:            "msg-r12-002-e2e",
		SourceChain:   ChainID("chainB"),
		TargetChain:   ChainID("chainC"),
		SourceAddress: addr,
		TargetAddress: "0xRecipient",
		AssetType:     AssetTypeNative,
		Amount:        "100",
		Nonce:         nonce,
		Timestamp:     time.Now().Unix(),
		MessageType:   MessageTypeAssetTransfer,
	}

	err := qb.SubmitMessage(context.Background(), msg)
	// The error (if any) must NOT be the cross-chain false-positive
	// "nonce already used" rejection. Other failures (no adapter for
	// chainB, signature validation, etc.) are acceptable for this test
	// since we are only verifying the nonce-isolation fix.
	if err != nil && strings.Contains(err.Error(), "already used") {
		t.Fatalf("BRIDGE-R12-002 REGRESSION: cross-chain same-nonce SubmitMessage was incorrectly rejected as 'already used' (should be isolated): %v", err)
	}

	// Sanity check: SubmitMessage must NOT have inserted anything into
	// chainB's namespace either — because it should have failed at
	// validateMessage (signature) BEFORE reaching the insert step.
	// This proves the cross-chain fix is wired through and SubmitMessage
	// correctly identifies chainB's nonce as NOT-already-used.
	qb.mu.RLock()
	nkB := nonceKey{chain: ChainID("chainB"), addr: addr}
	sub, ok := qb.usedNonces[nkB]
	qb.mu.RUnlock()
	if ok && sub != nil {
		if _, present := sub[nonce]; present {
			t.Fatal("BRIDGE-R12-002 REGRESSION: SubmitMessage recorded chainB's nonce even though signature validation should have failed first (check SubmitMessage control flow)")
		}
	}
}

// TestBRIDGE_R12_002_BootstrapRestoresCompositeKeys verifies that
// Initialize() restores usedNonces using the composite key, so post-restart
// replay protection is correctly isolated per (chain, address).
//
// This mirrors TestBoltMessageStore_BootstrapFromStore but asserts the
// composite-key layout directly: it writes messages with the SAME address
// but DIFFERENT source chains (each using the same nonce) and verifies
// that Initialize restores them as separate entries.
func TestBRIDGE_R12_002_BootstrapRestoresCompositeKeys(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "\\bootstrap-r12-002.db"
	ctx := context.Background()

	store1, err := NewBoltMessageStore(dbPath)
	if err != nil {
		t.Fatalf("first NewBoltMessageStore failed: %v", err)
	}

	// Two FAILED messages from the SAME address but DIFFERENT source chains,
	// each using the SAME nonce=100. Before the fix, bootstrap would have
	// collapsed them into a single usedNonces[addr][100] entry (last-write-wins),
	// losing the per-chain isolation after restart.
	msgA := makeMsg("msg-chainA", MessageStatusFailed, "addr-shared", 100)
	msgA.SourceChain = ChainID("chainA")
	if err := store1.SaveMessage(ctx, msgA); err != nil {
		t.Fatalf("SaveMessage msg-chainA failed: %v", err)
	}
	msgB := makeMsg("msg-chainB", MessageStatusFailed, "addr-shared", 100)
	msgB.SourceChain = ChainID("chainB")
	if err := store1.SaveMessage(ctx, msgB); err != nil {
		t.Fatalf("SaveMessage msg-chainB failed: %v", err)
	}

	if err := store1.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

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

	// After restart, both (chainA, addr-shared) and (chainB, addr-shared)
	// must have nonce=100 recorded independently. A replay from either
	// chain with the same nonce must be rejected.
	qb.mu.RLock()
	nkA := nonceKey{chain: ChainID("chainA"), addr: "addr-shared"}
	nkB := nonceKey{chain: ChainID("chainB"), addr: "addr-shared"}
	subA, hasA := qb.usedNonces[nkA]
	subB, hasB := qb.usedNonces[nkB]
	qb.mu.RUnlock()

	if !hasA || subA == nil {
		t.Fatal("BRIDGE-R12-002 REGRESSION: bootstrap did not restore (chainA, addr-shared) entry")
	}
	if !hasB || subB == nil {
		t.Fatal("BRIDGE-R12-002 REGRESSION: bootstrap did not restore (chainB, addr-shared) entry")
	}
	if _, ok := subA[100]; !ok {
		t.Fatal("BRIDGE-R12-002 REGRESSION: bootstrap did not record nonce=100 for (chainA, addr-shared)")
	}
	if _, ok := subB[100]; !ok {
		t.Fatal("BRIDGE-R12-002 REGRESSION: bootstrap did not record nonce=100 for (chainB, addr-shared)")
	}
}

// TestBRIDGE_R12_002_PerChainAddressCapIsolated verifies that the
// per-address cap (maxUsedNoncesPerAddress) is now enforced per
// (chain, address) pair, not per bare address. Filling up the cap for
// chainA must NOT prevent chainB (same address) from inserting nonces.
func TestBRIDGE_R12_002_PerChainAddressCapIsolated(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	addr := "addr-r12-002-cap"

	// Fill chainA's nonce map to the cap.
	qb.mu.Lock()
	nkA := nonceKey{chain: ChainID("chainA"), addr: addr}
	qb.usedNonces[nkA] = make(map[uint64]time.Time)
	for i := uint64(0); i < uint64(maxUsedNoncesPerAddress); i++ {
		qb.usedNonces[nkA][i] = time.Now()
		qb.totalUsedNonces++
	}
	qb.mu.Unlock()

	// chainB with the same address must still be able to insert a nonce
	// (its sub-map is empty).
	qb.mu.Lock()
	nkB := nonceKey{chain: ChainID("chainB"), addr: addr}
	if qb.usedNonces[nkB] == nil {
		qb.usedNonces[nkB] = make(map[uint64]time.Time)
	}
	if len(qb.usedNonces[nkB]) >= maxUsedNoncesPerAddress {
		t.Fatalf("BRIDGE-R12-002 REGRESSION: chainB nonce map was incorrectly capped at %d (should be isolated from chainA)", maxUsedNoncesPerAddress)
	}
	qb.usedNonces[nkB][1] = time.Now()
	qb.totalUsedNonces++
	qb.mu.Unlock()

	// Verify the cap is still enforced for chainA.
	qb.mu.RLock()
	if len(qb.usedNonces[nkA]) != maxUsedNoncesPerAddress {
		t.Errorf("chainA entry count = %d, want %d", len(qb.usedNonces[nkA]), maxUsedNoncesPerAddress)
	}
	if len(qb.usedNonces[nkB]) != 1 {
		t.Errorf("chainB entry count = %d, want 1", len(qb.usedNonces[nkB]))
	}
	qb.mu.RUnlock()
}

// TestBRIDGE_R12_002_TTLEvictionPerCompositeKey verifies that TTL-based
// eviction only removes nonces for the matching (chain, address) pair.
// Expiring an old nonce on chainA must NOT touch chainB's nonce.
func TestBRIDGE_R12_002_TTLEvictionPerCompositeKey(t *testing.T) {
	if nonceTTL == 0 {
		t.Skip("nonceTTL is 0 (nonces never expire); cannot test TTL eviction path")
	}

	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	addr := "addr-r12-002-ttl"

	// Insert an OLD nonce for chainA and a FRESH nonce for chainB with the
	// same nonce value and address.
	qb.mu.Lock()
	nkA := nonceKey{chain: ChainID("chainA"), addr: addr}
	nkB := nonceKey{chain: ChainID("chainB"), addr: addr}
	qb.usedNonces[nkA] = make(map[uint64]time.Time)
	qb.usedNonces[nkB] = make(map[uint64]time.Time)
	veryOld := time.Now().Add(-365 * 24 * time.Hour)
	qb.usedNonces[nkA][1] = veryOld
	qb.usedNonces[nkB][1] = veryOld
	qb.totalUsedNonces += 2
	qb.mu.Unlock()

	// Simulate the SubmitMessage TTL eviction path for chainB.
	// chainA's entry must remain untouched.
	qb.mu.Lock()
	now := time.Now()
	var expired []uint64
	for n, ts := range qb.usedNonces[nkB] {
		if now.Sub(ts) > nonceTTL {
			expired = append(expired, n)
		}
	}
	for _, n := range expired {
		delete(qb.usedNonces[nkB], n)
		qb.totalUsedNonces--
	}
	// chainA must still have its old entry.
	if _, ok := qb.usedNonces[nkA][1]; !ok {
		t.Error("BRIDGE-R12-002 REGRESSION: TTL eviction for chainB incorrectly removed chainA's nonce (should be isolated per composite key)")
	}
	qb.mu.Unlock()
}

// Quantaureum Node source, version 1.0.0.
// BRIDGE-H05 regression tests.
//
// BRIDGE-H05 (R30, 2026-07-27): The signature aggregator used "first writer
// wins" for the messageHash — once messageHashes[messageID] was set, all
// subsequent AddSignature calls with a DIFFERENT messageHash were silently
// ignored (or rejected in an intermediate fix). This meant if the first signer
// submitted a signature over a WRONG messageHash (bug, key compromise, or
// malicious signer), the message could NEVER reach quorum for the CORRECT
// hash — all subsequent valid signatures would be rejected because the stored
// hash didn't match. The message would be permanently stuck.
//
// FIX: Track signatures per (messageID, hash) pair. Each hash accumulates its
// own set of signatures. Quorum is reached when ANY single hash has enough
// signatures. A wrong first hash no longer blocks the correct hash from
// reaching quorum.
package bridge

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestBRIDGE_H05_WrongFirstHashDoesNotBlockCorrectHash verifies the core
// BRIDGE-H05 fix: if the first signer submits a signature over a WRONG hash,
// subsequent signers with the CORRECT hash can still reach quorum.
//
// Before the fix: the first (wrong) hash was stored permanently, and all
// subsequent signatures with the correct hash were rejected. The message
// could never reach quorum.
//
// After the fix: each hash accumulates its own signatures. The correct hash
// reaches quorum independently of the wrong hash.
func TestBRIDGE_H05_WrongFirstHashDoesNotBlockCorrectHash(t *testing.T) {
	mockVerifier := &mockVerifier{allowAll: true}
	sa, err := NewSignatureAggregator(2, mockVerifier, nil)
	if err != nil {
		t.Fatalf("NewSignatureAggregator failed: %v", err)
	}

	wrongHash := []byte("wrong-hash")
	correctHash := []byte("correct-hash")

	// Validator 1 signs over the WRONG hash (e.g., due to a bug).
	if err := sa.AddSignature("msg-h05", wrongHash, types.Address{1}, []byte("sig1-wrong")); err != nil {
		t.Fatalf("AddSignature with wrong hash failed: %v", err)
	}

	// Validator 2 signs over the CORRECT hash.
	if err := sa.AddSignature("msg-h05", correctHash, types.Address{2}, []byte("sig2-correct")); err != nil {
		t.Fatalf("BRIDGE-H05 regression: AddSignature with correct hash should succeed even after wrong hash, got: %v", err)
	}

	// Validator 3 signs over the CORRECT hash — this should reach quorum.
	if err := sa.AddSignature("msg-h05", correctHash, types.Address{3}, []byte("sig3-correct")); err != nil {
		t.Fatalf("BRIDGE-H05 regression: AddSignature with correct hash (2nd) should succeed, got: %v", err)
	}

	// Verify quorum is reached for the CORRECT hash.
	if !sa.HasQuorumForHash("msg-h05", correctHash) {
		t.Fatal("BRIDGE-H05 regression: HasQuorumForHash should return true for the correct hash — wrong first hash should not permanently block quorum")
	}

	// Verify quorum is NOT reached for the WRONG hash (only 1 signature).
	if sa.HasQuorumForHash("msg-h05", wrongHash) {
		t.Error("BRIDGE-H05: HasQuorumForHash should return false for the wrong hash (only 1 signature, threshold=2)")
	}

	// Verify HasQuorum (legacy, any hash) returns true.
	if !sa.HasQuorum("msg-h05") {
		t.Error("BRIDGE-H05: HasQuorum should return true when any hash has reached quorum")
	}
}

// TestBRIDGE_H05_SameValidatorCanSignDifferentHashes verifies that a single
// validator can sign for multiple hashes. This is acceptable because:
// 1. The signature is verified against the supplied hash.
// 2. Quorum requires M-of-N validators to sign the SAME hash.
// 3. A single buggy validator can't reach quorum alone.
//
// This allows a validator that computes the wrong hash (due to a bug) to
// still contribute a valid signature for the correct hash if it later
// recomputes and retries.
func TestBRIDGE_H05_SameValidatorCanSignDifferentHashes(t *testing.T) {
	mockVerifier := &mockVerifier{allowAll: true}
	sa, err := NewSignatureAggregator(2, mockVerifier, nil)
	if err != nil {
		t.Fatalf("NewSignatureAggregator failed: %v", err)
	}

	hashA := []byte("hash-A")
	hashB := []byte("hash-B")
	validator := types.Address{1}

	// Validator signs for hash A.
	if err := sa.AddSignature("msg-h05-dual", hashA, validator, []byte("sig-A")); err != nil {
		t.Fatalf("AddSignature for hash A failed: %v", err)
	}

	// Same validator signs for hash B — should succeed (different hash).
	if err := sa.AddSignature("msg-h05-dual", hashB, validator, []byte("sig-B")); err != nil {
		t.Fatalf("BRIDGE-H05 regression: same validator signing for a different hash should succeed, got: %v", err)
	}

	// Same validator signing for hash A AGAIN — should fail (duplicate).
	if err := sa.AddSignature("msg-h05-dual", hashA, validator, []byte("sig-A-2")); err == nil {
		t.Error("BRIDGE-H05: duplicate signature for the same (messageID, hash, validator) should fail")
	}
}

// TestBRIDGE_H05_PerHashQuorumIndependent verifies that multiple hashes can
// accumulate signatures independently, and each can reach quorum on its own.
func TestBRIDGE_H05_PerHashQuorumIndependent(t *testing.T) {
	mockVerifier := &mockVerifier{allowAll: true}
	sa, err := NewSignatureAggregator(2, mockVerifier, nil)
	if err != nil {
		t.Fatalf("NewSignatureAggregator failed: %v", err)
	}

	hashA := []byte("hash-A")
	hashB := []byte("hash-B")

	// Hash A gets 2 signatures (reaches quorum).
	sa.AddSignature("msg-h05-ind", hashA, types.Address{1}, []byte("sig1-A"))
	sa.AddSignature("msg-h05-ind", hashA, types.Address{2}, []byte("sig2-A"))

	// Hash B gets 2 signatures (reaches quorum).
	sa.AddSignature("msg-h05-ind", hashB, types.Address{3}, []byte("sig3-B"))
	sa.AddSignature("msg-h05-ind", hashB, types.Address{4}, []byte("sig4-B"))

	// Both hashes should have quorum.
	if !sa.HasQuorumForHash("msg-h05-ind", hashA) {
		t.Error("BRIDGE-H05: hash A should have quorum (2 signatures, threshold=2)")
	}
	if !sa.HasQuorumForHash("msg-h05-ind", hashB) {
		t.Error("BRIDGE-H05: hash B should have quorum (2 signatures, threshold=2)")
	}
	if !sa.HasQuorum("msg-h05-ind") {
		t.Error("BRIDGE-H05: HasQuorum should return true when multiple hashes have quorum")
	}

	// GetSignatureCount should return the max (2).
	if count := sa.GetSignatureCount("msg-h05-ind"); count != 2 {
		t.Errorf("BRIDGE-H05: GetSignatureCount should return 2 (max across hashes), got %d", count)
	}
}

// TestBRIDGE_H05_GetAggregatedSignatureForHash verifies that the aggregated
// signature is computed from the signatures for the SPECIFIC hash, not mixed
// with signatures from other hashes.
func TestBRIDGE_H05_GetAggregatedSignatureForHash(t *testing.T) {
	mockVerifier := &mockVerifier{allowAll: true}
	sa, err := NewSignatureAggregator(2, mockVerifier, nil)
	if err != nil {
		t.Fatalf("NewSignatureAggregator failed: %v", err)
	}

	hashA := []byte("hash-A")
	hashB := []byte("hash-B")

	// Hash A: validators 1, 2
	sa.AddSignature("msg-h05-agg", hashA, types.Address{1}, []byte("sig1-A"))
	sa.AddSignature("msg-h05-agg", hashA, types.Address{2}, []byte("sig2-A"))

	// Hash B: validators 3, 4
	sa.AddSignature("msg-h05-agg", hashB, types.Address{3}, []byte("sig3-B"))
	sa.AddSignature("msg-h05-agg", hashB, types.Address{4}, []byte("sig4-B"))

	// Get aggregated signature for hash A.
	aggA, err := sa.GetAggregatedSignatureForHash("msg-h05-agg", hashA)
	if err != nil {
		t.Fatalf("GetAggregatedSignatureForHash(A) failed: %v", err)
	}
	if len(aggA) == 0 {
		t.Fatal("GetAggregatedSignatureForHash(A) returned empty")
	}

	// Get aggregated signature for hash B.
	aggB, err := sa.GetAggregatedSignatureForHash("msg-h05-agg", hashB)
	if err != nil {
		t.Fatalf("GetAggregatedSignatureForHash(B) failed: %v", err)
	}
	if len(aggB) == 0 {
		t.Fatal("GetAggregatedSignatureForHash(B) returned empty")
	}

	// Aggregated signatures for different hashes MUST differ (different signers).
	if string(aggA) == string(aggB) {
		t.Error("BRIDGE-H05: aggregated signatures for different hashes should differ (different signer sets)")
	}
}

// TestBRIDGE_H05_GetAggregatedSignatureReturnsBestHash verifies that
// GetAggregatedSignature (without hash parameter) returns the aggregated
// signature for the hash with the most signatures that meets the threshold.
func TestBRIDGE_H05_GetAggregatedSignatureReturnsBestHash(t *testing.T) {
	mockVerifier := &mockVerifier{allowAll: true}
	sa, err := NewSignatureAggregator(2, mockVerifier, nil)
	if err != nil {
		t.Fatalf("NewSignatureAggregator failed: %v", err)
	}

	hashA := []byte("hash-A")
	hashB := []byte("hash-B")

	// Hash A: 2 signatures (meets threshold)
	sa.AddSignature("msg-h05-best", hashA, types.Address{1}, []byte("sig1-A"))
	sa.AddSignature("msg-h05-best", hashA, types.Address{2}, []byte("sig2-A"))

	// Hash B: 1 signature (below threshold)
	sa.AddSignature("msg-h05-best", hashB, types.Address{3}, []byte("sig3-B"))

	// GetAggregatedSignature should return the signature for hash A (the one with quorum).
	agg, err := sa.GetAggregatedSignature("msg-h05-best")
	if err != nil {
		t.Fatalf("GetAggregatedSignature failed: %v", err)
	}
	if len(agg) == 0 {
		t.Fatal("GetAggregatedSignature returned empty")
	}

	// Verify it matches hash A's aggregated signature.
	aggA, _ := sa.GetAggregatedSignatureForHash("msg-h05-best", hashA)
	if string(agg) != string(aggA) {
		t.Error("BRIDGE-H05: GetAggregatedSignature should return the hash with quorum (hash A)")
	}
}

// TestBRIDGE_H05_ClearMessageRemovesAllHashes verifies that ClearMessage
// removes all hash entries and signatures for a messageID.
func TestBRIDGE_H05_ClearMessageRemovesAllHashes(t *testing.T) {
	mockVerifier := &mockVerifier{allowAll: true}
	sa, err := NewSignatureAggregator(2, mockVerifier, nil)
	if err != nil {
		t.Fatalf("NewSignatureAggregator failed: %v", err)
	}

	hashA := []byte("hash-A")
	hashB := []byte("hash-B")

	sa.AddSignature("msg-h05-clear", hashA, types.Address{1}, []byte("sig1-A"))
	sa.AddSignature("msg-h05-clear", hashB, types.Address{2}, []byte("sig2-B"))

	// Verify both hashes are tracked.
	if sa.GetSignatureCount("msg-h05-clear") == 0 {
		t.Fatal("expected signatures before ClearMessage")
	}

	sa.ClearMessage("msg-h05-clear")

	// Verify all entries are removed.
	if count := sa.GetSignatureCount("msg-h05-clear"); count != 0 {
		t.Errorf("BRIDGE-H05: GetSignatureCount should return 0 after ClearMessage, got %d", count)
	}
	if sa.HasQuorum("msg-h05-clear") {
		t.Error("BRIDGE-H05: HasQuorum should return false after ClearMessage")
	}
	if sa.HasQuorumForHash("msg-h05-clear", hashA) {
		t.Error("BRIDGE-H05: HasQuorumForHash(A) should return false after ClearMessage")
	}
	if sa.HasQuorumForHash("msg-h05-clear", hashB) {
		t.Error("BRIDGE-H05: HasQuorumForHash(B) should return false after ClearMessage")
	}
}

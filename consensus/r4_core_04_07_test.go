// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR4CORE04_RequestSeal_RejectsNonCanonicalBlockHash verifies that
// RequestSeal now refuses to seal a (slot, blockHash) pair when the
// canonical slot root is known and doesn't match blockHash.
//
// AUDIT (2026) R4-CORE-04: Previously, RequestSeal accepted ANY
// (slot, blockHash) pair as long as the Review Chamber approved it,
// without verifying that blockHash is the canonical block at that slot.
// A threshold of executive chamber members could sign a non-canonical
// fork block, and it would be accepted as finalized. This test verifies
// the first line of defense (RequestSeal canonical check).
func TestR4CORE04_RequestSeal_RejectsNonCanonicalBlockHash(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	// Approve slot 5 in Review Chamber.
	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[5] = &ReviewSlotResult{
		Slot:          5,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	// Set the canonical slot root for slot 5.
	canonicalHash := types.Hash{0x11}
	qpos.SetSlotBlockRoot(5, canonicalHash)

	// Try to seal a NON-canonical block hash (different from canonical).
	nonCanonicalHash := types.Hash{0x22}
	err = qpos.RequestQTDFinalitySeal(5, nonCanonicalHash)
	if err == nil {
		t.Fatal("R4-CORE-04 REGRESSION: RequestSeal accepted a non-canonical block hash — should have been rejected")
	}
	t.Logf("=== R4-CORE-04: RequestSeal correctly rejected non-canonical blockHash: %v ===", err)
}

// TestR4CORE04_RequestSeal_AcceptsCanonicalBlockHash verifies that
// RequestSeal accepts a blockHash that matches the canonical slot root.
// This is the non-regression case: the fix must not break legitimate sealing.
func TestR4CORE04_RequestSeal_AcceptsCanonicalBlockHash(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[5] = &ReviewSlotResult{
		Slot:          5,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	// Set the canonical slot root for slot 5.
	canonicalHash := types.Hash{0xAB}
	qpos.SetSlotBlockRoot(5, canonicalHash)

	// Seal the canonical block hash — should succeed.
	err = qpos.RequestQTDFinalitySeal(5, canonicalHash)
	if err != nil {
		t.Fatalf("R4-CORE-04: RequestSeal should accept canonical blockHash, got error: %v", err)
	}
	t.Logf("=== R4-CORE-04: RequestSeal correctly accepted canonical blockHash ===")
}

// TestR4CORE04_RequestSeal_NoCanonicalRoot_AllowsSeal verifies that
// when no canonical root is known for a slot (early-sync bootstrap case),
// RequestSeal still accepts the block hash. This is required for QTD
// bootstrapping — the first block has no prior canonical root recorded.
func TestR4CORE04_RequestSeal_NoCanonicalRoot_AllowsSeal(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[7] = &ReviewSlotResult{
		Slot:          7,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	// NOTE: deliberately do NOT call SetSlotBlockRoot for slot 7.
	// This simulates the early-sync bootstrap case.
	blockHash := types.Hash{0xCD}
	err = qpos.RequestQTDFinalitySeal(7, blockHash)
	if err != nil {
		t.Fatalf("R4-CORE-04: RequestSeal should accept blockHash when no canonical root is known (bootstrap), got: %v", err)
	}
	t.Logf("=== R4-CORE-04: RequestSeal correctly accepted blockHash in bootstrap mode (no canonical root) ===")
}

// TestR4CORE04_CompleteSeal_RejectsNonCanonicalAtFinalize verifies the
// second line of defense in completeSealLockedFinalize: even if
// RequestSeal passed (because no canonical root was known at the time),
// the finalize step rejects the seal if a canonical root has been
// recorded by the time the seal completes.
//
// This is defense-in-depth: catches the case where the canonical chain
// forked between RequestSeal and seal completion, or the canonical root
// was recorded after RequestSeal but before completeSealLockedFinalize.
func TestR4CORE04_CompleteSeal_RejectsNonCanonicalAtFinalize(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	qfs := qpos.GetQTDFinality()
	qfs.SetQTDSigner(&mockThresholdSigner{})

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	review := coordinator.GetReviewChamber()
	review.mu.Lock()
	review.slotResults[5] = &ReviewSlotResult{
		Slot:          5,
		CommitteeSize: 5,
		ApproveStake:  big.NewInt(3000),
		RejectStake:   big.NewInt(1000),
		TotalStake:    big.NewInt(4000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	// Request seal with a blockHash (no canonical root known yet).
	nonCanonicalHash := types.Hash{0x22}
	err = qpos.RequestQTDFinalitySeal(5, nonCanonicalHash)
	if err != nil {
		t.Fatalf("RequestSeal failed (should pass in bootstrap): %v", err)
	}

	// Now set the canonical slot root to a DIFFERENT hash — simulating a
	// fork happening between RequestSeal and completeSealLockedFinalize.
	canonicalHash := types.Hash{0x11}
	qpos.SetSlotBlockRoot(5, canonicalHash)

	// Submit partial seals — this triggers completeSealLockedFinalize.
	_ = qfs.SubmitPartialSeal(0, 5, []byte("partial-sig-0-min16bytes"))
	_ = qfs.SubmitPartialSeal(1, 5, []byte("partial-sig-1-min16bytes"))

	// The seal should have been accepted into instantFinalizedSlots
	// (the QTD signature itself is valid proof of threshold agreement),
	// but qpos.finalizedRoot should NOT have been written with the
	// non-canonical hash.
	if !qfs.IsSlotFinalized(5) {
		t.Fatal("QTD seal should be recorded in instantFinalizedSlots (signature is valid proof)")
	}

	// Verify qpos.finalizedRoot was NOT updated to the non-canonical hash.
	qpos.mu.RLock()
	finalizedRoot := qpos.finalizedRoot
	qpos.mu.RUnlock()

	if finalizedRoot == nonCanonicalHash {
		t.Fatal("R4-CORE-04 REGRESSION: qpos.finalizedRoot was written with non-canonical blockHash — completeSealLockedFinalize failed to reject non-canonical seal")
	}
	t.Logf("=== R4-CORE-04: completeSealLockedFinalize correctly rejected non-canonical finalize (finalizedRoot=%s, not nonCanonicalHash=%s) ===",
		finalizedRoot.String(), nonCanonicalHash.String())
}

// TestR4CORE07_IsCompressed_NoUnboundedDecompression verifies that
// IsCompressed does NOT allocate unbounded memory for a crafted payload
// with a huge declared decompressed length.
//
// AUDIT (2026) R4-CORE-07: Previously, IsCompressed called
// snappy.Decode(nil, data) which allocated the FULL declared decompressed
// length upfront. A small compressed input declaring a multi-gigabyte
// decompressed length would trigger unbounded memory allocation — a DoS
// amplification vector.
//
// Fix: IsCompressed now calls snappy.DecodedLen first (no allocation) and
// rejects payloads whose declared length exceeds 10MB before calling
// snappy.Decode. This test crafts a payload with a valid Snappy header
// declaring a huge length and verifies IsCompressed returns false quickly.
func TestR4CORE07_IsCompressed_NoUnboundedDecompression(t *testing.T) {
	// Craft a snappy block header that declares a huge decompressed length.
	// Snappy block format: varint(uncompressed_length) followed by tokens.
	// We craft a varint that declares 2GB (2,000,000,000) — far exceeding
	// the 10MB cap — followed by garbage bytes.
	// 2,000,000,000 in varint = 0x80 0x8A 0xD8 0xB7 0x07 (5 bytes, high bits set)
	// followed by 4 garbage bytes to meet the min-4-byte check.
	crafted := []byte{0x80, 0x8A, 0xD8, 0xB7, 0x07, 0xAA, 0xBB, 0xCC}

	// IsCompressed should return false (declared length exceeds 10MB cap)
	// WITHOUT allocating the declared 2GB.
	result := IsCompressed(crafted)
	if result {
		t.Fatal("R4-CORE-07: IsCompressed should return false for crafted payload with huge declared length (exceeds 10MB cap)")
	}
	t.Logf("=== R4-CORE-07: IsCompressed correctly rejected crafted payload with huge declared length without unbounded allocation ===")
}

// TestR4CORE07_IsCompressed_ValidLargePayload verifies that a legitimate
// large Snappy payload (within the 10MB cap) is correctly detected as
// compressed. This is the non-regression case: the cap must not reject
// legitimate payloads.
func TestR4CORE07_IsCompressed_ValidLargePayload(t *testing.T) {
	// Create a 1MB input, compress it, and verify IsCompressed returns true.
	largeInput := make([]byte, 1024*1024) // 1MB
	for i := range largeInput {
		largeInput[i] = byte(i % 256)
	}
	compressed, err := CompressAggregationBits(largeInput)
	if err != nil {
		t.Fatalf("CompressAggregationBits failed: %v", err)
	}

	result := IsCompressed(compressed)
	if !result {
		t.Fatal("R4-CORE-07: IsCompressed should return true for valid Snappy data (1MB input, within 10MB cap)")
	}
	t.Logf("=== R4-CORE-07: IsCompressed returned true for %d-byte compressed payload (1MB input, within cap) ===", len(compressed))
}

// TestR4CORE07_IsCompressed_RejectsNonSnappy verifies that IsCompressed
// returns false for non-Snappy data that has a valid varint header but
// invalid Snappy token stream.
func TestR4CORE07_IsCompressed_RejectsNonSnappy(t *testing.T) {
	// Data that starts with a valid varint but is NOT valid Snappy.
	// Varint 0x04 means "declared length = 4 bytes", but the remaining
	// bytes are not valid Snappy token stream.
	nonSnappy := []byte{0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}
	result := IsCompressed(nonSnappy)
	if result {
		t.Fatal("R4-CORE-07: IsCompressed should return false for non-Snappy data with valid varint header")
	}
	t.Logf("=== R4-CORE-07: IsCompressed correctly returned false for non-Snappy data ===")
}

// TestR4CORE07_IsCompressed_EmptyAndShort verifies edge cases.
func TestR4CORE07_IsCompressed_EmptyAndShort(t *testing.T) {
	if IsCompressed(nil) {
		t.Error("R4-CORE-07: IsCompressed(nil) should be false")
	}
	if IsCompressed([]byte{}) {
		t.Error("R4-CORE-07: IsCompressed([]byte{}) should be false")
	}
	if IsCompressed([]byte{0x01}) {
		t.Error("R4-CORE-07: IsCompressed([0x01]) should be false (too short)")
	}
	if IsCompressed([]byte{0x01, 0x02, 0x03}) {
		t.Error("R4-CORE-07: IsCompressed([0x01,0x02,0x03]) should be false (too short)")
	}
}

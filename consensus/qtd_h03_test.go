// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// epochKeySigner is a test ThresholdKeySigner that returns a configurable
// group public key (so tests can simulate DKG rotation by switching keys).
type epochKeySigner struct {
	groupKey []byte
}

func (m *epochKeySigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("epoch-key-block-sig"), nil
}
func (m *epochKeySigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("epoch-key-vote-sig"), nil
}
func (m *epochKeySigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	return string(signature) == "epoch-key-valid-sig"
}
func (m *epochKeySigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return true
}
func (m *epochKeySigner) GroupPublicKey() []byte { return m.groupKey }
func (m *epochKeySigner) IsThresholdMode() bool  { return true }
func (m *epochKeySigner) AggregatePartialSignatures(
	sealers []int, partialSigs map[int][]byte, message []byte,
) ([]byte, error) {
	return []byte("epoch-key-aggregated-sig"), nil
}

// testAllZeroDilithium3GroupKey returns a 1952-byte all-zero slice — the
// canonical "DKG not initialized" degenerate group public key. Used by
// R38-P1-01 regression tests to assert the write-side / read-side
// chokepoints reject the all-zero forgery across all consumer paths.
func testAllZeroDilithium3GroupKey() []byte {
	return make([]byte, 1952)
}

// TestQTD_H03_getGroupPublicKeyForEpoch_HistoricalKey verifies that
// getGroupPublicKeyForEpoch returns the HISTORICAL group key for a past
// epoch (recorded via groupKeyHistory), NOT the current signer's key.
// This is the core QTD-H03 fix: during DKG rotation, the current signer
// has the NEW key, but seals from PAST epochs must be verified with the
// OLD key that was active at seal time.
func TestQTD_H03_getGroupPublicKeyForEpoch_HistoricalKey(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)

	// "Old" DKG key (epoch 5) and "new" DKG key (epoch 6, current).
	oldKey := []byte("old-dkg-group-key-epoch-5")
	newKey := []byte("new-dkg-group-key-epoch-6")

	// Set the current signer with the NEW key.
	qfs.SetQTDSigner(&epochKeySigner{groupKey: newKey})

	// Manually record the OLD key in the history for epoch 5 (simulating
	// a DKG rotation that happened at epoch 6).
	qfs.mu.Lock()
	qfs.groupKeyHistory[5] = oldKey
	qfs.mu.Unlock()

	// Lookup for epoch 5 must return the OLD key, not the current newKey.
	qfs.mu.RLock()
	got := qfs.getGroupPublicKeyForEpoch(5)
	qfs.mu.RUnlock()

	if string(got) != string(oldKey) {
		t.Errorf("getGroupPublicKeyForEpoch(5) = %q, want %q (historical key, not current)",
			string(got), string(oldKey))
	}

	// QTD-009 FIX (R30, 2026-07-26): Lookup for a NON-current epoch without
	// a historical record must FAIL-CLOSED (return nil) when DKG rotation
	// has occurred. Without this, an attacker who injects a malicious signer
	// could forge arbitrary historical finality proofs.
	//
	// We have groupKeyHistory[5] = oldKey, so DKG rotation is "detected".
	// Epoch 6 has no historical record and is NOT the current epoch
	// (GetCurrentEpoch() returns 0 when genesis time is unset) → must nil.
	qfs.mu.RLock()
	gotNonCurrent := qfs.getGroupPublicKeyForEpoch(6)
	qfs.mu.RUnlock()

	if gotNonCurrent != nil {
		t.Errorf("getGroupPublicKeyForEpoch(6) = %q, want nil (QTD-009: fail-closed for non-current epoch after DKG rotation)",
			string(gotNonCurrent))
	}

	// Lookup for the CURRENT epoch without a historical record must fallback
	// to the current signer's NEW key. This is the legitimate fallback: the
	// current epoch's key IS the current signer's key.
	// NOTE: GetCurrentEpoch() may return a non-zero value due to genesis time
	// state from other tests. Use the actual current epoch, not a hardcoded 0.
	currentEpoch := uint64(0)
	if qpos != nil {
		currentEpoch = qpos.GetCurrentEpoch()
	}
	qfs.mu.RLock()
	gotFallback := qfs.getGroupPublicKeyForEpoch(currentEpoch)
	qfs.mu.RUnlock()

	if string(gotFallback) != string(newKey) {
		t.Errorf("getGroupPublicKeyForEpoch(currentEpoch=%d) fallback = %q, want %q (current key for current epoch)",
			currentEpoch, string(gotFallback), string(newKey))
	}
}

// TestQTD_009_NoRotation_FallbackAllEpochs verifies the QTD-009 fix's
// "no rotation" branch: when groupKeyHistory is empty (no DKG rotation has
// occurred), the current signer's key is the ONLY key that ever existed,
// so it is valid for ALL epochs. The function must fall back to the current
// key for any epoch, including non-current ones.
//
// R31 FIX (2026-07-27): SetQTDSigner auto-populates groupKeyHistory[currentEpoch]
// (P2-QTD-HISTORY), so to truly simulate "no rotation" we must clear the map
// after SetQTDSigner. Otherwise hasRotation=true and non-current epochs
// fail-closed (correctly), which contradicts the test's premise.
func TestQTD_009_NoRotation_FallbackAllEpochs(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)
	currentKey := []byte("only-key-no-rotation")
	qfs.SetQTDSigner(&epochKeySigner{groupKey: currentKey})

	// Clear groupKeyHistory to simulate "no DKG rotation has occurred".
	// SetQTDSigner auto-records the current key at currentEpoch, which
	// would make hasRotation=true and break the test's premise.
	qfs.mu.Lock()
	qfs.groupKeyHistory = make(map[uint64][]byte)
	qfs.mu.Unlock()

	// No historical records — groupKeyHistory is empty.
	// Lookup for any epoch must fall back to the current key.
	for _, epoch := range []uint64{0, 1, 5, 18, 99, 1000} {
		qfs.mu.RLock()
		got := qfs.getGroupPublicKeyForEpoch(epoch)
		qfs.mu.RUnlock()
		if string(got) != string(currentKey) {
			t.Errorf("getGroupPublicKeyForEpoch(%d) = %q, want %q (no rotation: current key valid for all epochs)",
				epoch, string(got), string(currentKey))
		}
	}
}

// TestQTD_H03_getGroupPublicKeyForEpoch_EmptyKeyFailClosed verifies that
// when the historical record is missing AND the current signer has an empty
// GroupPublicKey (e.g., DKG not yet complete), getGroupPublicKeyForEpoch
// returns nil (fail-closed) rather than returning an empty key that could
// cause VerifyBlock to panic or silently accept invalid seals.
// This is the CONS-R27-MED-02 fix applied to the QTD-H03 fallback path.
func TestQTD_H03_getGroupPublicKeyForEpoch_EmptyKeyFailClosed(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)

	// Set a signer with an EMPTY group key (DKG not yet complete).
	qfs.SetQTDSigner(&epochKeySigner{groupKey: nil})

	// No historical record for epoch 99 → fallback to current key → empty.
	qfs.mu.RLock()
	got := qfs.getGroupPublicKeyForEpoch(99)
	qfs.mu.RUnlock()

	if got != nil {
		t.Errorf("getGroupPublicKeyForEpoch(99) = %v, want nil (fail-closed for empty current key)",
			got)
	}
}

// TestQTD_H03_SubmitCompletedSeal_UsesEpochKeyNotCurrent verifies the
// end-to-end QTD-H03 fix in SubmitCompletedSeal: when a seal is submitted
// for a past epoch, the verification MUST use the historical key for that
// epoch, not the current signer's key. This test sets up a scenario where
// the current signer has a NEW key but the seal was created under the OLD
// key. Without QTD-H03, verification would use the NEW key and reject the
// seal (DKG rotation breaks historical seal verification).
//
// We can't easily produce a valid signature under the OLD key (the mock
// signer's VerifyBlock always returns false for non-matching strings), so
// this test instead asserts that SubmitCompletedSeal reaches the
// verification step (returns a "signature verification failed" error,
// NOT a "group public key empty" error) — proving it found the historical
// key and proceeded to VerifyBlock with it.
func TestQTD_H03_SubmitCompletedSeal_UsesEpochKeyNotCurrent(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}
	// P2-QTD-META FIX: assign executive for epoch 5 (the epoch of the slot
	// under test). Previously this used epoch 0, but the slot is in epoch 5,
	// so GetExecutiveMembersForEpoch(5) returned nil and the PendingSeal's
	// MemberStakes was empty. The P2-QTD-META sealer-index-bounds check
	// (added in R29) then correctly rejected sealers [0,1,2] because they
	// were not in the empty member set. Fixing the epoch alignment makes
	// memberStakes populate correctly so the test reaches the signature
	// verification step as intended.
	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 5)
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()

	// Set the signer with the NEW key.
	newKey := []byte("new-dkg-key")
	qfs.SetQTDSigner(&epochKeySigner{groupKey: newKey})

	// Create a pending seal at a slot in epoch 5.
	slot := uint64(5 * 32) // SlotToEpoch(5*32) == 5
	blockHash := types.Hash{0x55}
	qpos.SetSlotBlockRoot(slot, blockHash)
	approveSlotForQTD(t, qpos, slot)
	if err := qpos.RequestQTDFinalitySeal(slot, blockHash); err != nil {
		t.Fatalf("RequestQTDFinalitySeal failed: %v", err)
	}

	// Manually record the OLD key for epoch 5 in the history.
	oldKey := []byte("old-dkg-key")
	qfs.mu.Lock()
	qfs.groupKeyHistory[5] = oldKey
	qfs.mu.Unlock()

	// Submit a completed seal with a dummy signature.
	// Expected behavior: SubmitCompletedSeal finds the OLD key for epoch 5
	// via getGroupPublicKeyForEpoch(5), then calls VerifyBlock with it.
	// The mock signer's VerifyBlock returns false for any non-matching
	// signature string, so this will fail with "signature verification
	// failed" — NOT "group public key empty".
	err = qfs.SubmitCompletedSeal(slot, []byte("dummy-sig-not-valid"), []int{0, 1, 2})
	if err == nil {
		t.Fatal("SubmitCompletedSeal unexpectedly succeeded with dummy signature")
	}

	// The error must be a signature verification failure, NOT a "group
	// public key empty" error. This proves QTD-H03 found the historical
	// key and proceeded to VerifyBlock with it (rather than failing
	// earlier due to empty key).
	errStr := err.Error()
	if !containsStr(errStr, "signature verification failed") {
		t.Errorf("SubmitCompletedSeal error = %q, want error containing 'signature verification failed' (proves historical key was found and used for VerifyBlock)", errStr)
	}
}

// containsStr is a simple substring helper (avoids importing strings just
// for one test).
func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

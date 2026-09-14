// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// keyAwareSigner is a test ThresholdKeySigner whose VerifyBlock validates
// based on the pubKey parameter. It returns true ONLY when pubKey matches
// the expectedKey. This lets tests distinguish between "used the historical
// key" (expected) vs "used the current key" (bug).
//
// Used by CONS-P0-01 regression tests to verify VerifyInstantFinality
// routes through getGroupPublicKeyForEpochLocked (historical key) instead
// of qtdSigner.GroupPublicKey() (current key).
type keyAwareSigner struct {
	currentKey  []byte // returned by GroupPublicKey()
	expectedKey []byte // only key VerifyBlock accepts
}

func (m *keyAwareSigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("key-aware-sig"), nil
}
func (m *keyAwareSigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("key-aware-vote-sig"), nil
}
func (m *keyAwareSigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	if len(pubKey) != len(m.expectedKey) {
		return false
	}
	for i := range pubKey {
		if pubKey[i] != m.expectedKey[i] {
			return false
		}
	}
	return true
}
func (m *keyAwareSigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return true
}
func (m *keyAwareSigner) GroupPublicKey() []byte { return m.currentKey }
func (m *keyAwareSigner) IsThresholdMode() bool  { return true }
func (m *keyAwareSigner) AggregatePartialSignatures(
	sealers []int, partialSigs map[int][]byte, message []byte,
) ([]byte, error) {
	return []byte("key-aware-aggregated-sig"), nil
}

// TestCONS_P0_01_VerifyInstantFinality_UsesHistoricalKey verifies the
// CONS-P0-01 fix: VerifyInstantFinality must use the historical group
// public key for the slot's epoch (via getGroupPublicKeyForEpochLocked),
// NOT the current signer's key. During DKG rotation, the current signer
// has the NEW key, but seals from PAST epochs must be verified with the
// OLD key that was active at seal time.
//
// Setup:
//   - currentKey = NEW key (returned by qtdSigner.GroupPublicKey())
//   - historicalKey = OLD key (recorded in groupKeyHistory for epoch 5)
//   - mock signer's VerifyBlock returns true ONLY when pubKey == historicalKey
//
// Expected:
//   - VerifyInstantFinality(slot_in_epoch_5, ..., valid_sig) returns true
//     (proves it used the historical key)
//   - If VerifyInstantFinality used the current key, VerifyBlock would
//     return false → test fails (this is the pre-fix bug).
func TestCONS_P0_01_VerifyInstantFinality_UsesHistoricalKey(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)

	historicalKey := []byte("old-dkg-key-epoch-5")
	currentKey := []byte("new-dkg-key-epoch-6")

	// Signer reports currentKey but VerifyBlock only accepts historicalKey.
	// If VerifyInstantFinality uses currentKey, VerifyBlock returns false.
	qfs.SetQTDSigner(&keyAwareSigner{
		currentKey:  currentKey,
		expectedKey: historicalKey,
	})

	// Record historical key for epoch 5 (simulating DKG rotation at epoch 6).
	qfs.mu.Lock()
	qfs.groupKeyHistory[5] = historicalKey
	qfs.mu.Unlock()

	// Slot in epoch 5 (SlotsPerEpoch assumed to be 32; SlotToEpoch(5*32) == 5).
	// Use whatever SlotsPerEpoch is at runtime to be safe.
	slot := uint64(5 * SlotsPerEpoch)
	blockHash := types.Hash{0xAB}

	// Pre-fix: VerifyInstantFinality used qtdSigner.GroupPublicKey() =
	// currentKey → VerifyBlock(currentKey, ...) = false → returns false.
	// Post-fix (CONS-P0-01): uses getGroupPublicKeyForEpochLocked(5) =
	// historicalKey → VerifyBlock(historicalKey, ...) = true → returns true.
	result := qfs.VerifyInstantFinality(slot, blockHash, []byte("any-sig"))
	if !result {
		t.Errorf("CONS-P0-01 NOT FIXED: VerifyInstantFinality returned false for epoch-5 slot. "+
			"Expected true (uses historical key %q), got false (likely used current key %q).",
			string(historicalKey), string(currentKey))
	}
}

// TestCONS_P0_01_VerifyInstantFinality_CurrentEpochUsesCurrentKey verifies
// the complementary case: for the CURRENT epoch (no DKG rotation or the
// current epoch's key), VerifyInstantFinality must use the current signer's
// key. This is the legitimate fallback in getGroupPublicKeyForEpochLocked.
func TestCONS_P0_01_VerifyInstantFinality_CurrentEpochUsesCurrentKey(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)

	currentKey := []byte("only-key-no-rotation")

	// No DKG rotation (groupKeyHistory empty) → currentKey is valid for ALL epochs.
	qfs.SetQTDSigner(&keyAwareSigner{
		currentKey:  currentKey,
		expectedKey: currentKey, // VerifyBlock accepts currentKey
	})

	// Slot in any epoch (use 0 for simplicity — current epoch is 0 when
	// genesis time is unset, which is the test default).
	slot := uint64(0)
	blockHash := types.Hash{0xCD}

	// No historical records → fallback to currentKey → VerifyBlock accepts.
	result := qfs.VerifyInstantFinality(slot, blockHash, []byte("any-sig"))
	if !result {
		t.Errorf("VerifyInstantFinality returned false for current-epoch slot with no rotation. "+
			"Expected true (uses current key %q).", string(currentKey))
	}
}

// TestCONS_P0_01_VerifyInstantFinalization_FailClosedOnEmptyKey verifies
// that VerifyInstantFinality fails closed when no group key is available
// for the requested epoch (e.g., DKG rotation occurred but no historical
// record exists for the non-current epoch). This is the QTD-009 fail-closed
// guarantee, now applied to the public VerifyInstantFinality entry point.
func TestCONS_P0_01_VerifyInstantFinality_FailClosedOnMissingHistoricalKey(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)

	currentKey := []byte("current-key-after-rotation")

	qfs.SetQTDSigner(&keyAwareSigner{
		currentKey:  currentKey,
		expectedKey: currentKey,
	})

	// Simulate DKG rotation: record a key for epoch 5, then query epoch 6.
	// Epoch 6 has no historical record AND is not the current epoch
	// (GetCurrentEpoch returns 0 in tests) → must fail-closed.
	qfs.mu.Lock()
	qfs.groupKeyHistory[5] = []byte("epoch-5-key")
	qfs.mu.Unlock()

	slot := uint64(6 * SlotsPerEpoch) // SlotToEpoch == 6
	blockHash := types.Hash{0xEF}

	// Pre-fix: VerifyInstantFinality used currentKey → VerifyBlock(currentKey) = true → WRONG (accepted).
	// Post-fix: uses getGroupPublicKeyForEpochLocked(6, currentEpoch=0) = nil → returns false (correct).
	result := qfs.VerifyInstantFinality(slot, blockHash, []byte("any-sig"))
	if result {
		t.Errorf("CONS-P0-01 NOT FIXED: VerifyInstantFinality returned true for epoch-6 slot " +
			"with no historical key. Expected false (fail-closed per QTD-009).")
	}
}

// TestCONS_P0_03_getGroupPublicKeyForEpochLocked_PrecomputesCurrentEpoch
// verifies the CONS-P0-03 fix: getGroupPublicKeyForEpochLocked takes a
// precomputed currentEpoch parameter (instead of calling
// qpos.GetCurrentEpoch() while holding qfs.mu). This test confirms the
// new function signature works correctly and returns the same results as
// the old wrapper-based approach.
//
// NOTE: SetQTDSigner automatically records the current key in
// groupKeyHistory[currentEpoch] (P2-QTD-HISTORY). To test the "no rotation"
// branch (groupKeyHistory empty), we must clear the map after SetQTDSigner.
func TestCONS_P0_03_getGroupPublicKeyForEpochLocked_PrecomputesCurrentEpoch(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)
	currentKey := []byte("current-key")
	qfs.SetQTDSigner(&epochKeySigner{groupKey: currentKey})

	// Precompute currentEpoch (this is the CONS-P0-03 pattern).
	currentEpoch := uint64(0)
	if qpos != nil {
		currentEpoch = qpos.GetCurrentEpoch()
	}

	// Case 1: No rotation → fallback to currentKey for any epoch.
	// Clear groupKeyHistory to simulate "no DKG rotation has occurred"
	// (SetQTDSigner auto-populates history, which we must undo for this case).
	qfs.mu.Lock()
	qfs.groupKeyHistory = make(map[uint64][]byte)
	qfs.mu.Unlock()

	qfs.mu.RLock()
	got := qfs.getGroupPublicKeyForEpochLocked(42, currentEpoch)
	qfs.mu.RUnlock()
	if string(got) != string(currentKey) {
		t.Errorf("Case 1: getGroupPublicKeyForEpochLocked(42, %d) = %q, want %q (no rotation: current key for all epochs)",
			currentEpoch, string(got), string(currentKey))
	}

	// Case 2: With rotation → historical key returned for past epoch.
	oldKey := []byte("old-key-epoch-3")
	qfs.mu.Lock()
	qfs.groupKeyHistory[3] = oldKey
	qfs.mu.Unlock()

	qfs.mu.RLock()
	gotHist := qfs.getGroupPublicKeyForEpochLocked(3, currentEpoch)
	qfs.mu.RUnlock()
	if string(gotHist) != string(oldKey) {
		t.Errorf("Case 2: getGroupPublicKeyForEpochLocked(3, %d) = %q, want %q (historical key for epoch 3)",
			currentEpoch, string(gotHist), string(oldKey))
	}

	// Case 3: With rotation → fail-closed for non-current epoch without history.
	qfs.mu.RLock()
	gotNil := qfs.getGroupPublicKeyForEpochLocked(99, currentEpoch)
	qfs.mu.RUnlock()
	if gotNil != nil {
		t.Errorf("Case 3: getGroupPublicKeyForEpochLocked(99, %d) = %q, want nil (fail-closed for non-current epoch after rotation)",
			currentEpoch, string(gotNil))
	}

	// Case 4: With rotation → fallback to currentKey for current epoch.
	// Re-add currentKey to history at currentEpoch (mimics SetQTDSigner behavior).
	qfs.mu.Lock()
	qfs.groupKeyHistory[currentEpoch] = currentKey
	qfs.mu.Unlock()

	qfs.mu.RLock()
	gotCurr := qfs.getGroupPublicKeyForEpochLocked(currentEpoch, currentEpoch)
	qfs.mu.RUnlock()
	if string(gotCurr) != string(currentKey) {
		t.Errorf("Case 4: getGroupPublicKeyForEpochLocked(%d, %d) = %q, want %q (current key for current epoch)",
			currentEpoch, currentEpoch, string(gotCurr), string(currentKey))
	}
}

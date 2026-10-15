// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
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

// Threshold implements consensus.ThresholdKeySigner. Returning 0 keeps the
// chamber-based quorum unchanged for this mock.
func (m *epochKeySigner) Threshold() int { return 0 }
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
	// a DKG rotation that happened at epoch 6). Pin the table to exactly
	// this one entry: SetQTDSigner above auto-recorded the live key under
	// the REAL current epoch, which is non-deterministic in this package
	// (the global genesis time is mutable by other tests) and would pollute
	// the floor-lookup assertions below.
	qfs.mu.Lock()
	qfs.groupKeyHistory = map[uint64][]byte{5: oldKey}
	qfs.mu.Unlock()

	// Lookup for epoch 5 must return the OLD key, not the current newKey.
	qfs.mu.RLock()
	got := qfs.getGroupPublicKeyForEpochLocked(5, 6)
	qfs.mu.RUnlock()

	if string(got) != string(oldKey) {
		t.Errorf("getGroupPublicKeyForEpochLocked(5, 6) = %q, want %q (historical key, not current)",
			string(got), string(oldKey))
	}

	// QTD-009 FIX (R30, 2026-07-26): once any history exists, a NON-current
	// epoch must NEVER be answered with the live signer's key — otherwise an
	// attacker who injects a malicious signer could forge arbitrary
	// historical finality proofs. After the QTD-H03 floor-lookup refinement
	// (2026-10-15) the fail-closed cases are exactly: (a) future epochs, and
	// (b) past epochs with no record at-or-before them. An epoch BETWEEN the
	// activation entry and the current epoch is served the activation key
	// (floor) — this is the last-slot-after-rollover scenario the refinement
	// fixed. Explicit currentEpoch values keep these assertions independent
	// of the package-global genesis time.
	qfs.mu.RLock()
	gotFuture := qfs.getGroupPublicKeyForEpochLocked(6, 5)
	qfs.mu.RUnlock()
	if gotFuture != nil {
		t.Errorf("getGroupPublicKeyForEpochLocked(6, current=5) = %q, want nil (QTD-009: future epoch fails closed after rotation)",
			string(gotFuture))
	}

	qfs.mu.RLock()
	gotPreActivation := qfs.getGroupPublicKeyForEpochLocked(4, 7)
	qfs.mu.RUnlock()
	if gotPreActivation != nil {
		t.Errorf("getGroupPublicKeyForEpochLocked(4, current=7) = %q, want nil (QTD-009: no entry at-or-before epoch 4)",
			string(gotPreActivation))
	}

	qfs.mu.RLock()
	gotFloor := qfs.getGroupPublicKeyForEpochLocked(6, 7)
	qfs.mu.RUnlock()
	if string(gotFloor) != string(oldKey) {
		t.Errorf("getGroupPublicKeyForEpochLocked(6, current=7) = %q, want %q (floor: newest entry at-or-before epoch 6, never the live key)",
			string(gotFloor), string(oldKey))
	}

	// Lookup for the CURRENT epoch without a historical record must fall back
	// to the current signer's NEW key. This is the legitimate fallback: the
	// current epoch's key IS the current signer's key. Explicit equal epochs
	// keep this independent of the package-global genesis time.
	qfs.mu.RLock()
	gotFallback := qfs.getGroupPublicKeyForEpochLocked(12, 12)
	qfs.mu.RUnlock()

	if string(gotFallback) != string(newKey) {
		t.Errorf("getGroupPublicKeyForEpochLocked(12, current=12) fallback = %q, want %q (current key for current epoch)",
			string(gotFallback), string(newKey))
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
	// R47-QTD-QUORUM: the weight check (ceil(2/3 of the FULL validator set
	// stake)) runs before signature verification. With 10 validators the
	// sealers {0,1,2} cover only 3000 of 6667, so the test would fail with a
	// weight error instead of reaching the signature-verification step this
	// test is designed to exercise. A 3-validator set makes the sealers
	// cover the full 3000 stake (>= 2000 required).
	vs := createTestValidatorSet(t, 3)
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

// TestQTD_H03_FloorLookup_ServesNewestEntryAtOrBeforeEpoch pins the
// floor-lookup contract of getGroupPublicKeyForEpochLocked (2026-10-15):
// the history table carries entries only at activation/rotation epochs, so
// for a PAST epoch with no exact record the lookup must serve the newest
// entry at-or-before it — while never serving the live signer's key, and
// failing closed for epochs before the first entry or in the future.
func TestQTD_H03_FloorLookup_ServesNewestEntryAtOrBeforeEpoch(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qfs := NewQTDFinalityState(qpos)

	liveKey := []byte("live-key-of-current-epoch")
	rotA := []byte("rotation-A-key-epoch-5")
	rotB := []byte("rotation-B-key-epoch-9")

	// Assign the signer directly under the lock instead of via SetQTDSigner:
	// SetQTDSigner auto-records the live key under the REAL current epoch,
	// which is non-deterministic in this package (the global genesis time is
	// mutable by other tests) and would pollute the floor matrix below.
	qfs.mu.Lock()
	qfs.qtdSigner = &epochKeySigner{groupKey: liveKey}
	qfs.groupKeyHistory[5] = rotA
	qfs.groupKeyHistory[9] = rotB
	qfs.mu.Unlock()

	const cur = uint64(12)
	cases := []struct {
		name  string
		epoch uint64
		want  []byte // nil means fail-closed
	}{
		{"before first entry: fail-closed", 4, nil},
		{"exact hit at first activation", 5, rotA},
		{"gap epoch: activation key still in force", 8, rotA},
		{"exact hit at rotation", 9, rotB},
		{"gap epoch after rotation: newest key", 11, rotB},
		{"current epoch: live signer fallback", 12, liveKey},
		{"future epoch: fail-closed", 13, nil},
	}
	for _, tc := range cases {
		qfs.mu.RLock()
		got := qfs.getGroupPublicKeyForEpochLocked(tc.epoch, cur)
		qfs.mu.RUnlock()
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: getGroupPublicKeyForEpochLocked(%d, current=%d) = %q, want %q",
				tc.name, tc.epoch, cur, string(got), string(tc.want))
		}
	}
}

// TestQTD_H03_SubmitCompletedSeal_BoundarySlotAfterRollover is the
// end-to-end regression for the QTD-H03 boundary failures observed on
// mainnet: the seal for the LAST slot of an epoch is assembled at the
// boundary and submitted only after the chain has already advanced into the
// next epoch. The custody table then holds only the activation-era entry —
// no exact record for the seal's epoch — so the exact-epoch lookup failed
// closed and the seal was rejected ("QTD-H03: group public key empty for
// epoch E (slot N)" with N%SlotsPerEpoch == SlotsPerEpoch-1 on every
// validator since arming). The floor lookup must resolve the seal's epoch
// to the entry in force at that epoch and let the seal complete — and the
// key-aware signer additionally proves it was the HISTORICAL key, not the
// live (already-rotated) one, that verified the seal.
func TestQTD_H03_SubmitCompletedSeal_BoundarySlotAfterRollover(t *testing.T) {
	// R47-QTD-QUORUM: a 3-validator set makes the sealers {0,1,2} cover the
	// full 3000 stake (>= 2000 required), as in the other SubmitCompletedSeal
	// test, so the weight check passes and the test reaches signature
	// verification.
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}
	const sealEpoch = uint64(5)
	if err := coordinator.AssignExecutive([]int{0, 1, 2}, sealEpoch); err != nil {
		t.Fatalf("AssignExecutive failed: %v", err)
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()

	// Pin genesis so the chain sits mid-epoch sealEpoch+1: the seal below
	// belongs to the FINAL slot of sealEpoch and is submitted only after the
	// rollover — the failure window seen on mainnet. Restored on exit.
	genesis := time.Now().Unix() - int64((sealEpoch+1)*SlotsPerEpoch+8)*int64(SlotDuration.Seconds())
	if err := SetGenesisTime(genesis); err != nil {
		t.Fatalf("SetGenesisTime failed: %v", err)
	}
	defer func() { _ = SetGenesisTime(time.Now().Unix()) }()

	// Post-rotation custody shape: the live signer already holds the ROTATED
	// key, and the only history entries are the old activation-era record
	// (epoch 3) plus the rotation record at the current epoch — no exact
	// record for the seal's epoch 5. The key-aware signer accepts
	// verification ONLY against the historical key, so a lookup that served
	// the live key here would fail the seal.
	rotatedKey := bytes.Repeat([]byte{0x21}, crypto.Dilithium3PublicKeySize) // satisfies the R39-P1-01 write gate
	activationKey := bytes.Repeat([]byte{0x7e}, crypto.Dilithium3PublicKeySize)
	qfs.SetQTDSigner(&keyAwareSigner{currentKey: rotatedKey, expectedKey: activationKey})
	qfs.mu.Lock()
	qfs.groupKeyHistory[3] = activationKey
	qfs.mu.Unlock()

	slot := sealEpoch*SlotsPerEpoch + (SlotsPerEpoch - 1) // last slot of sealEpoch
	blockHash := types.Hash{0x55}
	qpos.SetSlotBlockRoot(slot, blockHash)
	approveSlotForQTD(t, qpos, slot)
	if err := qpos.RequestQTDFinalitySeal(slot, blockHash); err != nil {
		t.Fatalf("RequestQTDFinalitySeal failed: %v", err)
	}

	if err := qfs.SubmitCompletedSeal(slot, []byte("any-valid-sig"), []int{0, 1, 2}); err != nil {
		t.Fatalf("boundary-slot seal after rollover must verify via the floor entry "+
			"(the pre-fix failure was 'group public key empty for epoch %d'), got: %v", sealEpoch, err)
	}

	qfs.mu.RLock()
	rec := qfs.instantFinalizedSlots[slot]
	qfs.mu.RUnlock()
	if rec == nil {
		t.Fatal("no instant-finality record published for the boundary slot")
	}
}

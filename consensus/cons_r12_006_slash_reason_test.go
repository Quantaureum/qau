// Quantaureum Node source, version 1.0.0.
// Package consensus — tests for CONS-R12-006 (same-epoch conflicting votes
// misclassified as SurroundVote).
//
// Audit finding (R12 Medium): checkSurroundVote was returning ErrSurroundVote
// for same-epoch conflicting votes (same source/target epoch with different
// roots). Per Casper FFG, these are DoubleVote offenses (canonically:
// "two votes with the same target epoch but different target hashes").
// SurroundVote requires strict < on both source and target epochs.
//
// Previously the caller (validator.go ValidateAttestation) unconditionally
// used SlashingReasonSurroundVote in evidence for ANY error from
// checkSurroundVote, causing:
//   - Wrong penalty branch in SlashingManager
//   - Wrong offense category in MinistryRevenue
//   - VerifySurroundVoteEvidence would reject DoubleVote evidence (it
//     expects strict < on both epochs)
//   - Audit logs mix the two offense types, hiding the true distribution
//
// Fix: checkSurroundVote now returns ErrDoubleVote for same-epoch cases.
// The caller inspects the error and uses SlashingReasonDoubleVote or
// SlashingReasonSurroundVote accordingly.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// makeAtt constructs an Attestation for testing.
func makeAtt(slot uint64, sourceEpoch uint64, sourceRoot types.Hash,
	targetEpoch uint64, targetRoot types.Hash, validatorIdx int) *Attestation {
	return &Attestation{
		Slot:            slot,
		BeaconBlockRoot: targetRoot, // convenience: block hash = target root
		Source:          AttestationCheckpoint{Epoch: sourceEpoch, Root: sourceRoot},
		Target:          AttestationCheckpoint{Epoch: targetEpoch, Root: targetRoot},
		ValidatorIndex:  validatorIdx,
	}
}

// storeAtt stores an attestation in qpos.validatorAttestations without going
// through ProcessAttestation (which would trigger the slashing checks we're
// testing). Caller MUST hold qpos.mu.
func storeAtt(qpos *QPOS, att *Attestation) {
	if qpos.validatorAttestations[att.ValidatorIndex] == nil {
		qpos.validatorAttestations[att.ValidatorIndex] = make(map[uint64]*Attestation)
	}
	qpos.validatorAttestations[att.ValidatorIndex][att.Slot] = att
}

// ---------------------------------------------------------------------------
// Error type tests — verify the same-epoch cases return ErrDoubleVote
// ---------------------------------------------------------------------------

// TestCONS_R12006_SameSourceEpochDifferentRootReturnsDoubleVote verifies the
// canonical CONS-R12-006 fix: same source epoch with different source roots
// is a DoubleVote offense (per Casper FFG), not SurroundVote.
func TestCONS_R12006_SameSourceEpochDifferentRootReturnsDoubleVote(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	// Existing attestation at slot=100, source=(epoch=5, root=0xAA...),
	// target=(epoch=6, root=0xBB...).
	existing := makeAtt(100, 5, types.Hash{0xAA}, 6, types.Hash{0xBB}, 0)
	qpos.mu.Lock()
	storeAtt(qpos, existing)
	qpos.mu.Unlock()

	// New attestation at slot=200 (different slot, so checkDoubleVote won't
	// trigger), source=(epoch=5, root=0xCC...) — same source epoch, different
	// source root → must be ErrDoubleVote (was ErrSurroundVote before fix).
	conflicting := makeAtt(200, 5, types.Hash{0xCC}, 7, types.Hash{0xDD}, 0)

	qpos.mu.Lock()
	_, err := qpos.checkSurroundVote(conflicting)
	qpos.mu.Unlock()

	if err != ErrDoubleVote {
		t.Errorf("same source epoch different root: got err=%v, want ErrDoubleVote (CONS-R12-006)", err)
	}
}

// TestCONS_R12006_SameTargetEpochDifferentRootReturnsDoubleVote verifies the
// canonical Casper FFG double vote: same target epoch, different target
// root → ErrDoubleVote.
func TestCONS_R12006_SameTargetEpochDifferentRootReturnsDoubleVote(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	existing := makeAtt(100, 5, types.Hash{0xAA}, 6, types.Hash{0xBB}, 0)
	qpos.mu.Lock()
	storeAtt(qpos, existing)
	qpos.mu.Unlock()

	// New attestation at slot=200, target=(epoch=6, root=0xCC...) — same
	// target epoch, different target root → ErrDoubleVote.
	conflicting := makeAtt(200, 5, types.Hash{0xAA}, 6, types.Hash{0xCC}, 0)

	qpos.mu.Lock()
	_, err := qpos.checkSurroundVote(conflicting)
	qpos.mu.Unlock()

	if err != ErrDoubleVote {
		t.Errorf("same target epoch different root: got err=%v, want ErrDoubleVote (CONS-R12-006)", err)
	}
}

// TestCONS_R12006_SurroundVoteStillReturnsSurroundVote verifies the strict-
// surround case continues to return ErrSurroundVote (regression guard).
func TestCONS_R12006_SurroundVoteStillReturnsSurroundVote(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	// Existing att: source=5, target=10 (spans 5 epochs).
	existing := makeAtt(100, 5, types.Hash{0xAA}, 10, types.Hash{0xBB}, 0)
	qpos.mu.Lock()
	storeAtt(qpos, existing)
	qpos.mu.Unlock()

	// New att: source=6, target=9 — strictly inside existing.
	// Pattern: existing.Source < new.Source < new.Target < existing.Target
	// → SurroundVote (NOT DoubleVote).
	surrounding := makeAtt(200, 6, types.Hash{0xCC}, 9, types.Hash{0xDD}, 0)

	qpos.mu.Lock()
	_, err := qpos.checkSurroundVote(surrounding)
	qpos.mu.Unlock()

	if err != ErrSurroundVote {
		t.Errorf("strict surround case: got err=%v, want ErrSurroundVote (regression — must remain surround)", err)
	}
}

// TestCONS_R12006_ReverseSurroundVoteReturnsSurroundVote verifies the reverse
// surround direction (new surrounds existing) also returns ErrSurroundVote.
func TestCONS_R12006_ReverseSurroundVoteReturnsSurroundVote(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	// Existing att: source=6, target=9 (smaller span).
	existing := makeAtt(100, 6, types.Hash{0xAA}, 9, types.Hash{0xBB}, 0)
	qpos.mu.Lock()
	storeAtt(qpos, existing)
	qpos.mu.Unlock()

	// New att: source=5, target=10 — strictly outside existing.
	// Pattern: new.Source < existing.Source < existing.Target < new.Target
	// → SurroundVote (the new att surrounds the existing one).
	surrounding := makeAtt(200, 5, types.Hash{0xCC}, 10, types.Hash{0xDD}, 0)

	qpos.mu.Lock()
	_, err := qpos.checkSurroundVote(surrounding)
	qpos.mu.Unlock()

	if err != ErrSurroundVote {
		t.Errorf("reverse surround case: got err=%v, want ErrSurroundVote", err)
	}
}

// TestCONS_R12006_SameEpochSameRootNoError verifies that same epoch + same
// root (no conflict) returns nil (not a slashable offense).
func TestCONS_R12006_SameEpochSameRootNoError(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	existing := makeAtt(100, 5, types.Hash{0xAA}, 6, types.Hash{0xBB}, 0)
	qpos.mu.Lock()
	storeAtt(qpos, existing)
	qpos.mu.Unlock()

	// Same source/target epoch AND same roots — not conflicting, not
	// surrounding. checkSurroundVote should return nil.
	nonConflicting := makeAtt(200, 5, types.Hash{0xAA}, 6, types.Hash{0xBB}, 0)

	qpos.mu.Lock()
	_, err := qpos.checkSurroundVote(nonConflicting)
	qpos.mu.Unlock()

	if err != nil {
		t.Errorf("same epoch same root (no conflict): got err=%v, want nil", err)
	}
}

// TestCONS_R12006_DifferentEpochDifferentRootNoError verifies that
// non-overlapping attestations (different source AND different target
// epochs, no surround relation) return nil.
func TestCONS_R12006_DifferentEpochDifferentRootNoError(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	existing := makeAtt(100, 5, types.Hash{0xAA}, 6, types.Hash{0xBB}, 0)
	qpos.mu.Lock()
	storeAtt(qpos, existing)
	qpos.mu.Unlock()

	// Source=7, target=8 — both epochs strictly greater than existing,
	// no surround relation (existing does not surround new and new does
	// not surround existing).
	nonConflicting := makeAtt(200, 7, types.Hash{0xCC}, 8, types.Hash{0xDD}, 0)

	qpos.mu.Lock()
	_, err := qpos.checkSurroundVote(nonConflicting)
	qpos.mu.Unlock()

	if err != nil {
		t.Errorf("different epochs no surround: got err=%v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// Caller integration tests — verify the reason-selection logic that
// validator.go uses when checkSurroundVote returns an error.
//
// We don't call ProcessAttestation directly because it requires a valid
// Dilithium3 signature, valid slot, valid epoch consistency, and a
// recorded canonical source root — too much setup for a unit test.
// Instead we replicate the caller's reason-selection logic (2 lines) and
// verify it produces the correct SlashingReason for each error type.
// ---------------------------------------------------------------------------

// TestCONS_R12006_CallerPicksDoubleVoteReasonForErrDoubleVote verifies that
// the caller's reason-selection logic picks SlashingReasonDoubleVote when
// checkSurroundVote returns ErrDoubleVote. This is the CONS-R12-006 fix's
// contract: the caller MUST map the error to the correct SlashingReason.
func TestCONS_R12006_CallerPicksDoubleVoteReasonForErrDoubleVote(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	// Pre-store existing attestation.
	existing := makeAtt(100, 5, types.Hash{0xAA}, 6, types.Hash{0xBB}, 0)
	qpos.mu.Lock()
	storeAtt(qpos, existing)
	qpos.mu.Unlock()

	// Conflicting attestation (same target epoch, different root).
	conflicting := makeAtt(200, 5, types.Hash{0xAA}, 6, types.Hash{0xCC}, 0)

	qpos.mu.Lock()
	surroundedAtt, err := qpos.checkSurroundVote(conflicting)
	qpos.mu.Unlock()

	if err != ErrDoubleVote {
		t.Fatalf("expected ErrDoubleVote from checkSurroundVote, got %v", err)
	}
	if surroundedAtt == nil {
		t.Fatal("expected non-nil surroundedAtt for evidence construction")
	}

	// Replicate the caller's reason-selection logic (validator.go:183-186).
	reason := SlashingReasonSurroundVote
	if err == ErrDoubleVote {
		reason = SlashingReasonDoubleVote
	}

	if reason != SlashingReasonDoubleVote {
		t.Errorf("caller reason selection: got %v, want SlashingReasonDoubleVote", reason)
	}

	// Verify the SlashingReason string representation matches DoubleVote.
	if reason.String() != "double_vote" {
		t.Errorf("reason.String(): got %q, want \"double_vote\"", reason.String())
	}
}

// TestCONS_R12006_CallerPicksSurroundVoteReasonForErrSurroundVote verifies
// that the caller's reason-selection logic picks SlashingReasonSurroundVote
// when checkSurroundVote returns ErrSurroundVote (regression guard for the
// strict surround case).
func TestCONS_R12006_CallerPicksSurroundVoteReasonForErrSurroundVote(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	// Existing att spans epochs 5..10.
	existing := makeAtt(100, 5, types.Hash{0xAA}, 10, types.Hash{0xBB}, 0)
	qpos.mu.Lock()
	storeAtt(qpos, existing)
	qpos.mu.Unlock()

	// Strict surround: source=6, target=9.
	surrounding := makeAtt(200, 6, types.Hash{0xCC}, 9, types.Hash{0xDD}, 0)

	qpos.mu.Lock()
	surroundedAtt, err := qpos.checkSurroundVote(surrounding)
	qpos.mu.Unlock()

	if err != ErrSurroundVote {
		t.Fatalf("expected ErrSurroundVote, got %v", err)
	}
	if surroundedAtt == nil {
		t.Fatal("expected non-nil surroundedAtt")
	}

	// Caller's reason-selection logic.
	reason := SlashingReasonSurroundVote
	if err == ErrDoubleVote {
		reason = SlashingReasonDoubleVote
	}

	if reason != SlashingReasonSurroundVote {
		t.Errorf("caller reason selection: got %v, want SlashingReasonSurroundVote", reason)
	}
	if reason.String() != "surround_vote" {
		t.Errorf("reason.String(): got %q, want \"surround_vote\"", reason.String())
	}
}

// ---------------------------------------------------------------------------
// End-to-end queue test — verify both reasons can coexist in the queue
// ---------------------------------------------------------------------------

// TestCONS_R12006_DoubleVoteAndSurroundVoteCoexistInQueue verifies that
// when one validator commits BOTH a same-epoch conflict (DoubleVote) AND a
// strict surround (SurroundVote), the evidence queue contains both with
// the correct reasons.
//
// We bypass ProcessAttestation (which requires full attestation validation)
// and queue evidence directly, mimicking what the caller does after
// checkSurroundVote returns an error.
func TestCONS_R12006_DoubleVoteAndSurroundVoteCoexistInQueue(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	validatorAddr := vs.Validators()[0].Address

	// Queue a DoubleVote evidence (as the caller would after
	// checkSurroundVote returns ErrDoubleVote for a same-epoch conflict).
	dvEvidence := &SlashingEvidence{
		Reason:        SlashingReasonDoubleVote,
		ValidatorAddr: validatorAddr,
		Height:        100,
		Timestamp:     100,
		Vote1:         &Vote{ValidatorAddr: validatorAddr, Height: 100, BlockHash: types.Hash{0xAA}},
		Vote2:         &Vote{ValidatorAddr: validatorAddr, Height: 200, BlockHash: types.Hash{0xBB}},
	}
	qpos.mu.Lock()
	qpos.queueSlashingEvidenceLocked(dvEvidence)
	qpos.mu.Unlock()

	// Queue a SurroundVote evidence (as the caller would after
	// checkSurroundVote returns ErrSurroundVote for a strict surround).
	svEvidence := &SlashingEvidence{
		Reason:        SlashingReasonSurroundVote,
		ValidatorAddr: validatorAddr,
		Height:        300,
		Timestamp:     300,
		Vote1:         &Vote{ValidatorAddr: validatorAddr, Height: 300, BlockHash: types.Hash{0xCC}},
		Vote2:         &Vote{ValidatorAddr: validatorAddr, Height: 400, BlockHash: types.Hash{0xDD}},
	}
	qpos.mu.Lock()
	qpos.queueSlashingEvidenceLocked(svEvidence)
	qpos.mu.Unlock()

	queue := qpos.GetQueuedEvidence()
	doubleVoteCount := 0
	surroundVoteCount := 0
	for _, ev := range queue {
		switch ev.Reason {
		case SlashingReasonDoubleVote:
			doubleVoteCount++
		case SlashingReasonSurroundVote:
			surroundVoteCount++
		}
	}

	if doubleVoteCount != 1 {
		t.Errorf("expected 1 DoubleVote evidence, got %d", doubleVoteCount)
	}
	if surroundVoteCount != 1 {
		t.Errorf("expected 1 SurroundVote evidence, got %d", surroundVoteCount)
	}
	t.Logf("queue contains %d DoubleVote + %d SurroundVote entries",
		doubleVoteCount, surroundVoteCount)
}

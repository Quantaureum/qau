// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// panickySigner is a test ThresholdKeySigner whose VerifyBlock panics.
// This simulates the QTD-H04/H06 attack vector: a malformed P2P message
// or a corrupted signer implementation that causes a panic during seal
// verification. Without defer recover() in ReceiveSealAnnouncement, this
// panic would kill the P2P message handler goroutine and stop all future
// QTD seal propagation (liveness DoS).
type panickySigner struct {
	groupKey []byte
}

func (p *panickySigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("panicky-signer-block-sig"), nil
}
func (p *panickySigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("panicky-signer-vote-sig"), nil
}
func (p *panickySigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	panic("QTD-H04/H06: simulated panic during VerifyBlock (malformed P2P payload or corrupted signer)")
}
func (p *panickySigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return true
}
func (p *panickySigner) GroupPublicKey() []byte { return p.groupKey }
func (p *panickySigner) IsThresholdMode() bool  { return true }
func (p *panickySigner) AggregatePartialSignatures(
	sealers []int, partialSigs map[int][]byte, message []byte,
) ([]byte, error) {
	return []byte("panicky-signer-aggregated-sig"), nil
}

// TestQTD_H04_H06_ReceiveSealAnnouncement_PanicRecovery verifies that
// ReceiveSealAnnouncement recovers from panics induced by malformed P2P
// payloads or corrupted signer implementations, returning false instead
// of crashing the calling goroutine.
//
// QTD-H04/H06 FIX (R29, 2026-07-25): ReceiveSealAnnouncement is invoked
// from the P2P message handler goroutine. Without defer recover(), a
// panic in VerifyBlock (or any downstream qpos method) would crash the
// goroutine and permanently stop QTD seal propagation for this node —
// a liveness DoS that an attacker could trigger by broadcasting a
// specially crafted seal announcement.
//
// This test sets up a panicky signer and submits a seal announcement
// that reaches VerifyBlock (the panic site). The fix's defer recover()
// must catch the panic and return false.
func TestQTD_H04_H06_ReceiveSealAnnouncement_PanicRecovery(t *testing.T) {
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
	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()

	// Install a signer whose VerifyBlock always panics.
	panickyKey := []byte("panicky-group-key")
	qfs.SetQTDSigner(&panickySigner{groupKey: panickyKey})

	// Set up a slot with a canonical block root so ReceiveSealAnnouncement
	// reaches the VerifyBlock call (the panic site).
	slot := uint64(300)
	blockHash := types.Hash{0xCC}
	qpos.SetSlotBlockRoot(slot, blockHash)

	// Call ReceiveSealAnnouncement with a non-empty signature. The
	// panicky signer's VerifyBlock will panic. Without the fix, this
	// test would crash with a panic. With the fix, the deferred
	// recover() catches it and returns false.
	ok := qfs.ReceiveSealAnnouncement(slot, blockHash, []byte("some-qtd-signature"), []int{0, 1, 2})

	if ok {
		t.Fatal("ReceiveSealAnnouncement returned true despite VerifyBlock panic — should have returned false (fail-closed)")
	}

	// Verify the slot was NOT stored in instantFinalizedSlots (panic
	// happened before storage, but verify defensive behavior).
	qfs.mu.RLock()
	_, stored := qfs.instantFinalizedSlots[slot]
	qfs.mu.RUnlock()
	if stored {
		t.Error("instantFinalizedSlots[slot] was stored despite panic — must not store on panic")
	}
}

// TestQTD_H04_H06_ReceiveSealAnnouncement_NilQposNoPanic verifies that
// ReceiveSealAnnouncement does not panic when qfs.qpos is nil (unit-test
// context). This is a defensive test for the qpos nil-check at line 1909.
func TestQTD_H04_H06_ReceiveSealAnnouncement_NilQposNoPanic(t *testing.T) {
	qfs := NewQTDFinalityState(nil) // qpos is nil
	qfs.SetQTDSigner(&epochKeySigner{groupKey: []byte("some-group-key")})

	slot := uint64(400)
	blockHash := types.Hash{0xDD}

	// Should not panic and should return false (verification fails since
	// the mock signer's VerifyBlock returns false for non-matching strings).
	ok := qfs.ReceiveSealAnnouncement(slot, blockHash, []byte("non-matching-sig"), []int{0, 1, 2})
	if ok {
		t.Fatal("ReceiveSealAnnouncement returned true with nil qpos and non-matching signature — should return false")
	}
}

// TestQTD_H04_H06_ReceiveSealAnnouncement_EmptySealersNoPanic verifies
// that ReceiveSealAnnouncement handles empty sealers list without panic.
// An attacker could broadcast a seal announcement with an empty sealers
// list as a malformed-message attack vector.
func TestQTD_H04_H06_ReceiveSealAnnouncement_EmptySealersNoPanic(t *testing.T) {
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
	_ = coordinator.AssignExecutive([]int{0, 1, 2}, 0)
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}
	if err := executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen)); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	qfs := qpos.GetQTDFinality()
	// Use epochKeySigner whose VerifyBlock returns true ONLY for the
	// string "epoch-key-valid-sig". With a non-matching sig, verification
	// fails before the sealers check — so to exercise the empty-sealers
	// path, we need a sig that passes VerifyBlock.
	// Instead, use a custom signer that always returns true.
	validSigner := &alwaysValidSigner{groupKey: []byte("valid-group-key")}
	qfs.SetQTDSigner(validSigner)

	slot := uint64(500)
	blockHash := types.Hash{0xEE}
	qpos.SetSlotBlockRoot(slot, blockHash)

	// Empty sealers should be rejected at the membership check (len==0),
	// not panic.
	ok := qfs.ReceiveSealAnnouncement(slot, blockHash, []byte("any-sig-16bytes"), []int{})
	if ok {
		t.Fatal("ReceiveSealAnnouncement returned true for empty sealers — should reject")
	}
}

// alwaysValidSigner is a test signer that always returns true for
// VerifyBlock, allowing tests to exercise post-verification code paths
// (like the sealers membership check).
type alwaysValidSigner struct {
	groupKey []byte
}

func (a *alwaysValidSigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("always-valid-block-sig"), nil
}
func (a *alwaysValidSigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return []byte("always-valid-vote-sig"), nil
}
func (a *alwaysValidSigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	return true
}
func (a *alwaysValidSigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return true
}
func (a *alwaysValidSigner) GroupPublicKey() []byte { return a.groupKey }
func (a *alwaysValidSigner) IsThresholdMode() bool  { return true }
func (a *alwaysValidSigner) AggregatePartialSignatures(
	sealers []int, partialSigs map[int][]byte, message []byte,
) ([]byte, error) {
	return []byte("always-valid-aggregated-sig"), nil
}

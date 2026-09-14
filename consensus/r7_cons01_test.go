// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// CONS-R7-01 (High) — SealedBidLottery.Finalize lacked a phase check and
// could be invoked during the Commit phase to terminate the lottery early.
//
// Audit source (AUDIT-R7-CONSENSUS-2026-07-17.md, CONS-R7-01):
//   "SealedBidLottery.Finalize lacking a phase check lets it abort during
//    the Commit phase"
//   Location: consensus/sealed_bid.go:370-405
//   "Add a phase guard at the start of Finalize()"
//
// Fix:
//   Finalize now calls updatePhaseLocked() upfront and only executes
//   during Reveal or Expired phases. Calls from Commit or Complete
//   return nil without effect.
//
// This test covers:
//   1. Finalize in Commit phase returns nil (no early termination)
//   2. Finalize in Reveal phase returns non-nil (normal path)
//   3. Finalize in Complete phase (second call) returns nil (no re-run)

// TestCONS_R7_01_FinalizeRejectedInCommitPhase verifies that Finalize
// returns nil when called during the Commit phase (before any reveals
// could be submitted). This prevents an attacker from winning the lottery
// as the sole revealer by finalizing early.
func TestCONS_R7_01_FinalizeRejectedInCommitPhase(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(700, 10*time.Second, 10*time.Second)
	// Phase is Commit (default)

	// Submit a commit but don't transition to Reveal
	addr := types.Address{0x01}
	output := &PQVRFOutput{}
	output.Value[0] = 0x42
	commit, _, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("CreateSealedBidCommitment: %v", err)
	}
	if err := sbl.SubmitCommit(commit); err != nil {
		t.Fatalf("SubmitCommit: %v", err)
	}

	// Attempt to Finalize during Commit phase
	result := sbl.Finalize()
	if result != nil {
		t.Fatalf("CONS-R7-01: Finalize must return nil during Commit phase; got non-nil result (SelectedAddr=%x)", result.SelectedAddr)
	}

	// Verify phase is still Commit (not changed to Complete)
	if phase := sbl.Phase(); phase == SealedBidPhaseComplete {
		t.Fatal("CONS-R7-01: phase must NOT change to Complete when Finalize is rejected")
	}

	t.Logf("CONS-R7-01 OK: Finalize rejected in Commit phase (returned nil)")
}

// TestCONS_R7_01_FinalizeAllowedInRevealPhase verifies that Finalize
// returns a valid result when called during the Reveal phase (normal path).
func TestCONS_R7_01_FinalizeAllowedInRevealPhase(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(700, 10*time.Second, 10*time.Second)

	addr := types.Address{0x01}
	output := &PQVRFOutput{}
	output.Value[0] = 0x42
	commit, nonce, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("CreateSealedBidCommitment: %v", err)
	}
	if err := sbl.SubmitCommit(commit); err != nil {
		t.Fatalf("SubmitCommit: %v", err)
	}

	sbl.TransitionToReveal()

	reveal := &SealedBidReveal{
		ValidatorAddr: addr,
		VRFProof:      &PQVRFProof{Proof: make([]byte, 64)},
		VRFOutput:     output,
		Nonce:         nonce,
		Timestamp:     time.Now(),
	}
	if err := sbl.submitRevealInternal(reveal); err != nil {
		t.Fatalf("submitRevealInternal: %v", err)
	}

	// Finalize during Reveal phase — should succeed
	result := sbl.Finalize()
	if result == nil {
		t.Fatal("CONS-R7-01: Finalize must return non-nil during Reveal phase")
	}
	if result.SelectedAddr != addr {
		t.Fatalf("CONS-R7-01: expected SelectedAddr %x, got %x", addr, result.SelectedAddr)
	}

	t.Logf("CONS-R7-01 OK: Finalize allowed in Reveal phase (SelectedAddr=%x)", result.SelectedAddr)
}

// TestCONS_R7_01_FinalizeRejectedInCompletePhase verifies that calling
// Finalize twice (second call in Complete phase) returns nil. This prevents
// re-finalization after the lottery has already concluded.
func TestCONS_R7_01_FinalizeRejectedInCompletePhase(t *testing.T) {
	sbl := NewSealedBidLotteryWithTimeouts(700, 10*time.Second, 10*time.Second)

	addr := types.Address{0x01}
	output := &PQVRFOutput{}
	output.Value[0] = 0x42
	commit, nonce, err := CreateSealedBidCommitment(addr, output)
	if err != nil {
		t.Fatalf("CreateSealedBidCommitment: %v", err)
	}
	if err := sbl.SubmitCommit(commit); err != nil {
		t.Fatalf("SubmitCommit: %v", err)
	}

	sbl.TransitionToReveal()

	reveal := &SealedBidReveal{
		ValidatorAddr: addr,
		VRFProof:      &PQVRFProof{Proof: make([]byte, 64)},
		VRFOutput:     output,
		Nonce:         nonce,
		Timestamp:     time.Now(),
	}
	if err := sbl.submitRevealInternal(reveal); err != nil {
		t.Fatalf("submitRevealInternal: %v", err)
	}

	// First Finalize — should succeed
	result1 := sbl.Finalize()
	if result1 == nil {
		t.Fatal("CONS-R7-01: first Finalize must succeed in Reveal phase")
	}

	// Second Finalize — should return nil (already Complete)
	result2 := sbl.Finalize()
	if result2 != nil {
		t.Fatal("CONS-R7-01: second Finalize must return nil (already Complete)")
	}

	t.Logf("CONS-R7-01 OK: second Finalize rejected in Complete phase (returned nil)")
}

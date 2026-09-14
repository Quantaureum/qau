// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// makeDoubleVoteEvidence creates valid SlashingReasonDoubleVote evidence at
// the given height. Both votes are signed by privKey for the same height but
// different block hashes, satisfying VerifyDoubleVoteEvidence.
func makeDoubleVoteEvidence(t *testing.T, privKey *crypto.PrivateKey, addr types.Address, height uint64) *SlashingEvidence {
	t.Helper()
	vote1 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        height,
		Round:         0,
		BlockHash:     types.Hash{0x01},
		ValidatorAddr: addr,
	}
	vote2 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        height,
		Round:         0,
		BlockHash:     types.Hash{0x02},
		ValidatorAddr: addr,
	}
	if err := vote1.Sign(privKey); err != nil {
		t.Fatalf("vote1.Sign failed: %v", err)
	}
	if err := vote2.Sign(privKey); err != nil {
		t.Fatalf("vote2.Sign failed: %v", err)
	}
	return &SlashingEvidence{
		ValidatorAddr: addr,
		Reason:        SlashingReasonDoubleVote,
		Height:        height,
		Vote1:         vote1,
		Vote2:         vote2,
		Timestamp:     time.Now().Unix(),
	}
}

// TestCONS_R13002_DoubleVote_MarksValidatorPermanentlySlashed verifies that
// submitting a SlashingReasonDoubleVote evidence marks the validator as
// PERMANENTLY slashed in signingInfo (same as DoubleSigning/SurroundVote).
// CONS-R13-002 (2026-07-21): Previously, the permanent flag was only set for
// DoubleSigning and SurroundVote — DoubleVote was treated as a temporary
// jail, allowing the attacker to unjail after 1 hour.
func TestCONS_R13002_DoubleVote_MarksValidatorPermanentlySlashed(t *testing.T) {
	_, sm, _, _, privKey, _, targetAddr, _ := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	evidence := makeDoubleVoteEvidence(t, privKey, targetAddr, offenseHeight)

	blockTime := time.Now().Unix()
	if _, err := sm.SubmitEvidence(evidence, sm.systemCaller, blockTime); err != nil {
		t.Fatalf("SubmitEvidence failed: %v", err)
	}

	// Sync async MarkValidatorSlashedByAddress goroutine.
	sm.SyncPendingSlashes()

	sm.mu.RLock()
	info := sm.signingInfo[targetAddr]
	sm.mu.RUnlock()
	if info == nil {
		t.Fatal("signingInfo[targetAddr] is nil after SubmitEvidence")
	}
	if !info.PermanentlySlashed {
		t.Error("CONS-R13-002 REGRESSION: DoubleVote did NOT set PermanentlySlashed=true — " +
			"validator can unjail after jail duration, defeating Casper FFG economic deterrence")
	}
}

// TestCONS_R13002_DoubleVote_UnjailRejected verifies that after a DoubleVote
// slash, the validator cannot unjail itself (because it is permanently slashed).
func TestCONS_R13002_DoubleVote_UnjailRejected(t *testing.T) {
	_, sm, _, _, privKey, _, targetAddr, _ := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	evidence := makeDoubleVoteEvidence(t, privKey, targetAddr, offenseHeight)

	blockTime := time.Now().Unix()
	if _, err := sm.SubmitEvidence(evidence, sm.systemCaller, blockTime); err != nil {
		t.Fatalf("SubmitEvidence failed: %v", err)
	}
	sm.SyncPendingSlashes()

	// Attempt to unjail — should fail with "permanently slashed" error.
	// Use a far-future block time to ensure jail period has expired (so the
	// only rejection reason is the permanent flag, not jail time).
	futureBlockTime := uint64(blockTime + 10*365*24*3600)
	err := sm.Unjail(sm.systemCaller, targetAddr, futureBlockTime)
	if err == nil {
		t.Fatal("CONS-R13-002 REGRESSION: Unjail succeeded for DoubleVote — " +
			"permanently slashed validator was able to rejoin consensus")
	}
	if !strings.Contains(err.Error(), "permanently slashed") {
		t.Errorf("expected 'permanently slashed' error, got: %v", err)
	}
}

// TestCONS_R13002_DoubleVote_SyncsToValidatorManager verifies that the
// DoubleVote permanent flag also propagates to ValidatorManager (so the
// R36-FIX / R41-CS-001 SetActive bypass guard fires).
func TestCONS_R13002_DoubleVote_SyncsToValidatorManager(t *testing.T) {
	_, sm, vm, _, privKey, _, targetAddr, _ := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	evidence := makeDoubleVoteEvidence(t, privKey, targetAddr, offenseHeight)

	blockTime := time.Now().Unix()
	if _, err := sm.SubmitEvidence(evidence, sm.systemCaller, blockTime); err != nil {
		t.Fatalf("SubmitEvidence failed: %v", err)
	}
	sm.SyncPendingSlashes()

	v, err := vm.GetValidator(targetAddr)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}
	if !v.PermanentlySlashed {
		t.Error("CONS-R13-002 REGRESSION: ValidatorManager.PermanentlySlashed not set " +
			"for DoubleVote — SetActive bypass guard will not fire")
	}
}

// TestR33_CONS_03_ZeroTimestampWithoutBlockTime_FailClosed verifies the R33
// CONS-03 fix: when evidence.Timestamp==0 and no blockTime is provided,
// SubmitEvidence must fail-closed instead of falling back to time.Now().
//
// Why: Using time.Now() for evidence timestamps is consensus-nondeterministic.
// Different validator nodes have different local clocks, so the same evidence
// would get different timestamps on different nodes, causing the freshness
// check to pass on some nodes and fail on others — leading to inconsistent
// slashing decisions and potential consensus forks.
//
// The fix requires either:
//   - evidence.Timestamp != 0 (submitter-provided), OR
//   - blockTime > 0 (consensus-derived)
//
// If neither is available, the evidence is rejected.
func TestR33_CONS_03_ZeroTimestampWithoutBlockTime_FailClosed(t *testing.T) {
	_, sm, _, _, privKey, _, targetAddr, _ := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	evidence := makeDoubleVoteEvidence(t, privKey, targetAddr, offenseHeight)
	evidence.Timestamp = 0 // simulate missing timestamp

	// Call without blockTime — must fail-closed.
	_, err := sm.SubmitEvidence(evidence, sm.systemCaller)
	if err == nil {
		t.Fatal("R33 CONS-03 REGRESSION: SubmitEvidence with Timestamp=0 and no " +
			"blockTime must fail-closed (consensus determinism), but it succeeded")
	}
	if !strings.Contains(err.Error(), "consensus determinism") {
		t.Errorf("expected 'consensus determinism' in error, got: %v", err)
	}
}

// TestR33_CONS_03_ZeroTimestampWithBlockTime_UsesBlockTime verifies that when
// evidence.Timestamp==0 but blockTime is provided, SubmitEvidence uses the
// blockTime as the evidence timestamp (deterministic fallback).
func TestR33_CONS_03_ZeroTimestampWithBlockTime_UsesBlockTime(t *testing.T) {
	_, sm, _, _, privKey, _, targetAddr, _ := setupR4GOV02Test(t)

	const offenseHeight = uint64(100)
	evidence := makeDoubleVoteEvidence(t, privKey, targetAddr, offenseHeight)
	evidence.Timestamp = 0 // simulate missing timestamp

	// Provide a deterministic blockTime (current time to pass freshness check).
	blockTime := time.Now().Unix()
	_, err := sm.SubmitEvidence(evidence, sm.systemCaller, blockTime)
	if err != nil {
		t.Fatalf("SubmitEvidence with Timestamp=0 but valid blockTime should succeed, got: %v", err)
	}

	// Verify the evidence timestamp was set to blockTime.
	if evidence.Timestamp != blockTime {
		t.Errorf("evidence.Timestamp should be %d (blockTime), got %d",
			blockTime, evidence.Timestamp)
	}
}

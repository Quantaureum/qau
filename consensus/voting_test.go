// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file contains unit tests for the voting system: Vote signing/verification,
// DoubleSignDetector evidence generation, VoteCollector validation, and
// VotingManager quorum/finality flows.
package consensus

import (
	"bytes"
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestVote_SignVerifyAndReject covers basic vote validation: a vote signed by
// the correct private key verifies successfully, fails with a foreign key, and
// fails when the signature is empty.
func TestVote_SignVerifyAndReject(t *testing.T) {
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         0,
		BlockHash:     types.Hash{0xab},
		ValidatorAddr: addr,
	}

	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign failed: %v", err)
	}
	if len(vote.Signature) == 0 {
		t.Fatal("signature not set after Sign")
	}
	if !vote.Verify(pubKey) {
		t.Error("Verify returned false for a valid signature")
	}

	// A different public key must not verify the signature.
	_, otherPub := createTestKeyPair(t)
	if vote.Verify(otherPub) {
		t.Error("Verify returned true for a wrong public key")
	}

	// Empty signature must fail verification.
	emptyVote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         0,
		BlockHash:     types.Hash{0xab},
		ValidatorAddr: addr,
	}
	if emptyVote.Verify(pubKey) {
		t.Error("Verify should fail for empty signature")
	}
}

// TestVote_VoteMessage_Deterministic ensures the signed message payload is
// stable across calls (required for reproducible signature verification) and
// that distinct votes produce distinct messages.
func TestVote_VoteMessage_Deterministic(t *testing.T) {
	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        42,
		Round:         3,
		BlockHash:     types.Hash{0x01, 0x02},
		ValidatorAddr: types.Address{0xde, 0xad},
		SourceEpoch:   5,
		TargetEpoch:   9,
	}
	msg1 := vote.VoteMessage()
	msg2 := vote.VoteMessage()
	if !bytes.Equal(msg1, msg2) {
		t.Error("VoteMessage must be deterministic")
	}
	if len(msg1) == 0 {
		t.Error("VoteMessage must not be empty")
	}

	// A different vote must produce a different message.
	other := &Vote{
		Type:          VoteTypePrecommit,
		Height:        43, // changed
		Round:         3,
		BlockHash:     types.Hash{0x01, 0x02},
		ValidatorAddr: types.Address{0xde, 0xad},
	}
	if bytes.Equal(msg1, other.VoteMessage()) {
		t.Error("different votes must produce different messages")
	}
}

// TestVote_Hash_NonZero confirms the vote hash is computed and non-zero.
func TestVote_Hash_NonZero(t *testing.T) {
	vote := &Vote{
		Type:      VoteTypePrevote,
		Height:    1,
		Round:     0,
		BlockHash: types.Hash{0xff},
	}
	h := vote.Hash()
	if h == (types.Hash{}) {
		t.Error("vote hash should not be the zero hash")
	}
}

// TestDoubleSignDetector_RecordVote verifies that recording a first vote
// produces no evidence and that recording the identical vote again is treated
// as a benign duplicate (ErrDuplicateVote), not a slashable offense.
func TestDoubleSignDetector_RecordVote(t *testing.T) {
	detector := NewDoubleSignDetector()
	addr := types.Address{0x11}

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        10,
		Round:         0,
		BlockHash:     types.Hash{0xaa},
		ValidatorAddr: addr,
	}

	// First recording: success, no evidence.
	ev, err := detector.CheckAndRecordVote(vote)
	if err != nil {
		t.Errorf("first CheckAndRecordVote returned err: %v", err)
	}
	if ev != nil {
		t.Error("first vote should not produce evidence")
	}

	// Same vote again: duplicate, no evidence.
	ev, err = detector.CheckAndRecordVote(vote)
	if !errors.Is(err, ErrDuplicateVote) {
		t.Errorf("duplicate vote: want ErrDuplicateVote, got %v", err)
	}
	if ev != nil {
		t.Error("duplicate vote should not produce evidence")
	}

	// No evidence collected yet.
	if got := detector.GetEvidence(); len(got) != 0 {
		t.Errorf("expected 0 evidence, got %d", len(got))
	}
	if detector.GetLatestEvidence() != nil {
		t.Error("expected nil latest evidence")
	}
}

// TestDoubleSignDetector_DetectDoubleSign verifies that a validator signing
// two different blocks at the same height/round generates slashing evidence
// and that the evidence can be retrieved via the public query methods.
func TestDoubleSignDetector_DetectDoubleSign(t *testing.T) {
	detector := NewDoubleSignDetector()
	addr := types.Address{0x22}

	vote1 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        20,
		Round:         1,
		BlockHash:     types.Hash{0xaa},
		ValidatorAddr: addr,
	}
	vote2 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        20,
		Round:         1,
		BlockHash:     types.Hash{0xbb}, // different block -> equivocation
		ValidatorAddr: addr,
	}

	if _, err := detector.CheckAndRecordVote(vote1); err != nil {
		t.Fatalf("record vote1: %v", err)
	}

	ev, err := detector.CheckAndRecordVote(vote2)
	if !errors.Is(err, ErrDoubleSign) {
		t.Fatalf("conflicting vote: want ErrDoubleSign, got %v", err)
	}
	if ev == nil {
		t.Fatal("conflicting vote should produce evidence")
	}

	// Evidence fields.
	if ev.ValidatorAddr != addr {
		t.Errorf("evidence addr: want %x, got %x", addr, ev.ValidatorAddr)
	}
	if ev.Height != 20 {
		t.Errorf("evidence height: want 20, got %d", ev.Height)
	}
	if ev.Reason != SlashingReasonDoubleSigning {
		t.Errorf("evidence reason: want %v, got %v", SlashingReasonDoubleSigning, ev.Reason)
	}
	if ev.Vote1 == nil || ev.Vote2 == nil {
		t.Fatal("evidence must contain both votes")
	}
	if ev.Vote1.BlockHash == ev.Vote2.BlockHash {
		t.Error("evidence votes should have different block hashes")
	}

	// Retrieval methods.
	all := detector.GetEvidence()
	if len(all) != 1 {
		t.Errorf("GetEvidence: want 1, got %d", len(all))
	}
	if detector.GetLatestEvidence() == nil {
		t.Error("GetLatestEvidence should return the evidence")
	}
	forAddr := detector.GetEvidenceForValidator(addr)
	if len(forAddr) != 1 {
		t.Errorf("GetEvidenceForValidator: want 1, got %d", len(forAddr))
	}
	other := detector.GetEvidenceForValidator(types.Address{0x99})
	if len(other) != 0 {
		t.Errorf("GetEvidenceForValidator(unrelated): want 0, got %d", len(other))
	}
}

// TestVoteCollector_AddVote verifies that a properly signed vote from a
// registered validator is accepted and recorded, and that a single validator
// holding all stake reaches the 2/3 quorum.
func TestVoteCollector_AddVote(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04 FIX (R31, 2026-07-27): AddValidator now leaves non-genesis
	// validators Active=false (EverActivated=false). Tests that exercise
	// AddVote must activate via ActivateFromQueue (mirroring the production
	// ProcessEpochAdvanced path) so the validator is in the active set
	// and its votes are not rejected as "vote from non-validator".
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	blockHash := types.Hash{0x01}
	vc := NewVoteCollector(100, 0, blockHash, vmgr)

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         0,
		BlockHash:     blockHash,
		ValidatorAddr: addr,
	}
	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign: %v", err)
	}

	if err := vc.AddVote(vote); err != nil {
		t.Fatalf("AddVote: %v", err)
	}
	if vc.VoteCount() != 1 {
		t.Errorf("VoteCount: want 1, got %d", vc.VoteCount())
	}
	if !vc.HasVoted(addr) {
		t.Error("HasVoted should be true after adding vote")
	}
	// Single validator owns 100% of stake -> 3*stake > 2*stake -> quorum.
	if !vc.HasQuorum() {
		t.Error("expected quorum with single validator holding all stake")
	}
}

// TestVoteCollector_RejectInvalidVotes ensures the collector rejects votes
// with mismatched block identifiers, bad signatures, and unknown validators.
func TestVoteCollector_RejectInvalidVotes(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04 FIX (R31, 2026-07-27): AddValidator now leaves non-genesis
	// validators Active=false (EverActivated=false). Tests that exercise
	// AddVote must activate via ActivateFromQueue (mirroring the production
	// ProcessEpochAdvanced path) so the validator is in the active set
	// and its votes are not rejected as "vote from non-validator".
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	blockHash := types.Hash{0x01}
	vc := NewVoteCollector(100, 0, blockHash, vmgr)

	// Wrong height.
	vWrongHeight := &Vote{Type: VoteTypePrecommit, Height: 99, Round: 0, BlockHash: blockHash, ValidatorAddr: addr}
	vWrongHeight.Sign(privKey)
	if err := vc.AddVote(vWrongHeight); !errors.Is(err, ErrBlockMismatch) {
		t.Errorf("wrong height: want ErrBlockMismatch, got %v", err)
	}

	// Wrong block hash.
	vWrongHash := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: types.Hash{0x02}, ValidatorAddr: addr}
	vWrongHash.Sign(privKey)
	if err := vc.AddVote(vWrongHash); !errors.Is(err, ErrBlockMismatch) {
		t.Errorf("wrong block hash: want ErrBlockMismatch, got %v", err)
	}

	// Invalid signature (signed by a different key).
	otherPriv, _ := createTestKeyPair(t)
	vBadSig := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockHash, ValidatorAddr: addr}
	vBadSig.Sign(otherPriv)
	if err := vc.AddVote(vBadSig); !errors.Is(err, ErrInvalidVoteSignature) {
		t.Errorf("bad signature: want ErrInvalidVoteSignature, got %v", err)
	}

	// Non-validator address (rejected before signature verification).
	_, nonValPub := createTestKeyPair(t)
	nonValAddr := nonValPub.Address()
	vNonVal := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockHash, ValidatorAddr: nonValAddr}
	vNonVal.Sign(otherPriv) // signature irrelevant; rejected before verification
	if err := vc.AddVote(vNonVal); !errors.Is(err, ErrVoteFromNonValidator) {
		t.Errorf("non-validator: want ErrVoteFromNonValidator, got %v", err)
	}

	// Ensure none of the rejected votes were recorded.
	if vc.VoteCount() != 0 {
		t.Errorf("no votes should be recorded, got %d", vc.VoteCount())
	}
}

// TestVoteCollector_RejectDuplicateVote verifies that a second vote from the
// same validator is rejected.
func TestVoteCollector_RejectDuplicateVote(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04 FIX (R31, 2026-07-27): AddValidator now leaves non-genesis
	// validators Active=false (EverActivated=false). Tests that exercise
	// AddVote must activate via ActivateFromQueue (mirroring the production
	// ProcessEpochAdvanced path) so the validator is in the active set
	// and its votes are not rejected as "vote from non-validator".
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	blockHash := types.Hash{0x01}
	vc := NewVoteCollector(100, 0, blockHash, vmgr)

	vote := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockHash, ValidatorAddr: addr}
	vote.Sign(privKey)

	if err := vc.AddVote(vote); err != nil {
		t.Fatalf("first AddVote: %v", err)
	}
	if err := vc.AddVote(vote); !errors.Is(err, ErrDuplicateVote) {
		t.Errorf("duplicate vote: want ErrDuplicateVote, got %v", err)
	}
	if vc.VoteCount() != 1 {
		t.Errorf("VoteCount: want 1, got %d", vc.VoteCount())
	}
}

// TestR14MED_VoteCollector_DoubleSignDetector_ForwardsAcceptedVote verifies
// that when a DoubleSignDetector is attached via SetDoubleSignDetector,
// AddVote forwards every accepted vote to the detector. This is the
// regression test for the R14 Medium fix that adds defense-in-depth
// cross-block equivocation detection at the VoteCollector layer.
//
// Previously VoteCollector had no DoubleSignDetector field and could not
// detect a validator voting for DIFFERENT blocks at the same (height, round)
// — only the higher-level FinalityTracker wrapper did. Future callers that
// use VoteCollector directly (without FinalityTracker) would have no
// double-sign detection at all.
func TestR14MED_VoteCollector_DoubleSignDetector_ForwardsAcceptedVote(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04 FIX (R31, 2026-07-27): AddValidator now leaves non-genesis
	// validators Active=false (EverActivated=false). Tests that exercise
	// AddVote must activate via ActivateFromQueue (mirroring the production
	// ProcessEpochAdvanced path) so the validator is in the active set
	// and its votes are not rejected as "vote from non-validator".
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	// Set up two VoteCollectors for DIFFERENT blocks at the same height/round,
	// both sharing a single DoubleSignDetector. This simulates the
	// cross-block equivocation scenario: a validator votes for block A
	// through vcA, then votes for block B through vcB. Without the detector,
	// neither collector would know about the other's vote.
	detector := NewDoubleSignDetector()
	blockA := types.Hash{0x01}
	blockB := types.Hash{0x02}
	vcA := NewVoteCollector(100, 0, blockA, vmgr)
	vcA.SetDoubleSignDetector(detector)
	vcB := NewVoteCollector(100, 0, blockB, vmgr)
	vcB.SetDoubleSignDetector(detector)

	// Validator votes for block A — should succeed and be recorded by detector.
	voteA := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockA, ValidatorAddr: addr}
	if err := voteA.Sign(privKey); err != nil {
		t.Fatalf("voteA.Sign: %v", err)
	}
	if err := vcA.AddVote(voteA); err != nil {
		t.Fatalf("vcA.AddVote(voteA): %v", err)
	}

	// Validator now votes for block B at the same height/round — this is
	// equivocation. CONS-FIX (R31, 2026-07-27): AddVote on vcB now
	// RETURNS ErrDoubleSign (instead of silently accepting voteB) and still
	// generates ONE slashing evidence entry queued in the shared detector.
	// The previous behavior accepted the equivocating vote and counted it
	// toward quorum — the new behavior rejects it AND keeps the evidence,
	// which is the more secure contract. Update the test to assert the
	// new contract: AddVote returns ErrDoubleSign, evidence is still produced.
	voteB := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockB, ValidatorAddr: addr}
	if err := voteB.Sign(privKey); err != nil {
		t.Fatalf("voteB.Sign: %v", err)
	}
	if err := vcB.AddVote(voteB); !errors.Is(err, ErrDoubleSign) {
		t.Fatalf("vcB.AddVote(voteB): want ErrDoubleSign (equivocation rejected per CONS-), got %v", err)
	}

	// The detector should have generated exactly one slashing evidence
	// entry for the equivocation.
	evidence := detector.GetEvidence()
	if len(evidence) != 1 {
		t.Fatalf("expected 1 slashing evidence entry, got %d", len(evidence))
	}
	ev := evidence[0]
	if ev.ValidatorAddr != addr {
		t.Errorf("evidence validator: want %s, got %s", addr, ev.ValidatorAddr)
	}
	if ev.Reason != SlashingReasonDoubleSigning {
		t.Errorf("evidence reason: want %v, got %v", SlashingReasonDoubleSigning, ev.Reason)
	}
	if ev.Height != 100 {
		t.Errorf("evidence height: want 100, got %d", ev.Height)
	}
	// Vote1 should be the earlier vote (block A), Vote2 the later (block B).
	if ev.Vote1.BlockHash != blockA {
		t.Errorf("evidence Vote1.BlockHash: want %s (block A), got %s", blockA, ev.Vote1.BlockHash)
	}
	if ev.Vote2.BlockHash != blockB {
		t.Errorf("evidence Vote2.BlockHash: want %s (block B), got %s", blockB, ev.Vote2.BlockHash)
	}
}

// TestR14MED_VoteCollector_NoDetector_NoCrash verifies that when no
// DoubleSignDetector is set (the default state, matching all existing
// callers), AddVote behaves exactly as before — no detector call, no
// panic, no behavior change.
func TestR14MED_VoteCollector_NoDetector_NoCrash(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04 FIX (R31, 2026-07-27): AddValidator now leaves non-genesis
	// validators Active=false (EverActivated=false). Tests that exercise
	// AddVote must activate via ActivateFromQueue (mirroring the production
	// ProcessEpochAdvanced path) so the validator is in the active set
	// and its votes are not rejected as "vote from non-validator".
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	blockHash := types.Hash{0x01}
	vc := NewVoteCollector(100, 0, blockHash, vmgr)
	// Intentionally do NOT call SetDoubleSignDetector — default state.

	vote := &Vote{Type: VoteTypePrecommit, Height: 100, Round: 0, BlockHash: blockHash, ValidatorAddr: addr}
	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign: %v", err)
	}
	if err := vc.AddVote(vote); err != nil {
		t.Fatalf("AddVote without detector: %v", err)
	}
	if vc.VoteCount() != 1 {
		t.Errorf("VoteCount: want 1, got %d", vc.VoteCount())
	}
}

// TestVotingManager_AddVote_ReachesQuorum verifies the VotingManager accepts a
// signed vote and reports quorum when a single validator owns all stake.
func TestVotingManager_AddVote_ReachesQuorum(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04 FIX (R31, 2026-07-27): AddValidator now leaves non-genesis
	// validators Active=false (EverActivated=false). Tests that exercise
	// AddVote must activate via ActivateFromQueue (mirroring the production
	// ProcessEpochAdvanced path) so the validator is in the active set
	// and its votes are not rejected as "vote from non-validator".
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	votingMgr := NewVotingManager(vmgr)
	blockHash := types.Hash{0x01}

	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         0,
		BlockHash:     blockHash,
		ValidatorAddr: addr,
	}
	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign: %v", err)
	}

	quorum, err := votingMgr.AddVote(vote)
	if err != nil {
		t.Fatalf("AddVote: %v", err)
	}
	if !quorum {
		t.Error("expected quorum with single validator holding all stake")
	}
	if !votingMgr.HasQuorum(100, 0) {
		t.Error("HasQuorum should be true")
	}
}

// TestVotingManager_RejectDoubleSign verifies that the VotingManager surfaces
// a double-sign error (via the embedded DoubleSignDetector) when the same
// validator votes for two different blocks at the same height/round.
func TestVotingManager_RejectDoubleSign(t *testing.T) {
	vmgr := NewValidatorManager()
	privKey, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()
	if err := vmgr.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04 FIX (R31, 2026-07-27): AddValidator now leaves non-genesis
	// validators Active=false (EverActivated=false). Tests that exercise
	// AddVote must activate via ActivateFromQueue (mirroring the production
	// ProcessEpochAdvanced path) so the validator is in the active set
	// and its votes are not rejected as "vote from non-validator".
	if err := vmgr.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	votingMgr := NewVotingManager(vmgr)

	mkVote := func(hash types.Hash) *Vote {
		v := &Vote{
			Type:          VoteTypePrecommit,
			Height:        100,
			Round:         0,
			BlockHash:     hash,
			ValidatorAddr: addr,
		}
		if err := v.Sign(privKey); err != nil {
			t.Fatalf("sign: %v", err)
		}
		return v
	}

	if _, err := votingMgr.AddVote(mkVote(types.Hash{0x01})); err != nil {
		t.Fatalf("first AddVote: %v", err)
	}
	// Second vote for a different block at the same height/round -> double-sign.
	_, err := votingMgr.AddVote(mkVote(types.Hash{0x02}))
	if !errors.Is(err, ErrDoubleSign) {
		t.Errorf("double-sign: want ErrDoubleSign, got %v", err)
	}
}

// TestVotingManager_FinalizeAndRejectRollback exercises the finality state
// machine: marking a block finalized, querying it, and rejecting
// double-finalization, empty hashes, and rollback attempts.
func TestVotingManager_FinalizeAndRejectRollback(t *testing.T) {
	vmgr := NewValidatorManager()
	votingMgr := NewVotingManager(vmgr)

	blockHash := types.Hash{0x01}

	// Empty hash rejected.
	if err := votingMgr.Finalize(100, types.Hash{}); err == nil {
		t.Error("Finalize with empty hash should fail")
	}

	// Successful finalization.
	if err := votingMgr.Finalize(100, blockHash); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if !votingMgr.IsFinalized(100) {
		t.Error("IsFinalized should be true")
	}
	got, ok := votingMgr.GetFinalizedHash(100)
	if !ok || got != blockHash {
		t.Errorf("GetFinalizedHash: want %x ok=true, got %x ok=%v", blockHash, got, ok)
	}

	// Double finalize at same height rejected.
	if err := votingMgr.Finalize(100, types.Hash{0x02}); !errors.Is(err, ErrAlreadyFinalized) {
		t.Errorf("double finalize: want ErrAlreadyFinalized, got %v", err)
	}

	// Rollback protection: finalizing a lower height rejected.
	if err := votingMgr.Finalize(99, types.Hash{0x03}); err == nil {
		t.Error("Finalize at lower height should be rejected (rollback protection)")
	}
}

// TestVoteSet_Quorum verifies the 2/3 quorum threshold arithmetic.
func TestVoteSet_Quorum(t *testing.T) {
	totalStake := big.NewInt(300) // 2/3 = 200
	detector := NewDoubleSignDetector()
	vs := NewVoteSet(1, 0, types.Hash{0x01}, totalStake, detector)

	if vs.HasQuorum() {
		t.Error("should not have quorum with zero votes")
	}

	// 150 stake: below 2/3 (200).
	v1 := &Vote{Type: VoteTypePrecommit, Height: 1, Round: 0, BlockHash: types.Hash{0x01}, ValidatorAddr: types.Address{0x01}}
	if err := vs.AddVote(v1, big.NewInt(150)); err != nil {
		t.Fatalf("AddVote v1: %v", err)
	}
	if vs.HasQuorum() {
		t.Error("150 stake should not reach quorum (need > 200)")
	}

	// +100 stake -> 250 total: above 2/3 (200).
	v2 := &Vote{Type: VoteTypePrecommit, Height: 1, Round: 0, BlockHash: types.Hash{0x01}, ValidatorAddr: types.Address{0x02}}
	if err := vs.AddVote(v2, big.NewInt(100)); err != nil {
		t.Fatalf("AddVote v2: %v", err)
	}
	if !vs.HasQuorum() {
		t.Error("250 stake should reach quorum (> 200)")
	}
	if got := vs.GetWeight(); got.Cmp(big.NewInt(250)) != 0 {
		t.Errorf("GetWeight: want 250, got %s", got.String())
	}
}

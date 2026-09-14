// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// setupR4GOV04ShardTest creates a ShardManager backed by a real
// MainChainCommitterImpl (with BoltDB-mem storage) and wires the
// ShardManager as the commitment authenticator — exactly the production
// wiring done in node.go.
//
// It also creates a shard with 3 validators, registers their Dilithium3
// public keys, and sets a mock election verifier so ProposeBlock succeeds
// in tests without real VRF proofs.
//
// AUDIT (2026) R4-GOV-04: These tests verify that the pre-fix attack
// vector — "anyone reaching the commit path can persist arbitrary
// (StateRoot, BlockHash) for any (shardID, height) and have it verify via
// byte comparison alone" — is closed.
func setupR4GOV04ShardTest(t *testing.T) (*ShardManager, *MainChainCommitterImpl, *ShardChain, []types.Address) {
	t.Helper()

	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	sm := NewShardManager(committer)

	// R4-GOV-04 production wiring: ShardManager authenticates commitments.
	committer.SetAuthenticator(sm)

	validators := []types.Address{{0x01}, {0x02}, {0x03}}
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}
	// Register validator pub keys BEFORE ActivateShard (activation requires keys).
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	return sm, committer, chain, validators
}

// proposeAndFinalizeR4GOV04Block proposes and finalizes a block at the next
// height on the given shard chain. Returns the finalized block.
func proposeAndFinalizeR4GOV04Block(t *testing.T, chain *ShardChain, proposer types.Address) *ShardBlock {
	t.Helper()
	block, err := proposeShardBlock(chain, proposer, nil, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}
	if err := finalizeShardBlock(chain, block.Header.Height); err != nil {
		t.Fatalf("FinalizeBlock failed: %v", err)
	}
	return block
}

// TestR4GOV04_FailClosedWithoutAuthenticator verifies that SubmitShardCommitment
// rejects ALL commitments when no authenticator is wired (fail-closed).
// This is the core security guarantee: production MUST wire an authenticator
// or no commitments can be persisted.
func TestR4GOV04_FailClosedWithoutAuthenticator(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	// Note: NO SetAuthenticator call — simulating misconfigured production.

	commitment := &ShardCommitment{
		ShardID:     1,
		BlockHeight: 1,
		BlockHash:   types.Hash{0xAA},
		StateRoot:   types.Hash{0xBB},
		Signer:      nonZeroSigner(),
		Signature:   []byte{0x01, 0x02, 0x03},
	}

	err := committer.SubmitShardCommitment(commitment)
	if err == nil {
		t.Fatal("expected error when no authenticator is wired (fail-closed)")
	}
	if !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("expected 'not authenticated' error, got: %v", err)
	}
}

// TestR4GOV04_RejectUnsignedCommitment verifies that the authenticator
// rejects commitments with an empty Signer field. This is the first line
// of defense against forged commitments.
func TestR4GOV04_RejectUnsignedCommitment(t *testing.T) {
	sm, committer, chain, validators := setupR4GOV04ShardTest(t)
	_ = sm
	_ = chain
	_ = validators

	// Commitment with empty Signer — should be rejected.
	unsigned := &ShardCommitment{
		ShardID:     1,
		BlockHeight: 1,
		BlockHash:   types.Hash{0xAA},
		StateRoot:   types.Hash{0xBB},
		Signer:      types.Address{}, // empty
		Signature:   []byte{0x01},
	}

	err := committer.SubmitShardCommitment(unsigned)
	if err == nil {
		t.Fatal("expected error for empty signer")
	}
	if !strings.Contains(err.Error(), "empty signer") {
		t.Fatalf("expected 'empty signer' error, got: %v", err)
	}

	// Commitment with non-zero Signer but empty Signature.
	noSig := &ShardCommitment{
		ShardID:     1,
		BlockHeight: 1,
		BlockHash:   types.Hash{0xAA},
		Signer:      nonZeroSigner(),
		Signature:   nil, // empty
	}
	err = committer.SubmitShardCommitment(noSig)
	if err == nil {
		t.Fatal("expected error for empty signature")
	}
	if !strings.Contains(err.Error(), "empty signature") {
		t.Fatalf("expected 'empty signature' error, got: %v", err)
	}
}

// TestR4GOV04_RejectAuthenticatorRejection verifies that when the authenticator
// rejects a commitment (e.g., always-reject), SubmitShardCommitment fails.
func TestR4GOV04_RejectAuthenticatorRejection(t *testing.T) {
	database := db.NewMemDB()
	slotFn := func() uint64 { return 1 }
	committer := NewMainChainCommitter(database, slotFn)
	committer.SetAuthenticator(alwaysRejectAuthenticator{})

	commitment := &ShardCommitment{
		ShardID:     1,
		BlockHeight: 1,
		BlockHash:   types.Hash{0xAA},
		Signer:      nonZeroSigner(),
		Signature:   []byte{0x01},
	}

	err := committer.SubmitShardCommitment(commitment)
	if err == nil {
		t.Fatal("expected error when authenticator rejects")
	}
	if !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("expected 'not authenticated' error, got: %v", err)
	}
}

// TestR4GOV04_AuthenticCommitmentAccepted verifies that a commitment derived
// from a real finalized shard block (with a valid proposer signature) is
// accepted by SubmitShardCommitment. This is the happy path after the fix.
func TestR4GOV04_AuthenticCommitmentAccepted(t *testing.T) {
	sm, committer, chain, validators := setupR4GOV04ShardTest(t)
	_ = sm

	// Propose + finalize a block.
	proposer := validators[0]
	block := proposeAndFinalizeR4GOV04Block(t, chain, proposer)

	// Build the commitment via CommitBlockToMainChain (production path).
	commitment, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}

	// Verify the commitment carries the proposer + signature (R4-GOV-04 fix).
	if commitment.Signer != proposer {
		t.Fatalf("commitment.Signer %x != proposer %x", commitment.Signer[:8], proposer[:8])
	}
	if len(commitment.Signature) == 0 {
		t.Fatal("commitment.Signature is empty — should carry block header signature")
	}

	// Submit via the real committer (with ShardManager as authenticator).
	if err := committer.SubmitShardCommitment(commitment); err != nil {
		t.Fatalf("SubmitShardCommitment failed for authentic commitment: %v", err)
	}

	// Verify the stored commitment matches.
	match, err := committer.VerifyShardCommitment(commitment)
	if err != nil {
		t.Fatalf("VerifyShardCommitment failed: %v", err)
	}
	if !match {
		t.Fatal("expected authentic commitment to verify successfully")
	}
}

// TestR4GOV04_ForgedCommitmentRejected verifies that a commitment with
// tampered fields (different StateRoot or BlockHash) is rejected even if
// it carries a valid-looking signature from a different context.
//
// This is the core R4-GOV-04 attack: an attacker who reaches the commit
// path tries to persist arbitrary (StateRoot, BlockHash) for a (shardID,
// height) that already has a finalized block. The authenticator re-fetches
// the canonical block and detects the mismatch.
func TestR4GOV04_ForgedCommitmentRejected(t *testing.T) {
	sm, committer, chain, validators := setupR4GOV04ShardTest(t)
	_ = sm

	proposer := validators[0]
	block := proposeAndFinalizeR4GOV04Block(t, chain, proposer)

	// Get the authentic commitment.
	authentic, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}

	// Tamper: change StateRoot but keep everything else.
	forged := *authentic // shallow copy
	forged.StateRoot = types.Hash{0xFF, 0xEE, 0xDD}

	err = committer.SubmitShardCommitment(&forged)
	if err == nil {
		t.Fatal("expected error for tampered StateRoot")
	}
	if !strings.Contains(err.Error(), "state root mismatch") {
		t.Fatalf("expected 'state root mismatch' error, got: %v", err)
	}

	// Tamper: change BlockHash.
	forged2 := *authentic
	forged2.BlockHash = types.Hash{0xAA, 0xBB, 0xCC}

	err = committer.SubmitShardCommitment(&forged2)
	if err == nil {
		t.Fatal("expected error for tampered BlockHash")
	}
	if !strings.Contains(err.Error(), "block hash mismatch") {
		t.Fatalf("expected 'block hash mismatch' error, got: %v", err)
	}

	// Tamper: change Signer to a different address.
	forged3 := *authentic
	forged3.Signer = validators[1] // different validator

	err = committer.SubmitShardCommitment(&forged3)
	if err == nil {
		t.Fatal("expected error for tampered Signer")
	}
	if !strings.Contains(err.Error(), "signer") || !strings.Contains(err.Error(), "proposer") {
		t.Fatalf("expected 'signer does not match block proposer' error, got: %v", err)
	}

	// Tamper: change Signature.
	forged4 := *authentic
	forged4.Signature = append([]byte{0x00}, authentic.Signature...) // prepend a byte

	err = committer.SubmitShardCommitment(&forged4)
	if err == nil {
		t.Fatal("expected error for tampered Signature")
	}
	if !strings.Contains(err.Error(), "signature does not match") {
		t.Fatalf("expected 'signature does not match' error, got: %v", err)
	}
}

// TestR4GOV04_RejectCommitmentForNonExistentShard verifies that a commitment
// for a shard that doesn't exist is rejected by the authenticator.
func TestR4GOV04_RejectCommitmentForNonExistentShard(t *testing.T) {
	sm, committer, chain, validators := setupR4GOV04ShardTest(t)
	_ = sm
	_ = chain

	proposer := validators[0]
	block := proposeAndFinalizeR4GOV04Block(t, chain, proposer)
	authentic, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}

	// Reference a shard that doesn't exist (shard 999).
	forged := *authentic
	forged.ShardID = 999

	err = committer.SubmitShardCommitment(&forged)
	if err == nil {
		t.Fatal("expected error for non-existent shard")
	}
	if !strings.Contains(err.Error(), "shard") || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'shard not found' error, got: %v", err)
	}
}

// TestR4GOV04_RejectCommitmentForNonExistentBlock verifies that a commitment
// for a (shardID, height) where no block exists is rejected.
func TestR4GOV04_RejectCommitmentForNonExistentBlock(t *testing.T) {
	sm, committer, chain, validators := setupR4GOV04ShardTest(t)
	_ = sm

	proposer := validators[0]
	block := proposeAndFinalizeR4GOV04Block(t, chain, proposer)
	authentic, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}

	// Reference a height that doesn't have a block.
	forged := *authentic
	forged.BlockHeight = 999

	err = committer.SubmitShardCommitment(&forged)
	if err == nil {
		t.Fatal("expected error for non-existent block")
	}
	if !strings.Contains(err.Error(), "cannot fetch block") {
		t.Fatalf("expected 'cannot fetch block' error, got: %v", err)
	}
}

// TestR4GOV04_VerifyRejectsForgedCommitment verifies that VerifyShardCommitment
// returns (false, nil) — not (true, nil) — for a forged commitment, even if
// the stored commitment byte-matches in some fields.
func TestR4GOV04_VerifyRejectsForgedCommitment(t *testing.T) {
	sm, committer, chain, validators := setupR4GOV04ShardTest(t)
	_ = sm

	proposer := validators[0]
	block := proposeAndFinalizeR4GOV04Block(t, chain, proposer)
	authentic, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("CommitBlockToMainChain failed: %v", err)
	}

	// Submit the authentic commitment.
	if err := committer.SubmitShardCommitment(authentic); err != nil {
		t.Fatalf("SubmitShardCommitment failed: %v", err)
	}

	// Verify the authentic commitment passes.
	match, err := committer.VerifyShardCommitment(authentic)
	if err != nil {
		t.Fatalf("VerifyShardCommitment failed: %v", err)
	}
	if !match {
		t.Fatal("expected authentic commitment to verify")
	}

	// Verify a forged commitment (tampered StateRoot) is rejected.
	forged := *authentic
	forged.StateRoot = types.Hash{0xFF}
	match, err = committer.VerifyShardCommitment(&forged)
	if err != nil {
		t.Fatalf("VerifyShardCommitment failed: %v", err)
	}
	if match {
		t.Fatal("expected forged commitment to NOT verify (state root mismatch)")
	}
}

// TestR4GOV04_FullProductionPath verifies the complete production flow:
// ShardManager.CommitShardBlock → CommitBlockToMainChain →
// MainChainCommitterImpl.SubmitShardCommitment → AuthenticateCommitment →
// database Put → VerifyShardCommitment.
//
// This confirms the end-to-end wiring works with the ShardManager as
// authenticator (exactly as node.go configures it).
func TestR4GOV04_FullProductionPath(t *testing.T) {
	sm, committer, chain, validators := setupR4GOV04ShardTest(t)
	_ = committer // used implicitly via sm.mainChain

	proposer := validators[0]
	block := proposeAndFinalizeR4GOV04Block(t, chain, proposer)

	// Production path: CommitShardBlock does CommitBlockToMainChain +
	// SubmitShardCommitment in one call.
	commitment, err := sm.CommitShardBlock(chain.ShardID(), block.Header.Height)
	if err != nil {
		t.Fatalf("CommitShardBlock failed: %v", err)
	}

	// Verify the commitment carries authentication fields.
	if commitment.Signer != proposer {
		t.Fatalf("commitment.Signer %x != proposer %x", commitment.Signer[:8], proposer[:8])
	}
	if len(commitment.Signature) == 0 {
		t.Fatal("commitment.Signature is empty")
	}

	// Verify via the production committer.
	match, err := sm.VerifyShardCommitment(commitment)
	if err != nil {
		t.Fatalf("VerifyShardCommitment failed: %v", err)
	}
	if !match {
		t.Fatal("expected production-path commitment to verify")
	}
}

// TestR4GOV04_FullProductionPath_ForgedRejected verifies that the production
// path (ShardManager.CommitShardBlock) cannot be bypassed by calling
// SubmitShardCommitment directly with a forged commitment.
func TestR4GOV04_FullProductionPath_ForgedRejected(t *testing.T) {
	sm, committer, chain, validators := setupR4GOV04ShardTest(t)
	_ = sm

	proposer := validators[0]
	block := proposeAndFinalizeR4GOV04Block(t, chain, proposer)

	// Production path: submit the authentic commitment.
	authentic, err := sm.CommitShardBlock(chain.ShardID(), block.Header.Height)
	if err != nil {
		t.Fatalf("CommitShardBlock failed: %v", err)
	}

	// Attacker tries to overwrite with a forged commitment for the same
	// (shardID, height) but with a different StateRoot.
	forged := *authentic
	forged.StateRoot = types.Hash{0xDE, 0xAD, 0xBE, 0xEF}

	err = committer.SubmitShardCommitment(&forged)
	if err == nil {
		t.Fatal("expected forged commitment to be rejected by authenticator")
	}
	if !strings.Contains(err.Error(), "state root mismatch") {
		t.Fatalf("expected 'state root mismatch' error, got: %v", err)
	}

	// Verify the original authentic commitment is still the one stored.
	match, err := committer.VerifyShardCommitment(authentic)
	if err != nil {
		t.Fatalf("VerifyShardCommitment failed: %v", err)
	}
	if !match {
		t.Fatal("expected original authentic commitment to still be stored (not overwritten)")
	}
}

// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// r5_04_mockVerifier is a test-only ElectionVerifier that returns a
// configurable error. It also tracks call count to verify delegation.
type r5_04_mockVerifier struct {
	callCount int
	lastAddr  types.Address
	err       error
}

func (m *r5_04_mockVerifier) VerifyProposerElection(
	proposer types.Address, vrfProof []byte, vrfOutput types.Hash, height uint64,
) error {
	m.callCount++
	m.lastAddr = proposer
	return m.err
}

// TestR5_SHRD_R5_04_WrapperRejectsNonShardValidator verifies that the
// shardMembershipVerifierWrapper rejects a proposer who is NOT a member of
// the shard's validator subset, even when the base verifier would accept.
//
// This is the core SHRD-R5-04 fix: the election verifier itself enforces
// "elected proposer must be a shard validator" (fail-closed), so the check
// is unified across ProposeBlock and ReceiveBlock paths.
func TestR5_SHRD_R5_04_WrapperRejectsNonShardValidator(t *testing.T) {
	shardValidator := types.Address{0x01}
	nonShardValidator := types.Address{0x02}

	chain := NewShardChain(1, []types.Address{shardValidator})

	// Base verifier always returns nil (simulating "election passed").
	base := &r5_04_mockVerifier{err: nil}

	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    base,
	}

	// Non-shard validator must be rejected.
	err := wrapper.VerifyProposerElection(nonShardValidator, nil, types.Hash{}, 1)
	if err == nil {
		t.Fatal("SHRD-R5-04: expected rejection for non-shard-validator proposer")
	}

	// Base verifier must NOT have been called (fail-closed before delegation).
	if base.callCount != 0 {
		t.Errorf("SHRD-R5-04: base verifier should not be called for non-member, got callCount=%d", base.callCount)
	}
}

// TestR5_SHRD_R5_04_WrapperAcceptsShardValidator verifies that the wrapper
// delegates to the base verifier when the proposer IS a shard validator.
func TestR5_SHRD_R5_04_WrapperAcceptsShardValidator(t *testing.T) {
	shardValidator := types.Address{0x01}

	chain := NewShardChain(1, []types.Address{shardValidator})

	base := &r5_04_mockVerifier{err: nil}
	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    base,
	}

	err := wrapper.VerifyProposerElection(shardValidator, nil, types.Hash{}, 1)
	if err != nil {
		t.Fatalf("SHRD-R5-04: expected acceptance for shard validator, got: %v", err)
	}

	if base.callCount != 1 {
		t.Errorf("SHRD-R5-04: base verifier should be called once, got callCount=%d", base.callCount)
	}
	if base.lastAddr != shardValidator {
		t.Errorf("SHRD-R5-04: base verifier called with wrong proposer %x, want %x", base.lastAddr[:4], shardValidator[:4])
	}
}

// TestR5_SHRD_R5_04_WrapperPropagatesBaseError verifies that if the base
// verifier rejects the proposer, the wrapper propagates the error (the
// membership check is necessary but not sufficient — the election must also
// verify).
func TestR5_SHRD_R5_04_WrapperPropagatesBaseError(t *testing.T) {
	shardValidator := types.Address{0x01}
	baseErr := errors.New("election mismatch")

	chain := NewShardChain(1, []types.Address{shardValidator})
	base := &r5_04_mockVerifier{err: baseErr}
	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    base,
	}

	err := wrapper.VerifyProposerElection(shardValidator, nil, types.Hash{}, 1)
	if err == nil {
		t.Fatal("SHRD-R5-04: expected base verifier error to propagate")
	}
	if !errors.Is(err, baseErr) {
		t.Errorf("SHRD-R5-04: expected base error %v, got %v", baseErr, err)
	}
}

// TestR5_SHRD_R5_04_InjectDependenciesWrapsVerifier verifies that
// InjectDependencies wraps the base verifier with the per-shard membership
// check. After injection, ProposeBlock's election verification path should
// reject non-shard validators via the wrapper.
func TestR5_SHRD_R5_04_InjectDependenciesWrapsVerifier(t *testing.T) {
	shardValidator := types.Address{0x01}
	nonShardValidator := types.Address{0x02}

	chain := NewShardChain(1, []types.Address{shardValidator})

	// Base verifier always accepts.
	base := &r5_04_mockVerifier{err: nil}

	// Inject — should wrap the base verifier.
	chain.InjectDependencies(nil, base)

	// Verify the wrapper was stored (not the raw base verifier).
	chain.mu.RLock()
	stored := chain.electionVerifier
	chain.mu.RUnlock()

	wrapper, ok := stored.(*shardMembershipVerifierWrapper)
	if !ok {
		t.Fatalf("SHRD-R5-04: InjectDependencies should store a *shardMembershipVerifierWrapper, got %T", stored)
	}
	if wrapper.shardID != 1 {
		t.Errorf("SHRD-R5-04: wrapper shardID = %d, want 1", wrapper.shardID)
	}

	// Non-shard validator rejected via the stored wrapper.
	err := stored.VerifyProposerElection(nonShardValidator, nil, types.Hash{}, 1)
	if err == nil {
		t.Fatal("SHRD-R5-04: stored wrapper should reject non-shard validator")
	}

	// Shard validator accepted.
	err = stored.VerifyProposerElection(shardValidator, nil, types.Hash{}, 1)
	if err != nil {
		t.Fatalf("SHRD-R5-04: stored wrapper should accept shard validator, got: %v", err)
	}
}

// TestR5_SHRD_R5_04_MultiShardIsolation verifies that two shards with
// different validator sets each enforce their OWN membership check, even
// though they share the same base verifier instance. This is the key
// architectural property: the shared ShardQPOSAdapter remains stateless,
// while per-shard wrappers provide the membership boundary.
func TestR5_SHRD_R5_04_MultiShardIsolation(t *testing.T) {
	shard1Validator := types.Address{0x01}
	shard2Validator := types.Address{0x02}

	chain1 := NewShardChain(1, []types.Address{shard1Validator})
	chain2 := NewShardChain(2, []types.Address{shard2Validator})

	// Both shards share the same base verifier (simulating the shared
	// ShardQPOSAdapter in production).
	sharedBase := &r5_04_mockVerifier{err: nil}

	chain1.InjectDependencies(nil, sharedBase)
	chain2.InjectDependencies(nil, sharedBase)

	chain1.mu.RLock()
	verifier1 := chain1.electionVerifier
	chain1.mu.RUnlock()
	chain2.mu.RLock()
	verifier2 := chain2.electionVerifier
	chain2.mu.RUnlock()

	// Shard 1 accepts its own validator, rejects shard 2's validator.
	if err := verifier1.VerifyProposerElection(shard1Validator, nil, types.Hash{}, 1); err != nil {
		t.Errorf("shard 1 should accept its own validator: %v", err)
	}
	if err := verifier1.VerifyProposerElection(shard2Validator, nil, types.Hash{}, 1); err == nil {
		t.Error("shard 1 should reject shard 2's validator")
	}

	// Shard 2 accepts its own validator, rejects shard 1's validator.
	if err := verifier2.VerifyProposerElection(shard2Validator, nil, types.Hash{}, 1); err != nil {
		t.Errorf("shard 2 should accept its own validator: %v", err)
	}
	if err := verifier2.VerifyProposerElection(shard1Validator, nil, types.Hash{}, 1); err == nil {
		t.Error("shard 2 should reject shard 1's validator")
	}
}

// TestR5_SHRD_R5_04_ReInjectionDoesNotDoubleWrap verifies that calling
// InjectDependencies multiple times does not create nested wrappers. This
// is important because ShardBlockProducer.handleIncomingShardBlock calls
// InjectDependencies on every received block.
func TestR5_SHRD_R5_04_ReInjectionDoesNotDoubleWrap(t *testing.T) {
	shardValidator := types.Address{0x01}
	chain := NewShardChain(1, []types.Address{shardValidator})

	base := &r5_04_mockVerifier{err: nil}

	// Inject twice (simulating re-injection on block receive).
	chain.InjectDependencies(nil, base)
	chain.InjectDependencies(nil, chain.electionVerifier) // re-inject the wrapper

	chain.mu.RLock()
	stored := chain.electionVerifier
	chain.mu.RUnlock()

	// Should be a single wrapper, not nested.
	wrapper, ok := stored.(*shardMembershipVerifierWrapper)
	if !ok {
		t.Fatalf("expected *shardMembershipVerifierWrapper, got %T", stored)
	}

	// The base of the stored wrapper should be the original base, not
	// another wrapper.
	innerBase := wrapper.base
	if _, isWrapper := innerBase.(*shardMembershipVerifierWrapper); isWrapper {
		t.Error("SHRD-R5-04: re-injection created nested wrapper (double-wrapping)")
	}

	// Verify functionality is intact.
	err := stored.VerifyProposerElection(shardValidator, nil, types.Hash{}, 1)
	if err != nil {
		t.Errorf("SHRD-R5-04: re-injected wrapper should accept shard validator, got: %v", err)
	}

	nonShard := types.Address{0x02}
	err = stored.VerifyProposerElection(nonShard, nil, types.Hash{}, 1)
	if err == nil {
		t.Error("SHRD-R5-04: re-injected wrapper should reject non-shard validator")
	}
}

// TestR5_SHRD_R5_04_EmptyValidatorSetRejectsAll verifies that a shard with
// no validators rejects ALL proposers (fail-closed). This prevents a shard
// from operating without a defined validator subset.
func TestR5_SHRD_R5_04_EmptyValidatorSetRejectsAll(t *testing.T) {
	chain := NewShardChain(1, []types.Address{}) // empty validator set

	base := &r5_04_mockVerifier{err: nil}
	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    base,
	}

	err := wrapper.VerifyProposerElection(types.Address{0x01}, nil, types.Hash{}, 1)
	if err == nil {
		t.Fatal("SHRD-R5-04: empty validator set should reject all proposers (fail-closed)")
	}
	if base.callCount != 0 {
		t.Errorf("SHRD-R5-04: base verifier should not be called when validator set is empty, got callCount=%d", base.callCount)
	}
}

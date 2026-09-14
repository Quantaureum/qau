// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ── SHRD: verification set must be the shard subset — closure tests ──
//
// Audit source (AUDIT-FULL-ROUND6-2026-07-17.md, SHRD, Medium / LATENT):
//   "election candidate set was not restricted to the shard subset"
//   file:line: shard.go election logic
//   Remediation: sharded election must return only members of that shard.
//
// Status: closed by the related SHRD fix commit.
//
// The earlier fix introduced shardMembershipVerifierWrapper, which calls
// w.chain.isValidatorLocked(proposer) inside VerifyProposerElection for a
// fail-closed membership check. Only addresses in sc.validators can pass
// election verification. This means:
//   - Even if a base verifier (e.g. ShardQPOSAdapter) returns a global
//     validator from the QPOS on the main chain, the wrapper fails closed
//    _if_ that validator is not in the shard's validator subset.
//   - After ReassignValidators refreshes sc.validators, the wrapper reads
//     the live validator list via the chain back-pointer.
//
// This test file asserts the closure:
//   1. Global validators that are not shard members cannot be elected.
//   2. Validators of the shard can be elected.
//   3. Validator sets across shards are mutually isolated.
//   4. After dynamic validator updates, previous members lose election.
//   5. After dynamic updates, newly added members become eligible.
//   6. Empty validator sets fail closed (reject all proposers).

// TestSHRD_R6_01_NonShardValidatorCannotBeElected verifies the core
// property: a validator that is NOT in the shard's validator subset cannot
// pass election verification, even if the base verifier (e.g., ShardQPOSAdapter)
// would accept them as the global QPOS-elected proposer.
//
// This is the central fix: the election set is restricted to the shard subset.
func TestSHRD_R6_01_NonShardValidatorCannotBeElected(t *testing.T) {
	shardValidator := types.Address{0xAA}
	globalValidatorNotInShard := types.Address{0xBB}

	chain := NewShardChain(1, []types.Address{shardValidator})

	// Base verifier accepts EVERYONE (simulating global QPOS election).
	alwaysAcceptBase := &r5_04_mockVerifier{err: nil}

	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    alwaysAcceptBase,
	}

	// Global validator (not in shard subset) must be rejected.
	err := wrapper.VerifyProposerElection(globalValidatorNotInShard, nil, types.Hash{}, 1)
	if err == nil {
		t.Fatal("SHRD- global validator not in shard subset was accepted (election set NOT restricted to shard subset)")
	}

	// Base verifier must NOT have been called (fail-closed before delegation).
	if alwaysAcceptBase.callCount != 0 {
		t.Errorf("SHRD- base verifier must not be called for non-shard proposer (fail-closed), got callCount=%d",
			alwaysAcceptBase.callCount)
	}
	t.Logf(" OK: non-shard validator rejected before base verifier call (fail-closed)")
}

// TestSHRD_R6_01_ShardValidatorCanBeElected verifies that a validator IN the
// shard subset can pass election verification (when the base verifier also
// accepts).
func TestSHRD_R6_01_ShardValidatorCanBeElected(t *testing.T) {
	shardValidator := types.Address{0xAA}

	chain := NewShardChain(1, []types.Address{shardValidator})
	base := &r5_04_mockVerifier{err: nil}
	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    base,
	}

	err := wrapper.VerifyProposerElection(shardValidator, nil, types.Hash{}, 1)
	if err != nil {
		t.Fatalf("SHRD- shard validator must be accepted, got: %v", err)
	}
	if base.callCount != 1 {
		t.Errorf("SHRD- base verifier must be called for shard validator, got callCount=%d", base.callCount)
	}
	t.Logf(" OK: shard validator accepted (delegated to base verifier)")
}

// TestSHRD_R6_01_MultiShardElectionIsolation verifies that two shards with
// different validator subsets each enforce their OWN membership check. A
// validator elected in shard 1 cannot propose in shard 2 and vice versa.
//
// This is the multi-shard security property: the election set per shard is
// independent.
func TestSHRD_R6_01_MultiShardElectionIsolation(t *testing.T) {
	shard1Validators := []types.Address{{0x01}, {0x02}, {0x03}}
	shard2Validators := []types.Address{{0x04}, {0x05}, {0x06}}

	chain1 := NewShardChain(1, shard1Validators)
	chain2 := NewShardChain(2, shard2Validators)

	// Shared base verifier (production: ShardQPOSAdapter is shared).
	sharedBase := &r5_04_mockVerifier{err: nil}
	chain1.InjectDependencies(nil, sharedBase)
	chain2.InjectDependencies(nil, sharedBase)

	chain1.mu.RLock()
	v1 := chain1.electionVerifier
	chain1.mu.RUnlock()
	chain2.mu.RLock()
	v2 := chain2.electionVerifier
	chain2.mu.RUnlock()

	// Shard 1 accepts its own validators, rejects shard 2's validators.
	for _, v := range shard1Validators {
		if err := v1.VerifyProposerElection(v, nil, types.Hash{}, 1); err != nil {
			t.Errorf("shard 1 should accept its own validator %x: %v", v[:4], err)
		}
	}
	for _, v := range shard2Validators {
		if err := v1.VerifyProposerElection(v, nil, types.Hash{}, 1); err == nil {
			t.Errorf("shard 1 should reject shard 2's validator %x (election set NOT isolated)", v[:4])
		}
	}

	// Shard 2 accepts its own validators, rejects shard 1's validators.
	for _, v := range shard2Validators {
		if err := v2.VerifyProposerElection(v, nil, types.Hash{}, 1); err != nil {
			t.Errorf("shard 2 should accept its own validator %x: %v", v[:4], err)
		}
	}
	for _, v := range shard1Validators {
		if err := v2.VerifyProposerElection(v, nil, types.Hash{}, 1); err == nil {
			t.Errorf("shard 2 should reject shard 1's validator %x (election set NOT isolated)", v[:4])
		}
	}
	t.Logf(" OK: multi-shard election isolation (3+3 validators, no cross-shard acceptance)")
}

// TestSHRD_R6_01_DynamicValidatorRotationEnforced verifies that after
// ReassignValidators updates the shard's validator subset, OLD validators
// can no longer be elected and NEW validators can. This is the dynamic
// enforcement of "election set = shard subset" — the wrapper reads the live
// validator list via the chain back-pointer, so rotations take effect
// immediately.
func TestSHRD_R6_01_DynamicValidatorRotationEnforced(t *testing.T) {
	initialValidator := types.Address{0x01}
	newValidator := types.Address{0x02}

	chain := NewShardChain(1, []types.Address{initialValidator})

	base := &r5_04_mockVerifier{err: nil}
	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    base,
	}

	// Initially, initialValidator is a member, newValidator is not.
	if err := wrapper.VerifyProposerElection(initialValidator, nil, types.Hash{}, 1); err != nil {
		t.Fatalf("before rotation: initialValidator must be accepted, got: %v", err)
	}
	if err := wrapper.VerifyProposerElection(newValidator, nil, types.Hash{}, 1); err == nil {
		t.Fatal("before rotation: newValidator must be rejected")
	}

	// Simulate ReassignValidators by directly updating chain.validators.
	// We bypass the full ReassignValidators path (which needs an authorizer)
	// to isolate the  membership-check property.
	chain.mu.Lock()
	chain.validators = []types.Address{newValidator}
	chain.mu.Unlock()

	// After rotation: initialValidator is no longer a member.
	base.callCount = 0
	if err := wrapper.VerifyProposerElection(initialValidator, nil, types.Hash{}, 2); err == nil {
		t.Fatal("after rotation: initialValidator must be rejected (no longer in shard subset)")
	}
	if base.callCount != 0 {
		t.Errorf("after rotation: base verifier must not be called for old validator, got callCount=%d", base.callCount)
	}

	// After rotation: newValidator is now a member.
	if err := wrapper.VerifyProposerElection(newValidator, nil, types.Hash{}, 2); err != nil {
		t.Fatalf("after rotation: newValidator must be accepted, got: %v", err)
	}
	t.Logf(" OK: dynamic rotation enforced (old validator evicted, new validator admitted)")
}

// TestSHRD_R6_01_EmptyValidatorSetFailClosed verifies that a shard with NO
// validators rejects ALL proposers (fail-closed). This prevents the degenerate
// case where an empty shard subset would allow anyone to propose.
func TestSHRD_R6_01_EmptyValidatorSetFailClosed(t *testing.T) {
	chain := NewShardChain(1, []types.Address{})
	base := &r5_04_mockVerifier{err: nil}
	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    base,
	}

	for _, addr := range []types.Address{{0x01}, {0x02}, {0xFF}} {
		base.callCount = 0
		err := wrapper.VerifyProposerElection(addr, nil, types.Hash{}, 1)
		if err == nil {
			t.Errorf("SHRD- empty shard must reject proposer %x (fail-closed)", addr[:4])
		}
		if base.callCount != 0 {
			t.Errorf("SHRD- empty shard must not delegate to base for proposer %x", addr[:4])
		}
	}
	t.Logf(" OK: empty validator set fail-closed (all proposers rejected)")
}

// TestSHRD_R6_01_BaseVerifierFailurePropagates verifies that when the proposer
// IS a shard member but the base verifier rejects (e.g., VRF proof invalid,
// or QPOS elected a different proposer), the wrapper propagates the error.
// This confirms the membership check is necessary but not sufficient — the
// election must also verify.
func TestSHRD_R6_01_BaseVerifierFailurePropagates(t *testing.T) {
	shardValidator := types.Address{0x01}
	chain := NewShardChain(1, []types.Address{shardValidator})

	baseErr := errors.New("VRF proof invalid: election mismatch")
	base := &r5_04_mockVerifier{err: baseErr}
	wrapper := &shardMembershipVerifierWrapper{
		shardID: 1,
		chain:   chain,
		base:    base,
	}

	err := wrapper.VerifyProposerElection(shardValidator, nil, types.Hash{}, 1)
	if err == nil {
		t.Fatal("SHRD- expected base verifier error to propagate")
	}
	if !errors.Is(err, baseErr) {
		t.Errorf("SHRD- expected base error %v, got %v", baseErr, err)
	}
	if base.callCount != 1 {
		t.Errorf("SHRD- base verifier must be called once for shard member, got callCount=%d", base.callCount)
	}
	t.Logf(" OK: base verifier failure propagated (membership check is necessary but not sufficient)")
}

// TestSHRD_R6_01_FixedSummary documents the  closure status.
func TestSHRD_R6_01_FixedSummary(t *testing.T) {
	t.Log("=== SHRD- CLOSURE SUMMARY ===")
	t.Log("")
	t.Log("Audit finding: election set was not restricted to the shard subset")
	t.Log("  The election verifier (ShardQPOSAdapter) queried the GLOBAL QPOS")
	t.Log("  proposer for a slot, which may not be a member of the specific")
	t.Log("  shard's validator subset. This could allow a non-shard validator")
	t.Log("  to propose shard blocks if the shard's own membership check was")
	t.Log("  ever bypassed.")
	t.Log("")
	t.Log("Fix (SHRD-, 2026-07-16):")
	t.Log("  Introduced shardMembershipVerifierWrapper (shard_election_verifier.go:257-309).")
	t.Log("  InjectDependencies (shard.go:667-689) wraps every base verifier in")
	t.Log("  this per-shard wrapper. The wrapper calls isValidatorLocked(proposer)")
	t.Log("  BEFORE delegating to the base verifier — fail-closed if the proposer")
	t.Log("  is not in sc.validators (the shard's subset).")
	t.Log("")
	t.Log("Security properties verified by this test file:")
	t.Log("  1. Non-shard validator rejected (even if base verifier accepts).")
	t.Log("  2. Shard validator accepted (delegated to base verifier).")
	t.Log("  3. Multi-shard isolation: each shard enforces its own subset.")
	t.Log("  4. Dynamic rotation: ReassignValidators updates take effect immediately.")
	t.Log("  5. Empty validator set: fail-closed (all proposers rejected).")
	t.Log("  6. Base verifier failure: propagated (membership is necessary, not sufficient).")
	t.Log("")
	t.Log(" status: FIXED (via SHRD-) ✓")
}

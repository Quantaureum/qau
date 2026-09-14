// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"sync"

	qaucrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// ShardElectionVerifier is a production-grade implementation of the
// ElectionVerifier interface for shard chains.
//
// FIX [HIGH] / M-11 [MEDIUM]: ProposeBlock requires an
// ElectionVerifier to confirm that the proposer was legitimately elected via
// VRF for the current slot. This implementation performs full verification:
//
//  1. Looks up the proposer's registered Dilithium3 public key.
//  2. Cryptographically verifies the VRF proof against the epoch seed using
//     consensus.VerifyVRF (proof validity + output determinism).
//  3. Verifies that the VRF output elects this proposer by calling
//     ValidatorSet.SelectProposer — the same stake-weighted selection algorithm
//     used by the main chain.
//
// Thread safety: ShardElectionVerifier is safe for concurrent use. It
// maintains its own mutex-protected copy of the validator pubkeys, VRF seed,
// and validator set. These should be updated at epoch boundaries via
// UpdateEpochState.
//
// Usage: During shard initialization, create a ShardElectionVerifier and
// register it via ShardChain.SetElectionVerifier.
//
//	verifier := consensus.NewShardElectionVerifier()
//	verifier.UpdateEpochState(pubKeys, vrfSeed, validatorSet)
//	chain.SetElectionVerifier(verifier)
type ShardElectionVerifier struct {
	mu sync.RWMutex

	// validatorPubKeys maps validator address → Dilithium3 public key bytes.
	validatorPubKeys map[types.Address][]byte

	// vrfSeed is the current epoch's VRF seed used for proposer election.
	vrfSeed types.Hash

	// validatorSet is used for stake-weighted proposer selection from VRF output.
	// May be nil if the shard uses a simpler round-robin election; in that case
	// only VRF proof validity is checked (not election result).
	validatorSet *ValidatorSet
}

// NewShardElectionVerifier creates a new production-grade election verifier
// for shard chains. The verifier starts empty; call UpdateEpochState before
// use to configure validator pubkeys, VRF seed, and validator set.
func NewShardElectionVerifier() *ShardElectionVerifier {
	return &ShardElectionVerifier{
		validatorPubKeys: make(map[types.Address][]byte),
	}
}

// UpdateEpochState updates the verifier's epoch state. This should be called
// at epoch boundaries (or shard reassignment) to refresh:
//   - validatorPubKeys: each validator's Dilithium3 public key
//   - vrfSeed: the current epoch's VRF seed
//   - validatorSet: the current validator set for stake-weighted selection
//
// Passing nil for validatorSet disables election-result verification (only
// VRF proof validity will be checked). This is less secure and should only
// be used for testing or shards without stake-weighted election.
// audit-remediation: reviewed 2026-09-11 — epoch bookkeeping; does not touch stake.
func (v *ShardElectionVerifier) UpdateEpochState(
	validatorPubKeys map[types.Address][]byte,
	vrfSeed types.Hash,
	validatorSet *ValidatorSet,
) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.validatorPubKeys = make(map[types.Address][]byte, len(validatorPubKeys))
	for addr, pk := range validatorPubKeys {
		pkCopy := make([]byte, len(pk))
		copy(pkCopy, pk)
		v.validatorPubKeys[addr] = pkCopy
	}
	v.vrfSeed = vrfSeed
	v.validatorSet = validatorSet
}

// VerifyProposerElection verifies that the proposer was legitimately elected
// for the given block height via VRF-based proposer election.
//
// Steps:
//  1. Look up the proposer's public key. Fail-closed if not registered.
//  2. Verify the VRF proof cryptographically (proof validity + output
//     determinism via consensus.VerifyVRF).
//  3. If a validator set is configured, verify the VRF output elects this
//     proposer via stake-weighted selection (ValidatorSet.SelectProposer).
//     If no validator set is configured, only VRF proof validity is checked.
//
// Returns nil if verification succeeds, or an error describing the failure.
func (v *ShardElectionVerifier) VerifyProposerElection(
	proposer types.Address,
	vrfProof []byte,
	vrfOutput types.Hash,
	height uint64,
) error {
	v.mu.RLock()
	pubKeyBytes, ok := v.validatorPubKeys[proposer]
	vrfSeed := v.vrfSeed
	validatorSet := v.validatorSet
	v.mu.RUnlock()

	if !ok || len(pubKeyBytes) == 0 {
		return fmt.Errorf("no public key registered for proposer %x", proposer[:4])
	}

	// Step 1: Reconstruct the public key from bytes.
	pubKey, err := qaucrypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil || pubKey == nil {
		return fmt.Errorf("invalid public key for proposer %x: %w", proposer[:4], err)
	}

	// Step 2: Cryptographically verify the VRF proof.
	// Fail-closed: if no VRF seed is configured, reject all proposals.
	if vrfSeed == (types.Hash{}) {
		return fmt.Errorf("VRF seed not configured for shard election verification")
	}

	if len(vrfProof) == 0 {
		return fmt.Errorf("empty VRF proof from proposer %x", proposer[:4])
	}

	proof := &VRFProof{Proof: vrfProof}
	output := &VRFOutput{Value: vrfOutput}

	if err := VerifyVRF(pubKey, vrfSeed, proof, output); err != nil {
		return fmt.Errorf("VRF proof verification failed for proposer %x: %w",
			proposer[:4], err)
	}

	// Step 3: Verify the VRF output elects this proposer.
	// If a validator set is configured, use stake-weighted selection to confirm
	// the proposer is the elected winner. Without this check, any validator with
	// a valid VRF proof could propose — but VRF proof validity alone does not
	// prove election (the output must also select this validator).
	//
	// SHRD-R5-04 (2026-07-16): The validatorSet may be the global/main-chain
	// set (depending on what was injected via UpdateEpochState), so
	// SelectProposer could elect a validator that is not actually assigned to
	// this shard. However, the membership check at the top of this function
	// (line ~111: "if !ok") already verifies that the CLAIMED proposer has a
	// registered public key in this shard's validatorPubKeys map — i.e., the
	// proposer IS a shard validator. Combined with the election-result check
	// below (elected.Address == proposer), this ensures:
	//   (a) The claimed proposer is a shard validator (pubkey registered).
	//   (b) The VRF output elects exactly this proposer.
	// So a global-set validator that is NOT a shard validator cannot pass (a),
	// and a shard validator that was not elected cannot pass (b).
	if validatorSet != nil {
		elected, err := validatorSet.SelectProposer(output)
		if err != nil {
			return fmt.Errorf("failed to select proposer from VRF output: %w", err)
		}
		if elected == nil {
			return fmt.Errorf("no proposer elected from VRF output")
		}
		if elected.Address != proposer {
			return fmt.Errorf("proposer mismatch: VRF elected %x, got %x (height %d)",
				elected.Address[:4], proposer[:4], height)
		}
	}

	return nil
}

// ShardQPOSAdapter is an alternative ElectionVerifier implementation that
// delegates proposer election verification to the mainchain QPOS engine.
// Instead of independently verifying VRF proofs, it maps the shard block
// height to a mainchain slot and queries QPOS.GetProposerForSlot.
//
// P0-5 (2026-07-14): This adapter is for shards that want to reuse the
// mainchain's QPOS election rather than maintaining an independent VRF
// election. It is simpler than ShardElectionVerifier (no VRF proof
// verification needed — QPOS already did that) but requires that shard
// blocks are produced in lockstep with mainchain slots (1:1 height mapping
// by default, overridable via SlotResolver).
//
// SHRD-R5-04 (2026-07-16): This adapter is a SHARED, stateless verifier —
// it does NOT check whether the QPOS-elected proposer belongs to a specific
// shard's validator subset (it cannot, because the same adapter instance is
// injected into every shard via InjectDependencies). The per-shard
// membership check is performed by shardMembershipVerifierWrapper, which
// wraps this adapter at injection time (see ShardChain.InjectDependencies).
// This design keeps the shared adapter stateless while still enforcing
// "elected proposer must be a shard validator" uniformly in both ProposeBlock
// and ReceiveBlock paths.
//
// Thread safety: ShardQPOSAdapter is safe for concurrent use because it
// only reads from *QPOS, whose methods are thread-safe.
type ShardQPOSAdapter struct {
	qpos         *QPOS
	slotResolver func(height uint64) uint64
}

// NewShardQPOSAdapter creates a QPOS-backed election verifier. If
// slotResolver is nil, shard height is used directly as the mainchain slot
// (1:1 mapping). For shards with a different height↔slot relationship,
// provide a custom resolver (e.g., slot = height * shardCount + shardID).
func NewShardQPOSAdapter(qpos *QPOS, slotResolver func(height uint64) uint64) *ShardQPOSAdapter {
	if slotResolver == nil {
		slotResolver = func(height uint64) uint64 { return height }
	}
	return &ShardQPOSAdapter{
		qpos:         qpos,
		slotResolver: slotResolver,
	}
}

// VerifyProposerElection maps the shard height to a mainchain slot via
// SlotResolver, then queries QPOS.GetProposerForSlot and compares the
// elected proposer's address against the claimed proposer.
//
// SHRD-R5-04 (2026-07-16): This method does NOT perform per-shard membership
// check — that is the responsibility of shardMembershipVerifierWrapper which
// wraps this adapter. Do NOT call this directly for shard block verification
// unless you perform the membership check separately.
//
// The vrfProof and vrfOutput parameters are NOT verified by this adapter —
// QPOS performs its own election internally. They are accepted to satisfy
// the ElectionVerifier interface.
func (a *ShardQPOSAdapter) VerifyProposerElection(
	proposer types.Address,
	vrfProof []byte,
	vrfOutput types.Hash,
	height uint64,
) error {
	if a.qpos == nil {
		return fmt.Errorf("ShardQPOSAdapter: qpos engine not configured")
	}

	slot := a.slotResolver(height)
	expected, err := a.qpos.GetProposerForSlot(slot)
	if err != nil {
		return fmt.Errorf("failed to determine elected proposer for slot %d (shard height %d): %w",
			slot, height, err)
	}
	if expected == nil {
		return fmt.Errorf("no proposer elected for slot %d (shard height %d)", slot, height)
	}

	if expected.Address != proposer {
		return fmt.Errorf("proposer mismatch: expected %x, got %x (slot %d, shard height %d)",
			expected.Address[:4], proposer[:4], slot, height)
	}

	return nil
}

// shardMembershipVerifierWrapper wraps a base ElectionVerifier with a
// per-shard validator membership check (SHRD-R5-04).
//
// Problem: ShardQPOSAdapter is a shared, stateless verifier injected into
// every shard. It queries the mainchain QPOS for the elected proposer, but
// QPOS returns the GLOBAL proposer for that slot — which may not be a member
// of this specific shard's validator subset. Without a per-shard membership
// check, the election verifier and the shard's own isValidatorLocked check
// could disagree, causing either liveness stalls (global election picks a
// non-shard validator → no valid proposer) or soundness gaps (if the shard
// membership check is ever bypassed).
//
// Fix: This wrapper is created per-shard in ShardChain.InjectDependencies.
// It checks that the claimed proposer is a member of THIS shard's validator
// subset (via ShardChain.isValidatorLocked) before delegating to the base
// verifier. This unifies the membership check inside the verifier so both
// ProposeBlock and ReceiveBlock paths enforce it identically.
//
// Thread safety: The wrapper is safe for concurrent use because it only
// reads from the ShardChain's validator list via isValidatorLocked. The
// caller (ProposeBlock/ReceiveBlock) must hold sc.mu when calling
// VerifyProposerElection — this is already the case in both paths.
type shardMembershipVerifierWrapper struct {
	shardID uint64
	chain   *ShardChain
	base    ElectionVerifier
}

// VerifyProposerElection first checks that the proposer is a member of this
// shard's validator subset (fail-closed), then delegates to the base
// verifier for election verification.
func (w *shardMembershipVerifierWrapper) VerifyProposerElection(
	proposer types.Address,
	vrfProof []byte,
	vrfOutput types.Hash,
	height uint64,
) error {
	// SHRD-R5-04 (2026-07-16): Fail-closed membership check. The proposer
	// must be a member of this shard's validator subset. This is checked
	// INSIDE the verifier (not just in ProposeBlock/ReceiveBlock) so the
	// membership enforcement is unified across both paths and cannot be
	// accidentally bypassed by a future code change in either caller.
	//
	// isValidatorLocked is non-locking (caller must hold sc.mu). Both
	// ProposeBlock and ReceiveBlock hold sc.mu when calling the verifier,
	// so this is safe. If a future caller invokes the verifier without
	// holding sc.mu, it must use Validators() instead.
	if !w.chain.isValidatorLocked(proposer) {
		return fmt.Errorf("SHRD-R5-04: proposer %x is not a member of shard %d's validator subset (height %d)",
			proposer[:4], w.shardID, height)
	}
	return w.base.VerifyProposerElection(proposer, vrfProof, vrfOutput, height)
}

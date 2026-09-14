// Quantaureum Node source, version 1.0.0.
// Package consensus implements QPOS (Quantum-resistant Proof of Stake) consensus.
// QPOS is modeled after Ethereum's Gasper (Casper FFG + LMD GHOST) but uses
// post-quantum cryptography (Dilithium3) for all signatures.
//
// Key concepts:
// - Slot: 12 second time period, one block per slot
// - Epoch: 32 slots = 6.4 minutes, used for finality checkpoints
// - Proposer: Selected validator to create block for a slot
// - Attester: Validators who vote on blocks
// - Finality: Blocks become irreversible after 2 epochs of attestations
package consensus

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// ProcessAttestation processes an attestation and updates finality.
// Fix 1: Vote recording is moved outside q.mu lock to reduce lock contention.
// The attestation is fully validated and stored inside the lock; only the
// vote recording (for statistics/double-sign detection) is done asynchronously
// via a goroutine after the lock is released.
func (q *QPOS) ProcessAttestation(att *Attestation) error {
	var voteData *Vote
	var voteStake *big.Int
	var vm *VotingManager

	// This defer runs AFTER q.mu.Unlock() (defers are LIFO), so vote recording
	// happens outside the lock, reducing contention on the hot path.
	defer func() {
		if vm != nil && voteData != nil {
			go vm.recordAttestationVote(voteData, voteStake)
		}
	}()

	q.mu.Lock()
	defer q.mu.Unlock()

	if att == nil {
		return ErrInvalidAttestation
	}

	// audit-fix C-2: reject attestations if network ID has not been configured.
	// This prevents processing attestations before SetAttestationNetworkID is called,
	// blocking cross-chain replay attacks between mainnet/testnet/devnet.
	if GetAttestationNetworkID() == 0 {
		return ErrNetworkIDNotConfigured
	}

	// Verify attestation is for a valid slot
	currentSlot := q.GetCurrentSlot()
	if att.Slot > currentSlot+1 {
		return ErrSlotTooFar
	}

	// audit-fix H-3: reject stale attestations older than 1 epoch.
	// This prevents replay of old legitimate attestations.
	if currentSlot > SlotsPerEpoch && att.Slot < currentSlot-SlotsPerEpoch {
		return ErrSlotInPast
	}

	// CONS-R13-M01 (2026-07-21): Reject attestations whose slot epoch is
	// strictly greater than the current wall-clock epoch. The existing
	// att.Slot <= currentSlot+1 check allows ONE future slot, but if that
	// future slot crosses an epoch boundary, att.Target.Epoch would be
	// currentEpoch+1. tryUpdateFinality only processes prevEpoch =
	// currentEpoch-1, so such "future epoch" attestations would be stored
	// in q.attestations but never counted toward finality — causing
	// memory growth and a false sense of "already processed". Worse,
	// wall-clock drift could let different nodes compute different
	// currentEpoch values, leading to inconsistent finality decisions.
	// Fail-closed: reject any attestation whose epoch hasn't started yet.
	currentEpoch := q.GetCurrentEpoch()
	attSlotEpoch := SlotToEpoch(att.Slot)
	if attSlotEpoch > currentEpoch {
		return fmt.Errorf("%w: attestation slot %d (epoch %d) is in a future epoch (current %d)",
			ErrSlotTooFar, att.Slot, attSlotEpoch, currentEpoch)
	}

	// Verify validator index is valid
	validators := q.validators.Validators()
	if att.ValidatorIndex < 0 || att.ValidatorIndex >= len(validators) {
		return fmt.Errorf("%w: validator index %d out of range [0, %d)", ErrInvalidAttestation, att.ValidatorIndex, len(validators))
	}

	// audit-fix R9-M1: reject attestations from slashed validators.
	// A slashed validator must not influence consensus weight or finality.
	if _, slashed := q.slashedValidators[att.ValidatorIndex]; slashed {
		return ErrValidatorSlashed
	}

	// audit-fix CS-03: reject attestations from inactive validators at the
	// submission entry, not only at downstream finality/fork-choice accounting.
	// Without this gate, an inactive validator's attestation is stored in
	// q.attestations and consumes bookkeeping state (duplicate detection,
	// surround-vote checks), even though it is later filtered out when
	// counting weight. Mirrors CR-1 in checkpoint.go AddSignature. The check
	// is placed before the expensive Dilithium3 verification and before the
	// duplicate/map writes so an inactive validator cannot pollute state.
	if !validators[att.ValidatorIndex].Active {
		return ErrValidatorNotActive
	}

	// L14-008: Early duplicate attestation check (rate limiting per validator per slot).
	// Reject duplicates before expensive Dilithium3 signature verification to prevent
	// CPU exhaustion from repeated invalid attestations. Uses O(1) map lookup.
	// CON-VAL-01 FIX (deep-audit 2026-07-12): only short-circuit when the prior
	// attestation is for the SAME block. A second attestation for a DIFFERENT
	// block at the same slot is equivocation (a double vote) and MUST fall
	// through to checkDoubleVote below so slashing evidence is generated. The old
	// slot-only guard rejected it as a plain duplicate, making the entire
	// double-vote detector (and its slashing path) dead code for attestations.
	if va := q.validatorAttestations[att.ValidatorIndex]; va != nil {
		if existing, exists := va[att.Slot]; exists && existing != nil {
			if existing.BeaconBlockRoot == att.BeaconBlockRoot {
				return ErrDuplicateAttestation
			}
		}
	}

	// Verify Dilithium3 signature on the attestation
	if err := q.verifyAttestationSignature(att, validators); err != nil {
		return err
	}

	// audit-fix MEDIUM: validate Source/Target epoch consistency.
	// att.Target.Epoch must match the epoch of att.Slot, and att.Source.Epoch
	// must be strictly less than att.Target.Epoch (source is the justified
	// checkpoint, target is the current epoch checkpoint). Without this check,
	// an attacker could craft attestations with arbitrary epochs to manipulate
	// finality accounting.
	if att.Target.Epoch != attSlotEpoch {
		return fmt.Errorf("%w: target epoch %d does not match slot epoch %d",
			ErrInvalidAttestation, att.Target.Epoch, attSlotEpoch)
	}
	if att.Source.Epoch >= att.Target.Epoch {
		return fmt.Errorf("%w: source epoch %d must be less than target epoch %d",
			ErrInvalidAttestation, att.Source.Epoch, att.Target.Epoch)
	}
	// CONS-003 (R8 2026-07-19 FIX): Bind att.Source.Root to the canonical
	// justified root at submission time. Without this, an attacker could
	// submit an attestation whose Source.Epoch is a justified epoch but
	// whose Source.Root points to a non-canonical fork root. The attestation
	// would be stored and later counted toward finality weight on a
	// conflicting fork in tryUpdateFinality — violating Casper FFG
	// accountable safety. Defense in depth: we also re-check this in
	// tryUpdateFinality so that any pre-existing polluted attestations
	// (from before this fix) cannot contribute weight. Fail-closed: if
	// the canonical root for Source.Epoch is not recorded (bootstrap),
	// reject the attestation. Genesis epoch (Source.Epoch == 0) is exempted
	// because the genesis root is fixed at node startup via genesis.json
	// and is not stored in epochBlockRoots; nodes with a different genesis
	// root are on a different chain anyway.
	if att.Source.Epoch > 0 {
		canonicalSourceRootAtSubmit := q.getEpochBlockRootLocked(att.Source.Epoch)
		if canonicalSourceRootAtSubmit == (types.Hash{}) {
			return fmt.Errorf("%w: source epoch %d has no canonical root recorded yet",
				ErrInvalidAttestation, att.Source.Epoch)
		}
		if att.Source.Root != canonicalSourceRootAtSubmit {
			return fmt.Errorf("%w: source root %s does not match canonical root %s for epoch %d",
				ErrInvalidAttestation, att.Source.Root.String(),
				canonicalSourceRootAtSubmit.String(), att.Source.Epoch)
		}
	}

	// Verify validator is in committee for this slot (lock-free internal version)
	// AUDIT-FULL ROUND1 2026-08-14 CS-03: isInCommitteeLocked selects validators
	// from the active set via VRF-based committee election, so inactive validators
	// cannot be selected. CONFIRMED-IN-PLACE.
	if !q.isInCommitteeLocked(att.Slot, validators[att.ValidatorIndex].Address) {
		return ErrNotInCommittee
	}

	// SLASHING CHECK 1: Double Vote Detection
	if err := q.checkDoubleVote(att); err != nil {
		return err
	}

	// SLASHING CHECK 2: Surround Vote Detection
	// CRITICAL FIX R13-C2: Now captures the surrounded attestation for evidence
	surroundedAtt, err := q.checkSurroundVote(att)
	if err != nil {
		// audit-fix HIGH-SURROUND: Submit surround vote evidence for slashing.
		// Previously, surround votes were rejected but the validator was not penalized,
		// making the attack "free" to attempt repeatedly.
		//
		// R17-C2 FIX: If slashingManager is nil but we have evidence to submit,
		// queue evidence for later submission instead of losing it.
		//
		// CONS- (2026-07-20) FIX: checkSurroundVote now returns
		// ErrDoubleVote for same-epoch conflicting votes and ErrSurroundVote
		// for strict-surround votes. The evidence SlashingReason must match
		// the actual offense, otherwise:
		//   - SlashingManager picks the wrong penalty branch
		//   - MinistryRevenue credits the wrong offense category
		//   - VerifySurroundVoteEvidence would reject DoubleVote evidence
		//     (it expects strict < on both epochs)
		//   - Audit logs mix the two offense types, hiding the true
		//     distribution of slashable offenses
		if surroundedAtt != nil {
			validators := q.validators.Validators()
			if att.ValidatorIndex >= 0 && att.ValidatorIndex < len(validators) {
				validatorAddr := validators[att.ValidatorIndex].Address
				reason := SlashingReasonSurroundVote
				if err == ErrDoubleVote {
					reason = SlashingReasonDoubleVote
				}
				evidence := &SlashingEvidence{
					Reason:        reason,
					ValidatorAddr: validatorAddr,
					Height:        att.Slot,
					// R33 CONS-01 FIX (2026-07-28): Use GetLastKnownBlockTime() for the
					// evidence timestamp. Previously used int64(att.Slot) (~50400) which
					// caused SubmitEvidence freshness check (now - Timestamp > 604800)
					// to permanently reject all surround-vote evidence because
					// time.Now().Unix() (~1.7B) - 50400 >> 604800. This made surround
					// vote slashing completely ineffective. Use the consensus-derived
					// block time, consistent with SlashValidator and double-vote path.
					Timestamp: q.GetLastKnownBlockTime(),
					// CRITICAL FIX R13-C2: Populate Vote1 and Vote2 for verification
					Vote1: attestationToVote(att, validatorAddr),
					Vote2: attestationToVote(surroundedAtt, validatorAddr),
				}
				// CRITICAL FIX: Queue evidence if slashingManager not available, don't lose it
				if q.slashingManager == nil {
					q.queueSlashingEvidenceLocked(evidence)
					return fmt.Errorf("[CRITICAL] slashingManager not initialized, evidence queued for later submission: %w", err)
				}
				// audit-fix RISK-009: Submit evidence asynchronously to avoid blocking the
				// consensus mutex. Previously, a retry loop with time.Sleep held q.mu for up
				// to 600ms, stalling all attestations. Async submission queues evidence
				// reliably without blocking the hot path.
				// Queue first to guarantee delivery regardless of async outcome.
				q.queueSlashingEvidenceLocked(evidence)
				// Capture slashingManager reference before goroutine launch.
				sm := q.slashingManager
				// R34-CONS-P0-003 FIX: Capture deterministic blockTime for
				// SubmitEvidence to prevent non-deterministic slashing timestamps
				// and jailUntil divergence across nodes. evidence.Timestamp was
				// already set to q.GetLastKnownBlockTime() above (consensus-derived).
				submitBlockTime := evidence.Timestamp
				// R5-P3-2 FIX: Deep copy evidence for the goroutine to prevent the
				// queue and goroutine from sharing the same pointer. Without this,
				// concurrent access to Vote1/Vote2 pointers could cause data races.
				evCopy := &SlashingEvidence{
					Reason:        evidence.Reason,
					ValidatorAddr: evidence.ValidatorAddr,
					Height:        evidence.Height,
					Timestamp:     evidence.Timestamp,
					Vote1:         deepCopyVote(evidence.Vote1),
					Vote2:         deepCopyVote(evidence.Vote2),
				}
				go func() {
					defer func() {
						if r := recover(); r != nil {
							// P3-LOG-06 FIX (R30, 2026-07-27): Use structured slashingLogger
							// (module=consensus, category=SECURITY) instead of fmt.Fprintf(os.Stderr)
							// so SIEM pipelines can collect this security-relevant panic event.
							// Slashing evidence submission failures can indicate bugs or attacks
							// on the slashing mechanism itself.
							slashingLogger.Error("Slashing evidence submission goroutine panic",
								map[string]any{"panic": fmt.Sprintf("%v", r)})
						}
					}()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					for i := 0; i < 3; i++ {
						select {
						case <-ctx.Done():
							return
						default:
						}
						if _, submitErr := sm.SubmitEvidence(evCopy, getVotingSystemCaller(), submitBlockTime); submitErr == nil {
							return
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(time.Duration(100*(i+1)) * time.Millisecond):
						}
					}
				}()
				return err // Continue processing attestation; evidence submission is async
			}
		}
		return err
	}

	// Check for duplicate attestation (same validator, same slot, same block)
	existingAtts := q.attestations[att.Slot]
	for _, existing := range existingAtts {
		if existing.ValidatorIndex == att.ValidatorIndex {
			return ErrDuplicateAttestation
		}
	}

	// audit-fix M-6: enforce MinAttestations is checked during finality,
	// and validate attestation count per slot doesn't exceed committee size.

	// Add attestation
	q.attestations[att.Slot] = append(q.attestations[att.Slot], att)

	// Track validator attestation for future slashing detection
	// MEDIUM FIX: Add bounds check for ValidatorIndex before accessing validatorAttestations
	// This prevents potential out-of-bounds access with malicious attestation data
	if att.ValidatorIndex < 0 {
		return ErrInvalidAttestation
	}
	// Additional safety: ensure validator index is within reasonable bounds
	// The upper bound check uses the current validator set size as the only valid boundary
	// CRITICAL FIX: Remove arbitrary constant 1000, use actual validator set size
	if att.ValidatorIndex >= len(validators) {
		return fmt.Errorf("%w: validator index %d exceeds validator set size %d",
			ErrInvalidAttestation, att.ValidatorIndex, len(validators))
	}
	if q.validatorAttestations[att.ValidatorIndex] == nil {
		q.validatorAttestations[att.ValidatorIndex] = make(map[uint64]*Attestation)
	}
	q.validatorAttestations[att.ValidatorIndex][att.Slot] = att

	// Collect vote data for async recording outside the lock (via defer above).
	// The signature is copied so the goroutine doesn't share a slice with the
	// attestation stored in q.attestations.
	vm = q.votingManager
	if vm != nil {
		validatorAddr := validators[att.ValidatorIndex].Address
		voteData = attestationToVote(att, validatorAddr)
		sigCopy := make([]byte, len(att.Signature))
		copy(sigCopy, att.Signature)
		voteData.Signature = sigCopy
		voteStake = new(big.Int).Set(validators[att.ValidatorIndex].Stake)
	}

	// CONS-005 (R8 2026-07-19 FIX): Removed the %8 throttle that previously
	// gated tryUpdateFinality(). With small validator sets (e.g. 3 validators
	// on mainnet), the modulo-8 check delayed finality updates by up to 8
	// attestations — spanning multiple slots — and could cause finality to
	// stall entirely if the counter never landed on a multiple of 8 within
	// an epoch boundary. tryUpdateFinality() is O(N_validators + N_slots *
	// N_attestations_per_slot) which is cheap enough to run on every
	// attestation; the previous "Fix 2" optimization traded correctness for
	// micro-perf and is no longer acceptable.
	q.attestationCounter++
	q.tryUpdateFinality()

	return nil
}

// verifyAttestationSignature verifies the individual Dilithium3 signature on an attestation.
// Attestations are always signed with the validator's individual key (not TSS), so we
// always verify with the validator's individual public key.
//
// R131: if the validator has rotated to a session key, ONLY the session key is
// accepted for epochs >= activation epoch; revoked validators are rejected outright.
// The historical attestations of a pre-rotation validator remain verifiable because
// resolution is evaluated at att.Target.Epoch, not at wall-clock time.
func (q *QPOS) verifyAttestationSignature(att *Attestation, validators []*Validator) error {
	if len(att.Signature) == 0 {
		return fmt.Errorf("%w: empty signature", ErrInvalidAttestation)
	}

	validator := validators[att.ValidatorIndex]

	// R131: revoked validator identities produce no valid attestations.
	if q.IsValidatorRevoked(validator.Address) {
		return fmt.Errorf("%w: validator %d identity is revoked", ErrInvalidAttestation, att.ValidatorIndex)
	}

	pubKeyBytes := validator.PublicKeyBytes
	if sessionPK, ok := q.EffectiveSessionPubKey(validator.Address, att.Target.Epoch); ok {
		pubKeyBytes = sessionPK
	}
	if len(pubKeyBytes) == 0 {
		return fmt.Errorf("%w: validator %d has no public key bytes", ErrInvalidAttestation, att.ValidatorIndex)
	}

	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("%w: invalid public key for validator %d: %v", ErrInvalidAttestation, att.ValidatorIndex, err)
	}

	data := q.attestationSigningData(att)

	if !crypto.Verify(pubKey, data, att.Signature) {
		return fmt.Errorf("%w: Dilithium3 signature verification failed for validator %d", ErrInvalidAttestation, att.ValidatorIndex)
	}

	return nil
}

// VerifyAttestationSignature is an exported wrapper around
// verifyAttestationSignature that allows the node layer to verify P2P
// attestation payloads BEFORE they are propagated to mesh peers or
// processed by the consensus engine.
//
// P2P-R12-CRIT-001 (2026-07-20) FIX: R11 added the Dilithium3PayloadVerifier
// framework in p2p/signature_verifier.go but never wired it into the node
// init flow. This wrapper provides the consensus-side entry point that the
// node layer's VoteSignatureVerifyFunc invokes.
//
// The method takes a snapshot of the validator set under the read lock, then
// releases the lock before invoking verifyAttestationSignature (which performs
// Dilithium3 crypto.Verify — a CPU-bound operation that should not hold the
// consensus mutex). This matches the locking discipline of ProcessAttestation.
//
// Returns nil if the signature is valid, or an error wrapping
// ErrInvalidAttestation with details otherwise.
func (q *QPOS) VerifyAttestationSignature(att *Attestation) error {
	if att == nil {
		return fmt.Errorf("%w: nil attestation", ErrInvalidAttestation)
	}
	if q.validators == nil {
		return fmt.Errorf("%w: validator set not initialized", ErrInvalidAttestation)
	}
	// Take a snapshot of the validator slice under the read lock.
	// Validators() returns a copy of the underlying slice (pointer-safe —
	// the []*Validator entries themselves are not mutated in place; the
	// slice is replaced wholesale by AddValidator/RemoveValidator).
	q.mu.RLock()
	validators := q.validators.Validators()
	q.mu.RUnlock()

	if att.ValidatorIndex < 0 || att.ValidatorIndex >= len(validators) {
		return fmt.Errorf("%w: validator index %d out of range (have %d validators)",
			ErrInvalidAttestation, att.ValidatorIndex, len(validators))
	}
	if validators[att.ValidatorIndex] == nil {
		return fmt.Errorf("%w: validator %d is nil", ErrInvalidAttestation, att.ValidatorIndex)
	}
	return q.verifyAttestationSignature(att, validators)
}

// tryUpdateFinality attempts to update justified and finalized checkpoints
// Implements Casper FFG finality rules
// GetAttestationsForSlot returns attestations for a slot.
// audit-fix NEW-15: returns deep copies so callers cannot mutate internal
// Signature byte slices and corrupt attestation data used for finality.
func (q *QPOS) GetAttestationsForSlot(slot uint64) []*Attestation {
	q.mu.RLock()
	defer q.mu.RUnlock()

	atts := q.attestations[slot]
	result := make([]*Attestation, len(atts))
	for i, att := range atts {
		result[i] = deepCopyAttestation(att)
	}
	return result
}

// deepCopyAttestation returns a deep copy of an Attestation, including its
// Signature byte slice, to prevent callers from mutating internal state.
// audit-fix NEW-15.
func deepCopyAttestation(att *Attestation) *Attestation {
	if att == nil {
		return nil
	}
	cp := *att
	if att.Signature != nil {
		cp.Signature = make([]byte, len(att.Signature))
		copy(cp.Signature, att.Signature)
	}
	return &cp
}

// CreateAttestation creates an attestation for a validator.
//
// CONS- (2026-07-19) FIX: Previously this method read
// justifiedEpoch/justifiedRoot under q.mu.RLock, RELEASED the lock, then
// read currentKeyVersion via GetCurrentKeyVersion() (which re-locks under
// q.keyVersionMu). Between those two atomic reads, another goroutine
// could call tryUpdateFinality (via ProcessAttestation) and SetKeyVersion
// (via key rotation), producing an attestation whose Source.Epoch/Root
// are from time T1 but whose KeyVersion is from time T2 — an inconsistent
// attestation that could fail signature verification downstream or
// confuse the slashing detector. The fix acquires BOTH locks in a
// consistent order (q.mu first, then q.keyVersionMu) and reads all
// three values atomically under that pair, eliminating the race window.
//
// Lock ordering contract: when both q.mu and q.keyVersionMu are held,
// q.mu is always acquired FIRST. This ordering must be respected by any
// future code path that acquires both locks.
func (q *QPOS) CreateAttestation(slot uint64, blockRoot types.Hash, validatorIndex int) *Attestation {
	q.mu.RLock()
	justifiedEpoch := q.justifiedEpoch
	justifiedRoot := q.justifiedRoot
	currentEpoch := SlotToEpoch(slot)
	// CRITICAL FIX: Target.Root must be the epoch boundary block root,
	// NOT the current block root. In Casper FFG, all attestations within
	// the same epoch must vote for the SAME target checkpoint (the block
	// at the first slot of the epoch). Using the current block root as
	// Target.Root causes every slot's attestation to have a different
	// Target.Root within the same epoch, which triggers false "double
	// vote" slashing detection in checkSurroundVote.
	targetRoot := q.getEpochBlockRootLocked(currentEpoch)
	q.keyVersionMu.RLock()
	currentKeyVersion := q.currentKeyVersion
	q.keyVersionMu.RUnlock()
	q.mu.RUnlock()

	// R42-P4 FIX (2026-08-07): If no epoch boundary block has been
	// recorded yet, return an EMPTY attestation (nil) instead of falling
	// back to the current block root. The previous fallback used the
	// current block root as Target.Root, but once the epoch boundary is
	// later set (via SetEpochBlockRoot/EnsureEpochBlockRoot) to a
	// DIFFERENT block, all subsequent attestations in the same epoch use
	// that boundary root — producing two different Target.Root values
	// within one epoch → false "double vote" slashing detection.
	//
	// Not voting is safer than voting with an unstable target root. The
	// caller (tryAttest) must handle a nil return by skipping attestation
	// for this slot. The epoch boundary is normally set as soon as the
	// first block of the epoch is processed, so this only affects the
	// earliest slots of an epoch.
	if targetRoot == (types.Hash{}) {
		return nil
	}

	return &Attestation{
		Slot:            slot,
		BeaconBlockRoot: blockRoot,
		Source: AttestationCheckpoint{
			Epoch: justifiedEpoch,
			Root:  justifiedRoot,
		},
		Target: AttestationCheckpoint{
			Epoch: currentEpoch,
			Root:  targetRoot,
		},
		ValidatorIndex: validatorIndex,
		KeyVersion:     currentKeyVersion,
	}
}

// SignAttestation signs an attestation using the validator's individual Dilithium3 key.
// Attestations are per-validator, per-slot operations that MUST use individual signatures,
// NOT TSS threshold signatures. TSS requires multi-node coordination which is not feasible
// within a 12-second slot. TSS remains available for block signing and other threshold
// operations (cross-chain bridges, multi-sig wallets).
func (q *QPOS) SignAttestation(att *Attestation, privateKey *crypto.PrivateKey) error {
	if att == nil {
		return ErrInvalidAttestation
	}

	data := q.attestationSigningData(att)

	sig, err := crypto.Sign(privateKey, data)
	if err != nil {
		return err
	}
	att.Signature = sig

	return nil
}

// AttestationDomainSeparator is the domain separator for attestation signing.
// audit-fix L-4: prevents cross-network replay of attestations.
var AttestationDomainSeparator = []byte("QUANTAUREUM_ATT_V1")

// attestationNetworkID is the network ID included in attestation signing data.
// audit-fix H-4: prevents cross-chain replay between mainnet/testnet/devnet.
// Must be set via SetAttestationNetworkID before consensus starts.
var (
	attestationNetworkID       uint64 = 0 // 0 = not set; production must configure
	attestationNetworkIDMu     sync.RWMutex
	attestationNetworkIDFrozen bool // audit-fix C-2: prevents mutation after consensus starts
)

// SetAttestationNetworkID sets the network ID used in attestation signing.
// audit-fix C-2: replaced sync.Once with freezable mutex. Can be reconfigured
// during startup, but once frozen it becomes immutable.
func SetAttestationNetworkID(id uint64) {
	attestationNetworkIDMu.Lock()
	defer attestationNetworkIDMu.Unlock()
	if attestationNetworkIDFrozen {
		return
	}
	attestationNetworkID = id
}

// FreezeAttestationNetworkID prevents further changes to attestation network ID.
func FreezeAttestationNetworkID() {
	attestationNetworkIDMu.Lock()
	defer attestationNetworkIDMu.Unlock()
	attestationNetworkIDFrozen = true
}

// ResetAttestationNetworkIDForTesting resets network ID state for unit tests.
// MUST NOT be called in production code.
// audit-fix M-1: panics if EnableTestHelpers() was not called first.
//
// R8-OBS-4 (2026-07-18): See ResetGenesisTimeForTesting for the rationale
// on why this panic is intentionally retained (test-only mutator with no
// return value; panic is the correct Go pattern for context-violation
// guards; EnableTestHelpers() is only called from _test.go files).
func ResetAttestationNetworkIDForTesting() {
	if !testHelpersEnabled {
		panic("consensus: ResetAttestationNetworkIDForTesting called without EnableTestHelpers(); this function is for tests only")
	}
	attestationNetworkIDMu.Lock()
	defer attestationNetworkIDMu.Unlock()
	attestationNetworkID = 0
	attestationNetworkIDFrozen = false
}

// GetAttestationNetworkID returns the configured attestation network ID.
func GetAttestationNetworkID() uint64 {
	attestationNetworkIDMu.RLock()
	defer attestationNetworkIDMu.RUnlock()
	return attestationNetworkID
}

// attestationSigningData creates the data to be signed for an attestation.
// audit-fix H-4: includes network ID to prevent cross-chain replay attacks.
// F1-6 MEDIUM FIX: includes KeyVersion to prevent forged attestations after key rotation.
func (q *QPOS) attestationSigningData(att *Attestation) []byte {
	domainLen := len(AttestationDomainSeparator)
	// F1-6: +8 for KeyVersion (was: domainLen+8+8+...+types.HashLength+8)
	data := make([]byte, domainLen+8+8+8+types.HashLength+8+types.HashLength+8+types.HashLength+8)
	offset := 0

	// Domain separator
	copy(data[offset:], AttestationDomainSeparator)
	offset += domainLen

	// audit-fix H-4: Network ID (prevents testnet attestations replaying on mainnet)
	binary.BigEndian.PutUint64(data[offset:], GetAttestationNetworkID())
	offset += 8

	// Slot
	binary.BigEndian.PutUint64(data[offset:], att.Slot)
	offset += 8

	// F1-6 MEDIUM FIX: KeyVersion (prevents attestations signed with retired keys)
	binary.BigEndian.PutUint64(data[offset:], att.KeyVersion)
	offset += 8

	// BeaconBlockRoot
	copy(data[offset:], att.BeaconBlockRoot[:])
	offset += types.HashLength

	// Source epoch and root
	binary.BigEndian.PutUint64(data[offset:], att.Source.Epoch)
	offset += 8
	copy(data[offset:], att.Source.Root[:])
	offset += types.HashLength

	// Target epoch and root
	binary.BigEndian.PutUint64(data[offset:], att.Target.Epoch)
	offset += 8
	copy(data[offset:], att.Target.Root[:])
	offset += types.HashLength

	// Validator index (audit-fix M-5: uint64 to prevent truncation)
	if att.ValidatorIndex < 0 {
		binary.BigEndian.PutUint64(data[offset:], 0)
	} else {
		binary.BigEndian.PutUint64(data[offset:], uint64(att.ValidatorIndex))
	}

	return data
}

// PruneOldAttestations removes attestations older than the given slot
func (q *QPOS) PruneOldAttestations(keepAboveSlot uint64) int {
	q.mu.Lock()
	defer q.mu.Unlock()

	pruned := 0

	// Prune from attestations pool
	for slot := range q.attestations {
		if slot < keepAboveSlot {
			pruned += len(q.attestations[slot])
			delete(q.attestations, slot)
		}
	}

	// Prune from validator attestations tracking (for slashing detection)
	// Keep extra epochs of data to ensure double-vote/surround-vote detection
	// is not undermined by premature pruning.
	// CONS-FIX: Casper FFG surround votes can span FinalityDelay (2)
	// epochs or more (source.epoch < target.epoch with surrounding relation).
	// Previously only 1 epoch was retained, so a surround vote whose source
	// was already pruned could not be detected. Retain FinalityDelay+1 (=3)
	// epochs as a safety margin so slashing evidence survives long enough
	// for checkSurroundVote to find both ends of the surround.
	slashingKeepEpochs := uint64(FinalityDelay + 1) // 3 epochs by default
	slashingKeepSlot := uint64(0)
	if keepAboveSlot > slashingKeepEpochs*SlotsPerEpoch {
		slashingKeepSlot = keepAboveSlot - slashingKeepEpochs*SlotsPerEpoch
	}
	for validatorIdx := range q.validatorAttestations {
		for slot := range q.validatorAttestations[validatorIdx] {
			if slot < slashingKeepSlot {
				delete(q.validatorAttestations[validatorIdx], slot)
			}
		}
		// audit-fix NEW-19: remove empty inner maps to prevent memory leak
		// proportional to the number of unique validators over chain lifetime.
		if len(q.validatorAttestations[validatorIdx]) == 0 {
			delete(q.validatorAttestations, validatorIdx)
		}
		// MEDIUM FIX: Limit validator index growth to prevent unbounded memory
		// Cap total tracked validators to prevent memory exhaustion from malicious activity
		if len(q.validatorAttestations) > MaxTrackedValidators {
			// CONS- (2026-07-19) FIX: Previously this loop used
			// `for idx := range q.validatorAttestations` which iterates a
			// Go map in NON-DETERMINISTIC order. The comment claimed "Remove
			// oldest entries (lowest indices)" but the code actually deleted
			// arbitrary entries — meaning two nodes running the same input
			// could end up tracking different validator sets, causing
			// consensus divergence on finality accounting.
			//
			// Fix: collect indices into a slice, sort ascending, then delete
			// the lowest `toRemove` indices. This matches the comment's
			// stated intent and makes the pruning deterministic across nodes.
			toRemove := len(q.validatorAttestations) - MaxTrackedValidators
			indices := make([]int, 0, len(q.validatorAttestations))
			for idx := range q.validatorAttestations {
				indices = append(indices, idx)
			}
			sort.Ints(indices)
			for i := 0; i < toRemove && i < len(indices); i++ {
				delete(q.validatorAttestations, indices[i])
			}
		}
	}

	// audit-fix R9-M2: prune aggregated attestations to prevent unbounded memory growth.
	for slot := range q.aggregatedAttestations {
		if slot < keepAboveSlot {
			delete(q.aggregatedAttestations, slot)
		}
	}

	return pruned
}

// GetValidatorSet returns the validator set
// R26-C1 FIX: Return a deep copy to prevent callers from mutating internal state
func (q *QPOS) GetValidatorSet() *ValidatorSet {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.validators.DeepCopy()
}

// updateValidatorSet updates the validator set with consistency checks.
// audit-fix C-3: unexported to prevent bypassing authorization.
// All external callers MUST use UpdateValidatorSetAuthorized.
func (q *QPOS) updateValidatorSet(vs *ValidatorSet) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// L14-009: Validate new validator set size before update.
	// Reject empty validator sets and sets exceeding MaxValidators to prevent
	// consensus failures from empty sets or DoS from oversized sets.
	if vs == nil || vs.Size() == 0 {
		return ErrEmptyValidatorSet
	}
	if vs.Size() > MaxValidators {
		return fmt.Errorf("validator set size %d exceeds maximum %d", vs.Size(), MaxValidators)
	}

	// Verify stake consistency before update
	if vs != nil && q.stakeChecker != nil {
		validators := vs.Validators()
		totalStake := vs.TotalStake()
		if err := q.stakeChecker.VerifyTotalStake(validators, totalStake); err != nil {
			return err
		}
	}

	q.validators = vs
	// Clear shuffle cache when validators change
	q.shuffleCache = make(map[uint64][]int)
	// R102: weighted proposer table follows the shuffle cache lifecycle exactly.
	q.weightedCumCache = make(map[uint64]*weightedEpochTable)
	// R38-P1-10 FIX (2026-08-01): Also clear committeeCache on validator set
	// swap. Cached committees reference Validator pointers + an index ordering
	// derived from the OLD set's size/shuffle seed, so they are invalid after a
	// swap. The committee-cache guard in qpos_committee.go relies on these
	// swaps clearing the cache to prevent stale membership reads.
	q.committeeCache = make(map[uint64][]*Validator)
	return nil
}

// UpdateValidatorSetAuthorized updates the validator set with caller authorization.
// audit-fix C-3: this is the only public entry point for validator set updates.
func (q *QPOS) UpdateValidatorSetAuthorized(vs *ValidatorSet, caller types.Address) error {
	// Check authorization
	if q.authorizedCallers != nil && !q.authorizedCallers.IsAuthorized(caller) && !q.authorizedCallers.IsGovernance(caller) {
		return ErrUnauthorizedOperation
	}

	return q.updateValidatorSet(vs)
}

// AddAuthorizedCaller adds an authorized caller for sensitive operations
func (q *QPOS) AddAuthorizedCaller(addr types.Address) {
	if q.authorizedCallers != nil {
		q.authorizedCallers.AddCaller(addr)
	}
}

// AddStakingValidator adds a new validator to the set from staking.
// This is called internally by the consensus layer when a staking transaction
// is processed, so it bypasses the external authorization check.
//
// R39-P1-03 (2026-08-02) FIX: enforce consensus.MaxValidators at this
// single chokepoint so EVERY entry path — staking-tx sync
// (node.syncStakingFromBlock), genesis/restart rehydration (node.go), the
// RPC adapter (adapters.go), and any future caller — is held to the same
// capacity invariant. R38-P1-09 routed self-registration through
// ValidatorManager.AddValidator (which has its own cap), but the
// staking-tx-driven sync path still came here directly and could push the
// ValidatorSet past MaxValidators in pathological cases (e.g. a malicious
// proposer including many register-stake txs in one block). Fail-closed
// by returning false (caller treats that as "not added") and letting the
// ValidatorManager's pending-queue admission handle any surplus.
//
// Note: Active is still set to true (election.go AddValidator) here because
// this path mirrors "validator already staked + finalized in a block"; the
// pending → active admission flow lives in ValidatorManager (used by
// self-registration). Audit R39-P1-03 explicitly scopes the fix to the
// MaxValidators cap, not to delaying activation.
func (q *QPOS) AddStakingValidator(addr types.Address, stake *big.Int) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.validators == nil {
		return false
	}

	vs := q.validators
	// R39-P1-03 (2026-08-02) FIX: enforce the protocol MaxValidators cap
	// BEFORE mutating the set. Size() includes both active and any
	// inactive-but-present entries (pending validators are stored in the
	// ValidatorManager queue, NOT in the ValidatorSet, so they don't
	// inflate this count). Rejecting here means no caller can push the
	// live consensus ValidatorSet past the 250k protocol ceiling.
	if validatorsCapExceeded(vs.Size()) {
		return false
	}
	// C21-004 FIX: Use ValidatorSet's public API instead of directly accessing
	// internal fields. This ensures proper locking via vs.mu and invariant enforcement.
	added := vs.AddValidator(addr, stake)

	// Clear shuffle cache when validators change
	q.shuffleCache = make(map[uint64][]int)
	// R102: weighted proposer table follows the shuffle cache lifecycle exactly.
	q.weightedCumCache = make(map[uint64]*weightedEpochTable)
	// R38-P1-10 FIX (2026-08-01): Also clear committeeCache when a new
	// validator is staked into the set. AddValidator mutates
	// vs.validators (and totalStake/cumulativeStakes) in place, so any cached
	// committee for a future/current slot reflects an ordering computed BEFORE
	// the new validator was appended, and its index-level membership may now
	// include/stale the wrong validators relative to the new shuffle/size.
	q.committeeCache = make(map[uint64][]*Validator)

	return added
}

// RemoveStakingValidator is the symmetric counterpart of
// AddStakingValidator: it removes an address from the LIVE consensus
// ValidatorSet and invalidates the shuffle / committee caches so the next
// proposer election sees the new set.
//
// R79-UNSTAKE-VSET (2026-08-28): the staking-tx sync path (Node.
// syncStakingFromBlock) used to call AddStakingValidator when a stake tx
// was applied but had NO counterpart for unstake txs. A validator that
// unstaked its whole balance therefore stayed active in the consensus set
// of whichever node had processed the stake, while nodes that had not
// processed it kept a smaller set. Proposer election is a function of the
// set, so the nodes can elect different proposers for the same slot and
// produce competing blocks.
//
// Returns true if the address was present and removed.
func (q *QPOS) RemoveStakingValidator(addr types.Address) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.validators == nil {
		return false
	}

	removed := q.validators.RemoveValidatorByAddr(addr)

	// Always invalidate the caches, even when nothing was removed: a caller
	// that reaches this path is reacting to a validator-set-affecting
	// transaction, and a stale shuffle/committee is worse than recomputing.
	q.shuffleCache = make(map[uint64][]int)
	// R102: weighted proposer table follows the shuffle cache lifecycle exactly.
	q.weightedCumCache = make(map[uint64]*weightedEpochTable)
	q.committeeCache = make(map[uint64][]*Validator)

	return removed
}

// validatorsCapExceeded is the single source of truth for the
// R39-P1-03 MaxValidators invariant. It is a package-level helper (rather
// than inlined) so the regression test can pin the boundary directly
// (TestR39_P1_03_ValidatorsCapExceeded) without having to construct a
// 250k-entry ValidatorSet (which would be the only way to exercise the
// inlined check in AddStakingValidator).
//
// Boundary: the cap is exclusive — when Size() == MaxValidators the set
// is full and the next AddStakingValidator MUST be rejected (no slot for
// the new validator). A Size() strictly less than MaxValidators leaves
// room for exactly one more.
func validatorsCapExceeded(size int) bool {
	return size >= MaxValidators
}

// SetGovernanceAddress sets the governance address for multi-sig operations
func (q *QPOS) SetGovernanceAddress(addr types.Address) {
	if q.authorizedCallers != nil {
		q.authorizedCallers.SetGovernance(addr)
	}
}

// SetSlashingManager sets the slashing manager for submitting Surround Vote evidence
// R17-C1 FIX: This enables the Surround Vote slashing mechanism which was previously
// non-functional due to missing field connection.
//
// P1-2 FIX: Immediately drains the evidence queue that was accumulated while
// slashingManager was nil. Without this, evidence detected during startup
// (before slashingManager was wired) is never submitted, allowing slashable
// offenses to go unpunished.
// audit-remediation: reviewed 2026-09-11 — wiring setter called once by the
// node assembler; not a stake-mutation surface. SubmitEvidence re-validates
// evidence and enforces penalty bounds independently.
func (q *QPOS) SetSlashingManager(sm *SlashingManager) {
	q.mu.Lock()
	q.slashingManager = sm
	// R30-IMPLEMENT (2026-07-27): SLASH-H2 — Propagate JailDuration so both
	// slash paths (QPOS.SlashValidator and SlashingManager.slashLocked)
	// produce the same JailUntil for temporary slashes. Without this,
	// QPOS.SlashValidator would use DefaultJailDuration (1h) while
	// SlashingManager.slashLocked uses the configured JailDuration,
	// causing inconsistent jail expiries for the same offense.
	if sm != nil && sm.params != nil {
		q.jailDuration = sm.params.JailDuration
	}
	queued := q.evidenceQueue
	q.evidenceQueue = make([]*SlashingEvidence, 0)
	q.mu.Unlock()

	if sm != nil && len(queued) > 0 {
		caller := getVotingSystemCaller()
		for _, evidence := range queued {
			// R34-CONS-P0-003 FIX: Pass evidence.Timestamp as blockTime for
			// deterministic slashing. Queued evidence already has Timestamp set
			// from a consensus time source; using it prevents time.Now()
			// fallback which causes jailUntil divergence across nodes.
			var bt int64
			if evidence.Timestamp > 0 {
				bt = evidence.Timestamp
			}
			if _, err := sm.SubmitEvidence(evidence, caller, bt); err != nil {
				qposAdvLogger.Warnf("failed to submit queued evidence to SlashingManager: %v", err)
			}
		}
		qposAdvLogger.Infof("drained %d queued slashing evidence items after SetSlashingManager", len(queued))
	}
}

// SetJailDuration sets the jail duration (seconds) used by QPOS.SlashValidator
// for temporary slashes. This allows external configuration to align
// QPOS.SlashValidator's jail expiry with SlashingManager's without needing
// to construct a full SlashingManager.
//
// R30-IMPLEMENT (2026-07-27): SLASH-H2 fix. SetSlashingManager propagates
// JailDuration automatically, but standalone QPOS instances (tests, devnet
// without SlashingManager) need a way to configure JailDuration directly.
// 0 means "use DefaultJailDuration" (backward-compatible).
func (q *QPOS) SetJailDuration(duration int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.jailDuration = duration
}

// SetBlacklistCheck sets a callback that CanPropose/CanAttest/CanSeal use to
// reject blacklisted validators. Called by MinistryRegistry during init.
//
// P0-T5 (2026-07-14): The callback signature now includes an optional
// blockTime parameter for deterministic expiry checks.
// P1-T5 (2026-07-14): Also propagates the callback to VotingManager so that
// AddVote rejects votes from blacklisted validators.
func (q *QPOS) SetBlacklistCheck(fn func(int, ...int64) bool) {
	q.mu.Lock()
	q.blacklistCheck = fn
	vm := q.votingManager
	q.mu.Unlock()
	// P1-T5: Propagate to VotingManager if already set via SetVotingManager.
	if vm != nil {
		vm.SetBlacklistCheck(fn)
	}
}

// drainEvidenceQueueLoop is a background goroutine that periodically drains
// the evidence queue and submits pending evidence to the slashing manager.
// P1-2 FIX: Without this, evidence queued when slashingManager was nil (during
// startup) or evidence redundantly queued alongside synchronous submission
// (checkDoubleVote/checkSurroundVote) is never consumed, causing slashable
// offenses to go unpunished and a minor memory leak (bounded by MaxEvidenceQueue).
// AUDIT (2026) CONS-FIX: Reduced interval from 30s to 10s so that
// evidence in a high-frequency equivocation attack is submitted faster,
// limiting the window during which a malicious validator can keep voting.
func (q *QPOS) drainEvidenceQueueLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			// R7-P3 FIX: wrap the ticker body in a closure with recover so a
			// panic during evidence draining does not kill this long-running
			// background goroutine. The loop continues on the next tick.
			func() {
				defer func() {
					if r := recover(); r != nil {
						qposAdvLogger.Errorf("panic in drainEvidenceQueueLoop: %v", r)
					}
				}()
				q.mu.RLock()
				sm := q.slashingManager
				q.mu.RUnlock()
				if sm == nil {
					return
				}
				queued := q.GetQueuedEvidence()
				if len(queued) == 0 {
					return
				}
				caller := getVotingSystemCaller()
				submitted := 0
				for _, evidence := range queued {
					// R34-CONS-P0-003 FIX: Pass deterministic blockTime for
					// SubmitEvidence. Prefer q.GetLastKnownBlockTime() (consensus-
					// derived), fall back to evidence.Timestamp. Prevents
					// non-deterministic jailUntil divergence across nodes.
					var bt int64
					bt = q.GetLastKnownBlockTime()
					if bt == 0 && evidence.Timestamp > 0 {
						bt = evidence.Timestamp
					}
					if _, err := sm.SubmitEvidence(evidence, caller, bt); err != nil {
						qposAdvLogger.Warnf("background drainer: failed to submit evidence: %v", err)
					} else {
						submitted++
					}
				}
				if submitted > 0 {
					qposAdvLogger.Infof("background drainer: submitted %d queued evidence items", submitted)
				}
			}()
		}
	}
}

// Stop signals background goroutines (e.g., evidence queue drainer) to stop.
// This should be called when the QPOS instance is no longer needed.
//
// CONS-FIX: also stop the SlashingManager's background sync loop so
// we don't leak the goroutine spawned in SlashingManager.SetQPOS(). Stopping
// SlashingManager before its drainer is safe because SlashingManager.Stop()
// only closes a channel; the drainer goroutine will pick up the close on its
// next select iteration.
func (q *QPOS) Stop() {
	select {
	case <-q.stopCh:
		// Already closed
	default:
		close(q.stopCh)
	}
	// Stop the SlashingManager's background sync loop, if any. The sm field
	// is read here without holding q.mu because Stop() must be callable from
	// Node.Shutdown and we don't want to risk deadlock against an in-flight
	// ProcessAttestation. A torn read here is benign: the worst case is
	// calling Stop() on a stale (previous) sm pointer, which is itself
	// idempotent and harmless.
	if sm := q.slashingManager; sm != nil {
		sm.Stop()
	}
}

// SetVotingManager sets the VotingManager for vote-level tracking synchronization.
// DATA FLOW: When ProcessAttestation accepts an attestation, it converts it to a Vote
// and forwards to VotingManager, ensuring voteSets and DoubleSignDetector.voteHistory
// stay in sync with QPOS.validatorAttestations.
// P1-T5 (2026-07-14): Also propagates the existing blacklistCheck to the new VM.
func (q *QPOS) SetVotingManager(vm *VotingManager) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.votingManager = vm
	// P1-T5: Propagate existing blacklist check if already set.
	if vm != nil && q.blacklistCheck != nil {
		vm.SetBlacklistCheck(q.blacklistCheck)
	}
}

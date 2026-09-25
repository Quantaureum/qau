// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/quantaureum/qau/types"
)

// tryUpdateFinality attempts to justify the previous epoch and finalize the one before it.
//
// LOCK CONTRACT: Caller MUST hold q.mu write lock. This function reads/writes
// q.justifiedEpoch, q.finalizedEpoch, q.attestations, and calls
// getEpochBlockRootLocked() which requires the lock to be held.
// The sole production caller ProcessAttestation() holds q.mu via defer.
// Fix 2: tryUpdateFinality is now called every 8 attestations (not every
// attestation) to reduce O(N×32) big.Int operations on the hot path.
// audit-remediation: reviewed 2026-09-11 — finality bookkeeping; does not touch stake.
func (q *QPOS) tryUpdateFinality() {
	// AUDIT-FULL CS-02 (2026-08-14): Derive the epoch from the latest known
	// BLOCK timestamp instead of the wall clock. GetCurrentEpoch() is backed
	// by time.Now(), so a node with skewed local clock could evaluate finality
	// against the wrong epoch boundary and diverge from honest peers. The
	// block timestamp is consensus data (all nodes agree on the chain head),
	// making the decision deterministic. The wall-clock epoch is kept ONLY as
	// a cold-start fallback when no block has been processed yet
	// (GetLastKnownBlockTime() == 0), matching the CONS-P0-02 pattern already
	// used by SlashValidator / JailUntil (qpos_slashing.go).
	gt := GetGenesisTime()
	blockDerived := q.GetLastKnownBlockTime()
	currentEpoch := uint64(0)
	if gt > 0 && blockDerived > gt {
		slot := uint64((blockDerived - gt) / int64(SlotDuration.Seconds())) // #nosec G115 -- safe: positive delta / 12s fits in uint64
		currentEpoch = slot / SlotsPerEpoch
	} else {
		currentEpoch = q.GetCurrentEpoch() // cold start: no block processed yet
	}
	if currentEpoch < 2 {
		return
	}

	// R42-CS-002 FIX: Guard against nil validators during node initialization.
	if q.validators == nil {
		return
	}

	prevEpoch := currentEpoch - 1
	prevEpochStartSlot := EpochStartSlot(prevEpoch)
	prevEpochEndSlot := prevEpochStartSlot + SlotsPerEpoch - 1

	totalWeight := big.NewInt(0)
	attestedWeight := big.NewInt(0)

	// CONS- (2026-07-19) FIX (redundant check): Previously this
	// function iterated `validators` TWICE with identical slashing + active
	// checks — once here to compute `totalWeight` and again at the bottom
	// to compute `activeValidatorCount`. Both loops consulted
	// `q.slashedValidators[i]` and `v.Active` for the same (i, v) pairs.
	// We now compute `activeValidatorCount` in the SAME loop as
	// `totalWeight`, eliminating the redundant second pass while keeping
	// the accounting identical.
	validators := q.validators.Validators()
	activeValidatorCount := 0
	for i, v := range validators {
		if _, slashed := q.slashedValidators[i]; slashed {
			continue
		}
		// audit-fix round 2 MEDIUM-2: Match calculateTotalStake semantics —
		// inactive validators must not contribute to finality totalWeight.
		if !v.Active {
			continue
		}
		// Effective-balance regime (gated on the weighted-proposer cutover):
		// finality weight uses the capped effective balance so a single large
		// validator cannot dominate finality beyond MaxEffectiveBalance.
		// prevEpoch is the epoch whose attestations are being finalized.
		totalWeight.Add(totalWeight, q.consensusWeight(v.Stake, prevEpoch))
		activeValidatorCount++
	}

	if totalWeight.Sign() <= 0 {
		return
	}

	attestedValidators := make(map[int]bool)
	// AUDIT (2026) CORE-03: Track the canonical epoch root so we can
	// reject attestations that target a conflicting root. Without this, two
	// conflicting forks could both accumulate enough attestations to reach
	// finality (accountable safety failure).
	canonicalEpochRoot := q.getEpochBlockRootLocked(prevEpoch)

	for slot := prevEpochStartSlot; slot <= prevEpochEndSlot; slot++ {
		// AUDIT (2026) R2-HIGH-01 (CORE-): Use the per-slot canonical
		// block root for the Target.Root check, not the epoch boundary root.
		// CreateAttestation sets Target.Root = blockRoot (the per-slot head),
		// so comparing against the epoch boundary root would reject all
		// non-boundary slots' attestations — permanently stalling finality
		// after the first epoch boundary is recorded.
		canonicalSlotRoot, slotRootKnown := q.slotBlockRoots[slot]

		for _, att := range q.attestations[slot] {
			// audit-fix LOW: only count attestations targeting the previous
			// epoch. Attestations stored in a slot range may carry a stale
			// Target.Epoch (e.g. from a prior epoch); without this check an
			// attacker could reuse old attestations to inflate finality weight.
			if att.Target.Epoch != prevEpoch {
				continue
			}
			// AUDIT (2026) CORE B-3 FIX: Validate Source→Target chain.
			// In Casper FFG, Source must be an already-justified checkpoint
			// that is an ancestor of Target. Without this check, an attacker
			// could craft attestations with arbitrary Source checkpoints to
			// inflate finality weight on a conflicting fork.
			if att.Source.Epoch >= att.Target.Epoch {
				// Source must precede Target (strict ancestor).
				continue
			}
			if att.Source.Epoch > q.justifiedEpoch {
				// Source must be an already-justified checkpoint. If the
				// attester claims a Source epoch we haven't justified yet,
				// the attestation is invalid.
				continue
			}
			// CONS-003 (R8 2026-07-19 FIX): Bind att.Source.Root to the
			// canonical justified root. The previous check only validated
			// that att.Source.Epoch <= q.justifiedEpoch (the epoch NUMBER),
			// but did NOT verify that att.Source.Root matches the canonical
			// root recorded for that epoch. This violates Casper FFG
			// accountable safety: an attacker could craft an attestation
			// with Source.Epoch = a justified epoch, but Source.Root = a
			// non-canonical root. Such an attestation would pass the
			// epoch-number check and contribute weight toward justifying a
			// Target that descends from a conflicting fork — enabling two
			// conflicting checkpoints to both reach 2/3 supermajority
			// (accountable safety failure). Now: for Source.Epoch > 0,
			// require att.Source.Root to match the canonical root from
			// getEpochBlockRootLocked(). Genesis epoch (Source.Epoch == 0)
			// is exempted because the genesis root is fixed at node startup
			// via genesis.json and is not stored in epochBlockRoots; nodes
			// with a different genesis root are on a different chain anyway.
			if att.Source.Epoch > 0 {
				canonicalSourceRoot := q.getEpochBlockRootLocked(att.Source.Epoch)
				if canonicalSourceRoot == (types.Hash{}) {
					// Canonical root for Source.Epoch is not recorded. This
					// happens during bootstrap or if SetEpochBlockRoot was
					// never called for this epoch. Fail-closed: skip the
					// attestation rather than risk counting weight toward an
					// unverified Source.Root.
					continue
				}
				if att.Source.Root != canonicalSourceRoot {
					// Source.Root is NOT the canonical root for the claimed
					// Source.Epoch. This is either an attacker trying to
					// inflate finality on a conflicting fork, or a stale /
					// misconfigured attestation. Either way, skip it.
					continue
				}
			}
			// R105-FINALITY-TARGET-BINDING (2026-08-31) FIX: since R42-P4,
			// CreateAttestation votes with Target.Root = the epoch BOUNDARY
			// root (identical for every slot in the epoch), not the per-slot
			// block root. Comparing Target.Root against the per-slot
			// canonical root therefore mismatched every vote except one
			// created exactly at the epoch-boundary slot, which live
			// producers usually never emit because the boundary block has not
			// been imported when that slot's attestation would be created. On
			// a fully synced healthy chain the counted stake can drop to zero
			// and justification can freeze.
			//
			// Correct binding: Target.Root must equal the canonical boundary
			// root of prevEpoch (canonicalEpochRoot, loaded above). The
			// per-slot canonical root — when known — pins BeaconBlockRoot
			// instead, so fork votes are still discarded and the
			// fork-detection property of R2-HIGH-01 is preserved.
			if canonicalEpochRoot == (types.Hash{}) {
				// No canonical boundary root recorded for this epoch —
				// cannot verify the vote, so skip the attestation.
				continue
			}
			if att.Target.Root != canonicalEpochRoot {
				continue
			}
			if slotRootKnown {
				if canonicalSlotRoot == (types.Hash{}) {
					continue // bootstrap placeholder — skip
				}
				if att.BeaconBlockRoot != canonicalSlotRoot {
					continue
				}
			}
			if _, slashed := q.slashedValidators[att.ValidatorIndex]; slashed {
				continue
			}
			// AUDIT (2026) CORE-02: Also skip inactive validators in the
			// numerator. Previously totalWeight (denominator) excluded inactive
			// validators but attestedWeight (numerator) did not — an inactive
			// validator who still attested would be counted in the numerator
			// but not the denominator, inflating the finality ratio.
			if att.ValidatorIndex >= len(validators) {
				continue
			}
			if !validators[att.ValidatorIndex].Active {
				continue
			}
			if !attestedValidators[att.ValidatorIndex] {
				attestedValidators[att.ValidatorIndex] = true
				// Mirror totalWeight: attested weight must use the same
				// effective-balance measure so the ratio stays consistent.
				attestedWeight.Add(attestedWeight, q.consensusWeight(validators[att.ValidatorIndex].Stake, prevEpoch))
			}
		}
	}

	// L11-003/L10-005 FIX (P0): Use dynamic threshold based on validator count.
	//
	// CONS- (2026-07-19) FIX: Previously the count-based threshold
	// used `len(validators)` (ALL validators, including inactive) while
	// the weight-based threshold used `totalWeight` (ONLY active
	// validators' stake). When a large fraction of validators is
	// inactive, the two thresholds disagree: the count threshold
	// requires ceil(N_total/2) distinct attesters but the weight
	// threshold only requires 2/3 of active stake. With 10 validators
	// where 5 are inactive, the count threshold demands 5 distinct
	// attesters, but only 5 active validators exist — so all active
	// validators must attest. This is stricter than the weight
	// threshold and breaks liveness: if even one active validator is
	// offline, finality stalls even though the chain has 2/3 of ACTIVE
	// stake attesting.
	//
	// Fix: compute the count threshold against the SAME base as the
	// weight threshold — active validators only. This keeps the count
	// threshold a fast pre-check (avoiding the expensive big.Int
	// comparison when participation is obviously too low) while
	// aligning with the weight-based finality decision.
	//
	// CONS- (2026-07-19) FIX: `activeValidatorCount` is now
	// computed in the same loop as `totalWeight` above (no longer a
	// separate redundant pass).
	if activeValidatorCount == 0 {
		return
	}
	if len(attestedValidators) < ComputeMinAttestations(activeValidatorCount) {
		return
	}

	threshold := new(big.Int).Mul(totalWeight, big.NewInt(2))
	attested := new(big.Int).Mul(attestedWeight, big.NewInt(3))

	if attested.Cmp(threshold) >= 0 {
		oldJustified := q.justifiedEpoch
		if prevEpoch > q.justifiedEpoch {
			q.justifiedEpoch = prevEpoch
			q.justifiedRoot = q.getEpochBlockRootLocked(prevEpoch)
			q.finalityPersistPending = true
		}
		// CONS-R9-L-REDO-01 (2026-07-19) FIX: Previously the guard was
		// `oldJustified > 0`, which permanently excluded the genesis epoch
		// (epoch 0) from being finalized — genesis stayed at
		// finalizedEpoch=0 but with finalizedRoot=zero-hash instead of the
		// real genesis root. As a result, the first finalizedRoot recorded
		// was the root of epoch 1's first block, and any consumer that
		// walks `finalizedRoot` to verify ancestry against genesis had to
		// special-case the genesis root itself.
		//
		// Now: allow oldJustified==0 (genesis) to be finalized too, but
		// ONLY if a non-zero genesis root has been registered via
		// SetGenesisRoot (or equivalently SetEpochBlockRoot(0, ...)). If
		// no genesis root was registered, the old behavior is preserved
		// (genesis cannot be finalized) so nodes that don't bootstrap the
		// genesis root are not exposed to a zero-root finalization.
		//
		// NOTE on the second branch: the initial state of QPOS is
		// finalizedEpoch=0 with finalizedRoot=zero-hash. When epoch 1 first
		// reaches 2/3 supermajority, oldJustified (the previously
		// justified epoch) is 0 and prevEpoch is 1, so
		// oldJustified == prevEpoch-1 == finalizedEpoch == 0. The strict
		// `>` comparison would skip the update, leaving finalizedRoot
		// permanently zero. The `==` branch below patches exactly this
		// bootstrap case: when oldJustified equals finalizedEpoch AND
		// finalizedRoot is still the zero hash, replace the zero hash with
		// the real genesis root. This branch is only reachable once
		// (after the first finalization, finalizedRoot becomes non-zero),
		// so it does not weaken the monotonic progression of finalizedEpoch.
		oldJustifiedRoot := q.getEpochBlockRootLocked(oldJustified)
		if oldJustifiedRoot != (types.Hash{}) && oldJustified == prevEpoch-1 {
			if oldJustified > q.finalizedEpoch {
				q.finalizedEpoch = oldJustified
				q.finalizedRoot = oldJustifiedRoot
				q.finalityPersistPending = true
			} else if oldJustified == q.finalizedEpoch && q.finalizedRoot == (types.Hash{}) {
				q.finalizedRoot = oldJustifiedRoot
				q.finalityPersistPending = true
			}
		}
		if q.votingManager != nil {
			q.votingManager.syncFinalityFromQPOS(q.justifiedEpoch, q.finalizedEpoch, q.justifiedRoot, q.finalizedRoot)
		}
		q.persistFinalityLocked()
	}
}

// SetGenesisRoot registers the genesis block root so that the genesis epoch
// (epoch 0) can be finalized once enough attestations accumulate for epoch 1.
//
// CONS-R9-L-REDO-01 (2026-07-19) FIX: Without this registration, the
// `oldJustified > 0` guard in tryUpdateFinality made genesis permanently
// unfinalizable (finalizedEpoch stayed at 0 with finalizedRoot=zero-hash),
// delaying the first *real* finalization by one epoch and forcing
// downstream consumers (slashing evidence retention, state pruning,
// sync committee rotation) to special-case the genesis root.
//
// This method MUST be called once at node startup, before the first
// ProcessAttestation, with the genesis block's hash read from genesis.json.
// Calling it again with a different root is a no-op (epoch 0 root is
// immutable once set) so a misconfigured restart cannot retroactively
// rewrite finalizedRoot for epoch 0.
func (q *QPOS) SetGenesisRoot(root types.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if existing, ok := q.epochBlockRoots[0]; ok && existing != (types.Hash{}) {
		// Genesis root already registered. Reject any attempt to overwrite
		// it with a different root — that would indicate a chain-restart
		// mismatch. A re-register with the SAME root is allowed (idempotent).
		if existing != root {
			log.Printf("[WARN] QPOS: SetGenesisRoot called with a different root "+
				"than the one already registered; ignoring (existing=%x, new=%x)",
				existing, root)
		}
		return
	}
	q.epochBlockRoots[0] = root
	// Also register slot 0 so that the per-slot canonical root lookup
	// (used by attestation Target.Root validation) succeeds for the
	// genesis slot. Without this, attestations targeting slot 0 would
	// be rejected as "no canonical slot root known".
	q.slotBlockRoots[0] = root
}

func (q *QPOS) GetJustifiedEpoch() uint64 {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.justifiedEpoch
}

func (q *QPOS) GetFinalizedEpoch() uint64 {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.finalizedEpoch
}

func (q *QPOS) CheckFinality() (justifiedEpoch, finalizedEpoch uint64, changed bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// FIX: Previously, CheckFinality duplicated the finality logic
	// from tryUpdateFinality (same threshold check, same epoch update) but
	// used different calculation helpers (calculateParticipatingStake vs
	// manual iteration), leading to subtle inconsistencies. Now CheckFinality
	// delegates to tryUpdateFinality, which is the single source of truth.
	oldJustified := q.justifiedEpoch
	oldFinalized := q.finalizedEpoch

	q.tryUpdateFinality()

	changed = q.justifiedEpoch != oldJustified || q.finalizedEpoch != oldFinalized

	if q.votingManager != nil && changed {
		q.votingManager.syncFinalityFromQPOS(q.justifiedEpoch, q.finalizedEpoch, q.justifiedRoot, q.finalizedRoot)
	}

	return q.justifiedEpoch, q.finalizedEpoch, changed
}

// AdoptHeaderFinality adopts the justified/finalized checkpoint epochs carried
// in a canonical block header into the local QPOS finality state.
//
// R106-FINALITY-SYNC (2026-09-02) FIX: finality state (justifiedEpoch,
// finalizedEpoch, attestations) lives ONLY in memory. A node that restarts —
// or a non-sealer RPC node that joins late — starts with justifiedEpoch=0 /
// finalizedEpoch=0 and can never re-derive them from gossip alone:
//
//   - tryUpdateFinality requires att.Source.Epoch <= local justifiedEpoch, so
//     every live attestation (whose Source is the network's CURRENT justified
//     epoch) is rejected on the restarted node → attestedWeight stays 0 → the
//     local checkpoint ratchet never re-engages (egg-and-chicken deadlock).
//   - ErrSlotInPast drops attestations older than one epoch, so history is
//     never replayable via gossip.
//   - Sealers escape the deadlock only because they re-attest from scratch
//     (CreateAttestation stamps Source = the LOCAL justifiedEpoch, and after
//     a coordinated restart enough low-Source votes accumulate to restart
//     the ratchet); non-sealers (validatorEnabled=false — e.g. the public RPC
//     node) never recover and can report finalizedEpoch=0 forever while the
//     chain itself is finalizing normally.
//
// The header is consensus data: the proposer stamped it from the same
// tryUpdateFinality ratchet after aggregating live attestations, and every
// honest validator's blockValidator accepted the block. This mirrors the
// R54-ACC pattern already used for the per-epoch VRF accumulator
// (SetEpochVRFAccumulator reads Header.VRFAccumulator on every import):
// local state converges from the on-chain value without any out-of-band
// channel.
//
// Safety properties:
//   - Monotonic: adopts an epoch only when it is STRICTLY newer than the
//     local value, so a malicious header cannot roll finality back (same
//     guard as ForkChoice.UpdateJustified / UpdateFinalized).
//   - The adopted value is an upper bound of what honest attesters reached;
//     it can only move a lagging node forward, never past what the network
//     itself justified.
//   - Roots: prefer the canonical epoch boundary root recorded locally
//     (authoritative; restored across restarts by the R101 backfill). Fall
//     back to the header block's own hash only while the boundary root is
//     unknown — the root feeds ancestry bookkeeping and RPC display only,
//     never weight accounting, so a fallback root cannot inflate
//     attestedWeight (that path counts attestations exclusively).
//
// After adoption the local ratchet re-engages on its own: attestations whose
// Source is <= the adopted epoch pass the CONS-003 gate, and R101's recent
// epoch roots satisfy the Source.Root binding, so tryUpdateFinality resumes
// from the adopted value on the next epoch boundary.
//
// LOCK CONTRACT: takes q.mu internally; safe to call from any import path.
func (q *QPOS) AdoptHeaderFinality(justifiedEpoch, finalizedEpoch uint64, headerHash types.Hash) {
	q.mu.Lock()
	adopted := false
	if justifiedEpoch > q.justifiedEpoch {
		q.justifiedEpoch = justifiedEpoch
		q.justifiedRoot = adoptCheckpointRoot(q.getEpochBlockRootLocked(justifiedEpoch), justifiedEpoch, headerHash)
		adopted = true
	}
	if finalizedEpoch > q.finalizedEpoch {
		q.finalizedEpoch = finalizedEpoch
		q.finalizedRoot = adoptCheckpointRoot(q.getEpochBlockRootLocked(finalizedEpoch), finalizedEpoch, headerHash)
		adopted = true
	}
	// Copy fields out while still holding q.mu, then notify the
	// VotingManager outside the lock (mirrors tryUpdateFinality's
	// syncFinalityFromQPOS handoff, which runs after q.mu is released by
	// ProcessAttestation's defer).
	justified, finalized := q.justifiedEpoch, q.finalizedEpoch
	jRoot, fRoot := q.justifiedRoot, q.finalizedRoot
	if adopted {
		q.finalityPersistPending = true
		q.persistFinalityLocked()
	}
	q.mu.Unlock()

	if adopted && q.votingManager != nil {
		q.votingManager.syncFinalityFromQPOS(justified, finalized, jRoot, fRoot)
	}
}

// adoptCheckpointRoot picks the root recorded for an adopted checkpoint
// epoch. The locally recorded epoch boundary root is authoritative; the
// header hash is a fallback marker for epochs whose boundary root has not
// been recorded yet (e.g. a long catch-up sync before the R101 backfill
// window covers them). Epoch 0 keeps the zero hash when unregistered so the
// genesis bootstrap branches in tryUpdateFinality stay reachable.
func adoptCheckpointRoot(recorded types.Hash, epoch uint64, headerHash types.Hash) types.Hash {
	if recorded != (types.Hash{}) {
		return recorded
	}
	if epoch == 0 {
		return types.Hash{}
	}
	return headerHash
}

// SetFinalityPersistCallback registers the R107-FINALITY-PERSIST hook. The
// callback is invoked synchronously while q.mu is held so disk state cannot
// lag behind a committed finality transition. Passing nil disables persistence.
func (q *QPOS) SetFinalityPersistCallback(
	callback func(justifiedEpoch, finalizedEpoch uint64, justifiedRoot, finalizedRoot types.Hash) error,
) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.finalityPersist = callback
	if q.finalityPersist != nil {
		if !q.hasCanonicalFinalityRootsLocked() {
			q.finalityPersistPending = true
		}
		q.persistFinalityLocked()
	}
}

// RestoreFinalityState restores a checkpoint captured by the durable callback
// and registers both roots in epochBlockRoots. Registration is the critical
// recovery step: without it, source attestations for the restored justified
// epoch are rejected by the canonical-root binding check after restart.
func (q *QPOS) RestoreFinalityState(
	justifiedEpoch uint64,
	finalizedEpoch uint64,
	justifiedRoot types.Hash,
	finalizedRoot types.Hash,
) error {
	if finalizedEpoch > justifiedEpoch {
		return fmt.Errorf("restore finality state: finalized epoch %d exceeds justified epoch %d", finalizedEpoch, justifiedEpoch)
	}
	if finalizedEpoch == justifiedEpoch && justifiedEpoch > 0 && justifiedRoot != finalizedRoot {
		return errors.New("restore finality state: equal checkpoints have different roots")
	}
	if justifiedEpoch > 0 && justifiedRoot == (types.Hash{}) {
		return errors.New("restore finality state: justified root is zero")
	}
	if finalizedEpoch > 0 && finalizedRoot == (types.Hash{}) {
		return errors.New("restore finality state: finalized root is zero")
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if justifiedEpoch < q.justifiedEpoch || finalizedEpoch < q.finalizedEpoch {
		return errors.New("restore finality state: checkpoint is older than local state")
	}
	if q.justifiedEpoch > 0 && justifiedEpoch == q.justifiedEpoch && justifiedRoot != q.justifiedRoot {
		return errors.New("restore finality state: conflicting justified root")
	}
	if q.finalizedEpoch > 0 && finalizedEpoch == q.finalizedEpoch && finalizedRoot != q.finalizedRoot {
		return errors.New("restore finality state: conflicting finalized root")
	}
	justifiedGenesisRoot, err := q.restoredGenesisRoot(justifiedEpoch, justifiedRoot)
	if err != nil {
		return err
	}
	finalizedGenesisRoot, err := q.restoredGenesisRoot(finalizedEpoch, finalizedRoot)
	if err != nil {
		return err
	}
	if justifiedEpoch == 0 && finalizedEpoch == 0 && justifiedRoot != (types.Hash{}) &&
		finalizedRoot != (types.Hash{}) && justifiedRoot != finalizedRoot {
		return errors.New("restore finality state: conflicting epoch-zero roots")
	}

	q.justifiedEpoch = justifiedEpoch
	q.justifiedRoot = justifiedRoot
	q.finalizedEpoch = finalizedEpoch
	q.finalizedRoot = finalizedRoot
	q.registerRestoredCheckpointRootsLocked()
	if justifiedGenesisRoot != (types.Hash{}) {
		q.epochBlockRoots[0] = justifiedGenesisRoot
		q.slotBlockRoots[0] = justifiedGenesisRoot
	}
	if finalizedGenesisRoot != (types.Hash{}) {
		if existing, exists := q.epochBlockRoots[0]; !exists || existing == (types.Hash{}) {
			q.epochBlockRoots[0] = finalizedGenesisRoot
			q.slotBlockRoots[0] = finalizedGenesisRoot
		}
	}
	return nil
}

func (q *QPOS) restoredGenesisRoot(epoch uint64, root types.Hash) (types.Hash, error) {
	if epoch != 0 || root == (types.Hash{}) {
		return types.Hash{}, nil
	}
	genesisRoot, exists := q.epochBlockRoots[0]
	if exists && genesisRoot != (types.Hash{}) && genesisRoot != root {
		return types.Hash{}, errors.New("restore finality state: conflicting genesis root")
	}
	return root, nil
}

func (q *QPOS) registerRestoredCheckpointRootsLocked() {
	if q.epochBlockRoots == nil {
		q.epochBlockRoots = make(map[uint64]types.Hash)
	}
	if q.justifiedEpoch > 0 && q.justifiedRoot != (types.Hash{}) {
		q.epochBlockRoots[q.justifiedEpoch] = q.justifiedRoot
	}
	if q.finalizedEpoch > 0 && q.finalizedRoot != (types.Hash{}) {
		q.epochBlockRoots[q.finalizedEpoch] = q.finalizedRoot
	}
	if q.hasCanonicalFinalityRootsLocked() {
		q.finalityPersistPending = false
	}
}

// persistFinalityLocked snapshots the current checkpoint and invokes the
// storage callback. Caller MUST hold q.mu. Non-genesis checkpoint roots must
// already match epochBlockRoots; a header-hash fallback is never durable.
// A failed durable write leaves finalityPersistPending set so a later
// canonical-root update or backfill can retry it.
func (q *QPOS) persistFinalityLocked() {
	if q.finalityPersist == nil {
		return
	}
	if !q.hasCanonicalFinalityRootsLocked() {
		q.finalityPersistPending = true
		return
	}
	if !q.finalityPersistPending {
		return
	}
	if err := q.finalityPersist(
		q.justifiedEpoch,
		q.finalizedEpoch,
		q.justifiedRoot,
		q.finalizedRoot,
	); err != nil {
		// Keep the checkpoint pending so a later canonical-root update or
		// backfill retries the durable write.
		q.finalityPersistPending = true
		log.Printf("[ERROR] QPOS: failed to persist finality checkpoint: %v", err)
		return
	}
	q.finalityPersistPending = false
}

func (q *QPOS) hasCanonicalFinalityRootsLocked() bool {
	checkpoints := [...]struct {
		epoch uint64
		root  types.Hash
	}{
		{epoch: q.justifiedEpoch, root: q.justifiedRoot},
		{epoch: q.finalizedEpoch, root: q.finalizedRoot},
	}
	for _, checkpoint := range checkpoints {
		if checkpoint.epoch == 0 {
			continue
		}
		canonicalRoot, exists := q.epochBlockRoots[checkpoint.epoch]
		if !exists || canonicalRoot == (types.Hash{}) || canonicalRoot != checkpoint.root {
			return false
		}
	}
	return true
}

func (q *QPOS) calculateParticipatingStake(epoch uint64) *big.Int {
	// R42-CS-002 FIX: Guard against nil validators during node initialization.
	if q.validators == nil {
		return big.NewInt(0)
	}
	startSlot := EpochStartSlot(epoch)
	endSlot := startSlot + SlotsPerEpoch - 1

	participated := make(map[int]bool)
	validators := q.validators.Validators()

	for slot := startSlot; slot <= endSlot; slot++ {
		for _, att := range q.attestations[slot] {
			// Skip attestations from slashed validators - they must not count toward consensus
			if _, slashed := q.slashedValidators[att.ValidatorIndex]; slashed {
				continue
			}
			// audit-fix MEDIUM: validate attestation target epoch matches the
			// epoch being evaluated. Without this check, attestations targeting
			// other epochs could inflate participating stake for this epoch's
			// finality calculation.
			if att.Target.Epoch != epoch {
				continue
			}
			participated[att.ValidatorIndex] = true
		}
	}

	stake := big.NewInt(0)
	for idx := range participated {
		if idx < len(validators) && validators[idx].Active {
			stake.Add(stake, q.consensusWeight(validators[idx].Stake, epoch))
		}
	}

	return stake
}

func (q *QPOS) calculateTotalStake() *big.Int {
	// R42-CS-002 FIX: Guard against nil validators during node initialization.
	if q.validators == nil {
		return big.NewInt(0)
	}
	validators := q.validators.Validators()
	total := big.NewInt(0)
	// calculateTotalStake feeds finality participation ratios; use the same
	// effective-balance measure as calculateParticipatingStake so numerator
	// and denominator stay consistent. Derive the epoch from the latest known
	// block time (consensus data), matching tryUpdateFinality's approach.
	ebEpoch := q.currentFinalityEpoch()
	for i, v := range validators {
		if _, slashed := q.slashedValidators[i]; slashed {
			continue
		}
		if v.Active {
			total.Add(total, q.consensusWeight(v.Stake, ebEpoch))
		}
	}
	return total
}

func (q *QPOS) GetFinalityStatus() map[string]any {
	q.mu.RLock()
	defer q.mu.RUnlock()

	currentEpoch := q.GetCurrentEpoch()

	// audit-fix LOW: guard against uint64 underflow when finalizedEpoch has not
	// caught up to currentEpoch (e.g. during initial sync or finality stall).
	var epochsBehind uint64
	if currentEpoch > q.finalizedEpoch {
		epochsBehind = currentEpoch - q.finalizedEpoch
	}

	return map[string]any{
		"currentEpoch":   currentEpoch,
		"justifiedEpoch": q.justifiedEpoch,
		"finalizedEpoch": q.finalizedEpoch,
		"justifiedRoot":  q.justifiedRoot,
		"finalizedRoot":  q.finalizedRoot,
		"epochsBehind":   epochsBehind,
		"isFinalized":    q.finalizedEpoch > 0,
	}
}

// syncFinalityFromVM was a VM-driven finality entrypoint that allowed the
// VotingManager to propagate finality BACK into QPOS. This created a SECOND
// finality path that bypassed the Casper FFG 2/3 supermajority weight check
// enforced in tryUpdateFinality, violating accountable safety: an attacker
// who could call VotingManager.Finalize(canonical_height, canonical_root)
// would mark a canonical block as finalized even without 2/3 attestation
// weight — the canonical-root match did not imply finality had been reached.
//
// CONS- (2026-07-19) FIX: This function and the call from
// VotingManager.Finalize have been removed. The Casper FFG finality path
// (QPOS.ProcessAttestation → tryUpdateFinality → votingManager.syncFinalityFromQPOS)
// is now the SINGLE source of truth for QPOS finality state. The reverse
// direction (VM → QPOS) is no longer permitted.
//
// Existing call sites should rely on the canonical attestation path
// instead. If a finality signal is needed for an external consumer, it
// should read QPOS.GetFinalizedEpoch() / GetFinalizedRoot() directly
// rather than attempting to drive finality from the outside.

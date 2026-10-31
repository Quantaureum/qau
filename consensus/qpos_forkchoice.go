// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"log"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/types"
)

// SetProposerBoost sets the proposer boost for a block.
//
// AUDIT (2026) CORE-08 FIX: This legacy setter does not provide the total
// committee stake, so the correct boost value cannot be computed. It now sets
// proposerBoostWeight to nil (fail-closed: no boost applied). Callers that
// know the total active committee stake should use SetProposerBoostWithWeight.
func (q *QPOS) SetProposerBoost(blockRoot types.Hash, slot uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.proposerBoostRoot = blockRoot
	q.proposerBoostSlot = slot
	q.proposerBoostWeight = nil
}

// SetProposerBoostWithWeight sets the proposer boost using the total active
// committee stake to derive the boost value (40% of that stake).
// AUDIT (2026) CORE-08 FIX: replaces the incorrect 40%-of-own-weight formula.
func (q *QPOS) SetProposerBoostWithWeight(blockRoot types.Hash, slot uint64, totalCommitteeStake *big.Int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.proposerBoostRoot = blockRoot
	q.proposerBoostSlot = slot
	if totalCommitteeStake == nil || totalCommitteeStake.Sign() <= 0 {
		q.proposerBoostWeight = nil
		return
	}
	boost := new(big.Int).Mul(totalCommitteeStake, big.NewInt(ProposerScoreBoost))
	boost.Div(boost, big.NewInt(100))
	q.proposerBoostWeight = boost
}

func (q *QPOS) GetProposerBoost() (types.Hash, uint64) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.proposerBoostRoot, q.proposerBoostSlot
}

// CalculateBlockScore computes the total attestation weight for a block root
// within the current epoch. This is used as a building block for LMD GHOST.
func (q *QPOS) CalculateBlockScore(blockRoot types.Hash, slot uint64) *big.Int {
	q.mu.RLock()
	defer q.mu.RUnlock()

	return q.calculateBlockScoreLocked(blockRoot, slot)
}

func (q *QPOS) calculateBlockScoreLocked(blockRoot types.Hash, slot uint64) *big.Int {
	score := big.NewInt(0)

	epoch := SlotToEpoch(slot)
	startSlot := EpochStartSlot(epoch)
	endSlot := startSlot + SlotsPerEpoch - 1

	validators := q.validators.Validators()

	for s := startSlot; s <= endSlot && s <= slot; s++ {
		for _, att := range q.attestations[s] {
			if att.BeaconBlockRoot == blockRoot {
				if att.ValidatorIndex < len(validators) {
					// audit-fix MEDIUM-2: Exclude slashed validators from block
					// score. A slashed validator's attestation must not count
					// toward fork choice weight.
					if _, slashed := q.slashedValidators[att.ValidatorIndex]; slashed {
						continue
					}
					// FIX: Exclude inactive validators from fork choice
					// weight. tryUpdateFinality already excludes !Active validators;
					// fork choice must be consistent to prevent stale attestations
					// from deactivated (but not slashed) validators inflating score.
					if !validators[att.ValidatorIndex].Active {
						continue
					}
					// Effective-balance regime (gated on the weighted-proposer
					// cutover): fork-choice weight uses the capped effective
					// balance, consistent with finality and proposer election.
					score.Add(score, q.consensusWeight(validators[att.ValidatorIndex].Stake, epoch))
				}
			}
		}
	}

	// AUDIT (2026) CORE-08 FIX: Apply the fixed proposerBoostWeight
	// (40% of total active committee stake) instead of 40% of the block's own
	// score. The old formula amplified already-heavy blocks; the correct
	// semantics is a uniform committee-derived bonus. If the legacy
	// SetProposerBoost was used (no committee context), proposerBoostWeight is
	// nil and no boost is applied (fail-closed).
	if q.proposerBoostRoot == blockRoot && q.proposerBoostSlot == slot && q.proposerBoostWeight != nil {
		score.Add(score, new(big.Int).Set(q.proposerBoostWeight))
	}

	return score
}

// LatestMessage holds the latest attestation message from a validator.
type LatestMessage struct {
	BlockRoot types.Hash
	Slot      uint64
}

// ForkChoiceStore maintains the state needed for LMD GHOST fork choice.
type ForkChoiceStore struct {
	mu             sync.RWMutex
	latestMessages map[int]*LatestMessage
	blockChildren  map[types.Hash][]types.Hash
	// audit-fix LOW: blockParent is a reverse mapping (child -> parent) for
	// O(1) parent lookup in isInSubtree, replacing the previous O(n) linear
	// scan over blockChildren.
	blockParent   map[types.Hash]types.Hash
	blockSlots    map[types.Hash]uint64
	validators    *ValidatorSet
	justifiedRoot types.Hash
	justifiedSlot uint64
	finalizedRoot types.Hash
	// audit-fix MEDIUM-3: slashedValidators tracks validators that have been
	// slashed and must be excluded from subtree weight calculations. ForkChoiceStore
	// does not have direct access to QPOS.slashedValidators, so this map is
	// populated via MarkValidatorSlashed.
	slashedValidators map[int]uint64
}

// NewForkChoiceStore creates a new fork choice store.
func NewForkChoiceStore(validators *ValidatorSet) *ForkChoiceStore {
	return &ForkChoiceStore{
		latestMessages:    make(map[int]*LatestMessage),
		blockChildren:     make(map[types.Hash][]types.Hash),
		blockParent:       make(map[types.Hash]types.Hash),
		blockSlots:        make(map[types.Hash]uint64),
		validators:        validators,
		slashedValidators: make(map[int]uint64),
	}
}

// MarkValidatorSlashed marks a validator as slashed in the fork choice store.
// audit-fix MEDIUM-3: Slashed validators must be excluded from subtree weight
// calculations to prevent them from influencing fork choice. Since
// ForkChoiceStore is decoupled from QPOS, this method allows QPOS to propagate
// slashing events into the fork choice state.
// audit-remediation: reviewed 2026-09-11 — status flag for fork choice; actual penalty goes through SlashingManager.
func (fc *ForkChoiceStore) MarkValidatorSlashed(validatorIndex int, epoch uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.slashedValidators[validatorIndex] = epoch
}

// UpdateLatestMessage updates the latest attestation message from a validator.
// audit-remediation: reviewed 2026-09-11 — attestation bookkeeping; does not touch stake.
func (fc *ForkChoiceStore) UpdateLatestMessage(validatorIndex int, blockRoot types.Hash, slot uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if existing, ok := fc.latestMessages[validatorIndex]; ok {
		if slot > existing.Slot {
			fc.latestMessages[validatorIndex] = &LatestMessage{
				BlockRoot: blockRoot,
				Slot:      slot,
			}
		}
	} else {
		fc.latestMessages[validatorIndex] = &LatestMessage{
			BlockRoot: blockRoot,
			Slot:      slot,
		}
	}
}

// AddBlock adds a block to the fork choice tree.
//
// CONS- (2026-07-19) FIX: Previously this function accepted any
// `slot` value with no validation — not even non-zero, not bounded above,
// and not validated against the parent's slot. Compare with the parallel
// ForkChoice.OnBlock (qpos_advanced.go:849-895) which DOES validate
// `slot > parent.Slot`. Without this check, a malicious or buggy caller
// could insert blocks with stale/equal slots, corrupting the fork choice
// view and enabling equivocation (similar to the issue L20-004 fixed in
// OnBlock).
//
// We now enforce:
//   - slot != 0 (genesis slot is reserved and only set via SetGenesis)
//   - if parent is known: slot > parentSlot (strict child ordering)
//   - if parent is unknown: still accept (block may arrive before parent
//     during sync), but the slot sanity check still applies.
//
// Returns true if the block was added, false if it was rejected.
func (fc *ForkChoiceStore) AddBlock(blockRoot, parentRoot types.Hash, slot uint64) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// CONS- slot sanity check. Reject slot=0 (genesis slot is
	// reserved) and reject obviously bogus values. We use slot > 0 as the
	// lower bound (genesis is added via a separate SetGenesis path).
	if slot == 0 {
		return false
	}

	// If the parent is already known, enforce strict child ordering.
	// If the parent is not yet known (block arriving before parent during
	// sync), we still accept the block so that sync can later reconcile.
	if parentSlot, parentKnown := fc.blockSlots[parentRoot]; parentKnown {
		if slot <= parentSlot {
			return false
		}
	}

	fc.blockChildren[parentRoot] = append(fc.blockChildren[parentRoot], blockRoot)
	// audit-fix LOW: maintain reverse parent mapping for O(1) lookup in
	// isInSubtree, replacing the previous O(n) scan over blockChildren.
	fc.blockParent[blockRoot] = parentRoot
	fc.blockSlots[blockRoot] = slot
	return true
}

// SetJustifiedCheckpoint updates the justified checkpoint.
// audit-fix HIGH: Added rollback protection — reject setting the justified
// checkpoint to a slot older than the current one. Without this check, an
// attacker could roll back the justified checkpoint to an older slot,
// potentially allowing reorgs of justified blocks.
func (fc *ForkChoiceStore) SetJustifiedCheckpoint(root types.Hash, slot uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	// audit-fix HIGH: Only update if the new slot is newer or equal (prevents rollback)
	if slot >= fc.justifiedSlot {
		fc.justifiedRoot = root
		fc.justifiedSlot = slot
	}
}

// SetFinalizedCheckpoint updates the finalized checkpoint.
// audit-fix HIGH: Added rollback protection — reject setting the finalized
// checkpoint to a block with a slot older than the current finalized block.
// Without this check, an attacker could roll back the finalized checkpoint,
// allowing finalized blocks to be reorged (the most severe consensus violation).
func (fc *ForkChoiceStore) SetFinalizedCheckpoint(root types.Hash) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	// FIX: Reject zero hash as a finalized checkpoint. A zero hash
	// indicates uninitialized data and must never be set as finalized, since
	// finalized checkpoints are irreversible. Silently ignoring prevents
	// consensus corruption from buggy or malicious callers.
	if root == (types.Hash{}) {
		return
	}
	// audit-fix HIGH: Look up the slot of the new finalized root and compare
	// with the current finalized root's slot. Only update if the new root's
	// slot is newer (prevents rollback of finalized blocks).
	newSlot, newOk := fc.blockSlots[root]
	currentSlot, currentOk := fc.blockSlots[fc.finalizedRoot]
	if !newOk {
		// New root not in blockSlots — allow only if no current finalized root
		// (initial setup). Otherwise reject to prevent setting unknown roots.
		if fc.finalizedRoot != (types.Hash{}) {
			return
		}
	} else if currentOk && newSlot < currentSlot {
		// New root has an older slot than current — reject (rollback)
		return
	}
	fc.finalizedRoot = root
}

// GetHead computes the head of the chain using the LMD GHOST algorithm.
//
// LMD GHOST (Latest Message Driven Greedy Heaviest-Observed Subtree):
// 1. Start from the justified checkpoint (the root of the fork choice).
// 2. At each node, compute the total attestation weight of each child subtree.
// 3. Select the child with the heaviest subtree weight.
// 4. Repeat until reaching a leaf node.
// 5. The leaf is the head of the chain.
func (fc *ForkChoiceStore) GetHead() types.Hash {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	startRoot := fc.justifiedRoot
	if startRoot == (types.Hash{}) {
		// FIX: When justifiedRoot is zero (e.g. during initial sync
		// before the first justified checkpoint is set), fall back to
		// finalizedRoot instead of returning an empty hash. Returning an
		// empty hash can cause callers to treat the chain head as unknown,
		// leading to skipped slots or stalled sync. The finalized root is the
		// best available anchor in this state.
		startRoot = fc.finalizedRoot
		if startRoot == (types.Hash{}) {
			return types.Hash{}
		}
	}

	return fc.lmdGhost(startRoot)
}

// lmdGhost iteratively selects the heaviest child at each level.
// audit-fix MEDIUM: tie-breaking by hash ensures deterministic selection when
// multiple children have equal subtree weight.
// audit-fix LOW: iterative implementation avoids stack overflow on deep chains.
func (fc *ForkChoiceStore) lmdGhost(root types.Hash) types.Hash {
	current := root
	for {
		children := fc.blockChildren[current]
		if len(children) == 0 {
			return current
		}
		bestChild := children[0]
		bestWeight := fc.subtreeWeight(bestChild)
		for _, child := range children[1:] {
			weight := fc.subtreeWeight(child)
			if weight.Cmp(bestWeight) > 0 ||
				(weight.Cmp(bestWeight) == 0 && bytes.Compare(child[:], bestChild[:]) < 0) {
				bestWeight = weight
				bestChild = child
			}
		}
		current = bestChild
	}
}

// subtreeWeight computes the total attestation weight of a subtree rooted at blockRoot.
// It sums the effective balance of all validators whose latest attestation target
// is within the subtree rooted at blockRoot.
//
//	CONSISTENCY NOTE: The keys of fc.latestMessages (validator indices) MUST
//
// correspond to indices in fc.validators.Validators(). If validators are ever removed
// from the set, stale entries in latestMessages could index out of range. The bounds
// check below (idx < 0 || idx >= len(validatorList)) guards against this by skipping
// any out-of-range index. This is the same contract as ForkChoice.OnAttestation
// () and must be maintained together.
func (fc *ForkChoiceStore) subtreeWeight(blockRoot types.Hash) *big.Int {
	weight := big.NewInt(0)
	validatorList := fc.validators.Validators()

	for idx, msg := range fc.latestMessages {
		if msg == nil {
			continue
		}
		// FIX: bounds-check idx against the validator list. A negative
		// index (shouldn't happen but defensive) or an index >= len(validatorList)
		// would cause an out-of-range access. Skip such stale entries.
		if idx < 0 || idx >= len(validatorList) {
			continue
		}
		// audit-fix MEDIUM-3: Exclude slashed validators from subtree weight.
		// A slashed validator's latest attestation must not influence the
		// LMD GHOST fork choice.
		if _, slashed := fc.slashedValidators[idx]; slashed {
			continue
		}
		// FIX: Exclude inactive validators from subtree weight,
		// consistent with calculateBlockScoreLocked ().
		if !validatorList[idx].Active {
			continue
		}
		if fc.isInSubtree(msg.BlockRoot, blockRoot) {
			weight.Add(weight, validatorList[idx].Stake)
		}
	}

	return weight
}

// isInSubtree checks if targetRoot is within the subtree rooted at blockRoot.
// A block B is in the subtree of block A if:
// - B == A, or
// - B's slot >= A's slot and B is a descendant of A
func (fc *ForkChoiceStore) isInSubtree(targetRoot, blockRoot types.Hash) bool {
	if targetRoot == blockRoot {
		return true
	}

	targetSlot, targetOk := fc.blockSlots[targetRoot]
	blockSlot, blockOk := fc.blockSlots[blockRoot]

	if !targetOk || !blockOk {
		return false
	}

	if targetSlot < blockSlot {
		return false
	}

	current := targetRoot
	for {
		if current == blockRoot {
			return true
		}

		currentSlot, ok := fc.blockSlots[current]
		if !ok || currentSlot <= blockSlot {
			return false
		}

		// audit-fix LOW: use O(1) blockParent reverse mapping instead of
		// the previous O(n) linear scan over blockChildren.
		parent, ok := fc.blockParent[current]
		if !ok {
			return false
		}
		current = parent
	}
}

// PruneAttestations removes attestations for slots older than the given slot.
func (fc *ForkChoiceStore) PruneAttestations(oldestSlot uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	for idx, msg := range fc.latestMessages {
		if msg != nil && msg.Slot < oldestSlot {
			delete(fc.latestMessages, idx)
		}
	}
	// audit-fix MEDIUM: prune finalized blocks (slot < oldestSlot) from
	// blockSlots/blockParent to prevent unbounded memory growth. Previously
	// only latestMessages was pruned, leaving block metadata to accumulate.
	for hash, slot := range fc.blockSlots {
		if slot < oldestSlot {
			delete(fc.blockSlots, hash)
			delete(fc.blockParent, hash)
		}
	}
	// Clean up blockChildren: remove pruned children and drop empty parent entries.
	for parent, children := range fc.blockChildren {
		var kept []types.Hash
		for _, child := range children {
			if _, exists := fc.blockSlots[child]; exists {
				kept = append(kept, child)
			}
		}
		if len(kept) == 0 {
			delete(fc.blockChildren, parent)
		} else {
			fc.blockChildren[parent] = kept
		}
	}
}

func (q *QPOS) SetEpochBlockRoot(epoch uint64, blockRoot types.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.setEpochBlockRootLocked(epoch, blockRoot)
}

// EnsureEpochBlockRoot sets the epoch boundary block root only if it hasn't
// been set yet. This handles the case where the first block of an epoch is
// NOT at the boundary slot (slot % 32 != 0) — e.g., the block at slot 33 is
// the first block of epoch 1 because slot 32 was skipped. In this case, the
// caller should pass the PARENT block's hash as the epoch boundary, because
// the parent is the chain tip at the start of the epoch (the correct Casper
// FFG checkpoint).
//
// R42-P3 FIX (2026-08-07): Without this, the epoch boundary root is never
// set for epochs where the first block is not at the boundary slot.
// CreateAttestation then falls back to using the current block root as
// Target.Root, which differs between slots within the same epoch → false
// "double vote" slashing detection.
func (q *QPOS) EnsureEpochBlockRoot(epoch uint64, blockRoot types.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, exists := q.epochBlockRoots[epoch]; exists {
		return
	}
	q.setEpochBlockRootLocked(epoch, blockRoot)
}

// setEpochBlockRootLocked is the lock-free inner implementation of
// SetEpochBlockRoot. Caller MUST hold q.mu.
func (q *QPOS) setEpochBlockRootLocked(epoch uint64, blockRoot types.Hash) {
	existingRoot, hasExistingRoot := q.epochBlockRoots[epoch]
	if epoch == q.finalizedEpoch && q.finalizedEpoch > 0 && hasExistingRoot &&
		existingRoot != (types.Hash{}) && existingRoot != blockRoot {
		// A canonical finalized checkpoint root is immutable. An adopted
		// header may still carry a non-canonical fallback that was never
		// entered into epochBlockRoots; in that case this first canonical
		// root is allowed to reconcile it.
		return
	}
	q.epochBlockRoots[epoch] = blockRoot
	// Header finality adoption may temporarily use the importing block hash
	// until the canonical epoch boundary root is available. Reconcile the
	// checkpoint roots as soon as that authoritative root is recorded so new
	// attestations bind to the same source root that verification expects.
	checkpointRootChanged := false
	if q.justifiedEpoch == epoch && q.justifiedRoot != blockRoot {
		q.justifiedRoot = blockRoot
		checkpointRootChanged = true
	}
	if q.finalizedEpoch == epoch && q.finalizedRoot != blockRoot {
		q.finalizedRoot = blockRoot
		checkpointRootChanged = true
	}
	if checkpointRootChanged {
		q.finalityPersistPending = true
	}
	if checkpointRootChanged || q.finalityPersistPending {
		q.persistFinalityLocked()
	}
	// SECURITY: Invalidate the shuffle cache for epoch+1 to ensure the
	// shuffle is recomputed with the latest state. (Note: as of R4-CORE-01,
	// the shuffle seed now uses the VRF accumulator, not the epoch block
	// root. This cache invalidation is retained as a safety measure for
	// any future seed changes and for the epochBlockRoots consumers like
	// tryUpdateFinality.)
	delete(q.shuffleCache, epoch+1)
	// AUDIT (2026) CORE B-2 FIX: Prune epochBlockRoots to prevent
	// unbounded memory growth. tryUpdateFinality only looks at prevEpoch =
	// currentEpoch - 1, so entries older than finalizedEpoch - 1 are never
	// read again. Prune when the map exceeds a reasonable threshold.
	//
	// AUDIT (2026) R4-CORE-03 FIX: The previous pruning cutoff was fixed
	// at finalizedEpoch-1. When finality stalls (e.g., network partition,
	// supermajority offline), finalizedEpoch stops advancing but the chain
	// keeps producing blocks → epochBlockRoots grows without bound. Now we
	// also prune based on the current epoch: entries older than
	// currentEpoch-3 are safe to prune because tryUpdateFinality only reads
	// prevEpoch = currentEpoch-1. Take the MAX of the two cutoffs.
	if len(q.epochBlockRoots) > 10 {
		pruneCutoff := epoch
		if q.finalizedEpoch > 1 {
			pruneCutoff = q.finalizedEpoch - 1
		}
		// R4-CORE-03: When finality stalls, fall back to a wall-clock
		// cutoff based on the current epoch. Keep the last 3 epochs.
		// NOTE: q.currentEpoch is currently never updated (dead); the branch
		// is kept inert rather than removed pending a decision on reviving
		// the field (see docs/qpos-weighted-consensus-plan.md).
		if q.currentEpoch > 3 {
			wallClockCutoff := q.currentEpoch - 3
			if wallClockCutoff > pruneCutoff {
				pruneCutoff = wallClockCutoff
			}
		}
		// R104-EPOCHROOT-PRUNE-JUSTIFIED FIX (2026-08-31): NEVER prune the
		// justified checkpoint epoch (nor its predecessor). Casper votes
		// created after a restart carry Source.Epoch = justifiedEpoch, and
		// ProcessAttestation hard-rejects them when the canonical root for
		// that epoch is missing (fail-closed CONS-003 binding). With
		// finalizedEpoch == 0 the old logic effectively kept only the
		// newest root: every SetEpochBlockRoot(e) deleted everything below
		// e, so justified could never advance again.
		if q.justifiedEpoch > 1 && q.justifiedEpoch-1 < pruneCutoff {
			pruneCutoff = q.justifiedEpoch - 1
		}
		for e := range q.epochBlockRoots {
			if e < pruneCutoff {
				delete(q.epochBlockRoots, e)
			}
		}
	}
}

// SetSlotBlockRoot records the canonical block root produced at a specific slot.
//
// AUDIT (2026) GOV-05 FIX: The Review Chamber's getExpectedBlockRoot
// previously looked up block roots by epoch, causing every slot in an epoch
// to compare attestations against the same root. This method populates a
// per-slot map so attestations are classified against the correct canonical
// block for their slot. Callers (block import/production paths) should invoke
// this whenever a new canonical block is added to the chain.
//
// AUDIT (2026) CORE B-1 FIX: Callers must only invoke this for blocks
// that are on the canonical chain (i.e., became the fork-choice head). The
// node import paths now gate this call by shouldSwitch.
//
// AUDIT (2026) CORE B-2 FIX: Prune slotBlockRoots to prevent unbounded
// memory growth. tryUpdateFinality only reads slots in the previous epoch
// (prevEpochStartSlot..prevEpochEndSlot), so entries for slots older than
// the finalized epoch's start are never read again.
func (q *QPOS) SetSlotBlockRoot(slot uint64, blockRoot types.Hash) {
	var qfs *QTDFinalityState
	func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		q.slotBlockRoots[slot] = blockRoot
		// R30 F23 (2026-10-30): keep the checkpoint pin alive. Pruning below can
		// drop the checkpoint's own slot root once it ages out of the window, and
		// a node that restarted with an empty map only ever learns it here.
		if blockRoot != (types.Hash{}) && blockRoot == q.finalizedRoot {
			q.finalizedSlotPin = finalizedCheckpointPin{root: blockRoot, slot: slot}
		}
		// Prune when the map exceeds 3 epochs worth of slots (3 * 32 = 96).
		if len(q.slotBlockRoots) > 3*SlotsPerEpoch {
			var pruneCutoff uint64
			if q.finalizedEpoch > 1 {
				pruneCutoff = EpochStartSlot(q.finalizedEpoch - 1)
			} else {
				// During initial sync (no finalized epoch yet), prune entries
				// older than 2 epochs before the current slot.
				pruneCutoff = 0
				if slot > 2*SlotsPerEpoch {
					pruneCutoff = slot - 2*SlotsPerEpoch
				}
			}
			// AUDIT (2026) R4-CORE-03 FIX: When finality stalls, the
			// finalizedEpoch-based cutoff stops advancing and slotBlockRoots
			// grows without bound. Fall back to a wall-clock cutoff based on
			// the current slot. Keep the last 3 epochs of slots.
			if q.currentSlot > 3*SlotsPerEpoch {
				wallClockCutoff := q.currentSlot - 3*SlotsPerEpoch
				if wallClockCutoff > pruneCutoff {
					pruneCutoff = wallClockCutoff
				}
			}
			for s := range q.slotBlockRoots {
				if s < pruneCutoff {
					delete(q.slotBlockRoots, s)
				}
			}
		}
		qfs = q.qtdFinality
	}()

	// R23 (2026-10-29): re-drive the QTD finalization for this slot. A seal
	// that completed BEFORE the canonical root landed was recorded (the
	// threshold agreement is a valid proof) but never advanced the QPOS
	// finality state, and nothing re-ran it — the slot silently lost its
	// instant finality and the chain kept waiting for the ordinary epoch
	// finalizer.
	//
	// Lock order: q.mu is RELEASED before the QTD state is touched. The
	// re-drive takes qfs.mu (to read the seal record) and then qpos.mu
	// (inside advanceQPOSFinalityForSeal), so calling it while holding q.mu
	// would create the qpos.mu → qfs.mu → qpos.mu cycle this codebase
	// deliberately avoids.
	if qfs != nil {
		qfs.reconcileCanonicalSeal(slot, blockRoot)
	}
}

// GetSlotBlockRoot returns the canonical block root for a specific slot.
// Returns the zero hash and false if no block root has been recorded for the
// slot.
//
// R27 (2026-10-30) FIX (auditor finding N2): a recorded ZERO root is reported
// as "not known". The all-zero value is a placeholder, not a block hash, and
// every consumer must reach the same verdict for it — normalising here (the
// read entry point) is what keeps the admission check, the seal driver, the
// announcement path and the reporting layer from disagreeing about the same
// stored value.
func (q *QPOS) GetSlotBlockRoot(slot uint64) (types.Hash, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	root, ok := q.slotBlockRoots[slot]
	if !ok || root == (types.Hash{}) {
		return types.Hash{}, false
	}
	return root, true
}

// GetEpochBlockRoot returns the canonical checkpoint root recorded for an
// epoch (R24, 2026-10-29).
//
// It is the POSITIVE canonicality evidence used when a slot's own root is
// not known: when the epoch checkpoint IS the sealed block, the seal
// provably attests a canonical block. It is never negative evidence — a
// checkpoint root that differs from the sealed hash says nothing about the
// sealed block (they are different blocks at different slots).
//
// Returns the zero hash and false if no checkpoint root has been recorded for
// the epoch.
func (q *QPOS) GetEpochBlockRoot(epoch uint64) (types.Hash, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	root, ok := q.epochBlockRoots[epoch]
	if !ok || root == (types.Hash{}) {
		return types.Hash{}, false
	}
	return root, true
}

// AccumulateVRFOutput XORs a proposer's VRF output into the per-epoch VRF
// accumulator (AUDIT R4-CORE-01, 2026-07-15).
//
// This is the core entropy source for the proposer shuffle seed. The
// accumulator for epoch N is used by computeDeterministicShuffleForEpoch(N+1)
// to make the next epoch's proposer schedule unpredictable — an attacker
// cannot compute the schedule until all proposers in epoch N have produced
// their blocks (revealing their VRF outputs).
//
// Caller must ONLY invoke this for canonical-chain blocks (i.e., blocks that
// became the fork-choice head). The node import path gates this call by
// shouldSwitch. Calling it for non-canonical forks would pollute the
// accumulator and cause honest nodes to diverge.
//
// Idempotent w.r.t. (epoch, slot, vrfOutput): XORing the same VRF output
// twice for the same epoch would cancel it out (XOR is self-inverse). To
// prevent this, the caller tracks which (slot, proposer) pairs have already
// been accumulated via slotBlockRoots (only canonical blocks call this, and
// each canonical slot has exactly one block).
//
// Thread-safety: acquires q.mu.
func (q *QPOS) AccumulateVRFOutput(epoch uint64, vrfOutput types.Hash) {
	if vrfOutput == (types.Hash{}) {
		// Skip empty VRF outputs (e.g., epoch 0 genesis or blocks produced
		// without a validator key). An empty VRF output would cancel itself
		// out via XOR and add no entropy.
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	acc := q.epochVRFAccumulator[epoch]
	for i := 0; i < types.HashLength; i++ {
		acc[i] ^= vrfOutput[i]
	}
	q.epochVRFAccumulator[epoch] = acc

	// SECURITY (R4-CORE-01): Invalidate the shuffle cache for epochs that
	// depend on this epoch's VRF accumulator.
	//
	// CONS-R13-M03 (2026-07-21): After the epoch-2 seed delay fix,
	// accumulating VRF output for epoch N affects the shuffle of epoch N+2
	// (not N+1). We invalidate BOTH epoch+1 and epoch+2 to be safe:
	//   - epoch+1: defensive — preserves correctness if any future code path
	//     reverts to epoch-1 seed sourcing.
	//   - epoch+2: required — the new seed source for epoch N+2 is
	//     epochVRFAccumulator[N], so any change to epoch N's accumulator
	//     invalidates epoch N+2's cached shuffle.
	delete(q.shuffleCache, epoch+1)
	delete(q.shuffleCache, epoch+2)

	// Prune old accumulators (same threshold as epochBlockRoots).
	//
	// CONS-R40-P1-01 FIX (2026-08-04): PROPOSER DIVERGENCE BUG.
	// The original code pruned everything below (finalizedEpoch - 1), but
	// proposer election for epoch N depends on VRF accumulator from (N - 2).
	// If N-2 <= finalizedEpoch - 2 → N-2 is below pruneCutoff → gets deleted
	// → zero accumulator is used → different seed → different proposer → chain
	// split. The fix: never prune an epoch that could still be needed by any
	// future election — the farthest future is (currentEpoch + 2) which needs
	// currentEpoch → so the cutoff must be at most currentEpoch - 3.
	if len(q.epochVRFAccumulator) > 10 {
		pruneCutoff := epoch
		if q.finalizedEpoch > 1 {
			pruneCutoff = q.finalizedEpoch - 1
		}
		// Never prune any epoch that could still be needed by a future
		// proposer election. The farthest future that needs an epoch E
		// is E + 2 (because (E+2) needs (E+2) - 2 = E). So we must keep
		// at least (currentEpoch - 2) → cutoff ≤ currentEpoch - 3.
		maxSafeCutoff := epoch - 3
		if pruneCutoff > maxSafeCutoff {
			pruneCutoff = maxSafeCutoff
		}
		for e := range q.epochVRFAccumulator {
			if e < pruneCutoff {
				delete(q.epochVRFAccumulator, e)
			}
		}
	}
}

// SetEpochVRFAccumulator is the R54-ACC (2026-08-07) replacement for the
// incremental-XOR accumulation path. It records the per-epoch VRF accumulator
// for epoch directly from the ON-CHAIN value carried in a canonical block
// header (blk.Header.VRFAccumulator), which is a deterministic function of
// the verified chain (see consensus.ComputeNextVRFAccumulator).
//
// WHY assignment instead of XOR: the old AccumulateVRFOutput XOR'd each
// block's VRF output into a node-local map, and that map was mutated from
// several execution paths (produce, blockInsertLoop, startup replay, reorg
// recompute). Any asymmetry between those paths (e.g. a block XOR'd on the
// live path but not the sync path, or XOR'd twice and self-canceled) made
// the accumulator — and therefore the future-epoch proposer shuffle — differ
// across honest nodes, which is the root cause of the recurring chain fork.
//
// Because the header value is identical on every node that imports the same
// canonical block, this assignment is idempotent and path-independent: the
// map converges to the last canonical block of each epoch, which carries that
// epoch's FULL accumulator. This eliminates the fork mechanism entirely.
//
// Thread-safety: acquires q.mu.
func (q *QPOS) SetEpochVRFAccumulator(epoch uint64, accOnChain types.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.epochVRFAccumulator[epoch] = accOnChain

	// VDF seed hardening (stage-2): kick off the async T-step evaluation
	// for this epoch's accumulator so the shuffle for epoch+2 finds the
	// hardened seed cached. Never blocks: on cache miss the derivation
	// falls back to a deterministic inline compute (see vdf_seed.go).
	q.spawnVDFSeedPrecompute(epoch, accOnChain)

	// SECURITY (R4-CORE-01): Invalidate the shuffle cache for epochs that
	// depend on this epoch's VRF accumulator (same policy as
	// AccumulateVRFOutput / CONS-R13-M03).
	delete(q.shuffleCache, epoch+1)
	delete(q.shuffleCache, epoch+2)

	// VDF seed hardening (stage-2): the cache is keyed by (srcEpoch, acc),
	// so a reorg that changes the accumulator for this epoch leaves a stale
	// entry only for the OLD accumulator — harmless (different key). The
	// new accumulator gets its own cache entry. No explicit invalidation
	// needed: the key collision is impossible.

	// R45-PoA-FIX (2026-08-12): The accumulator for THIS epoch just got
	// populated from the on-chain header. Epochs that depend on it
	// (epoch+1 and epoch+2) can now be safely recomputed with proper
	// entropy next time their shuffle is requested — clear the
	// cold-start flags so BlockProducer / BlockValidator know they can
	// trust subsequent GetProposerForSlot results for those epochs.
	delete(q.coldStartEpochs, epoch+1)
	delete(q.coldStartEpochs, epoch+2)

	// CONS-R40-P1-01 FIX (2026-08-04): PROPOSER DIVERGENCE BUG.
	// Never prune an epoch that could still be needed by any future election
	// (the farthest future is epoch+2, which needs the current epoch). The
	// cutoff must be at most currentEpoch - 3.
	if len(q.epochVRFAccumulator) > 10 {
		pruneCutoff := epoch
		if q.finalizedEpoch > 1 {
			pruneCutoff = q.finalizedEpoch - 1
		}
		maxSafeCutoff := epoch - 3
		if pruneCutoff > maxSafeCutoff {
			pruneCutoff = maxSafeCutoff
		}
		for e := range q.epochVRFAccumulator {
			if e < pruneCutoff {
				delete(q.epochVRFAccumulator, e)
			}
		}
	}

	// R58-VRF-PERSIST (2026-08-18): durably record the authoritative
	// on-chain accumulator via the registered callback (node.go → block
	// store). Invoked under q.mu; nil callback = persistence disabled.
	if q.vrfPersist != nil {
		q.vrfPersist(epoch, accOnChain)
	}
}

// ClearEpochVRFAccumulatorsFrom deletes every accumulated per-epoch VRF
// value whose epoch is >= fromEpoch, along with the shuffle cache entries
// that depend on them.
//
// WHY (2026-08-07, fork-recovery root cause): OnForkRollback previously only
// rolled back stateDB and syncBuf; the QPOS epochVRFAccumulator map retained
// values read from the ABANDONED fork's block headers. Those residual values
// changed the future-epoch proposer shuffle seed, so the node kept electing a
// different proposer than its peers → others rejected its blocks → it rolled
// back again, creating a permanent fork divergence loop.
//
// Because the accumulator values are now assigned idempotently from the
// ON-CHAIN block header (SetEpochVRFAccumulator), clearing them is safe: the
// canonical chain re-import re-populates them deterministically. Clearing here
// simply removes the stale fork-specific values so a node never uses them for
// an election before it has re-synced the canonical chain.
//
// Thread-safety: acquires q.mu.
func (q *QPOS) ClearEpochVRFAccumulatorsFrom(fromEpoch uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for e := range q.epochVRFAccumulator {
		if e >= fromEpoch {
			delete(q.epochVRFAccumulator, e)
			// Invalidate shuffle caches that depend on this epoch's
			// accumulator (same policy as SetEpochVRFAccumulator).
			delete(q.shuffleCache, e+1)
			delete(q.shuffleCache, e+2)
		}
	}
}

// getEpochVRFAccumulatorLocked returns the accumulated VRF output for the
// given epoch, or the zero hash if no VRF outputs have been accumulated.
// Caller must hold q.mu (at least RLock).
func (q *QPOS) getEpochVRFAccumulatorLocked(epoch uint64) types.Hash {
	return q.epochVRFAccumulator[epoch]
}

// GetEpochVRFAccumulator is the public, lock-safe accessor for the per-epoch
// VRF accumulator. Returns the zero hash if no VRF outputs have been
// accumulated for the given epoch.
//
// AUDIT (2026) R4-CRND-01 FIX: Exposed for use by the DA committee
// shuffle seed. The DA committee previously used qpos.GetRANDAO() which
// ignores the epoch parameter and returns a single cumulative XOR that
// never resets → identical shuffle every epoch. Now the DA committee can
// use this per-epoch VRF accumulator, which provides distinct, unpredictable
// entropy per epoch (sourced from the canonical-chain proposers' VRF outputs).
func (q *QPOS) GetEpochVRFAccumulator(epoch uint64) types.Hash {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.epochVRFAccumulator[epoch]
}

// SetVRFPersistCallback registers the R58-VRF-PERSIST persistence hook called
// (under q.mu) after every authoritative SetEpochVRFAccumulator commit.
// node.go registers it to durably record the accumulator in the block store.
// Passing nil disables persistence.
func (q *QPOS) SetVRFPersistCallback(fn func(epoch uint64, acc types.Hash)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.vrfPersist = fn
}

// SetAllEpochVRFAccumulators bulk-loads persisted per-epoch accumulator
// checkpoints into QPOS (R58-VRF-PERSIST startup recovery). It assigns the
// map entries directly WITHOUT invoking the persistence callback (these
// values just came from the store) and WITHOUT pruning — the caller decides
// the working set. The R52 block replay, which runs afterwards, overwrites
// each epoch with the authoritative on-chain header value.
func (q *QPOS) SetAllEpochVRFAccumulators(accs map[uint64]types.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for e, acc := range accs {
		if acc == (types.Hash{}) {
			continue
		}
		q.epochVRFAccumulator[e] = acc
		// Invalidate shuffle caches that depend on this epoch's accumulator
		// (same policy as SetEpochVRFAccumulator).
		delete(q.shuffleCache, e+1)
		delete(q.shuffleCache, e+2)
		delete(q.coldStartEpochs, e+1)
		delete(q.coldStartEpochs, e+2)
	}
}

// ReanchorSlotRoots re-anchors slotBlockRoots for the slots on the NEW
// canonical chain following a reorg (AUDIT R4-CORE-02, 2026-07-15).
//
// BUG: SetSlotBlockRoot only records the root for a block's OWN slot when it
// becomes the head. In a multi-block reorg, the intermediate blocks that
// never individually became head leave slotBlockRoots[reorged_slot]
// pointing at the ABANDONED fork's roots. tryUpdateFinality then compares
// honest attestations (Target = new canonical block) against those stale
// roots → honest votes are rejected, abandoned-fork votes are counted →
// finality stalls or misclassifies; nodes with different import orders can
// finalize conflicting roots (accountable safety failure).
//
// FIX: The caller walks the new head back to the common ancestor with the
// old head and builds roots = {slot: canonicalBlockHash} for every slot on
// the new canonical segment strictly above the common ancestor. This method
// atomically:
//  1. Overwrites slotBlockRoots[s] = roots[s] for each slot in roots
//     (canonicalizing the new chain), and
//  2. DELETES any slotBlockRoots entry whose slot falls inside the reorged
//     range but is NOT in roots — these belong to the abandoned fork and
//     would otherwise poison finality. The range is [min(roots), max(roots)],
//     widened by the bounds the caller observed: down to the common ancestor
//     and up to the replaced head, and it still applies when roots is empty
//     (see ReanchorBounds).
//
// Entries below the range (predating the reorg, still canonical) are left
// untouched. Entries above the range are left untouched by THIS entry point
// because they are assumed to be future slots — see
// ReanchorSlotRootsWithStaleAbove for the head-rollback case where that
// assumption does not hold.
//
// CONSENSUS-DETERMINISM FIX (2026-08-04): vrfAccUpdates carries the
// recomputed per-epoch VRF accumulator for every epoch touched by the reorg
// above the common ancestor. The epoch VRF accumulator is the XOR of ALL
// canonical blocks' VRF outputs in that epoch and feeds the shuffle seed of
// epoch+2 (computeDeterministicShuffleForEpoch). AccumulateVRFOutput mutates
// it incrementally as each block becomes head; on a reorg the abandoned
// fork's VRF outputs would otherwise remain in the accumulator, making it
// differ across nodes (different import orders → different accumulators →
// different future shuffles → permanent chain split). Recomputing it from
// the canonical chain (as the caller does) and applying it here restores the
// Ethereum-aligned invariant that the shuffle seed is a deterministic
// function of the canonical chain. The updates are applied ONLY when the
// reorg is accepted (not rejected for touching finalized history), so the
// accumulator never diverges from slotBlockRoots.
func (q *QPOS) ReanchorSlotRoots(roots map[uint64]types.Hash, vrfAccUpdates map[uint64]types.Hash) bool {
	return q.reanchorSlotRoots(roots, vrfAccUpdates, ReanchorBounds{})
}

// ReanchorSlotRootsWithStaleAbove is ReanchorSlotRoots for a reorg whose new
// head sits at a LOWER slot than the head it replaces (R27, 2026-10-30 —
// auditor finding N1).
//
// The plain entry point assumes every recorded root above the re-anchored
// range belongs to a FUTURE slot, which is true only while the head keeps
// moving forward. Fork choice also accepts a switch to an equal-height head at
// an earlier slot, and sync-time rollbacks do the same: then slots in
// (newHeadSlot, oldHeadSlot] keep the abandoned chain's roots, their seals keep
// classifying as canonical against a live root, and the public RPCs keep
// reporting those reorged-away blocks as final.
//
// staleAbove is the slot of the head being REPLACED (inclusive). Every recorded
// slot root in (maxSlot, staleAbove] is part of the abandoned chain and is
// removed; every removed slot's seal classification is invalidated too, and the
// epoch checkpoint roots of epochs above the new head are dropped (nothing
// canonical exists there — otherwise the checkpoint fallback could still
// confirm a seal over a reorged-away block).
//
// Passing staleAbove <= maxSlot makes this identical to ReanchorSlotRoots.
func (q *QPOS) ReanchorSlotRootsWithStaleAbove(roots map[uint64]types.Hash, vrfAccUpdates map[uint64]types.Hash, staleAbove uint64) bool {
	return q.reanchorSlotRoots(roots, vrfAccUpdates, ReanchorBounds{ReplacedHeadSlot: staleAbove})
}

// ReanchorBounds describes the part of the chain a reorg ABANDONS, so that
// reanchorSlotRoots can clean exactly that range and nothing else (R28,
// 2026-10-30 — auditor findings R27-O1 and R27-O3).
//
// Every field is an OBSERVED property of the walk the caller performed; the
// zero value means "the caller did not observe it", which keeps the entry
// points that cannot know a bound on the conservative (do-not-delete) side.
type ReanchorBounds struct {
	// AncestorSlot is the slot of the common ancestor block between the new
	// canonical chain and the abandoned one. It is only meaningful when
	// AncestorKnown is true; when the caller could not locate the ancestor
	// (deep reorg, chain still syncing) the zero value must be ignored, or
	// the whole prefix of canonical slot roots would be wiped.
	//
	// When known, every slot in (AncestorSlot, min(roots)) has NO canonical
	// block on the new chain, so any recorded root there belongs to the
	// abandoned fork. That lower bound is what closes the gap left by the
	// original R4-CORE-02 range: a new chain that SKIPS the epoch boundary
	// slot (e.g. ancestor 30, blocks 31 then 33) leaves slotBlockRoots[32]
	// pointing at the abandoned chain, because 32 is neither in roots (no
	// canonical block) nor inside [min(roots), ...].
	AncestorSlot uint64

	// AncestorKnown reports that AncestorSlot was located by walking both
	// chains back to a shared block.
	AncestorKnown bool

	// ReplacedHeadSlot is the slot of the head being REPLACED (inclusive).
	// Recorded slot roots in (max(roots), ReplacedHeadSlot] belong to the
	// abandoned chain when the new head sits at a lower slot than the head it
	// replaces (head rollback / sync rollback).
	//
	// Together with AncestorSlot it also delimits the range when roots is
	// EMPTY (R29, 2026-10-30 — auditor finding B1): a rollback whose new head
	// IS the common ancestor contributes no re-anchored slot at all, and the
	// abandoned range is still (AncestorSlot, ReplacedHeadSlot].
	ReplacedHeadSlot uint64

	// AncestorHash is the block hash of the common ancestor. It is the
	// canonical chain tip the abandoned slots fell back to: for an epoch
	// whose boundary no new-chain block reaches yet, the checkpoint IS that
	// tip (R42-P3), so the ancestor hash is the correct value to record
	// instead of dropping the checkpoint (R29, 2026-10-30 — auditor finding
	// N7). Only meaningful when AncestorKnown is true.
	AncestorHash types.Hash

	// EpochRoots carries the checkpoint root the NEW canonical chain implies
	// for every epoch the reorg reaches into: the boundary block itself when
	// the block at slot e*SlotsPerEpoch is on the new chain, otherwise that
	// block's parent (the chain tip at the start of the epoch, per the
	// R42-P3 rule). Epochs absent from the map have no canonical block above
	// the common ancestor and are left without a checkpoint.
	//
	// Only epochs the abandoned range actually reaches are rewritten (a
	// checkpoint depends on blocks up to its own boundary slot and nothing
	// above it); see reanchorSlotRoots.
	EpochRoots map[uint64]types.Hash
}

// ReanchorSlotRootsBounded is the full entry point: the caller passes what it
// observed about the abandoned range (common ancestor, replaced head, and the
// epoch checkpoints the new chain implies) and this method cleans exactly that
// range. ReanchorSlotRoots and ReanchorSlotRootsWithStaleAbove are the
// conservative specialisations of it.
//
// The bool reports whether the reorg was ACCEPTED: false means it was refused
// for rewriting finalized history and no state was touched.
func (q *QPOS) ReanchorSlotRootsBounded(roots map[uint64]types.Hash, vrfAccUpdates map[uint64]types.Hash, bounds ReanchorBounds) bool {
	return q.reanchorSlotRoots(roots, vrfAccUpdates, bounds)
}

// ReanchorCleanRange derives the slot range a reorg ABANDONS from the
// re-anchored segment and the bounds the caller observed (R30, 2026-10-30).
//
// `roots` is the NEW canonical segment; any pre-existing entry in the range
// that is not in roots is stale. The range is widened by what the caller
// observed about the abandoned branch:
//
//   - to reaches the replaced head's slot (R27, 2026-10-30): a rollback
//     leaves the abandoned chain's roots behind above the new head's own
//     slot.
//   - from reaches the slot after the common ancestor (R28, 2026-10-30 —
//     auditor finding R27-O3): every slot between the ancestor and the first
//     re-anchored block has no canonical block on the new chain either — the
//     new chain simply SKIPPED it. Only extended when the ancestor is known:
//     a caller that could not find it (deep reorg, chain still syncing) must
//     not wipe the canonical prefix.
//
// R29 (2026-10-30) FIX (auditor finding B1): an EMPTY roots map is not a
// no-op. It is exactly the pure head-rollback shape — the new head IS the
// common ancestor, so the new chain contributes no block above it — and the
// abandoned range (ancestor, replaced head] still has to be cleaned.
// Returning early left every slot root of that range pointing at a block the
// rollback removed: its seal kept classifying as canonical against that live
// root and the RPCs kept reporting a deleted block as final, with no later
// pass to correct it (the chain re-extends linearly from the ancestor, and a
// linear extension is a no-op here).
//
// It is exported so the fork choice can run the SAME computation before it
// commits a head (R30): a reorg the QPOS would refuse must reject the head
// switch, not just the root bookkeeping.
//
// ok=false means the bounds describe no abandoned range at all (linear
// extension, or too little information to act on) — every caller treats that
// as "nothing to do".
func ReanchorCleanRange(roots map[uint64]types.Hash, bounds ReanchorBounds) (from, to uint64, ok bool) {
	if len(roots) > 0 {
		var minSlot, maxSlot uint64
		first := true
		for s := range roots {
			if first {
				minSlot, maxSlot = s, s
				first = false
				continue
			}
			if s < minSlot {
				minSlot = s
			}
			if s > maxSlot {
				maxSlot = s
			}
		}
		from, to = minSlot, maxSlot
		if bounds.AncestorKnown && bounds.AncestorSlot+1 < from {
			from = bounds.AncestorSlot + 1
		}
		if bounds.ReplacedHeadSlot > to {
			to = bounds.ReplacedHeadSlot
		}
		return from, to, true
	}
	if bounds.AncestorKnown && bounds.ReplacedHeadSlot > bounds.AncestorSlot {
		// Pure head rollback: the whole abandoned range is above the ancestor.
		return bounds.AncestorSlot + 1, bounds.ReplacedHeadSlot, true
	}
	return 0, 0, false
}

// ReanchorConflictsWithFinality reports whether accepting a reorg described by
// (roots, bounds) would rewrite finalized history on a node whose finality
// checkpoint block sits at finalSlot: the abandoned range would start at or
// below that block, i.e. the reorg replaces or deletes a canonical block that is
// already final.
//
// finalSlot MUST be the slot of the finalized checkpoint BLOCK (R42-P3), not the
// finalized epoch's boundary slot: in a chain that skips slots the boundary slot
// can hold no block at all, and comparing against it refuses legal reorgs that
// only replace blocks above the checkpoint (R30 F21). See
// FinalizedCheckpointSlot, which derives it.
//
// It is the single definition of the rule: reanchorSlotRoots enforces exactly
// this predicate under q.mu, so a caller that refuses a head before committing
// it cannot disagree with the guard that would have refused the same write.
// Pure, so it is testable without any QPOS state (R30).
func ReanchorConflictsWithFinality(roots map[uint64]types.Hash, bounds ReanchorBounds, finalSlot uint64) bool {
	from, _, ok := ReanchorCleanRange(roots, bounds)
	return ok && from <= finalSlot
}

// FinalityFloorSlot returns the finalized epoch's boundary slot (finalizedEpoch
// * SlotsPerEpoch) together with whether anything is finalized yet.
//
// It is an UPPER BOUND on the slot of the finalized checkpoint block: the
// checkpoint is the highest canonical block at or below this slot (R42-P3), so
// it sits at this slot only when the boundary slot itself carries a block. Use
// it for "which region of the chain is frozen" questions (store rollbacks,
// operator diagnostics); use FinalizedCheckpointSlot for "would this reorg
// replace finalized history" decisions.
func (q *QPOS) FinalityFloorSlot() (uint64, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.finalityFloorSlotLocked()
}

// finalizedCheckpointPin records the slot that holds the finalized checkpoint
// block, bound to the checkpoint root it belongs to so it invalidates itself
// when finality advances (a new checkpoint has a different root).
//
// R30 F23 (2026-10-30): the slot-root map cannot answer this question for the
// lifetime of a node — it starts empty on every restart and is pruned while the
// node runs — and the epoch boundary slot is only an upper bound (R42-P3).
// Without the pin, every reorg decision taken after a restart compared the
// abandoned range against the boundary slot, i.e. it silently fell back to the
// F21 defect (legal reorgs in the (checkpoint, boundary] band refused) for as
// long as the node ran.
type finalizedCheckpointPin struct {
	root types.Hash
	slot uint64
}

// SetFinalizedCheckpointSlot pins the slot holding the current finalized
// checkpoint block. It is called by the node after a restart, when the
// checkpoint root has just been restored from disk and the slot-root map is
// still empty, so the caller has to resolve the slot from the block store.
//
// Returns false (and pins nothing) when the slot cannot be the checkpoint's:
// the root must be the current finalized root and the slot must not lie above
// the finalized epoch's boundary slot. The caller keeps the conservative
// fallback in that case — an unpinned checkpoint is compared as its boundary
// slot, which refuses reorgs that would actually be legal, never the reverse.
func (q *QPOS) SetFinalizedCheckpointSlot(root types.Hash, slot uint64) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if root == (types.Hash{}) || q.finalizedRoot != root {
		return false
	}
	if slot > q.finalizedEpoch*SlotsPerEpoch {
		return false
	}
	q.finalizedSlotPin = finalizedCheckpointPin{root: root, slot: slot}
	return true
}

// pinFinalizedCheckpointSlotLocked refreshes the pin from the slot-root map
// after finality moved. Caller MUST hold q.mu.
//
// A pin that already belongs to the current checkpoint root is exact (a block
// hash identifies one block, hence one slot) and is left alone; otherwise the
// map is scanned once, at the moment finality advances, which is far cheaper
// than scanning it on every reorg decision.
func (q *QPOS) pinFinalizedCheckpointSlotLocked() {
	if q.finalizedRoot == (types.Hash{}) {
		q.finalizedSlotPin = finalizedCheckpointPin{}
		return
	}
	if q.finalizedSlotPin.root == q.finalizedRoot {
		return
	}
	boundary := q.finalizedEpoch * SlotsPerEpoch
	slot, found := uint64(0), false
	for s, root := range q.slotBlockRoots {
		if s > boundary || root != q.finalizedRoot {
			continue
		}
		if !found || s > slot {
			slot, found = s, true
		}
	}
	if found {
		q.finalizedSlotPin = finalizedCheckpointPin{root: q.finalizedRoot, slot: slot}
	}
}

// FinalizedCheckpointSlot returns the slot of the finalized checkpoint BLOCK
// (the highest canonical block at or below the finalized epoch's boundary slot)
// together with whether anything is finalized yet.
//
// This is the boundary a reorg must not cross: the checkpoint block and every
// ancestor of it are final, everything ABOVE it is still reorgable. Comparing
// against the boundary slot instead (FinalityFloorSlot) is not equivalent — the
// boundary slot carries no block whenever the chain skipped it, so the whole
// band between the checkpoint block and that slot was treated as final and legal
// reorgs that only replace blocks above the checkpoint were refused. On a chain
// with skipped slots that band sits immediately above the head, so the refusal
// could strand a node on a branch its peers had legitimately abandoned
// (R30 F21, 2026-10-30).
//
// The checkpoint root is located by hash in the slot-root map. When it cannot be
// found (pruned, never recorded, or a zero root) the boundary slot is returned
// instead, which is the strictly more conservative answer: refusing a legal
// reorg costs liveness, accepting an illegal one breaks finality.
func (q *QPOS) FinalizedCheckpointSlot() (uint64, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.finalizedCheckpointSlotLocked()
}

// finalizedCheckpointSlotLocked is FinalizedCheckpointSlot for callers that
// already hold q.mu.
func (q *QPOS) finalizedCheckpointSlotLocked() (uint64, bool) {
	boundary, ok := q.finalityFloorSlotLocked()
	if !ok {
		return 0, false
	}
	if q.finalizedRoot == (types.Hash{}) {
		return boundary, true
	}
	// The pin was resolved when finality moved (or pinned from the block store
	// after a restart) and is keyed by the checkpoint root, so it stays exact
	// while the slot-root map is pruned or empty (R30 F23).
	if pin := q.finalizedSlotPin; pin.root == q.finalizedRoot && pin.slot <= boundary {
		return pin.slot, true
	}
	// A block hash identifies exactly one block, so a slot root equal to the
	// checkpoint root IS the checkpoint block: no slot above it can match.
	// Skipped slots cost a scan of the map, which only reorg decisions pay.
	slot, found := uint64(0), false
	for s, root := range q.slotBlockRoots {
		if s > boundary || root != q.finalizedRoot {
			continue
		}
		if !found || s > slot {
			slot, found = s, true
		}
	}
	if !found {
		return boundary, true
	}
	return slot, true
}

// finalityFloorSlotLocked is FinalityFloorSlot for callers that already hold
// q.mu.
func (q *QPOS) finalityFloorSlotLocked() (uint64, bool) {
	if q.finalizedEpoch == 0 && q.finalizedRoot == (types.Hash{}) {
		return 0, false
	}
	return q.finalizedEpoch * SlotsPerEpoch, true
}

func (q *QPOS) reanchorSlotRoots(roots map[uint64]types.Hash, vrfAccUpdates map[uint64]types.Hash, bounds ReanchorBounds) bool {
	// SHRD- (Info, 2026-07-17): the range is computed before q.mu.Lock() is
	// taken below. This is safe because `roots` is a caller-local map (built
	// in reanchorSlotRootsAfterReorg as `roots := make(map[uint64]types.Hash,
	// len(newChain))`) and is not shared with any other goroutine, so no
	// concurrent modification can occur between this point and the lock
	// acquisition. Only the q.slotBlockRoots mutations (steps 1 and 2 below)
	// require the lock.
	cleanMin, cleanMax, haveRange := ReanchorCleanRange(roots, bounds)
	if !haveRange {
		return true
	}

	// R25 (2026-10-30) FIX (auditor finding N2): a reorg that reverts a slot
	// can make that slot's sealed block CANONICAL again — exactly the case
	// SetSlotBlockRoot re-drives (R23). ReanchorSlotRoots updated slotBlockRoots
	// directly with no QTD hook, so a sealed block that became canonical
	// again through a reorg was never re-classified, re-marked, or counted,
	// and its stale Differs/Unknown would survive the next root pruning.
	//
	// The locked body is wrapped in a closure (the QTD re-drive must run AFTER
	// q.mu is released, mirroring SetSlotBlockRoot, so reconcile's
	// advanceQPOSFinalityForSeal can take qpos.mu without an inversion). The
	// re-drive is skipped when qfs was not captured (the reorg was rejected
	// for touching finalized history, so no state changed).
	var qfs *QTDFinalityState
	var applied map[uint64]types.Hash
	accepted := true
	func() {
		q.mu.Lock()
		defer q.mu.Unlock()

		// CONS-R13-M04 (2026-07-21): Refuse to re-anchor roots that fall inside
		// or below the finalized epoch. Casper FFG finality is IRREVERSIBLE: a
		// finalized epoch's slot roots (and all earlier epochs) must never
		// change. A reorg that touches a finalized slot would either:
		//   (a) overwrite canonicalRoots[slot] with a different hash, OR
		//   (b) delete canonicalRoots[slot] (step 2 below) — making the
		//       finalized block look "unknown" to subsequent tryUpdateFinality
		//       calls, causing finality accounting divergence across nodes,
		//       or allowing QTD instant-finality's canonical-root check to
		//       fail-closed (QUANTUM-) on a previously-finalized slot.
		//
		// Both outcomes violate accountable safety: finalized history must
		// never be rewritten. Fail-closed: reject the entire reorg (do NOT
		// partially apply it) and log the violation so operators can
		// investigate the reorg source.
		//
		// We check against q.finalizedEpoch (the latest finalized epoch).
		// Slots in epochs > finalizedEpoch may legitimately be reorged (the
		// chain above finality is the "hot" forkchoice region).
		// R28 (2026-10-30) SAFETY: the check below uses cleanMin — the START of
		// the abandoned range — not minSlot, the first re-anchored slot. The two
		// differ exactly when the common ancestor sits BELOW the finalized
		// boundary while the new chain skips back above it: the reorg then
		// rewrites history that starts below finality, and steps 2/3 would
		// delete finalized slot roots and checkpoints. Checking the abandoned
		// start is what keeps the irreversible-history invariant true for the
		// range this method actually cleans.
		//
		// R29 (2026-10-30) FIX (auditor finding N1): the boundary is INCLUSIVE.
		// The block on the finalized epoch's boundary slot IS its checkpoint
		// root (R42-P3), so cleanMin == finalizedEpochStartSlot means the reorg
		// replaces or drops that very block — steps 1/2 would overwrite or
		// delete its slot root, which no reorg may do. (If the new chain
		// contained the SAME boundary block, the ancestor would have been found
		// at that slot or above, so cleanMin would start higher.)
		//
		// The R28 maxSlot branch is gone (auditor finding N2): cleanMin <= cleanMax
		// always holds here, so "the whole range is below finality" is a
		// strict special case of the single check below.
		if finalizedSlot, ok := q.finalizedCheckpointSlotLocked(); ok {
			// R30 (2026-10-30): the conflict test is the exported predicate so
			// the rule has exactly one implementation. The fork choice used to
			// call it before committing a head; it now calls this method instead
			// (the decision is this method's refusal), but keeping the predicate
			// as the single definition of "does this reorg touch finalized
			// history" is what stops a caller from re-deriving the range
			// differently. cleanMin/cleanMax above are kept for the log.
			//
			// R30 F21 (2026-10-30): the boundary is the finalized checkpoint
			// BLOCK's slot, not the epoch's boundary slot. The two differ when
			// the boundary slot was skipped: the blocks between the checkpoint
			// and the boundary are NOT final, so protecting them refused legal
			// reorgs and could strand this node on an abandoned branch.
			if ReanchorConflictsWithFinality(roots, bounds, finalizedSlot) {
				// The abandoned range starts at or below the finalized
				// checkpoint block: accepting it would rewrite irreversible
				// history. Refuse the whole reorg rather than partially applying it.
				log.Printf("[ERROR] qpos: ReanchorSlotRoots: refusing reorg of finalized history: "+
					"abandoned range [%d,%d] reaches the finalized checkpoint block at slot %d "+
					"(epoch %d, boundary slot %d, finalizedRoot=%s)",
					cleanMin, cleanMax, finalizedSlot, q.finalizedEpoch,
					q.finalizedEpoch*SlotsPerEpoch, q.finalizedRoot.String())
				accepted = false
				return
			}
		}

		// 1. Overwrite with the new canonical roots.
		for s, r := range roots {
			q.slotBlockRoots[s] = r
		}
		// 2. Delete stale entries that fell inside the reorged range but are
		//    not on the new canonical chain.
		for s := range q.slotBlockRoots {
			if s >= cleanMin && s <= cleanMax {
				if _, ok := roots[s]; !ok {
					delete(q.slotBlockRoots, s)
				}
			}
		}
		// 3. Re-derive the epoch checkpoint roots of every epoch the abandoned
		//    range reaches into.
		//
		//    R27 (2026-10-30) added the "epoch above the new head" case; R28
		//    (2026-10-30, auditor findings R27-O1/R27-O3) generalises it.
		//
		//    A checkpoint for epoch e is a function of the canonical blocks at
		//    slots <= e*SlotsPerEpoch (the block on the boundary slot itself,
		//    else the highest block below it — R42-P3). The reorg can therefore
		//    only invalidate it when the abandoned range starts at or below that
		//    boundary. This covers both the epoch ABOVE the new head (no
		//    canonical block exists there at all) and the epoch a rollback
		//    partially rewrote (a same-epoch rollback leaves the old epoch's
		//    first block behind as the checkpoint). When the reorg starts ABOVE
		//    the boundary the recorded checkpoint is still correct and must not
		//    be touched: EpochRoots only describes the re-anchored segment, so
		//    its derived value would name a mid-epoch block as the epoch start.
		//
		//    The justified and finalized checkpoints are never dropped or
		//    rewritten, matching the R104-EPOCHROOT-PRUNE-JUSTIFIED rule in
		//    setEpochBlockRootLocked: attestations carry Source.Epoch =
		//    justifiedEpoch and ProcessAttestation fail-closes (CONS-003) when
		//    the canonical root for that epoch is missing, so deleting it would
		//    stall finality. Keeping the anchor is the fail-safe choice.
		//    R29 (2026-10-30) FIX (auditor finding N7): an epoch whose checkpoint
		//    the abandoned range invalidates, but which the new chain has no
		//    block in, is not left empty. Its checkpoint is still determined:
		//    every canonical block up to that epoch's boundary lies at or below
		//    the common ancestor, so the checkpoint IS the ancestor (R42-P3).
		//    Dropping it made ProcessAttestation fail-closed (CONS-003) for every
		//    vote whose Source.Epoch fell in that epoch, and nothing re-created
		//    it — the checkpoint is only re-recorded when the new chain reaches a
		//    boundary slot, which a skipping chain never does.
		//
		//    Ceil() is written as a divide-plus-adjust rather than
		//    SlotToEpoch(cleanMin + SlotsPerEpoch - 1) so a slot range can
		//    never wrap around.
		firstReachedEpoch := SlotToEpoch(cleanMin)
		if cleanMin%SlotsPerEpoch != 0 {
			firstReachedEpoch++
		}
		// The invalidated epochs are collected while they are removed so the
		// fallback below walks a set bounded by the map size. A numeric walk up
		// to SlotToEpoch(cleanMax) would spin under q.mu if the replaced head's
		// slot were absurdly large.
		var fallenEpochs []uint64
		for e := range q.epochBlockRoots {
			if e == q.justifiedEpoch || e == q.finalizedEpoch {
				continue
			}
			if e >= firstReachedEpoch {
				fallenEpochs = append(fallenEpochs, e)
				delete(q.epochBlockRoots, e)
			}
		}
		for e, root := range bounds.EpochRoots {
			if root == (types.Hash{}) || e < firstReachedEpoch {
				continue
			}
			if e == q.justifiedEpoch || e == q.finalizedEpoch {
				continue
			}
			q.epochBlockRoots[e] = root
		}
		if bounds.AncestorKnown && bounds.AncestorHash != (types.Hash{}) {
			for _, e := range fallenEpochs {
				if root, ok := bounds.EpochRoots[e]; ok && root != (types.Hash{}) {
					continue
				}
				q.epochBlockRoots[e] = bounds.AncestorHash
			}
		}
		// CONSENSUS-DETERMINISM FIX (2026-08-04): Apply the recomputed per-epoch
		// VRF accumulator for the epochs touched by this reorg. This runs only on
		// the accepted path (we are past the finalized-history rejection above),
		// so the accumulator is guaranteed to stay consistent with slotBlockRoots.
		// The shuffle caches for epochs depending on these accumulators are reset
		// by the CONS- cache-clear below (so the next shuffle recomputes from
		// the new accumulator).
		if len(vrfAccUpdates) > 0 {
			for e, v := range vrfAccUpdates {
				// A zero accumulator means the epoch no longer has canonical VRF
				// outputs after the reorg (e.g., all blocks in the epoch were
				// reorged away). Store it explicitly so the seed logic reads a
				// deterministic value rather than a stale one.
				q.epochVRFAccumulator[e] = v
			}
		}
		// CONS-FIX: After a reorg the epoch VRF accumulator may differ on
		// the new canonical chain (AccumulateVRFOutput recomputes it from the
		// new slot roots). The shuffleCache and committeeCache, however, are
		// keyed only by epoch/slot and would otherwise keep returning the
		// pre-fork proposer/committee ordering. Reset both caches so the next
		// GetCommitteeForSlot / IsProposer recomputes from the new accumulator.
		for k := range q.shuffleCache {
			delete(q.shuffleCache, k)
		}
		for k := range q.committeeCache {
			delete(q.committeeCache, k)
		}
		// Only the accepted path reaches here: capture the QTD finality engine
		// and the applied roots for the post-unlock re-drive.
		qfs = q.qtdFinality
		applied = roots
	}()
	if !accepted {
		return false
	}

	// Re-drive QTD classification for every re-anchored slot, exactly like
	// SetSlotBlockRoot: refresh the persisted canonical classification, the
	// epoch markers, and the executive seal counter. Idempotent — the re-drive
	// only advances markers when the epoch is ahead of the marker and counts a
	// record at most once (claimSealCount), so a slot whose block is still the
	// same canonical one is a no-op.
	// R26 (2026-10-30) FIX (auditor finding D1) / R28 (2026-10-30) GENERALISED:
	// a seal recorded for a slot inside the ABANDONED range (common ancestor,
	// replaced head] attests a block that is not canonical any more. Its
	// persisted "matches" classification must be dropped to Unknown — without
	// it the public RPCs kept reporting the reorged-away block as final. The
	// range form (rather than only the slots whose root this reorg deleted)
	// also covers records whose per-slot root was PRUNED before the reorg: the
	// live classification is Unknown for them, so GetSlotSealDetails falls back
	// to the persisted value and would otherwise resurrect the stale verdict.
	// Re-anchored slots are excluded — reconcileCanonicalSeal just re-classified
	// them from the new canonical root. The record itself (the
	// threshold-agreement proof) always survives.
	if qfs != nil {
		for s, r := range applied {
			qfs.reconcileCanonicalSeal(s, r)
		}
		qfs.invalidateCanonicalSealsInRange(cleanMin, cleanMax, applied)
	}
	return true
}

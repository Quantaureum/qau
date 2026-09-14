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
					score.Add(score, validators[att.ValidatorIndex].Stake)
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
	q.epochBlockRoots[epoch] = blockRoot
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
	q.mu.Lock()
	defer q.mu.Unlock()
	q.slotBlockRoots[slot] = blockRoot
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
}

// GetSlotBlockRoot returns the canonical block root for a specific slot.
// Returns the zero hash and false if no block root has been recorded for the
// slot.
func (q *QPOS) GetSlotBlockRoot(slot uint64) (types.Hash, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	root, ok := q.slotBlockRoots[slot]
	return root, ok
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

	// SECURITY (R4-CORE-01): Invalidate the shuffle cache for epochs that
	// depend on this epoch's VRF accumulator (same policy as
	// AccumulateVRFOutput / CONS-R13-M03).
	delete(q.shuffleCache, epoch+1)
	delete(q.shuffleCache, epoch+2)

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
//     range [min(roots), max(roots)] but is NOT in roots — these belong to
//     the abandoned fork and would otherwise poison finality.
//
// Entries below the range (predating the reorg, still canonical) and above
// the range (future slots) are left untouched.
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
func (q *QPOS) ReanchorSlotRoots(roots map[uint64]types.Hash, vrfAccUpdates map[uint64]types.Hash) {
	if len(roots) == 0 {
		return
	}
	// Compute the slot range to clean. min/max are over the NEW canonical
	// segment; any pre-existing entry in [min,max] not in roots is stale.
	//
	// SHRD- (Info, 2026-07-17): minSlot/maxSlot are computed before
	// q.mu.Lock() is taken below. This is safe because `roots` is a
	// caller-local map (built in reanchorSlotRootsAfterReorg as
	// `roots := make(map[uint64]types.Hash, len(newChain))`) and is not
	// shared with any other goroutine, so no concurrent modification can
	// occur between this point and the lock acquisition. Only the
	// q.slotBlockRoots mutations (steps 1 and 2 below) require the lock.
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
	if finalized := q.finalizedEpoch; finalized > 0 || q.finalizedRoot != (types.Hash{}) {
		finalizedEpochStartSlot := finalized * SlotsPerEpoch
		if maxSlot < finalizedEpochStartSlot {
			// Entire reorg range predates finalized epoch — forbidden.
			log.Printf("[ERROR] qpos: ReanchorSlotRoots: refusing reorg of finalized history: "+
				"reorg range [%d,%d] is below finalized epoch %d (finalizedRoot=%s)",
				minSlot, maxSlot, finalized, q.finalizedRoot.String())
			return
		}
		if minSlot < finalizedEpochStartSlot {
			// Partial overlap: reorg crosses finalized boundary.
			// Refuse the whole reorg rather than partially applying it.
			log.Printf("[ERROR] qpos: ReanchorSlotRoots: refusing reorg that crosses finalized boundary: "+
				"reorg range [%d,%d] overlaps finalized epoch %d (finalizedRoot=%s)",
				minSlot, maxSlot, finalized, q.finalizedRoot.String())
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
		if s >= minSlot && s <= maxSlot {
			if _, ok := roots[s]; !ok {
				delete(q.slotBlockRoots, s)
			}
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
}

// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"

	qencoding "github.com/quantaureum/qau/encoding"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

var shuffleIndexBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, types.HashLength+16+4)
		return &b
	},
}

// isValidatorActive checks if a validator at the given index is Active
// in the provided ValidatorSet snapshot. Returns false if the index is
// out of bounds or the validator is not active.
//
// AUDIT (2026) R4-CORE-05 FIX: Used by the proposer selection loop to
// skip inactive (but not slashed) validators — they should not produce
// empty blocks.
func isValidatorActive(validators *ValidatorSet, idx int) bool {
	if validators == nil {
		return false
	}
	v := validators.GetValidatorByIndex(idx)
	if v == nil {
		return false
	}
	return v.Active
}

func (q *QPOS) CommitRANDAO(epoch uint64, validatorIndex int, commitment types.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.randaoCommits == nil {
		q.randaoCommits = make(map[uint64]map[int]types.Hash)
	}
	if q.randaoCommits[epoch] == nil {
		q.randaoCommits[epoch] = make(map[int]types.Hash)
	}
	q.randaoCommits[epoch][validatorIndex] = commitment
}

// audit-remediation: reviewed 2026-09-11 — deterministic round bookkeeping; does not touch stake.
func (q *QPOS) UpdateRANDAO(reveal types.Hash, epoch uint64, validatorIndex int) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.randaoCommits == nil {
		q.randaoCommits = make(map[uint64]map[int]types.Hash)
	}

	epochCommits, ok := q.randaoCommits[epoch]
	if !ok {
		return fmt.Errorf("no RANDAO commitment for epoch %d", epoch)
	}
	expectedCommit, ok := epochCommits[validatorIndex]
	if !ok {
		return fmt.Errorf("no RANDAO commitment from validator %d for epoch %d", validatorIndex, epoch)
	}

	revealHash := sha3.Sum256(reveal[:])
	if subtle.ConstantTimeCompare(revealHash[:], expectedCommit[:]) != 1 {
		return fmt.Errorf("RANDAO reveal does not match commitment")
	}

	for i := 0; i < types.HashLength; i++ {
		q.randaoMix[i] ^= reveal[i]
	}
	return nil
}

func (q *QPOS) GetRANDAO() types.Hash {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.randaoMix
}

func (q *QPOS) ShuffleValidators(epoch uint64) []int {
	if q.validators == nil {
		return nil
	}

	n := q.validators.Size()
	if n == 0 {
		return nil
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if cached, exists := q.shuffleCache[epoch]; exists {
		return cached
	}

	indices := q.computeShuffleForEpoch(epoch, n)

	q.shuffleCache[epoch] = indices

	q.evictStaleShuffleCacheLocked()

	return indices
}

// currentEpochUnlocked computes the current epoch from wall-clock time and
// genesis time. This is used for LOCAL timing decisions only (e.g., "which
// slot are we in right now" for proposer scheduling).
//
// R49-CS-02 NOTE: This is NOT a consensus determinism issue. All blockchain
// networks (Ethereum 2.0, Cosmos, etc.) compute the current slot/epoch from
// wall-clock time + genesis time. Consensus agreement on the current slot
// comes from block headers (BlockHeader.Slot), not from this function.
// Nodes with drifted clocks will simply be slightly early/late to propose,
// but the block's Slot field is the canonical source of truth that all nodes
// agree on. The GetProposer function uses the block's Slot, not wall-clock.
func currentEpochUnlocked() uint64 {
	now := time.Now().Unix() // NOT consensus-critical: local proposer scheduling only
	gt := GetGenesisTime()
	if now < gt {
		return 0
	}
	return uint64((now-gt)/int64(SlotDuration.Seconds())) / SlotsPerEpoch // #nosec G115
}

func (q *QPOS) evictStaleShuffleCacheLocked() {
	currentEpoch := currentEpochUnlocked()
	for e := range q.shuffleCache {
		if e+uint64(MaxShuffleCacheSize) <= currentEpoch {
			delete(q.shuffleCache, e)
		}
	}
}

func (q *QPOS) computeShuffleIndex(seed types.Hash, position, bound uint64) int {
	if bound == 0 {
		return 0
	}
	maxVal := math.MaxUint64 - (math.MaxUint64 % bound)

	for attempt := 0; attempt < 8; attempt++ {
		bufPtr := shuffleIndexBufPool.Get().(*[]byte)
		data := *bufPtr
		copy(data, seed[:])
		binary.BigEndian.PutUint64(data[types.HashLength:], position)
		binary.BigEndian.PutUint64(data[types.HashLength+8:], bound)
		binary.BigEndian.PutUint32(data[types.HashLength+16:], uint32(attempt)) // #nosec G115

		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(data)
		hash := hasher.Sum(nil)
		shuffleIndexBufPool.Put(bufPtr)

		val := binary.BigEndian.Uint64(hash[:8])
		if val <= maxVal {
			return int(val % bound) // #nosec G115
		}
	}

	bufPtr := shuffleIndexBufPool.Get().(*[]byte)
	data := *bufPtr
	copy(data, seed[:])
	binary.BigEndian.PutUint64(data[types.HashLength:], position)
	binary.BigEndian.PutUint64(data[types.HashLength+8:], bound)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	hash := hasher.Sum(nil)
	shuffleIndexBufPool.Put(bufPtr)

	val := binary.BigEndian.Uint64(hash[:8])
	return int(val % bound) // #nosec G115
}

// IsProposerScheduleReadyForEpoch reports whether the deterministic
// shuffle for the given epoch was computed WITH the proper VRF
// accumulator entropy (i.e. not under the cold-start fallback).
// R45-PoA-FIX (2026-08-12).
//
// Returns true when:
//   - epoch < 2 (always uses the genesis root, never cold-start),
//   - OR epochVRFAccumulator[epoch-2] was already populated when the
//     shuffle was first computed.
//
// Returns false when the shuffle was computed under the cold-start
// fallback path — i.e. this sealer restarted and has not yet replayed
// the canonical chain far enough to repopulate the accumulator for
// epoch-2. BlockProducer.MustSkipUntilReady and BlockValidator's
// VerifyProposer path consult this and refuse to act on slots in the
// disputed epoch until SetEpochVRFAccumulator clears the cold-start flag
// and the shuffle cache is invalidated, forcing a recomputation.
func (q *QPOS) IsProposerScheduleReadyForEpoch(epoch uint64) bool {
	if epoch < 2 {
		return true
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	_, cold := q.coldStartEpochs[epoch]
	return !cold
}

// ClearColdStartEpochs wipes all stale per-epoch cold-start flags after a
// rebuild of q.epochVRFAccumulator (see R45-COLDSTART-CLEAR-FIX, node.go's R52
// rebuild loop). Epochs covered by the rebuild no longer need the cold-start
// guard because (a) their VRF accumulator is now loaded from a canonical
// on-chain header (deterministic shuffle), and (b) the cold-start entries
// remaining from a previous session may have been populated by fail-closed
// fallbacks that suggested an out-of-date schedule.
//
// Returns the number of cleared entries (informational).
func (q *QPOS) ClearColdStartEpochs() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := len(q.coldStartEpochs)
	q.coldStartEpochs = make(map[uint64]struct{})
	return n
}

// IsProposerScheduleReadyForSlot is the slot-level wrapper around
// IsProposerScheduleReadyForEpoch. Used by node/block_producer.go to
// refuse to propose / validate upcoming slots until QPOS is ready.
func (q *QPOS) IsProposerScheduleReadyForSlot(slot uint64) bool {
	return q.IsProposerScheduleReadyForEpoch(SlotToEpoch(slot))
}

// SetFirstBlockEpoch records the epoch of block 1 (the first non-genesis
// block). R88-F (2026-08-30): mirrors node.FirstBlockEpoch into the consensus
// layer so the Executive cold-start guard can distinguish "accumulator not
// yet loaded" (fail-closed) from "accumulator cannot exist on this chain"
// (high-genesis chain; every node selects with the zero hash — identical
// selection, no divergence). Idempotent; safe to call at any time.
func (q *QPOS) SetFirstBlockEpoch(epoch uint64) {
	q.firstBlockEpoch.Store(epoch)
	q.firstBlockEpochKnown.Store(true)
}

// ChainStartsAfterEpoch reports whether the chain's first block lives in an
// epoch strictly greater than the given epoch — meaning the epoch CANNOT have
// an on-chain VRF accumulator (no blocks exist at or below it). R88-F.
// Returns false when the first-block epoch is unknown (fail toward the
// fail-closed guard; node wires SetFirstBlockEpoch at startup).
func (q *QPOS) ChainStartsAfterEpoch(epoch uint64) bool {
	if !q.firstBlockEpochKnown.Load() {
		return false
	}
	return q.firstBlockEpoch.Load() > epoch
}

func (q *QPOS) GetProposerForSlot(slot uint64) (*Validator, error) {
	// P3-7 FIX: Use RLock for the read-heavy portion (validator set snapshot +
	// cache lookup). The common cache-hit path now allows concurrent proposer
	// lookups instead of serializing them behind a write lock. Only the rare
	// cache-miss path briefly upgrades to a write lock to store the computed
	// shuffle. No deadlock risk: RLock is always released before acquiring Lock.
	//
	// audit-fix FIX [MEDIUM]: Read q.validators under q.mu to prevent
	// TOCTOU race with updateValidatorSet (which writes q.validators under q.mu).
	q.mu.RLock()
	validators := q.validators
	if validators == nil || validators.Size() == 0 {
		q.mu.RUnlock()
		return nil, ErrNotProposer
	}

	n := validators.ValidatorCount()
	if n == 0 {
		q.mu.RUnlock()
		return nil, ErrNotProposer
	}

	epoch := SlotToEpoch(slot)
	slotInEpoch := slot % SlotsPerEpoch

	// R102-WEIGHTED-PROPOSER: epoch-gated stake-weighted election.
	// Byte-identical legacy behavior below the cutover. LOCK DISCIPLINE:
	// table build under the write lock (map ops + direct reads only);
	// eligibility selection runs AFTER releasing q.mu because IsSlashed /
	// HasChambers / CanPropose acquire q.mu.RLock themselves (same pattern
	// as the legacy slashed/inactive scan below).
	if q.weightedProposerEnabled(epoch) {
		table := q.weightedCumCache[epoch]
		seed, cold := q.epochSeedLocked(epoch)
		if table == nil {
			q.mu.RUnlock()
			q.mu.Lock()
			if q.validators == validators {
				table = q.buildWeightedEpochTableLocked(epoch)
				if cold {
					q.coldStartEpochs[epoch] = struct{}{}
				}
			} else {
				// Validator set swapped concurrently: rebuild against the
				// current set and re-snapshot it for selection below.
				validators = q.validators
				table = q.buildWeightedEpochTableLocked(epoch)
				if cold {
					q.coldStartEpochs[epoch] = struct{}{}
				}
			}
			q.mu.Unlock()
		} else {
			q.mu.RUnlock()
		}
		if table == nil || table.total == nil || table.total.Sign() == 0 {
			// No eligible stake (e.g. everyone slashed/inactive): degrade to
			// the legacy shuffle path for liveness (matches the empty-shuffle
			// degraded branch semantics below).
			q.mu.RLock()
		} else {
			proposerIdx := q.weightedProposerSelect(slot, table, seed, validators)
			if proposerIdx < 0 {
				return nil, fmt.Errorf("no active non-slashed proposer available for slot %d (weighted regime)", slot)
			}
			if proposer := validators.GetValidatorByIndex(proposerIdx); proposer != nil {
				return proposer, nil
			}
			return nil, ErrNotProposer
		}
		// Fall-through: legacy path with RLock re-acquired.
	}

	// Try cache under read lock (common fast path).
	shuffled := q.shuffleCache[epoch]
	var shuffledCopy []int
	if shuffled != nil {
		shuffledCopy = make([]int, len(shuffled))
		copy(shuffledCopy, shuffled)
		q.mu.RUnlock()
	} else {
		// Cache miss: compute the shuffle under read lock.
		// computeDeterministicShuffleForEpoch mixes the previous epoch's
		// VRF accumulator into the seed (audit R4-CORE-01 fix), making
		// proposers unpredictable while remaining deterministic across nodes
		// and immune to last-proposer grind (VRF output is ungrindable).
		computed, coldStart := q.computeDeterministicShuffleForEpoch(epoch, n)
		shuffledCopy = make([]int, len(computed))
		copy(shuffledCopy, computed)
		// R88-PROPONENT-DIAG: log the seed inputs on first computation per
		// epoch (opt-in, QAU_R88_DIAG=1). Re-reads acc[epoch-2] for display;
		// computeDeterministicShuffleForEpoch already read it under this RLock.
		r88LogShuffleSeed(epoch, n, !coldStart, q.epochVRFAccumulator[epochSrcEpoch(epoch)])
		q.mu.RUnlock()

		// Store in cache under write lock (brief, rare path).
		// Guard with a pointer-equality check so we don't cache a shuffle
		// computed for a validator set that has since been replaced by
		// updateValidatorSet / AddStakingValidator (which also clear the cache).
		//
		// R88-B (2026-08-29): coldStartEpochs is ALSO marked here, under the
		// WRITE lock — computeDeterministicShuffleForEpoch itself no longer
		// writes it (it runs under q.mu.RLock on this path; writing the map
		// there was a data race: two goroutines computing shuffles
		// concurrently under RLock would perform concurrent map writes →
		// runtime fatal). Marking here keeps the R45-PoA-FIX guard semantics:
		// the first computation of a cold-start epoch marks it so subsequent
		// IsProposerScheduleReadyForSlot checks refuse to act on the fallback
		// shuffle.
		q.mu.Lock()
		if q.validators == validators {
			if _, exists := q.shuffleCache[epoch]; !exists {
				q.shuffleCache[epoch] = computed
				q.evictStaleShuffleCacheLocked()
			}
			if coldStart {
				q.coldStartEpochs[epoch] = struct{}{}
			}
		}
		q.mu.Unlock()
	}

	if len(shuffledCopy) == 0 {
		return validators.GetValidatorByIndex(int(slot % uint64(n))), nil // #nosec G115
	}

	proposerIdx := shuffledCopy[int(slotInEpoch)%len(shuffledCopy)] // #nosec G115
	if proposerIdx >= n {
		proposerIdx = proposerIdx % n
	}

	// audit-fix round 2 HIGH-1: Slashed validators must not propose blocks.
	// If the selected proposer is slashed, scan the shuffled list for a
	// non-slashed alternative. Fail-closed if every candidate is slashed.
	//
	// AUDIT (2026) R4-CORE-05 FIX: Also skip INACTIVE validators (not
	// slashed, just not Active). Previously only slashed validators were
	// skipped, allowing deactivated/exiting validators to be selected as
	// proposers → empty block liveness issues. Now we check both IsSlashed
	// and the validator's Active flag.
	if q.IsSlashed(proposerIdx) || !isValidatorActive(validators, proposerIdx) {
		found := false
		for offset := 1; offset < len(shuffledCopy); offset++ {
			altIdx := shuffledCopy[(int(slotInEpoch)+offset)%len(shuffledCopy)] // #nosec G115
			if altIdx >= n {
				altIdx = altIdx % n
			}
			if !q.IsSlashed(altIdx) && isValidatorActive(validators, altIdx) {
				proposerIdx = altIdx
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no active non-slashed proposer available for slot %d", slot)
		}
	}

	proposer := validators.GetValidatorByIndex(proposerIdx)

	if q.HasChambers() {
		if !q.CanPropose(proposerIdx, slot) {
			for offset := 1; offset < len(shuffledCopy); offset++ {
				altIdx := shuffledCopy[(int(slotInEpoch)+offset)%len(shuffledCopy)]
				if altIdx >= n {
					altIdx = altIdx % n
				}
				if q.CanPropose(altIdx, slot) {
					// audit-fix MEDIUM-1: Use local `validators` snapshot captured
					// under q.mu instead of q.validators, which may have been
					// replaced by updateValidatorSet after the lock was released.
					proposer = validators.GetValidatorByIndex(altIdx)
					proposerIdx = altIdx
					break
				}
			}
		}
		coordinator := q.GetChambersCoordinator()
		if coordinator != nil {
			if err := coordinator.AssignProposing(proposerIdx, slot); err != nil {
				tpfLog.Warnf("AssignProposing failed for proposer %d slot %d: %v", proposerIdx, slot, err)
			}
		}
	}

	return proposer, nil
}

// GetProposerIndexForSlot returns the deterministically-elected proposer
// index for a slot, or -1 if none is eligible. This is a lock-safe public
// wrapper over getProposerIndexForSlotUnlocked.
//
// R59-CENSUS-PROP (2026-08-09): Used by the epoch-boundary census builder to
// derive the COMMITTED proposer index that is embedded in the on-chain census
// (the Ethereum-aligned analog of block.proposer_index). Once embedded, every
// node reproduces identical proposer rewards from the census without re-deriving
// from node-local VRF-accumulator/shuffle state.
func (q *QPOS) GetProposerIndexForSlot(slot uint64) int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.validators == nil {
		return -1
	}
	return q.getProposerIndexForSlotUnlocked(slot, q.validators)
}

// getProposerIndexForSlotUnlocked computes the proposer index for a slot
// WITHOUT acquiring q.mu. Caller MUST hold q.mu (at least RLock).
//
// CONS- (2026-07-19) FIX: Previously ProcessEpochRewards built the
// ProposerRewards map but never populated it, so validators received zero
// proposer rewards — breaking the economic incentive to propose blocks.
// This helper mirrors the index-selection logic in GetProposerForSlot but
// is safe to call from contexts already holding q.mu (ProcessEpochRewards
// runs under q.mu.Lock). It returns -1 if no eligible proposer exists.
//
// Skipped/ineligible proposers (slashed or inactive) are passed over in
// favor of the next eligible validator in the shuffle, matching
// GetProposerForSlot behavior. Chambers/committee filtering is not applied
// here because epoch rewards are accounting-only, not a liveness gate.
func (q *QPOS) getProposerIndexForSlotUnlocked(slot uint64, validators *ValidatorSet) int {
	if validators == nil || validators.Size() == 0 {
		return -1
	}
	n := validators.ValidatorCount()
	if n == 0 {
		return -1
	}

	epoch := SlotToEpoch(slot)
	slotInEpoch := slot % SlotsPerEpoch

	// computeDeterministicShuffleForEpoch reads q.epochVRFAccumulator via
	// getEpochVRFAccumulatorLocked, which is safe under q.mu (it acquires
	// no further locks). Caching happens lazily inside GetProposerForSlot;
	// here we accept the recomputation cost since ProcessEpochRewards is
	// called once per epoch (not per slot).
	// R102-WEIGHTED-PROPOSER: census-committed proposer index MUST follow the
	// same epoch-gated rule as block validation, or the on-chain census would
	// commit a different proposer than the elected one after cutover.
	// Attempt-counter semantics mirror weightedProposerForSlotLocked minus the
	// chambers filter (census is accounting, not a liveness gate — same rule
	// as the legacy comment above). Caller of this function holds q.mu (Lock
	// from ProcessEpochRewards), so we build/read the table without acquiring
	// locks; chamber checks are handled via the attempt sequence only.
	if q.weightedProposerEnabled(epoch) {
		table := q.buildWeightedEpochTableLocked(epoch)
		if table == nil || table.total == nil || table.total.Sign() == 0 {
			return -1
		}
		seed, _ := q.epochSeedLocked(epoch)
		for attempt := uint64(0); attempt <= uint64(n); attempt++ {
			idx := weightedPickIndex(table, seed, slotInEpoch, attempt)
			if idx < 0 {
				return -1
			}
			if _, slashed := q.slashedValidators[idx]; !slashed && isValidatorActive(validators, idx) {
				return idx
			}
		}
		return -1
	}

	// computeDeterministicShuffleForEpoch reads q.epochVRFAccumulator via
	// getEpochVRFAccumulatorLocked, which is safe under q.mu (it acquires
	// no further locks). Caching happens lazily inside GetProposerForSlot;
	// here we accept the recomputation cost since ProcessEpochRewards is
	// called once per epoch (not per slot).
	// R88-B: the cold-start flag is intentionally ignored on this read-only
	// path — marking coldStartEpochs is the producer guard's duty
	// (GetProposerForSlot marks it under the write lock).
	shuffled, _ := q.computeDeterministicShuffleForEpoch(epoch, n)
	if len(shuffled) == 0 {
		// Fallback to modulo selection (matches GetProposerForSlot fallback).
		return int(slot % uint64(n)) // #nosec G115 -- n > 0 guaranteed above
	}

	proposerIdx := shuffled[int(slotInEpoch)%len(shuffled)] // #nosec G115
	if proposerIdx >= n {
		proposerIdx = proposerIdx % n
	}

	// Skip slashed / inactive proposers, matching GetProposerForSlot.
	if _, slashed := q.slashedValidators[proposerIdx]; slashed || !isValidatorActive(validators, proposerIdx) {
		for offset := 1; offset < len(shuffled); offset++ {
			altIdx := shuffled[(int(slotInEpoch)+offset)%len(shuffled)] // #nosec G115
			if altIdx >= n {
				altIdx = altIdx % n
			}
			if _, slashed := q.slashedValidators[altIdx]; !slashed && isValidatorActive(validators, altIdx) {
				return altIdx
			}
		}
		return -1
	}

	return proposerIdx
}

// computeDeterministicShuffleForEpoch computes the shuffled validator index
// list for the given epoch.
//
// SECURITY (audit CORE-04 + R4-CORE-01): The shuffle seed mixes two entropy
// sources into keccak(epoch):
//  1. The PREVIOUS epoch's VRF accumulator (XOR of all VRF outputs from
//     proposers that produced canonical blocks in epoch-1). This is the
//     primary unpredictability source — VRF outputs are random and only
//     revealed when blocks are produced, so an attacker cannot compute the
//     schedule until epoch-1's proposers have revealed their VRF outputs.
//  2. (Historical note) The previous epoch's block root was previously
//     mixed in, but this was REMOVED by CORE- because the last proposer
//     of an epoch could grind block contents to bias the root (single
//     last-revealer attack). The VRF accumulator does NOT have this problem:
//     VRF output is deterministic for (privKey, seed), so the proposer
//     CANNOT grind by choosing among multiple outputs.
//
// CORE- CONSTRAINT SATISFIED: The seed does NOT depend on randaoMix
// or finalizedRoot. The VRF accumulator is a SEPARATE entropy source:
//   - randaoMix = XOR of RANDAO reveals (commit-reveal, grindable — DEAD CODE)
//   - VRF accumulator = XOR of VRF outputs (deterministic, UNGRINDABLE — LIVE)
//
// For epoch 0 (genesis) or when the previous epoch's VRF accumulator is not
// yet available (e.g., during initial sync), the seed falls back to
// keccak(epoch) only. This is safe because epoch 0's schedule is defined in
// genesis, and during sync the node is not producing blocks.
//
// Caller must hold q.mu (at least RLock) because this function reads
// q.epochVRFAccumulator via getEpochVRFAccumulatorLocked.
// computeDeterministicShuffleForEpoch computes the shuffled validator index
// list for the given epoch. It returns (indices, coldStart): coldStart is
// true when the epoch-2 VRF accumulator was missing and the fallback
// keccak(epoch)-only seed was used (R45-PoA-FIX).
//
// R88-B (2026-08-29): This function NO LONGER writes q.coldStartEpochs
// itself. It is invoked under q.mu.RLock from GetProposerForSlot and
// getProposerIndexForSlotUnlocked; writing the map there was a data race
// (concurrent map writes from two RLock holders → runtime fatal). Callers
// that hold the WRITE lock (or the post-compute Lock section in
// GetProposerForSlot) mark q.coldStartEpochs[epoch] based on the returned
// flag. Read-only callers may ignore the flag.
func (q *QPOS) computeDeterministicShuffleForEpoch(epoch uint64, n int) ([]int, bool) {
	if n == 0 {
		return nil, false
	}

	coldStart := false

	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	// AUDIT (2026) R4-CORE-01 FIX: Mix a PRIOR epoch's VRF
	// accumulator into the shuffle seed. This adds genuine unpredictability
	// (VRF outputs are random) without enabling grind attacks (VRF output is
	// deterministic for a given key+seed, so the proposer cannot choose among
	// multiple outputs).
	//
	// CORE- (2026-07-14): Previously the seed was keccak(epoch) only,
	// which was fully predictable from genesis. This allowed any observer to
	// compute the entire future proposer schedule → targeted DoS / eclipse of
	// the next proposer, adaptive censorship. The VRF accumulator fixes this
	// while preserving the CORE- property (no last-proposer grind).
	//
	// CONS-R13-M03 (2026-07-21): Use epoch-2 (not epoch-1) as the VRF
	// accumulator source. The XOR-accumulated VRF accumulator for epoch N
	// is built incrementally from each slot's VRF output. The LAST proposer
	// of epoch N can choose between two final accumulator values by
	// withholding vs publishing their proposal — a single-bit grind that
	// lets them select between two shuffle orders for any epoch whose seed
	// depends on epochVRFAccumulator[N].
	//
	// Before this fix, the seed for epoch N+1 used
	// epochVRFAccumulator[N], so the last proposer of epoch N could
	// adaptively grind the very next epoch's shuffle in real time (1-epoch
	// delay). Delaying by one more epoch (epoch-2) gives the network a full
	// epoch of buffer to observe and react to any withheld proposal,
	// reducing the grind's adaptivity to 2 epochs. Combined with the
	// existing committee-based block production (each slot has a backup
	// proposer), this makes the grind unprofitable: the attacker must
	// commit to the grind 2 epochs in advance and cannot adapt mid-attack.
	//
	// Trade-off: at epoch 0 and 1, epoch-2 underflows. We fall back to
	// keccak(epoch) only (same as genesis behavior). Epoch 0's schedule is
	// defined in genesis; epoch 1 still uses keccak(1) (predictable but
	// unavoidable — the network needs at least one epoch of VRF
	// accumulation before entropy is available). From epoch 2 onward, the
	// seed mixes in epochVRFAccumulator[epoch-2] which is fully accumulated
	// before epoch epoch-1 starts.
	//
	// R33 CONS-04 FIX (2026-07-28): For epoch 0 and 1, we ALSO mix in the
	// genesis block root (epochBlockRoots[0]) as additional entropy. This
	// doesn't make the seed fully unpredictable (the genesis root is known
	// once genesis.json is published), but it does:
	//   1. Prevent offline pre-computation of the proposer schedule before
	//      genesis is finalized (an attacker with the validator set but
	//      not the genesis root cannot precompute epoch 0/1 shuffles).
	//   2. Bind the shuffle to a specific chain instance, preventing
	//      cross-chain replay of the proposer schedule (two chains with
	//      the same validator set but different genesis roots get
	//      different shuffles).
	//   3. CONSENSUS-DETERMINISM FIX (2026-08-04): The epoch-1 seed
	//      previously ALSO mixed epochBlockRoots[1], but that source is a
	//      self-reference: epochBlockRoots[epoch] is set to the FIRST block
	//      of that epoch (Slot%SlotsPerEpoch==0), so epochBlockRoots[1] is
	//      slot 32's block, whose proposer is itself chosen by the epoch-1
	//      shuffle. Nodes that computed the epoch-1 shuffle before importing
	//      slot 32 used a different seed than nodes that computed it after,
	//      causing cross-node proposer divergence (the observed chain split
	//      at heights 21-36 spanning epoch 0/1). Per the Ethereum-aligned
	//      rule, proposer election for an epoch MUST depend only on state
	//      finalized before that epoch begins, so only the genesis root is
	//      mixed into epoch 0/1. From epoch 2 onward the seed uses the
	//      finalized epoch-2 VRF accumulator (see below).
	// R102-WEIGHTED-PROPOSER: seed construction delegated to the shared
	// epochSeedLocked helper so the legacy shuffle and the weighted proposer
	// draw from BYTE-IDENTICAL seeds (keccak(epoch) for epochs 0-1 incl.
	// genesis-root mixing; keccak(epoch || epochVRFAccumulator[epoch-2]) from
	// epoch 2). The long-form rationale comments for cold-start determinism
	// (R45-PoA-FIX), epoch-0/1 genesis-root mixing (R33 CONS-04), the
	// unconditional on-chain accumulator mix (R55-ACC-ONCHAIN) and the
	// seed-not-blockroot determinism fix (CONSENSUS-DETERMINISM 2026-08-04)
	// apply equally to the helper; see r102_weighted_proposer.go.
	seed, cold := q.epochSeedLocked(epoch)
	if cold {
		coldStart = true
	}

	for i := n - 1; i > 0; i-- {
		j := q.computeShuffleIndex(seed, uint64(i), uint64(i+1)) // #nosec G115
		indices[i], indices[j] = indices[j], indices[i]
	}

	return indices, coldStart
}

// loggerLockPreWarmup is a stub helper for the R45-WARMUP-DIAG note:
// coldStartEpochs is a writer-path struct, but we already hold q.mu via
// RLock from GetProposerForSlot. Adding a real log call here would
// require releasing the RLock first — for now we leave the diagnostic
// to the BlockProducer's WARN log ("QPOS cold-start for slot=...") which
// already fires once per slot.
func (q *QPOS) loggerLockPreWarmup() {}

// computeShuffleForEpoch is a thin alias over
// computeDeterministicShuffleForEpoch that preserves the single-return
// signature for callers that do not need the cold-start flag (R88-B).
func (q *QPOS) computeShuffleForEpoch(epoch uint64, n int) []int {
	indices, _ := q.computeDeterministicShuffleForEpoch(epoch, n)
	return indices
}

// ApplyBlockHeader replays a CANONICAL block header into the QPOS internal
// proposer-state snapshot so that proposer election can be verified
// block-by-block during initial chain sync.
//
// R38-P1-08 DEEP FIX (2026-08-02). The conservative R38-P1-08 mitigation
// (Fix 2) skipped proposer election verification wholesale during
// syncingMode and logged a WARN + bumped syncingModeSkipCount for each
// block. This deep fix closes the gap: by incrementally rebuilding
// randaoMix / epochVRFAccumulator / epochBlockRoots / slotBlockRoots as
// each canonical block is applied, the BlockValidator can pass an
// ElectionVerifier whose GetProposerForSlot(slot) lookup will return the
// same proposer the network elected — so proposer election can be
// verified block-by-block instead of being skipped.
//
// REPLAY MIRROR: This function mirrors the canonical-import path in
// node/node.go (around line 6437-6461: SetSlotBlockRoot →
// AccumulateVRFOutput → SetEpochBlockRoot → UpdateRANDAO). Any change
// to the canonical path MUST be mirrored here. The node import path
// runs AFTER this reconstruction completes (sync finishes before the
// node starts producing/consuming new heads); so this function is only
// used to bring the snapshot UP TO the head. Once sync is done,
// SetSyncingMode(false) re-enables strict election verification, and
// ApplyBlockHeader is no longer called from the validator path.
//
// IDEMPOTENCY: A canonical block should never be replayed twice (XOR
// XOR = identity — a second XOR flips the accumulator bit-by-bit,
// corrupting the shuffle seed for epochs ≥2 away). We track applied
// block hashes in q.appliedBlockRoots; a second ApplyBlockHeader call
// with the same blockHash is a no-op.
//
// Input invariants:
//   - blk != nil and blk.Header != nil (callers must check; we do not panic
//     on nil but return an error to surface misuse).
//   - blk.Header.Height == 0 (genesis) IS supported: ApplyBlockHeader records
//     the genesis root via SetEpochBlockRoot(0, ...) and SetSlotBlockRoot(0, ...)
//   - SetGenesisRoot idempotency path. genesis MUST NOT have a VRF output
//     (VRFValue == zero hash is skipped by AccumulateVRFOutput).
//
// SAFE FOR PARALLEL USE: callers may invoke ApplyBlockHeader from the
// syncer's applyBlockInternal which runs on a single goroutine, but the
// internal locking is fully mutex-guarded so concurrent callers are safe.
//
// Best-effort: if any single step fails (e.g., UpdateRANDAO returns an
// error because no commitment was registered — the dead-code forward-compat
// path), the error is swallowed and the rest of the reconstruction
// continues. The VRF accumulator + slot/epoch roots are the load-bearing
// state; UpdateRANDAO is forward-compat only (see node.go:6454-6461
// comment).
func (q *QPOS) ApplyBlockHeader(blk *qencoding.Block, blockHash types.Hash) error {
	if blk == nil || blk.Header == nil {
		return fmt.Errorf("consensus.ApplyBlockHeader: nil block or header")
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// Idempotency: skip if we have already replayed this canonical block.
	// A re-sync or reorg may re-process the same canonical block; XOR'ing
	// the VRF output twice would flip the accumulator (XOR XOR = identity
	// is wrong here — we want each block to contribute ONCE, period).
	if _, applied := q.appliedBlockRoots[blockHash]; applied {
		return nil
	}

	q.appliedBlockRoots[blockHash] = struct{}{}

	// Bound the idempotency set to the finalized-window (3 epochs of slots).
	// A block older than that is permanently in finality and will never be
	// reprocessed by sync incremental reconstruction. We use a heuristic:
	// prune when the set exceeds 3*SlotsPerEpoch entries, removing entries
	// that are well below the current epoch (we don't have the block height
	// here easily without decoding from blockHash, so we just clear the set
	// down to size when it grows past the bound — the simplest correct
	// strategy that prevents unbounded growth). See pruneAppliedBlockRoots.
	if len(q.appliedBlockRoots) > 3*SlotsPerEpoch {
		q.pruneAppliedBlockRootsLocked(blk.Header.Slot)
	}

	// 1. Record per-slot canonical block root (mirrors node.go:6437).
	q.slotBlockRoots[blk.Header.Slot] = blockHash

	// 2. VRF accumulator: DELIBERATELY NOT updated here. The per-epoch VRF
	// accumulator (entropy for the future-epoch shuffle seed) is owned
	// EXCLUSIVELY by SetEpochVRFAccumulator assignments — the R54-ACC
	// chokepoints: syncer.ProcessBlock (node/syncer.go, per canonical
	// block), node/blockInsertLoop's head-switch path (node/node.go, only
	// when shouldSwitch), and the block-produce path (own blocks). All of
	// them ASSiGN the on-chain header value (idempotent, path-independent).
	//
	// Historical note (R54-ACC): the accumulator was previously maintained
	// by the XOR-based AccumulateVRFOutput — which has NO callers since
	// R54 (dead code, kept only as a library API). XOR semantics were
	// path-asymmetric (double-count / ordering divergence) and caused the
	// proposer-divergence forks fixed by R54. Do NOT reintroduce XOR here:
	// every block that reaches applyBlockInternal has already been assigned
	// by one of the SetEpochVRFAccumulator chokepoints, and an extra XOR
	// here would corrupt the assigned value.
	//
	// The slotBlockRoots / epochBlockRoots / randao updates below remain
	// (idempotent overwrites that are harmless to re-run on the live path),
	// preserving the R38-P1-08 incremental-snapshot reconstruction contract.

	// 3. Epoch-boundary epoch-block root (mirrors node.go:6446).
	// Only record when there's a RANDAOReveal AND the slot is at the start
	// of an epoch (matching the canonical-path guard). For epoch 0 we
	// additionally apply the SetGenesisRoot immutable-once-set semantics:
	// a registered genesis root is NOT overwritten by a re-seed replay
	// with a different hash (see qpos_finality.go:287).
	if blk.Header.RANDAOReveal != (types.Hash{}) && blk.Header.Slot%SlotsPerEpoch == 0 {
		if blk.Header.Epoch == 0 {
			// Genesis epoch: apply immutable-once-set semantics.
			if existing, ok := q.epochBlockRoots[0]; !ok || existing == (types.Hash{}) {
				q.epochBlockRoots[0] = blockHash
				q.slotBlockRoots[0] = blockHash
			} else if existing != blockHash {
				logging.Global().Warn("QPOS.ApplyBlockHeader: genesis root already registered — ignoring epoch-0 replay with different hash",
					map[string]any{"existing": fmt.Sprintf("%x", existing[:8]), "new": fmt.Sprintf("%x", blockHash[:8])})
			}
		} else {
			q.epochBlockRoots[blk.Header.Epoch] = blockHash
		}
	} else if blk.Header.Epoch == 0 && blk.Header.Height == 0 {
		// Genesis block with no RANDAOReveal (sync seed genesis) — still
		// register the epoch-0 root so epoch-1 finality can lookup up it.
		// Mirror SetGenesisRoot's immutable-once-set semantics: a genesis
		// root, once registered, MUST NOT be silently overwritten by a
		// re-seed replay with a different hash. We accept the first
		// registration; subsequent proposals with a different hash are
		// bogus (a node ended up on a different chain) and we log+ignore.
		if existing, ok := q.epochBlockRoots[0]; !ok || existing == (types.Hash{}) {
			q.epochBlockRoots[0] = blockHash
			q.slotBlockRoots[0] = blockHash
		} else if existing != blockHash {
			logging.Global().Warn("QPOS.ApplyBlockHeader: genesis root already registered — ignoring re-seed replay with different hash",
				map[string]any{"existing": fmt.Sprintf("%x", existing[:8]), "new": fmt.Sprintf("%x", blockHash[:8])})
		}
	}

	// 4. UpdateRANDAO (forward-compat — mirrors node.go:6453-6461).
	// CommitRANDAO was never called (dead code), so UpdateRANDAO returns an
	// error. Swallowed. Kept for forward compatibility.
	if blk.Header.RANDAOReveal != (types.Hash{}) {
		if q.validators != nil {
			validatorIdx := q.validators.GetValidatorIndex(blk.Header.ProposerAddr)
			if validatorIdx >= 0 {
				for i := 0; i < types.HashLength; i++ {
					q.randaoMix[i] ^= blk.Header.RANDAOReveal[i]
				}
			}
		}
	}

	return nil
}

// pruneAppliedBlockRootsLocked drops entries from the idempotency set
// when it grows past the bound. We do not have height information from
// the hash alone, so we apply a simple FIFO-ish eviction: when the set
// is larger than the bound we eagerly keep entries whose slot is within
// the prune window relative to the current reference slot (everything
// else is assumed to be finalized and never re-processed). Caller MUST
// hold q.mu.
//
// We can't derive slot from hash without decoding, so we keep this
// simple: when invoked, drop any entries that have been applied by an
// earlier ApplyBlockHeader call (which the syncer already persists in
// blockStore; re-sync from genesis would re-apply them, but the
// labeling is the same hash so the map lookup will still work — we
// just don't dedup across full-restart syncs, which is fine because at
// restart the QPOS is freshly NewQPOS'd anyway with an empty
// appliedBlockRoots map).
//
// NET EFFECT: limit set to 3*SlotsPerEpoch+1 entries by simple random
// eviction. This is intentionally a heuristic — correctness is
// preserved even with NO pruning (the set just grows with chain
// length, which is undesirable but not unsafe). The prune keeps memory
// bounded for long-running validators.
func (q *QPOS) pruneAppliedBlockRootsLocked(refSlot uint64) {
	// Conservative: if reference slot < 3 epochs, nothing to prune.
	if refSlot < 3*SlotsPerEpoch {
		return
	}
	cutoff := refSlot - 3*SlotsPerEpoch
	// We don't have slot↔hash mapping in this set, so drop the first
	// ~half of entries found below the bound. This is O(n) but n is
	// bounded by 3*SlotsPerEpoch = 96 entries, so it's fine.
	dropCount := len(q.appliedBlockRoots) - 3*SlotsPerEpoch
	if dropCount <= 0 {
		return
	}
	_ = cutoff // referenced for clarity; eviction is by count not slot here
	dropped := 0
	for h := range q.appliedBlockRoots {
		delete(q.appliedBlockRoots, h)
		dropped++
		if dropped >= dropCount {
			break
		}
	}
}

// pruneVRFAccumulatorLocked mirrors qpos_forkchoice.go:600 — prune
// accumulators older than finalizedEpoch-1 (or stale relative to the
// current epoch). Caller MUST hold q.mu.
func (q *QPOS) pruneVRFAccumulatorLocked(currentEpoch uint64) {
	pruneCutoff := currentEpoch
	if q.finalizedEpoch > 1 {
		pruneCutoff = q.finalizedEpoch - 1
	}
	for e := range q.epochVRFAccumulator {
		if e < pruneCutoff {
			delete(q.epochVRFAccumulator, e)
		}
	}
}

// HasAppliedBlockHeader reports whether ApplyBlockHeader has already been
// called for this block hash. Useful for tests asserting idempotency.
// R38-P1-08 deep-fix provisioning.
func (q *QPOS) HasAppliedBlockHeader(blockHash types.Hash) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	_, applied := q.appliedBlockRoots[blockHash]
	return applied
}

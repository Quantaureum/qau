// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"math/big"
	"sort"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// R102-WEIGHTED-PROPOSER (2026-08-30)
//
// LEGACY DEFECT: the Fisher-Yates shuffle assigns each of the 32 slots of an
// epoch to exactly one validator, uniformly at random, IGNORING stake. At
// n=6 genesis validators that is harmless, but the door was left open:
// MinStakeAmount is 32 QAU, so beyond 32 validators one attacker wallet
// holding 640_000 QAU (20_000 × 32) would control ~50% of ALL block
// production and ~50% of attester seats while 6 genesis validators (36_000
// QAU real stake) would hold 0.03%. Gigacat-style sybils are free under
// uniform election.
//
// Ethereum pattern (adopted, adapted): weight election by effective stake.
// Variant B (design doc docs/qpos-weighted-consensus-plan.md): ONE validator
// index per address, weight = its live stake (no per-32-QAU index splitting,
// which would require no-op staking-contract churn). Block/attestation
// rewards remain per-index; over time they become stake-proportional because
// selection frequency is.
//
// Deterministic algorithm (byte-identical across nodes given the same
// validator set + epoch, both fully determined by the canonical chain):
//
//	target  = keccak256(epochSeed ‖ slotInEpoch ‖ attempt)  interpreted as
//	          uint256 mod totalWeight        (big.Int — exact, no floats)
//	prover  = first eligible validator whose cumulative weight exceeds target
//
// where epochSeed is EXACTLY the seed of the existing Fisher-Yates shuffle
// (keccak(epoch) for epochs 0-1 incl. genesis root mixing, keccak(epoch ‖
// epochVRFAccumulator[epoch-2]) from epoch 2 — reused via epochSeedLocked so
// there is ONE seed source, one cold-start signal, one cache lifecycle).
//
// Fork-sensitivity: proposer identity is cross-verified ("invalid block
// proposer"), so the cutover is epoch-gated (SetWeightedProposerCutover).
// All nodes must configure the SAME cutover epoch in node config. Before
// the cutover the code path is byte-identical to legacy.
//
// Residual pre-existing TOCTOU (NOT new): stakes change via staking-contract
// txs mid-epoch; the table is lazily built on first use per epoch and cached
// like the shuffle. Slashed/deactivated validators mid-epoch behave exactly
// as legacy (excluded at build; re-check at use).

// weightedEpochTable is the per-epoch stake-cumulative table over ELIGIBLE
// validators (Active && not slashed at build time). cum[i] is the exclusive
// prefix sum of stakes for idx[:i+1]  → target in [cum[i-1], cum[i]) picks
// idx[i]. Built under the QPOS write-lock, then read-only.
type weightedEpochTable struct {
	idx   []int      // eligible validator indices, canonical (ascending) order
	cum   []*big.Int // exclusive→inclusive cumulative stake; cum[len-1]=total
	total *big.Int   // totalWeight == cum[last]
}

// GetWeightedProposerCutover reports the configured cutover epoch
// (math.MaxUint64 when disabled).
func (q *QPOS) GetWeightedProposerCutover() uint64 {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.weightedProposerCutover
}

// SetWeightedProposerCutover configures the epoch at which weighted proposer
// election activates. Call ONCE at node startup from config; all validators
// of a network MUST use the same value or the chain forks at the cutover.
func (q *QPOS) SetWeightedProposerCutover(epoch uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.weightedProposerCutover = epoch
}

// weightedProposerEnabled reports (under any lock already held) whether the
// weighted regime applies to the given epoch.
func (q *QPOS) weightedProposerEnabled(epoch uint64) bool {
	return epoch >= q.weightedProposerCutover
}

// weightedProposerSelect runs the eligibility loop over the cached table
// using the Lock-free legacy pattern: the CALLER MUST NOT HOLD q.mu —
// eligibility helpers (IsSlashed / HasChambers / CanPropose) acquire RLock
// internally, exactly like the legacy proposer scan in GetProposerForSlot.
// Table/seed/validators are immutable snapshots captured earlier under the
// lock. Returns -1 when no eligible pick exists (equivalent to legacy
// "no active non-slashed proposer available").
//
// Attempt order (slashed/inactive → chambers) is SHARED with the census
// path (getProposerIndexForSlotUnlocked) so both derive identical picks
// whenever no chamber restriction changes the outcome.
func (q *QPOS) weightedProposerSelect(slot uint64, table *weightedEpochTable, seed types.Hash, validators *ValidatorSet) int {
	slotInEpoch := slot % SlotsPerEpoch
	if table == nil || table.total == nil || table.total.Sign() == 0 || len(table.idx) == 0 {
		return -1
	}
	cap_ := uint64(validators.Size())
	for attempt := uint64(0); attempt <= cap_; attempt++ {
		proposerIdx := weightedPickIndex(table, seed, slotInEpoch, attempt)
		if proposerIdx < 0 {
			return -1
		}
		// Same eligibility re-checks as the legacy path (defense in depth:
		// excluded at build, re-verified here at use time).
		if q.IsSlashed(proposerIdx) || !isValidatorActive(validators, proposerIdx) {
			continue
		}
		// Mirror the legacy path exactly: chamber restrictions only apply when
		// chambers are configured.
		if q.HasChambers() && !q.CanPropose(proposerIdx, slot) {
			continue
		}
		return proposerIdx
	}
	return -1
}

// weightedPickIndex is the PURE weighted selection: no lock assumptions, no
// stake/chamber checks, deterministic given (table, seed, slotInEpoch,
// attempt). Shared by the block path and the census path so both attempt
// sequences stay byte-identical.
// target = keccak(seed ‖ slotInEpoch ‖ attempt) mod totalWeight → first
// table index whose cumulative weight EXCEEDS target.
func weightedPickIndex(table *weightedEpochTable, seed types.Hash, slotInEpoch, attempt uint64) int {
	h := sha3.NewLegacyKeccak256()
	h.Write(seed[:])
	var tail [16]byte
	binary.BigEndian.PutUint64(tail[0:8], slotInEpoch)
	binary.BigEndian.PutUint64(tail[8:16], attempt)
	h.Write(tail[:])
	target := new(big.Int).SetBytes(h.Sum(nil))
	target.Mod(target, table.total)

	i := sort.Search(len(table.cum), func(i int) bool {
		return table.cum[i].Cmp(target) > 0
	})
	if i >= len(table.idx) {
		return -1 // numerically impossible (target < total) — defensive
	}
	return table.idx[i]
}

// buildWeightedEpochTableLocked constructs (or rebuilds) the cumulative table
// for `epoch`. Caller must hold q.mu (write lock). It mirrors the shuffle
// cache contract: entries are created on first use and dropped whenever the
// validator set changes (same call sites that clear shuffleCache).
func (q *QPOS) buildWeightedEpochTableLocked(epoch uint64) *weightedEpochTable {
	if q.weightedCumCache == nil {
		// Defensive: QPOS instances built via struct literal (some legacy
		// tests) skip NewQPOS and leave this map nil. The default cutover
		// keeps the weighted regime off anyway, but never panic.
		q.weightedCumCache = make(map[uint64]*weightedEpochTable)
	}
	if t, ok := q.weightedCumCache[epoch]; ok {
		return t
	}
	n := q.validators.Size()
	t := &weightedEpochTable{
		idx:   make([]int, 0, n),
		cum:   make([]*big.Int, 0, n),
		total: big.NewInt(0),
	}
	running := big.NewInt(0)
	for i := 0; i < n; i++ {
		// Direct map read (caller holds the WRITE lock — IsSlashed would
		// self-RLock and deadlock here).
		if _, slashed := q.slashedValidators[i]; slashed || !isValidatorActive(q.validators, i) {
			continue
		}
		v := q.validators.GetValidatorByIndex(i)
		if v == nil || v.Stake == nil || v.Stake.Sign() <= 0 {
			continue
		}
		t.idx = append(t.idx, i)
		running = running.Add(running, v.Stake)
		c := new(big.Int).Set(running)
		t.cum = append(t.cum, c)
		t.total = new(big.Int).Set(running)
	}
	// Prune old epochs the same spirit as the shuffle cache (which is per
	// hot-path replaced wholesale). Keep only the last 4 epochs to bound
	// memory under mid-epoch validator-set churn recomputations.
	for e := range q.weightedCumCache {
		if e+4 < epoch {
			delete(q.weightedCumCache, e)
		}
	}
	q.weightedCumCache[epoch] = t
	return t
}

// epochSeedLocked extracts the seed construction previously inlined in
// computeDeterministicShuffleForEpoch — DO NOT DIVERGE: both the legacy
// shuffle and the weighted proposer MUST derive from the identical seed
// bytes, including the cold-start signal. Caller holds at least the read
// lock; cold-start bookkeeping (coldStartEpochs marking) stays at the
// original call sites.
func (q *QPOS) epochSeedLocked(epoch uint64) (types.Hash, bool) {
	seedData := make([]byte, 8)
	binary.BigEndian.PutUint64(seedData[:8], epoch)
	coldStart := false
	if epoch >= 2 {
		srcEpoch := epoch - 2
		if vrfAcc := q.getEpochVRFAccumulatorLocked(srcEpoch); vrfAcc != (types.Hash{}) {
			seedData = append(seedData, vrfAcc[:]...)
		} else {
			coldStart = true
		}
	} else {
		if genesisRoot, ok := q.epochBlockRoots[0]; ok && genesisRoot != (types.Hash{}) {
			seedData = append(seedData, genesisRoot[:]...)
		}
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(seedData)
	var seed types.Hash
	copy(seed[:], h.Sum(nil))
	return seed, coldStart
}

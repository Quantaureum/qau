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
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/quantaureum/qau/types"
)

// GetEpochSummary returns a summary of an epoch's activity
type EpochSummary struct {
	Epoch             uint64
	StartSlot         uint64
	EndSlot           uint64
	ProposedBlocks    int
	TotalAttestations int
	ParticipationRate float64
	IsJustified       bool
	IsFinalized       bool
}

// GetEpochSummary returns summary information for an epoch
func (q *QPOS) GetEpochSummary(epoch uint64) *EpochSummary {
	q.mu.RLock()
	defer q.mu.RUnlock()

	startSlot := EpochStartSlot(epoch)
	endSlot := startSlot + SlotsPerEpoch - 1

	totalAtts := 0
	for slot := startSlot; slot <= endSlot; slot++ {
		totalAtts += len(q.attestations[slot])
	}

	// Calculate participation rate.
	//
	// CONS- (2026-07-19) FIX: Previously this used
	// `q.validators.Size()` (TOTAL validator count, including inactive
	// and slashed validators) as the denominator. This is INCONSISTENT
	// with the finality path (qpos_finality.go tryUpdateFinality), which
	// only counts ACTIVE non-slashed validators toward the threshold.
	// When a large fraction of validators is inactive, the reported
	// participation rate would appear artificially low (e.g., 5 active
	// out of 10 total → 50% instead of 100% of the active set), which
	// misleads operators into thinking finality is at risk when it is
	// not, and masks real participation drops when inactive validators
	// come back online.
	//
	// Fix: compute the denominator from ACTIVE non-slashed validators
	// only, matching the finality threshold's accounting.
	// R46-CS-08 FIX: Guard against nil validators to prevent panic.
	activeValidatorCount := 0
	if q.validators != nil {
		for i, v := range q.validators.Validators() {
			if _, slashed := q.slashedValidators[i]; slashed {
				continue
			}
			if v.Active {
				activeValidatorCount++
			}
		}
	}
	expectedAtts := activeValidatorCount * int(SlotsPerEpoch)
	participationRate := 0.0
	if expectedAtts > 0 {
		participationRate = float64(totalAtts) / float64(expectedAtts)
	}

	return &EpochSummary{
		Epoch:             epoch,
		StartSlot:         startSlot,
		EndSlot:           endSlot,
		TotalAttestations: totalAtts,
		ParticipationRate: participationRate,
		IsJustified:       epoch <= q.justifiedEpoch,
		IsFinalized:       epoch <= q.finalizedEpoch,
	}
}

// ValidateSlotAttestations checks whether a slot has received the minimum
// number of attestations required for a block to be considered valid.
// audit-fix H-4: enforces MinAttestations per slot, not just at finality.
// Returns nil if the slot has sufficient attestations, or an error otherwise.
func (q *QPOS) ValidateSlotAttestations(slot uint64) error {
	q.mu.RLock()
	defer q.mu.RUnlock()

	attCount := len(q.attestations[slot])
	// L11-003/L10-005 FIX (P0): Use dynamic threshold based on validator count.
	validatorCount := q.validators.Size()
	minAtt := ComputeMinAttestations(validatorCount)
	if attCount < minAtt {
		return fmt.Errorf("slot %d has %d attestations, minimum %d required", slot, attCount, minAtt)
	}
	return nil
}

// ============================================================================
// ATTESTATION AGGREGATION
// ============================================================================

// AggregateAttestations aggregates attestations for a slot into a single aggregated attestation.
// Phase 3 optimization: When QTD threshold signer is available, produces a single
// AggregatedSignature (3293 bytes) instead of N individual signatures (N×3293 bytes).
// Falls back to individual signatures when QTD is not available.
func (q *QPOS) AggregateAttestations(slot uint64) *AggregatedAttestation {
	q.mu.Lock()
	defer q.mu.Unlock()

	atts := q.attestations[slot]
	if len(atts) == 0 {
		return nil
	}

	// Group attestations by target block
	byBlock := make(map[types.Hash][]*Attestation)
	for _, att := range atts {
		byBlock[att.BeaconBlockRoot] = append(byBlock[att.BeaconBlockRoot], att)
	}

	// Find the block with most attestations
	// audit-fix NEW-4: deterministic tiebreaker on block hash when counts are equal
	var bestBlock types.Hash
	var bestAtts []*Attestation
	for block, blockAtts := range byBlock {
		if len(blockAtts) > len(bestAtts) ||
			(len(blockAtts) == len(bestAtts) && bytes.Compare(block[:], bestBlock[:]) < 0) {
			bestBlock = block
			bestAtts = blockAtts
		}
	}

	if len(bestAtts) == 0 {
		return nil
	}

	// CONS-FIX: Attestations grouped by BeaconBlockRoot may still carry
	// different Source/Target checkpoints (e.g. a validator using a stale
	// justified checkpoint). Using bestAtts[0].Source/Target directly would
	// propagate that stale checkpoint into the aggregated attestation and
	// distort Casper FFG finality decisions. Find the majority (Source,Target)
	// pair and keep only attestations matching it.
	counts := make(map[stKey]int, len(bestAtts))
	for _, att := range bestAtts {
		k := stKey{
			sourceEpoch: att.Source.Epoch,
			sourceRoot:  att.Source.Root,
			targetEpoch: att.Target.Epoch,
			targetRoot:  att.Target.Root,
		}
		counts[k]++
	}
	var majority stKey
	var majorityCount int
	for k, c := range counts {
		// Deterministic tiebreaker: prefer larger count, then lexicographically
		// smaller key (by source root, then target root) so all nodes converge
		// on the same majority pair even under exact ties.
		if c > majorityCount ||
			(c == majorityCount && compareSTKey(k, majority) < 0) {
			majorityCount = c
			majority = k
		}
	}
	if majorityCount < len(bestAtts) {
		filtered := make([]*Attestation, 0, majorityCount)
		for _, att := range bestAtts {
			if att.Source.Epoch == majority.sourceEpoch &&
				att.Source.Root == majority.sourceRoot &&
				att.Target.Epoch == majority.targetEpoch &&
				att.Target.Root == majority.targetRoot {
				filtered = append(filtered, att)
			}
		}
		bestAtts = filtered
	}

	// Create aggregated attestation
	validatorCount := q.validators.Size()
	aggregationBits := make([]byte, (validatorCount+7)/8)

	// Phase 3: Use QTD threshold signing when available for single aggregated signature
	hasQTD := q.tssSigner != nil && q.tssSigner.IsThresholdMode()
	var aggregatedSig []byte
	signatures := make([][]byte, 0, len(bestAtts))

	for _, att := range bestAtts {
		// Set bit for this validator
		byteIdx := att.ValidatorIndex / 8
		bitIdx := uint(att.ValidatorIndex % 8) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		if byteIdx < len(aggregationBits) {
			aggregationBits[byteIdx] |= 1 << bitIdx
		}
		// audit-fix NEW-17: deep-copy signature to avoid sharing slices
		// between individual and aggregated attestations.
		sigCopy := make([]byte, len(att.Signature))
		copy(sigCopy, att.Signature)
		signatures = append(signatures, sigCopy)
	}

	// Phase 3: If QTD is available, aggregate all signatures by hashing them
	// together to produce a single aggregated signature that represents ALL
	// participating validators, not just the first one.
	//
	// audit-fix L3-017 (P1, unresolved 3 rounds): Previously this code simply
	// copied the FIRST validator's signature as the "aggregated" signature,
	// which provided no actual aggregation. Now we:
	// 1. Count set bits in aggregationBits to verify quorum (2/3 threshold)
	// 2. Hash ALL signatures together via SHA-256 to create a binding aggregate
	// 3. Only accept the aggregate if quorum is met
	if hasQTD && len(signatures) > 0 {
		// AUDIT (2026) CONS-FIX: Explicitly handle the
		// validatorCount == 0 boundary. The quorumThreshold formula
		// below would compute 0 in that case, and the participantCount(0)
		// < 0 check would be false, falling through to the else branch
		// and producing a binding aggregate over a zero-validator set —
		// semantically meaningless. Guard explicitly to keep the behavior
		// obvious and prevent future regressions if the formula changes.
		if validatorCount == 0 {
			aggregatedSig = nil
		} else {
			// Count participating validators from aggregationBits
			participantCount := 0
			for _, b := range aggregationBits {
				participantCount += bits.OnesCount8(b)
			}

			// Verify quorum: need at least ceil(validatorCount * 2/3) participants
			quorumThreshold := (validatorCount * 2) / 3
			if (validatorCount*2)%3 != 0 {
				quorumThreshold++
			}
			if participantCount < quorumThreshold {
				// Not enough validators; keep individual signatures for fallback
				aggregatedSig = nil
			} else {
				// C21-006 FIX: Dilithium3 does not support native signature aggregation
				// like BLS. The hash below serves as a binding COMMITMENT over all
				// participant signatures, NOT as a verifiable aggregate signature.
				// Individual signatures are RETAINED so that verifiers can validate
				// each participant's signature independently.
				h := sha256.New()
				for _, sig := range signatures {
					h.Write(sig)
				}
				aggregatedSig = h.Sum(nil)
				// C21-006 FIX: Do NOT clear individual signatures. They are needed
				// for verification since the hash is not a verifiable signature.
			}
		}
	}

	// CONS-007 (R8 2026-07-19 FIX): Construct Source/Target directly from
	// the `majority` stKey computed above, instead of indexing bestAtts[0].
	// Previously this used bestAtts[0].Source/Target, which depended on the
	// implicit invariant that bestAtts is non-empty after the majority
	// filter (lines 156-167). Although that filter always retains at least
	// one element (majorityCount >= 1 because counts[k]++ produced at least
	// one entry), the dependency on slice indexing is fragile: any future
	// change to the filtering logic could break the invariant and panic
	// with index-out-of-range on a consensus-critical path. Using the
	// already-computed `majority` value removes that dependency entirely
	// and makes the result identical to what the filter selected.
	//
	// Add a defensive bounds check for forward safety: if a future
	// refactor leaves an empty bestAtts here, return nil rather than panic.
	if len(bestAtts) == 0 {
		return nil
	}

	agg := &AggregatedAttestation{
		Slot:            slot,
		BeaconBlockRoot: bestBlock,
		Source: AttestationCheckpoint{
			Epoch: majority.sourceEpoch,
			Root:  majority.sourceRoot,
		},
		Target: AttestationCheckpoint{
			Epoch: majority.targetEpoch,
			Root:  majority.targetRoot,
		},
		AggregationBits:     aggregationBits,
		AggregatedSignature: aggregatedSig,
		Signatures:          signatures,
		ValidatorCount:      len(bestAtts),
	}

	// Cache the aggregated attestation
	q.aggregatedAttestations[slot] = agg

	return agg
}

// GetAggregatedAttestation returns the aggregated attestation for a slot.
// audit-fix NEW-16: returns a deep copy so callers cannot mutate internal
// AggregationBits or Signatures and corrupt consensus data.
func (q *QPOS) GetAggregatedAttestation(slot uint64) *AggregatedAttestation {
	q.mu.RLock()
	defer q.mu.RUnlock()
	agg := q.aggregatedAttestations[slot]
	if agg == nil {
		return nil
	}
	return agg.deepCopy()
}

// deepCopy returns a deep copy of an AggregatedAttestation, including all
// byte slices (AggregationBits, AggregatedSignature, Signatures), to prevent
// callers from mutating internal consensus state.
// audit-fix NEW-16.
func (a *AggregatedAttestation) deepCopy() *AggregatedAttestation {
	cp := *a
	if a.AggregationBits != nil {
		cp.AggregationBits = make([]byte, len(a.AggregationBits))
		copy(cp.AggregationBits, a.AggregationBits)
	}
	if a.AggregatedSignature != nil {
		cp.AggregatedSignature = make([]byte, len(a.AggregatedSignature))
		copy(cp.AggregatedSignature, a.AggregatedSignature)
	}
	if a.Signatures != nil {
		cp.Signatures = make([][]byte, len(a.Signatures))
		for i, sig := range a.Signatures {
			cp.Signatures[i] = make([]byte, len(sig))
			copy(cp.Signatures[i], sig)
		}
	}
	return &cp
}

// ============================================================================
// VALIDATOR REWARDS AND PENALTIES
// ============================================================================

// CalculateBaseReward calculates the base reward for a validator
// Based on Ethereum's formula: effective_balance * BASE_REWARD_FACTOR / sqrt(total_active_balance) / BASE_REWARDS_PER_EPOCH
//
//	SECURITY NOTE: All reward arithmetic uses big.Int integer math
//
// exclusively. No floating-point operations are used in the reward
// calculation path, preventing precision loss or rounding ambiguity in
// token distribution. The participationRate (float64) is used only for
// display/logging, never for actual reward computation.
func (q *QPOS) CalculateBaseReward(validatorIndex int) *big.Int {
	if q.validators == nil || validatorIndex < 0 || validatorIndex >= q.validators.Size() {
		return big.NewInt(0)
	}

	validators := q.validators.Validators()
	validator := validators[validatorIndex]

	// Calculate total active balance (in wei)
	totalBalance := big.NewInt(0)
	for _, v := range validators {
		if v.Active {
			totalBalance.Add(totalBalance, v.Stake)
		}
	}

	if totalBalance.Sign() == 0 {
		return big.NewInt(0)
	}

	// Convert wei to gwei for reward calculation (aligned with Ethereum's
	// consensus layer which uses gwei internally). This compensates for the
	// 10^9 unit difference between wei (QAU/EVM native) and gwei (Ethereum
	// beacon chain native), which is the unit basis BaseRewardFactor is
	// calibrated in. See consensus/block.go for the EM-2 calibration.
	gweiPerEth := big.NewInt(1_000_000_000)
	stakeGwei := new(big.Int).Div(validator.Stake, gweiPerEth)
	totalGwei := new(big.Int).Div(totalBalance, gweiPerEth)

	if totalGwei.Sign() == 0 {
		return big.NewInt(0)
	}

	// Base reward = effective_balance * BaseRewardFactor
	//               / (sqrt(total_balance) * BaseRewardsPerEpoch)
	sqrtTotal := new(big.Int).Sqrt(totalGwei)
	if sqrtTotal.Sign() == 0 {
		sqrtTotal = big.NewInt(1)
	}

	// R46-CS-05 FIX: Combine divisors into a single division to reduce
	// truncation error from two sequential integer divisions.
	rewardGwei := new(big.Int).Mul(stakeGwei, big.NewInt(BaseRewardFactor))
	combinedDivisor := new(big.Int).Mul(sqrtTotal, big.NewInt(BaseRewardsPerEpoch))
	rewardGwei.Div(rewardGwei, combinedDivisor)

	// Convert gwei back to wei for consistency with the rest of the system
	reward := new(big.Int).Mul(rewardGwei, gweiPerEth)
	return reward
}

// ProcessEpochRewards processes rewards and penalties for an epoch
func (q *QPOS) ProcessEpochRewards(epoch uint64) *EpochRewards {
	q.mu.Lock()
	defer q.mu.Unlock()

	// FIX: Epoch 0 is the genesis epoch. No rewards or penalties
	// should be processed during genesis as the validator set is still
	// being initialized and no blocks have been proposed yet.
	if epoch == 0 {
		genesisRewards := &EpochRewards{
			Epoch:              0,
			ProposerRewards:    make(map[int]*big.Int),
			AttesterRewards:    make(map[int]*big.Int),
			Penalties:          make(map[int]*big.Int),
			SlashingPenalties:  make(map[int]*big.Int),
			TotalRewards:       big.NewInt(0),
			TotalPenalties:     big.NewInt(0),
			ParticipatingStake: big.NewInt(0),
			TotalStake:         big.NewInt(0),
		}
		if q.epochRewards == nil {
			q.epochRewards = make(map[uint64]*EpochRewards)
		}
		q.epochRewards[0] = genesisRewards
		return genesisRewards
	}

	// CNS-EPH-001 (2026-08-08): Delegate the reward FORMULA to the shared core
	// (computeEpochRewardsUnlocked). Both ProcessEpochRewards (local P2P
	// attestations) and ComputeEpochRewardsFromCensus (on-chain census) use the
	// same core so they can NEVER diverge. See epoch_rewards_census.go.
	//
	// R59-CENSUS-PROP: the legacy path passes nil propSource, so the shared core
	// falls back to the local (accumulator-based) proposer derivation. Only the
	// on-chain census path carries the committed proposer.
	rewards := q.computeEpochRewardsUnlocked(epoch, func(slot uint64) []*Attestation {
		return q.attestations[slot]
	}, nil)

	// Cache the rewards
	q.epochRewards[epoch] = rewards

	// Auto-prune old attestations up to finalized epoch to prevent unbounded growth
	if q.finalizedEpoch > 0 {
		pruneBeforeSlot := EpochStartSlot(q.finalizedEpoch)
		for slot := range q.attestations {
			if slot < pruneBeforeSlot {
				delete(q.attestations, slot)
			}
		}
		// CONS-004 (R8 2026-07-19 FIX): Retain FinalityDelay+1 (=3) epochs of
		// validator attestations for slashing detection, matching the
		// CONS- fix already applied in PruneOldAttestations (validator.go).
		// The previous pruning here kept only 1 extra epoch, which is
		// insufficient for surround vote detection: a surround vote spans
		// source.epoch < target.epoch with surrounding relation, and Casper
		// FFG surround votes can span FinalityDelay (2) epochs or more. If
		// the source attestation is pruned before checkSurroundVote runs,
		// the slashing evidence is lost and the attacker gets away free.
		// Keep 3 epochs to ensure both ends of a surround vote survive
		// long enough for detection. This must be kept in sync with the
		// pruning logic in PruneOldAttestations (validator.go).
		slashingKeepEpochs := uint64(FinalityDelay + 1) // 3 epochs by default
		slashingPruneSlot := uint64(0)
		if pruneBeforeSlot > slashingKeepEpochs*SlotsPerEpoch {
			slashingPruneSlot = pruneBeforeSlot - slashingKeepEpochs*SlotsPerEpoch
		}
		for validatorIdx := range q.validatorAttestations {
			for slot := range q.validatorAttestations[validatorIdx] {
				if slot < slashingPruneSlot {
					delete(q.validatorAttestations[validatorIdx], slot)
				}
			}
			// audit-fix NEW-19: remove empty inner maps to prevent memory leak.
			if len(q.validatorAttestations[validatorIdx]) == 0 {
				delete(q.validatorAttestations, validatorIdx)
			}
		}

		// audit-fix  prune old epoch rewards to prevent unbounded memory growth.
		// Keep rewards for the last 3 finalized epochs.
		for e := range q.epochRewards {
			if e+3 < q.finalizedEpoch {
				delete(q.epochRewards, e)
			}
		}

		// audit-fix  prune old aggregated attestations to prevent unbounded memory growth.
		for slot := range q.aggregatedAttestations {
			if slot < pruneBeforeSlot {
				delete(q.aggregatedAttestations, slot)
			}
		}
	}

	return rewards
}

// calculateBaseRewardUnlocked calculates base reward without locking (internal use)
func (q *QPOS) calculateBaseRewardUnlocked(validatorIndex int) *big.Int {
	if q.validators == nil || validatorIndex < 0 || validatorIndex >= q.validators.Size() {
		return big.NewInt(0)
	}

	validators := q.validators.Validators()
	validator := validators[validatorIndex]

	// FIX: exclude slashed validators from the total balance used to
	// compute base rewards. Slashed validators should not dilute the reward
	// pool, consistent with  (totalStake excludes slashed).
	totalBalance := big.NewInt(0)
	for i, v := range validators {
		if v.Active {
			if _, slashed := q.slashedValidators[i]; slashed {
				continue
			}
			totalBalance.Add(totalBalance, v.Stake)
		}
	}

	if totalBalance.Sign() == 0 {
		return big.NewInt(0)
	}

	// Convert wei to gwei for reward calculation (aligned with Ethereum's
	// consensus layer which uses gwei internally). See CalculateBaseReward
	// for detailed rationale.
	gweiPerEth := big.NewInt(1_000_000_000)
	stakeGwei := new(big.Int).Div(validator.Stake, gweiPerEth)
	totalGwei := new(big.Int).Div(totalBalance, gweiPerEth)

	if totalGwei.Sign() == 0 {
		return big.NewInt(0)
	}

	sqrtTotal := new(big.Int).Sqrt(totalGwei)
	if sqrtTotal.Sign() == 0 {
		sqrtTotal = big.NewInt(1)
	}

	// CONS-006 (R8 2026-07-19 FIX): Combine divisors into a single
	// division to match CalculateBaseReward (R46-CS-05 FIX) and avoid
	// truncation divergence between the two functions. Two sequential
	// integer divisions truncate twice, producing a smaller result than
	// the single-division form whenever the intermediate remainder is
	// nonzero. Since CalculateBaseReward is the public path (called by
	// RPC) and calculateBaseRewardUnlocked is the internal path (called
	// from ProcessEpochRewards under lock), divergence between them can
	// cause the publicly-quoted reward to differ from what is actually
	// distributed, breaking accounting invariants. Use the merged-divisor
	// form on both paths so they produce identical results.
	rewardGwei := new(big.Int).Mul(stakeGwei, big.NewInt(BaseRewardFactor))
	combinedDivisor := new(big.Int).Mul(sqrtTotal, big.NewInt(BaseRewardsPerEpoch))
	rewardGwei.Div(rewardGwei, combinedDivisor)

	// Convert gwei back to wei
	reward := new(big.Int).Mul(rewardGwei, gweiPerEth)

	return reward
}

// GetEpochRewards returns the rewards for an epoch.
// audit-fix  returns a deep copy to prevent callers from mutating
// internal *big.Int fields (TotalRewards, TotalPenalties, etc.).
func (q *QPOS) GetEpochRewards(epoch uint64) *EpochRewards {
	q.mu.RLock()
	defer q.mu.RUnlock()
	rewards := q.epochRewards[epoch]
	if rewards == nil {
		return nil
	}
	return rewards.deepCopy()
}

// getEpochBlockRootLocked is the lock-free internal version of getEpochBlockRoot.
// CRITICAL FIX: MUST be called while q.mu is already held (read or write).
// Previously, CheckFinality() held q.mu write lock and called getEpochBlockRoot()
// which tried to acquire q.mu read lock, causing a DEADLOCK with sync.RWMutex.
func (q *QPOS) getEpochBlockRootLocked(epoch uint64) types.Hash {
	if root, ok := q.epochBlockRoots[epoch]; ok {
		return root
	}
	return types.Hash{}
}

// GetSyncCommittee returns the current sync committee for light clients.
func (q *QPOS) GetSyncCommittee() *SyncCommittee {
	if q.syncCommitteeManager == nil {
		return nil
	}
	return q.syncCommitteeManager.GetCurrentCommittee()
}

// ComputeAndRotateSyncCommittee computes the next sync committee and rotates if needed.
func (q *QPOS) ComputeAndRotateSyncCommittee(epoch uint64) {
	if q.syncCommitteeManager == nil {
		return
	}

	period := epoch / SyncCommitteePeriod
	currentCommittee := q.syncCommitteeManager.GetCurrentCommittee()
	if currentCommittee != nil && currentCommittee.Period >= period {
		return
	}

	validators := q.validators.Validators()
	nextCommittee := q.syncCommitteeManager.ComputeSyncCommittee(period, validators, q.randaoMix)
	if nextCommittee != nil {
		q.syncCommitteeManager.RotateCommittee(nextCommittee)
	}
}

// GetSyncCommitteeManager returns the sync committee manager.
func (q *QPOS) GetSyncCommitteeManager() *SyncCommitteeManager {
	return q.syncCommitteeManager
}

// stKey is a (Source,Target) checkpoint pair used as a map key when
// detecting the majority Source/Target pair inside AggregateAttestations.
// Defined at package scope so the compareSTKey helper can reference it.
// CONS-FIX.
type stKey struct {
	sourceEpoch uint64
	sourceRoot  types.Hash
	targetEpoch uint64
	targetRoot  types.Hash
}

// compareSTKey provides a deterministic ordering between two (Source,Target)
// checkpoint pairs so all nodes converge on the same majority pair when
// counts are tied. Used by AggregateAttestations (CONS-FIX).
// Returns -1, 0, or 1 like bytes.Compare.
func compareSTKey(a, b stKey) int {
	if a.sourceEpoch != b.sourceEpoch {
		if a.sourceEpoch < b.sourceEpoch {
			return -1
		}
		return 1
	}
	if c := bytes.Compare(a.sourceRoot[:], b.sourceRoot[:]); c != 0 {
		return c
	}
	if a.targetEpoch != b.targetEpoch {
		if a.targetEpoch < b.targetEpoch {
			return -1
		}
		return 1
	}
	return bytes.Compare(a.targetRoot[:], b.targetRoot[:])
}

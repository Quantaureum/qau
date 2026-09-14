// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

const (
	// DefaultProposerRewardShare / Attester / Sealer weight the MinistryRevenue
	// governance AUDIT RECORD (DistributeEpochRewards below). They are NOT the
	// issuance split.
	//
	// ⚠️ KNOWN DIVERGENCE (EM-2, 2026-08-31): actual issuance now pays proposers
	// ProposerWeight/WeightDenominator = 8/64 = 12.5% of the epoch total and
	// attesters the remaining 87.5% (see consensus/epoch_rewards_census.go).
	// This audit record instead splits the same total by 8/(8 + N_attesters +
	// 4*N_sealers), which at 6 attesters and no sealers gives the proposer 57.1%.
	// So the audit trail and the real payouts disagree.
	//
	// It is only an audit trail — node/block_producer.go:1823 calls this after
	// the real crediting, which reads qpos.epochRewards independently — so no
	// balance is wrong. Aligning the two requires deciding what a "sealer" earns
	// under EM-2, which is a governance question, not a monetary one, and is
	// tracked in docs/economic-model.md §9 rather than guessed at here.
	DefaultProposerRewardShare = 8
	DefaultAttesterRewardShare = 1
	DefaultSealerRewardShare   = 4
	SlashPenaltyDoubleSign     = 10000 // FIX: 100% — was 3300 (33%), inconsistent with slashing.go's DoubleSignSlashPercent=100 (100%). Casper FFG standard requires full slashing for double signing.
	SlashPenaltySurroundVote   = 10000 // FIX: 100% — surround voting is a Casper FFG slashable offense, same severity as double signing.
	SlashPenaltyDowntime       = 10
	SlashPenaltyInvalidVRF     = 1000
	// FIX: Named constant for basis points denominator (100% = 10000).
	// Previously hardcoded as big.NewInt(10000) in penalty calculation.
	BasisPointsDenominator = 10000
	// FIX: Named constant for percentage denominator used by
	// ValidatorManager.SlashStake (which receives slashPercent in 0-100 range,
	// NOT basis points). Previously hardcoded as big.NewInt(100).
	PercentDenominator = 100
	// rewardRecordsRetainEpochs is the number of recent epochs whose reward
	// distribution records are retained in memory. Older records are pruned
	// on each distribution; historical reward data remains available from
	// the chain itself (rewards are applied on-chain at the epoch boundary).
	// R37-P3-28 FIX (2026-07-31): prevents unbounded rewardRecords growth.
	rewardRecordsRetainEpochs = 512
)

type RewardDistributionRecord struct {
	Epoch         uint64
	Proposer      int
	Attesters     []int
	Sealers       []int
	Amounts       map[int]*big.Int
	Total         *big.Int
	DistributedAt time.Time
	// P0-T2 (2026-07-14): QPOS consensus-level reward totals, populated by
	// calling QPOS.ProcessEpochRewards. The syncer reads qpos.epochRewards
	// to credit actual QAU balances. These fields provide an audit trail
	// linking the ministry record to the QPOS calculation.
	QPOSEpochRewards   *big.Int
	QPOSEpochPenalties *big.Int
}

type SlashExecutionRecord struct {
	ValidatorIndex int
	Reason         SlashingReason
	Amount         *big.Int
	Epoch          uint64
	ExecutedAt     time.Time
	Chamber        ChamberID
}

type MinistryRevenue struct {
	mu sync.RWMutex

	qpos        *QPOS
	coordinator *ThreeChambersCoordinator
	registry    *MinistryRegistry

	rewardRecords map[uint64]*RewardDistributionRecord
	slashRecords  []SlashExecutionRecord
	totalRewards  *big.Int
	totalSlashed  *big.Int

	operations uint64
	errors     uint64
	lastActive time.Time
}

func NewMinistryRevenue(qpos *QPOS, coordinator *ThreeChambersCoordinator, registry *MinistryRegistry) *MinistryRevenue {
	return &MinistryRevenue{
		qpos:          qpos,
		coordinator:   coordinator,
		registry:      registry,
		rewardRecords: make(map[uint64]*RewardDistributionRecord),
		slashRecords:  make([]SlashExecutionRecord, 0),
		totalRewards:  big.NewInt(0),
		totalSlashed:  big.NewInt(0),
	}
}

func (mr *MinistryRevenue) DistributeEpochRewards(caller types.Address, epoch uint64, proposerIndex int, attesterIndices []int, sealerIndices []int, totalReward *big.Int, blockTime ...int64) (*RewardDistributionRecord, error) {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can distribute epoch rewards.
	if caller == (types.Address{}) {
		return nil, fmt.Errorf("unauthorized: zero address cannot distribute rewards")
	}
	if !isSystemCaller(caller) {
		return nil, fmt.Errorf("unauthorized: only system callers can distribute rewards")
	}

	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.operations++
	mr.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	if _, exists := mr.rewardRecords[epoch]; exists {
		mr.errors++
		return nil, fmt.Errorf("rewards already distributed for epoch %d", epoch)
	}

	totalShares := DefaultProposerRewardShare + len(attesterIndices)*DefaultAttesterRewardShare
	if len(sealerIndices) > 0 {
		totalShares += len(sealerIndices) * DefaultSealerRewardShare
	}

	if totalShares == 0 {
		mr.errors++
		return nil, fmt.Errorf("no participants for reward distribution in epoch %d", epoch)
	}

	amounts := make(map[int]*big.Int)

	proposerAmount := new(big.Int).Mul(totalReward, big.NewInt(int64(DefaultProposerRewardShare)))
	proposerAmount.Div(proposerAmount, big.NewInt(int64(totalShares)))
	amounts[proposerIndex] = proposerAmount

	attesterShare := new(big.Int).Mul(totalReward, big.NewInt(int64(DefaultAttesterRewardShare)))
	attesterShare.Div(attesterShare, big.NewInt(int64(totalShares)))
	for _, idx := range attesterIndices {
		if existing, ok := amounts[idx]; ok {
			amounts[idx] = new(big.Int).Add(existing, attesterShare)
		} else {
			amounts[idx] = new(big.Int).Set(attesterShare)
		}
	}

	if len(sealerIndices) > 0 {
		sealerShare := new(big.Int).Mul(totalReward, big.NewInt(int64(DefaultSealerRewardShare)))
		sealerShare.Div(sealerShare, big.NewInt(int64(totalShares)))
		for _, idx := range sealerIndices {
			if existing, ok := amounts[idx]; ok {
				amounts[idx] = new(big.Int).Add(existing, sealerShare)
			} else {
				amounts[idx] = new(big.Int).Set(sealerShare)
			}
		}
	}

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	record := &RewardDistributionRecord{
		Epoch:         epoch,
		Proposer:      proposerIndex,
		Attesters:     attesterIndices,
		Sealers:       sealerIndices,
		Amounts:       amounts,
		Total:         new(big.Int).Set(totalReward),
		DistributedAt: now,
	}

	mr.rewardRecords[epoch] = record
	mr.totalRewards.Add(mr.totalRewards, totalReward)

	// R37-P3-28 FIX (2026-07-31): prune records outside the retention
	// window so the map stays bounded.
	if epoch >= rewardRecordsRetainEpochs {
		minEpoch := epoch - rewardRecordsRetainEpochs + 1
		for e := range mr.rewardRecords {
			if e < minEpoch {
				delete(mr.rewardRecords, e)
			}
		}
	}

	// P0-T2 (2026-07-14): Real side effect — trigger QPOS epoch reward
	// calculation. This populates qpos.epochRewards[epoch], which the
	// syncer (node/syncer.go:applyEpochRewards) reads to credit actual
	// QAU token balances to validator addresses in the state DB.
	//
	// Without this call, the ministry's reward record is pure bookkeeping
	// — validators never receive their rewards because the syncer has no
	// epoch rewards to apply.
	if mr.qpos != nil {
		qposRewards := mr.qpos.ProcessEpochRewards(epoch)
		if qposRewards != nil {
			record.QPOSEpochRewards = qposRewards.TotalRewards
			record.QPOSEpochPenalties = qposRewards.TotalPenalties
		}
	}

	if mr.registry != nil && mr.registry.Personnel() != nil {
		mp := mr.registry.Personnel()
		_ = mp.RecordBlockProduced(caller, proposerIndex, blockTime...)
		for _, idx := range attesterIndices {
			_ = mp.RecordAttestation(caller, idx, blockTime...)
		}
		for _, idx := range sealerIndices {
			_ = mp.RecordSeal(caller, idx, blockTime...)
		}
	}

	// P3-T2 (2026-07-15): Structured audit log for reward distribution.
	if mr.registry != nil {
		mr.registry.logAudit(MinistryIDRevenue, "distribute_rewards", caller,
			fmt.Sprintf("epoch=%d proposer=%d attesters=%d sealers=%d total=%s",
				epoch, proposerIndex, len(attesterIndices), len(sealerIndices), totalReward.String()),
			"ok", now)
	}

	return record, nil
}

// audit-remediation: reviewed 2026-09-11 — revenue accounting; stake deduction happens in the authorized SlashingManager path.
func (mr *MinistryRevenue) ExecuteSlashing(caller types.Address, validatorIndex int, reason SlashingReason, stake *big.Int, epoch uint64, offenseHeight uint64, blockTime ...int64) (*SlashExecutionRecord, error) {
	// AUDIT (2026) R4-GOV-02 FIX: Added `offenseHeight` parameter.
	// Previously this function only had `epoch`, and the double-punishment
	// guard called IsOffenseSlashed/RecordOffenseOnly with `epoch` as the
	// height argument. But SlashingManager's offense keys use `height`
	// (createOffenseKey → "addr:reason:height"), so the ministry path's
	// "addr:reason:epoch" key NEVER matched the slashing path's key.
	// Result: the same offense could be slashed twice via the two paths.
	// The fix unifies on `height` (the block height at which the offense
	// occurred), which is what SlashingEvidence.Height and createOffenseKey
	// already use. `epoch` is retained for the SlashExecutionRecord.
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can execute slashing.
	if caller == (types.Address{}) {
		return nil, fmt.Errorf("unauthorized: zero address cannot execute slashing")
	}
	if !isSystemCaller(caller) {
		return nil, fmt.Errorf("unauthorized: only system callers can execute slashing")
	}

	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.operations++
	mr.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	var penaltyBasisPoints int
	switch reason {
	case SlashingReasonDoubleSigning:
		penaltyBasisPoints = SlashPenaltyDoubleSign
	case SlashingReasonSurroundVote:
		penaltyBasisPoints = SlashPenaltySurroundVote
	case SlashingReasonDoubleVote:
		penaltyBasisPoints = SlashPenaltyDoubleSign
	case SlashingReasonDowntime:
		penaltyBasisPoints = SlashPenaltyDowntime
	case SlashingReasonInvalidVRF:
		penaltyBasisPoints = SlashPenaltyInvalidVRF
	default:
		penaltyBasisPoints = SlashPenaltyDowntime
	}

	//  int64(penaltyBasisPoints) is safe — penaltyBasisPoints is uint32
	// basis points (e.g., SlashPenaltyDowntime=1000), far below int64 max.
	penalty := new(big.Int).Mul(stake, big.NewInt(int64(penaltyBasisPoints))) //nolint:gosec,G115
	// FIX: Use named BasisPointsDenominator constant instead of magic 10000.
	penalty.Div(penalty, big.NewInt(BasisPointsDenominator))

	if penalty.Cmp(stake) > 0 {
		penalty.Set(stake)
	}

	chamber := ChamberNone
	if mr.coordinator != nil {
		chamber = mr.coordinator.assignment.GetChamber(validatorIndex)
	}

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	record := SlashExecutionRecord{
		ValidatorIndex: validatorIndex,
		Reason:         reason,
		Amount:         penalty,
		Epoch:          epoch,
		ExecutedAt:     now,
		Chamber:        chamber,
	}

	// AUDIT (2026) R4-GOV-03 FIX: Previously the record was appended to
	// slashRecords and totalSlashed was updated BEFORE the double-punishment
	// guards ran. If a guard triggered (returning an error), the phantom
	// record remained in slashRecords and totalSlashed was inflated. Now we
	// only commit the record after all guards and side effects succeed.
	// P0-T2: Real side effect — actually slash stake via ValidatorManager.
	// Convert basis points (0-10000) to percentage (0-100) for SlashStake.
	if mr.qpos != nil && mr.qpos.slashingManager != nil && mr.qpos.slashingManager.validatorMgr != nil {
		vm := mr.qpos.slashingManager.validatorMgr
		vs := mr.qpos.GetValidatorSet()
		if vs != nil {
			validators := vs.Validators()
			if validatorIndex < len(validators) {
				addr := validators[validatorIndex].Address

				// AUDIT (2026) GOV B-1 FIX: Double-punishment guard.
				// The first slashing path (SlashingManager.SubmitEvidence)
				// checks both qpos.IsSlashed and slashedOffenses before
				// slashing. This second path (via MinistryJustice.ResolveDispute
				// → MinistryRevenue.ExecuteSlashing) had NO such guard, allowing
				// the same validator to be slashed twice for the same offense.
				// Now we check both conditions and skip if already slashed.
				//
				// AUDIT (2026) R4-GOV-02 FIX: The guard previously called
				// IsOffenseSlashed/RecordOffenseOnly with `epoch` as the
				// height argument, but SlashingManager's offense keys use
				// `height`. The key mismatch defeated the guard. Now we pass
				// `offenseHeight` (the block height at which the offense
				// occurred), matching the key used by SubmitEvidence → slash.
				if mr.qpos.IsSlashed(validatorIndex) {
					mr.errors++
					return nil, fmt.Errorf("validator %d already slashed by QPOS — refusing double punishment (GOV B-1)", validatorIndex)
				}
				if mr.qpos.slashingManager.IsOffenseSlashed(addr, reason, offenseHeight) {
					mr.errors++
					return nil, fmt.Errorf("offense (%x, %d, height %d) already slashed — refusing double punishment (GOV B-1)", addr[:8], reason, offenseHeight)
				}

				slashPercent := big.NewInt(int64(penaltyBasisPoints / 100))
				if slashPercent.Cmp(big.NewInt(100)) > 0 {
					slashPercent.Set(big.NewInt(100))
				}
				if slashPercent.Cmp(big.NewInt(0)) > 0 {
					_, err := vm.SlashStake(mr.qpos.slashingManager.systemCaller, addr, slashPercent)
					if err != nil {
						mr.errors++
						return nil, fmt.Errorf("execute slashing failed: validator manager slash stake: %w", err)
					}
				}
				// Deactivate the validator
				if err := vm.SetActive(mr.qpos.slashingManager.systemCaller, addr, false); err != nil {
					mr.errors++
					return nil, fmt.Errorf("execute slashing failed: deactivate validator: %w", err)
				}
				// Sync QPOS slashed validators map
				// CONS- (2026-07-20): Pass permanent + jailUntil so
				// the QPOS entry correctly distinguishes permanent bans from
				// temporary jails, matching the SlashingManager.slash() path.
				// Without this, every ministry-driven slash would be recorded
				// as a temporary jail and could be cleared by Unjail.
				permanent := reason == SlashingReasonDoubleSigning ||
					reason == SlashingReasonSurroundVote ||
					reason == SlashingReasonDoubleVote
				var jailUntil int64
				if sm := mr.qpos.slashingManager; sm != nil && sm.params != nil {
					if sm.params.JailDuration > 0 && now.Unix() > math.MaxInt64-sm.params.JailDuration {
						jailUntil = math.MaxInt64
					} else {
						jailUntil = now.Unix() + sm.params.JailDuration
					}
				}
				_ = mr.qpos.MarkValidatorSlashedByAddress(addr, permanent, jailUntil)
				// Record offense in slashedOffenses to prevent future double-slash.
				// AUDIT (2026) R4-GOV-02 FIX: Use `offenseHeight` (not
				// `epoch`) so the offense key matches the key used by the
				// SubmitEvidence → slash path (createOffenseKey uses
				// evidence.Height). Without this match, the other path
				// wouldn't see this offense and could slash again.
				mr.qpos.slashingManager.RecordOffenseOnly(addr, reason, offenseHeight)
			}
		}
	}

	// AUDIT (2026) R4-GOV-03 FIX: Commit the record only after all guards
	// and side effects succeed. Previously this was done before the guards,
	// leaving phantom records when the guards rejected the slashing.
	mr.slashRecords = append(mr.slashRecords, record)
	mr.totalSlashed.Add(mr.totalSlashed, penalty)

	if mr.registry != nil && mr.registry.Personnel() != nil {
		_ = mr.registry.Personnel().RecordSlashing(caller, validatorIndex, reason, blockTime...)
	}

	// P3-T2 (2026-07-15): Structured audit log for slashing execution.
	if mr.registry != nil {
		mr.registry.logAudit(MinistryIDRevenue, "execute_slashing", caller,
			fmt.Sprintf("validator=%d reason=%s epoch=%d penalty=%s",
				validatorIndex, reason, epoch, record.Amount.String()),
			"ok", now)
	}

	return &record, nil
}

func (mr *MinistryRevenue) GetRewardRecord(epoch uint64) *RewardDistributionRecord {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	if r, ok := mr.rewardRecords[epoch]; ok {
		copy := &RewardDistributionRecord{
			Epoch:         r.Epoch,
			Proposer:      r.Proposer,
			Attesters:     append([]int(nil), r.Attesters...),
			Sealers:       append([]int(nil), r.Sealers...),
			Amounts:       make(map[int]*big.Int),
			Total:         new(big.Int).Set(r.Total),
			DistributedAt: r.DistributedAt,
		}
		for k, v := range r.Amounts {
			copy.Amounts[k] = new(big.Int).Set(v)
		}
		return copy
	}
	return nil
}

func (mr *MinistryRevenue) GetSlashRecords(validatorIndex int) []SlashExecutionRecord {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	result := make([]SlashExecutionRecord, 0)
	for _, r := range mr.slashRecords {
		if r.ValidatorIndex == validatorIndex {
			result = append(result, r)
		}
	}
	return result
}

// RecordSlashingExecution records a slashing event in the ministry's slashRecords
// WITHOUT re-executing the actual slashing side effects (stake reduction, deactivation).
//
// P1-T3 (2026-07-14): This is called by SlashingManager.slash() after the actual
// slashing has been performed. It provides governance visibility into slashing
// events without causing double-punishment (which would occur if ExecuteSlashing
// were called, since ExecuteSlashing also calls SlashStake/SetActive).
//
// The caller must be a system caller (the slashing-system address registered in
// slashing.go:228).
// audit-remediation: reviewed 2026-09-11 — bookkeeping of an already-executed slash; no new mutation.
func (mr *MinistryRevenue) RecordSlashingExecution(caller types.Address, validatorIndex int, reason SlashingReason, slashedAmount *big.Int, epoch uint64, blockTime ...int64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can record slashing events.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot record slashing")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can record slashing")
	}

	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.operations++
	mr.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	chamber := ChamberNone
	if mr.coordinator != nil {
		chamber = mr.coordinator.assignment.GetChamber(validatorIndex)
	}

	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	record := SlashExecutionRecord{
		ValidatorIndex: validatorIndex,
		Reason:         reason,
		Amount:         new(big.Int).Set(slashedAmount),
		Epoch:          epoch,
		ExecutedAt:     now,
		Chamber:        chamber,
	}

	mr.slashRecords = append(mr.slashRecords, record)
	mr.totalSlashed.Add(mr.totalSlashed, slashedAmount)

	// Record in Personnel ministry for reputation tracking.
	if mr.registry != nil && mr.registry.Personnel() != nil {
		_ = mr.registry.Personnel().RecordSlashing(caller, validatorIndex, reason, blockTime...)
	}

	// P3-T2 (2026-07-15): Structured audit log for slashing record.
	if mr.registry != nil {
		mr.registry.logAudit(MinistryIDRevenue, "record_slashing", caller,
			fmt.Sprintf("validator=%d reason=%s epoch=%d amount=%s",
				validatorIndex, reason, epoch, slashedAmount.String()),
			"ok", now)
	}

	return nil
}

func (mr *MinistryRevenue) GetFinancialSummary() map[string]any {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	return map[string]any{
		"totalRewardsDistributed": mr.totalRewards.String(),
		"totalSlashed":            mr.totalSlashed.String(),
		"epochsRewarded":          len(mr.rewardRecords),
		"totalSlashExecutions":    len(mr.slashRecords),
	}
}

func (mr *MinistryRevenue) GetStatus() map[string]any {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	return map[string]any{
		"ministry":    MinistryIDRevenue.String(),
		"displayName": MinistryIDRevenue.DisplayName(),
		"active":      true,
		"operations":  mr.operations,
		"errors":      mr.errors,
		"lastActive":  mr.lastActive,
	}
}

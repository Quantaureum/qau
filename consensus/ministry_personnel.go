// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

const (
	DefaultReputationScore    = 1000
	MinReputationScore        = 0
	MaxReputationScore        = 10000
	ReputationDecayRate       = 1
	ReputationPenaltySlashing = 500
	ReputationPenaltyDowntime = 50
	ReputationBonusBlock      = 10
	ReputationBonusAttest     = 5
	ReputationBonusSeal       = 20
)

type ReputationRecord struct {
	ValidatorIndex int
	Score          int
	LastUpdated    time.Time
	TotalBlocks    uint64
	TotalAttests   uint64
	TotalSeals     uint64
	TotalSlashes   uint64
	Penalties      uint64
	Bonuses        uint64
}

type MinistryPersonnel struct {
	mu sync.RWMutex

	qpos        *QPOS
	coordinator *ThreeChambersCoordinator
	registry    *MinistryRegistry

	reputations map[int]*ReputationRecord

	operations uint64
	errors     uint64
	lastActive time.Time
}

func NewMinistryPersonnel(qpos *QPOS, coordinator *ThreeChambersCoordinator, registry *MinistryRegistry) *MinistryPersonnel {
	return &MinistryPersonnel{
		qpos:        qpos,
		coordinator: coordinator,
		registry:    registry,
		reputations: make(map[int]*ReputationRecord),
	}
}

func (mp *MinistryPersonnel) RegisterValidator(caller, addr types.Address, pubKey *crypto.PublicKey, stake *big.Int, commission uint32, height uint64, blockTime ...int64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// or the validator itself (self-registration) can register a new validator.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot register validators")
	}
	isSystem := isSystemCaller(caller)
	isSelf := caller == addr
	if !isSystem && !isSelf {
		return fmt.Errorf("unauthorized: only the validator or system can register a validator")
	}

	// R38-P1-09 FIX (2026-08-01): Scope mp.mu to the validation/bookkeeping
	// phase ONLY, and release it BEFORE calling validatorMgr.AddValidator.
	// AddValidator internally calls back into
	// MinistryPersonnel.RecordValidatorRegistration (vm.ministryPersonnel),
	// which re-acquires mp.mu — mp.mu is NOT reentrant, so holding it across
	// the AddValidator call would self-deadlock. The qpos reference captured
	// here is safe to use after Unlock because qpos itself owns its own lock.
	mp.mu.Lock()
	mp.operations++
	mp.lastActive = time.Now()

	if mp.qpos == nil {
		mp.errors++
		mp.mu.Unlock()
		return fmt.Errorf("QPOS not initialized")
	}

	vs := mp.qpos.GetValidatorSet()
	if vs == nil {
		mp.errors++
		mp.mu.Unlock()
		return fmt.Errorf("validator set not available")
	}

	alreadyExists := false
	for _, v := range vs.Validators() {
		if v.Address == addr {
			alreadyExists = true
			break
		}
	}
	if alreadyExists {
		mp.errors++
		mp.mu.Unlock()
		return fmt.Errorf("validator %x already exists in validator set", addr[:4])
	}

	if stake.Cmp(MinStakeAmount) < 0 {
		mp.errors++
		mp.mu.Unlock()
		return fmt.Errorf("insufficient stake: %s < %s", stake.String(), MinStakeAmount.String())
	}

	if mp.qpos.slashingManager == nil || mp.qpos.slashingManager.validatorMgr == nil {
		mp.errors++
		mp.mu.Unlock()
		return fmt.Errorf("register failed: validator manager not available")
	}
	sm := mp.qpos.slashingManager
	// R38-P1-09 FIX: Previously this called mp.qpos.AddStakingValidator(addr,
	// stake) which inserted the new validator directly into the active
	// ValidatorSet, bypassing the ValidatorManager's inactive/queue admission
	// flow + public-key validation + queue delay + MaxValidators cap. New
	// validators MUST go through validatorMgr.AddValidator so they start
	// inactive and are activated later by the ValidatorQueue (matching
	// ProcessEpochAdvanced). The qpos.AddStakingValidator path is reserved
	// for staking-transaction-driven ValidatorSet sync from the node layer,
	// NOT for self-registration.
	vmRef := sm.validatorMgr
	vmCaller := sm.systemCaller
	mp.mu.Unlock()

	// Use commission=MinCommission as a sane default for self-registered
	// validators; callers needing a specific commission rate should use
	// validatorMgr.AddValidator directly.
	if err := vmRef.AddValidator(vmCaller, addr, pubKey, stake, MinCommission, height); err != nil {
		mp.mu.Lock()
		mp.errors++
		mp.mu.Unlock()
		return fmt.Errorf("register failed: validator manager AddValidator: %w", err)
	}

	return nil
}

// RecordValidatorRegistration records a validator registration in the Personnel
// reputation system WITHOUT the AddStakingValidator side effect.
//
// P1-T4 (2026-07-14): Called by ValidatorManager.AddValidator to record the
// registration for governance visibility. Unlike RegisterValidator, this method
// does NOT call qpos.AddStakingValidator — the caller is responsible for the
// actual validator set update.
func (mp *MinistryPersonnel) RecordValidatorRegistration(caller, addr types.Address, stake *big.Int, height uint64, blockTime ...int64) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot record validator registration")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can record validator registration")
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.operations++
	mp.lastActive = time.Now()

	if mp.qpos == nil {
		mp.errors++
		return fmt.Errorf("QPOS not initialized")
	}

	vs := mp.qpos.GetValidatorSet()
	if vs == nil {
		mp.errors++
		return fmt.Errorf("validator set not available")
	}

	// Find the validator index. The validator should already be in the set
	// (added by the caller before calling this method).
	//
	// GOV-R7-06 (Low): Previously this branch tolerated a missing validator
	// by falling back to `idx = vs.Size()`, predicting the index the
	// validator WOULD receive if AddValidator succeeded later. That
	// prediction is unsafe: if AddValidator fails (e.g. duplicate address)
	// or if another validator is added concurrently, the predicted index
	// points at the wrong slot and the reputation record gets cross-linked
	// with another validator. Per the contract above the caller MUST have
	// already added the validator, so a missing index is now a hard error
	// rather than a silent fallback.
	idx := vs.GetValidatorIndex(addr)
	if idx < 0 {
		mp.errors++
		return fmt.Errorf("validator %x not found in validator set; caller must add it before recording registration", addr[:4])
	}

	// Don't overwrite if already tracked.
	if _, exists := mp.reputations[idx]; exists {
		return nil
	}

	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	mp.reputations[idx] = &ReputationRecord{
		ValidatorIndex: idx,
		Score:          DefaultReputationScore,
		LastUpdated:    now,
	}

	return nil
}

func (mp *MinistryPersonnel) DeregisterValidator(caller types.Address, validatorIndex int, epoch uint64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can deregister validators.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot deregister validators")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can deregister validators")
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.operations++
	mp.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	if mp.coordinator != nil {
		chamber := mp.coordinator.assignment.GetChamber(validatorIndex)
		if chamber != ChamberNone {
			mp.errors++
			return fmt.Errorf("validator %d is still in %s chamber, must be removed first", validatorIndex, chamber)
		}
	}

	// P0-T2: Real side effect — remove validator from the actual ValidatorSet.
	// P0-T2 FIX (2026-07-14): Previously, delete(mp.reputations, ...) ran
	// BEFORE the ValidatorSet removal, and RemoveValidator's error was
	// silently ignored (_ =). If dependencies were nil, the reputation was
	// deleted but the validator stayed in the ValidatorSet — silent
	// inconsistency. Now: check deps first, fail-closed on missing deps,
	// propagate RemoveValidator error, only delete reputation on success.
	if mp.qpos == nil {
		mp.errors++
		return fmt.Errorf("deregister failed: QPOS not available")
	}
	if mp.qpos.slashingManager == nil || mp.qpos.slashingManager.validatorMgr == nil {
		mp.errors++
		return fmt.Errorf("deregister failed: validator manager not available")
	}

	vs := mp.qpos.GetValidatorSet()
	if vs == nil {
		mp.errors++
		return fmt.Errorf("deregister failed: validator set not available")
	}

	validators := vs.Validators()
	if validatorIndex >= len(validators) {
		mp.errors++
		return fmt.Errorf("deregister failed: validator index %d out of range (len=%d)", validatorIndex, len(validators))
	}

	addr := validators[validatorIndex].Address
	if err := mp.qpos.slashingManager.validatorMgr.RemoveValidator(
		mp.qpos.slashingManager.systemCaller, addr,
	); err != nil {
		mp.errors++
		return fmt.Errorf("deregister failed: RemoveValidator error: %w", err)
	}

	// Only delete reputation after successful ValidatorSet removal.
	delete(mp.reputations, validatorIndex)

	return nil
}

func (mp *MinistryPersonnel) GetReputation(validatorIndex int) *ReputationRecord {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	if r, ok := mp.reputations[validatorIndex]; ok {
		copy := &ReputationRecord{
			ValidatorIndex: r.ValidatorIndex,
			Score:          r.Score,
			LastUpdated:    r.LastUpdated,
			TotalBlocks:    r.TotalBlocks,
			TotalAttests:   r.TotalAttests,
			TotalSeals:     r.TotalSeals,
			TotalSlashes:   r.TotalSlashes,
			Penalties:      r.Penalties,
			Bonuses:        r.Bonuses,
		}
		return copy
	}
	return nil
}

func (mp *MinistryPersonnel) RecordBlockProduced(caller types.Address, validatorIndex int, blockTime ...int64) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot record block produced")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can record block produced")
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}

	r, ok := mp.reputations[validatorIndex]
	if !ok {
		r = &ReputationRecord{
			ValidatorIndex: validatorIndex,
			Score:          DefaultReputationScore,
			LastUpdated:    now,
		}
		mp.reputations[validatorIndex] = r
	}

	r.TotalBlocks++
	r.Bonuses++
	r.Score += ReputationBonusBlock
	if r.Score > MaxReputationScore {
		r.Score = MaxReputationScore
	}
	r.LastUpdated = now
	return nil
}

func (mp *MinistryPersonnel) RecordAttestation(caller types.Address, validatorIndex int, blockTime ...int64) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot record attestation")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can record attestation")
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}

	r, ok := mp.reputations[validatorIndex]
	if !ok {
		r = &ReputationRecord{
			ValidatorIndex: validatorIndex,
			Score:          DefaultReputationScore,
			LastUpdated:    now,
		}
		mp.reputations[validatorIndex] = r
	}

	r.TotalAttests++
	r.Bonuses++
	r.Score += ReputationBonusAttest
	if r.Score > MaxReputationScore {
		r.Score = MaxReputationScore
	}
	r.LastUpdated = now
	return nil
}

func (mp *MinistryPersonnel) RecordSeal(caller types.Address, validatorIndex int, blockTime ...int64) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot record seal")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can record seal")
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}

	r, ok := mp.reputations[validatorIndex]
	if !ok {
		r = &ReputationRecord{
			ValidatorIndex: validatorIndex,
			Score:          DefaultReputationScore,
			LastUpdated:    now,
		}
		mp.reputations[validatorIndex] = r
	}

	r.TotalSeals++
	r.Bonuses++
	r.Score += ReputationBonusSeal
	if r.Score > MaxReputationScore {
		r.Score = MaxReputationScore
	}
	r.LastUpdated = now
	return nil
}

func (mp *MinistryPersonnel) RecordSlashing(caller types.Address, validatorIndex int, reason SlashingReason, blockTime ...int64) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot record slashing")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can record slashing")
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}

	r, ok := mp.reputations[validatorIndex]
	if !ok {
		r = &ReputationRecord{
			ValidatorIndex: validatorIndex,
			Score:          DefaultReputationScore,
			LastUpdated:    now,
		}
		mp.reputations[validatorIndex] = r
	}

	r.TotalSlashes++
	r.Penalties++

	penalty := ReputationPenaltyDowntime
	switch reason {
	case SlashingReasonDoubleSigning, SlashingReasonSurroundVote, SlashingReasonDoubleVote:
		penalty = ReputationPenaltySlashing
	case SlashingReasonInvalidVRF:
		penalty = ReputationPenaltySlashing / 2
	}

	r.Score -= penalty
	if r.Score < MinReputationScore {
		r.Score = MinReputationScore
	}
	r.LastUpdated = now
	return nil
}

func (mp *MinistryPersonnel) DecayReputations(caller types.Address, blockTime ...int64) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot decay reputations")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can decay reputations")
	}

	mp.mu.Lock()
	defer mp.mu.Unlock()

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}

	for _, r := range mp.reputations {
		if r.Score > DefaultReputationScore {
			r.Score -= ReputationDecayRate
			if r.Score < DefaultReputationScore {
				r.Score = DefaultReputationScore
			}
		}
		r.LastUpdated = now
	}
	return nil
}

func (mp *MinistryPersonnel) GetEligibleForExecutive(epoch uint64) []int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	type scoredValidator struct {
		index int
		score int
	}

	candidates := make([]scoredValidator, 0)
	for idx, r := range mp.reputations {
		if r.Score >= DefaultReputationScore && r.TotalSlashes == 0 {
			if mp.coordinator != nil {
				chamber := mp.coordinator.assignment.GetChamber(idx)
				if chamber == ChamberNone || chamber == ChamberExecutive {
					candidates = append(candidates, scoredValidator{index: idx, score: r.Score})
				}
			} else {
				candidates = append(candidates, scoredValidator{index: idx, score: r.Score})
			}
		}
	}

	result := make([]int, len(candidates))
	for i, c := range candidates {
		result[i] = c.index
	}
	return result
}

func (mp *MinistryPersonnel) GetChamberAssignments() map[ChamberID][]int {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	result := map[ChamberID][]int{
		ChamberProposing: {},
		ChamberReview:    {},
		ChamberExecutive: {},
	}

	if mp.coordinator != nil {
		result[ChamberProposing] = mp.coordinator.assignment.GetValidatorsInChamber(ChamberProposing)
		result[ChamberReview] = mp.coordinator.assignment.GetValidatorsInChamber(ChamberReview)
		result[ChamberExecutive] = mp.coordinator.assignment.GetValidatorsInChamber(ChamberExecutive)
	}

	return result
}

func (mp *MinistryPersonnel) GetStatus() map[string]any {
	mp.mu.RLock()
	defer mp.mu.RUnlock()

	totalScore := 0
	activeCount := 0
	for _, r := range mp.reputations {
		totalScore += r.Score
		if r.Score >= DefaultReputationScore {
			activeCount++
		}
	}

	avgScore := 0
	if len(mp.reputations) > 0 {
		avgScore = totalScore / len(mp.reputations)
	}

	return map[string]any{
		"ministry":      MinistryIDPersonnel.String(),
		"displayName":   MinistryIDPersonnel.DisplayName(),
		"active":        true,
		"operations":    mp.operations,
		"errors":        mp.errors,
		"lastActive":    mp.lastActive,
		"trackedCount":  len(mp.reputations),
		"activeCount":   activeCount,
		"avgReputation": avgScore,
	}
}

// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

type DisputeType uint8

const (
	DisputeNone               DisputeType = 0
	DisputeDoubleSpend        DisputeType = 1
	DisputeFork               DisputeType = 2
	DisputeInvalidBlock       DisputeType = 3
	DisputeProposerMisconduct DisputeType = 4
)

func (d DisputeType) String() string {
	switch d {
	case DisputeNone:
		return "None"
	case DisputeDoubleSpend:
		return "DoubleSpend"
	case DisputeFork:
		return "Fork"
	case DisputeInvalidBlock:
		return "InvalidBlock"
	case DisputeProposerMisconduct:
		return "ProposerMisconduct"
	default:
		return fmt.Sprintf("Unknown(%d)", d)
	}
}

type DisputeStatus uint8

const (
	DisputeStatusPending  DisputeStatus = 0
	DisputeStatusVerified DisputeStatus = 1
	DisputeStatusRejected DisputeStatus = 2
	DisputeStatusResolved DisputeStatus = 3
)

func (d DisputeStatus) String() string {
	switch d {
	case DisputeStatusPending:
		return "Pending"
	case DisputeStatusVerified:
		return "Verified"
	case DisputeStatusRejected:
		return "Rejected"
	case DisputeStatusResolved:
		return "Resolved"
	default:
		return fmt.Sprintf("Unknown(%d)", d)
	}
}

type DisputeCase struct {
	ID         uint64
	Type       DisputeType
	Status     DisputeStatus
	Slot       uint64
	BlockHash  types.Hash
	Accuser    int
	Accused    int
	Evidence   *SlashingEvidence
	Verdict    string
	CreatedAt  time.Time
	ResolvedAt time.Time
}

type MinistryJustice struct {
	mu sync.RWMutex

	qpos        *QPOS
	coordinator *ThreeChambersCoordinator
	registry    *MinistryRegistry

	cases      map[uint64]*DisputeCase
	nextCaseID uint64
	maxCases   int

	// GOV-R7-07 (Low): oldestCaseID tracks the smallest live case ID so
	// that SubmitDispute can evict the oldest case in O(1) instead of
	// scanning the whole map (O(N), N=maxCases=10000). caseID is a
	// monotonically increasing counter assigned in SubmitDispute, and the
	// ONLY deletion path that targets the oldest case is SubmitDispute
	// itself (verified by searching for `delete(mj.cases` — there is no
	// other call site). Therefore the smallest live caseID is always
	// either oldestCaseID (still present) or the next non-deleted ID
	// after it (after a wraparound / store reload). recomputeOldestLocked
	// restores the invariant when LoadJustice repopulates cases.
	oldestCaseID uint64

	operations uint64
	errors     uint64
	lastActive time.Time
}

func NewMinistryJustice(qpos *QPOS, coordinator *ThreeChambersCoordinator, registry *MinistryRegistry) *MinistryJustice {
	return &MinistryJustice{
		qpos:         qpos,
		coordinator:  coordinator,
		registry:     registry,
		cases:        make(map[uint64]*DisputeCase),
		nextCaseID:   1,
		oldestCaseID: 1,
		maxCases:     10000,
	}
}

func (mj *MinistryJustice) SubmitDispute(caller types.Address, disputeType DisputeType, slot uint64, blockHash types.Hash, accuserIndex int, accusedIndex int, evidence *SlashingEvidence, blockTime ...int64) (uint64, error) {
	if caller == (types.Address{}) {
		return 0, fmt.Errorf("unauthorized: zero address cannot submit disputes")
	}
	if !isSystemCaller(caller) {
		return 0, fmt.Errorf("unauthorized: only system callers can submit disputes")
	}

	mj.mu.Lock()
	defer mj.mu.Unlock()
	mj.operations++
	mj.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	if disputeType == DisputeNone {
		mj.errors++
		return 0, fmt.Errorf("invalid dispute type")
	}

	if accusedIndex < 0 {
		mj.errors++
		return 0, fmt.Errorf("invalid accused validator index")
	}

	caseID := mj.nextCaseID
	mj.nextCaseID++

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}
	caseRecord := &DisputeCase{
		ID:        caseID,
		Type:      disputeType,
		Status:    DisputeStatusPending,
		Slot:      slot,
		BlockHash: blockHash,
		Accuser:   accuserIndex,
		Accused:   accusedIndex,
		Evidence:  evidence,
		CreatedAt: now,
	}

	if len(mj.cases) >= mj.maxCases {
		// GOV-R7-07 (Low): Evict in O(1) using oldestCaseID instead of
		// scanning the whole map. Because caseID is monotonically
		// increasing and SubmitDispute is the only deletion site, the
		// smallest live caseID is oldestCaseID (or the next ID that
		// still exists if oldestCaseID was skipped — e.g. after a store
		// reload). The fallback scan below only runs in that rare case,
		// keeping the steady-state cost O(1).
		evictID := mj.oldestCaseID
		if _, ok := mj.cases[evictID]; !ok {
			// Fallback: rescan to find the smallest live caseID. This is
			// O(N) but only happens once after a store reload or if the
			// invariant is broken; after the rescan oldestCaseID is
			// re-anchored and subsequent evictions are O(1) again.
			evictID = ^uint64(0)
			for id := range mj.cases {
				if id < evictID {
					evictID = id
				}
			}
		}
		if evictID != ^uint64(0) {
			delete(mj.cases, evictID)
			mj.oldestCaseID = evictID + 1
		}
	}

	mj.cases[caseID] = caseRecord

	// P3-T2 (2026-07-15): Structured audit log for dispute submission.
	if mj.registry != nil {
		mj.registry.logAudit(MinistryIDJustice, "submit_dispute", caller,
			fmt.Sprintf("caseID=%d type=%d slot=%d accuser=%d accused=%d",
				caseID, disputeType, slot, accuserIndex, accusedIndex),
			"ok", now)
	}

	return caseID, nil
}

func (mj *MinistryJustice) VerifyEvidence(caller types.Address, caseID uint64, blockTime ...int64) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot verify evidence")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can verify evidence")
	}

	mj.mu.Lock()
	defer mj.mu.Unlock()
	mj.operations++
	mj.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	caseRecord, exists := mj.cases[caseID]
	if !exists {
		mj.errors++
		return fmt.Errorf("case %d not found", caseID)
	}

	if caseRecord.Status != DisputeStatusPending {
		mj.errors++
		return fmt.Errorf("case %d is not pending (status: %s)", caseID, caseRecord.Status)
	}

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}

	if caseRecord.Evidence == nil {
		caseRecord.Status = DisputeStatusRejected
		caseRecord.Verdict = "no evidence provided"
		caseRecord.ResolvedAt = now
		return fmt.Errorf("no evidence provided for case %d", caseID)
	}

	// GOV-R5-02 (2026-07-16): Fail-closed when verification dependencies
	// are missing. Previously, when qpos==nil OR slashingManager==nil, the
	// verification block was SKIPPED and the code fell through to mark the
	// evidence as Verified — allowing unverified disputes to proceed to
	// ExecuteSlashing via ResolveDispute (which only requires Status==
	// Verified). This is a fail-open vulnerability: misconfiguration or
	// partial deployment enables wrongful slashing.
	//
	// Fix: when either dependency is nil, the evidence CANNOT be verified,
	// so the dispute is rejected with a descriptive verdict. This prevents
	// the dispute from being used to trigger slashing until the dependency
	// is properly wired. Operators must fix the configuration and re-submit.
	if mj.qpos == nil {
		mj.errors++
		caseRecord.Status = DisputeStatusRejected
		caseRecord.Verdict = "evidence verification failed: qpos not configured (fail-closed)"
		caseRecord.ResolvedAt = now
		return fmt.Errorf("case %d: cannot verify evidence: qpos not configured (fail-closed)", caseID)
	}
	if mj.qpos.slashingManager == nil {
		mj.errors++
		caseRecord.Status = DisputeStatusRejected
		caseRecord.Verdict = "evidence verification failed: slashing manager not configured (fail-closed)"
		caseRecord.ResolvedAt = now
		return fmt.Errorf("case %d: cannot verify evidence: slashing manager not configured (fail-closed)", caseID)
	}

	// R33 P2-18 FIX: Pass blockTime to VerifyEvidence for deterministic freshness check.
	if err := mj.qpos.slashingManager.VerifyEvidence(caseRecord.Evidence, blockTime...); err != nil {
		caseRecord.Status = DisputeStatusRejected
		caseRecord.Verdict = fmt.Sprintf("evidence verification failed: %v", err)
		caseRecord.ResolvedAt = now
		return nil
	}

	caseRecord.Status = DisputeStatusVerified
	return nil
}

func (mj *MinistryJustice) ResolveDispute(caller types.Address, caseID uint64, guilty bool, verdict string, blockTime ...int64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can resolve disputes. This is defense-in-depth on top of the
	// state-machine gating (require Verified status) already in place.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot resolve disputes")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can resolve disputes")
	}

	mj.mu.Lock()
	defer mj.mu.Unlock()
	mj.operations++
	mj.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	caseRecord, exists := mj.cases[caseID]
	if !exists {
		mj.errors++
		return fmt.Errorf("case %d not found", caseID)
	}

	if caseRecord.Status == DisputeStatusResolved {
		mj.errors++
		return fmt.Errorf("case %d already resolved", caseID)
	}

	// AUDIT (2026) GOV-03: Require that the dispute evidence has been
	// verified before allowing resolution. Previously, ResolveDispute could
	// be called on a Pending case (not yet verified) and still trigger
	// ExecuteSlashing, bypassing the evidence verification step entirely.
	if caseRecord.Status != DisputeStatusVerified {
		mj.errors++
		return fmt.Errorf("case %d must be verified before resolution (current status: %s)", caseID, caseRecord.Status)
	}

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	now := time.Now()
	if len(blockTime) > 0 {
		now = time.Unix(blockTime[0], 0)
	}

	if guilty {
		if mj.registry != nil && mj.registry.Revenue() != nil && caseRecord.Evidence != nil {
			vs := mj.qpos.GetValidatorSet()
			if vs != nil {
				validators := vs.Validators()
				if caseRecord.Accused < len(validators) {
					accused := validators[caseRecord.Accused]
					_, err := mj.registry.Revenue().ExecuteSlashing(
						caller,
						caseRecord.Accused,
						caseRecord.Evidence.Reason,
						accused.Stake,
						SlotToEpoch(caseRecord.Slot),
						// AUDIT (2026) R4-GOV-02: Pass the evidence's block
						// height (not the epoch) so the double-punishment guard's
						// offense key matches the key used by SubmitEvidence.
						caseRecord.Evidence.Height,
						blockTime...,
					)
					if err != nil {
						// P0-T3 (2026-07-14): Roll back to Pending on slashing failure.
						// Previously the case stayed in Verified, which technically
						// allowed retries but didn't match the "fail → reset" contract.
						// Rolling back to Pending forces re-verification of evidence
						// before another resolution attempt, preventing repeated
						// slashing attempts against a potentially stale case.
						caseRecord.Status = DisputeStatusPending
						mj.errors++
						return fmt.Errorf("resolve dispute failed: execute slashing failed (case rolled back to Pending): %w", err)
					}
				}
			}
		}

		caseRecord.Status = DisputeStatusResolved
		caseRecord.Verdict = verdict
		caseRecord.ResolvedAt = now
	} else {
		caseRecord.Status = DisputeStatusResolved
		caseRecord.Verdict = verdict
		caseRecord.ResolvedAt = now
	}

	// P3-T2 (2026-07-15): Structured audit log for dispute resolution.
	if mj.registry != nil {
		mj.registry.logAudit(MinistryIDJustice, "resolve_dispute", caller,
			fmt.Sprintf("caseID=%d guilty=%v verdict=%s", caseID, guilty, verdict),
			"ok", now)
	}

	return nil
}

func (mj *MinistryJustice) GetCase(caseID uint64) *DisputeCase {
	mj.mu.RLock()
	defer mj.mu.RUnlock()

	if c, ok := mj.cases[caseID]; ok {
		copy := &DisputeCase{
			ID:         c.ID,
			Type:       c.Type,
			Status:     c.Status,
			Slot:       c.Slot,
			BlockHash:  c.BlockHash,
			Accuser:    c.Accuser,
			Accused:    c.Accused,
			Verdict:    c.Verdict,
			CreatedAt:  c.CreatedAt,
			ResolvedAt: c.ResolvedAt,
		}
		return copy
	}
	return nil
}

func (mj *MinistryJustice) GetPendingCases() []uint64 {
	mj.mu.RLock()
	defer mj.mu.RUnlock()

	result := make([]uint64, 0)
	for id, c := range mj.cases {
		if c.Status == DisputeStatusPending {
			result = append(result, id)
		}
	}
	return result
}

func (mj *MinistryJustice) GetCasesByAccused(accusedIndex int) []uint64 {
	mj.mu.RLock()
	defer mj.mu.RUnlock()

	result := make([]uint64, 0)
	for id, c := range mj.cases {
		if c.Accused == accusedIndex {
			result = append(result, id)
		}
	}
	return result
}

func (mj *MinistryJustice) ArbitrateFork(caller types.Address, slot uint64, competingBlocks []types.Hash) (types.Hash, error) {
	if caller == (types.Address{}) {
		return types.Hash{}, fmt.Errorf("unauthorized: zero address cannot arbitrate forks")
	}
	if !isSystemCaller(caller) {
		return types.Hash{}, fmt.Errorf("unauthorized: only system callers can arbitrate forks")
	}

	mj.mu.Lock()
	defer mj.mu.Unlock()
	mj.operations++
	mj.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	if len(competingBlocks) == 0 {
		mj.errors++
		return types.Hash{}, fmt.Errorf("no competing blocks provided")
	}

	if len(competingBlocks) == 1 {
		return competingBlocks[0], nil
	}

	if mj.coordinator == nil {
		mj.errors++
		return types.Hash{}, fmt.Errorf("coordinator not available for fork arbitration")
	}

	review := mj.coordinator.GetReviewChamber()
	if review == nil {
		mj.errors++
		return types.Hash{}, fmt.Errorf("review chamber not available")
	}

	// P0-T4 (2026-07-14): Per-hash fork choice. Previously, ArbitrateFork
	// always returned competingBlocks[0] regardless of approval status —
	// the loop checked IsBlockApproved(slot) (slot-scoped) instead of
	// checking which specific hash was approved.
	//
	// Now we use ReviewChamber.IsHashApproved(slot, hash) which checks both:
	//   1. The slot is approved (VerdictApproved), AND
	//   2. The hash matches the expected canonical block root for that slot.
	//
	// Algorithm:
	//   1. Iterate over competing blocks, return the first approved hash.
	//   2. If no block is approved, fail-closed (return error). The caller
	//      should wait for review approval rather than selecting a block
	//      via a grindable tiebreaker.
	for _, hash := range competingBlocks {
		if review.IsHashApproved(slot, hash) {
			return hash, nil
		}
	}

	// GOV-R5-03 (2026-07-17): No block was approved by the review chamber.
	// Previously, this fell back to a "lexicographically smallest hash"
	// tiebreaker to ensure all honest nodes converged on the same block.
	// However, this tiebreaker is grindable: a proposer can manipulate
	// block contents (e.g., nonce, extra data) to produce a smaller hash,
	// biasing fork choice in their favor without review approval.
	//
	// Fix: fail-closed — return an error so the caller waits for review
	// approval rather than selecting a block via a biased tiebreaker. This
	// eliminates the grinding vector entirely. All honest nodes will still
	// converge (they all receive the same error and wait), preserving
	// consensus safety at the cost of temporary liveness during network
	// partitions or startup — which is the correct safety/liveness tradeoff
	// for a fork arbitration mechanism.
	mj.errors++
	return types.Hash{}, fmt.Errorf(
		"GOV-R5-03: no competing block is approved for slot %d — refusing to use grindable hash tiebreaker; wait for review approval",
		slot,
	)
}

func (mj *MinistryJustice) GetStatus() map[string]any {
	mj.mu.RLock()
	defer mj.mu.RUnlock()

	pending := 0
	verified := 0
	rejected := 0
	resolved := 0
	for _, c := range mj.cases {
		switch c.Status {
		case DisputeStatusPending:
			pending++
		case DisputeStatusVerified:
			verified++
		case DisputeStatusRejected:
			rejected++
		case DisputeStatusResolved:
			resolved++
		}
	}

	return map[string]any{
		"ministry":    MinistryIDJustice.String(),
		"displayName": MinistryIDJustice.DisplayName(),
		"active":      true,
		"operations":  mj.operations,
		"errors":      mj.errors,
		"lastActive":  mj.lastActive,
		"totalCases":  len(mj.cases),
		"pending":     pending,
		"verified":    verified,
		"rejected":    rejected,
		"resolved":    resolved,
	}
}

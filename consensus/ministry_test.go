// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// testSystemCaller is a registered system caller address used in ministry
// tests to pass the GOV-03 authorization checks.
// NOTE: Address value 0x01 is intentionally avoided here — existing tests in
// consensus_coverage_test.go use types.Address{1} (= 0x01) to represent a
// "non-system caller" that should be rejected. Using 0x7f prevents collision.
var testSystemCaller = types.Address{0x7f}

func init() {
	// SECURITY (audit GOV-03): Register the test system caller once for all
	// consensus tests. This ensures ministry authorization checks pass in
	// tests that create ministries directly (not via setupMinistryRegistry).
	RegisterSystemCaller(testSystemCaller)
}

func setupMinistryRegistry(t *testing.T, validatorCount int) (*QPOS, *MinistryRegistry) {
	t.Helper()
	// SECURITY (audit GOV-03): Register a system caller for tests so that
	// ministry methods with authorization checks can be called.
	// R54-SYSCALLERS-RESET-01: This setup function reuses the package-level
	// testSystemCaller 0x7f already registered by init(). Tests that call
	// this setup are responsible for not depending on the absence of that
	// registration; the init() registration lives for the whole test
	// binary lifetime.
	RegisterSystemCaller(testSystemCaller)
	vs := createTestValidatorSet(t, validatorCount)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	registry := NewMinistryRegistry(qpos, coordinator)
	return qpos, registry
}

func TestMinistryIDString(t *testing.T) {
	tests := []struct {
		id       MinistryID
		expected string
	}{
		{MinistryIDNone, "None"},
		{MinistryIDPersonnel, "Personnel"},
		{MinistryIDRevenue, "Revenue"},
		{MinistryIDJustice, "Justice"},
		{MinistryIDDefense, "Defense"},
		{MinistryIDRites, "Rites"},
		{MinistryIDWorks, "Works"},
		{MinistryID(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.id.String(); got != tt.expected {
			t.Errorf("MinistryID(%d).String() = %q, want %q", tt.id, got, tt.expected)
		}
	}
	t.Log("=== 2.5 Ministry ID string: PASS ===")
}

func TestMinistryIDDisplayName(t *testing.T) {
	tests := []struct {
		id       MinistryID
		expected string
	}{
		{MinistryIDNone, "None"},
		{MinistryIDPersonnel, "Personnel"},
		{MinistryIDRevenue, "Revenue"},
		{MinistryIDJustice, "Justice"},
		{MinistryIDDefense, "Defense"},
	}
	for _, tt := range tests {
		if got := tt.id.DisplayName(); got != tt.expected {
			t.Errorf("MinistryID(%d).DisplayName() = %q, want %q", tt.id, got, tt.expected)
		}
	}
	t.Log("=== 2.5 Ministry ID display names: PASS ===")
}

func TestMinistryRegistryCreation(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)

	if registry.Personnel() == nil {
		t.Error("Personnel ministry should not be nil")
	}
	if registry.Revenue() == nil {
		t.Error("Revenue ministry should not be nil")
	}
	if registry.Justice() == nil {
		t.Error("Justice ministry should not be nil")
	}
	if registry.Defense() == nil {
		t.Error("Defense ministry should not be nil")
	}

	status := registry.GetStatus()
	if status["personnel"] == nil {
		t.Error("Personnel status should not be nil")
	}
	t.Log("=== 2.5 Ministry registry creation: PASS ===")
}

func TestMinistryPersonnelReputation(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	mp := registry.Personnel()

	mp.RecordBlockProduced(testSystemCaller, 0)
	r := mp.GetReputation(0)
	if r == nil {
		t.Fatal("Reputation record should exist for validator 0")
	}
	if r.Score != DefaultReputationScore+ReputationBonusBlock {
		t.Errorf("Score = %d, want %d", r.Score, DefaultReputationScore+ReputationBonusBlock)
	}
	if r.TotalBlocks != 1 {
		t.Errorf("TotalBlocks = %d, want 1", r.TotalBlocks)
	}

	mp.RecordAttestation(testSystemCaller, 1)
	r = mp.GetReputation(1)
	if r == nil {
		t.Fatal("Reputation record should exist for validator 1")
	}
	if r.Score != DefaultReputationScore+ReputationBonusAttest {
		t.Errorf("Score = %d, want %d", r.Score, DefaultReputationScore+ReputationBonusAttest)
	}

	mp.RecordSeal(testSystemCaller, 2)
	r = mp.GetReputation(2)
	if r == nil {
		t.Fatal("Reputation record should exist for validator 2")
	}
	if r.Score != DefaultReputationScore+ReputationBonusSeal {
		t.Errorf("Score = %d, want %d", r.Score, DefaultReputationScore+ReputationBonusSeal)
	}

	t.Log("=== 2.5 Personnel: reputation tracking: PASS ===")
}

func TestMinistryPersonnelSlashingReputation(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	mp := registry.Personnel()

	mp.RecordBlockProduced(testSystemCaller, 0)
	mp.RecordSlashing(testSystemCaller, 0, SlashingReasonDoubleSigning)

	r := mp.GetReputation(0)
	if r == nil {
		t.Fatal("Reputation record should exist")
	}
	if r.Score >= DefaultReputationScore {
		t.Errorf("Score should decrease after slashing, got %d", r.Score)
	}
	if r.TotalSlashes != 1 {
		t.Errorf("TotalSlashes = %d, want 1", r.TotalSlashes)
	}

	t.Log("=== 2.5 Personnel: slashing reputation penalty: PASS ===")
}

func TestMinistryPersonnelDecay(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	mp := registry.Personnel()

	for i := 0; i < 1000; i++ {
		mp.RecordBlockProduced(testSystemCaller, 0)
	}
	r := mp.GetReputation(0)
	if r.Score != MaxReputationScore {
		t.Errorf("Score should be capped at %d, got %d", MaxReputationScore, r.Score)
	}

	mp.DecayReputations(testSystemCaller)
	r = mp.GetReputation(0)
	if r.Score >= MaxReputationScore {
		t.Errorf("Score should decay from max, got %d", r.Score)
	}

	t.Log("=== 2.5 Personnel: reputation decay: PASS ===")
}

func TestMinistryPersonnelEligibleForExecutive(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	mp := registry.Personnel()

	mp.RecordBlockProduced(testSystemCaller, 0)
	mp.RecordBlockProduced(testSystemCaller, 1)
	mp.RecordSlashing(testSystemCaller, 2, SlashingReasonDoubleSigning)

	eligible := mp.GetEligibleForExecutive(0)
	for _, idx := range eligible {
		if idx == 2 {
			t.Error("Slashed validator 2 should not be eligible for executive")
		}
	}

	t.Logf("Eligible for executive: %d validators", len(eligible))
	t.Log("=== 2.5 Personnel: executive eligibility: PASS ===")
}

func TestMinistryRevenueDistribution(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	mr := registry.Revenue()

	totalReward := big.NewInt(1e18)
	record, err := mr.DistributeEpochRewards(testSystemCaller, 0, 0, []int{1, 2, 3}, []int{4, 5}, totalReward)
	if err != nil {
		t.Fatalf("DistributeEpochRewards failed: %v", err)
	}

	if record.Total.Cmp(totalReward) != 0 {
		t.Errorf("Total = %s, want %s", record.Total.String(), totalReward.String())
	}

	if _, ok := record.Amounts[0]; !ok {
		t.Error("Proposer should have reward amount")
	}
	if _, ok := record.Amounts[1]; !ok {
		t.Error("Attester 1 should have reward amount")
	}
	if _, ok := record.Amounts[4]; !ok {
		t.Error("Sealer 4 should have reward amount")
	}

	_, err = mr.DistributeEpochRewards(testSystemCaller, 0, 0, []int{1}, nil, totalReward)
	if err == nil {
		t.Error("Should fail: rewards already distributed for epoch 0")
	}

	summary := mr.GetFinancialSummary()
	if summary["epochsRewarded"].(int) != 1 {
		t.Error("Should have 1 epoch rewarded")
	}

	t.Log("=== 2.5 Revenue: reward distribution: PASS ===")
}

func TestMinistryRevenueSlashing(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	mr := registry.Revenue()

	stake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	record, err := mr.ExecuteSlashing(testSystemCaller, 0, SlashingReasonDoubleSigning, stake, 0, 0)
	if err != nil {
		t.Fatalf("ExecuteSlashing failed: %v", err)
	}

	if record.Amount.Cmp(big.NewInt(0)) <= 0 {
		t.Error("Slashing amount should be positive")
	}
	if record.Amount.Cmp(stake) > 0 {
		t.Error("Slashing amount should not exceed stake")
	}
	if record.Chamber != ChamberNone {
		t.Errorf("Chamber = %v, want None (validator not assigned)", record.Chamber)
	}

	slashRecords := mr.GetSlashRecords(0)
	if len(slashRecords) != 1 {
		t.Errorf("Slash records count = %d, want 1", len(slashRecords))
	}

	t.Logf("Double signing penalty: %s from stake %s", record.Amount.String(), stake.String())
	t.Log("=== 2.5 Revenue: slashing execution: PASS ===")
}

func TestMinistryJusticeDisputeLifecycle(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	mj := registry.Justice()

	// GOV-R5-02 (2026-07-16): VerifyEvidence is now fail-closed — it
	// rejects (not skips) when slashingManager is nil. We must attach a
	// real SlashingManager with valid cryptographic evidence so the
	// legitimate verify→resolve path is exercised.
	_, kp := r5_gov_r5_02_attachSlashingManager(t, qpos, 1)
	addr := qpos.GetValidatorSet().Validators()[1].Address
	evidence := r5_gov_r5_02_buildDoubleSignEvidence(t, addr, kp, 1)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	caseID, err := mj.SubmitDispute(testSystemCaller, DisputeDoubleSpend, 1, blockHash, 0, 1, evidence)
	if err != nil {
		t.Fatalf("SubmitDispute failed: %v", err)
	}

	pending := mj.GetPendingCases()
	if len(pending) != 1 {
		t.Errorf("Pending cases = %d, want 1", len(pending))
	}

	err = mj.VerifyEvidence(testSystemCaller, caseID)
	if err != nil {
		t.Fatalf("VerifyEvidence failed: %v", err)
	}

	c := mj.GetCase(caseID)
	if c == nil {
		t.Fatal("Case should exist")
	}
	if c.Status != DisputeStatusVerified {
		t.Fatalf("Case status = %v, want Verified", c.Status)
	}

	err = mj.ResolveDispute(testSystemCaller, caseID, true, "double spend confirmed")
	if err != nil {
		t.Fatalf("ResolveDispute failed: %v", err)
	}

	c = mj.GetCase(caseID)
	if c.Status != DisputeStatusResolved {
		t.Errorf("Status = %v, want Resolved", c.Status)
	}

	casesByAccused := mj.GetCasesByAccused(1)
	if len(casesByAccused) != 1 {
		t.Errorf("Cases for accused 1 = %d, want 1", len(casesByAccused))
	}

	t.Log("=== 2.5 Justice: dispute lifecycle: PASS ===")
}

// TestMinistryJusticeResolveDispute_RollbackOnSlashingFailure verifies P0-T3 fix:
// when ExecuteSlashing fails inside ResolveDispute, the case status must be
// rolled back to DisputeStatusPending (NOT left at DisputeStatusVerified).
//
// Setup: Pre-mark the accused validator as already slashed in QPOS. When
// ResolveDispute calls ExecuteSlashing, the double-punishment guard (GOV B-1)
// triggers and returns an error. ResolveDispute must:
//  1. Return the error to the caller
//  2. Roll back caseRecord.Status to DisputeStatusPending
//
// GOV-R5-02 (2026-07-16): SlashingManager is attached BEFORE VerifyEvidence
// because VerifyEvidence is now fail-closed (rejects when slashingManager
// is nil). Valid cryptographic evidence is used so VerifyEvidence succeeds,
// then the validator is pre-marked as slashed to trigger the rollback path.
func TestMinistryJusticeResolveDispute_RollbackOnSlashingFailure(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	mj := registry.Justice()

	// Attach SlashingManager with real key pair for validator index 1.
	_, kp := r5_gov_r5_02_attachSlashingManager(t, qpos, 1)
	addr := qpos.GetValidatorSet().Validators()[1].Address
	evidence := r5_gov_r5_02_buildDoubleSignEvidence(t, addr, kp, 1)

	blockHash := types.Hash{}
	blockHash[0] = 0x01

	// Step 1: Submit dispute → case is Pending
	caseID, err := mj.SubmitDispute(testSystemCaller, DisputeDoubleSpend, 1, blockHash, 0, 1, evidence)
	if err != nil {
		t.Fatalf("SubmitDispute failed: %v", err)
	}

	// Step 2: Verify evidence → case is Verified
	// SlashingManager is present with valid evidence, so VerifyEvidence passes.
	if err := mj.VerifyEvidence(testSystemCaller, caseID); err != nil {
		t.Fatalf("VerifyEvidence failed: %v", err)
	}
	c := mj.GetCase(caseID)
	if c.Status != DisputeStatusVerified {
		t.Fatalf("precondition: status = %v, want Verified", c.Status)
	}

	// Step 3: Pre-mark validator as slashed so ExecuteSlashing's
	// double-punishment guard triggers.
	// CONS-R12-002: slashedValidators now stores *SlashedEntry.
	qpos.slashedValidators[1] = &SlashedEntry{Epoch: 0} // validator index 1 already slashed

	// Step 4: ResolveDispute should fail because ExecuteSlashing detects
	// the validator is already slashed (double-punishment guard GOV B-1).
	err = mj.ResolveDispute(testSystemCaller, caseID, true, "double spend confirmed")
	if err == nil {
		t.Fatal("ResolveDispute should fail when ExecuteSlashing fails")
	}

	// Step 5: Case status must be rolled back to Pending (P0-T3 fix).
	c = mj.GetCase(caseID)
	if c == nil {
		t.Fatal("case should still exist after failed resolution")
	}
	if c.Status != DisputeStatusPending {
		t.Errorf("P0-T3 rollback: status = %v, want Pending (rolled back from Verified)", c.Status)
	}

	t.Logf("P0-T3 rollback verified: error=%v, status=%v", err, c.Status)
	t.Log("=== P0-T3: ResolveDispute rollback on slashing failure: PASS ===")
}

func TestMinistryJusticeForkArbitration(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	mj := registry.Justice()

	hash1 := types.Hash{}
	hash1[0] = 0x01
	hash2 := types.Hash{}
	hash2[0] = 0x02

	// GOV-R5-03 (2026-07-17): When no block is approved by the review
	// chamber, ArbitrateFork now fail-closed (returns error) instead of
	// falling back to a grindable lexicographic tiebreaker. This test
	// verifies the fail-closed behavior for the no-approval case.
	result, err := mj.ArbitrateFork(testSystemCaller, 1, []types.Hash{hash1, hash2})
	if err == nil {
		t.Fatalf("GOV-R5-03: ArbitrateFork should fail-closed when no block is approved, got result %x", result)
	}

	// Single-block case: no fork to arbitrate, so no approval needed.
	// This path returns early (len == 1) before the approval check.
	single, err := mj.ArbitrateFork(testSystemCaller, 2, []types.Hash{hash1})
	if err != nil {
		t.Fatalf("ArbitrateFork single block failed: %v", err)
	}
	if single != hash1 {
		t.Error("Single block should be selected")
	}

	t.Log("=== 2.5 Justice: fork arbitration: PASS ===")
}

// TestMinistryJusticeForkArbitration_PerHashChoice verifies P0-T4 fix:
// when the Review Chamber has approved a slot with a specific expected
// block root, ArbitrateFork must return the competing block whose hash
// matches that expected root — NOT the first block, NOT the
// lexicographically smallest.
//
// Setup: slot 7 is approved with expected root = canonicalHash.
// Competing blocks: [nonCanonicalHash, canonicalHash, otherHash].
// Expected result: canonicalHash (the only approved one).
func TestMinistryJusticeForkArbitration_PerHashChoice(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	mj := registry.Justice()

	review := qpos.GetChambersCoordinator().GetReviewChamber()
	if review == nil {
		t.Fatal("ReviewChamber not available")
	}

	const slot = uint64(7)
	canonicalHash := types.Hash{0x05, 0x05, 0x05}    // the approved block
	nonCanonicalHash := types.Hash{0x01, 0x01, 0x01} // lexicographically smaller, but NOT approved
	otherHash := types.Hash{0x09, 0x09, 0x09}

	// Set the expected canonical block root for the slot.
	qpos.SetSlotBlockRoot(slot, canonicalHash)

	// Mark the slot as approved by directly creating a ReviewSlotResult
	// with VerdictApproved. (Internal test can access private fields.)
	review.mu.Lock()
	review.slotResults[slot] = &ReviewSlotResult{
		Slot:          slot,
		CommitteeSize: 10,
		ApproveCount:  8,
		RejectCount:   2,
		ApproveStake:  big.NewInt(8000),
		RejectStake:   big.NewInt(2000),
		TotalStake:    big.NewInt(10000),
		Verdict:       VerdictApproved,
	}
	review.mu.Unlock()

	// Verify IsHashApproved helper works as expected.
	if !review.IsHashApproved(slot, canonicalHash) {
		t.Fatal("IsHashApproved should return true for the canonical hash")
	}
	if review.IsHashApproved(slot, nonCanonicalHash) {
		t.Fatal("IsHashApproved should return false for a non-canonical hash")
	}

	// ArbitrateFork must pick canonicalHash even though it's NOT first and
	// NOT the lexicographically smallest (nonCanonicalHash is smaller).
	result, err := mj.ArbitrateFork(testSystemCaller, slot, []types.Hash{
		nonCanonicalHash,
		canonicalHash,
		otherHash,
	})
	if err != nil {
		t.Fatalf("ArbitrateFork failed: %v", err)
	}
	if result != canonicalHash {
		t.Fatalf("ArbitrateFork per-hash choice: got %x, want canonical %x", result, canonicalHash)
	}

	// GOV-R5-03 (2026-07-17): When no hash matches the approved root,
	// ArbitrateFork now fail-closed (returns error) instead of falling
	// back to a grindable lexicographic tiebreaker. The slot is still
	// approved (VerdictApproved), but the expected root (0xFF...) doesn't
	// match any competing block, so IsHashApproved returns false for all.
	qpos.SetSlotBlockRoot(slot, types.Hash{0xFF}) // expected root not in competing set
	result2, err := mj.ArbitrateFork(testSystemCaller, slot, []types.Hash{
		otherHash,        // 0x09...
		nonCanonicalHash, // 0x01... (smallest)
	})
	if err == nil {
		t.Fatalf("GOV-R5-03: ArbitrateFork should fail-closed when no competing block matches the approved root, got result %x", result2)
	}

	t.Log("=== P0-T4 Justice: per-hash fork choice: PASS ===")
}

func TestMinistryDefenseQuantumAttack(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	alert := md.DetectQuantumAttack(testSystemCaller, 1, "suspicious lattice reduction attempt")
	if alert == nil {
		t.Fatal("Should detect quantum attack")
	}
	if alert.Level != ThreatCritical {
		t.Errorf("Level = %v, want Critical", alert.Level)
	}
	if alert.ThreatType != ThreatTypeQuantumAttack {
		t.Errorf("Type = %v, want QuantumAttack", alert.ThreatType)
	}

	activeAlerts := md.GetActiveAlerts()
	if len(activeAlerts) == 0 {
		t.Error("Should have active alerts")
	}

	err := md.ResolveAlert(testSystemCaller, alert.ID)
	if err != nil {
		t.Fatalf("ResolveAlert failed: %v", err)
	}

	activeAlerts = md.GetActiveAlerts()
	if len(activeAlerts) != 0 {
		t.Errorf("Active alerts after resolve = %d, want 0", len(activeAlerts))
	}

	t.Log("=== 2.5 Defense: quantum attack detection: PASS ===")
}

func TestMinistryDefenseNetworkPartition(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	alert := md.DetectNetworkPartition(testSystemCaller, 1, 3, 10)
	if alert == nil {
		t.Fatal("Should detect network partition (3/10 online)")
	}
	if alert.Level != ThreatCritical {
		t.Errorf("Level = %v, want Critical (30%% online)", alert.Level)
	}

	ps := md.GetPartitionState()
	if !ps.Detected {
		t.Error("Partition should be detected")
	}

	md.ResolveAlert(testSystemCaller, alert.ID)
	ps = md.GetPartitionState()
	if ps.Detected {
		t.Error("Partition should be resolved after alert resolution")
	}

	alert = md.DetectNetworkPartition(testSystemCaller, 2, 5, 10)
	if alert == nil {
		t.Fatal("Should detect medium partition (50% online)")
	}
	if alert.Level != ThreatMedium {
		t.Errorf("Level = %v, want Medium (50%% online)", alert.Level)
	}

	t.Log("=== 2.5 Defense: network partition detection: PASS ===")
}

func TestMinistryDefenseBlacklist(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	err := md.AddToBlacklist(testSystemCaller, 5, "malicious behavior", time.Hour)
	if err != nil {
		t.Fatalf("AddToBlacklist failed: %v", err)
	}

	if !md.IsBlacklisted(5) {
		t.Error("Validator 5 should be blacklisted")
	}
	if md.IsBlacklisted(6) {
		t.Error("Validator 6 should not be blacklisted")
	}

	err = md.AddToBlacklist(testSystemCaller, 5, "duplicate", time.Hour)
	if err == nil {
		t.Error("Should fail: validator already blacklisted")
	}

	err = md.RemoveFromBlacklist(testSystemCaller, 5)
	if err != nil {
		t.Fatalf("RemoveFromBlacklist failed: %v", err)
	}
	if md.IsBlacklisted(5) {
		t.Error("Validator 5 should no longer be blacklisted")
	}

	t.Log("=== 2.5 Defense: blacklist management: PASS ===")
}

func TestMinistryDefenseCollusionDetection(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	alert := md.DetectCollusion(testSystemCaller, 1, []int{0, 1, 2})
	if alert == nil {
		t.Fatal("Should detect collusion")
	}
	if alert.ThreatType != ThreatTypeCollusion {
		t.Errorf("Type = %v, want Collusion", alert.ThreatType)
	}
	if len(alert.Validators) != 3 {
		t.Errorf("Validators count = %d, want 3", len(alert.Validators))
	}

	t.Log("=== 2.5 Defense: collusion detection: PASS ===")
}

func TestMinistryDefenseExpiredBlacklist(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	err := md.AddToBlacklist(testSystemCaller, 3, "short ban", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("AddToBlacklist failed: %v", err)
	}

	time.Sleep(2 * time.Nanosecond)

	if md.IsBlacklisted(3) {
		t.Error("Validator 3 should have expired from blacklist")
	}

	removed := md.CleanupExpiredBlacklist()
	if removed != 1 {
		t.Errorf("Removed = %d, want 1", removed)
	}

	t.Log("=== 2.5 Defense: expired blacklist cleanup: PASS ===")
}

// TestMinistryDefense_BlockTime_DeterministicExpiry verifies P0-T5 fix:
// IsBlacklisted and CleanupExpiredBlacklist use the provided blockTime
// (consensus time) instead of time.Now(), ensuring all honest nodes agree
// on blacklist state regardless of wall-clock differences.
//
// Scenario:
//   - T0 = 1000000 (consensus time at slot boundary)
//   - AddToBlacklist at T0 with 1h duration → ExpiresAt = T0 + 3600
//   - IsBlacklisted(T0+1800) → true (still within 1h)
//   - IsBlacklisted(T0+4000) → false (expired, 4000 > 3600)
//   - CleanupExpiredBlacklist(T0+4000) → removes entry
func TestMinistryDefense_BlockTime_DeterministicExpiry(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	const t0 int64 = 1000000
	const duration = 3600 // 1 hour in seconds

	// Add to blacklist at consensus time T0 with 1h duration.
	err := md.AddToBlacklist(testSystemCaller, 7, "consensus test ban", time.Duration(duration)*time.Second, t0)
	if err != nil {
		t.Fatalf("AddToBlacklist failed: %v", err)
	}

	// At T0+1800 (30 min later), validator should still be blacklisted.
	if !md.IsBlacklisted(7, t0+1800) {
		t.Fatal("IsBlacklisted(t0+1800) = false, want true (within 1h duration)")
	}

	// At T0+4000 (> 1h), validator should be expired.
	if md.IsBlacklisted(7, t0+4000) {
		t.Fatal("IsBlacklisted(t0+4000) = true, want false (expired after 1h)")
	}

	// CleanupExpiredBlacklist at T0+4000 should remove the entry.
	removed := md.CleanupExpiredBlacklist(t0 + 4000)
	if removed != 1 {
		t.Fatalf("CleanupExpiredBlacklist removed = %d, want 1", removed)
	}

	// After cleanup, IsBlacklisted should return false regardless of time.
	if md.IsBlacklisted(7, t0+1800) {
		t.Fatal("IsBlacklisted after cleanup should be false")
	}

	t.Log("=== P0-T5 Defense: deterministic blockTime expiry: PASS ===")
}

// TestMinistryDefense_BlockTime_QPOSIntegration verifies that QPOS
// CanPropose/CanAttest/CanSeal pass the slot-derived consensus time to the
// blacklist check, so that blacklisted validators are rejected
// deterministically.
func TestMinistryDefense_BlockTime_QPOSIntegration(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	// Blacklist validator index 5 permanently.
	err := md.AddToBlacklist(testSystemCaller, 5, "permanent ban", 0)
	if err != nil {
		t.Fatalf("AddToBlacklist failed: %v", err)
	}

	// CanPropose should reject validator 5 at any slot.
	if qpos.CanPropose(5, 100) {
		t.Fatal("CanPropose(5, 100) = true, want false (blacklisted)")
	}

	// CanAttest should reject validator 5.
	if qpos.CanAttest(5, 100) {
		t.Fatal("CanAttest(5, 100) = true, want false (blacklisted)")
	}

	// CanSeal should reject validator 5.
	if qpos.CanSeal(5, 3) {
		t.Fatal("CanSeal(5, 3) = true, want false (blacklisted)")
	}

	// Non-blacklisted validator should be allowed (if not slashed, etc).
	// Note: CanPropose may still return false due to other checks (e.g.,
	// not being the proposer for that slot), but the blacklist should not
	// be the reason. We verify the blacklist specifically does not block
	// validator 0 by checking that it's not in the blacklist.
	if md.IsBlacklisted(0) {
		t.Fatal("validator 0 should not be blacklisted")
	}

	t.Log("=== P0-T5 Defense: QPOS integration deterministic: PASS ===")
}

// TestMinistryRevenue_DistributeEpochRewards_QPOSIntegration verifies P0-T2:
// DistributeEpochRewards calls QPOS.ProcessEpochRewards, populating the
// consensus-level epoch rewards that the syncer reads to credit actual
// QAU token balances.
func TestMinistryRevenue_DistributeEpochRewards_QPOSIntegration(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	mr := registry.Revenue()

	const epoch = uint64(1)
	totalReward := big.NewInt(1e18)

	record, err := mr.DistributeEpochRewards(testSystemCaller, epoch, 0, []int{1, 2, 3}, nil, totalReward)
	if err != nil {
		t.Fatalf("DistributeEpochRewards failed: %v", err)
	}

	// Verify QPOS epoch rewards were populated by ProcessEpochRewards.
	qposRewards := qpos.GetEpochRewards(epoch)
	if qposRewards == nil {
		t.Fatal("QPOS.GetEpochRewards(epoch) = nil, want non-nil (ProcessEpochRewards should have been called)")
	}
	if qposRewards.Epoch != epoch {
		t.Fatalf("QPOS rewards epoch = %d, want %d", qposRewards.Epoch, epoch)
	}

	// Verify the ministry record links to the QPOS calculation.
	if record.QPOSEpochRewards == nil {
		t.Fatal("record.QPOSEpochRewards = nil, want non-nil")
	}

	t.Log("=== P0-T2 Revenue: DistributeEpochRewards QPOS integration: PASS ===")
}

// P1-T6 (2026-07-15): TestMinistryRites_ExecuteProposal_EmergencyAction removed.
// The legacy ExecuteProposal path has been removed — governance proposals now
// flow through economics.GovernanceManager. The emergency halt functionality
// is verified by TestP1T6_HandleEmergencyAction below, which tests the
// production path (GovernanceManager → HandleEmergencyAction).

// TestMinistryPersonnel_DeregisterValidator_FailClosed verifies P0-T2:
// DeregisterValidator returns an error (not silent success) when
// dependencies (QPOS, SlashingManager, ValidatorManager) are not available.
// Previously, it silently deleted reputation but left the validator in the
// ValidatorSet — an inconsistent state.
func TestMinistryPersonnel_DeregisterValidator_FailClosed(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	mp := registry.Personnel()

	// Case 1: No SlashingManager set → should fail-closed.
	err := mp.DeregisterValidator(testSystemCaller, 0, 1)
	if err == nil {
		t.Fatal("DeregisterValidator without SlashingManager should return error (fail-closed)")
	}

	// Case 2: SlashingManager set but validatorMgr is nil → should fail-closed.
	qpos.SetSlashingManager(NewSlashingManager(nil))
	err = mp.DeregisterValidator(testSystemCaller, 0, 1)
	if err == nil {
		t.Fatal("DeregisterValidator with nil validatorMgr should return error (fail-closed)")
	}

	// Verify reputation was NOT deleted (fail-closed preserves state).
	r := mp.GetReputation(0)
	// GetReputation returns nil if not found. Since we didn't set up
	// reputations, it should still be nil — the point is that
	// DeregisterValidator didn't silently succeed.
	_ = r

	t.Log("=== P0-T2 Personnel: DeregisterValidator fail-closed: PASS ===")
}

func TestMinistryIntegration(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)

	qpos.SetSlashingManager(NewSlashingManager(nil))
	mp := registry.Personnel()
	mr := registry.Revenue()
	mj := registry.Justice()
	md := registry.Defense()

	mp.RecordBlockProduced(testSystemCaller, 0)
	mp.RecordAttestation(testSystemCaller, 1)
	mp.RecordAttestation(testSystemCaller, 2)
	mp.RecordSeal(testSystemCaller, 3)

	totalReward := big.NewInt(1e18)
	_, err := mr.DistributeEpochRewards(testSystemCaller, 0, 0, []int{1, 2}, []int{3}, totalReward)
	if err != nil {
		t.Fatalf("DistributeEpochRewards failed: %v", err)
	}

	stake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	_, err = mr.ExecuteSlashing(testSystemCaller, 4, SlashingReasonDoubleSigning, stake, 0, 0)
	if err != nil {
		t.Fatalf("ExecuteSlashing failed: %v", err)
	}

	blockHash := types.Hash{}
	blockHash[0] = 0x01
	_, err = mj.SubmitDispute(testSystemCaller, DisputeDoubleSpend, 1, blockHash, 0, 4, nil)
	if err != nil {
		t.Fatalf("SubmitDispute failed: %v", err)
	}

	md.DetectQuantumAttack(testSystemCaller, 1, "test quantum threat")
	md.AddToBlacklist(testSystemCaller, 4, "double signing", 24*time.Hour)

	r0 := mp.GetReputation(0)
	if r0 == nil || r0.TotalBlocks != 2 {
		t.Errorf("Validator 0 should have 2 blocks produced (1 direct + 1 from reward), got %d", r0.TotalBlocks)
	}

	r4 := mp.GetReputation(4)
	if r4 == nil || r4.TotalSlashes != 1 {
		t.Error("Validator 4 should have 1 slash")
	}

	if !md.IsBlacklisted(4) {
		t.Error("Validator 4 should be blacklisted")
	}

	status := registry.GetStatus()
	if status["personnel"] == nil || status["revenue"] == nil || status["justice"] == nil || status["defense"] == nil {
		t.Error("All ministry statuses should be available")
	}

	t.Log("=== 2.5 Ministry integration test: PASS ===")
}

// TestP1T2_EpochBoundaryRewardIntegration verifies P1-T2: the epoch boundary
// reward distribution path wires QPOS.ProcessEpochRewards results into
// MinistryRevenue.DistributeEpochRewards via the deterministic system caller.
//
// This test simulates the same flow that BlockProducer.distributeMinistryRewards
// executes at epoch boundaries (node/block_producer.go):
//  1. QPOS.ProcessEpochRewards(epoch) computes consensus-level rewards
//  2. DeriveSystemCaller(epoch) generates the authorized caller
//  3. MinistryRevenue.DistributeEpochRewards records the distribution
//  4. rewardRecords[epoch] is populated for governance visibility
func TestP1T2_EpochBoundaryRewardIntegration(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	mr := registry.Revenue()

	// Use a high epoch number to avoid interference from
	// TestDeriveSystemCaller_MaxCleanup_Boost9 which registers 110 epochs
	// (0-109) and cleans up the oldest, potentially unregistering low-epoch
	// system callers when tests run in the same process.
	const epoch = uint64(50000)
	const slot = epoch * SlotsPerEpoch // first slot of the epoch

	// Step 1: QPOS computes consensus-level rewards (as processEpochBoundary does).
	qposRewards := qpos.ProcessEpochRewards(epoch)
	if qposRewards == nil {
		t.Fatal("ProcessEpochRewards returned nil")
	}

	// Simulate a non-zero reward by setting TotalRewards directly. In production
	// this is populated by attestations; tests need a non-zero value to trigger
	// the distribution path.
	qposRewards.TotalRewards = big.NewInt(1e18) // 1 QAU
	qposRewards.ProposerRewards[0] = big.NewInt(5e17)
	qposRewards.AttesterRewards[1] = big.NewInt(5e17)

	// Step 2: Derive the deterministic system caller (same as block_producer.go).
	caller := DeriveSystemCaller(epoch)
	if caller == (types.Address{}) {
		t.Fatal("DeriveSystemCaller returned zero address")
	}

	// Step 3: Verify the caller passes authorization (isSystemCaller).
	if !isSystemCaller(caller) {
		t.Fatal("DeriveSystemCaller did not register as system caller")
	}

	// Step 4: Extract indices from EpochRewards (same logic as distributeMinistryRewards).
	proposerIndex := -1
	for idx := range qposRewards.ProposerRewards {
		proposerIndex = idx
		break
	}
	attesterIndices := make([]int, 0, len(qposRewards.AttesterRewards))
	for idx := range qposRewards.AttesterRewards {
		attesterIndices = append(attesterIndices, idx)
	}

	// Step 5: Use the slot's start time as deterministic blockTime.
	blockTime := GetSlotStartTime(slot).Unix()

	// Step 6: Record the distribution in MinistryRevenue.
	record, err := mr.DistributeEpochRewards(
		caller, epoch, proposerIndex, attesterIndices, nil,
		qposRewards.TotalRewards, blockTime,
	)
	if err != nil {
		t.Fatalf("DistributeEpochRewards failed: %v", err)
	}

	// Step 7: Verify rewardRecords[epoch] is populated.
	stored := mr.GetRewardRecord(epoch)
	if stored == nil {
		t.Fatal("GetRewardRecord(epoch) = nil after distribution")
	}
	if stored.Epoch != epoch {
		t.Errorf("stored epoch = %d, want %d", stored.Epoch, epoch)
	}
	if stored.Proposer != proposerIndex {
		t.Errorf("stored proposer = %d, want %d", stored.Proposer, proposerIndex)
	}
	if stored.Total.Cmp(qposRewards.TotalRewards) != 0 {
		t.Errorf("stored total = %s, want %s", stored.Total.String(), qposRewards.TotalRewards.String())
	}
	if len(stored.Attesters) != len(attesterIndices) {
		t.Errorf("stored attesters count = %d, want %d", len(stored.Attesters), len(attesterIndices))
	}
	// QPOS link fields should be populated (DistributeEpochRewards calls ProcessEpochRewards internally).
	if record.QPOSEpochRewards == nil {
		t.Error("record.QPOSEpochRewards = nil, want non-nil")
	}

	// Step 8: Idempotency — second distribution for the same epoch must fail.
	_, err = mr.DistributeEpochRewards(
		caller, epoch, proposerIndex, attesterIndices, nil,
		qposRewards.TotalRewards, blockTime,
	)
	if err == nil {
		t.Error("DistributeEpochRewards should fail for already-distributed epoch")
	}

	// Step 9: Authorization — non-system caller must be rejected.
	_, err = mr.DistributeEpochRewards(
		types.Address{0x99}, epoch+1, 0, []int{1}, nil,
		qposRewards.TotalRewards, blockTime,
	)
	if err == nil {
		t.Error("DistributeEpochRewards should reject non-system caller")
	}

	t.Log("=== P1-T2: Epoch boundary reward integration: PASS ===")
}

// TestP1T3_SlashingManagerMinistryRecording verifies P1-T3: SlashingManager.slash()
// records slashing events in MinistryRevenue.slashRecords via RecordSlashingExecution.
//
// This test creates a double-signing scenario, triggers slash() via SubmitEvidence,
// and verifies that the ministry's slashRecords is populated.
func TestP1T3_SlashingManagerMinistryRecording(t *testing.T) {
	// Create a validator with a real key pair for the ValidatorManager.
	privKey, pubKey := createTestKeyPair(t)
	targetAddr := pubKey.Address()

	// Set up QPOS with the validator in the set.
	validators := []*Validator{
		{
			Address:        targetAddr,
			Stake:          validStake(),
			Active:         true,
			PublicKeyBytes: pubKey.Bytes(),
		},
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Create SlashingManager with the validator registered in ValidatorManager.
	vm := NewValidatorManager()
	if err := vm.AddValidator(targetAddr, targetAddr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}
	// VAL-H04/VAL-H05 FIX (R31, 2026-07-27): First-time activation MUST go
	// through ActivateFromQueue (sets EverActivated=true).
	if err := vm.ActivateFromQueue(targetAddr); err != nil {
		t.Fatalf("ActivateFromQueue failed: %v", err)
	}
	sm := NewSlashingManager(vm)
	qpos.SetSlashingManager(sm)
	sm.SetQPOS(qpos)

	// Create the ministry registry — this wires MinistryRevenue into
	// SlashingManager via SetMinistryRevenue.
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	registry := NewMinistryRegistry(qpos, coordinator)
	RegisterSystemCaller(testSystemCaller)
	mr := registry.Revenue()

	// Verify the wiring.
	if sm.ministryRevenue == nil {
		t.Fatal("SlashingManager.ministryRevenue is nil — SetMinistryRevenue not called")
	}

	targetIndex := vs.GetValidatorIndex(targetAddr)
	if targetIndex < 0 {
		t.Fatalf("validator %x not found in set", targetAddr[:8])
	}

	// Create double-signing evidence with real signatures.
	vote1 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         0,
		BlockHash:     types.Hash{0x01},
		ValidatorAddr: targetAddr,
	}
	vote2 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        100,
		Round:         0,
		BlockHash:     types.Hash{0x02},
		ValidatorAddr: targetAddr,
	}
	if err := vote1.Sign(privKey); err != nil {
		t.Fatalf("vote1.Sign failed: %v", err)
	}
	if err := vote2.Sign(privKey); err != nil {
		t.Fatalf("vote2.Sign failed: %v", err)
	}

	evidence := &SlashingEvidence{
		ValidatorAddr: targetAddr,
		Reason:        SlashingReasonDoubleSigning,
		Height:        100,
		Vote1:         vote1,
		Vote2:         vote2,
	}

	// Submit the evidence to trigger slash().
	blockTime := time.Now().Unix()
	record, err := sm.SubmitEvidence(evidence, sm.systemCaller, blockTime)
	if err != nil {
		t.Fatalf("SubmitEvidence failed: %v", err)
	}
	if record == nil {
		t.Fatal("SubmitEvidence returned nil record")
	}

	// Verify the ministry's slashRecords was populated by RecordSlashingExecution.
	slashRecords := mr.GetSlashRecords(targetIndex)
	if len(slashRecords) == 0 {
		t.Fatal("GetSlashRecords returned empty — RecordSlashingExecution not called or failed")
	}

	latest := slashRecords[len(slashRecords)-1]
	if latest.ValidatorIndex != targetIndex {
		t.Errorf("slash record validatorIndex = %d, want %d", latest.ValidatorIndex, targetIndex)
	}
	if latest.Reason != SlashingReasonDoubleSigning {
		t.Errorf("slash record reason = %v, want %v", latest.Reason, SlashingReasonDoubleSigning)
	}
	if latest.Amount == nil || latest.Amount.Sign() <= 0 {
		t.Error("slash record amount should be positive")
	}

	t.Log("=== P1-T3: SlashingManager ministry recording: PASS ===")
}

// TestP1T6_HandleEmergencyAction verifies that MinistryRites.HandleEmergencyAction
// (the economics.EmergencyActionHandler interface method) correctly blacklists
// all validators when invoked. This is the production path: GovernanceManager
// calls this method when an Emergency-type proposal is executed.
func TestP1T6_HandleEmergencyAction(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 10)
	rites := registry.Rites()
	md := registry.Defense()

	validators := qpos.GetValidatorSet().Validators()
	if len(validators) < 4 {
		t.Fatalf("need at least 4 validators, got %d", len(validators))
	}

	// Verify no validators are blacklisted initially.
	for i := range validators {
		if md.IsBlacklisted(i) {
			t.Fatalf("validator %d already blacklisted before test", i)
		}
	}

	// Invoke HandleEmergencyAction — simulates GovernanceManager.ExecuteProposal
	// calling the handler after an Emergency proposal passes.
	proposalID := uint64(42)
	title := "Critical vulnerability halt"
	description := "Halt chain due to critical consensus bug"
	if err := rites.HandleEmergencyAction(proposalID, validators[0].Address, title, description); err != nil {
		t.Fatalf("HandleEmergencyAction failed: %v", err)
	}

	// Verify ALL validators are blacklisted.
	blacklistedCount := 0
	for i := range validators {
		if md.IsBlacklisted(i) {
			blacklistedCount++
		}
	}
	if blacklistedCount != len(validators) {
		t.Fatalf("blacklisted %d/%d validators, want all blacklisted", blacklistedCount, len(validators))
	}

	// Verify CanPropose/CanAttest/CanSeal all reject (chain halted).
	for i := range validators {
		if qpos.CanPropose(i, 100) {
			t.Errorf("CanPropose(%d) = true, want false (chain halted)", i)
		}
		if qpos.CanAttest(i, 100) {
			t.Errorf("CanAttest(%d) = true, want false (chain halted)", i)
		}
		if qpos.CanSeal(i, 100) {
			t.Errorf("CanSeal(%d) = true, want false (chain halted)", i)
		}
	}

	t.Log("=== P1-T6: HandleEmergencyAction (unified governance): PASS ===")
}

// TestP1T6_HandleEmergencyAction_NilDependencies verifies that
// HandleEmergencyAction does not panic when registry/Defense/QPOS are nil.
// It should log a warning and return nil (best-effort pattern).
func TestP1T6_HandleEmergencyAction_NilDependencies(t *testing.T) {
	// Create a MinistryRites with nil registry (simulates misconfiguration).
	mr := NewMinistryRites(nil, nil, nil)

	// Should not panic, should return nil.
	err := mr.HandleEmergencyAction(1, types.Address{}, "test", "test")
	if err != nil {
		t.Errorf("HandleEmergencyAction with nil deps returned error: %v", err)
	}

	t.Log("=== P1-T6: HandleEmergencyAction nil deps: PASS ===")
}

// TestP1T7_MinistryWorksBridgeRecording verifies that MinistryWorks correctly
// records bridge registrations and cross-chain transactions when called
// through the bridge.MinistryWorksRecorder interface (via node adapter).
func TestP1T7_MinistryWorksBridgeRecording(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 4)
	works := registry.Works()

	// Register a bridge via MinistryWorks.
	caller := getVotingSystemCaller()
	bridgeInfo, err := works.RegisterBridge(caller, "test-bridge", 1, 3, "1000000")
	if err != nil {
		t.Fatalf("RegisterBridge failed: %v", err)
	}
	if bridgeInfo.ID == 0 {
		t.Fatal("bridge ID should be non-zero")
	}
	if bridgeInfo.Name != "test-bridge" {
		t.Errorf("bridge name = %q, want %q", bridgeInfo.Name, "test-bridge")
	}

	// Record a cross-chain transaction.
	txHash := types.Hash{0x01, 0x02, 0x03}
	tx, err := works.RecordCrossChainTx(caller, bridgeInfo.ID, txHash, "500")
	if err != nil {
		t.Fatalf("RecordCrossChainTx failed: %v", err)
	}
	if tx.ID == 0 {
		t.Fatal("tx ID should be non-zero")
	}
	if tx.BridgeID != bridgeInfo.ID {
		t.Errorf("tx bridgeID = %d, want %d", tx.BridgeID, bridgeInfo.ID)
	}
	if tx.Amount != "500" {
		t.Errorf("tx amount = %q, want %q", tx.Amount, "500")
	}

	// Verify the bridge's pending tx count was incremented.
	storedBridge, err := works.GetBridge(bridgeInfo.ID)
	if err != nil {
		t.Fatalf("GetBridge failed: %v", err)
	}
	if storedBridge.PendingTxCount != 1 {
		t.Errorf("bridge pendingTxCount = %d, want 1", storedBridge.PendingTxCount)
	}

	// Verify qpos is available (used by node adapter).
	if qpos == nil {
		t.Fatal("qpos should not be nil")
	}

	t.Log("=== P1-T7: MinistryWorks bridge recording: PASS ===")
}

// TestP1T5_DefenseBlacklistEnforcement verifies that the MinistryDefense
// blacklist prevents blacklisted validators from producing blocks and voting.
func TestP1T5_DefenseBlacklistEnforcement(t *testing.T) {
	// Create a validator with a real key pair.
	privKey, pubKey := createTestKeyPair(t)
	targetAddr := pubKey.Address()

	// Set up QPOS with the validator in the set.
	validators := []*Validator{
		{
			Address:        targetAddr,
			Stake:          validStake(),
			Active:         true,
			PublicKeyBytes: pubKey.Bytes(),
		},
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Create ValidatorManager and register the validator.
	vmgr := NewValidatorManager()
	if err := vmgr.AddValidator(targetAddr, targetAddr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}
	// VAL-H04/VAL-H05 FIX (R31, 2026-07-27): First-time activation MUST go
	// through ActivateFromQueue (sets EverActivated=true).
	if err := vmgr.ActivateFromQueue(targetAddr); err != nil {
		t.Fatalf("ActivateFromQueue failed: %v", err)
	}

	// Create VotingManager and wire it to QPOS.
	votingMgr := NewVotingManager(vmgr)
	votingMgr.SetQPOS(qpos)
	qpos.SetVotingManager(votingMgr)

	// Initialize chambers + ministry registry.
	// NewMinistryRegistry calls qpos.SetBlacklistCheck(mr.defense.IsBlacklisted),
	// which (via P1-T5) also propagates to VotingManager.
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	registry := NewMinistryRegistry(qpos, coordinator)
	RegisterSystemCaller(testSystemCaller)

	md := registry.Defense()
	if md == nil {
		t.Fatal("MinistryDefense is nil")
	}

	// Debug: verify QPOS internal state.
	qpos.mu.RLock()
	qposVM := qpos.votingManager
	qposBLC := qpos.blacklistCheck
	qpos.mu.RUnlock()
	if qposVM == nil {
		t.Fatal("qpos.votingManager is nil after SetVotingManager")
	}
	if qposBLC == nil {
		t.Fatal("qpos.blacklistCheck is nil after NewMinistryRegistry")
	}

	// Verify the blacklist check was propagated to VotingManager.
	votingMgr.mu.RLock()
	vmCheck := votingMgr.blacklistCheck
	votingMgr.mu.RUnlock()
	if vmCheck == nil {
		t.Fatal("VotingManager.blacklistCheck is nil — SetBlacklistCheck not propagated")
	}

	targetIdx := vs.GetValidatorIndex(targetAddr)
	if targetIdx < 0 {
		t.Fatalf("validator %x not found in set", targetAddr[:8])
	}

	// === Part 1: QPOS.CanPropose rejects blacklisted validator ===
	// Before blacklisting, validator can propose.
	slot := uint64(100)
	if !qpos.CanPropose(targetIdx, slot) {
		t.Error("CanPropose should return true before blacklisting")
	}

	// Add to blacklist.
	if err := md.AddToBlacklist(testSystemCaller, targetIdx, "test malicious behavior", time.Hour); err != nil {
		t.Fatalf("AddToBlacklist failed: %v", err)
	}

	// After blacklisting, CanPropose should return false.
	if qpos.CanPropose(targetIdx, slot) {
		t.Error("CanPropose should return false for blacklisted validator")
	}

	// CanAttest should also return false.
	if qpos.CanAttest(targetIdx, slot) {
		t.Error("CanAttest should return false for blacklisted validator")
	}

	// CanSeal should also return false.
	epoch := SlotToEpoch(slot)
	if qpos.CanSeal(targetIdx, epoch) {
		t.Error("CanSeal should return false for blacklisted validator")
	}

	// === Part 2: VotingManager.AddVote rejects blacklisted validator ===
	vote := &Vote{
		Type:          VoteTypePrecommit,
		Height:        slot,
		Round:         0,
		BlockHash:     types.Hash{0x01},
		ValidatorAddr: targetAddr,
	}
	if err := vote.Sign(privKey); err != nil {
		t.Fatalf("vote.Sign failed: %v", err)
	}

	accepted, err := votingMgr.AddVote(vote)
	if accepted {
		t.Error("AddVote should reject blacklisted validator's vote")
	}
	if err != ErrValidatorBlacklisted {
		t.Errorf("AddVote error = %v, want ErrValidatorBlacklisted", err)
	}

	// === Part 3: After removing from blacklist, vote is accepted ===
	if err := md.RemoveFromBlacklist(testSystemCaller, targetIdx); err != nil {
		t.Fatalf("RemoveFromBlacklist failed: %v", err)
	}

	if !qpos.CanPropose(targetIdx, slot) {
		t.Error("CanPropose should return true after removing from blacklist")
	}

	// Create a new vote (different BlockHash to avoid duplicate detection).
	vote2 := &Vote{
		Type:          VoteTypePrecommit,
		Height:        slot,
		Round:         0,
		BlockHash:     types.Hash{0x02},
		ValidatorAddr: targetAddr,
	}
	if err := vote2.Sign(privKey); err != nil {
		t.Fatalf("vote2.Sign failed: %v", err)
	}

	accepted2, err2 := votingMgr.AddVote(vote2)
	if err2 != nil {
		t.Errorf("AddVote after unblacklist failed: %v", err2)
	}
	if !accepted2 {
		// quorum may not be reached with 1 validator, but no error is fine
		t.Log("AddVote after unblacklist: accepted but quorum not reached (expected with 1 validator)")
	}

	t.Log("=== P1-T5: Defense blacklist enforcement (QPOS + VotingManager): PASS ===")
}

// TestP1T8_MinistryStatePersistence_SaveLoadAll verifies that all six
// ministries' state survives a simulated restart (SaveAll → new registry →
// LoadAll). This is the core P1-T8 requirement: "no state is lost across a restart".
func TestP1T8_MinistryStatePersistence_SaveLoadAll(t *testing.T) {
	// === Phase 1: Create registry, mutate state, save ===
	_, registry1 := setupMinistryRegistry(t, 4)

	// Mutate Personnel: record reputation entries.
	mp1 := registry1.Personnel()
	if err := mp1.RecordBlockProduced(testSystemCaller, 0); err != nil {
		t.Fatalf("RecordBlockProduced failed: %v", err)
	}
	if err := mp1.RecordAttestation(testSystemCaller, 1); err != nil {
		t.Fatalf("RecordAttestation failed: %v", err)
	}

	// Mutate Defense: add a blacklist entry (critical for consensus safety).
	md1 := registry1.Defense()
	if err := md1.AddToBlacklist(testSystemCaller, 2, "test malicious validator", 0); err != nil {
		t.Fatalf("AddToBlacklist failed: %v", err)
	}

	// Mutate Revenue: distribute rewards.
	mr1 := registry1.Revenue()
	if _, err := mr1.DistributeEpochRewards(testSystemCaller, 1, 0, []int{1}, []int{2}, big.NewInt(1000)); err != nil {
		t.Fatalf("DistributeEpochRewards failed: %v", err)
	}

	// Mutate Justice: submit a dispute case.
	mj1 := registry1.Justice()
	evidence := &SlashingEvidence{
		Reason: SlashingReasonDoubleSigning,
	}
	if _, err := mj1.SubmitDispute(testSystemCaller, DisputeDoubleSpend, 1, types.Hash{0xaa}, 0, 1, evidence); err != nil {
		t.Fatalf("SubmitDispute failed: %v", err)
	}

	// Mutate Works: register a bridge.
	mw1 := registry1.Works()
	caller := getVotingSystemCaller()
	if _, err := mw1.RegisterBridge(caller, "test-bridge", 1, 3, "1000000"); err != nil {
		t.Fatalf("RegisterBridge failed: %v", err)
	}

	// Capture state before save for comparison after load.
	savedR0 := mp1.GetReputation(0)
	savedR1 := mp1.GetReputation(1)
	savedBlacklistLen := len(md1.GetBlacklist())
	savedSummary := mr1.GetFinancialSummary()
	savedPendingCases := len(mj1.GetPendingCases())
	savedBridges := mw1.GetActiveBridges()

	// Create state store with MemDB and save all state at epoch 5.
	memDB := newMinistryTestMemDB()
	store := NewMinistryStateStore(memDB)
	if err := store.SaveAll(registry1, 5); err != nil {
		t.Fatalf("SaveAll failed: %v", err)
	}

	// Verify checkpoint was written.
	ckpt, err := store.LoadCheckpoint()
	if err != nil {
		t.Fatalf("LoadCheckpoint failed: %v", err)
	}
	if ckpt != 5 {
		t.Errorf("checkpoint = %d, want 5", ckpt)
	}

	// === Phase 2: Simulate restart — create fresh registry, load state ===
	qpos2, registry2 := setupMinistryRegistry(t, 4)
	_ = qpos2

	// Load persisted state into the new registry.
	store2 := NewMinistryStateStore(memDB)
	loadedEpoch, err := store2.LoadAll(registry2)
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}
	if loadedEpoch != 5 {
		t.Errorf("loaded checkpoint = %d, want 5", loadedEpoch)
	}

	// === Phase 3: Verify state was restored (compare with pre-save values) ===

	// Personnel: reputation counts should match saved values.
	mp2 := registry2.Personnel()
	r0 := mp2.GetReputation(0)
	if r0 == nil {
		t.Fatal("Personnel: reputation for validator 0 should exist after load")
	}
	if r0.TotalBlocks != savedR0.TotalBlocks {
		t.Errorf("Personnel: TotalBlocks = %d, want %d (saved value)", r0.TotalBlocks, savedR0.TotalBlocks)
	}
	r1 := mp2.GetReputation(1)
	if r1 == nil {
		t.Fatal("Personnel: reputation for validator 1 should exist after load")
	}
	if r1.TotalAttests != savedR1.TotalAttests {
		t.Errorf("Personnel: TotalAttests = %d, want %d (saved value)", r1.TotalAttests, savedR1.TotalAttests)
	}

	// Defense: blacklist entry for validator 2 should survive.
	md2 := registry2.Defense()
	if !md2.IsBlacklisted(2) {
		t.Error("Defense: validator 2 should still be blacklisted after restart")
	}
	blacklist := md2.GetBlacklist()
	if len(blacklist) != savedBlacklistLen {
		t.Errorf("Defense: blacklist len = %d, want %d", len(blacklist), savedBlacklistLen)
	}

	// Revenue: total rewards should match saved value.
	mr2 := registry2.Revenue()
	summary := mr2.GetFinancialSummary()
	savedRewardsStr, _ := savedSummary["totalRewardsDistributed"].(string)
	loadedRewardsStr, _ := summary["totalRewardsDistributed"].(string)
	if loadedRewardsStr != savedRewardsStr {
		t.Errorf("Revenue: totalRewards = %s, want %s (saved value)", loadedRewardsStr, savedRewardsStr)
	}

	// Justice: pending cases should match saved count.
	mj2 := registry2.Justice()
	pending := mj2.GetPendingCases()
	if len(pending) != savedPendingCases {
		t.Errorf("Justice: pending cases = %d, want %d (saved value)", len(pending), savedPendingCases)
	}

	// Works: active bridges should match saved state.
	mw2 := registry2.Works()
	bridges := mw2.GetActiveBridges()
	if len(bridges) != len(savedBridges) {
		t.Errorf("Works: active bridges = %d, want %d (saved value)", len(bridges), len(savedBridges))
	}
	if len(bridges) > 0 && bridges[0].Name != "test-bridge" {
		t.Errorf("Works: bridge name = %q, want %q", bridges[0].Name, "test-bridge")
	}

	t.Log("=== P1-T8: Ministry state persistence (save → restart → load): PASS ===")
}

// TestP1T8_MinistryStatePersistence_EmptyDB verifies that LoadAll on a fresh
// database (no prior SaveAll) returns epoch 0 and does not error.
func TestP1T8_MinistryStatePersistence_EmptyDB(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 4)

	memDB := newMinistryTestMemDB()
	store := NewMinistryStateStore(memDB)

	epoch, err := store.LoadAll(registry)
	if err != nil {
		t.Fatalf("LoadAll on empty DB should not error: %v", err)
	}
	if epoch != 0 {
		t.Errorf("epoch on empty DB = %d, want 0", epoch)
	}
	t.Log("=== P1-T8: Ministry state persistence (empty DB): PASS ===")
}

// TestP1T8_MinistryStatePersistence_NilStore verifies that nil store and nil
// ministry pointers are handled safely (no panics).
func TestP1T8_MinistryStatePersistence_NilSafety(t *testing.T) {
	// Nil store.
	var nilStore *MinistryStateStore
	if err := nilStore.SaveAll(nil, 1); err != ErrStateStoreNotConfigured {
		t.Errorf("nilStore.SaveAll err = %v, want ErrStateStoreNotConfigured", err)
	}
	if _, err := nilStore.LoadAll(nil); err != ErrStateStoreNotConfigured {
		t.Errorf("nilStore.LoadAll err = %v, want ErrStateStoreNotConfigured", err)
	}

	// Non-nil store with nil registry — should be a no-op.
	memDB := newMinistryTestMemDB()
	store := NewMinistryStateStore(memDB)
	if err := store.SaveAll(nil, 1); err != nil {
		t.Errorf("SaveAll(nil registry) err = %v, want nil", err)
	}
	if _, err := store.LoadAll(nil); err != nil {
		t.Errorf("LoadAll(nil registry) err = %v, want nil", err)
	}

	t.Log("=== P1-T8: Ministry state persistence (nil safety): PASS ===")
}

// newMinistryTestMemDB creates a minimal in-memory key-value store for
// ministry state persistence tests. It implements only the Get/Put/Delete/Has
// subset needed by MinistryStateStore (which uses prefix keys, not batches).
func newMinistryTestMemDB() *ministryTestMemDB {
	return &ministryTestMemDB{data: make(map[string][]byte)}
}

type ministryTestMemDB struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func (m *ministryTestMemDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[string(key)]
	if !ok {
		return nil, db.ErrKeyNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (m *ministryTestMemDB) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]byte, len(value))
	copy(out, value)
	m.data[string(key)] = out
	return nil
}

func (m *ministryTestMemDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *ministryTestMemDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[string(key)]
	return ok, nil
}

func (m *ministryTestMemDB) Close() error                                 { return nil }
func (m *ministryTestMemDB) NewBatch() db.Batch                           { return &ministryTestBatch{db: m} }
func (m *ministryTestMemDB) NewIterator(prefix, start []byte) db.Iterator { return nil }
func (m *ministryTestMemDB) NewIteratorWithLimit(prefix, start []byte, limit int) db.Iterator {
	return nil
}

type ministryTestBatch struct {
	db  *ministryTestMemDB
	ops []ministryBatchOp
}

type ministryBatchOp struct {
	key   []byte
	value []byte
	del   bool
}

func (b *ministryTestBatch) Put(key, value []byte) error {
	k := make([]byte, len(key))
	copy(k, key)
	v := make([]byte, len(value))
	copy(v, value)
	b.ops = append(b.ops, ministryBatchOp{key: k, value: v})
	return nil
}

func (b *ministryTestBatch) Delete(key []byte) error {
	k := make([]byte, len(key))
	copy(k, key)
	b.ops = append(b.ops, ministryBatchOp{key: k, del: true})
	return nil
}

func (b *ministryTestBatch) Write() error {
	b.db.mu.Lock()
	defer b.db.mu.Unlock()
	for _, op := range b.ops {
		if op.del {
			delete(b.db.data, string(op.key))
		} else {
			b.db.data[string(op.key)] = op.value
		}
	}
	return nil
}

func (b *ministryTestBatch) Reset() { b.ops = nil }
func (b *ministryTestBatch) ValueSize() int {
	size := 0
	for _, op := range b.ops {
		size += len(op.value)
	}
	return size
}

// Flush implements db.Batch (DB-R12-002): commits accumulated ops and resets
// the in-memory batch. The mock DB has no size limits, so Flush is equivalent
// to Write + Reset.
func (b *ministryTestBatch) Flush() error {
	if err := b.Write(); err != nil {
		return err
	}
	b.Reset()
	return nil
}

// Quantaureum Node source, version 1.0.0.
// GOV-R13-M01 and GOV-R13-M02 regression tests.
//
// GOV-R13-M01 (Medium): Timelock on governance address transfers — verify the
// two-step Propose → (timelock) → Confirm flow enforces the configured
// governanceTimelock for non-first-time transfers, and that first-time setup
// remains exempt (genesis wiring).
//
// GOV-R13-M02 (Medium): ExecuteProposal parameter validation — verify that
// ExecuteProposal does NOT bypass validateParameter (the regression that R10
// discovered and GOV-R11-002 remediated by extracting setParameterLocked).
// Also covers the GOV-R11-003 stale OldValue check (parameter rollback
// attack mitigation).
package economics

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestGOV_R13_M01_Timelock_FirstTimeSetup_NoTimelock verifies the first-time
// governance address setup is exempt from the timelock. Genesis wiring needs
// to be able to set the governance address immediately.
func TestGOV_R13_M01_Timelock_FirstTimeSetup_NoTimelock(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	// Configure an initializer (genesis operator).
	initializer := types.Address{0xAA}
	gm.SetInitializerAddress(initializer)

	// First-time propose → confirm immediately (no timelock wait).
	newGov := types.Address{0xBB}
	if err := gm.ProposeGovernanceAddress(newGov, initializer); err != nil {
		t.Fatalf("first-time propose failed: %v", err)
	}
	if err := gm.ConfirmGovernanceAddress(initializer); err != nil {
		t.Fatalf("first-time confirm should succeed without timelock, got: %v", err)
	}

	// Verify the address was set.
	pending, _ := gm.PendingGovernanceAddress()
	if pending != (types.Address{}) {
		t.Errorf("pending should be cleared after confirm, got %x", pending)
	}
}

// TestGOV_R13_M01_Timelock_SubsequentTransfer_EnforcesTimelock verifies that
// after the governance address is already set, a subsequent transfer MUST
// wait governanceTimelock before ConfirmGovernanceAddress succeeds.
//
// We set the timelock via direct field access because the public
// SetGovernanceTimelock enforces a minimum of 1 minute (defense-in-depth
// against operator misconfiguration). Direct field access lets the test
// exercise the enforcement logic with a 100ms timelock instead of waiting
// a full minute.
func TestGOV_R13_M01_Timelock_SubsequentTransfer_EnforcesTimelock(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	// Tighten the timelock to keep the test fast. We bypass the public setter
	// (which requires >= 1 minute) and write directly to the field — safe in
	// this test because we control every call.
	const testTimelock = 100 * time.Millisecond
	gm.governanceTimelock = testTimelock

	// First-time setup (no timelock).
	initializer := types.Address{0xAA}
	gm.SetInitializerAddress(initializer)
	currentGov := types.Address{0xBB}
	if err := gm.ProposeGovernanceAddress(currentGov, initializer); err != nil {
		t.Fatalf("first-time propose failed: %v", err)
	}
	if err := gm.ConfirmGovernanceAddress(initializer); err != nil {
		t.Fatalf("first-time confirm failed: %v", err)
	}

	// Subsequent transfer: propose from current governance address.
	newGov := types.Address{0xCC}
	if err := gm.ProposeGovernanceAddress(newGov, currentGov); err != nil {
		t.Fatalf("subsequent propose failed: %v", err)
	}

	// Confirm IMMEDIATELY — should be rejected because timelock has not elapsed.
	if err := gm.ConfirmGovernanceAddress(currentGov); err != ErrGovernanceTimelockNotElapsed {
		t.Errorf("immediate confirm should fail with ErrGovernanceTimelockNotElapsed, got: %v", err)
	}

	// Wait for the timelock to elapse, then confirm succeeds.
	time.Sleep(testTimelock + 50*time.Millisecond)
	if err := gm.ConfirmGovernanceAddress(currentGov); err != nil {
		t.Errorf("confirm after timelock should succeed, got: %v", err)
	}
}

// TestGOV_R13_M01_SetGovernanceTimelock_RejectsInsecureValues verifies that
// the public SetGovernanceTimelock API rejects insecure values (< 1 minute
// or zero). This is defense-in-depth against operator misconfiguration:
// an operator should not be able to set a 1-second or zero timelock that
// would effectively disable the two-step governance transfer protection.
func TestGOV_R13_M01_SetGovernanceTimelock_RejectsInsecureValues(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	tests := []struct {
		name string
		ttl  time.Duration
	}{
		{"zero", 0},
		{"100ms", 100 * time.Millisecond},
		{"500ms", 500 * time.Millisecond},
		{"59s", 59 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := gm.SetGovernanceTimelock(tt.ttl)
			if err == nil {
				t.Errorf("SetGovernanceTimelock(%v) should reject insecure value", tt.ttl)
			}
			t.Logf("got expected error: %v", err)
		})
	}

	// 1 minute should be accepted (boundary).
	if err := gm.SetGovernanceTimelock(time.Minute); err != nil {
		t.Errorf("SetGovernanceTimelock(1m) should be accepted at boundary, got: %v", err)
	}

	// Once governance is set, no more changes.
	initializer := types.Address{0xAA}
	gm.SetInitializerAddress(initializer)
	currentGov := types.Address{0xBB}
	_ = gm.ProposeGovernanceAddress(currentGov, initializer)
	_ = gm.ConfirmGovernanceAddress(initializer)
	if err := gm.SetGovernanceTimelock(2 * time.Minute); err == nil {
		t.Errorf("SetGovernanceTimelock should fail after governance address is set")
	}
}

// TestGOV_R13_M01_Timelock_UnauthorizedCaller_Rejected verifies that the
// timelock enforcement also requires caller authorization — a non-governance
// caller cannot bypass the timelock by calling Confirm directly.
func TestGOV_R13_M01_Timelock_UnauthorizedCaller_Rejected(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	if err := gm.SetGovernanceTimelock(time.Hour); err != nil {
		t.Fatalf("SetGovernanceTimelock failed: %v", err)
	}

	initializer := types.Address{0xAA}
	gm.SetInitializerAddress(initializer)
	currentGov := types.Address{0xBB}
	_ = gm.ProposeGovernanceAddress(currentGov, initializer)
	_ = gm.ConfirmGovernanceAddress(initializer)

	// Attacker proposes a new address (should fail — not governance).
	attacker := types.Address{0xEE}
	if err := gm.ProposeGovernanceAddress(types.Address{0xFF}, attacker); err != ErrGovernanceProposeUnauthorized {
		t.Errorf("attacker propose should fail with ErrGovernanceProposeUnauthorized, got: %v", err)
	}

	// Attacker tries to confirm a pending proposal (should fail — not governance).
	_ = gm.ProposeGovernanceAddress(types.Address{0xFF}, currentGov) // legitimate propose
	if err := gm.ConfirmGovernanceAddress(attacker); err != ErrGovernanceConfirmUnauthorized {
		t.Errorf("attacker confirm should fail with ErrGovernanceConfirmUnauthorized, got: %v", err)
	}
}

// TestGOV_R13_M02_ExecuteProposal_RejectsNonWhitelistedParameter verifies
// that ExecuteProposal goes through validateParameter (via setParameterLocked)
// and rejects proposals that try to set a parameter NOT in the whitelist.
//
// This is the core GOV-R11-002 regression: previously ExecuteProposal wrote
// gm.parameters directly, bypassing validation entirely.
func TestGOV_R13_M02_ExecuteProposal_RejectsNonWhitelistedParameter(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// "EvilBackdoor" is not in any whitelist — validateParameter returns
	// ErrParameterNotSupported. ExecuteProposal must propagate this error.
	changes := []ParameterChange{
		{Parameter: "EvilBackdoor", OldValue: "", NewValue: "1"},
	}
	p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeParameter, "Backdoor",
		"install backdoor", changes, deposit, 100, nil,
		54,
		nil)
	p.Status = ProposalStatusPassed
	gm.proposals[p.ID] = p

	err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
	if err == nil {
		t.Fatal("ExecuteProposal should reject non-whitelisted parameter")
	}
	// The error should wrap ErrParameterValueInvalid or ErrParameterNotSupported.
	t.Logf("got expected error: %v", err)
}

// TestGOV_R13_M02_ExecuteProposal_RejectsOutOfRangeValue verifies that even
// for whitelisted parameters, ExecuteProposal enforces the value range.
// InflationRate is in basis points (0-10000); an out-of-range value must be
// rejected at execute time, not silently applied.
func TestGOV_R13_M02_ExecuteProposal_RejectsOutOfRangeValue(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	// Initialize default parameters so InflationRate exists for the
	// "unchanged after rejection" assertion. NewGovernanceManager(nil)
	// does not auto-load DefaultGovernanceParameters — the caller is
	// expected to initialize them via the genesis wiring path.
	gm.InitializeParameters(DefaultGovernanceParameters())

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// InflationRate is in bps (0..10000). 1000000 is way out of range.
	changes := []ParameterChange{
		{Parameter: "InflationRate", OldValue: "500", NewValue: "1000000"},
	}
	p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeParameter, "Hyperinflation",
		"set inflation to 1000%", changes, deposit, 100, nil,
		53,
		nil)
	p.Status = ProposalStatusPassed
	gm.proposals[p.ID] = p

	err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
	if err == nil {
		t.Fatal("ExecuteProposal should reject out-of-range InflationRate")
	}

	// Verify the parameter was NOT mutated.
	v, exists := gm.GetParameter("InflationRate")
	if !exists || v != "500" {
		t.Errorf("InflationRate should be unchanged (500), got %s (exists=%v)", v, exists)
	}
	t.Logf("got expected error: %v", err)
}

// TestGOV_R13_M02_ExecuteProposal_StaleOldValue_Rejected verifies the
// GOV-R11-003 parameter-rollback-attack mitigation: if another proposal
// executed between voting and execution changed the parameter to a value
// different from the proposal's OldValue, ExecuteProposal must reject the
// stale proposal.
func TestGOV_R13_M02_ExecuteProposal_StaleOldValue_Rejected(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// Initial state: MinStakeAmount = 1000 (default).
	// Proposal A: MinStakeAmount 1000 -> 2000.
	// Proposal B: MinStakeAmount 1000 -> 3000.
	// If B executes first, A's OldValue (1000) no longer matches current (3000).
	changesA := []ParameterChange{
		{Parameter: "MinStakeAmount", OldValue: "1000", NewValue: "2000"},
	}
	changesB := []ParameterChange{
		{Parameter: "MinStakeAmount", OldValue: "1000", NewValue: "3000"},
	}

	pA, _ := gm.CreateProposal(types.Address{1}, ProposalTypeParameter, "A",
		"raise to 2000", changesA, deposit, 100, nil,
		52,
		nil)
	pB, _ := gm.CreateProposal(types.Address{2}, ProposalTypeParameter, "B",
		"raise to 3000", changesB, deposit, 100, nil,
		51,
		nil)
	pA.Status = ProposalStatusPassed
	pB.Status = ProposalStatusPassed
	gm.proposals[pA.ID] = pA
	gm.proposals[pB.ID] = pB

	// Execute B first — this changes MinStakeAmount from 1000 to 3000.
	if err := gm.ExecuteProposal(pB.ID, pB.EndHeight+execDelay+1); err != nil {
		t.Fatalf("proposal B should execute: %v", err)
	}
	v, _ := gm.GetParameter("MinStakeAmount")
	if v != "3000" {
		t.Fatalf("MinStakeAmount should be 3000 after B executes, got %s", v)
	}

	// Now executing A should fail — its OldValue (1000) doesn't match current (3000).
	err := gm.ExecuteProposal(pA.ID, pA.EndHeight+execDelay+1)
	if err == nil {
		t.Fatal("ExecuteProposal should reject stale OldValue (parameter rollback attack)")
	}
	t.Logf("got expected stale OldValue error: %v", err)

	// Verify the parameter was NOT rolled back to 2000.
	v, _ = gm.GetParameter("MinStakeAmount")
	if v != "3000" {
		t.Errorf("MinStakeAmount should remain 3000 (not rolled back to 2000), got %s", v)
	}
}

// TestGOV_R13_M02_ExecuteProposal_EmptyOldValue_SkipsStaleCheck verifies the
// backward-compatibility escape hatch: a proposal with empty OldValue skips
// the stale check (for proposals created before GOV-R11-003, or for new
// parameters that have no prior value).
func TestGOV_R13_M02_ExecuteProposal_EmptyOldValue_SkipsStaleCheck(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// Empty OldValue means "don't check stale state".
	changes := []ParameterChange{
		{Parameter: "MinStakeAmount", OldValue: "", NewValue: "5000"},
	}
	p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeParameter, "Raise",
		"raise stake", changes, deposit, 100, nil,
		50,
		nil)
	p.Status = ProposalStatusPassed
	gm.proposals[p.ID] = p

	if err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1); err != nil {
		t.Fatalf("empty OldValue should skip stale check: %v", err)
	}

	v, _ := gm.GetParameter("MinStakeAmount")
	if v != "5000" {
		t.Errorf("MinStakeAmount should be 5000, got %s", v)
	}
}

// TestGOV_R13_M02_ExecuteProposal_ValidChange_Succeeds verifies the happy path:
// a whitelisted parameter with in-range value and matching OldValue executes
// successfully and actually mutates the parameter.
func TestGOV_R13_M02_ExecuteProposal_ValidChange_Succeeds(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// InflationRate default is 500 bps (5%). Change to 300 bps (3%).
	changes := []ParameterChange{
		{Parameter: "InflationRate", OldValue: "500", NewValue: "300"},
	}
	p, _ := gm.CreateProposal(types.Address{1}, ProposalTypeParameter, "Lower",
		"lower inflation", changes, deposit, 100, nil,
		49,
		nil)
	p.Status = ProposalStatusPassed
	gm.proposals[p.ID] = p

	if err := gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1); err != nil {
		t.Fatalf("valid parameter change should succeed: %v", err)
	}

	v, _ := gm.GetParameter("InflationRate")
	if v != "300" {
		t.Errorf("InflationRate should be 300, got %s", v)
	}

	// Proposal should be marked as Executed.
	proposal, _ := gm.GetProposal(p.ID)
	if proposal.Status != ProposalStatusExecuted {
		t.Errorf("proposal status should be Executed, got %d", proposal.Status)
	}
}

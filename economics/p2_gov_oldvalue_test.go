// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestP2_GOV_OLDVALUE_NewParamCreatedDuringVotingRejected verifies the
// P2-GOV-OLDVALUE fix: when a proposal is created for a NEW parameter
// (one that does not exist yet, so OldValue is auto-populated to ""),
// and another proposal creates/modifies that parameter during the voting
// window, executing the first proposal must FAIL instead of silently
// overwriting the new value.
//
// Attack scenario (before fix):
//  1. Proposer A creates proposal P1 to set InflationRate = "50" (param
//     doesn't exist → OldValue auto-populated to "").
//  2. Proposer B creates proposal P2 to set InflationRate = "60" (param
//     still doesn't exist → OldValue auto-populated to "").
//  3. P2 executes first, setting InflationRate = "60".
//  4. P1 executes — OldValue == "" skips the rollback check, so P1 silently
//     overwrites "60" with "50". This is a parameter rollback attack.
//
// After fix: step 4 rejects P1 because OldValue == "" but the parameter now
// exists with a non-empty value "60".
func TestP2_GOV_OLDVALUE_NewParamCreatedDuringVotingRejected(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// Step 1: Proposer A creates P1 to set new param "InflationRate" = "50".
	// At creation time, "InflationRate" doesn't exist → OldValue stays "".
	p1, err := gm.CreateProposal(types.Address{1}, ProposalTypeParameter,
		"P1: set InflationRate=50", "desc",
		[]ParameterChange{{Parameter: "InflationRate", OldValue: "", NewValue: "50"}},
		deposit, 100, nil,
		63,
		nil)
	if err != nil {
		t.Fatalf("CreateProposal P1 failed: %v", err)
	}
	// Verify OldValue was NOT auto-populated (param didn't exist).
	if len(p1.Changes) != 1 || p1.Changes[0].OldValue != "" {
		t.Fatalf("P1 OldValue should be empty (new param), got %q", p1.Changes[0].OldValue)
	}

	// Step 2: Directly set the parameter to "60" (simulating another
	// proposal executing first and creating the parameter).
	gm.mu.Lock()
	gm.parameters["InflationRate"] = "60"
	gm.mu.Unlock()

	// Step 3: Try to execute P1 — should FAIL because OldValue == "" but
	// the parameter now exists with a non-empty value "60".
	p1.Status = ProposalStatusPassed
	gm.proposals[p1.ID] = p1

	err = gm.ExecuteProposal(p1.ID, p1.EndHeight+execDelay+1)
	if err == nil {
		t.Fatal("P2-GOV-OLDVALUE REGRESSION: ExecuteProposal should fail when new param was created during voting window")
	}
	if !strings.Contains(err.Error(), "created during voting window") {
		t.Errorf("expected 'created during voting window' error, got: %v", err)
	}

	// Verify the parameter was NOT overwritten.
	v, exists := gm.GetParameter("InflationRate")
	if !exists || v != "60" {
		t.Errorf("parameter was overwritten: got %q, want %q", v, "60")
	}
}

// TestP2_GOV_OLDVALUE_NewParamStillNotExists_Allowed verifies that when
// OldValue == "" and the parameter STILL doesn't exist at execution time
// (the legitimate new-parameter case), the proposal executes successfully.
func TestP2_GOV_OLDVALUE_NewParamStillNotExists_Allowed(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// Create proposal for a new parameter (VotingPeriod is in the whitelist).
	p, err := gm.CreateProposal(types.Address{1}, ProposalTypeParameter,
		"set VotingPeriod=100", "desc",
		[]ParameterChange{{Parameter: "VotingPeriod", OldValue: "", NewValue: "100"}},
		deposit, 100, nil,
		62,
		nil)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	// Don't create the parameter — it still doesn't exist at execution time.
	p.Status = ProposalStatusPassed
	gm.proposals[p.ID] = p

	err = gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
	if err != nil {
		t.Fatalf("ExecuteProposal should succeed for new param (still doesn't exist): %v", err)
	}

	// Verify the parameter was set.
	v, exists := gm.GetParameter("VotingPeriod")
	if !exists || v != "100" {
		t.Errorf("parameter not set correctly: got %q, want %q", v, "100")
	}
}

// TestP2_GOV_OLDVALUE_EmptyStringParamUnchanged_Allowed verifies that
// when OldValue == "" and the parameter exists with an empty string value
// (legitimate empty-valued parameter, e.g., legacy pre-validation param),
// the proposal executes successfully.
// This is the edge case: parameter exists but has value "".
func TestP2_GOV_OLDVALUE_EmptyStringParamUnchanged_Allowed(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// Pre-set a parameter with an empty string value (simulating a legacy
	// parameter that was set before validation was added).
	gm.mu.Lock()
	gm.parameters["InflationRate"] = ""
	gm.mu.Unlock()

	// Create proposal with OldValue = "" (matches the current empty value).
	// At creation time, OldValue == "" and parameter exists with value "",
	// so the auto-populate path sets OldValue = "" (no change).
	p, err := gm.CreateProposal(types.Address{1}, ProposalTypeParameter,
		"set InflationRate=50", "desc",
		[]ParameterChange{{Parameter: "InflationRate", OldValue: "", NewValue: "50"}},
		deposit, 100, nil,
		61,
		nil)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	// Parameter still has empty value at execution time.
	p.Status = ProposalStatusPassed
	gm.proposals[p.ID] = p

	err = gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
	if err != nil {
		t.Fatalf("ExecuteProposal should succeed for empty-valued param (OldValue matches): %v", err)
	}

	// Verify the parameter was updated.
	v, exists := gm.GetParameter("InflationRate")
	if !exists || v != "50" {
		t.Errorf("parameter not updated: got %q, want %q", v, "50")
	}
}

// TestP2_GOV_OLDVALUE_NonEmptyOldValueStillWorks verifies that the
// existing non-empty OldValue rollback protection still works after
// the P2-GOV-OLDVALUE fix (no regression).
func TestP2_GOV_OLDVALUE_NonEmptyOldValueStillWorks(t *testing.T) {
	gm := NewGovernanceManager(nil)
	defer gm.Close()

	deposit := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	execDelay := DefaultGovernanceConfig().ExecutionDelay

	// Pre-set a parameter.
	gm.mu.Lock()
	gm.parameters["InflationRate"] = "50"
	gm.mu.Unlock()

	// Create proposal with correct OldValue.
	p, err := gm.CreateProposal(types.Address{1}, ProposalTypeParameter,
		"change InflationRate", "desc",
		[]ParameterChange{{Parameter: "InflationRate", OldValue: "50", NewValue: "60"}},
		deposit, 100, nil,
		60,
		nil)
	if err != nil {
		t.Fatalf("CreateProposal failed: %v", err)
	}

	// Modify the parameter between creation and execution (simulating
	// another proposal executing first).
	gm.mu.Lock()
	gm.parameters["InflationRate"] = "70"
	gm.mu.Unlock()

	// Execute — should fail because OldValue != current value.
	p.Status = ProposalStatusPassed
	gm.proposals[p.ID] = p

	err = gm.ExecuteProposal(p.ID, p.EndHeight+execDelay+1)
	if err == nil {
		t.Fatal("ExecuteProposal should fail when OldValue doesn't match current value")
	}
	if !strings.Contains(err.Error(), "stale OldValue") {
		t.Errorf("expected 'stale OldValue' error, got: %v", err)
	}
}

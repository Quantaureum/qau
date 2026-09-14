// Quantaureum Node source, version 1.0.0.
package economics

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R38-P1-13 (2026-08-01): fail-closed guards for DeFiIncentiveManager.
//
// These tests assert the security regression:
//   - CreateProgram with an EMPTY authorizedCreators set must REJECT (was: accept anyone).
//   - ClaimReward with a NIL actionVerifier must REJECT (was: accept any claimant — Sybil).
//   - The AllowAllCreators() / AllowAllClaims() opt-ins revert to the prior permissive posture and are intended only for tests / one-shot allocation.
//   - The fail-closed posture is the DEFAULT in the production constructor NewDeFiIncentiveManager — no caller can accidentally get a fail-open instance.

// ------------------------------------------------------------------
// CreateProgram fail-closed
// ------------------------------------------------------------------

func TestR38P1_13_CreateProgram_RejectsWhenNoAuthorizedCreatorsConfigured(t *testing.T) {
	// Production default: empty authorizedCreators => fail-closed.
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	// Sanity check the defaults are fail-closed — no opt-in called.
	if dim == nil {
		t.Fatal("NewDeFiIncentiveManager returned nil")
	}

	program := &IncentiveProgram{
		ID:              "r13-unauth",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
	}
	err := dim.CreateProgram(program)
	if err != ErrUnauthorizedCreator {
		t.Fatalf("expected ErrUnauthorizedCreator when no creators are configured, got %v", err)
	}

	// Verify the program was NOT created — fail-closed must not mutate state.
	if _, exists := dim.GetProgram("r13-unauth"); exists {
		t.Fatal("fail-closed guard created a program; state should be untouched on rejection")
	}
	// Budget untouched: ensuring no silent budget drain via side channel.
	if got := dim.GetRemainingBudget(); got.Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Fatalf("fail-closed guard leaked budget: got %s, want 1000000000", got)
	}
}

func TestR38P1_13_CreateProgram_RejectsCreatorNotInAuthorizedSet(t *testing.T) {
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	// Authorize only one specific address.
	allowedAddr := types.Address{0xAB}
	dim.SetAuthorizedCreator(allowedAddr)

	// A different creator must be rejected — verifies the caller check runs
	// even when the allow-list is non-empty (the original fail-open bug only
	// tripped when the list was empty; the populated-list path was already
	// correct, but we exercise it to lock the behavior).
	otherAddr := types.Address{0xCD}
	program := &IncentiveProgram{
		ID:              "r13-other",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
		Creator:         otherAddr,
	}
	err := dim.CreateProgram(program)
	if err == nil {
		t.Fatal("expected error when creator is not in the authorized set")
	}
	if !errorsIs(err, ErrCreatorNotInList) {
		t.Fatalf("expected ErrCreatorNotInList wrapping, got %v", err)
	}
	// And the state must still be intact.
	if _, exists := dim.GetProgram("r13-other"); exists {
		t.Fatal("program from a non-authorized creator was stored")
	}
}

func TestR38P1_13_CreateProgram_AcceptsWhenCreatorInAuthorized(t *testing.T) {
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	allowedAddr := types.Address{0xAB}
	dim.SetAuthorizedCreator(allowedAddr)

	program := &IncentiveProgram{
		ID:              "r13-allowed",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
		Creator:         allowedAddr,
	}
	if err := dim.CreateProgram(program); err != nil {
		t.Fatalf("expected CreateProgram to succeed for authorized creator, got %v", err)
	}
	retrieved, exists := dim.GetProgram("r13-allowed")
	if !exists {
		t.Fatal("authorized program not stored")
	}
	if !retrieved.Active {
		t.Fatal("authorized program should be active after CreateProgram")
	}
}

func TestR38P1_13_CreateProgram_AcceptsWhenAllowAllCreatorsOptIn(t *testing.T) {
	// The AllowAllCreators() opt-in reverts to the old permissive posture.
	// This is the recovery path for tests / one-shot genesis allocation that
	// legitimately run before the authorized set is wired up.
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	dim.AllowAllCreators()

	program := &IncentiveProgram{
		ID:              "r13-optin",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
		Creator:         types.Address{0x99}, // arbitrary, not in any allow-list
	}
	if err := dim.CreateProgram(program); err != nil {
		t.Fatalf("expected CreateProgram to succeed under AllowAllCreators, got %v", err)
	}
}

// ------------------------------------------------------------------
// ClaimReward fail-closed
// ------------------------------------------------------------------

func TestR38P1_13_ClaimReward_RejectsWhenNoActionVerifierConfigured(t *testing.T) {
	// Production default: nil actionVerifier => fail-closed.
	// We must first create a program so that we get past the program lookup
	// checks (ClaimReward returns ErrProgramNotFound before the verifier
	// check; we want to assert the verifier-specific rejection).
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	allowedAddr := types.Address{0xAB}
	dim.SetAuthorizedCreator(allowedAddr)

	program := &IncentiveProgram{
		ID:              "r13-claim-noverifier",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
		Creator:         allowedAddr,
	}
	if err := dim.CreateProgram(program); err != nil {
		t.Fatalf("setup CreateProgram failed: %v", err)
	}

	// Claiming with NO verifier configured must be rejected.
	claimant := types.Address{0x01}
	claim, err := dim.ClaimReward("r13-claim-noverifier", claimant, 500)
	if err != ErrNoActionVerifier {
		t.Fatalf("expected ErrNoActionVerifier, got %v (claim=%v)", err, claim)
	}

	// No claim record must have been created — fail-closed must not leak
	// reward bookkeeping.
	claims := dim.GetClaimsByUser(claimant)
	if len(claims) != 0 {
		t.Fatalf("fail-closed guard still recorded a claim: %d entries", len(claims))
	}
	if got := dim.GetTotalDistributed(); got.Sign() != 0 {
		t.Fatalf("fail-closed guard leaked totalDistributed: got %s, want 0", got)
	}
	// The program's RemainingBudget must also be untouched.
	retrieved, _ := dim.GetProgram("r13-claim-noverifier")
	if retrieved.RemainingBudget.Cmp(program.TotalBudget) != 0 {
		t.Fatalf("fail-closed guard leaked RemainingBudget: got %s, want %s", retrieved.RemainingBudget, program.TotalBudget)
	}
}

func TestR38P1_13_ClaimReward_RejectsWhenVerifierReturnsFalse(t *testing.T) {
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	allowedAddr := types.Address{0xAB}
	dim.SetAuthorizedCreator(allowedAddr)

	program := &IncentiveProgram{
		ID:              "r13-claim-failverifier",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
		Creator:         allowedAddr,
	}
	if err := dim.CreateProgram(program); err != nil {
		t.Fatalf("setup CreateProgram failed: %v", err)
	}

	// Verifier rejects everyone.
	calls := 0
	dim.SetActionVerifier(func(programID string, claimant types.Address, blockHeight uint64) bool {
		calls++
		if programID != "r13-claim-failverifier" {
			t.Errorf("verifier got programID=%q, want %q", programID, "r13-claim-failverifier")
		}
		_ = claimant
		_ = blockHeight
		return false
	})

	claimant := types.Address{0x02}
	claim, err := dim.ClaimReward("r13-claim-failverifier", claimant, 500)
	if err != ErrActionNotVerified {
		t.Fatalf("expected ErrActionNotVerified, got %v (claim=%v)", err, claim)
	}
	if calls == 0 {
		t.Fatal("verifier was not invoked — the fail-closed check must still call the verifier when it is configured")
	}
	if got := dim.GetTotalDistributed(); got.Sign() != 0 {
		t.Fatalf("rejected claim should not distribute anything, got %s", got)
	}
}

func TestR38P1_13_ClaimReward_AcceptsWhenVerifierPass(t *testing.T) {
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	allowedAddr := types.Address{0xAB}
	dim.SetAuthorizedCreator(allowedAddr)

	program := &IncentiveProgram{
		ID:              "r13-claim-passverifier",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
		Creator:         allowedAddr,
	}
	if err := dim.CreateProgram(program); err != nil {
		t.Fatalf("setup CreateProgram failed: %v", err)
	}

	// Verifier accepts everyone.
	dim.SetActionVerifier(func(programID string, claimant types.Address, blockHeight uint64) bool {
		_ = programID
		_ = claimant
		_ = blockHeight
		return true
	})

	claimant := types.Address{0x03}
	claim, err := dim.ClaimReward("r13-claim-passverifier", claimant, 500)
	if err != nil {
		t.Fatalf("expected ClaimReward to succeed when verifier passes, got %v", err)
	}
	if claim == nil {
		t.Fatal("claim must not be nil on success")
	}
	if claim.Amount.Cmp(program.RewardPerAction) != 0 {
		t.Fatalf("claim amount %s != reward %s", claim.Amount, program.RewardPerAction)
	}
	if got := dim.GetTotalDistributed(); got.Cmp(program.RewardPerAction) != 0 {
		t.Fatalf("totalDistributed %s != reward %s", got, program.RewardPerAction)
	}
}

func TestR38P1_13_ClaimReward_AcceptsWhenAllowAllClaimsOptIn(t *testing.T) {
	// The AllowAllClaims() opt-in skips the verifier check entirely.
	// Note this is independent of AllowAllCreators(): we still need to
	// create the program somehow, so we use the authorized creator path.
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	allowedAddr := types.Address{0xAB}
	dim.SetAuthorizedCreator(allowedAddr)
	dim.AllowAllClaims()

	program := &IncentiveProgram{
		ID:              "r13-claim-optin",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
		Creator:         allowedAddr,
	}
	if err := dim.CreateProgram(program); err != nil {
		t.Fatalf("setup CreateProgram failed: %v", err)
	}

	// No verifier configured at all — AllowAllClaims() must let it through.
	claimant := types.Address{0x04}
	if _, err := dim.ClaimReward("r13-claim-optin", claimant, 500); err != nil {
		t.Fatalf("expected ClaimReward to succeed under AllowAllClaims (no verifier configured), got %v", err)
	}
}

// ------------------------------------------------------------------
// Behavioral invariants: opt-ins are independent and do not affect unrelated
// accounting paths. These guard against accidental future coupling.
// ------------------------------------------------------------------

func TestR38P1_13_AllowAllCreators_DoesNotBypassVerifierAndViceVersa(t *testing.T) {
	// AllowAllCreators() must NOT bypass ClaimReward's verifier check.
	dim := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	dim.AllowAllCreators() // but NOT AllowAllClaims

	if err := dim.CreateProgram(&IncentiveProgram{
		ID:              "r13-cross",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
	}); err != nil {
		t.Fatalf("AllowAllCreators should permit CreateProgram, got %v", err)
	}

	if _, err := dim.ClaimReward("r13-cross", types.Address{0x05}, 500); err != ErrNoActionVerifier {
		t.Fatalf("AllowAllCreators must NOT bypass verifier check on ClaimReward: want ErrNoActionVerifier, got %v", err)
	}

	// Conversely, AllowAllClaims must NOT bypass CreateProgram's authorization.
	dim2 := NewDeFiIncentiveManager(big.NewInt(1_000_000_000))
	dim2.AllowAllClaims() // but NOT AllowAllCreators

	if err := dim2.CreateProgram(&IncentiveProgram{
		ID:              "r13-cross2",
		TotalBudget:     big.NewInt(1_000),
		RewardPerAction: big.NewInt(10),
		StartBlock:      0,
		EndBlock:        1_000_000,
	}); err != ErrUnauthorizedCreator {
		t.Fatalf("AllowAllClaims must NOT bypass creator check on CreateProgram: want ErrUnauthorizedCreator, got %v", err)
	}
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

// errorsIs is a tiny local wrapper around errors.Is so we do not import the
// standard library errors package just for one assertion (we already use it
// for nothing else in this file — importing it would be wasted complexity).
func errorsIs(err, target error) bool {
	for cur := err; cur != nil; {
		if cur == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		if u, ok := cur.(unwrapper); ok {
			cur = u.Unwrap()
			continue
		}
		return false
	}
	return false
}

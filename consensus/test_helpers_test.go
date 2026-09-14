// Quantaureum Node source, version 1.0.0.
// Package consensus contains shared test helpers used across multiple test
// files in this package. This file is only compiled during testing and does
// NOT ship in the production binary.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// activateValidatorForTest marks the given validator as Active=true directly
// in the ValidatorManager's internal map, bypassing the normal SetActive
// authorization path.
//
// R30-IMPLEMENT (2026-07-27): Used by slash_h1_test.go to put a validator
// into a fully active state before exercising RemoveValidator/WithdrawStake
// flows. AddValidator already sets Active=true for validators with
// sufficient stake, but this helper provides a robust, future-proof
// activation path that will keep working even if AddValidator is later
// changed to set Active=false for non-genesis validators (e.g., the
// VAL-H04/VAL-H05 fix that forces first-time activation through
// ActivateFromQueue / ProcessEpochAdvanced). Test-only code is allowed to
// bypass the authorization checks because it directly manipulates internal
// state under the test's control.
//
// Caller must have already added the validator via AddValidator or
// AddGenesisValidator; this helper only flips the Active flag.
//
// VAL-H04/VAL-H05 FIX (R31, 2026-07-27): Also set EverActivated=true so
// subsequent SetActive calls (e.g. deactivate/reactivate for unjail testing)
// are accepted. Without EverActivated=true, SetActive rejects first-time
// activations, breaking tests that exercise the reactivation path.
func activateValidatorForTest(t *testing.T, vm *ValidatorManager, addr types.Address) {
	t.Helper()
	vm.mu.Lock()
	defer vm.mu.Unlock()
	v, exists := vm.validators[addr]
	if !exists {
		t.Fatalf("activateValidatorForTest: validator %x not found in vm.validators (call AddValidator first)", addr)
	}
	v.Active = true
	v.EverActivated = true
}

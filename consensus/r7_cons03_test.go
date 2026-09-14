// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// CONS-R7-03 (High) — ValidatorManager.SetActive previously used
// wall-clock time to check jail expiry, but GetActiveValidators used
// the consensus clock. The two disagreed.
//
// Audit source (AUDIT-R7-CONSENSUS-2026-07-17.md, CONS-R7-03):
//   "ValidatorManager.SetActive uses wall clock for jail-expiry check,
//    inconsistent with GetActiveValidators' consensus time"
//   Location: consensus/validator_manager.go:583-625 (SetActive at line 604)
//             consensus/validator_manager.go:685-712 (GetActiveValidators at line 694)
//   "SetActive should use vm.currentBlockTime (when set) instead of time.Now()"
//
// Fix:
//   SetActive now uses vm.currentBlockTime (matching GetActiveValidators),
//   falling back to time.Now() only when currentBlockTime==0 (test mode).
//
// This test covers:
//   1. Consensus time within the jail period → SetActive refuses to activate.
//   2. Consensus time past the jail period   → SetActive allows activation.
//   3. SetActive and GetActiveValidators agree on the time source.
//   4. currentBlockTime==0 falls back to wall clock.

// consR703SysCaller is a registered system caller used by these tests.
// It must be registered via RegisterSystemCaller before use.
var consR703SysCaller = types.Address{0x7e, 0x03}

// consR703setupVM creates a ValidatorManager with one validator that is
// jailed until a fixed timestamp. The system caller is registered so that
// SetJailedUntil can be invoked.
func consR703setupVM(t *testing.T, jailedUntil int64) (*ValidatorManager, types.Address, types.Address) {
	t.Helper()
	RegisterSystemCaller(consR703SysCaller)
	vm := NewValidatorManager()

	// Generate a Dilithium3 key pair for the validator
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("crypto.GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()

	// Use addr as both caller and validator (self-registration)
	stake := big.NewInt(0).Mul(big.NewInt(32), big.NewInt(1e18))
	if err := vm.AddValidator(addr, addr, kp.Public, stake, 100, 1); err != nil {
		t.Fatalf("AddValidator: %v", err)
	}
	// VAL-H04/VAL-H05 FIX (R31, 2026-07-27): First-time activation MUST go
	// through ActivateFromQueue so EverActivated=true. The tests in this file
	// exercise the unjail re-activation path via SetActive, which requires
	// EverActivated=true (SetActive rejects first-time activations).
	if err := vm.ActivateFromQueue(addr); err != nil {
		t.Fatalf("ActivateFromQueue: %v", err)
	}

	// Jail the validator using the registered system caller
	if jailedUntil > 0 {
		if err := vm.SetJailedUntil(consR703SysCaller, addr, jailedUntil); err != nil {
			t.Fatalf("SetJailedUntil: %v", err)
		}
	}

	// Deactivate first (jailed validators should be inactive)
	vm.validators[addr].Active = false

	return vm, addr, addr
}

// TestCONS_R7_03_SetActiveUsesConsensusTime_Jailed verifies that SetActive
// rejects activation when consensus block time is within the jail period.
func TestCONS_R7_03_SetActiveUsesConsensusTime_Jailed(t *testing.T) {
	jailedUntil := int64(10000)
	vm, caller, addr := consR703setupVM(t, jailedUntil)

	// Set consensus time BEFORE jail expiry
	vm.SetCurrentBlockTime(5000)

	// SetActive must reject (consensus time 5000 < jailedUntil 10000)
	err := vm.SetActive(caller, addr, true)
	if err == nil {
		t.Fatal("CONS-R7-03: SetActive must reject when consensus time < jailedUntil")
	}

	t.Logf("CONS-R7-03 OK: SetActive rejected during jail (consensus time=5000 < jailedUntil=10000)")
}

// TestCONS_R7_03_SetActiveUsesConsensusTime_Expired verifies that SetActive
// allows activation when consensus block time is past the jail period.
func TestCONS_R7_03_SetActiveUsesConsensusTime_Expired(t *testing.T) {
	jailedUntil := int64(10000)
	vm, caller, addr := consR703setupVM(t, jailedUntil)

	// Set consensus time AFTER jail expiry
	vm.SetCurrentBlockTime(15000)

	// SetActive must succeed (consensus time 15000 >= jailedUntil 10000)
	err := vm.SetActive(caller, addr, true)
	if err != nil {
		t.Fatalf("CONS-R7-03: SetActive should succeed after jail expiry: %v", err)
	}

	// Verify JailedUntil was cleared
	v, _ := vm.GetValidator(addr)
	if v.JailedUntil != 0 {
		t.Errorf("CONS-R7-03: JailedUntil should be cleared after unjail, got %d", v.JailedUntil)
	}

	t.Logf("CONS-R7-03 OK: SetActive succeeded after jail expiry (consensus time=15000 >= jailedUntil=10000)")
}

// TestCONS_R7_03_ConsistencyWithGetActiveValidators verifies that SetActive
// and GetActiveValidators agree on jail status when using the same consensus
// time. This is the core consistency property broken by the wall-clock bug.
func TestCONS_R7_03_ConsistencyWithGetActiveValidators(t *testing.T) {
	jailedUntil := int64(10000)
	vm, caller, addr := consR703setupVM(t, jailedUntil)

	// Set consensus time during jail period
	vm.SetCurrentBlockTime(5000)

	// SetActive should reject (validator is jailed per consensus time)
	err := vm.SetActive(caller, addr, true)
	if err == nil {
		t.Fatal("CONS-R7-03: SetActive should reject jailed validator")
	}

	// Even if we force Active=true, GetActiveValidators should exclude it
	// (because isJailed check uses the same consensus time)
	vm.validators[addr].Active = true
	activeList := vm.GetActiveValidators()
	for _, v := range activeList {
		if v.Address == addr {
			t.Fatal("CONS-R7-03: GetActiveValidators must NOT include jailed validator (consensus time=5000 < jailedUntil=10000)")
		}
	}

	// Now set consensus time past jail
	vm.SetCurrentBlockTime(15000)

	// SetActive should now succeed
	err = vm.SetActive(caller, addr, true)
	if err != nil {
		t.Fatalf("CONS-R7-03: SetActive should succeed after jail: %v", err)
	}

	// GetActiveValidators should now include it
	activeList = vm.GetActiveValidators()
	found := false
	for _, v := range activeList {
		if v.Address == addr {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("CONS-R7-03: GetActiveValidators must include unjailed validator after consensus time passed jail expiry")
	}

	t.Logf("CONS-R7-03 OK: SetActive and GetActiveValidators agree on jail status at both time points")
}

// TestCONS_R7_03_FallbackToWallClock verifies that when currentBlockTime is
// not set (==0), SetActive falls back to wall-clock time. This preserves
// backward compatibility for tests that don't set consensus time.
func TestCONS_R7_03_FallbackToWallClock(t *testing.T) {
	// Jail until 1 second from now
	jailedUntil := time.Now().Unix() + 1
	vm, caller, addr := consR703setupVM(t, jailedUntil)

	// Don't set currentBlockTime (stays 0) → fallback to wall-clock
	err := vm.SetActive(caller, addr, true)
	if err == nil {
		// Edge case: time may have advanced past jailedUntil during test setup.
		// This is acceptable — the point is that no panic occurs and the
		// fallback path works.
		t.Logf("CONS-R7-03 OK: fallback to wall-clock allowed activation (time advanced past jail)")
	} else {
		t.Logf("CONS-R7-03 OK: fallback to wall-clock rejected activation (still jailed)")
	}

	// Now wait for jail to expire and verify activation works
	time.Sleep(2 * time.Second)
	err = vm.SetActive(caller, addr, true)
	if err != nil {
		t.Fatalf("CONS-R7-03: SetActive should succeed after jail expires (wall-clock fallback): %v", err)
	}

	t.Logf("CONS-R7-03 OK: fallback to wall-clock works after jail expiry")
}

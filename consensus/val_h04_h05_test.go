// Quantaureum Node source, version 1.0.0.
// Package consensus contains regression tests for the R29 audit's VAL-H04
// and VAL-H05 findings.
//
// VAL-H04 (qpos_advanced.go): ValidatorQueue system caller could bypass
// the 4-epoch activation queue and directly activate validators via
// SetActive. The fix adds an EverActivated flag to ValidatorInfo;
// first-time activation (EverActivated=false) is REJECTED by SetActive
// regardless of caller (self OR system caller). The only legitimate
// first-time activation path is ActivateFromQueue, called exclusively by
// ProcessEpochAdvanced AFTER validatorQueue.ProcessEpoch has verified
// the 4-epoch activation delay has elapsed.
//
// VAL-H05 (node.go staking path): After AddValidator, node.go called
// SetActive(addr, addr, true) to immediately activate the validator,
// bypassing the ValidatorQueue's 4-epoch activation delay. The fix
// removes that SetActive call; non-genesis validators must now wait for
// ProcessEpochAdvanced to activate them after the queue delay.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestVAL_H04_FirstTimeSelfActivationRejected verifies that a non-genesis
// validator (EverActivated=false) CANNOT activate itself via
// SetActive(addr, addr, true). This is the core VAL-H04/VAL-H05 fix:
// first-time activation must go through ActivateFromQueue (called by
// ProcessEpochAdvanced after the 4-epoch queue delay).
func TestVAL_H04_FirstTimeSelfActivationRejected(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := validStake()
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// VAL-H04/VAL-H05 FIX: Self-activation (caller == addr) must be
	// rejected for first-time activation (EverActivated=false).
	err := vm.SetActive(addr, addr, true)
	if err == nil {
		t.Fatal("VAL-H04 REGRESSION: self-activation should be rejected for " +
			"first-time activation (EverActivated=false), but SetActive succeeded")
	}

	// Verify the validator is still inactive.
	info, err := vm.GetValidator(addr)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}
	if info.Active {
		t.Error("VAL-H04 REGRESSION: validator should be Active=false after " +
			"rejected self-activation, but is Active=true")
	}
	if info.EverActivated {
		t.Error("VAL-H04 REGRESSION: EverActivated should be false after " +
			"rejected self-activation")
	}
}

// TestVAL_H04_SystemCallerSetActiveRejected verifies that a registered
// system caller CANNOT perform first-time activation via SetActive.
//
// VAL-H04 FIX (R29, 2026-07-25): Previously, system callers could bypass
// the 4-epoch queue by calling SetActive(systemCaller, addr, true). Now
// SetActive rejects ALL first-time activations (EverActivated=false)
// regardless of caller. The only first-time activation path is
// ActivateFromQueue, called by ProcessEpochAdvanced.
func TestVAL_H04_SystemCallerSetActiveRejected(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := validStake()
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// Register a system caller (mimics DeriveSystemCaller).
	systemCaller := types.Address{0x42}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)

	// VAL-H04 FIX: System caller CANNOT activate via SetActive for
	// first-time activation. This closes the system-caller bypass.
	err := vm.SetActive(systemCaller, addr, true)
	if err == nil {
		t.Fatal("VAL-H04 REGRESSION: system caller should NOT be able to " +
			"perform first-time activation via SetActive — must use ActivateFromQueue")
	}

	// Verify the validator is still inactive.
	info, err := vm.GetValidator(addr)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}
	if info.Active {
		t.Error("VAL-H04: validator should be Active=false after rejected " +
			"system-caller SetActive")
	}
	if info.EverActivated {
		t.Error("VAL-H04: EverActivated should be false after rejected " +
			"system-caller SetActive")
	}
}

// TestVAL_H04_ActivateFromQueueWorks verifies that ActivateFromQueue
// successfully performs first-time activation. This is the legitimate
// path used by ProcessEpochAdvanced after the 4-epoch queue delay.
func TestVAL_H04_ActivateFromQueueWorks(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := validStake()
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// ActivateFromQueue is the sole legitimate first-time activation path.
	if err := vm.ActivateFromQueue(addr); err != nil {
		t.Fatalf("VAL-H04: ActivateFromQueue should succeed for first-time "+
			"activation: %v", err)
	}

	// Verify the validator is now active and EverActivated=true.
	info, err := vm.GetValidator(addr)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}
	if !info.Active {
		t.Error("VAL-H04: validator should be Active=true after ActivateFromQueue")
	}
	if !info.EverActivated {
		t.Error("VAL-H04: EverActivated should be true after ActivateFromQueue")
	}
}

// TestVAL_H04_ActivateFromQueueIdempotent verifies that calling
// ActivateFromQueue on an already-active validator is a no-op.
// ProcessEpochAdvanced may re-process the same activation across epoch
// boundaries if a previous attempt failed (e.g. transient jail).
func TestVAL_H04_ActivateFromQueueIdempotent(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := validStake()
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// First activation.
	if err := vm.ActivateFromQueue(addr); err != nil {
		t.Fatalf("first ActivateFromQueue failed: %v", err)
	}

	// Second activation should be a no-op (not an error).
	if err := vm.ActivateFromQueue(addr); err != nil {
		t.Fatalf("second ActivateFromQueue should be idempotent: %v", err)
	}

	info, err := vm.GetValidator(addr)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}
	if !info.Active || !info.EverActivated {
		t.Error("VAL-H04: validator should remain Active=true EverActivated=true " +
			"after idempotent re-activation")
	}
}

// TestVAL_H04_SelfReactivationAfterFirstActivation verifies that AFTER a
// validator has been activated via ActivateFromQueue (EverActivated=true),
// self-activation (caller == addr) works for re-activation (e.g. unjail).
// This ensures the unjail path is not broken by the VAL-H04 fix.
func TestVAL_H04_SelfReactivationAfterFirstActivation(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := validStake()
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// First-time activation via ActivateFromQueue (the only legitimate path).
	if err := vm.ActivateFromQueue(addr); err != nil {
		t.Fatalf("first-time activation via ActivateFromQueue failed: %v", err)
	}

	// Deactivate (e.g. slash) via system caller.
	systemCaller := types.Address{0x42}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)
	if err := vm.SetActive(systemCaller, addr, false); err != nil {
		t.Fatalf("deactivation failed: %v", err)
	}

	// Self re-activation should now work (EverActivated=true, unjail path).
	if err := vm.SetActive(addr, addr, true); err != nil {
		t.Fatalf("VAL-H04 REGRESSION: self re-activation after first activation "+
			"should succeed (unjail path), but failed: %v", err)
	}

	info, err := vm.GetValidator(addr)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}
	if !info.Active {
		t.Error("VAL-H04: validator should be Active=true after self re-activation")
	}
}

// TestVAL_H04_GenesisValidatorImmediatelyActive verifies that genesis
// validators are immediately Active=true and EverActivated=true. Genesis
// validators bootstrap the chain and don't need to go through the
// ValidatorQueue activation delay.
func TestVAL_H04_GenesisValidatorImmediatelyActive(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := validStake()
	if err := vm.AddGenesisValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddGenesisValidator failed: %v", err)
	}

	info, err := vm.GetValidator(addr)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}
	if !info.Active {
		t.Error("VAL-H04: genesis validator should be Active=true immediately")
	}
	if !info.EverActivated {
		t.Error("VAL-H04: genesis validator should have EverActivated=true immediately")
	}
}

// TestVAL_H04_NonGenesisValidatorStartsInactive verifies that non-genesis
// validators start Active=false and EverActivated=false. They MUST wait
// for ProcessEpochAdvanced to activate them after the 4-epoch queue delay.
func TestVAL_H04_NonGenesisValidatorStartsInactive(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := validStake()
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	info, err := vm.GetValidator(addr)
	if err != nil {
		t.Fatalf("GetValidator failed: %v", err)
	}
	if info.Active {
		t.Error("VAL-H04: non-genesis validator should start Active=false " +
			"(must wait for 4-epoch queue delay)")
	}
	if info.EverActivated {
		t.Error("VAL-H04: non-genesis validator should start EverActivated=false")
	}
}

// TestVAL_H05_NoBypassViaDirectSetActive verifies that even if an attacker
// calls SetActive(addr, addr, true) directly after AddValidator (as
// node.go used to do), the activation is rejected. This is the VAL-H05
// regression test.
func TestVAL_H05_NoBypassViaDirectSetActive(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := validStake()
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// VAL-H05: Direct self-activation must fail (this is what node.go
	// used to do, bypassing the 4-epoch queue).
	err := vm.SetActive(addr, addr, true)
	if err == nil {
		t.Fatal("VAL-H05 REGRESSION: direct SetActive(addr, addr, true) after " +
			"AddValidator should be rejected, but succeeded — 4-epoch queue " +
			"activation delay bypassed!")
	}

	// The validator must remain inactive.
	if vm.ActiveValidatorCount() != 0 {
		t.Errorf("VAL-H05: expected 0 active validators after rejected bypass, got %d",
			vm.ActiveValidatorCount())
	}
}

// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"os"
	"testing"
)

// ── DA: CanPropose hard-rejects DA-unavailable slots (production mode) ──
//
// Audit source (AUDIT-FULL-ROUND6-2026-07-17.md, DA):
//   CanPropose only emitted a non-blocking warning on parent-slot DA failure,
//   still allowing continued production while DA was unavailable. Although
//   FinalizeBlock enforces a hard check, the DA-failed block has already
//   entered the chain and cannot be undone.
//
// Fix: in production (QAU_PRODUCTION=1) CanPropose hard-rejects parents
// whose slot has no DA. Non-production keeps a soft warning so local dev
// flows keep working.

// setProductionMode sets QAU_PRODUCTION=1 and returns a cleanup function
// that restores the original value.
func setProductionMode(t *testing.T) func() {
	t.Helper()
	orig := os.Getenv("QAU_PRODUCTION")
	os.Setenv("QAU_PRODUCTION", "1")
	return func() {
		if orig == "" {
			os.Unsetenv("QAU_PRODUCTION")
		} else {
			os.Setenv("QAU_PRODUCTION", orig)
		}
	}
}

// setDevMode ensures QAU_PRODUCTION is unset (dev mode) and returns a
// cleanup function.
func setDevMode(t *testing.T) func() {
	t.Helper()
	orig := os.Getenv("QAU_PRODUCTION")
	os.Unsetenv("QAU_PRODUCTION")
	return func() {
		if orig != "" {
			os.Setenv("QAU_PRODUCTION", orig)
		}
	}
}

// TestDA_R6_01_ProductionMode_HardReject verifies that in production mode
// (QAU_PRODUCTION=1), CanPropose HARD REJECTS when the DA availability
// check fails for the parent slot.
func TestDA_R6_01_ProductionMode_HardReject(t *testing.T) {
	cleanup := setProductionMode(t)
	defer cleanup()

	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Set a DA checker that always fails.
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return errors.New("DA sampling failed: blob data not available")
	})

	// CanPropose should return FALSE in production mode (hard reject).
	// slot=1 → checks parent slot 0.
	result := qpos.CanPropose(0, 1)
	if result {
		t.Fatal("CanPropose should return FALSE in production mode when DA check fails (hard reject)")
	}
}

// TestDA_R6_01_ProductionMode_DAAvailable verifies that in production mode,
// CanPropose returns true when the DA availability check passes.
func TestDA_R6_01_ProductionMode_DAAvailable(t *testing.T) {
	cleanup := setProductionMode(t)
	defer cleanup()

	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Set a DA checker that always succeeds.
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return nil // DA available
	})

	// CanPropose should return TRUE — DA is available.
	result := qpos.CanPropose(0, 1)
	if !result {
		t.Fatal("CanPropose should return TRUE in production mode when DA is available")
	}
}

// TestDA_R6_01_ProductionMode_NoChecker verifies that in production mode,
// CanPropose returns true when no DA checker is configured (opt-in).
func TestDA_R6_01_ProductionMode_NoChecker(t *testing.T) {
	cleanup := setProductionMode(t)
	defer cleanup()

	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// No DA checker configured — CanPropose should work normally.
	result := qpos.CanPropose(0, 1)
	if !result {
		t.Fatal("CanPropose should return TRUE when no DA checker is configured (opt-in)")
	}
}

// TestDA_R6_01_DevMode_SoftCheck verifies that in dev mode (no QAU_PRODUCTION),
// CanPropose still returns true when DA check fails (soft check, liveness
// priority). This preserves backward compatibility with P1-4 behavior.
func TestDA_R6_01_DevMode_SoftCheck(t *testing.T) {
	cleanup := setDevMode(t)
	defer cleanup()

	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Set a DA checker that always fails.
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return errors.New("DA unavailable")
	})

	// CanPropose should return TRUE in dev mode (soft check, non-blocking).
	result := qpos.CanPropose(0, 1)
	if !result {
		t.Fatal("CanPropose should return TRUE in dev mode when DA check fails (soft check, liveness priority)")
	}
}

// TestDA_R6_01_DevMode_DAAvailable verifies that in dev mode, CanPropose
// returns true when DA is available (baseline).
func TestDA_R6_01_DevMode_DAAvailable(t *testing.T) {
	cleanup := setDevMode(t)
	defer cleanup()

	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return nil
	})

	result := qpos.CanPropose(0, 1)
	if !result {
		t.Fatal("CanPropose should return TRUE in dev mode when DA is available")
	}
}

// TestDA_R6_01_SlotZeroSkipsCheck verifies that when slot=0 (no parent),
// the DA check is skipped — there is no parent slot to check.
func TestDA_R6_01_SlotZeroSkipsCheck(t *testing.T) {
	cleanup := setProductionMode(t)
	defer cleanup()

	vs := createTestValidatorSet(t, 4)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	checkCalled := false
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		checkCalled = true
		return errors.New("DA unavailable")
	})

	// slot=0 → no parent slot to check, should skip DA check.
	result := qpos.CanPropose(0, 0)
	if !result {
		t.Fatal("CanPropose should return TRUE for slot=0 (no parent to check)")
	}
	if checkCalled {
		t.Fatal("DA checker should NOT be called for slot=0 (no parent)")
	}
}

// TestDA_R6_01_ProductionMode_HardReject_WithChambers verifies that the
// production hard reject also applies when chambers are configured.
func TestDA_R6_01_ProductionMode_HardReject_WithChambers(t *testing.T) {
	cleanup := setProductionMode(t)
	defer cleanup()

	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()

	// Set a DA checker that always fails.
	qpos.SetDAAvailabilityChecker(func(slot uint64) error {
		return errors.New("DA sampling failed")
	})

	// CanPropose should return FALSE even with chambers configured.
	result := qpos.CanPropose(0, 1)
	if result {
		t.Fatal("CanPropose should return FALSE in production mode with chambers when DA check fails")
	}
}

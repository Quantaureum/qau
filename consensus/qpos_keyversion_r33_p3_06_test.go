// Quantaureum Node source, version 1.0.0.
// Package consensus — R33 P3-06 regression tests for key version authorization.
//
// R33 P3-06 FIX (2026-07-28): FreezeKeyVersion and DeactivateKeyVersion
// previously had no caller authorization check. If either were ever exposed
// via RPC or reached through a privileged-escalation path, an attacker could:
//   - Freeze the key version, preventing legitimate key rotation and locking
//     the consensus into a stale key forever.
//   - Deactivate the current key version, forcing all subsequent blocks to
//     fail key-version validation and halting consensus.
//
// The fix adds isSystemCaller(caller) authorization matching
// ReactivateKeyVersion's pattern (CONS-R7-08).
//
// These tests verify:
//   - Unauthorized callers are rejected.
//   - Authorized (registered) callers succeed.
//   - Zero address is always rejected (even if somehow registered).
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR33_P3_06_FreezeKeyVersion_RejectsUnauthorizedCaller verifies that
// FreezeKeyVersion returns an error when the caller is not a registered
// system caller.
func TestR33_P3_06_FreezeKeyVersion_RejectsUnauthorizedCaller(t *testing.T) {
	qpos := &QPOS{}

	unauthorized := types.Address{0xAA, 0xBB, 0xCC}
	// Sanity check: unauthorized caller is NOT registered.
	if isSystemCaller(unauthorized) {
		t.Fatalf("test setup error: %x should not be a registered system caller", unauthorized)
	}

	err := qpos.FreezeKeyVersion(unauthorized)
	if err == nil {
		t.Fatal("R33 P3-06 REGRESSION: FreezeKeyVersion succeeded for unauthorized caller")
	}
}

// TestR33_P3_06_FreezeKeyVersion_RejectsZeroAddress verifies that the zero
// address is rejected even though it's not registered (defense in depth).
func TestR33_P3_06_FreezeKeyVersion_RejectsZeroAddress(t *testing.T) {
	qpos := &QPOS{}

	err := qpos.FreezeKeyVersion(types.Address{})
	if err == nil {
		t.Fatal("R33 P3-06 REGRESSION: FreezeKeyVersion succeeded for zero address")
	}
}

// TestR33_P3_06_FreezeKeyVersion_AcceptsAuthorizedCaller verifies that
// FreezeKeyVersion succeeds when the caller is a registered system caller.
func TestR33_P3_06_FreezeKeyVersion_AcceptsAuthorizedCaller(t *testing.T) {
	qpos := &QPOS{}

	authorized := types.Address{0x01, 0x02, 0x03}
	RegisterSystemCaller(authorized)
	defer func() {
		// Clean up the registration so other tests aren't affected.
		systemCallersMu.Lock()
		delete(systemCallers, authorized)
		systemCallersMu.Unlock()
	}()

	err := qpos.FreezeKeyVersion(authorized)
	if err != nil {
		t.Fatalf("R33 P3-06: FreezeKeyVersion failed for authorized caller: %v", err)
	}

	if !qpos.keyVersionFrozen {
		t.Fatal("R33 P3-06: FreezeKeyVersion did not set keyVersionFrozen=true")
	}
}

// TestR33_P3_06_DeactivateKeyVersion_RejectsUnauthorizedCaller verifies that
// DeactivateKeyVersion returns an error when the caller is not a registered
// system caller.
func TestR33_P3_06_DeactivateKeyVersion_RejectsUnauthorizedCaller(t *testing.T) {
	qpos := &QPOS{}
	// Pre-seed a key version so the authorization check is the only thing
	// being tested (not the "not found" error).
	if err := SetKeyVersion(qpos, 1, 1000); err != nil {
		t.Fatalf("SetKeyVersion failed: %v", err)
	}

	unauthorized := types.Address{0xDD, 0xEE, 0xFF}
	err := qpos.DeactivateKeyVersion(1, 2000, unauthorized)
	if err == nil {
		t.Fatal("R33 P3-06 REGRESSION: DeactivateKeyVersion succeeded for unauthorized caller")
	}
}

// TestR33_P3_06_DeactivateKeyVersion_RejectsZeroAddress verifies that the
// zero address is rejected for DeactivateKeyVersion.
func TestR33_P3_06_DeactivateKeyVersion_RejectsZeroAddress(t *testing.T) {
	qpos := &QPOS{}
	if err := SetKeyVersion(qpos, 1, 1000); err != nil {
		t.Fatalf("SetKeyVersion failed: %v", err)
	}

	err := qpos.DeactivateKeyVersion(1, 2000, types.Address{})
	if err == nil {
		t.Fatal("R33 P3-06 REGRESSION: DeactivateKeyVersion succeeded for zero address")
	}
}

// TestR33_P3_06_DeactivateKeyVersion_AcceptsAuthorizedCaller verifies that
// DeactivateKeyVersion succeeds when the caller is a registered system caller.
func TestR33_P3_06_DeactivateKeyVersion_AcceptsAuthorizedCaller(t *testing.T) {
	qpos := &QPOS{}
	if err := SetKeyVersion(qpos, 1, 1000); err != nil {
		t.Fatalf("SetKeyVersion failed: %v", err)
	}

	authorized := types.Address{0x04, 0x05, 0x06}
	RegisterSystemCaller(authorized)
	defer func() {
		systemCallersMu.Lock()
		delete(systemCallers, authorized)
		systemCallersMu.Unlock()
	}()

	err := qpos.DeactivateKeyVersion(1, 2000, authorized)
	if err != nil {
		t.Fatalf("R33 P3-06: DeactivateKeyVersion failed for authorized caller: %v", err)
	}

	// Verify the deactivation was actually recorded.
	qpos.keyVersionMu.RLock()
	kvi := qpos.keyVersionHistory[1]
	qpos.keyVersionMu.RUnlock()

	if kvi == nil {
		t.Fatal("key version 1 not found in history")
	}
	if kvi.DeactivationTime != 2000 {
		t.Errorf("DeactivationTime = %d, want 2000", kvi.DeactivationTime)
	}
}

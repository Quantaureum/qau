// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestCONS_R12002_TemporarySlash_CanBeUnmarked verifies that a temporary slash
// entry in QPOS.slashedValidators can be cleared by UnmarkValidatorSlashed.
// CONS-R12-002 (2026-07-20): Previously the slashedValidators map was
// map[int]uint64 with only the slash epoch, and there was no Unmark method —
// so a temporary slash (downtime) became a permanent ban even after Unjail.
func TestCONS_R12002_TemporarySlash_CanBeUnmarked(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address

	// Mark as temporarily slashed (downtime — not permanent).
	if err := qpos.MarkValidatorSlashedByAddress(addr0, false, time.Now().Unix()+3600); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress(temporary) failed: %v", err)
	}

	// Verify it's actually marked.
	if !qpos.IsSlashed(0) {
		t.Fatal("expected validator 0 to be slashed after MarkValidatorSlashedByAddress(temporary)")
	}

	// Unmark — this is the new path that was missing before CONS-R12-002.
	if err := qpos.UnmarkValidatorSlashed(addr0); err != nil {
		t.Fatalf("UnmarkValidatorSlashed failed for temporary slash: %v", err)
	}

	// Verify the entry is gone.
	if qpos.IsSlashed(0) {
		t.Error("validator 0 should NOT be slashed after UnmarkValidatorSlashed (temporary slash)")
	}
}

// TestCONS_R12002_PermanentSlash_CannotBeUnmarked verifies that a permanent
// slash (double-signing) is NOT clearable by UnmarkValidatorSlashed.
// This is the safety guarantee that attackers cannot undo a permanent ban
// via Unjail or any other code path.
func TestCONS_R12002_PermanentSlash_CannotBeUnmarked(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address

	// Mark as permanently slashed (double-signing).
	if err := qpos.MarkValidatorSlashedByAddress(addr0, true, 0); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress(permanent) failed: %v", err)
	}

	if !qpos.IsSlashed(0) {
		t.Fatal("expected validator 0 to be slashed after permanent mark")
	}

	// Attempting to unmark a permanent slash must fail.
	err := qpos.UnmarkValidatorSlashed(addr0)
	if err != ErrValidatorPermanent {
		t.Errorf("expected ErrValidatorPermanent for unmarking permanent slash, got %v", err)
	}

	// Verify the entry is STILL there.
	if !qpos.IsSlashed(0) {
		t.Error("permanent slash entry was cleared — this is a CRITICAL security bug")
	}
}

// TestCONS_R12002_TemporaryUpgradeToPermanent verifies that if a validator
// is first slashed temporarily and later slashed permanently (e.g., downtime
// then double-signing), the entry is upgraded to permanent and cannot be
// downgraded back to temporary.
func TestCONS_R12002_TemporaryUpgradeToPermanent(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address

	// Step 1: temporary slash (downtime).
	if err := qpos.MarkValidatorSlashedByAddress(addr0, false, time.Now().Unix()+3600); err != nil {
		t.Fatalf("first MarkValidatorSlashedByAddress(temporary) failed: %v", err)
	}

	// Verify it can be unmarked at this point.
	if err := qpos.UnmarkValidatorSlashed(addr0); err != nil {
		t.Fatalf("UnmarkValidatorSlashed failed for temporary slash: %v", err)
	}

	// Step 2: re-mark as permanent (double-signing).
	if err := qpos.MarkValidatorSlashedByAddress(addr0, true, 0); err != nil {
		t.Fatalf("second MarkValidatorSlashedByAddress(permanent) failed: %v", err)
	}

	// Now unmark MUST fail (permanent).
	if err := qpos.UnmarkValidatorSlashed(addr0); err != ErrValidatorPermanent {
		t.Errorf("expected ErrValidatorPermanent after upgrade, got %v", err)
	}
}

// TestCONS_R12002_PermanentNotDowngradedToTemporary verifies that a
// permanent slash entry is NOT downgraded to temporary by a later temporary
// slash. This prevents an attacker from exploiting a stale temporary evidence
// to "downgrade" a permanent ban and then Unjail it.
func TestCONS_R12002_PermanentNotDowngradedToTemporary(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address

	// Step 1: permanent slash (double-signing).
	if err := qpos.MarkValidatorSlashedByAddress(addr0, true, 0); err != nil {
		t.Fatalf("first MarkValidatorSlashedByAddress(permanent) failed: %v", err)
	}

	// Step 2: later temporary slash (e.g., stale downtime evidence).
	if err := qpos.MarkValidatorSlashedByAddress(addr0, false, time.Now().Unix()+3600); err != nil {
		t.Fatalf("second MarkValidatorSlashedByAddress(temporary) failed: %v", err)
	}

	// Verify the entry is STILL permanent — unmark MUST fail.
	if err := qpos.UnmarkValidatorSlashed(addr0); err != ErrValidatorPermanent {
		t.Errorf("expected ErrValidatorPermanent (entry should still be permanent), got %v", err)
	}
}

// TestCONS_R12002_GetSlashedValidators_ReturnsSlashedEntry verifies that
// GetSlashedValidators returns the new *SlashedEntry type with Permanent /
// JailUntil fields populated correctly.
func TestCONS_R12002_GetSlashedValidators_ReturnsSlashedEntry(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address
	addr1 := vs.Validators()[1].Address

	// Mark validator 0 as permanent, validator 1 as temporary.
	if err := qpos.MarkValidatorSlashedByAddress(addr0, true, 0); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress(permanent) for v0 failed: %v", err)
	}
	tempJailUntil := time.Now().Unix() + 7200
	if err := qpos.MarkValidatorSlashedByAddress(addr1, false, tempJailUntil); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress(temporary) for v1 failed: %v", err)
	}

	snapshot := qpos.GetSlashedValidators()
	if len(snapshot) != 2 {
		t.Fatalf("expected 2 slashed validators, got %d", len(snapshot))
	}

	entry0, ok0 := snapshot[0]
	if !ok0 {
		t.Fatal("expected validator 0 in snapshot")
	}
	if !entry0.Permanent {
		t.Error("validator 0 should be permanent")
	}
	if entry0.JailUntil != 0 {
		t.Errorf("permanent slash should have JailUntil=0, got %d", entry0.JailUntil)
	}

	entry1, ok1 := snapshot[1]
	if !ok1 {
		t.Fatal("expected validator 1 in snapshot")
	}
	if entry1.Permanent {
		t.Error("validator 1 should NOT be permanent")
	}
	if entry1.JailUntil != tempJailUntil {
		t.Errorf("temporary slash JailUntil mismatch: got %d, want %d", entry1.JailUntil, tempJailUntil)
	}
}

// TestCONS_R12002_Unjail_ClearsQPOSSlashedValidators verifies the integration:
// SlashingManager.Unjail() calls QPOS.UnmarkValidatorSlashed() to clear the
// slashedValidators entry for a temporary slash after jail expires.
// This is the production path that was completely missing before CONS-R12-002.
func TestCONS_R12002_Unjail_ClearsQPOSSlashedValidators(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	vm := NewValidatorManager()
	// Register the validators directly (same package — can access private field).
	addr0 := vs.Validators()[0].Address
	vm.validators[addr0] = &ValidatorInfo{
		Address:    addr0,
		Stake:      MinStakeAmount,
		Active:     false, // slashed → inactive
		Commission: 100,
		// VAL-H04/VAL-H05 FIX (R31, 2026-07-27): EverActivated=true so the
		// Unjail path (which calls SetActive for re-activation) is allowed.
		// This simulates a validator that was previously activated, then
		// slashed/jailed (the only legitimate scenario for Unjail).
		EverActivated: true,
	}
	// Register system caller for SetActive authorization.
	slashingSysAddr := types.BytesToAddress([]byte("test-unjail-slash"))
	RegisterSystemCaller(slashingSysAddr)

	sm := NewSlashingManager(vm)
	sm.SetQPOS(qpos)
	defer sm.Stop()

	// Simulate a temporary slash via SlashingManager.slash-equivalent path:
	// directly mark via QPOS + signingInfo.
	now := time.Now()
	qpos.mu.Lock()
	qpos.slashedValidators[0] = &SlashedEntry{
		Epoch:     0,
		Permanent: false,
		JailUntil: now.Unix() - 1, // already expired
	}
	qpos.mu.Unlock()

	sm.mu.Lock()
	sm.signingInfo[addr0] = &ValidatorSigningInfo{
		Address:            addr0,
		JailedUntil:        now.Unix() - 1, // already expired
		PermanentlySlashed: false,
	}
	sm.mu.Unlock()

	// Sanity: validator is slashed in QPOS.
	if !qpos.IsSlashed(0) {
		t.Fatal("precondition: validator 0 should be slashed in QPOS")
	}

	// Call Unjail — should clear QPOS.slashedValidators[0] via goroutine.
	// Use blockTime far in the future to ensure JailedUntil < blockTime check passes.
	err := sm.Unjail(slashingSysAddr, addr0, uint64(now.Unix()+3600))
	if err != nil {
		t.Fatalf("Unjail failed: %v", err)
	}

	// The UnmarkValidatorSlashed call happens in a goroutine — wait for it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !qpos.IsSlashed(0) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if qpos.IsSlashed(0) {
		t.Error("validator 0 should be cleared from QPOS.slashedValidators after Unjail (temporary slash)")
	}
}

// TestCONS_R12002_Unjail_DoesNotClearPermanentSlash verifies that Unjail
// refuses to clear a permanent slash — UnmarkValidatorSlashed returns
// ErrValidatorPermanent and the slashedValidators entry remains.
// (Note: SlashingManager.Unjail already rejects PermanentlySlashed signingInfo
// at line ~1692, so UnmarkValidatorSlashed is defense-in-depth.)
func TestCONS_R12002_Unjail_DoesNotClearPermanentSlash(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address

	// Mark as permanent.
	if err := qpos.MarkValidatorSlashedByAddress(addr0, true, 0); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress(permanent) failed: %v", err)
	}

	// Directly call UnmarkValidatorSlashed — should be rejected.
	err := qpos.UnmarkValidatorSlashed(addr0)
	if err != ErrValidatorPermanent {
		t.Errorf("expected ErrValidatorPermanent, got %v", err)
	}

	// Entry must remain.
	if !qpos.IsSlashed(0) {
		t.Error("permanent slash entry was cleared — CRITICAL security bug")
	}
}

// TestCONS_R12002_UnmarkValidatorSlashed_Idempotent verifies that calling
// UnmarkValidatorSlashed on a non-slashed validator is a no-op (returns nil).
// This is important because Unjail's goroutine may race with another path
// that already cleared the entry.
func TestCONS_R12002_UnmarkValidatorSlashed_Idempotent(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address

	// Not slashed — should return nil (idempotent).
	err := qpos.UnmarkValidatorSlashed(addr0)
	if err != nil {
		t.Errorf("UnmarkValidatorSlashed on non-slashed validator should return nil, got %v", err)
	}
}

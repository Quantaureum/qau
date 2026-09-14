// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestCONS_R12001_SetQPOS_StartsBackgroundSyncLoop verifies that calling
// SetQPOS spawns exactly one background syncPendingSlashesLoop goroutine.
// CONS-R12-001 (R11 regression): the prior fix introduced pendingSlashedAddrs
// and SyncPendingSlashes() but never wired a production caller — so a slashed
// validator could remain un-slashed in QPOS.slashedValidators forever.
// We now start a background goroutine in SetQPOS. Calling SetQPOS multiple
// times must not spawn duplicate loops (startOnce guard).
func TestCONS_R12001_SetQPOS_StartsBackgroundSyncLoop(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	sm := NewSlashingManager(NewValidatorManager())
	// Calling SetQPOS twice must still spawn only ONE goroutine (startOnce guard).
	sm.SetQPOS(qpos)
	originalStopCh := sm.stopCh
	sm.SetQPOS(qpos)
	if sm.stopCh != originalStopCh {
		t.Error("second SetQPOS must not replace stopCh (would leak the first goroutine)")
	}
	sm.SetQPOS(qpos)
	if sm.stopCh != originalStopCh {
		t.Error("third SetQPOS must not replace stopCh (would leak the first two goroutines)")
	}

	// stopCh must be initialized and not closed.
	if sm.stopCh == nil {
		t.Fatal("expected stopCh to be initialized after SetQPOS")
	}
	select {
	case <-sm.stopCh:
		t.Fatal("stopCh should not be closed while SlashingManager is running")
	default:
		// good — still open
	}

	// Stop the manager — must close stopCh exactly once.
	sm.Stop()
	select {
	case <-sm.stopCh:
		// good — closed
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Stop() should close stopCh")
	}

	// Calling Stop again must be a no-op (idempotent, no panic).
	sm.Stop()
}

// TestCONS_R12001_SyncPendingSlashes_AppliesPendingSlash verifies that
// SyncPendingSlashes() — which the background loop calls every 10s —
// successfully re-applies a pending slash to QPOS.slashedValidators when
// the async goroutine in slash() had failed (simulated here by directly
// injecting into pendingSlashedAddrs).
func TestCONS_R12001_SyncPendingSlashes_AppliesPendingSlash(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	sm := NewSlashingManager(NewValidatorManager())
	sm.SetQPOS(qpos)
	defer sm.Stop()

	// Pick validator 0's address.
	addr0 := vs.Validators()[0].Address

	// Inject a pending slashed address — simulates the case where the
	// async slash() goroutine failed before calling MarkValidatorSlashedByAddress.
	sm.pendingSlashedMu.Lock()
	sm.pendingSlashedAddrs[addr0] = true
	sm.pendingSlashedMu.Unlock()

	// Pre-condition: validator 0 is NOT yet in slashedValidators.
	if qpos.IsSlashed(0) {
		t.Fatal("precondition failed: validator 0 should not be slashed yet")
	}

	// Trigger the sync manually (the background loop calls this every 10s).
	sm.SyncPendingSlashes()

	// Post-condition: validator 0 IS now in slashedValidators.
	if !qpos.IsSlashed(0) {
		t.Fatal("after SyncPendingSlashes, validator 0 should be slashed")
	}

	// Post-condition: the pendingSlashedAddrs entry should be removed on success.
	sm.pendingSlashedMu.Lock()
	_, stillPending := sm.pendingSlashedAddrs[addr0]
	sm.pendingSlashedMu.Unlock()
	if stillPending {
		t.Error("pendingSlashedAddrs entry should be cleared after successful sync")
	}
}

// TestCONS_R12001_MarkValidatorSlashedByAddress_ClearsPendingDeactivation
// verifies that MarkValidatorSlashedByAddress clears the corresponding
// pendingDeactivationAddrs entry on success — audit recommendation #3 for
// CONS-R12-001. Without this cleanup, the pendingDeactivationAddrs map would
// grow unbounded as more validators get slashed.
func TestCONS_R12001_MarkValidatorSlashedByAddress_ClearsPendingDeactivation(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address

	// Simulate the path where SlashingManager.slash() failed to SetActive and
	// fell back to MarkPendingDeactivationAddr.
	qpos.MarkPendingDeactivationAddr(addr0)

	// Pre-condition: pendingDeactivationAddrs has the entry.
	if !qpos.isPendingDeactivation(0) {
		t.Fatal("precondition failed: pendingDeactivationAddrs should contain addr0")
	}

	// Now MarkValidatorSlashedByAddress succeeds.
	if err := qpos.MarkValidatorSlashedByAddress(addr0, false, 0); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress failed: %v", err)
	}

	// Post-condition: pendingDeactivationAddrs should be cleared.
	if qpos.isPendingDeactivation(0) {
		t.Error("pendingDeactivationAddrs should be cleared after MarkValidatorSlashedByAddress succeeds")
	}
}

// TestCONS_R12001_MarkValidatorSlashedByAddress_ClearsPendingDeactivation_AlreadySlashedPath
// verifies that the no-op path (validator already slashed) ALSO clears the
// stale pendingDeactivationAddrs entry — the fix's defensive cleanup.
func TestCONS_R12001_MarkValidatorSlashedByAddress_ClearsPendingDeactivation_AlreadySlashedPath(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr0 := vs.Validators()[0].Address

	// Mark as slashed FIRST.
	if err := qpos.MarkValidatorSlashedByAddress(addr0, false, 0); err != nil {
		t.Fatalf("first MarkValidatorSlashedByAddress failed: %v", err)
	}
	// Add a stale pending deactivation entry (simulates a bug where
	// SlashingManager.slash() fell back to MarkPendingDeactivationAddr AFTER
	// the validator had already been marked as slashed).
	qpos.MarkPendingDeactivationAddr(addr0)
	if !qpos.isPendingDeactivation(0) {
		t.Fatal("precondition failed: pendingDeactivationAddrs should contain addr0")
	}

	// Calling MarkValidatorSlashedByAddress again is a no-op for slashedValidators
	// (already there), but the CONS-R12-001 fix must STILL clear the stale
	// pendingDeactivationAddrs entry.
	if err := qpos.MarkValidatorSlashedByAddress(addr0, false, 0); err != nil {
		t.Fatalf("second MarkValidatorSlashedByAddress failed: %v", err)
	}
	if qpos.isPendingDeactivation(0) {
		t.Error("stale pendingDeactivationAddrs entry should be cleared on the no-op path too")
	}
}

// TestCONS_R12001_Stop_PreventsGoroutineLeak verifies that calling Stop()
// terminates the background goroutine so it does not leak across test runs.
// We can't observe the goroutine directly, but we can verify that Stop()
// returns promptly and that further SetQPOS calls don't accidentally
// restart the loop (startOnce guards the start).
func TestCONS_R12001_Stop_PreventsGoroutineLeak(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	sm := NewSlashingManager(NewValidatorManager())
	sm.SetQPOS(qpos)

	// Stop should return promptly (it only closes a channel).
	done := make(chan struct{})
	go func() {
		sm.Stop()
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() took too long — possible goroutine leak or deadlock")
	}

	// Calling SetQPOS after Stop must NOT spawn a new goroutine
	// (startOnce already fired).
	sm.SetQPOS(qpos)
	// stopCh is still closed — the loop did not restart.
	select {
	case <-sm.stopCh:
		// good — still closed, loop not restarted
	case <-time.After(100 * time.Millisecond):
		t.Fatal("startOnce should prevent restart of the sync loop after Stop")
	}
}

// TestCONS_R12001_SyncPendingSlashes_NoQPOS verifies that SyncPendingSlashes
// is a safe no-op when qpos is nil (defensive: avoids nil pointer panic).
func TestCONS_R12001_SyncPendingSlashes_NoQPOS(t *testing.T) {
	sm := NewSlashingManager(NewValidatorManager())
	// Do NOT call SetQPOS — sm.qpos stays nil.

	// Inject a pending address.
	addr := types.Address{0xAA}
	sm.pendingSlashedMu.Lock()
	sm.pendingSlashedAddrs[addr] = true
	sm.pendingSlashedMu.Unlock()

	// Must not panic.
	sm.SyncPendingSlashes()

	// Entry should remain (no QPOS to apply to).
	sm.pendingSlashedMu.Lock()
	_, stillPending := sm.pendingSlashedAddrs[addr]
	sm.pendingSlashedMu.Unlock()
	if !stillPending {
		t.Error("entry should remain when QPOS is nil — nothing to sync to")
	}
}

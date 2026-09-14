// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// ---------------------------------------------------------------------------
// CONS-R13-001: Unjail state cleanup retry via SyncPendingSlashes
// ---------------------------------------------------------------------------
//
// Audit finding (R13 High): Unjail's async goroutine only logged failures
// when UnmarkValidatorSlashed returned an error — no retry mechanism. If the
// goroutine failed (transient error, sm.qpos nil, node crash mid-flight),
// the validator remained permanently banned in QPOS.slashedValidators despite
// having served the jail sentence. The slash path had a symmetric
// pendingSlashedAddrs + SyncPendingSlashes retry loop; the unjail path did
// not.
//
// Fix: added pendingUnjailAddrs queue; Unjail registers the address before
// spawning the goroutine, and SyncPendingSlashes now sweeps both pending
// slashes AND pending unjails every 10s.

// TestCONS_R13001_SyncPendingSlashes_RetriesPendingUnjail verifies that
// SyncPendingSlashes re-applies a pending UNJAIL decision: a temporarily
// slashed validator is unmarked from QPOS.slashedValidators after the sync
// sweep, and the pendingUnjailAddrs entry is cleared on success.
func TestCONS_R13001_SyncPendingSlashes_RetriesPendingUnjail(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	sm := NewSlashingManager(NewValidatorManager())
	sm.SetQPOS(qpos)
	defer sm.Stop()

	addr0 := vs.Validators()[0].Address

	// Pre-condition: slash validator 0 temporarily (jailUntil=0, permanent=false).
	if err := qpos.MarkValidatorSlashedByAddress(addr0, false, 0); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress failed: %v", err)
	}
	if !qpos.IsSlashed(0) {
		t.Fatal("precondition: validator 0 should be slashed")
	}

	// Inject a pending unjail — simulates Unjail's goroutine having failed.
	sm.pendingSlashedMu.Lock()
	sm.pendingUnjailAddrs[addr0] = true
	sm.pendingSlashedMu.Unlock()

	// Trigger the sync (the background loop calls this every 10s).
	sm.SyncPendingSlashes()

	// Post-condition: validator 0 is NO LONGER slashed.
	if qpos.IsSlashed(0) {
		t.Error("after SyncPendingSlashes, validator 0 should be unmarked (unjail succeeded)")
	}

	// Post-condition: pendingUnjailAddrs entry removed on success.
	sm.pendingSlashedMu.Lock()
	_, stillPending := sm.pendingUnjailAddrs[addr0]
	sm.pendingSlashedMu.Unlock()
	if stillPending {
		t.Error("pendingUnjailAddrs entry should be cleared after successful unjail sync")
	}
}

// TestCONS_R13001_SyncPendingSlashes_Unjail_PermanentSlashDropped
// verifies that a permanently-slashed validator CANNOT be unjail'd via the
// pending queue — UnmarkValidatorSlashed returns ErrValidatorPermanent, so
// the entry is DROPPED from pendingUnjailAddrs (R14-LOW fix: retrying a
// permanent ban every 10s is futile and causes unbounded map growth).
// The validator remains slashed in QPOS — only the pending retry entry
// is removed.
func TestCONS_R13001_SyncPendingSlashes_Unjail_PermanentSlashDropped(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	sm := NewSlashingManager(NewValidatorManager())
	sm.SetQPOS(qpos)
	defer sm.Stop()

	addr0 := vs.Validators()[0].Address

	// Slash validator 0 PERMANENTLY.
	if err := qpos.MarkValidatorSlashedByAddress(addr0, true, 0); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress failed: %v", err)
	}
	if !qpos.IsSlashed(0) {
		t.Fatal("precondition: validator 0 should be permanently slashed")
	}

	// Inject a pending unjail (shouldn't happen for permanent slashes in
	// normal flow — Unjail rejects permanent bans before reaching the
	// goroutine — but we test the defensive sync path anyway).
	sm.pendingSlashedMu.Lock()
	sm.pendingUnjailAddrs[addr0] = true
	sm.pendingSlashedMu.Unlock()

	// Trigger the sync.
	sm.SyncPendingSlashes()

	// Post-condition: validator 0 IS STILL slashed (permanent bans can't be unjail'd).
	if !qpos.IsSlashed(0) {
		t.Error("permanently-slashed validator should NOT be unmarked by sync")
	}

	// Post-condition (R14-LOW): pendingUnjailAddrs entry is DROPPED —
	// retrying a permanent ban is futile and would cause unbounded growth.
	sm.pendingSlashedMu.Lock()
	_, stillPending := sm.pendingUnjailAddrs[addr0]
	sm.pendingSlashedMu.Unlock()
	if stillPending {
		t.Error("pendingUnjailAddrs entry should be DROPPED for permanently-slashed validator (R14-LOW fix: futile retries removed)")
	}
}

// TestCONS_R13001_SyncPendingSlashes_NoQPOS_PreservesUnjailQueue verifies
// that when sm.qpos is nil, SyncPendingSlashes is a safe no-op that
// preserves the pendingUnjailAddrs entries for later retry (once SetQPOS
// is called).
func TestCONS_R13001_SyncPendingSlashes_NoQPOS_PreservesUnjailQueue(t *testing.T) {
	sm := NewSlashingManager(NewValidatorManager())
	// Do NOT call SetQPOS — sm.qpos stays nil.

	addr := types.Address{0xBB}
	sm.pendingSlashedMu.Lock()
	sm.pendingUnjailAddrs[addr] = true
	sm.pendingSlashedMu.Unlock()

	// Must not panic, must not clear the entry.
	sm.SyncPendingSlashes()

	sm.pendingSlashedMu.Lock()
	_, stillPending := sm.pendingUnjailAddrs[addr]
	sm.pendingSlashedMu.Unlock()
	if !stillPending {
		t.Error("pendingUnjailAddrs entry should remain when QPOS is nil — nothing to sync to")
	}
}

// TestCONS_R13001_SyncPendingSlashes_BothQueuesProcessed verifies that a
// single SyncPendingSlashes call processes BOTH pending slashes AND pending
// unjails in one pass. This guards against a regression where the unjail
// sweep is accidentally skipped when the slash sweep is non-empty.
func TestCONS_R13001_SyncPendingSlashes_BothQueuesProcessed(t *testing.T) {
	vs := createTestValidatorSetHC(4)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	sm := NewSlashingManager(NewValidatorManager())
	sm.SetQPOS(qpos)
	defer sm.Stop()

	addr0 := vs.Validators()[0].Address
	addr1 := vs.Validators()[1].Address

	// Slash addr0 temporarily, then queue a pending unjail for addr0.
	if err := qpos.MarkValidatorSlashedByAddress(addr0, false, 0); err != nil {
		t.Fatalf("MarkValidatorSlashedByAddress(addr0) failed: %v", err)
	}
	sm.pendingSlashedMu.Lock()
	sm.pendingUnjailAddrs[addr0] = true
	sm.pendingSlashedMu.Unlock()

	// Queue a pending SLASH for addr1 (not yet slashed in QPOS).
	sm.pendingSlashedMu.Lock()
	sm.pendingSlashedAddrs[addr1] = true
	// Inject signingInfo for addr1 so SyncPendingSlashes can read permanent flag.
	sm.pendingSlashedMu.Unlock()
	sm.mu.Lock()
	if sm.signingInfo == nil {
		sm.signingInfo = make(map[types.Address]*ValidatorSigningInfo)
	}
	sm.signingInfo[addr1] = &ValidatorSigningInfo{
		PermanentlySlashed: false,
		JailedUntil:        0,
	}
	sm.mu.Unlock()

	// Trigger the sync — should process BOTH queues in one pass.
	sm.SyncPendingSlashes()

	// addr0: should be unmarked (unjail succeeded).
	if qpos.IsSlashed(0) {
		t.Error("addr0 should be unmarked after sync (pending unjail processed)")
	}

	// addr1: should be slashed (pending slash processed).
	if !qpos.IsSlashed(1) {
		t.Error("addr1 should be slashed after sync (pending slash processed)")
	}

	// Both queues should be empty.
	sm.pendingSlashedMu.Lock()
	unjailEmpty := len(sm.pendingUnjailAddrs) == 0
	slashEmpty := len(sm.pendingSlashedAddrs) == 0
	sm.pendingSlashedMu.Unlock()
	if !unjailEmpty {
		t.Error("pendingUnjailAddrs should be empty after successful sync")
	}
	if !slashEmpty {
		t.Error("pendingSlashedAddrs should be empty after successful sync")
	}
}

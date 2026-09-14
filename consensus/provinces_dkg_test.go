// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"
)

// TestTriggerDKG_NilExecutive verifies TriggerDKG returns false when the
// executive chamber is nil (coordinator has no executive).
func TestTriggerDKG_NilExecutive(t *testing.T) {
	tpc := &ThreeChambersCoordinator{} // executive is nil
	if tpc.TriggerDKG([]byte("key")) {
		t.Error("TriggerDKG should return false when executive is nil")
	}
}

// TestTriggerDKG_AlreadyActive verifies TriggerDKG returns true (idempotent)
// when the executive is already active.
func TestTriggerDKG_AlreadyActive(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	// Already active — should return true without changing state.
	if !coordinator.TriggerDKG([]byte("new-key")) {
		t.Error("TriggerDKG should return true when already active")
	}
	// Public key should NOT be overwritten by the new key.
	pk := executive.PublicKey()
	if string(pk) != string(make([]byte, minGroupPublicKeyLen)) {
		t.Errorf("public key should not change when already active; got %q", pk)
	}
}

// TestTriggerDKG_NotRunning verifies TriggerDKG returns false when the
// executive state is Idle (not DKGRunning).
func TestTriggerDKG_NotRunning(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	// Executive is in ExecutiveIdle state (no SetMembers called).
	if executive.State() != ExecutiveIdle {
		t.Fatalf("expected ExecutiveIdle, got %s", executive.State())
	}
	if coordinator.TriggerDKG([]byte("key")) {
		t.Error("TriggerDKG should return false when state is Idle")
	}
}

// TestTriggerDKG_EmptyGroupKey verifies TriggerDKG returns false when the
// group key is empty (DKG still pending).
func TestTriggerDKG_EmptyGroupKey(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	// Now in ExecutiveDKGRunning state.
	if executive.State() != ExecutiveDKGRunning {
		t.Fatalf("expected ExecutiveDKGRunning, got %s", executive.State())
	}
	if coordinator.TriggerDKG(nil) {
		t.Error("TriggerDKG should return false when group key is nil")
	}
	if coordinator.TriggerDKG([]byte{}) {
		t.Error("TriggerDKG should return false when group key is empty")
	}
	// State should still be DKGRunning.
	if executive.State() != ExecutiveDKGRunning {
		t.Errorf("expected DKGRunning, got %s", executive.State())
	}
}

// TestTriggerDKG_CompletesDKG verifies TriggerDKG transitions the executive
// from DKGRunning to Active when a valid group key is provided.
func TestTriggerDKG_CompletesDKG(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)

	if executive.State() != ExecutiveDKGRunning {
		t.Fatalf("expected DKGRunning, got %s", executive.State())
	}

	groupKey := make([]byte, minGroupPublicKeyLen)
	if !coordinator.TriggerDKG(groupKey) {
		t.Error("TriggerDKG should return true when DKG completes")
	}

	if executive.State() != ExecutiveActive {
		t.Errorf("expected Active after TriggerDKG, got %s", executive.State())
	}
	pk := executive.PublicKey()
	if string(pk) != string(groupKey) {
		t.Errorf("public key mismatch: got %q, want %q", pk, groupKey)
	}
}

// TestCheckDKGTimeout_NotRunning verifies CheckDKGTimeout returns false when
// DKG is not in the running state.
func TestCheckDKGTimeout_NotRunning(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	// Idle state.
	if coordinator.CheckDKGTimeout(1 * time.Second) {
		t.Error("CheckDKGTimeout should return false when state is Idle")
	}

	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))
	// Active state.
	if coordinator.CheckDKGTimeout(1 * time.Second) {
		t.Error("CheckDKGTimeout should return false when state is Active")
	}
}

// TestCheckDKGTimeout_TimedOut verifies CheckDKGTimeout returns true when the
// DKG has been running longer than the timeout.
func TestCheckDKGTimeout_TimedOut(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)

	// Sleep briefly so time.Since(dkgStartTime) exceeds the timeout.
	// Windows timer resolution is ~15ms, so 20ms is sufficient.
	time.Sleep(20 * time.Millisecond)
	if !coordinator.CheckDKGTimeout(10 * time.Millisecond) {
		t.Error("CheckDKGTimeout should return true when elapsed > timeout")
	}
}

// TestCheckDKGTimeout_NilExecutive verifies CheckDKGTimeout returns false
// when the executive chamber is nil.
func TestCheckDKGTimeout_NilExecutive(t *testing.T) {
	tpc := &ThreeChambersCoordinator{}
	if tpc.CheckDKGTimeout(1 * time.Second) {
		t.Error("CheckDKGTimeout should return false when executive is nil")
	}
}

// TestGetDKGStatus_NilExecutive verifies GetDKGStatus returns unavailable
// when the executive chamber is nil.
func TestGetDKGStatus_NilExecutive(t *testing.T) {
	tpc := &ThreeChambersCoordinator{}
	status := tpc.GetDKGStatus()
	if status["available"] != false {
		t.Errorf("expected available=false, got %v", status["available"])
	}
}

// TestGetDKGStatus_Idle verifies GetDKGStatus returns correct fields when
// the executive is in Idle state.
func TestGetDKGStatus_Idle(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	status := coordinator.GetDKGStatus()

	if status["available"] != true {
		t.Errorf("expected available=true, got %v", status["available"])
	}
	if status["state"] != "Idle" {
		t.Errorf("expected state=Idle, got %v", status["state"])
	}
	if status["hasGroupKey"] != false {
		t.Errorf("expected hasGroupKey=false, got %v", status["hasGroupKey"])
	}
}

// TestGetDKGStatus_DKGRunning verifies GetDKGStatus reports DKGRunning state
// with elapsed time.
func TestGetDKGStatus_DKGRunning(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)

	status := coordinator.GetDKGStatus()
	if status["state"] != "DKGRunning" {
		t.Errorf("expected state=DKGRunning, got %v", status["state"])
	}
	if status["epoch"] != uint64(0) {
		t.Errorf("expected epoch=0, got %v", status["epoch"])
	}
	// dkgElapsed should be present since dkgStartTime is set.
	if _, ok := status["dkgElapsed"]; !ok {
		t.Error("expected dkgElapsed field in DKGRunning status")
	}
}

// TestGetDKGStatus_Active verifies GetDKGStatus reports Active state with
// group key and duration.
func TestGetDKGStatus_Active(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)
	_ = executive.SetDKGComplete(make([]byte, minGroupPublicKeyLen))

	status := coordinator.GetDKGStatus()
	if status["state"] != "Active" {
		t.Errorf("expected state=Active, got %v", status["state"])
	}
	if status["hasGroupKey"] != true {
		t.Errorf("expected hasGroupKey=true, got %v", status["hasGroupKey"])
	}
	if status["threshold"] != 2 {
		t.Errorf("expected threshold=2, got %v", status["threshold"])
	}
	// dkgDuration should be present since DKG completed.
	if _, ok := status["dkgDuration"]; !ok {
		t.Error("expected dkgDuration field in Active status")
	}
}

// TestGOV_R5_05_RequireDistributedDKG_BlocksTriggerDKG verifies the
// GOV-R5-05 production gate: when SetRequireDistributedDKG(true) is set,
// TriggerDKG refuses to activate the executive chamber using a locally-preset
// group key. This is the placeholder DKG path that must be blocked on mainnet
// until real P2P distributed DKG is implemented.
//
// GOV-R5-05 (2026-07-17)
func TestGOV_R5_05_RequireDistributedDKG_BlocksTriggerDKG(t *testing.T) {
	_, coordinator, _ := setupStardustEnv(t, 10)
	executive := coordinator.GetExecutiveChamber()
	_ = executive.SetMembers([]int{0, 1, 2}, 0)

	if executive.State() != ExecutiveDKGRunning {
		t.Fatalf("expected DKGRunning, got %s", executive.State())
	}

	// Enable the production gate (mainnet mode).
	coordinator.SetRequireDistributedDKG(true)

	// TriggerDKG must refuse the local preset key and return false.
	if coordinator.TriggerDKG([]byte("local-preset-key")) {
		t.Error("GOV-R5-05: TriggerDKG should return false when requireDistributedDKG=true (local preset key blocked)")
	}
	// Executive must remain in DKGRunning (not activated).
	if executive.State() != ExecutiveDKGRunning {
		t.Errorf("GOV-R5-05: executive should remain DKGRunning when gate blocks activation; got %s", executive.State())
	}
	// Public key must NOT be set.
	if pk := executive.PublicKey(); len(pk) != 0 {
		t.Errorf("GOV-R5-05: public key should not be set when gate blocks activation; got %x", pk)
	}

	// Disabling the gate (testnet mode) should allow TriggerDKG to proceed.
	coordinator.SetRequireDistributedDKG(false)
	if !coordinator.TriggerDKG(make([]byte, minGroupPublicKeyLen)) {
		t.Error("TriggerDKG should return true after disabling the gate (testnet mode)")
	}
	if executive.State() != ExecutiveActive {
		t.Errorf("expected Active after gate disabled, got %s", executive.State())
	}
}

// TestGOV_R5_05_RequireDistributedDKG_BlocksTransitionExecutive verifies the
// GOV-R5-05 production gate also blocks TransitionExecutiveForEpoch from
// activating the executive chamber with a local preset key.
//
// GOV-R5-05 (2026-07-17)
func TestGOV_R5_05_RequireDistributedDKG_BlocksTransitionExecutive(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	executive := coordinator.GetExecutiveChamber()

	// Enable the production gate (mainnet mode).
	coordinator.SetRequireDistributedDKG(true)

	// TransitionExecutiveForEpoch with a non-empty group key must NOT
	// activate the executive chamber when the gate is enabled.
	err = coordinator.TransitionExecutiveForEpoch(1, vs, []byte("local-preset-key"))
	if err != nil {
		t.Fatalf("TransitionExecutiveForEpoch returned error: %v", err)
	}
	if executive.IsActive() {
		t.Error("GOV-R5-05: executive should NOT be activated when requireDistributedDKG=true blocks local preset key")
	}
}

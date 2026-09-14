// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"os"
	"strings"
	"testing"
)

// QVM-R15-CRIT-001 (2026-07-22): JIT SELFDESTRUCT is incomplete (missing
// EIP-6780 check, gas, balance transfer). JIT must NEVER run in production.
// These tests verify the defense-in-depth hard guard at the Execute()
// dispatch point blocks JIT when QAU_PRODUCTION=1, even if jitEnabled is
// somehow true.

func TestQVM_R15_CRIT_001_ProductionGuard_BlocksJIT(t *testing.T) {
	os.Setenv("QAU_PRODUCTION", "1")
	defer os.Unsetenv("QAU_PRODUCTION")

	executor := NewExecutorWithJIT()
	executor.enableJITForTesting() // bypass EnableJIT() checks

	if !executor.IsJITEnabled() {
		t.Fatal("JIT should be enabled for this test")
	}

	ctx := &ExecutionContext{
		Code: []byte{0x00}, // STOP
		Gas:  1000,
	}
	result := executor.Execute(ctx, nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Err == nil {
		t.Fatal("expected error for JIT in production mode")
	}
	if !strings.Contains(result.Err.Error(), "QVM-R15-CRIT-001") {
		t.Errorf("error should reference QVM-R15-CRIT-001, got: %v", result.Err)
	}
	if !strings.Contains(result.Err.Error(), "production") {
		t.Errorf("error should mention production mode, got: %v", result.Err)
	}
}

func TestQVM_R15_CRIT_001_NonProduction_AllowsJIT(t *testing.T) {
	// R31-HIGH-1: the dispatch gate now requires BOTH non-production mode
	// AND the explicit QAU_ENABLE_JIT=1 opt-in (same double gate as
	// EnableJIT). Non-production ALONE no longer allows JIT.
	os.Unsetenv("QAU_PRODUCTION")
	t.Setenv("QAU_ENABLE_JIT", "1")

	executor := NewExecutorWithJIT()
	executor.enableJITForTesting()

	if !executor.IsJITEnabled() {
		t.Fatal("JIT should be enabled for this test")
	}

	// Execute with nil stateDB will trigger panic recovery (QVM-R13-CRIT-001),
	// NOT the production guard. This proves the production guard didn't fire.
	ctx := &ExecutionContext{
		Code: []byte{0x00},
		Gas:  1000,
	}
	result := executor.Execute(ctx, nil)
	if result == nil || result.Err == nil {
		t.Fatal("expected error from JIT panic recovery, not nil")
	}
	// Should be a panic recovery error, NOT a production guard error.
	if strings.Contains(result.Err.Error(), "QVM-R15-CRIT-001") {
		t.Errorf("JIT should run in non-production mode, got production guard: %v", result.Err)
	}
}

func TestQVM_R15_CRIT_001_EnableJIT_BlockedInProduction(t *testing.T) {
	os.Setenv("QAU_PRODUCTION", "1")
	defer os.Unsetenv("QAU_PRODUCTION")

	executor := NewExecutorWithJIT()
	err := executor.EnableJIT()
	if err == nil {
		t.Fatal("EnableJIT should fail in production mode")
	}
	if !strings.Contains(err.Error(), "production") {
		t.Errorf("error should mention production, got: %v", err)
	}
	if executor.IsJITEnabled() {
		t.Error("JIT should remain disabled after failed EnableJIT")
	}
}

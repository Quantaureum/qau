// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// BRIDGE-R15-CRIT-001 (2026-07-22) regression tests: RefundFailedLock
// authorization. Previously RefundFailedLock had no caller authorization,
// so any RPC caller could trigger a refund on an arbitrary lockID. The
// fix introduces:
//   - SetAuthorizedOperators / IsAuthorizedOperator for operator management
//   - RefundFailedLockAuthorized (external, fail-closed when no operators)
//   - RefundFailedLock (internal/test wrapper, no auth check)
//
// These tests verify:
//  1. RefundFailedLockAuthorized rejects ALL callers when no operators are
//     configured (fail-closed).
//  2. RefundFailedLockAuthorized rejects callers not in the operator set.
//  3. RefundFailedLockAuthorized accepts callers in the operator set and
//     proceeds to the refund logic.
//  4. RefundFailedLock (legacy/internal) still works for unit tests and
//     the timeout watcher without requiring operators.
//  5. IsAuthorizedOperator returns false for everyone when unconfigured.
package bridge

import (
	"context"
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestBRIDGE_R15_CRIT_001_FailClosedWhenNoOperators verifies that
// RefundFailedLockAuthorized rejects every caller when
// SetAuthorizedOperators has not been called.
func TestBRIDGE_R15_CRIT_001_FailClosedWhenNoOperators(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	insertFailedLock(alm, "lock-fc-1", "source-chain", "target-chain",
		"mint submit failed: simulated (was Locked)")

	// No SetAuthorizedOperators call — fail-closed.
	caller := types.Address{0x01}
	err := alm.RefundFailedLockAuthorized(context.Background(), "lock-fc-1", caller)
	if !errors.Is(err, ErrUnauthorizedOperator) {
		t.Fatalf("expected ErrUnauthorizedOperator when no operators configured, got %v", err)
	}

	// Lock must remain in Failed status (refund did not proceed).
	lock, ok := alm.GetLock("lock-fc-1")
	if !ok || lock.Status != LockStatusFailed {
		t.Fatalf("lock should remain Failed after rejected auth, got ok=%v status=%d", ok, lock.Status)
	}
}

// TestBRIDGE_R15_CRIT_001_RejectsNonOperator verifies that after
// configuring operators, a caller NOT in the set is rejected.
func TestBRIDGE_R15_CRIT_001_RejectsNonOperator(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	attacker := types.Address{0xBB}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	insertFailedLock(alm, "lock-rej-1", "source-chain", "target-chain",
		"mint submit failed: simulated (was Locked)")

	err := alm.RefundFailedLockAuthorized(context.Background(), "lock-rej-1", attacker)
	if !errors.Is(err, ErrUnauthorizedOperator) {
		t.Fatalf("expected ErrUnauthorizedOperator for non-operator, got %v", err)
	}
}

// TestBRIDGE_R15_CRIT_001_AcceptsAuthorizedOperator verifies that an
// operator in the configured set is allowed through to the refund logic.
// We expect the refund to fail at bridge.SubmitMessage (fail-closed in
// tests without trusted validator keys) — but the error must NOT be
// ErrUnauthorizedOperator.
func TestBRIDGE_R15_CRIT_001_AcceptsAuthorizedOperator(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op})

	insertFailedLock(alm, "lock-ok-1", "source-chain", "target-chain",
		"mint submit failed: simulated (was Locked)")

	err := alm.RefundFailedLockAuthorized(context.Background(), "lock-ok-1", op)
	// The refund should NOT be rejected for authorization reasons.
	if errors.Is(err, ErrUnauthorizedOperator) {
		t.Fatalf("authorized operator was rejected: %v", err)
	}
	// It MAY fail at bridge.SubmitMessage (fail-closed without trusted
	// keys) — that's expected and proves the auth check passed.
	if err == nil {
		// If it somehow succeeded, the lock must have transitioned.
		lock, ok := alm.GetLock("lock-ok-1")
		if !ok || lock.Status != LockStatusRefunded {
			t.Fatalf("on success, lock should be Refunded, got ok=%v status=%d", ok, lock.Status)
		}
	}
}

// TestBRIDGE_R15_CRIT_001_LegacyRefundFailedLockStillWorks verifies that
// the unexported/internal refundFailedLockLegacy entry point still functions
// (used by timeout watcher and unit tests) without requiring operators.
func TestBRIDGE_R15_CRIT_001_LegacyRefundFailedLockStillWorks(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	// Deliberately do NOT call SetAuthorizedOperators.
	insertFailedLock(alm, "lock-leg-1", "source-chain", "target-chain",
		"mint submit failed: simulated (was Locked)")

	// refundFailedLockLegacy (internal) should still be callable. We expect it
	// to fail at bridge.SubmitMessage (no trusted keys), but NOT at the
	// authorization check (there is none on the internal path).
	err := alm.refundFailedLockLegacy(context.Background(), "lock-leg-1")
	if errors.Is(err, ErrUnauthorizedOperator) {
		t.Fatalf("internal refundFailedLockLegacy must not perform auth check, got %v", err)
	}
}

// TestBRIDGE_R15_CRIT_001_IsAuthorizedOperator verifies the helper:
//   - returns false for everyone when unconfigured
//   - returns true only for configured operators
func TestBRIDGE_R15_CRIT_001_IsAuthorizedOperator(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	other := types.Address{0xBB}

	if alm.IsAuthorizedOperator(op) {
		t.Error("expected false when no operators configured")
	}
	if alm.IsAuthorizedOperator(other) {
		t.Error("expected false when no operators configured")
	}

	alm.setAuthorizedOperatorsForTest([]types.Address{op})
	if !alm.IsAuthorizedOperator(op) {
		t.Error("expected true for configured operator")
	}
	if alm.IsAuthorizedOperator(other) {
		t.Error("expected false for non-operator")
	}
}

// TestBRIDGE_R15_CRIT_001_SetAuthorizedOperatorsDedupes verifies that
// passing duplicate addresses to SetAuthorizedOperators is safe.
func TestBRIDGE_R15_CRIT_001_SetAuthorizedOperatorsDedupes(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	op := types.Address{0xAA}
	alm.setAuthorizedOperatorsForTest([]types.Address{op, op, op})
	if !alm.IsAuthorizedOperator(op) {
		t.Error("expected true for configured operator after dedup")
	}
}

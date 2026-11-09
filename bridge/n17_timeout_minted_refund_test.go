// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// AUDIT N-17 (2026-11-06): the timeout watcher used to render the failed
// status numerically ("in status 2"). The BRIDGE-H06 burn-proof gate only
// matched the literal "Minted" hint, so a timed-out lock that had already
// minted the wrapped asset on the target chain was auto-refunded without a
// burn proof — a double-spend. These tests pin the symbolic reason rendering
// and the structural (MintedAt / MintTxHash) gate.
package bridge

import (
	"context"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// insertStatusLock inserts a lock in a non-Failed status with an entry
// timestamp old enough to be considered stale by scanStaleLocks.
func insertStatusLock(alm *AssetLockManager, id string, source, target ChainID, status LockStatus, minted bool) *AssetLock {
	now := time.Now().Unix()
	old := now - int64((3*time.Hour)/time.Second)
	lock := &AssetLock{
		ID:           id,
		SourceChain:  source,
		TargetChain:  target,
		AssetType:    AssetTypeQRC20,
		TokenAddress: types.Address{0x11},
		Amount:       bigNewInt(1000),
		Owner:        types.Address{0xAA},
		Recipient:    types.Address{0xBB},
		Status:       status,
		LockTxHash:   "0xn17lock",
		CreatedAt:    old,
		LockedAt:     old,
	}
	if minted {
		lock.MintedAt = old
		lock.MintTxHash = "0xn17minthash"
	}

	alm.mu.Lock()
	defer alm.mu.Unlock()
	alm.locks[id] = lock
	alm.locksByOwner[lock.Owner] = append(alm.locksByOwner[lock.Owner], id)
	if alm.locksByStatus[status] == nil {
		alm.locksByStatus[status] = make(map[string]bool)
	}
	alm.locksByStatus[status][id] = true
	return lock
}

// TestN17_TimeoutMintedLockRendersSymbolicStatusAndRequiresBurnProof pins the
// whole regression: timeout → Failed, reason carries "Minted", refund refused.
func TestN17_TimeoutMintedLockRendersSymbolicStatusAndRequiresBurnProof(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	if err := alm.SetLockTimeout(1 * time.Hour); err != nil {
		t.Fatalf("SetLockTimeout: %v", err)
	}

	insertStatusLock(alm, "lock-n17-timeout", "source-chain", "target-chain", LockStatusMinted, true)

	alm.scanStaleLocks()

	updated, ok := alm.GetLock("lock-n17-timeout")
	if !ok {
		t.Fatal("lock disappeared after timeout scan")
	}
	if updated.Status != LockStatusFailed {
		t.Fatalf("stale minted lock must become Failed, got %d", updated.Status)
	}

	err := alm.refundFailedLockLegacy(context.Background(), "lock-n17-timeout")
	if err == nil {
		t.Fatal("N-17 regression: a timed-out minted lock was refunded without a burn proof")
	}
	if !containsStr(err.Error(), "Minted status") && !containsStr(err.Error(), "burn proof") {
		t.Fatalf("expected the burn-proof rejection, got: %v", err)
	}
	if updated.Status != LockStatusFailed {
		t.Fatalf("lock must stay Failed after the rejected refund, got %d", updated.Status)
	}
}

// TestN17_StructuralMintEvidenceIgnoresReasonFormatting proves the gate no
// longer depends on the reason string at all: the exact pre-fix numeric
// rendering ("in status 2") no longer bypasses the burn-proof requirement.
func TestN17_StructuralMintEvidenceIgnoresReasonFormatting(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	lock := insertFailedLock(alm, "lock-n17-numeric",
		"source-chain", "target-chain",
		"timeout after 24h0m0s in status 2 (entered at 1, now 2)")

	// Structural mint evidence: the lock actually minted before failing.
	lock.MintedAt = time.Now().Unix()
	lock.MintTxHash = "0xn17minthash"

	err := alm.refundFailedLockLegacy(context.Background(), "lock-n17-numeric")
	if err == nil {
		t.Fatal("N-17 regression: numeric status rendering bypassed the burn-proof gate")
	}
	if !containsStr(err.Error(), "burn proof") {
		t.Fatalf("expected the burn-proof rejection, got: %v", err)
	}
}

// TestN17_LockedTimeoutLockStillRefundableWithoutBurnProof guards against
// over-blocking: a lock that never minted stays refundable without a proof.
func TestN17_LockedTimeoutLockStillRefundableWithoutBurnProof(t *testing.T) {
	b, alm := setupBridgeWithAdapters(t)
	defer b.Stop(context.Background())

	if err := alm.SetLockTimeout(1 * time.Hour); err != nil {
		t.Fatalf("SetLockTimeout: %v", err)
	}

	insertStatusLock(alm, "lock-n17-locked", "source-chain", "target-chain", LockStatusLocked, false)

	alm.scanStaleLocks()

	updated, ok := alm.GetLock("lock-n17-locked")
	if !ok || updated.Status != LockStatusFailed {
		t.Fatalf("stale Locked lock must become Failed, got ok=%v", ok)
	}
	if updated.wasMinted() {
		t.Fatal("test setup error: lock must not carry mint evidence")
	}

	err := alm.refundFailedLockLegacy(context.Background(), "lock-n17-locked")
	// The refund may still fail at SubmitMessage (fail-closed without trusted
	// validator keys), but it must NOT be rejected for burn-proof reasons.
	if err != nil {
		if containsStr(err.Error(), "burn proof") || containsStr(err.Error(), "Minted status") {
			t.Fatalf("over-block: never-minted lock must not require a burn proof, got: %v", err)
		}
	}
}

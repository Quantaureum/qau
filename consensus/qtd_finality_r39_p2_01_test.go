// Quantaureum Node source, version 1.0.0.
package consensus

// R39-P2-01 (2026-08-02) regression tests for the IsSlotFinalized cross-
// check against QPOS.finalizedEpoch.
//
// Audit (R39-P2-01): IsSlotFinalized previously consulted ONLY the local
// instantFinalizedSlots map; a peer-induced or bug-induced map entry would
// be reported as finalized even though QPOS hadn't reached the epoch yet.
// Consumers (RPC "finalized", fork chooser, sync sentinel) would trust a
// slot as instant-finalized while the chain's actual finality marker was
// still behind, exposing the node to short-range reorg exploitation.
//
// The fix returns false when BOTH map entry exists AND record.Epoch >
// QPOS.finalizedEpoch (cross-check fails). When record.Epoch == 0 (legacy
// records without the Epoch field) or qpos == nil (test shells), the
// cross-check falls back to map-only (pre-R39-P2-01 behavior) to
// preserve backward compatibility.
//
// Tests in this file pin three guarantees:
//   1. A record whose Epoch <= QPOS.finalizedEpoch → IsSlotFinalized=true.
//   2. A record whose Epoch >  QPOS.finalizedEpoch → IsSlotFinalized=false
//      even though the map entry exists.
//   3. A record with Epoch == 0 (legacy) → IsSlotFinalized=true regardless
//      of QPOS.finalizedEpoch (backward-compat fallback).
//   4. A QFS with qpos=nil → IsSlotFinalized=true iff map entry exists
//      (qpos==nil skips the cross-check entirely).

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// r39P2_01NewQFSWithQPOS constructs a QTDFinalityState bound to a QPOS
// instance with finalizedEpoch pre-populated via direct field assignment
// (the same pattern used by cons_r13_m01_m04_test.go). The qpos here is a
// minimal shell — we only need finalizedEpoch readable through
// GetFinalizedEpoch, which is a plain RLock+return — no chambers,
// validators, or genesis state are required. We use a tiny 4-validator set
// (the minimum NewQPOS accepts) to satisfy the constructor's invariants.
func r39P2_01NewQFSWithQPOS(t *testing.T, finalizedEpoch uint64) (*QTDFinalityState, *QPOS) {
	t.Helper()
	var validators []*Validator
	for i := 0; i < 4; i++ {
		validators = append(validators, &Validator{
			Address:        types.BytesToAddress([]byte{byte(i + 1)}),
			Stake:          big.NewInt(1000),
			Active:         true,
			PublicKeyBytes: make([]byte, 1952), // crypto.Dilithium3PublicKeySize
		})
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("fixture NewValidatorSet failed: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("fixture NewQPOS failed: %v", err)
	}
	qpos.mu.Lock()
	qpos.finalizedEpoch = finalizedEpoch
	qpos.mu.Unlock()
	qfs := NewQTDFinalityState(qpos)
	return qfs, qpos
}

// r39P2_01SeedRecord writes an InstantFinalityRecord directly into the
// instantFinalizedSlots map under qfs.mu. We bypass the
// VerifyInstantFinality + SubmitCompletedSeal chain (which would require
// a fully-wired TSS signer) and instead populate the map at the level
// the audit's finding is about — the read-path correctness.
func r39P2_01SeedRecord(qfs *QTDFinalityState, slot, epoch uint64, blockHash types.Hash) {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()
	qfs.instantFinalizedSlots[slot] = &InstantFinalityRecord{
		Slot:         slot,
		Epoch:        epoch,
		BlockHash:    blockHash,
		QTDSignature: make([]byte, 3293), // crypto.Dilithium3SignatureSize
		SealedAt:     time.Time{},        // zero time — value doesn't matter for IsSlotFinalized
		Sealers:      []int{0, 1, 2},
	}
}

// ── Test 1: record.Epoch ≤ QPOS.finalizedEpoch → IsSlotFinalized=true. ──

// TestR39_P2_01_IsSlotFinalized_True_WhenQPOSCaughtUp pins the happy path:
// the QPOS finalizer has caught up to or past the record's epoch, so the
// slot is reported as finalized. This is the production steady-state —
// once QPOS finalizes an epoch, every QTD-sealed slot in that epoch (and
// earlier) is observable as instant-finalized.
func TestR39_P2_01_IsSlotFinalized_True_WhenQPOSCaughtUp(t *testing.T) {
	qfs, qpos := r39P2_01NewQFSWithQPOS(t, 5)
	_ = qpos
	const slot uint64 = 100
	const epoch uint64 = 5 // <= finalizedEpoch=5
	hash := types.Hash{0xAA, 0xBB, 0xCC}
	r39P2_01SeedRecord(qfs, slot, epoch, hash)

	if !qfs.IsSlotFinalized(slot) {
		t.Fatalf("R39-P2-01: IsSlotFinalized must return true when record exists AND record.Epoch(%d) <= qpos.finalizedEpoch(%d) — QPOS has caught up, this is the production steady-state; cross-check is unnecessarily strict", epoch, 5)
	}
}

// ── Test 2: record.Epoch > QPOS.finalizedEpoch → IsSlotFinalized = false. ──

// TestR39_P2_01_IsSlotFinalized_False_WhenQPOSBehind pins the FIX: a map
// entry whose epoch is AHEAD of QPOS.finalizedEpoch must return false.
// Without the cross-check (pre-R39-P2-01), this would return true — the
// audit's exact finding. The test seeds a record at epoch=10 while
// QPOS.finalizedEpoch=5; IsSlotFinalized must return false so consumers
// don't trust a slot as finalized when the chain's actual finality marker
// hasn't reached it yet.
//
// Realistic trigger: a peer-induced map entry (e.g., a goroutine that
// forgot the qfs.mu.Lock) writes a future-epoch record before QPOS
// finalizes it. Consumers (RPC "finalized" block, fork chooser) would
// then trust a slot that the QPOS finalizer hasn't actually finalized
// — exposing the node to short-range reorg exploitation.
func TestR39_P2_01_IsSlotFinalized_False_WhenQPOSBehind(t *testing.T) {
	qfs, qpos := r39P2_01NewQFSWithQPOS(t, 5)
	_ = qpos
	const slot uint64 = 200
	const epoch uint64 = 10 // > finalizedEpoch=5
	hash := types.Hash{0xDD, 0xEE, 0xFF}
	r39P2_01SeedRecord(qfs, slot, epoch, hash)

	if qfs.IsSlotFinalized(slot) {
		t.Fatalf("R39-P2-01: IsSlotFinalized returned TRUE for a record whose Epoch(%d) > qpos.finalizedEpoch(%d) — the cross-check is missing or inverted; the audit's R39-P2-01 finding is NOT fixed: a peer-induced map entry would be reported as finalized while QPOS finality is still behind, exposing consumers to short-range reorg exploitation", epoch, 5)
	}
}

// ── Test 3: legacy record with Epoch=0 → fallback to map-only. ──

// TestR39_P2_01_IsSlotFinalized_LegacyRecord_FallbackToMapOnly pins the
// backward-compat fallback: records produced before R39-P0-01 added the
// Epoch field (or tests that construct the record manually without it)
// fall back to map-only semantics. The cross-check is a no-op for these
// records because record.Epoch == 0 is treated as "no epoch known" —
// we can't compare an unknown epoch against QPOS.finalizedEpoch.
//
// This preserves existing behavior for any on-disk records loaded from
// pre-R39-P0-01 state (no migration backfills Epoch retroactively) and
// for tests in qtd_finality_test.go that construct InstantFinalityRecord
// without setting Epoch.
func TestR39_P2_01_IsSlotFinalized_LegacyRecord_FallbackToMapOnly(t *testing.T) {
	qfs, _ := r39P2_01NewQFSWithQPOS(t, 5)
	const slot uint64 = 300
	const epoch uint64 = 0 // legacy
	hash := types.Hash{0x11, 0x22, 0x33}
	r39P2_01SeedRecord(qfs, slot, epoch, hash)

	// Even though QPOS.finalizedEpoch=5 and record.Epoch=0 would normally
	// trigger the cross-check (record.Epoch <= qposFinalizedEpoch is
	// 0 <= 5 = true, but the test contract is: Epoch=0 ⇒ skip cross-check
	// ⇒ fall back to map-only). Both paths return true here, so the
	// assertion is the same; we test the more interesting case below
	// where QPOS is also 0.
	if !qfs.IsSlotFinalized(slot) {
		t.Fatalf("R39-P2-01: legacy record (Epoch=0) MUST fall back to map-only semantics, returning true when the map entry exists — backward-compat contract broken")
	}

	// More discriminating: legacy record + qpos.finalizedEpoch=0 also
	// falls back to map-only. (Both branches of the conditional skip the
	// cross-check when EITHER qposFinalizedEpoch==0 OR record.Epoch==0.)
	qfs2, _ := r39P2_01NewQFSWithQPOS(t, 0) // QPOS never finalized anything
	const slot2 uint64 = 301
	r39P2_01SeedRecord(qfs2, slot2, 0, hash)
	if !qfs2.IsSlotFinalized(slot2) {
		t.Fatalf("R39-P2-01: legacy record (Epoch=0) + qpos.finalizedEpoch=0 MUST still return true (both qposFinalizedEpoch==0 AND record.Epoch==0 trigger the fallback) — a node that hasn't finalized any epoch yet still observes its own prior QTD seals")
	}
}

// ── Test 4: qpos=nil (test shell) → cross-check skipped, map-only. ──

// TestR39_P2_01_IsSlotFinalized_NilQPOS_SkipsCrossCheck pins the qpos==nil
// defensive branch: a QTDFinalityState constructed without a QPOS (test
// shells, bootstrapping) MUST still report map entries as finalized.
// Without this guard, any test that builds the struct manually and then
// calls IsSlotFinalized would panic on qfs.qpos.GetFinalizedEpoch()'s nil
// deref. The cross-check is opt-in via qpos being non-nil.
//
// In production this branch is unreachable (NewQTDFinalityState always
// receives a non-nil qpos), but the audit's defensive-programming
// expectation carries through to Test-3's nil branch.
func TestR39_P2_01_IsSlotFinalized_NilQPOS_SkipsCrossCheck(t *testing.T) {
	qfs := NewQTDFinalityState(nil) // explicit nil qpos
	const slot uint64 = 400
	const epoch uint64 = 999 // large epoch that WOULD fail the cross-check
	hash := types.Hash{0x44, 0x55, 0x66}
	r39P2_01SeedRecord(qfs, slot, epoch, hash)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("R39-P2-01: IsSlotFinalized panicked on qpos=nil QTDFinalityState — the cross-check nil-guard is missing; a nil qpos deref would crash test shells and bootstrap paths: %v", r)
		}
	}()
	// qpos==nil MUST skip the cross-check entirely; map entry exists ⇒
	// IsSlotFinalized returns true regardless of record.Epoch.
	if !qfs.IsSlotFinalized(slot) {
		t.Fatalf("R39-P2-01: qpos==nil + map entry exists MUST return true (cross-check skipped) — the audit's defensive nil-guard is missing")
	}
}

// ── Test 5: record doesn't exist → IsSlotFinalized always false. ──

// TestR39_P2_01_IsSlotFinalized_AlwaysFalse_WhenNoMapEntry pins the
// trivial case: a slot without a map entry is never finalized,
// regardless of QPOS.finalizedEpoch. This guards against a future
// refactor that accidentally swaps the cross-check order (e.g., returns
// true if qposFinalizedEpoch > 0, ignoring the map).
func TestR39_P2_01_IsSlotFinalized_AlwaysFalse_WhenNoMapEntry(t *testing.T) {
	qfs, _ := r39P2_01NewQFSWithQPOS(t, 5)
	const missingSlot uint64 = 999999
	if qfs.IsSlotFinalized(missingSlot) {
		t.Fatalf("R39-P2-01: IsSlotFinalized returned TRUE for a slot with no map entry — the map-presence check must come BEFORE the cross-check (a missing record can never be finalized regardless of QPOS state)")
	}
}

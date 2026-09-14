// Quantaureum Node source, version 1.0.0.
package rollup

// R39-P2-06 (2026-08-02) regression tests for the sequencer-elector
// liveness gate's batch-info completeness invariant.
//
// Audit finding (R39-P2-06): "the liveness gate update path did not carry batch
// completeness" — the previous RecordBatchReceivedFromCurrentSequencer
// took no arguments. A malicious attacker controlling the caller
// could feed evidence-less liveness ticks to keep the gate
// permanently open (suppressing legitimate failover) indefinitely,
// even when no real batch was produced. The fix requires the caller
// to supply the batch's fingerprint (batchHash + postStateRoot) and
// rejects (silently no-ops) calls where either is the zero hash.
//
// Tests in this file pin four guarantees:
//   1. RecordBatchReceivedFromCurrentSequencer REJECTS (no-op) when
//      batchHash is zero — fail-closed per the audit.
//   2. RecordBatchReceivedFromCurrentSequencer REJECTS (no-op) when
//      postStateRoot is zero.
//   3. RecordBatchReceivedFromCurrentSequencer ACCEPTS when both
//      are non-zero — gate updates as expected.
//   4. On accept, lastObservedBatchEvidence stores the batchHash so
//      post-failover auditors can verify what the gate last saw.

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// r39P2_06_newEngineWithElector builds a minimal rollup engine with a
// mock sequencer elector configured, ready for liveness-gate tests.
// Helper shared by all 4 tests below.
func r39P2_06_newEngineWithElector(t *testing.T) *RollupEngine {
	t.Helper()
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 50 * time.Millisecond
	cfg.SequencerTimeout = 3
	cfg.MinTxPerBatch = 1

	localAddr := types.Address{0xAA}
	currentSeq := types.Address{0xBB}
	elector := &mockSequencerElector{
		current: currentSeq,
		next:    localAddr,
	}

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}
	engine.SetSequencerElector(elector)
	engine.SetLocalAddress(localAddr)
	return engine
}

// ── Test 1: zero batchHash → gate does NOT update (fail-closed). ──

// TestR39_P2_06_ZeroBatchHash_RejectsLivenessUpdate pins the audit's
// primary fail-closed invariant: when RecordBatchReceivedFromCurrentSequencer
// is called with a zero batchHash, the method MUST silently no-op
// (gate stays at zero observation time; failover remains eligible
// after the silence window). Without this rejection, an attacker
// controlling the caller could supply only the zero batchHash and
// keep the gate open without ever producing a real batch.
//
// The contract: zero batchHash → no state mutation; specifically,
// lastObservedBatchTime stays zero (its initial value) AND
// missedBatchCount stays zero (its initial value) AND the new
// lastObservedBatchEvidence stays zero (the audit-added forensics
// field).
func TestR39_P2_06_ZeroBatchHash_RejectsLivenessUpdate(t *testing.T) {
	engine := r39P2_06_newEngineWithElector(t)

	// Sanity: precondition — lastObservedBatchTime is zero.
	engine.mu.RLock()
	preTime := engine.lastObservedBatchTime
	engine.mu.RUnlock()
	if !preTime.IsZero() {
		t.Fatalf("R39-P2-06: precondition — lastObservedBatchTime should start zero, got %v", preTime)
	}

	var zeroHash types.Hash
	validPostRoot := types.Hash{0x50, 0x14} // non-zero post-state-root

	// Call with zero batchHash — MUST be a no-op per the audit's
	// fail-closed invariant.
	engine.RecordBatchReceivedFromCurrentSequencer(zeroHash, validPostRoot)

	engine.mu.RLock()
	postTime := engine.lastObservedBatchTime
	postEvidence := engine.lastObservedBatchEvidence
	postMissed := engine.missedBatchCount
	engine.mu.RUnlock()

	if !postTime.IsZero() {
		t.Fatalf("R39-P2-06: RecordBatchReceivedFromCurrentSequencer(zero batchHash, ...) updated lastObservedBatchTime to %v — fail-closed invariant broken; an attacker could feed evidence-less liveness ticks to keep the gate open", postTime)
	}
	if postEvidence != (types.Hash{}) {
		t.Fatalf("R39-P2-06: lastObservedBatchEvidence = %x after zero-batchHash call; MUST remain zero (the audit's forensics field must reflect that NO valid batch was attested)", postEvidence)
	}
	if postMissed != 0 {
		t.Fatalf("R39-P2-06: missedBatchCount = %d after zero-batchHash call; MUST remain 0 (no liveness event should reset the missed counter)", postMissed)
	}
}

// ── Test 2: zero postStateRoot → gate does NOT update (fail-closed). ──

// TestR39_P2_06_ZeroPostStateRoot_RejectsLivenessUpdate pins the
// symmetric case: when postStateRoot is zero, the gate MUST reject.
// The audit's intent is "batch info completeness" — both components of the
// fingerprint must be present.
func TestR39_P2_06_ZeroPostStateRoot_RejectsLivenessUpdate(t *testing.T) {
	engine := r39P2_06_newEngineWithElector(t)

	var zeroHash types.Hash
	validBatchHash := types.Hash{0x38, 0x14}

	engine.RecordBatchReceivedFromCurrentSequencer(validBatchHash, zeroHash)

	engine.mu.RLock()
	postTime := engine.lastObservedBatchTime
	postEvidence := engine.lastObservedBatchEvidence
	postMissed := engine.missedBatchCount
	engine.mu.RUnlock()

	if !postTime.IsZero() {
		t.Fatalf("R39-P2-06: zero postStateRoot updated lastObservedBatchTime to %v; fail-closed invariant broken on the postStateRoot axis — the audit's batch-info completeness check requires BOTH components non-zero", postTime)
	}
	if postEvidence != (types.Hash{}) {
		t.Fatalf("R39-P2-06: lastObservedBatchEvidence = %x after zero-postStateRoot call; MUST remain zero", postEvidence)
	}
	if postMissed != 0 {
		t.Fatalf("R39-P2-06: missedBatchCount = %d after zero-postStateRoot call; MUST remain 0", postMissed)
	}
}

// ── Test 3: both non-zero → gate UPDATES (happy path). ──

// TestR39_P2_06_BothNonZero_AcceptsLivenessUpdate pins the happy path:
// when both batchHash and postStateRoot are non-zero, the gate MUST
// update — lastObservedBatchTime is set to now, missedBatchCount is
// reset to 0, and lastObservedBatchEvidence stores the batchHash.
//
// This test guards against over-failure: a future refactor that
// always-rejects (regression to fail-toomuch-closed) would break
// legitimate failover suppression.
func TestR39_P2_06_BothNonZero_AcceptsLivenessUpdate(t *testing.T) {
	engine := r39P2_06_newEngineWithElector(t)

	validBatchHash := types.Hash{0x38, 0x14}
	validPostRoot := types.Hash{0x50, 0x14}

	before := time.Now()
	engine.RecordBatchReceivedFromCurrentSequencer(validBatchHash, validPostRoot)
	after := time.Now()

	engine.mu.RLock()
	postTime := engine.lastObservedBatchTime
	postEvidence := engine.lastObservedBatchEvidence
	postMissed := engine.missedBatchCount
	engine.mu.RUnlock()

	if postTime.IsZero() {
		t.Fatalf("R39-P2-06: lastObservedBatchTime stayed zero after valid (non-zero) batchHash + postStateRoot call — happy path is broken; the audit's completeness check over-rejects")
	}
	if postTime.Before(before) || postTime.After(after.Add(time.Millisecond)) {
		t.Fatalf("R39-P2-06: lastObservedBatchTime = %v, expected to be within (%v, %v) — gate clock did not update to wall-time now", postTime, before, after)
	}
	if postEvidence != validBatchHash {
		t.Fatalf("R39-P2-06: lastObservedBatchEvidence = %x, want %x — the audit-added forensics field MUST store the attested batchHash on accept", postEvidence, validBatchHash)
	}
	if postMissed != 0 {
		t.Fatalf("R39-P2-06: missedBatchCount = %d after valid liveness update; MUST be reset to 0 (a real batch observation is the strongest possible liveness signal)", postMissed)
	}
}

// ── Test 4: evid koherence — lastObservedBatchEvidence tracks the LAST accepted batch. ──

// TestR39_P2_06_Evidence_TracksLastAcceptedBatch pins the forensics
// contract: when multiple valid batches are observed in sequence,
// lastObservedBatchEvidence reflects the LAST one (not the first).
// Without this, a post-failover auditor inspecting the field could
// mis-attribute the gate's preceding evidence to an older batch.
//
// Fixture: two valid liveness updates with different batchHashes.
// lastObservedBatchEvidence must equal the SECOND batchHash.
func TestR39_P2_06_Evidence_TracksLastAcceptedBatch(t *testing.T) {
	engine := r39P2_06_newEngineWithElector(t)

	validPostRoot := types.Hash{0x50, 0x14}
	batch1 := types.Hash{0x11, 0x22}
	batch2 := types.Hash{0x33, 0x44}

	engine.RecordBatchReceivedFromCurrentSequencer(batch1, validPostRoot)
	engine.mu.RLock()
	e1 := engine.lastObservedBatchEvidence
	engine.mu.RUnlock()
	if e1 != batch1 {
		t.Fatalf("R39-P2-06: after 1st valid update, evidence = %x, want %x (1st batch)", e1, batch1)
	}

	engine.RecordBatchReceivedFromCurrentSequencer(batch2, validPostRoot)
	engine.mu.RLock()
	e2 := engine.lastObservedBatchEvidence
	engine.mu.RUnlock()
	if e2 != batch2 {
		t.Fatalf("R39-P2-06: after 2nd valid update, evidence = %x, want %x (2nd batch — forensics field MUST track the LAST accepted, not the FIRST)", e2, batch2)
	}

	// Audit-injected zero-hash rejection MUST NOT mutate the evidence
	// — the audit's completeness invariant: rejected calls don't
	// touch forensics.
	var zeroHash types.Hash
	engine.RecordBatchReceivedFromCurrentSequencer(zeroHash, validPostRoot)
	engine.mu.RLock()
	e3 := engine.lastObservedBatchEvidence
	engine.mu.RUnlock()
	if e3 != batch2 {
		t.Fatalf("R39-P2-06: after a rejected (zero batchHash) call, evidence = %x, want %x (forensics field MUST NOT mutate on rejected calls)", e3, batch2)
	}
}

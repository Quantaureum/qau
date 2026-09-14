// Quantaureum Node source, version 1.0.0.
package rollup

// R38-P1-14 — sequencer liveness observation wiring regression tests.
//
// Audit R38-P1-14 found that RollupEngine.RecordBatchReceivedFromCurrentSequencer
// (sequencer_elector.go:355) had ZERO production call-sites: the only caller
// was a test setup in r36_rollup_p1_test.go:160. Consequently
// lastObservedBatchTime stayed at the zero value forever, so the
// P1-ROLLUP-02 failover safety gate in shouldBuildBatch
// (sequencer_elector.go:448: !lastObserved.IsZero() ...) was effectively
// dead in production — every non-sequencer node would take over after
// SequencerTimeout ticks even when the current sequencer was healthy.
//
// FIX: the batchLoop success path (rollup.go tryBuildAndSubmitBatch, right
// after the successful anchorBatch) now calls
// engine.RecordBatchReceivedFromCurrentSequencer(). Producing (and, when
// L1 anchoring is configured, committing) a batch is the strongest
// liveness signal available inside this single-node batchLoop. In a
// future P2P-gossip wiring, the same hook is the entry point other nodes
// would call when observing the current sequencer's batch.
//
// These tests pin the wiring so a regression (the call being removed or
// moved out of the success path) is caught immediately.

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestR38P1_14_RecordBatchReceived_ProductionWiring verifies that the
// production batchLoop success path (tryBuildAndSubmitBatch, when this
// node is the current sequencer and successfully builds + submits +
// anchors a batch) actually invokes RecordBatchReceivedFromCurrentSequencer,
// advancing lastObservedBatchTime off the zero value and resetting
// missedBatchCount. Without the R38-P1-14 wiring, lastObservedBatchTime
// would remain zero forever and the P1-ROLLUP-02 failover gate would be
// dead in production.
//
// R38-P1-14 FIX (2026-08-01)
func TestR38P1_14_RecordBatchReceived_ProductionWiring(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 50 * time.Millisecond
	cfg.SequencerTimeout = 3
	cfg.MinTxPerBatch = 1

	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine: %v", err)
	}
	engine.SetSequencerElector(elector)
	engine.SetRequireTxSig(false)

	// Make THIS node the current epoch's sequencer so shouldBuildBatch
	// returns true and tryBuildAndSubmitBatch actually produces a batch.
	currentIdx := computeSequencerIndex(0, provider.seed, len(addrs))
	engine.SetLocalAddress(addrs[currentIdx])

	// Fund the sender so ProcessBatch does not reject the tx.
	sender := types.Address{0xaa}
	sm := engine.GetStateManager()
	sm.mu.Lock()
	sm.accountStates[sender] = &RollupAccount{Balance: big.NewInt(1_000_000)}
	engine.GetBatchManager().lastStateRoot = sm.computeStateRoot()
	sm.mu.Unlock()

	// Pre-condition: before any batch is produced, lastObservedBatchTime
	// MUST be the zero value — this is the very bug R38-P1-14 fixes (the
	// gate is dead when this stays zero forever in production).
	engine.mu.RLock()
	preObserved := engine.lastObservedBatchTime
	engine.mu.RUnlock()
	if !preObserved.IsZero() {
		t.Fatalf("pre-condition: expected zero lastObservedBatchTime on a fresh engine, got %v", preObserved)
	}

	// Put the engine in Running WITHOUT calling Start() so the background
	// batchLoop goroutine does not race our manual tryBuildAndSubmitBatch.
	engine.mu.Lock()
	engine.status = RollupStatusRunning
	engine.mu.Unlock()

	// Submit one tx and trigger the same code path the production
	// batchLoop runs each tick.
	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     sender,
		ChainID:  cfg.ChainID,
	}
	if err := engine.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction: %v", err)
	}
	engine.tryBuildAndSubmitBatch()

	// A batch MUST have been produced — otherwise the wiring is untested
	// (a no-op build path cannot exercise RecordBatchReceivedFromCurrentSequencer).
	totalBatches, _, _ := engine.GetStats()
	if totalBatches != 1 {
		t.Fatalf("R38-P1-14: expected 1 batch produced to exercise the wiring, got %d (build path did not succeed — wiring untested)", totalBatches)
	}

	// CORE ASSERTION: the production batchLoop success path MUST have
	// invoked RecordBatchReceivedFromCurrentSequencer, advancing
	// lastObservedBatchTime off the zero value. If this is still zero,
	// the R38-P1-14 wiring was removed / moved out of the success path
	// and the P1-ROLLUP-02 failover gate is dead in production again.
	engine.mu.RLock()
	postObserved := engine.lastObservedBatchTime
	missed := engine.missedBatchCount
	engine.mu.RUnlock()
	if postObserved.IsZero() {
		t.Fatal("R38-P1-14 REGRESSION: lastObservedBatchTime is still zero after a successful batch build+submit — RecordBatchReceivedFromCurrentSequencer was NOT wired into the production success path; P1-ROLLUP-02 failover gate is dead in production")
	}
	// RecordBatchReceivedFromCurrentSequencer also resets missedBatchCount
	// (it is the strongest liveness signal, strictly stronger than the
	// tick counter). Pin this so a future refactor does not regress it.
	if missed != 0 {
		t.Errorf("R38-P1-14: expected missedBatchCount reset to 0 by RecordBatchReceivedFromCurrentSequencer, got %d", missed)
	}
}

// TestR38P1_14_FailoverGateAliveAfterWiring verifies that, with the R38-P1-14
// wiring in place, the P1-ROLLUP-02 failover gate actually becomes live:
// when this node is NOT the current sequencer but produces a batch (a
// simulation of receiving/observing a batch — same hook), the gate then
// SUPPRESSES a spurious failover even though missedBatchCount exceeds
// SequencerTimeout. This is the integrated end-to-end safety property
// that the bug made unreachable in production.
//
// R38-P1-14 FIX (2026-08-01). Builds on R36-P1-ROLLUP-02 (2026-07-30).
func TestR38P1_14_FailoverGateAliveAfterWiring(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 50 * time.Millisecond
	cfg.SequencerTimeout = 3
	cfg.MinTxPerBatch = 1

	localAddr := types.Address{0xAA}
	currentSeq := types.Address{0xBB}
	// localAddr is the NEXT sequencer so it is eligible for takeover — the
	// only thing stopping a spurious failover is the observation gate.
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

	// Fund localAddr so a build attempt would succeed if the (suppressed)
	// failover ever fired — this makes a regression produce a real batch
	// rather than failing for the wrong reason.
	sm := engine.GetStateManager()
	sm.getOrCreateAccount(localAddr)
	sm.accountStates[localAddr].Balance = new(big.Int).SetInt64(1_000_000)
	preRoot := sm.computeStateRoot()
	engine.GetBatchManager().RestoreMeta(0, preRoot)

	// Prime lastSequencerAddr=currentSeq via one shouldBuildBatch call so
	// the later missedBatchCount increments are not wiped by the
	// "sequencer changed" reset path. (Mirrors the R36 test setup.)
	if engine.shouldBuildBatch() {
		t.Fatal("setup sanity: shouldBuildBatch must be false with missedBatchCount=0 and local != current")
	}
	engine.mu.RLock()
	lastSeq := engine.lastSequencerAddr
	engine.mu.RUnlock()
	if lastSeq != currentSeq {
		t.Fatalf("setup sanity: lastSequencerAddr=%x, want %x", lastSeq, currentSeq)
	}

	// Simulate the R38-P1-14 wiring firing: this node observed the current
	// sequencer produce a batch (in a real system this is the P2P gossip
	// hook; the production batchLoop success path calls the same method
	// when this node IS the sequencer). After this, lastObservedBatchTime
	// is non-zero and the P1-ROLLUP-02 gate is alive.
	// R39-P2-06: pass non-zero batchHash + postStateRoot to comply with
	// the new fail-closed signature (the audit's "batch info completeness" check).
	engine.RecordBatchReceivedFromCurrentSequencer(
		types.Hash{0x38, 0x14}, // synthetic non-zero batchHash
		types.Hash{0x50, 0x14}, // synthetic non-zero postStateRoot
	)
	engine.mu.RLock()
	observed := engine.lastObservedBatchTime
	engine.mu.RUnlock()
	if observed.IsZero() {
		t.Fatal("R38-P1-14: RecordBatchReceivedFromCurrentSequencer did not advance lastObservedBatchTime off zero — gate still dead")
	}

	// Advance missedBatchCount past SequencerTimeout WITHOUT a matching
	// observation advance. Under the dead-gate bug, shouldBuildBatch would
	// return true (spurious takeover → dual sequencer / state fork). With
	// the gate alive, the recent observation MUST suppress the takeover.
	for i := 0; i < int(cfg.SequencerTimeout)*2; i++ {
		engine.mu.Lock()
		engine.missedBatchCount++
		engine.mu.Unlock()
	}
	if engine.shouldBuildBatch() {
		t.Fatal("R38-P1-14 REGRESSION: failover fired with a live current sequencer (observation clock recent) — P1-ROLLUP-02 gate is not actually alive after wiring; spurious takeover → dual sequencer / state fork risk")
	}

	// Flip side of the safety property: once the observation silence
	// window exceeds SequencerTimeout*BlockTime, failover MUST be allowed.
	// This proves the gate is not stuck closed (which would stall the
	// chain). The wiring's job is only to make the gate LIVE — the gate
	// itself still has to open on a genuinely dead sequencer.
	engine.mu.Lock()
	engine.lastObservedBatchTime = time.Now().Add(-time.Hour)
	engine.mu.Unlock()
	if !engine.shouldBuildBatch() {
		t.Fatal("R38-P1-14: failover did NOT trigger after the observation silence window exceeded the timeout — gate is stuck closed and the chain would stall")
	}
}

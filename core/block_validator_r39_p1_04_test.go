// Quantaureum Node source, version 1.0.0.
package core

// R39-P1-04 (2026-08-02) regression tests for:
//   - NewBlockValidator default syncProposerVerification=true
//   - pendingReverify queue accumulation at both skip paths in ValidateBlock
//   - SetSyncingMode(true) clears pendingReverify (no stale records carry
//     forward into the next sync session)
//   - SetSyncingMode(false) spins a best-effort re-verification sweep
//     goroutine that walks the recorded sync-period blocks and runs
//     VerifyProposer against each; PASS/FAIL counted on existing counters;
//     and returns promptly (does not block caller pending the sweep).
//
// The audit's (R39-P1-04) core demand is that operator "force a re-walk of
// all sync-trusted blocks after SetSyncingMode(false)" is enforced, AND the
// default value is true (no more "default OFF + opt-in checklist" non-defense).
//
// Tests in this file exercise ONLY the BlockValidator surface that R39-P1-04
// touches; they do not depend on a fully wired QPOS — a test-local
// ProposerElectionVerifier mock lets us deterministically force PASS or FAIL
// per (slot,epoch,proposer) tuple without consensus state. The full QPOS
// integration is exercised by node/r38_p1_08_sync_failclosed_test.go's
// deep-fix suite.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// r39P1_04MockElectionVerifier is a deterministic ProposerElectionVerifier
// whose per-call result is steered by a map keyed on (slot, epoch, proposer).
// nil entries default to "pass"; non-nil errors pass through to the caller.
// This lets us drive the sweep's PASS/FAIL buckets without any consensus
// wiring. The atomic counters are exposed for assertions.
type r39P1_04MockElectionVerifier struct {
	mu      sync.Mutex
	results map[r39P1_04Key]error
	calls   uint64 // atomic; observable for "sweep actually invoked"
}

type r39P1_04Key struct {
	slot     uint64
	epoch    uint64
	proposer types.Address
}

// r39P1_04NewMockElectionVerifier builds a verifier whose VerifyProposer
// returns nil for any tuple not explicitly registered via setExpect.
func r39P1_04NewMockElectionVerifier() *r39P1_04MockElectionVerifier {
	return &r39P1_04MockElectionVerifier{
		results: make(map[r39P1_04Key]error),
	}
}

// setExpect injects the error VerifyProposer must return for the
// (slot, epoch, proposer) tuple. Pass nil to record a PASS expectation.
// Each tuple may be overwritten; last-write wins.
func (m *r39P1_04MockElectionVerifier) setExpect(slot, epoch uint64, proposer types.Address, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results[r39P1_04Key{slot: slot, epoch: epoch, proposer: proposer}] = err
}

// VerifyProposer satisfies the core.ProposerElectionVerifier contract.
func (m *r39P1_04MockElectionVerifier) VerifyProposer(proposer types.Address, slot, epoch uint64) error {
	atomic.AddUint64(&m.calls, 1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err, ok := m.results[r39P1_04Key{slot: slot, epoch: epoch, proposer: proposer}]; ok {
		return err
	}
	// Default pass — matches the "no expectation registered for this tuple
	// ⇒ treat the proposer as honestly elected" intuition used by the QPOS
	// deep-fix happy path.
	return nil
}

// callCount returns the number of VerifyProposer invocations so far.
func (m *r39P1_04MockElectionVerifier) callCount() uint64 {
	return atomic.LoadUint64(&m.calls)
}

// r39P1_04FixedParent builds a parent header with a deterministic, FIXED
// timestamp (not time.Now()) so consecutive child headers derived from it
// hash to stable values and don't depend on wall-clock drift. This mirrors
// r38p1_08_makeValidParentHeader in node/r38_p1_08_sync_failclosed_test.go.
func r39P1_04FixedParent() *encoding.BlockHeader {
	return &encoding.BlockHeader{
		Version:      1,
		Height:       0,
		Slot:         0,
		Epoch:        0,
		Timestamp:    1700000000,
		ChainID:      1333,
		ProposerAddr: types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}),
		GasLimit:     30000000,
	}
}

// r39P1_04FixedChild mirrors makeValidChildHeader but using the public-ish
// bv.computeHeaderHash for ParentHash derivation (same path
// makeValidChildHeader takes). We do NOT reuse makeValidChildHeader directly
// because that helper uses time.Now() in the parent for its own timestamp
// derivation — our parent uses a fixed timestamp, so the helper would still
// be deterministic as long as the parent is fixed. Re-use is safe; we still
// make a local helper here to avoid coupling R39-P1-04 fixture stability to
// potential future churn in makeValidChildHeader.
func r39P1_04FixedChild(parent *encoding.BlockHeader, bv *BlockValidator) *encoding.BlockHeader {
	return makeValidChildHeader(parent, bv)
}

// r39P1_04NewDevBV constructs a devMode BlockValidator (chainID=1333,
// 30M gas) wired with a dummy validator lookup so ValidateSignature's
// devMode early-return path is the only thing exercised (we never use a
// real Dilithium3 signature in these tests). devMode lets
// ValidateBlock reach the election-verification branches without
// additional cryptography.
func r39P1_04NewDevBV(t *testing.T) *BlockValidator {
	t.Helper()
	bv := NewBlockValidator(1333, 30_000_000)
	bv.SetDevMode(true)
	bv.SetValidatorLookup(&mockValidatorLookup{isValidator: true})
	return bv
}

// r39P1_04ValidBlock builds a fully passable block at parent.Height+1 with a
// 3293-byte Dilithium3-length signature and non-zero roots so the R38-P1-08
// syncer-side root-presence gate (if ever invoked) skips. The block here
// isn't put through ProcessBlock — we're only feeding it to ValidateBlock
// directly — but we still supply valid-looking RootBlock fields so any
// future gate (e.g. on the snapshotted child) doesn't spuriously reject.
func r39P1_04ValidBlock(bv *BlockValidator, parent *encoding.BlockHeader) *encoding.Block {
	child := r39P1_04FixedChild(parent, bv)
	child.Signature = make([]byte, 3293) // crypto.Dilithium3SignatureSize
	child.StateRoot = types.Hash{0xAA}
	child.ReceiptRoot = types.Hash{0xBB}
	return &encoding.Block{Header: child, Transactions: nil}
}

// ── Test 1: default is now ON (regression guard against accidental flip back to OFF). ──

// TestR39_P1_04_NewBlockValidator_DefaultSyncProposerVerificationTrue pins the
// flip in default value. R38-P1-08 left this OFF and only documented
// SetSyncProposerVerification(true) as a deployment checklist item; the R39
// audit (P1-04) calls out that "default OFF + opt-in checklist" is
// operationally equivalent to "no defense" because no production deployment
// actually flips the opt-in. NewBlockValidator must therefore set
// syncProposerVerification=true explicitly so production nodes always run
// the best-effort check.
//
// Regressions: a future "revert to default OFF for backward-compatibility"
// change would make this test fail with Want=true, Got=false. Operators who
// genuinely want the legacy OFF behavior must call
// SetSyncProposerVerification(false) explicitly — that path is tested in
// node/r38_p1_08_sync_failclosed_test.go's
// TestR38P1_08_Deep_BlockValidator_DefaultOptsOutPreservesFix2 (renamed
// when that R38 test was repurposed to pin the legacy-OPT-OUT behavior).
func TestR39_P1_04_NewBlockValidator_DefaultSyncProposerVerificationTrue(t *testing.T) {
	bv := NewBlockValidator(1333, 30_000_000)
	if !bv.IsSyncProposerVerification() {
		t.Fatalf("R39-P1-04: NewBlockValidator must default syncProposerVerification=true (audit demands fail-safe defaults), IsSyncProposerVerification()==false — production nodes are running with the conservative R38-P1-08 opt-in OFF posture, i.e. no defense during sync")
	}
}

// ── Test 2: SetSyncingMode(true) clears stale pendingReverify. ──

// TestR39_P1_04_SetSyncingMode_TrueClearsPendingReverify pins the "fresh
// sync session wipes stale records" contract: a node toggling sync twice
// (once for the initial catch-up, again after an operator hit pause/resume
// for maintenance) must NOT re-verify blocks from the previous sync session
// — they were either already verified by the prior SetSyncingMode(false)
// sweep, or the node is fine re-issuing a sync because the prior sync was
// aborted without ever disabling sync (e.g. process restart mid-sync).
func TestR39_P1_04_SetSyncingMode_TrueClearsPendingReverify(t *testing.T) {
	bv := r39P1_04NewDevBV(t)

	// Seed pendingReverify directly via a write-lock; this is allowed because
	// the test is package-internal and the field is unexported.
	bv.mu.Lock()
	bv.pendingReverify = []reverifyRecord{
		{height: 100, slot: 100, epoch: 3, proposer: types.BytesToAddress([]byte{0x01})},
		{height: 101, slot: 101, epoch: 3, proposer: types.BytesToAddress([]byte{0x02})},
		{height: 102, slot: 102, epoch: 3, proposer: types.BytesToAddress([]byte{0x03})},
	}
	bv.mu.Unlock()

	// Toggle sync ON — this must wipe the queue.
	bv.SetSyncingMode(true)

	bv.mu.RLock()
	left := len(bv.pendingReverify)
	bv.mu.RUnlock()
	if left != 0 {
		t.Fatalf("R39-P1-04: SetSyncingMode(true) must clear pendingReverify so a fresh sync session doesn't re-verify stale records from a prior session (memory-pressure escape valve + correctness); got len=%d", left)
	}
	// And syncingMode must now be true (paranoia: SetSyncingMode must have
	// flipped the flag, not just cleared the queue).
	if !bv.IsSyncingMode() {
		t.Fatalf("R39-P1-04: SetSyncingMode(true) left syncingMode=false — flip lost")
	}
}

// ── Test 3: sweep goroutine counts PASS and FAIL on the existing counters. ──

// TestR39_P1_04_SetSyncingMode_FalseTriggersSweep_PassAndFailCounted
// exercises the audit's core requirement: after the chain completes sync,
// the BlockValidator MUST re-walk the previously-trusted sync blocks and
// run VerifyProposer on each against the now-complete QPOS snapshot. The
// sweep increments the existing syncProposerVerificationPassCount /
// syncProposerVerificationFailCount counters, and FAIL cases are logged at
// WARN with the R39-P1-04 SYNC-REVERIFY-FAIL tag (we don't assert the log
// line here — the audit's requirement is the counter, a single grep point
// is the surface; full fail-then-log path is verified via test logger
// inspection in a separate test if needed).
//
// We seed two PASS tuples and one FAIL tuple, then SetSyncingMode(false),
// then poll the counters until both PASS=2 and FAIL=1 are observed (the
// sweep runs in a goroutine; we wait up to 2s).
func TestR39_P1_04_SetSyncingMode_FalseTriggersSweep_PassAndFailCounted(t *testing.T) {
	bv := r39P1_04NewDevBV(t)
	ver := r39P1_04NewMockElectionVerifier()

	// PASS tuples — VerifyProposer returns nil by default, but we register
	// explicit nil expectations so a future change to the default doesn't
	// silently change this test's semantics.
	proposerA := types.BytesToAddress([]byte{0xAA})
	proposerB := types.BytesToAddress([]byte{0xBB})
	ver.setExpect(100, 3, proposerA, nil)
	ver.setExpect(101, 3, proposerB, nil)
	// FAIL tuple — VerifyProposer returns a fixed error.
	proposerC := types.BytesToAddress([]byte{0xCC})
	ver.setExpect(102, 3, proposerC, errR39P1_04TestFailed)

	// Seed pendingReverify with the matching records.
	bv.mu.Lock()
	bv.pendingReverify = []reverifyRecord{
		{height: 100, slot: 100, epoch: 3, proposer: proposerA},
		{height: 101, slot: 101, epoch: 3, proposer: proposerB},
		{height: 102, slot: 102, epoch: 3, proposer: proposerC},
	}
	bv.mu.Unlock()

	beforePass := bv.SyncProposerVerificationPassCount()
	beforeFail := bv.SyncProposerVerificationFailCount()
	if beforePass != 0 || beforeFail != 0 {
		t.Fatalf("precondition: Pass/Fail counters must start at 0, got Pass=%d Fail=%d", beforePass, beforeFail)
	}

	bv.SetElectionVerifier(ver)
	// Disabling sync must spin the sweep goroutine.
	bv.SetSyncingMode(false)

	// Poll: the sweep is a goroutine, so we must wait for it to land.
	// Cap at 2s so a CI under load still completes; this is not a timing
	// test — the goroutine is O(records) and three records should finish
	// in microseconds.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		passed := bv.SyncProposerVerificationPassCount()
		failed := bv.SyncProposerVerificationFailCount()
		if passed == 2 && failed == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	passed := bv.SyncProposerVerificationPassCount()
	failed := bv.SyncProposerVerificationFailCount()
	if passed != 2 {
		t.Fatalf("R39-P1-04 sweep: PassCount must be 2 (two PASS records seeded), got %d — sweep goroutine did not run, did not call VerifyProposer, or call was routed to the wrong bucket", passed)
	}
	if failed != 1 {
		t.Fatalf("R39-P1-04 sweep: FailCount must be 1 (one FAIL record seeded), got %d — sweep goroutine did not run, did not call VerifyProposer, or call was routed to the wrong bucket", failed)
	}
	if got := ver.callCount(); got != 3 {
		t.Fatalf("R39-P1-04 sweep: VerifyProposer must have been called exactly 3 times (once per pending record), got %d", got)
	}

	// After the sweep, pendingReverify MUST be cleared (SetSyncingMode(false)
	// primitives it out BEFORE launching the goroutine, so even if the
	// goroutine is still in-flight when we read here, the field is already
	// nil — there is no observable half-processed list).
	bv.mu.RLock()
	left := len(bv.pendingReverify)
	bv.mu.RUnlock()
	if left != 0 {
		t.Fatalf("R39-P1-04 sweep: pendingReverify must be cleared by SetSyncingMode(false) before the goroutine is launched, got len=%d — concurrent ValidateBlock could observe a half-processed list (data race)", left)
	}
}

// errR39P1_04TestFailed is the fixed error returned by the mock for FAIL
// tuples in Test 3 and Test 5. Kept at file scope so the sweep goroutine
// (which is in package core) can compare by identity if needed.
var errR39P1_04TestFailed = &r39P1_04ErrorString{"R39-P1-04-test: proposer election not legitimate"}

type r39P1_04ErrorString struct{ s string }

func (e *r39P1_04ErrorString) Error() string { return e.s }

// ── Test 4: SetSyncingMode(false) returns promptly, sweep goroutine is async. ──

// TestR39_P1_04_SweepDoesNotBlock_SetSyncingModeFalseReturns verifies the
// audit's "best-effort re-verification is observability/alerting, not on the
// critical path" contract: SetSyncingMode(false) returns IMMEDIATELY even
// when the sweep queue is large. We seed a 500-record queue and a verifier
// that sleeps 10ms per call (5s of work total); SetSyncingMode(false) must
// return in well under that.
//
// What this rules out: any future refactor that, e.g. joins the sweep
// goroutine (`wg.Wait()`) before returning from SetSyncingMode would pin
// the caller for the sweep's duration — node startup would block for
// seconds/minutes as the sweep walks thousands of records. This is the
// regression guard against that.
func TestR39_P1_04_SweepDoesNotBlock_SetSyncingModeFalseReturns(t *testing.T) {
	bv := r39P1_04NewDevBV(t)
	ver := &r39P1_04SlowVerifier{perCall: 10 * time.Millisecond}

	// Seed 500 records — at 10ms per call, sweep work = 5s.
	records := make([]reverifyRecord, 500)
	for i := range records {
		records[i] = reverifyRecord{
			height:   uint64(i) + 1,
			slot:     uint64(i) + 1,
			epoch:    3,
			proposer: types.BytesToAddress([]byte{byte(i % 256)}),
		}
	}
	bv.mu.Lock()
	bv.pendingReverify = records
	bv.mu.Unlock()

	bv.SetElectionVerifier(ver)
	start := time.Now()
	bv.SetSyncingMode(false)
	elapsed := time.Since(start)

	// SetSyncingMode(false) must return in well under the sweep's 5s of
	// work. 1s is generous (the sweep goroutine should start in µs); the
	// assertion's role is to FAIL catastrophically if someone adds a
	// `wg.Wait()` to join the goroutine, not to flake on a slow CI scheduler.
	if elapsed >= time.Second {
		t.Fatalf("R39-P1-04: SetSyncingMode(false) must return promptly (sweep goroutine is async — observability, not critical path); took %v with a 5s-of-work sweep queued — future refactor may have joined the goroutine synchronously, pinning node startup to the sweep duration", elapsed)
	}
	// We do NOT wait for the sweep to complete here — the test only
	// verifies the caller-side contract. The sweep itself is exercised by
	// Test 3 above. Letting the goroutine finish in the background is
	// harmless (the test process exits after the test goroutine returns,
	// but the sweep goroutine is detached and is not asserted-on here).
}

// r39P1_04SlowVerifier is a ProposerElectionVerifier that sleeps perCall on
// every VerifyProposer invocation, used by Test 4 to make the sweep's total
// work duration much larger than SetSyncingMode(false)'s allowed return time.
type r39P1_04SlowVerifier struct {
	perCall time.Duration
}

func (m *r39P1_04SlowVerifier) VerifyProposer(proposer types.Address, slot, epoch uint64) error {
	time.Sleep(m.perCall)
	return nil
}

// ── Test 5: ValidateBlock records into pendingReverify at the conservative-skip path (no electionVerifier). ──

// TestR39_P1_04_ValidateBlock_ConservativeSkip_RecordsReverify drives the
// "no electionVerifier → conservative skip" branch in ValidateBlock (the
// second skip path) and asserts the block is appended to pendingReverify.
// This is the contract that powers the post-sync sweep even when the
// operator never wires a QPOS election verifier (e.g. in tests, or early
// sync before node.go calls SetElectionVerifier at line 5625): the records
// accumulate so that, once an election verifier becomes available, a
// re-toggle of SetSyncingMode(false) can re-verify them.
//
// devMode + no electionVerifier → syncingMode branch enters the
// `syncProposerVerification && electionVerifier != nil` FALLS THROUGH to
// `else` (electionVerifier is nil), so the conservative-skip path runs and
// records. Note: we explicitly do NOT call SetElectionVerifier here.
func TestR39_P1_04_ValidateBlock_ConservativeSkip_RecordsReverify(t *testing.T) {
	bv := r39P1_04NewDevBV(t)
	// No SetElectionVerifier call — electionVerifier is nil.
	bv.SetSyncingMode(true)
	// Default IsSyncProposerVerification() == true (Test 1 pins this), but
	// the electionVerifier==nil guard routes us through the else branch.

	parent := r39P1_04FixedParent()
	blk := r39P1_04ValidBlock(bv, parent)

	before := bv.SyncingModeSkipCount()
	if _, _, err := bv.ValidateBlock(blk, parent); err != nil {
		t.Fatalf("R39-P1-04: ValidateBlock with no electionVerifier in syncingMode should still pass (conservative skip), got: %v", err)
	}
	if got := bv.SyncingModeSkipCount(); got != before+1 {
		t.Fatalf("R39-P1-04: SyncingModeSkipCount should increment by 1 (conservative skip), before=%d after=%d", before, got)
	}

	bv.mu.RLock()
	records := len(bv.pendingReverify)
	bv.mu.RUnlock()
	if records != 1 {
		t.Fatalf("R39-P1-04: conservative-skip path MUST append exactly one reverifyRecord (block.ProposerAddr, Slot, Epoch, Height) to pendingReverify so SetSyncingMode(false) can re-walk it later — got len=%d", records)
	}

	// Toggle sync OFF — even with no electionVerifier, SetSyncingMode(false)
	// logs a WARN (no sweep goroutine to start) and clears the queue. The
	// records should be discarded (no verifier means the sweep is a no-op
	// — we cannot re-verify, the operator must investigate the WARN).
	bv.SetSyncingMode(false)

	// Give the WARN path a moment (no goroutine is launched in the no-
	// verifier sub-branch, so no poll loop is needed — the records are
	// dropped synchronously inside SetSyncingMode(false)).
	bv.mu.RLock()
	left := len(bv.pendingReverify)
	bv.mu.RUnlock()
	if left != 0 {
		t.Fatalf("R39-P1-04: SetSyncingMode(false) with no electionVerifier must drop pendingReverify (sweep is skipped per the WARN path) — got len=%d", left)
	}
}

// ── Test 6: best-effort FAIL path also records for the post-sync sweep. ──

// TestR39_P1_04_ValidateBlock_BestEffortFail_RecordsReverify drives the
// deep-fix-failed branch (syncProposerVerification=true AND
// electionVerifier != nil AND VerifyProposer returns err). This branch
// falls back to conservative skip AND records into pendingReverify so the
// sweep at SetSyncingMode(false) time gets a chance to re-decide once the
// QPOS snapshot is complete.
//
// This is the audit's strongest requirement: the deep-fix must not silently
// accept a VerifyProposer failure as "best-effort — skip and forget"; it
// MUST retain the record so the operator-visible sweep can flag it as
// SYNC-REVERIFY-FAIL later if the snapshot still says illegitimate.
func TestR39_P1_04_ValidateBlock_BestEffortFail_RecordsReverify(t *testing.T) {
	bv := r39P1_04NewDevBV(t)
	ver := r39P1_04NewMockElectionVerifier()

	parent := r39P1_04FixedParent()
	blk := r39P1_04ValidBlock(bv, parent)

	// Force VerifyProposer to FAIL for the block's (slot, epoch, proposer).
	ver.setExpect(blk.Header.Slot, blk.Header.Epoch, blk.Header.ProposerAddr, errR39P1_04TestFailed)

	bv.SetElectionVerifier(ver)
	bv.SetSyncingMode(true)
	// IsSyncProposerVerification defaults to true (Test 1), so the
	// best-effort path is taken.

	beforeFail := bv.SyncProposerVerificationFailCount()
	beforeSkip := bv.SyncingModeSkipCount()
	if _, _, err := bv.ValidateBlock(blk, parent); err != nil {
		// Best-effort FAIL falls back to conservative skip — block accepted.
		t.Fatalf("R39-P1-04: ValidateBlock best-effort FAIL must NOT reject the block (fall back to skip), got: %v", err)
	}
	if got := bv.SyncProposerVerificationFailCount(); got != beforeFail+1 {
		t.Fatalf("R39-P1-04: best-effort FAIL must bump FailCount, before=%d after=%d", beforeFail, got)
	}
	if got := bv.SyncingModeSkipCount(); got != beforeSkip+1 {
		t.Fatalf("R39-P1-04: best-effort FAIL must ALSO bump SkipCount (fall back to conservative skip), before=%d after=%d", beforeSkip, got)
	}

	bv.mu.RLock()
	records := len(bv.pendingReverify)
	bv.mu.RUnlock()
	if records != 1 {
		t.Fatalf("R39-P1-04: best-effort FAIL path MUST append the block to pendingReverify so the post-sync sweep re-decides once the QPOS snapshot is complete — got len=%d", records)
	}
}

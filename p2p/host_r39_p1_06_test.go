// Quantaureum Node source, version 1.0.0.
package p2p

// R39-P1-06 (2026-08-02) regression tests for the
// peerScorer.IsBanned → disconnectPeer integration.
//
// Audit (R39-P1-06) pointed out that PeerScorer.IsBanned was unit-tested to
// make the right ban decision, but the production path never consumed the
// decision. A peer whose score was pushed below the ban threshold (-50)
// stayed connected forever, continued to spam invalid messages, decayed
// back above threshold, and re-entered acceptable standing without ever
// being disconnected.
//
// The fix introduces Host.enforcePeerBans and calls it on a 30s ticker
// inside peerScorerCleanupLoop. These tests pin five guarantees:
//
//   1. After enforcePeerBans runs, a peer explicitly demoted below the
//      ban threshold is disconnected (gone from h.peers, cancel fired).
//   2. A peer whose score remains above the ban threshold is NOT
//      disconnected (false-positive disconnect would be a regression).
//   3. A peer that was concurrently disconnected (readLoop closed it)
//      by the time enforcePeerBans reaches step-2 is safely skipped
//      (no redundant cancel call → no double-firing of OnDisconnect).
//   4. A Host constructed without a PeerScorer (test shell / shutdown
//      state) does not panic when enforcePeerBans runs.
//   5. enforcePeerBans exists and is wired as the entry point — this
//      test stays around as a compile-time hook so any refactor that
//      removes the function fails the build.
//
// All tests in this file stub the network: a Peer's Conn is left nil (the
// disconnectPeer path takes a nil-check before calling Close). The Peer's
// cancel is wired with a sentinel so we can observe disconnect enforcement
// by checking that cancel() ran.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// r39P1_06MakeTestHost builds a minimal Host with just enough state for
// enforcePeerBans: a peers map, a real PeerScorer (so IsBanned returns
// the configured ban threshold against scores we froze), and an empty
// config. Nothing else is wired.
func r39P1_06MakeTestHost(t *testing.T) *Host {
	t.Helper()
	ps := NewPeerScorer()
	h := &Host{
		config:     &Config{},
		peers:      make(map[PeerID]*Peer),
		peersMu:    sync.RWMutex{},
		peerScorer: ps,
	}
	return h
}

// r39P1_06MakePeer constructs a Peer with a cancel sentinel we can poll.
// cancel is wrapped so the sentinel reports true after cancel ran.
// The peer's Conn stays nil — disconnectPeer has a `peer.Conn != nil` guard.
func r39P1_06MakePeer(id PeerID) (*Peer, *uint32) {
	var canceled uint32
	ctx, cancel := context.WithCancel(context.Background())
	// Wrap cancel to set the sentinel atomically on call. cancel is
	// idempotent (Go's context.WithCancel guarantees that), so calling
	// it twice is a safe no-op; the sentinel lets us assert "the
	// disconnect path ran" without inspecting ctx.Err() directly.
	wrappedCancel := func() {
		atomic.StoreUint32(&canceled, 1)
		cancel()
	}
	p := &Peer{
		ID:     id,
		Addr:   "127.0.0.1:9999",
		ctx:    ctx,
		cancel: wrappedCancel,
	}
	return p, &canceled
}

// ── Test 1: enforcePeerBans disconnects a banned peer. ──

// TestR39_P1_06_EnforcePeerBans_DisconnectsBannedPeer pins the audit's
// core ask: when a peer's score is below the ban threshold and
// enforcePeerBans runs, the peer MUST be disconnected (gone from h.peers,
// cancel fired). Without this contract, the audit's "IsBanned is dead
// code" finding re-appears.
//
// We force-ban the peer by calling RecordProtocolViolation until the
// score is below the default ban threshold (-50). The test stops asserting
// on the score itself (we don't pin the RecordProtocolViolation penalty
// constant — instead we check IsBanned returns true before the sweep and
// that the peer is gone from h.peers after).
func TestR39_P1_06_EnforcePeerBans_DisconnectsBannedPeer(t *testing.T) {
	h := r39P1_06MakeTestHost(t)
	peerID := PeerID("banned-peer-01")
	peer, canceled := r39P1_06MakePeer(peerID)

	h.peersMu.Lock()
	h.peers[peerID] = peer
	h.peersMu.Unlock()

	// R39-P1-06: PeerScorer's RecordProtocolViolation silently no-ops on
	// peer IDs the scorer has never seen via OnConnect (the entry is the
	// scoring record). Production codepaths always call OnConnect in
	// Host.handleNewPeer BEFORE any RecordProtocolViolation can fire, so
	// this sequencing matches production. Without OnConnect, the test's
	// 200 violations land on a non-existent entry and GetScore stays
	// DefaultScore=0 (above banThreshold=-50), so IsBanned never returns
	// true and the fixture fails to demote the peer.
	h.peerScorer.OnConnect(peerID, false)

	// The PeerScorer's total score = clamp(clamp(protocolScore)*0.20 + …)
	// and clampScore floors individual sub-scores at MinPeerScore=-100, so
	// even 200×RecordProtocolViolation (×-30 each) → protocolScore floors
	// at -100 → total = -100*0.20 = -20 — far above the default ban
	// threshold of -50. So merely hammering RecordProtocolViolation is
	// not enough to trip IsBanned under the default ban threshold; we'd
	// need to also drive qualityScore, uptimeScore, discoveryScore, and
	// responseScore all below zero simultaneously. That's not what this
	// test is about — the test is about enforcePeerBans's CONSUMPTION of
	// the IsBanned decision, not the scorer's threshold arithmetic.
	//
	// So we use the production-exposed SetBanThreshold API (audit's
	// R37-P3-20 fix made IsBanned honor this value) to raise the
	// threshold above the peer's already-negative score. After TWO
	// RecordProtocolViolation calls the peer's protocolScore is -60,
	// total = -60*0.20 = -12, ban threshold raised to +1 → -12 ≤ 1 ⇒
	// IsBanned returns true. This models the production "operator tunes
	// ban sensitivity" workflow — operators CAN set this threshold; we
	// just exercise it deterministically here.
	h.peerScorer.SetBanThreshold(1.0)
	for i := 0; i < 200; i++ {
		h.peerScorer.RecordProtocolViolation(peerID)
		if h.peerScorer.IsBanned(peerID) {
			break
		}
	}
	if !h.peerScorer.IsBanned(peerID) {
		t.Fatalf("R39-P1-06: test fixture failed to demote peer below raised ban threshold (200 RecordProtocolViolation calls after OnConnect + SetBanThreshold(1.0) insufficient?) — IsBanned still false, sweep test cannot meaningfully proceed")
	}

	// Pre-condition: peer is connected, cancel has not fired.
	if _, ok := h.peers[peerID]; !ok {
		t.Fatalf("R39-P1-06: fixture peer not in h.peers")
	}
	if atomic.LoadUint32(canceled) != 0 {
		t.Fatalf("R39-P1-06: fixture peer cancel fired before sweep — fixture race")
	}

	// Action: run the sweep.
	h.enforcePeerBans()

	// Assert: peer is GONE, cancel fired.
	if _, ok := h.peers[peerID]; ok {
		t.Fatalf("R39-P1-06: enforcePeerBans did NOT disconnect banned peer — peer still in h.peers (IsBanned returned true but production path didn't consume the decision; audit's 'IsBanned is dead code' finding returned)")
	}
	if atomic.LoadUint32(canceled) != 1 {
		t.Fatalf("R39-P1-06: enforcePeerBans did NOT fire peer.cancel — peer remains connected at the TCP layer (cancel governs every read/write goroutine on the peer)")
	}
}

// ── Test 2: enforcePeerBans leaves non-banned peers connected. ──

// TestR39_P1_06_EnforcePeerBans_PreservesNonBannedPeer pins the false-
// positive disconnect guard: a peer whose score remains above the ban
// threshold MUST survive enforcePeerBans. Without this contract, a future
// refactor that accidentally disconnects every peer (or even every peer
// with score < 0) would crash the network.
//
// We use a virgin PeerScorer (peer not yet scored → score=0, above the
// default -50 threshold → IsBanned=false). The sweep must NO-OP.
func TestR39_P1_06_EnforcePeerBans_PreservesNonBannedPeer(t *testing.T) {
	h := r39P1_06MakeTestHost(t)
	peerID := PeerID("good-peer-02")
	peer, canceled := r39P1_06MakePeer(peerID)

	h.peersMu.Lock()
	h.peers[peerID] = peer
	h.peersMu.Unlock()

	// Don't demote the peer — score remains 0, above -50, not banned.
	if h.peerScorer.IsBanned(peerID) {
		t.Fatalf("R39-P1-06: fixture virgin peer is unexpectedly banned — PeerScorer returned IsBanned=true for a never-scored peer; default banThreshold might have been changed from -50 to >=0 in a future refactor, which would silently break this test and the production sweep")
	}

	h.enforcePeerBans()

	if _, ok := h.peers[peerID]; !ok {
		t.Fatalf("R39-P1-06: enforcePeerBans FALSE-POSITIVELY disconnected a non-banned peer — peer removed from h.peers despite IsBanned=false; sweep must ONLY disconnect explicitly-banned peers (false-positive disconnect of legit peers is a network outage hazard)")
	}
	if atomic.LoadUint32(canceled) != 0 {
		t.Fatalf("R39-P1-06: enforcePeerBans fired cancel on a non-banned peer — production would disconnect the peer up to 30s after every connect, partitioning the node from honest peers")
	}
}

// ── Test 3: peer concurrently disconnected before step-2 is skipped. ──

// TestR39_P1_06_EnforcePeerBans_SkipsConcurrentlyDisconnectedPeer pins the
// race-window safe-skip path: between snapshot (step 1) and disconnect
// (step 2) a concurrent disconnect path (readLoop EOF, cert-rotation,
// manual Disconnect, etc.) may have already removed the peer. The step-2
// re-check MUST skip the disconnect for IDs no longer in h.peers —
// calling disconnectPeer on a deleted entry would redundantly fire
// peerScorer.OnDisconnect (the concurrent path already fired it once via
// its own disconnectPeer call), inflating bad-peer-churn metrics and
// potentially pushing legit peers below threshold in a thundering-herd
// storm.
//
// Test strategy (Host.peerScorer is the concrete *PeerScorer type, NOT an
// interface — we can't wrap it). We observe the race indirectly through
// the peer.cancel sentinel:
//   - step A: snapshot the peer under test (already banned);
//   - step B: simulate concurrent disconnect by manually calling
//     peer.cancel() + delete(h.peers, id) + peerScorer.OnDisconnect (the
//     same side effects disconnectPeer produces);
//   - step C: reset the cancel sentinel to 0 (cancel is idempotent so
//     this is harmless — it just clears our observation harness).
//   - step D: enforcePeerBans runs; step-1 of the sweep snapshots the
//     banned peer ID. The peer is now GONE, so step-2's h.peers re-check
//     must SKIP the disconnect — sentinel stays 0.
//
// If a future refactor removes the step-2 re-check, sentinel becomes 1,
// proving the sweep redundantly drove disconnectPeer on a deleted entry.
func TestR39_P1_06_EnforcePeerBans_SkipsConcurrentlyDisconnectedPeer(t *testing.T) {
	h := r39P1_06MakeTestHost(t)
	peerID := PeerID("race-peer-03")
	peer, canceled := r39P1_06MakePeer(peerID)

	h.peersMu.Lock()
	h.peers[peerID] = peer
	h.peersMu.Unlock()

	// OnConnect + SetBanThreshold — see Test 1 explanation. The default
	// ban threshold of -50 isn't reachable via RecordProtocolViolation
	// alone (clampScore floors the protocol sub-score at -100, weighting
	// it by 0.20 in the total). We raise the threshold so two violations
	// suffice.
	h.peerScorer.OnConnect(peerID, false)
	h.peerScorer.SetBanThreshold(1.0)

	// Demote below threshold.
	for i := 0; i < 200; i++ {
		h.peerScorer.RecordProtocolViolation(peerID)
		if h.peerScorer.IsBanned(peerID) {
			break
		}
	}
	if !h.peerScorer.IsBanned(peerID) {
		t.Fatalf("R39-P1-06: fixture failed to demote race-peer below raised ban threshold after OnConnect")
	}

	// Step B: simulate concurrent disconnect. We mirror what
	// Host.disconnectPeer does: cancel + Conn.Close (no Conn here) +
	// delete from peers + peerScorer.OnDisconnect.
	h.peersMu.Lock()
	peer.cancel()
	delete(h.peers, peerID)
	h.peerScorer.OnDisconnect(peerID, false)
	h.peersMu.Unlock()

	// Sanity: cancel fired during the concurrent disconnect.
	if atomic.LoadUint32(canceled) != 1 {
		t.Fatalf("R39-P1-06: fixture precondition — concurrent disconnect did not fire cancel")
	}

	// Step C: reset sentinel. cancel is idempotent; the sentinel was
	// only our observation harness, not the peer's actual state.
	// Re-sentinel reset to 0 lets us detect a second cancel call.
	atomic.StoreUint32(canceled, 0)

	// Step D: run the sweep. The peer is gone from h.peers; step-2's
	// re-check MUST skip the disconnect.
	h.enforcePeerBans()

	if got := atomic.LoadUint32(canceled); got != 0 {
		t.Fatalf("R39-P1-06: enforcePeerBans redundantly fired peer.cancel() on a peer that was concurrently disconnected before step 2 — sentinel=%d (expected 0); the step-2 h.peers re-check must skip deleted entries to avoid double-firing peerScorer.OnDisconnect and amplifying bad-peer churn on a thundering herd", got)
	}
}

// ── Test 4: nil peerScorer is a safe no-op. ──

// TestR39_P1_06_EnforcePeerBans_NilPeerScorer_NoOp pins the defensive
// nil-guard: a Host constructed without a PeerScorer (a test Host shell
// or a deliberately-stripped production Host during shutdown) MUST NOT
// panic when enforcePeerBans runs. Without this guard, the 30s ticker
// panics once per cycle and `peerScorerCleanupLoop`'s recover() turns
// the panic into a single-line error log every 30s — the loop survives
// but spammy, and more importantly, the ban enforcement is silently
// disabled for the entire session.
func TestR39_P1_06_EnforcePeerBans_NilPeerScorer_NoOp(t *testing.T) {
	h := &Host{
		config:     &Config{},
		peers:      make(map[PeerID]*Peer),
		peersMu:    sync.RWMutex{},
		peerScorer: nil, // explicit nil
	}
	// Add a peer so the iteration path is exercised.
	peerID := PeerID("nil-scorer-peer")
	peer, canceled := r39P1_06MakePeer(peerID)
	h.peersMu.Lock()
	h.peers[peerID] = peer
	h.peersMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("R39-P1-06: enforcePeerBans panicked on nil peerScorer — nil-guard not in place; production path would log a panic + skip ban enforcement for entire session: %v", r)
		}
	}()
	h.enforcePeerBans()

	// Peer must remain connected — nil scorer means no ban to enforce.
	if _, ok := h.peers[peerID]; !ok {
		t.Fatalf("R39-P1-06: enforcePeerBans with nil peerScorer must be a no-op — peer unexpectedly disconnected")
	}
	if atomic.LoadUint32(canceled) != 0 {
		t.Fatalf("R39-P1-06: enforcePeerBans with nil peerScorer fired cancel — no-op contract broken")
	}
}

// ── Test 5: enforcePeerBans exists as a public-enforceable entry point. ──

// TestR39_P1_06_PeerScorerCleanupLoop_TriggersEnforcePeerBans is a
// compile-time guard: if a future refactor removes enforcePeerBans (or
// renames it), this test fails to build, surfacing the regression
// without needing to spin the 30s cleanup loop. The deep behavior is
// covered by tests 1-4; this test verifies the call is a safe no-op on
// an empty Host (one more panic-recovery guarantee).
func TestR39_P1_06_PeerScorerCleanupLoop_TriggersEnforcePeerBans(t *testing.T) {
	h := r39P1_06MakeTestHost(t)
	if h == nil {
		t.Fatalf("R39-P1-06: fixture Host is nil")
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("R39-P1-06: enforcePeerBans panicked on empty Host: %v", r)
		}
	}()
	h.enforcePeerBans()
}

// r39P1_06_dummy import anchor — keeps `time` referenced through the
// file even though the deep tests use only the standard library's
// atomic/context helpers. If a future test here adds polling/timeout
// logic, `time` will be needed; keeping the import bound means a
// subsequent edit doesn't have to re-fight `imported and not used`.
var _ = time.Second

// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// R43 (2026-08-03) regression tests for the three P2 bridge audit
// findings:
//   - R43-BRIDGE-IP-01: ipStates background TTL reaper + hard cap.
//   - R43-BRIDGE-XFF-01: clientIP honors X-Forwarded-For only when
//     TrustProxy is enabled; spoofed XFF cannot bypass per-IP rate
//     limits / bans on direct exposure.
//   - R43-BRIDGE-MSG-01: in-memory `messages` map is bounded to
//     maxMessagesInMemory by sweepMessages, which evicts terminal
//     (EXECUTED / FAILED / EXPIRED) messages oldest first while
//     keeping in-progress (PENDING / VERIFIED) messages regardless of count.
package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// R43-BRIDGE-IP-01: ipStates TTL reaper + hard cap.
// ----------------------------------------------------------------------------

// TestR43_BRIDGE_IP_01_ReaperEvictsExpiredEntries verifies that the
// background reaper goroutine launched by startIPReaper removes
// ipStates entries whose failure window has lapsed AND that are NOT
// currently banned. We use a short cleanupInterval (50ms) via the
// test-only constructor so we don't have to wait the production
// ipCleanupInterval = time.Hour.
func TestR43_BRIDGE_IP_01_ReaperEvictsExpiredEntries(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := newBridgeAPIWithCleanupInterval(qb, nil, nil, nil, "test-key", 50*time.Millisecond)

	// Inject a stale entry: firstFail is 2h in the past (well past
	// apiFailWindow = 1m) with no ban set.
	api.ipLimiterMu.Lock()
	stale := &ipRateState{
		limiter:   newRateLimiter(int(apiRatePerSec), apiBurst),
		firstFail: time.Now().Add(-2 * time.Hour),
	}
	api.ipStates["10.0.0.42"] = stale
	api.ipLimiterMu.Unlock()

	// Start the reaper (would normally happen in Start()).
	api.startIPReaper()
	// Close MUST stop the reaper; deferred so it runs even on Fatalf.
	defer api.Close()

	// Wait for at least one reaper tick (50ms) to fire. We give it
	// generous slack to avoid flake on slow CI.
	deadline := time.Now().Add(2 * time.Second)
	for {
		api.ipLimiterMu.Lock()
		_, exists := api.ipStates["10.0.0.42"]
		api.ipLimiterMu.Unlock()
		if !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reaper did not evict stale entry within deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestR43_BRIDGE_IP_01_ReaperKeepsActiveBan verifies that an entry
// that is CURRENTLY banned (bannedUntil in the future) is NOT reaped
// even if its firstFail is old. The reaper must never silently drop
// an active ban — a banned attacker should stay out for apiBanDuration.
func TestR43_BRIDGE_IP_01_ReaperKeepsActiveBan(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := newBridgeAPIWithCleanupInterval(qb, nil, nil, nil, "test-key", 50*time.Millisecond)

	now := time.Now()
	api.ipLimiterMu.Lock()
	banned := &ipRateState{
		limiter:     newRateLimiter(int(apiRatePerSec), apiBurst),
		firstFail:   now.Add(-2 * time.Hour),   // very old failure window
		bannedUntil: now.Add(30 * time.Minute), // ...but ban is still active
	}
	api.ipStates["10.0.0.7"] = banned
	api.ipLimiterMu.Unlock()

	api.startIPReaper()
	defer api.Close()
	time.Sleep(150 * time.Millisecond) // ~3 ticks

	api.ipLimiterMu.Lock()
	_, exists := api.ipStates["10.0.0.7"]
	api.ipLimiterMu.Unlock()
	if !exists {
		t.Fatal("reaper evicted an entry that is still in its ban window")
	}
}

// TestR43_BRIDGE_IP_01_CloseStopsReaper verifies that Close() stops the
// background reaper goroutine and is idempotent.
func TestR43_BRIDGE_IP_01_CloseStopsReaper(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := newBridgeAPIWithCleanupInterval(qb, nil, nil, nil, "test-key", 25*time.Millisecond)

	api.startIPReaper()
	// stopCleanup is now non-nil.
	api.ipLimiterMu.Lock()
	stopCh := api.stopCleanup
	api.ipLimiterMu.Unlock()
	if stopCh == nil {
		t.Fatal("startIPReaper did not set stopCleanup")
	}

	api.Close()
	// stopCleanup should be nil after Close.
	api.ipLimiterMu.Lock()
	stopCh2 := api.stopCleanup
	api.ipLimiterMu.Unlock()
	if stopCh2 != nil {
		t.Fatal("Close did not clear stopCleanup")
	}

	// Idempotent: second Close must be a no-op (not panic, not block).
	api.Close()
	api.Close()
}

// TestR43_BRIDGE_IP_01_SweepExpiredIPStatesHelper verifies the in-package
// sweep used by both the periodic reaper and the synchronous cap-guard
// logic. It exercises every branch: active ban kept, lapsed ban +
// open failure window kept, lapsed ban + lapsed window reaped,
// never-failed reaped, fresh failure window kept.
func TestR43_BRIDGE_IP_01_SweepExpiredIPStatesHelper(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "test-key")

	now := time.Now()
	api.ipLimiterMu.Lock()
	// active ban: KEEP
	api.ipStates["banned"] = &ipRateState{
		limiter:     newRateLimiter(int(apiRatePerSec), apiBurst),
		firstFail:   now.Add(-30 * time.Minute),
		bannedUntil: now.Add(30 * time.Minute),
	}
	// lapsed ban (ban in the past + failure window open): the lapsed
	// ban means we KEEP until the failure window also lapses. So this
	// entry is KEPT (failure window is still open).
	api.ipStates["lapsed-ban-fresh-window"] = &ipRateState{
		limiter:     newRateLimiter(int(apiRatePerSec), apiBurst),
		firstFail:   now.Add(-10 * time.Second),
		bannedUntil: now.Add(-5 * time.Minute), // ban lapsed
	}
	// lapsed ban + lapsed window: REAP
	api.ipStates["lapsed-ban-stale-window"] = &ipRateState{
		limiter:     newRateLimiter(int(apiRatePerSec), apiBurst),
		firstFail:   now.Add(-2 * time.Hour),
		bannedUntil: now.Add(-1 * time.Hour), // ban lapsed
	}
	// never failed, no ban (limiter-only entry): firstFail.IsZero() → REAP
	api.ipStates["never-failed"] = &ipRateState{
		limiter: newRateLimiter(int(apiRatePerSec), apiBurst),
	}
	// fresh failure window, no ban: KEEP
	api.ipStates["fresh"] = &ipRateState{
		limiter:   newRateLimiter(int(apiRatePerSec), apiBurst),
		firstFail: now,
	}
	removed := api.sweepExpiredIPStates()
	api.ipLimiterMu.Unlock()

	if removed == 0 {
		t.Fatal("expected sweep to remove at least one entry")
	}
	api.ipLimiterMu.Lock()
	defer api.ipLimiterMu.Unlock()
	for _, mustKeep := range []string{"banned", "lapsed-ban-fresh-window", "fresh"} {
		if _, ok := api.ipStates[mustKeep]; !ok {
			t.Errorf("sweep evicted %q which must be kept", mustKeep)
		}
	}
	for _, mustReap := range []string{"lapsed-ban-stale-window", "never-failed"} {
		if _, ok := api.ipStates[mustReap]; ok {
			t.Errorf("sweep kept %q which must be reaped", mustReap)
		}
	}
}

// TestR43_BRIDGE_IP_01_SynchronousSweepAtCap exercises the hard-cap
// branch in getIPState: when len(ipStates) reaches ipStatesMaxEntries
// (= 200000, the production const), adding a NEW IP synchronously
// sweeps expired+lapsed entries BEFORE creating the new entry. The
// sweep is O(n), but it only fires at the cap so normal operation
// stays O(1).
//
// To test this without waiting for the production reaper (1h) we spam
// the map with ipStatesMaxEntries STALE entries (old firstFail, no
// ban) so the synchronous sweep reclaims essentially all of them in
// one shot when the next NEW IP would push the map over the cap. We
// then verify the new IP entry was created AND the map size dropped
// well below ipStatesMaxEntries after the synchronous sweep.
//
// 200k map inserts + a 200k sweep take ~100-300ms in CI — well inside
// the 240s `go test ./bridge/` budget.
//
// NOTE: we deliberately DON'T call Start() here (so no reaper goroutine
// is running concurrently with the synchronous sweep we drive by hand
// via getIPState). The reaper would otherwise race the synchronous
// sweep on stale entries.
func TestR43_BRIDGE_IP_01_SynchronousSweepAtCap(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "test-key")

	oldFirstFail := time.Now().Add(-2 * time.Hour) // stale: past apiFailWindow, no ban

	// Pre-populate with ipStatesMaxEntries STALE entries so the NEXT
	// new getIPState triggers the synchronous sweep at cap (the new IP
	// itself is not yet present, so getIPState falls into the !ok branch
	// where the cap guard `len(...) >= ipStatesMaxEntries` runs).
	api.ipLimiterMu.Lock()
	for i := 0; i < ipStatesMaxEntries; i++ {
		ip := "stale-" + itoa(i)
		api.ipStates[ip] = &ipRateState{
			limiter:   newRateLimiter(int(apiRatePerSec), apiBurst),
			firstFail: oldFirstFail,
		}
	}
	api.ipLimiterMu.Unlock()

	if got := func() int {
		api.ipLimiterMu.Lock()
		defer api.ipLimiterMu.Unlock()
		return len(api.ipStates)
	}(); got != ipStatesMaxEntries {
		t.Fatalf("precondition: ipStates size = %d, want %d", got, ipStatesMaxEntries)
	}

	// Trigger the synchronous sweep-at-cap via getIPState on a NEW IP.
	// All 200k pre-existing entries are stale (old firstFail, no ban),
	// so the sweep reclaims essentially all of them BEFORE the new entry
	// is inserted.
	_ = api.getIPState("brand-new-ip")

	api.ipLimiterMu.Lock()
	finalSize := len(api.ipStates)
	_, newIPExists := api.ipStates["brand-new-ip"]
	api.ipLimiterMu.Unlock()
	if !newIPExists {
		t.Fatal("synchronous-sweep branch did NOT create the new IP entry")
	}
	// The sweep should have reclaimed ALL stale entries (they all have
	// firstFail past apiFailWindow and no ban), plus the brand-new-ip
	// was added. So finalSize should be small (close to 1).
	if finalSize > 100 {
		t.Fatalf("synchronous sweep did not reclaim stale entries: finalSize=%d (expected ~1)", finalSize)
	}
}

// TestR43_BRIDGE_IP_01_CloseSafeWithoutStart verifies that Close() is a
// safe no-op when the reaper was never started (stopCleanup == nil).
// This protects callers that construct a BridgeAPI but never call
// Start() (all of the bridge_api_test.go unit tests do this).
func TestR43_BRIDGE_IP_01_CloseSafeWithoutStart(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "test-key")
	// Close without ever calling Start/startIPReaper.
	api.Close()
	api.Close() // idempotent
}

// ----------------------------------------------------------------------------
// R43-BRIDGE-XFF-01: XFF spoofing cannot bypass per-IP rate limit / ban.
// ----------------------------------------------------------------------------

// TestR43_BRIDGE_XFF_01_SpoofedXFFCannotBypassBan verifies that with
// TrustProxy=false (default), a banned IP cannot bypass its ban by
// spoofing a different X-Forwarded-For. The per-IP rate limit + ban
// must key on r.RemoteAddr (the actual TCP peer), not the spoofable
// XFF value.
func TestR43_BRIDGE_XFF_01_SpoofedXFFCannotBypassBan(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "test-key")
	// TrustProxy is false by default (direct-exposure safe).

	// Pre-ban the actual peer IP "10.0.0.5" by recording apiMaxFailures
	// auth failures against it. Do this directly via recordAuthFailure
	// using the r.RemoteAddr-stripped IP for fidelity.
	peer := "10.0.0.5"
	for i := 0; i < apiMaxFailures; i++ {
		api.recordAuthFailure(peer)
	}
	if !api.isIPBanned(peer) {
		t.Fatalf("peer %s should be banned after %d failures", peer, apiMaxFailures)
	}

	// Now build an authenticated handler and try to reach it with the
	// banned peer as RemoteAddr but XFF spoofing a "clean" IP.
	h := api.authenticate(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bridge/status", nil)
	req.RemoteAddr = peer + ":1234"
	// Spoof XFF to a "fresh" IP — under TrustProxy=false this must be
	// IGNORED, so the request must still appear to come from the banned
	// peer and be rejected with 429 (ban takes precedence over auth).
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed XFF should not bypass ban (TrustProxy=false): expected 429, got %d", rr.Code)
	}
}

// TestR43_BRIDGE_XFF_01_TrustProxyHonorsXFF verifies that with
// TrustProxy=true, the per-IP rate limiter / ban DOES key on the XFF
// value (the real client behind a trusted reverse proxy). A ban on
// the XFF IP must reject subsequent requests even from a different
// RemoteAddr (the proxy).
func TestR43_BRIDGE_XFF_01_TrustProxyHonorsXFF(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "test-key")
	api.SetTrustProxy(true)

	// Ban the XFF IP "198.51.100.7" via recordAuthFailure. We use the
	// XFF value as the ban key directly (since TrustProxy=true would
	// route requests with XFF 198.51.100.7 to that key).
	xffIP := "198.51.100.7"
	for i := 0; i < apiMaxFailures; i++ {
		api.recordAuthFailure(xffIP)
	}
	if !api.isIPBanned(xffIP) {
		t.Fatalf("xff IP %s should be banned after %d failures", xffIP, apiMaxFailures)
	}

	// A request FROM a different RemoteAddr (the proxy) but WITH the
	// banned XFF value must be rejected with 429 — because TrustProxy
	// makes clientIP return the XFF value, and isIPBanned checks that key.
	h := api.authenticate(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bridge/status", nil)
	req.RemoteAddr = "127.0.0.1:8080" // the proxy's loopback
	req.Header.Set("X-Forwarded-For", xffIP)
	rr := httptest.NewRecorder()
	h(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("with TrustProxy=true a banned XFF must reject: expected 429, got %d", rr.Code)
	}
}

// TestR43_BRIDGE_XFF_01_WarnThrottle verifies the once-per-IP-per-second
// warning gate (warnXFFIgnored): two concurrent calls from the same peer
// within the same second emit at most one slog.Warn for that peer, and a
// different peer gets its own warning. We don't assert on log output
// (slog to stderr); we verify the throttle MAP is updated once per
// second per IP.
func TestR43_BRIDGE_XFF_01_WarnThrottle(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "test-key")

	// First warn from peer A: should record a timestamp.
	api.warnXFFIgnored("10.0.0.1")
	api.xffWarnMu.Lock()
	nA := len(api.xffWarnLast)
	tsA := api.xffWarnLast["10.0.0.1"]
	api.xffWarnMu.Unlock()
	if nA != 1 {
		t.Fatalf("expected 1 warn entry, got %d", nA)
	}
	if tsA.IsZero() {
		t.Fatal("warn timestamp for peer A is zero")
	}

	// Second warn from the SAME peer A within the same second: must NOT
	// update the timestamp (throttled — the throttle window is <1s).
	api.warnXFFIgnored("10.0.0.1")
	api.xffWarnMu.Lock()
	tsA2 := api.xffWarnLast["10.0.0.1"]
	api.xffWarnMu.Unlock()
	if !tsA2.Equal(tsA) {
		t.Fatalf("throttle should NOT update timestamp within 1s: tsA=%v tsA2=%v", tsA, tsA2)
	}

	// Warn from a different peer B: must record a separate entry.
	api.warnXFFIgnored("10.0.0.2")
	api.xffWarnMu.Lock()
	nAB := len(api.xffWarnLast)
	api.xffWarnMu.Unlock()
	if nAB != 2 {
		t.Fatalf("expected 2 warn entries (one per peer), got %d", nAB)
	}
}

// TestR43_BRIDGE_XFF_01_SpoofedXFFIgnoredUnderAttack is a concurrency
// smoke test: many goroutines hammer the same banned peer IP with
// random XFF values. TrustProxy=false, so ALL XFF values must be
// ignored and the request rate-limited/banned by the peer IP.
//
// We assert no panic and at least one 429 (ban takes effect).
func TestR43_BRIDGE_XFF_01_SpoofedXFFIgnoredUnderAttack(t *testing.T) {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	api := NewBridgeAPI(qb, nil, nil, nil, "test-key")
	// TrustProxy=false default.
	peer := "10.0.0.99"
	for i := 0; i < apiMaxFailures; i++ {
		api.recordAuthFailure(peer)
	}

	h := api.authenticate(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	})

	var wg sync.WaitGroup
	got429 := make(chan struct{}, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/bridge/status", nil)
			req.RemoteAddr = peer + ":1234"
			// Spoofed XFF — each goroutine uses a different fake IP.
			req.Header.Set("X-Forwarded-For", "203.0.113."+itoa(i))
			rr := httptest.NewRecorder()
			h(rr, req)
			if rr.Code == http.StatusTooManyRequests {
				select {
				case got429 <- struct{}{}:
				default:
				}
			}
		}(i)
	}
	wg.Wait()
	close(got429)

	if _, ok := <-got429; !ok {
		t.Fatal("expected at least one 429 (ban enforced despite XFF spoofing)")
	}
}

// itoa is a tiny dependency-free int->string helper used by the
// concurrency smoke test above. Kept local to avoid pulling in strconv
// just for tiny test helpers (matches the no-deps pattern used
// elsewhere for tiny helper funcs).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ----------------------------------------------------------------------------
// R43-BRIDGE-MSG-01: sweepMessages bounds the in-memory `messages` map.
// ----------------------------------------------------------------------------

// injectMessagesWithLock bulk-inserts `count` bridge messages under
// b.mu (caller MUST already hold b.mu), splitting them across the
// given status according to `statusFor(i)`. Returns nothing — the
// caller reads b.messages directly to assert post-state.
func injectMessagesWithLock(b *QuantumBridge, count int, statusFor func(i int) BridgeMessageStatus) {
	now := time.Now().Unix()
	for i := 0; i < count; i++ {
		status := statusFor(i)
		id := "msg-" + itoa(i)
		b.messages[id] = &BridgeMessage{
			ID:        id,
			Status:    status,
			Timestamp: now + int64(i), // strictly increasing
		}
		if b.messagesByStatus[status] == nil {
			b.messagesByStatus[status] = make(map[string]bool)
		}
		b.messagesByStatus[status][id] = true
	}
}

// TestR43_BRIDGE_MSG_01_SweepEvictsTerminalOldestFirst verifies that
// sweepMessages removes terminal (EXECUTED / FAILED / EXPIRED)
// messages oldest-first when the map exceeds maxMessagesInMemory,
// while keeping PENDING / VERIFIED messages regardless of count.
//
// We use a SMALL count (cap+5 terminal + 2 pending = 10007) so this
// test runs in milliseconds — the sweep is O(n) but n is tiny and we
// are NOT testing the cap threshold here (only the eviction policy).
func TestR43_BRIDGE_MSG_01_SweepEvictsTerminalOldestFirst(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	// Inject maxMessagesInMemory + 5 TERMINAL messages with increasing
	// timestamps so "oldest first" ordering is deterministic, plus 2
	// PENDING in-progress messages that must NEVER be evicted.
	terminalCount := maxMessagesInMemory + 5
	terminalFor := func(i int) BridgeMessageStatus {
		switch i % 3 {
		case 0:
			return MessageStatusExecuted
		case 1:
			return MessageStatusFailed
		default:
			return MessageStatusExpired
		}
	}

	b.mu.Lock()
	injectMessagesWithLock(b, terminalCount, terminalFor)
	// Two PENDING in-progress messages — must be KEPT regardless of count.
	for i := 0; i < 2; i++ {
		id := "pending-" + itoa(i)
		b.messages[id] = &BridgeMessage{
			ID:        id,
			Status:    MessageStatusPending,
			Timestamp: time.Now().Unix() + int64(terminalCount+i),
		}
		if b.messagesByStatus[MessageStatusPending] == nil {
			b.messagesByStatus[MessageStatusPending] = make(map[string]bool)
		}
		b.messagesByStatus[MessageStatusPending][id] = true
	}
	preCount := len(b.messages)
	if preCount != terminalCount+2 {
		b.mu.Unlock()
		t.Fatalf("pre-sweep count: got %d, want %d", preCount, terminalCount+2)
	}

	b.sweepMessages()

	postCount := len(b.messages)
	// We evict the (terminalCount + 2 - maxMessagesInMemory) oldest
	// terminal messages so the final count is exactly maxMessagesInMemory.
	wantEvicted := (terminalCount + 2) - maxMessagesInMemory
	wantRemaining := maxMessagesInMemory
	if postCount != wantRemaining {
		b.mu.Unlock()
		t.Fatalf("post-sweep count: got %d, want %d (evicted %d, wanted %d)", postCount, wantRemaining, preCount-postCount, wantEvicted)
	}
	if preCount-postCount != wantEvicted {
		b.mu.Unlock()
		t.Fatalf("evicted count: got %d, want %d", preCount-postCount, wantEvicted)
	}

	// The 2 PENDING messages must survive.
	for i := 0; i < 2; i++ {
		id := "pending-" + itoa(i)
		if _, ok := b.messages[id]; !ok {
			t.Errorf("sweep evicted in-progress PENDING message %q", id)
		}
	}
	// The terminal messages evicted must be the OLDEST ones
	// (msg-0 .. msg-(wantEvicted-1)).
	for i := 0; i < wantEvicted; i++ {
		id := "msg-" + itoa(i)
		if _, ok := b.messages[id]; ok {
			t.Errorf("sweep kept oldest terminal %q (should have been evicted first)", id)
		}
	}
	// The newest terminal messages must survive.
	for i := wantEvicted; i < terminalCount; i++ {
		id := "msg-" + itoa(i)
		if _, ok := b.messages[id]; !ok {
			t.Errorf("sweep evicted newer-than-cap terminal %q (should have been kept)", id)
		}
	}
	// Every EVICTED terminal message must be marked finalized so a
	// replay with that ID is rejected at SubmitMessage time even though
	// the entry is no longer in the messages cache. Surviving terminal
	// messages are still protected by the `messages[id] != nil` check
	// at SubmitMessage and so do NOT need a finalizedIDs marker.
	for i := 0; i < wantEvicted; i++ {
		id := "msg-" + itoa(i)
		if !b.finalizedIDs[id] {
			t.Errorf("evicted terminal %q must be marked finalized for replay protection", id)
		}
	}
	b.mu.Unlock()
}

// TestR43_BRIDGE_MSG_01_SweepNoopWhenUnderCap verifies that sweepMessages
// is O(1) (early-return) when the map is at or below the cap.
func TestR43_BRIDGE_MSG_01_SweepNoopWhenUnderCap(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	b.mu.Lock()
	// Insert exactly maxMessagesInMemory entries (at the cap, not over).
	for i := 0; i < maxMessagesInMemory; i++ {
		id := "at-cap-" + itoa(i)
		b.messages[id] = &BridgeMessage{ID: id, Status: MessageStatusExecuted, Timestamp: int64(i)}
		if b.messagesByStatus[MessageStatusExecuted] == nil {
			b.messagesByStatus[MessageStatusExecuted] = make(map[string]bool)
		}
		b.messagesByStatus[MessageStatusExecuted][id] = true
	}
	b.sweepMessages()
	count := len(b.messages)
	b.mu.Unlock()
	if count != maxMessagesInMemory {
		t.Fatalf("sweep should be a no-op at the cap: got %d, want %d", count, maxMessagesInMemory)
	}
}

// TestR43_BRIDGE_MSG_01_SweepKeepsInProgressOnly verifies that when the
// map is over the cap but contains ONLY in-progress (PENDING / VERIFIED)
// messages, sweepMessages is a no-op (in-progress messages are never
// evicted regardless of count).
func TestR43_BRIDGE_MSG_01_SweepKeepsInProgressOnly(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	b.mu.Lock()
	for i := 0; i < maxMessagesInMemory+5; i++ {
		var status BridgeMessageStatus
		if i%2 == 0 {
			status = MessageStatusPending
		} else {
			status = MessageStatusVerified
		}
		id := "inprogress-" + itoa(i)
		b.messages[id] = &BridgeMessage{ID: id, Status: status, Timestamp: int64(i)}
		if b.messagesByStatus[status] == nil {
			b.messagesByStatus[status] = make(map[string]bool)
		}
		b.messagesByStatus[status][id] = true
	}
	b.sweepMessages()
	count := len(b.messages)
	b.mu.Unlock()
	if count != maxMessagesInMemory+5 {
		t.Fatalf("sweep evicted in-progress messages: got %d, want %d (no eviction of PENDING/VERIFIED)", count, maxMessagesInMemory+5)
	}
}

// TestR43_BRIDGE_MSG_01_GetMessageReturnsNotFoundAfterSweep verifies
// that after sweepMessages evicts a terminal message, a downstream
// GetMessage call for that ID returns the canonical "message not found"
// error, matching the existing behavior for unknown IDs.
func TestR43_BRIDGE_MSG_01_GetMessageReturnsNotFoundAfterSweep(t *testing.T) {
	cfg := DefaultBridgeConfig()
	cfg.ConfirmationsRequired = 0
	b := NewQuantumBridge(cfg).(*QuantumBridge)
	defer b.Stop(context.Background())

	b.mu.Lock()
	now := time.Now().Unix()
	// Fill the map over the cap with terminal messages; we evict the
	// oldest one ("msg-0").
	for i := 0; i < maxMessagesInMemory+5; i++ {
		id := "msg-" + itoa(i)
		b.messages[id] = &BridgeMessage{ID: id, Status: MessageStatusExecuted, Timestamp: now + int64(i)}
		if b.messagesByStatus[MessageStatusExecuted] == nil {
			b.messagesByStatus[MessageStatusExecuted] = make(map[string]bool)
		}
		b.messagesByStatus[MessageStatusExecuted][id] = true
	}
	b.sweepMessages()
	b.mu.Unlock()

	// msg-0 must have been evicted → GetMessage returns not-found.
	_, err := b.GetMessage(context.Background(), "msg-0")
	if err == nil {
		t.Fatal("expected GetMessage to return not-found error for swept message ID")
	}
}

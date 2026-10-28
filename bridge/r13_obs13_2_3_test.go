// Quantaureum Node source, version 1.0.0.
// SPDX-License-Identifier: MIT
//
// Round-13 observation items OBS-13-2 and OBS-13-3:
//   - ipStates had a soft cap: at capacity, a sweep that reclaimed nothing
//     still let the caller insert, so the map grew past ipStatesMaxEntries.
//   - xffWarnLast had neither a cap nor a cleanup path.
package bridge

import (
	"testing"
	"time"
)

func newOBS13TestAPI(interval time.Duration) *BridgeAPI {
	qb := NewQuantumBridge(DefaultBridgeConfig()).(*QuantumBridge)
	return newBridgeAPIWithCleanupInterval(qb, nil, nil, nil, "test-key", interval)
}

// fillBannedIPStates saturates ipStates with entries that the synchronous
// sweep must keep (every one is inside an active ban window), so a caller
// cannot free a slot by sweeping.
func fillBannedIPStates(t *testing.T, api *BridgeAPI) {
	t.Helper()
	now := time.Now()
	api.ipLimiterMu.Lock()
	for i := 0; i < ipStatesMaxEntries; i++ {
		api.ipStates["banned-"+itoa(i)] = &ipRateState{
			limiter:     newRateLimiter(int(apiRatePerSec), apiBurst),
			firstFail:   now.Add(-time.Minute),
			bannedUntil: now.Add(time.Hour),
		}
	}
	api.ipLimiterMu.Unlock()
}

// TestOBS13_2_GetIPStateFailsClosedAtCap asserts a NEW source IP is denied
// when the tracking table is saturated by still-active entries, and that the
// denial does not grow the map.
func TestOBS13_2_GetIPStateFailsClosedAtCap(t *testing.T) {
	api := newOBS13TestAPI(time.Hour)
	defer api.Close()
	fillBannedIPStates(t, api)

	st, admitted := api.getIPState("fresh-ip")
	if admitted {
		t.Fatal("getIPState admitted a new IP while the table was saturated")
	}
	if st != nil {
		t.Fatal("getIPState returned a state for a denied IP")
	}

	api.ipLimiterMu.Lock()
	size := len(api.ipStates)
	_, exists := api.ipStates["fresh-ip"]
	api.ipLimiterMu.Unlock()
	if size != ipStatesMaxEntries {
		t.Fatalf("ipStates size = %d, want %d (cap must not be exceeded)", size, ipStatesMaxEntries)
	}
	if exists {
		t.Fatal("denied IP was inserted into ipStates")
	}
}

// TestOBS13_2_RecordAuthFailureAtCapDoesNotGrow asserts the failure-recording
// path also refuses to grow the map (ban accounting is dropped instead).
func TestOBS13_2_RecordAuthFailureAtCapDoesNotGrow(t *testing.T) {
	api := newOBS13TestAPI(time.Hour)
	defer api.Close()
	fillBannedIPStates(t, api)

	api.recordAuthFailure("fresh-ip-2")

	api.ipLimiterMu.Lock()
	size := len(api.ipStates)
	_, exists := api.ipStates["fresh-ip-2"]
	api.ipLimiterMu.Unlock()
	if size != ipStatesMaxEntries {
		t.Fatalf("ipStates size = %d after recordAuthFailure, want %d", size, ipStatesMaxEntries)
	}
	if exists {
		t.Fatal("recordAuthFailure inserted an entry past the cap")
	}
}

// TestOBS13_2_ExistingIPStillServedAtCap asserts fail-closed only affects NEW
// IPs: an already-tracked IP keeps its state (so active bans are never lost).
func TestOBS13_2_ExistingIPStillServedAtCap(t *testing.T) {
	api := newOBS13TestAPI(time.Hour)
	defer api.Close()
	fillBannedIPStates(t, api)

	st, admitted := api.getIPState("banned-0")
	if !admitted || st == nil {
		t.Fatal("existing tracked IP was denied while the table was saturated")
	}
	if !api.isIPBanned("banned-0") {
		t.Fatal("existing ban was lost at saturation")
	}
}

// TestOBS13_3_XFFWarnReclaimsStaleAtCap asserts a full throttle table is
// swept before a new peer is recorded, so the map never exceeds its cap.
func TestOBS13_3_XFFWarnReclaimsStaleAtCap(t *testing.T) {
	api := newOBS13TestAPI(time.Hour)
	defer api.Close()

	stale := time.Now().Add(-2 * xffWarnTTL)
	api.xffWarnMu.Lock()
	for i := 0; i < xffWarnMaxEntries; i++ {
		api.xffWarnLast["stale-"+itoa(i)] = stale
	}
	api.xffWarnMu.Unlock()

	api.warnXFFIgnored("new-peer")

	api.xffWarnMu.Lock()
	size := len(api.xffWarnLast)
	_, exists := api.xffWarnLast["new-peer"]
	api.xffWarnMu.Unlock()
	if size > xffWarnMaxEntries {
		t.Fatalf("xffWarnLast size = %d, exceeds cap %d", size, xffWarnMaxEntries)
	}
	if !exists {
		t.Fatal("new peer was not recorded after stale entries were reclaimed")
	}
}

// TestOBS13_3_XFFWarnRefusesGrowthWhenAllFresh asserts that when the table is
// full of entries that are still inside the throttle TTL, the warning is
// dropped rather than the map being grown.
func TestOBS13_3_XFFWarnRefusesGrowthWhenAllFresh(t *testing.T) {
	api := newOBS13TestAPI(time.Hour)
	defer api.Close()

	now := time.Now()
	api.xffWarnMu.Lock()
	for i := 0; i < xffWarnMaxEntries; i++ {
		api.xffWarnLast["fresh-"+itoa(i)] = now
	}
	api.xffWarnMu.Unlock()

	api.warnXFFIgnored("new-peer")

	api.xffWarnMu.Lock()
	size := len(api.xffWarnLast)
	_, exists := api.xffWarnLast["new-peer"]
	api.xffWarnMu.Unlock()
	if size != xffWarnMaxEntries {
		t.Fatalf("xffWarnLast size = %d, want %d (must not grow)", size, xffWarnMaxEntries)
	}
	if exists {
		t.Fatal("new peer was recorded into a saturated, all-fresh throttle table")
	}
}

// TestOBS13_3_SweepXFFWarnDropsOnlyExpired pins the sweep predicate.
func TestOBS13_3_SweepXFFWarnDropsOnlyExpired(t *testing.T) {
	api := newOBS13TestAPI(time.Hour)
	defer api.Close()

	now := time.Now()
	api.xffWarnMu.Lock()
	api.xffWarnLast["old"] = now.Add(-2 * xffWarnTTL)
	api.xffWarnLast["fresh"] = now
	removed := api.sweepXFFWarnLocked(now)
	_, oldKept := api.xffWarnLast["old"]
	_, freshKept := api.xffWarnLast["fresh"]
	api.xffWarnMu.Unlock()

	if removed != 1 {
		t.Fatalf("sweep removed %d entries, want 1", removed)
	}
	if oldKept {
		t.Fatal("expired throttle entry survived the sweep")
	}
	if !freshKept {
		t.Fatal("in-window throttle entry was dropped by the sweep")
	}
}

// TestOBS13_3_ReaperPrunesXFFWarn asserts the background reaper (not just the
// insertion path) ages out throttle entries.
func TestOBS13_3_ReaperPrunesXFFWarn(t *testing.T) {
	api := newOBS13TestAPI(20 * time.Millisecond)

	api.xffWarnMu.Lock()
	api.xffWarnLast["stale-peer"] = time.Now().Add(-2 * xffWarnTTL)
	api.xffWarnMu.Unlock()

	api.startIPReaper()
	defer api.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		api.xffWarnMu.Lock()
		_, exists := api.xffWarnLast["stale-peer"]
		api.xffWarnMu.Unlock()
		if !exists {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("reaper never pruned the expired xffWarnLast entry")
}

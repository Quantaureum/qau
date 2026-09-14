// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements per-peer rate limiting
type RateLimiter struct {
	limit    int           // Maximum requests per window
	window   time.Duration // Time window
	counters map[PeerID]*rateLimitCounter
	mu       sync.RWMutex
	maxSize  int           // audit-fix L-4: maximum number of counters to prevent memory exhaustion
	stopCh   chan struct{} // audit-fix M-5: stop channel to prevent goroutine leak
	stopOnce sync.Once     // audit-fix R6-C1: prevent double-close panic
	// audit-fix RATE-LIMIT-1: track rate limit violations per peer
	violations        map[PeerID]*rateLimitViolationTracker
	violationsMu      sync.RWMutex
	violationStopCh   chan struct{}
	violationStopOnce sync.Once // FIX: prevent double-close panic
}

type rateLimitCounter struct {
	count     int
	windowEnd time.Time
}

// audit-fix RATE-LIMIT-1: track violations for per-peer rate limiting
type rateLimitViolationTracker struct {
	count     int
	windowEnd time.Time
}

// audit-fix RATE-LIMIT-1: constants for rate limit violation handling
const (
	// RateLimitViolationThreshold is the number of rate limit violations before banning
	RateLimitViolationThreshold = 3
)

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	// R42-RP-002 FIX: Validate limit and window to prevent misconfiguration.
	// limit <= 0 would allow exactly 1 request per window (due to the
	// new-window branch in Allow), which is not a true "block all" semantics.
	// window <= 0 would panic the cleanup goroutine's time.NewTicker.
	if limit <= 0 {
		limit = 1
	}
	if window <= 0 {
		window = time.Second
	}
	// RPC-R9-M (2026-07-19) FIX: Cap window at 24h. The cleanup goroutine
	// below calls `time.NewTicker(rl.window * 2)`; without an upper bound,
	// a caller passing window=math.MaxInt64 (or any value > MaxInt64/2)
	// would cause `rl.window * 2` to wrap to a negative value, panicking
	// time.NewTicker. 24h is well above any sane rate-limit window while
	// leaving plenty of headroom for the *2 multiplication.
	const maxRateLimitWindow = 24 * time.Hour
	if window > maxRateLimitWindow {
		window = maxRateLimitWindow
	}
	rl := &RateLimiter{
		limit:    limit,
		window:   window,
		counters: make(map[PeerID]*rateLimitCounter),
		maxSize:  DefaultMaxBlacklistSize, // Reuse same default
		stopCh:   make(chan struct{}),     // audit-fix M-5
		// audit-fix RATE-LIMIT-1: initialize violations map
		violations:      make(map[PeerID]*rateLimitViolationTracker),
		violationStopCh: make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()
	// audit-fix RATE-LIMIT-1: start violation cleanup goroutine
	go rl.violationCleanup()

	return rl
}

// evictExpiredLocked removes expired counters. Must hold rl.mu.
func (rl *RateLimiter) evictExpiredLocked() {
	now := time.Now()
	for p, counter := range rl.counters {
		if now.After(counter.windowEnd) {
			delete(rl.counters, p)
		}
	}
}

// rateLimiterEvictionSamples caps the number of map entries inspected
// when looking for the oldest windowEnd to evict. Go map iteration order
// is randomized, so inspecting the first K entries yields a uniform
// random sample of the map. Among K samples the probability of picking
// the truly-oldest entry is K/N; for K=128 and N=10000 that is ~1.3%,
// which is sufficient for an approximate-LRU eviction policy whose
// only goal is to bound memory — not to provide strict LRU semantics.
//
// This is the same technique used by Redis's `maxmemory-policy
// allkeys-lru` (which samples 5 entries by default) and by the Linux
// kernel's inactive-list shrinking.
//
// P2P-R11-L01 (2026-07-20) FIX: RPC-R9-M (2026-07-19) changed the
// eviction from "delete a random entry" to "scan the entire map to find
// the truly-oldest entry". That restored correctness but introduced an
// O(N) scan inside the hot path of Allow(). Under the 200K-peer scale
// test (TestScale_200KRateLimiter_ViolationTracking) with window=1h
// (peers never expire during the test), every Allow() call after the
// first 10K peers scanned all 10K entries — O(N²) total — causing the
// test to time out at 60s. Sampling restores O(1) per-call cost while
// keeping the "evict close-to-oldest" guarantee that prevents the
// freshly-added-peer eviction RPC-R9-M was fixing.
const rateLimiterEvictionSamples = 128

// Allow checks if a request from a peer is allowed
func (rl *RateLimiter) Allow(p PeerID) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.counters[p]

	if !exists || now.After(counter.windowEnd) {
		// audit-fix L-4: enforce max size
		if !exists && rl.maxSize > 0 && len(rl.counters) >= rl.maxSize {
			rl.evictExpiredLocked()
			// If still at capacity, evict the entry with the earliest
			// windowEnd (i.e. the one closest to expiring). Previously this
			// loop just deleted an arbitrary entry from the map iteration
			// (Go map iteration order is randomized), which could evict a
			// freshly-added active peer — resetting its rate-limit budget
			// and allowing it to burst more requests than the configured
			// limit. RPC-R9-M (2026-07-19) FIX: pick the truly-oldest entry.
			//
			// P2P-R11-L01 (2026-07-20) FIX: RPC-R9-M's full-map scan was
			// O(N) per call and caused O(N²) behavior under load (see
			// rateLimiterEvictionSamples comment above). Now we sample the
			// first rateLimiterEvictionSamples entries from the (randomized)
			// map iteration and pick the oldest among them. This preserves
			// the "evict close-to-oldest" guarantee while bounding per-call
			// cost to O(rateLimiterEvictionSamples).
			if len(rl.counters) >= rl.maxSize {
				var oldestID PeerID
				var oldestWindow time.Time
				found := false
				inspected := 0
				for id, c := range rl.counters {
					if inspected >= rateLimiterEvictionSamples {
						break
					}
					inspected++
					if !found || c.windowEnd.Before(oldestWindow) {
						oldestID = id
						oldestWindow = c.windowEnd
						found = true
					}
				}
				if found {
					delete(rl.counters, oldestID)
				}
			}
		}

		// New window
		rl.counters[p] = &rateLimitCounter{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}

	if counter.count >= rl.limit {
		return false
	}

	counter.count++
	return true
}

// GetCount returns the current request count for a peer
func (rl *RateLimiter) GetCount(p PeerID) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	counter, exists := rl.counters[p]
	if !exists {
		return 0
	}

	if time.Now().After(counter.windowEnd) {
		return 0
	}

	return counter.count
}

// Reset resets the counter for a peer
func (rl *RateLimiter) Reset(p PeerID) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.counters, p)
	// audit-fix RATE-LIMIT-1: also clear violations on reset
	rl.violationsMu.Lock()
	delete(rl.violations, p)
	rl.violationsMu.Unlock()
}

// Stop stops the rate limiter's background cleanup goroutine.
// audit-fix M-5: prevents goroutine leak.
// audit-fix R6-C1: use sync.Once to prevent panic on double-close.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCh)
	})
	// FIX: use sync.Once for violationStopCh to prevent
	// double-close panic when Stop() is called more than once.
	rl.violationStopOnce.Do(func() {
		close(rl.violationStopCh)
	})
}

// cleanup periodically removes expired counters
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window * 2)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in RateLimiter.cleanup: %v", r)
		}
	}()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for p, counter := range rl.counters {
				if now.After(counter.windowEnd) {
					delete(rl.counters, p)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// audit-fix RATE-LIMIT-1: violationCleanup periodically removes expired violation trackers
func (rl *RateLimiter) violationCleanup() {
	// Use a longer interval for violations (5 minutes)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in RateLimiter.violationCleanup: %v", r)
		}
	}()

	for {
		select {
		case <-ticker.C:
			rl.violationsMu.Lock()
			now := time.Now()
			for p, tracker := range rl.violations {
				if now.After(tracker.windowEnd) {
					delete(rl.violations, p)
				}
			}
			rl.violationsMu.Unlock()
		case <-rl.violationStopCh:
			return
		}
	}
}

// RecordViolation records a rate limit violation for a peer and returns true if the peer should be banned
// audit-fix RATE-LIMIT-1: track violations and trigger ban when threshold is exceeded
//
// P3-4 (R15 Low): enforce maxSize on the violations map. Previously the
// violations map only had a periodic cleanup goroutine (5-minute interval)
// but no hard cap. Under a Sybil attack that triggers many violations
// without hitting the ban threshold (each peer only violates twice before
// the 1-minute window expires), the map could grow unbounded between
// cleanup ticks — especially since the cleanup goroutine runs every 5
// minutes but violation windows are only 1 minute long. Now we evict
// expired entries and, if still at capacity, sample-evict the oldest
// entry before inserting a new one, mirroring the counters map logic.
func (rl *RateLimiter) RecordViolation(p PeerID) bool {
	rl.violationsMu.Lock()
	defer rl.violationsMu.Unlock()

	now := time.Now()
	tracker, exists := rl.violations[p]

	if !exists || now.After(tracker.windowEnd) {
		// P3-4: enforce maxSize before adding a new entry.
		if !exists && rl.maxSize > 0 && len(rl.violations) >= rl.maxSize {
			// First pass: evict expired entries.
			for id, t := range rl.violations {
				if now.After(t.windowEnd) {
					delete(rl.violations, id)
				}
			}
			// If still at capacity, sample-evict the oldest entry (same
			// sampling technique as Allow() — see rateLimiterEvictionSamples).
			if len(rl.violations) >= rl.maxSize {
				var oldestID PeerID
				var oldestWindow time.Time
				found := false
				inspected := 0
				for id, t := range rl.violations {
					if inspected >= rateLimiterEvictionSamples {
						break
					}
					inspected++
					if !found || t.windowEnd.Before(oldestWindow) {
						oldestID = id
						oldestWindow = t.windowEnd
						found = true
					}
				}
				if found {
					delete(rl.violations, oldestID)
				}
			}
		}

		// Start a new violation window (1 minute)
		rl.violations[p] = &rateLimitViolationTracker{
			count:     1,
			windowEnd: now.Add(time.Minute),
		}
		return false
	}

	tracker.count++

	if tracker.count >= RateLimitViolationThreshold {
		return true // Peer should be banned
	}

	return false
}

// GetViolationCount returns the current violation count for a peer
// audit-fix RATE-LIMIT-1: getter for violation count
func (rl *RateLimiter) GetViolationCount(p PeerID) int {
	rl.violationsMu.RLock()
	defer rl.violationsMu.RUnlock()

	tracker, exists := rl.violations[p]
	if !exists || time.Now().After(tracker.windowEnd) {
		return 0
	}

	return tracker.count
}

// audit-fix L-4: maximum number of blacklist entries to prevent memory exhaustion.
const DefaultMaxBlacklistSize = 10000

// validateBlacklistReason validates and sanitizes blacklist reasons.
// audit-fix H-4: prevents reason injection attacks and ensures safe logging.
func validateBlacklistReason(reason string) string {
	// Trim whitespace
	reason = strings.TrimSpace(reason)
	// Limit length to prevent memory exhaustion
	if len(reason) > 256 {
		reason = reason[:256]
	}
	// Remove control characters that could affect log formatting
	var sanitized []byte
	for i := 0; i < len(reason); i++ {
		c := reason[i]
		if c >= 0x20 && c <= 0x7E || c == '	' {
			sanitized = append(sanitized, c)
		}
	}
	return string(sanitized)
}

// Blacklist manages blacklisted peers
type Blacklist struct {
	peers    map[PeerID]*blacklistEntry
	mu       sync.RWMutex
	duration time.Duration // Default ban duration
	maxSize  int           // audit-fix L-4: maximum entries
	stopCh   chan struct{} // audit-fix M-5: stop channel to prevent goroutine leak
	stopOnce sync.Once     // audit-fix CRIT-3: prevent double-close panic

	// P2P-C-02 (R29, 2026-07-25) FIX: Sybil-resistance via IP/subnet layer.
	// Previously the blacklist keyed only on PeerID (SHA3-256 of Dilithium
	// public key). An attacker could simply rotate Dilithium3 keypairs to
	// generate fresh PeerIDs and immediately reconnect, bypassing any
	// temporary or permanent ban. The fix mirrors the per-peer map with
	// per-IP and per-/24-subnet maps so a Sybil attacker rotating
	// identities from the same IP range stays banned.
	//
	// Semantics:
	//   - IsBlacklistedWithIP(p, ip) returns true if any of {p, ip, /24(ip)} is banned.
	//   - AddWithIP/AddPermanentWithIP/AddWithDurationWithIP record entries
	//     in ALL THREE maps atomically under bl.mu.
	//   - Each map independently enforces maxSize via evictIfNeededLockedKind.
	//   - The peer map remains the source of truth for backward-compatible
	//     Add/IsBlacklisted; the IP/subnet maps are additive overlays.
	//   - Empty IP ("") is a no-op for the IP/subnet maps so legacy callers
	//     (e.g., tests that don't track remote addr) keep working.
	ips     map[string]*blacklistEntry // key = a literal IP address
	subnets map[string]*blacklistEntry // key = a /24 subnet

	// P2P-R11-M02 (2026-07-20) FIX: persistence for permanent + long-TTL bans.
	// Without this, a node restart clears the entire blacklist and every
	// previously-banned attacker can immediately reconnect. Operators opt in
	// by calling SetPersistencePath(path) once during startup; subsequent
	// Add/AddPermanent/AddWithDuration calls atomically rewrite the file.
	// Only entries with remaining TTL >= BlacklistPersistMinTTL are saved
	// (short bans would likely expire before the next restart anyway).
	persistencePath string
}

type blacklistEntry struct {
	reason    string
	expiresAt time.Time
	permanent bool
}

// blacklistKind identifies which map an entry lives in. Used by the
// persistence layer and the per-kind eviction helper.
type blacklistKind int

const (
	blacklistKindPeer   blacklistKind = iota // bl.peers
	blacklistKindIP                          // bl.ips
	blacklistKindSubnet                      // bl.subnets
)

// BlacklistPersistMinTTL is the minimum remaining TTL an entry must have
// to be included in a persistence snapshot. Short-lived bans (e.g., 60s
// rate-limit cooloffs) are not worth persisting — they would likely expire
// before the next restart.
const BlacklistPersistMinTTL = 1 * time.Hour

// NewBlacklist creates a new blacklist
func NewBlacklist() *Blacklist {
	bl := &Blacklist{
		peers:    make(map[PeerID]*blacklistEntry),
		duration: 24 * time.Hour,          // Default 24 hour ban
		maxSize:  DefaultMaxBlacklistSize, // audit-fix L-4
		stopCh:   make(chan struct{}),     // audit-fix M-5
		// P2P-C-02 (R29): IP/subnet layer for Sybil resistance.
		ips:     make(map[string]*blacklistEntry),
		subnets: make(map[string]*blacklistEntry),
	}

	// Start cleanup goroutine
	go bl.cleanup()

	return bl
}

// extractIPFromAddr parses a network address of the form "host:port" or
// "[ipv6]:port" and returns the bare IP string. Returns "" for empty input
// or unparseable addresses — callers treat "" as "no IP info available"
// and skip IP/subnet layer operations.
//
// P2P-C-02 (R29): used by the IP-aware Blacklist methods to derive the
// IP key from a peer's net.Conn.RemoteAddr() / Peer.Addr string.
func extractIPFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	// net.SplitHostPort handles "host:port", "[ipv6]:port", and bare host
	// gracefully. We intentionally do NOT use net.ParseIP on the full addr
	// because that fails for "host:port".
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Either no port (bare IP/hostname) or malformed. Try parsing the
		// whole string as an IP - succeeds for a literal IPv4 address or "::1".
		if ip := net.ParseIP(addr); ip != nil {
			return ip.String()
		}
		// Fall back to the raw string; callers that pass hostnames will
		// get harmless no-op entries (subnetKeyFromIP returns "" for
		// non-IP inputs, and the IP map simply stores the hostname).
		return addr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// subnetKeyFromIP returns the /24 (IPv4) or /64 (IPv6) CIDR key for the
// given IP string. Returns "" for empty/non-IP inputs so the caller can
// skip the subnet map. We deliberately use coarse /24 (not /16) to avoid
// banning an entire ISP behind a Carrier-Grade NAT — a /24 is small
// enough to confine a Sybil attacker to a single IP range while large
// enough to absorb dynamic-IP churn within one household.
//
// P2P-C-02 (R29): /24 for IPv4, /64 for IPv6 (the IPv6 equivalent of a
// single end-user allocation per RFC 6177).
func subnetKeyFromIP(ipStr string) string {
	if ipStr == "" {
		return ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		// /24 = first 3 octets + ".0/24"
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	// IPv6 /64: zero out the last 8 bytes.
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	masked := make(net.IP, 16)
	copy(masked, v6[:8])
	return fmt.Sprintf("%s/64", masked.String())
}

// evictExpiredLocked removes expired non-permanent entries. Must hold bl.mu.
//
// P2P-C-02 (R29): also prunes the ips and subnets maps so they don't
// leak memory under Sybil attacks that generate many short-TTL IP bans.
func (bl *Blacklist) evictExpiredLocked() {
	now := time.Now()
	for p, entry := range bl.peers {
		if !entry.permanent && now.After(entry.expiresAt) {
			delete(bl.peers, p)
		}
	}
	if bl.ips != nil {
		for ip, entry := range bl.ips {
			if !entry.permanent && now.After(entry.expiresAt) {
				delete(bl.ips, ip)
			}
		}
	}
	if bl.subnets != nil {
		for sn, entry := range bl.subnets {
			if !entry.permanent && now.After(entry.expiresAt) {
				delete(bl.subnets, sn)
			}
		}
	}
}

// evictIfNeededLocked enforces the maxSize bound by:
//  1. Calling evictExpiredLocked to remove expired non-permanent entries.
//  2. If still at or above maxSize, evicting non-permanent entries with the
//     LEAST remaining ban time first (closest to expiration), until size
//     drops to 90% of maxSize.
//  3. If no non-permanent entries remain (all entries are permanent),
//     the loop stops without deleting any — preserves the audit trail of
//     permanent bans.
//
// Returns true if there is now room for one more entry (i.e. the map
// size is strictly below maxSize, or maxSize is 0/unlimited). Returns
// false if the map is still at capacity after eviction (all entries are
// permanent).
//
// P2P-R11-L01 (2026-07-20) FIX: Extracted from Add/AddPermanent/AddWithDuration
// to eliminate the duplicated maxSize check + eviction logic. The previous
// code had three slightly different implementations:
//   - Add:               evictExpired + drop ONE non-permanent entry
//   - AddPermanent:      evictExpired + drop ONE non-permanent entry, else reject
//   - AddWithDuration:   evictExpired + loop to 90% threshold (P2P-R11-H05 fix)
//
// The unified version uses the most aggressive strategy (loop to 90%)
// for consistency, matching AddWithDuration's P2P-R11-H05 fix. The
// "reject if at capacity" decision is left to the caller (only AddPermanent
// rejects; Add and AddWithDuration fall through to overwrite-or-add,
// preserving their pre-refactor behavior).
//
// P2-BLACKLIST-EVICT FIX (R29, 2026-07-26): Previously, the eviction loop
// iterated over the map in Go's randomized order and deleted the first
// non-permanent entry it found. This meant a recently-added temporary ban
// (e.g., a 1-hour ban for a serious violation, applied 1 second ago) was
// equally likely to be evicted as an entry about to expire (e.g., a 5-minute
// ban applied 4 minutes and 59 seconds ago). Under high pressure (blacklist
// full of temporary bans), this could evict a legitimate, recently-applied
// ban to make room for a new entry, defeating the purpose of the ban.
//
// Fix: collect all non-permanent entries, sort them by expiresAt (ascending),
// and evict from the closest-to-expiration first. This minimizes the security
// impact of eviction — an entry that was going to expire in 5 seconds is
// "less harmful" to evict than one that was going to expire in 1 hour. The
// sort is O(n log n) but only runs when the blacklist is at capacity, which
// is rare in normal operation.
//
// Must hold bl.mu.
func (bl *Blacklist) evictIfNeededLocked() bool {
	if bl.maxSize == 0 || len(bl.peers) < bl.maxSize {
		return true
	}

	bl.evictExpiredLocked()
	// P2P-R11-H05: loop eviction to reach 90% threshold. If all entries
	// are permanent, the loop stops without deleting any.
	target := bl.maxSize * 9 / 10
	if target < 1 {
		target = 1
	}

	// P2-BLACKLIST-EVICT FIX (R29, 2026-07-26): Collect non-permanent entries
	// and sort by expiration time (ascending). Evict the ones closest to
	// expiration first — this minimizes the security impact of eviction.
	// A ban that was going to expire in 5 seconds is "less harmful" to evict
	// than one that was going to expire in 1 hour, because the 5-second ban
	// would have stopped protecting the network almost immediately anyway.
	//
	// Previously, the eviction used Go's randomized map iteration order,
	// which could evict a recently-added long ban to make room for a new
	// entry — defeating the purpose of the long ban.
	if len(bl.peers) >= target {
		type entry struct {
			id        PeerID
			expiresAt time.Time
		}
		candidates := make([]entry, 0, len(bl.peers))
		for id, e := range bl.peers {
			if !e.permanent {
				candidates = append(candidates, entry{id: id, expiresAt: e.expiresAt})
			}
		}
		// Sort by expiresAt ascending (earliest expiration first).
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].expiresAt.Before(candidates[j].expiresAt)
		})
		// Evict from the front (closest to expiration) until we reach target.
		for _, c := range candidates {
			if len(bl.peers) < target {
				break
			}
			delete(bl.peers, c.id)
		}
	}
	return len(bl.peers) < bl.maxSize
}

// evictStringMapLocked enforces the same maxSize bound on a string-keyed
// map (ips or subnets). Same eviction policy as evictIfNeededLocked: drop
// expired entries first, then evict non-permanent entries with the least
// remaining ban time first, never delete permanent entries.
//
// P2P-C-02 (R29): the ips/subnets maps would otherwise grow unbounded
// under a Sybil attack that bans thousands of unique IPs from one /24
// (or thousands of /24s from one ASN). Each map enforces maxSize
// independently — an attacker cannot exhaust the IP map and thereby
// disable the subnet map (or vice versa).
//
// P2-BLACKLIST-EVICT FIX (R29, 2026-07-26): Same fix as evictIfNeededLocked —
// sort non-permanent entries by expiration time and evict the ones closest
// to expiration first, rather than using Go's randomized map iteration order.
// This prevents a recently-applied long IP/subnet ban from being evicted to
// make room for a new entry.
//
// Must hold bl.mu. The caller is responsible for having called
// evictExpiredLocked() first if it wants expired entries pruned; this
// helper does call evictExpiredLocked() defensively to be safe when
// invoked standalone.
func (bl *Blacklist) evictStringMapLocked(m map[string]*blacklistEntry) bool {
	if bl.maxSize == 0 || len(m) < bl.maxSize {
		return true
	}
	// Prune expired entries from THIS map only (evictExpiredLocked walks
	// all three maps, which is fine but redundant when called from the
	// per-map helper; the redundancy is harmless).
	now := time.Now()
	for k, e := range m {
		if !e.permanent && now.After(e.expiresAt) {
			delete(m, k)
		}
	}
	target := bl.maxSize * 9 / 10
	if target < 1 {
		target = 1
	}

	// P2-BLACKLIST-EVICT FIX (R29, 2026-07-26): Same expiration-time-based
	// eviction as evictIfNeededLocked. Sort non-permanent entries by expiresAt
	// (ascending) and evict the closest-to-expiration first.
	if len(m) >= target {
		type entry struct {
			key       string
			expiresAt time.Time
		}
		candidates := make([]entry, 0, len(m))
		for k, e := range m {
			if !e.permanent {
				candidates = append(candidates, entry{key: k, expiresAt: e.expiresAt})
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].expiresAt.Before(candidates[j].expiresAt)
		})
		for _, c := range candidates {
			if len(m) < target {
				break
			}
			delete(m, c.key)
		}
	}
	return len(m) < bl.maxSize
}

// Add adds a peer to the blacklist
func (bl *Blacklist) Add(p PeerID, reason string) {
	// audit-fix H-4: Validate reason to prevent injection/logging issues
	reason = validateBlacklistReason(reason)

	bl.mu.Lock()
	// P2P-R11-L01 FIX: use shared evictIfNeededLocked() instead of
	// inlined maxSize + eviction logic.
	bl.evictIfNeededLocked()

	bl.peers[p] = &blacklistEntry{
		reason:    reason,
		expiresAt: time.Now().Add(bl.duration),
		permanent: false,
	}
	bl.mu.Unlock()
	// P2P-R11-M02: persist outside the lock to minimize contention. The
	// save path takes its own RLock and re-reads the map.
	bl.savePersistence()
}

// AddPermanent adds a peer to the blacklist permanently
//
// RPC-R9-H1 (2026-07-19) FIX: Previously this method did NOT enforce maxSize,
// allowing an attacker (or buggy caller) to add unlimited permanent entries
// and exhaust memory. The `Add` method already enforced maxSize, but
// `AddPermanent` and `AddWithDuration` bypassed it. Now all three Add paths
// enforce the same maxSize bound via the shared evictIfNeededLocked():
//  1. First evict expired entries.
//  2. If still at capacity, drop non-permanent entries down to 90% threshold.
//  3. If all entries are permanent and at capacity, reject the new addition
//     (return without storing) and log a warning so operators notice the
//     pattern. Silently accepting would unbound the map; erroring out would
//     break callers that don't check the return value.
func (bl *Blacklist) AddPermanent(p PeerID, reason string) {
	// audit-fix H-4: Validate reason to prevent injection/logging issues
	reason = validateBlacklistReason(reason)

	bl.mu.Lock()
	// RPC-R9-H1 + P2P-R11-L01 FIX: enforce maxSize via shared helper.
	// If this peer is already in the list, we're updating not adding —
	// skip the capacity check.
	if _, exists := bl.peers[p]; !exists {
		if !bl.evictIfNeededLocked() {
			// All entries are permanent and at capacity.
			// Reject the addition to keep the map bounded.
			log.Printf("[SECURITY] Blacklist: AddPermanent rejected for peer %s — at capacity (%d permanent entries)",
				p, len(bl.peers))
			bl.mu.Unlock()
			return
		}
	}

	bl.peers[p] = &blacklistEntry{
		reason:    reason,
		permanent: true,
	}
	bl.mu.Unlock()
	// P2P-R11-M02: persist permanent bans (most critical to survive restart).
	bl.savePersistence()
}

// AddWithDuration adds a peer to the blacklist for a specific duration
//
// RPC-R9-H1 (2026-07-19) FIX: Same maxSize enforcement as AddPermanent —
// previously bypassed the bound, allowing unlimited timed entries.
//
// RPC-R9-M (2026-07-19) FIX: Cap `duration` at 1 year. time.Time internally
// stores an int64 nanosecond offset from year 1; values close to
// math.MaxInt64 ns (~292 years) cause time.Now().Add(duration) to overflow
// past year 2255 or wrap into the far past — either way the resulting
// expiresAt no longer matches the caller's intent and the entry behaves
// unpredictably (e.g. immediately expired, or never expired relative to a
// wall-clock check that uses monotonic time). 1 year is well above any sane
// temporary ban while staying far from the int64 overflow boundary.
//
// P2P-R11-H05 (2026-07-20) FIX: Previously this block only deleted ONE
// non-permanent entry per Add call, even when the blacklist was full of
// permanent or long-TTL entries. An attacker filling the blacklist with
// permanent entries would prevent new malicious peers from being added,
// effectively disabling rate limiting for the rest of the attack.
// Now uses the shared evictIfNeededLocked() which loops deletion until
// size drops to 90% of maxSize.
func (bl *Blacklist) AddWithDuration(p PeerID, reason string, duration time.Duration) {
	// audit-fix H-4: Validate reason to prevent injection/logging issues
	reason = validateBlacklistReason(reason)

	// RPC-R9-M FIX: Cap duration to prevent time.Time overflow.
	const maxBlacklistDuration = 365 * 24 * time.Hour
	if duration > maxBlacklistDuration {
		duration = maxBlacklistDuration
	} else if duration < 0 {
		// Negative durations make no sense for a ban — normalize to 0 so the
		// entry expires immediately and the next cleanup pass removes it.
		duration = 0
	}

	bl.mu.Lock()
	// P2P-R11-L01 FIX: use shared evictIfNeededLocked() instead of inlined
	// maxSize + eviction loop. If the peer already exists, this is an
	// update — skip the capacity check.
	if _, exists := bl.peers[p]; !exists {
		bl.evictIfNeededLocked()
	}

	bl.peers[p] = &blacklistEntry{
		reason:    reason,
		expiresAt: time.Now().Add(duration),
		permanent: false,
	}
	bl.mu.Unlock()
	// P2P-R11-M02: persist if the entry will outlive BlacklistPersistMinTTL.
	if duration >= BlacklistPersistMinTTL {
		bl.savePersistence()
	}
}

// AddWithIP adds a peer AND its IP / /24 subnet to the blacklist, using
// the default ban duration (24h). All three entries are stored atomically
// under bl.mu so a check via IsBlacklistedWithIP observes a consistent
// state.
//
// P2P-C-02 (R29): Sybil resistance. Without the IP/subnet layer an
// attacker could rotate Dilithium3 keypairs to mint fresh PeerIDs and
// bypass any peer-only ban in microseconds. Banning the IP closes the
// trivial rotation path; banning the /24 subnet additionally covers the
// case where the attacker has a small block of IPs (e.g., a /24 from a
// compromised VPS) but cannot easily move to a different ASN.
//
// Empty `ip` is a no-op for the IP/subnet layer (legacy callers without
// remote-addr tracking still get peer-only behavior, matching the
// pre-fix semantics).
func (bl *Blacklist) AddWithIP(p PeerID, ip, reason string) {
	bl.AddWithDurationWithIP(p, ip, reason, bl.duration)
}

// AddPermanentWithIP adds a peer AND its IP / /24 subnet permanently.
// See AddWithIP for the Sybil-resistance rationale. If the IP map is at
// capacity (all permanent), the IP entry is rejected with a warning —
// the peer entry is still recorded so IsBlacklisted(p) keeps working.
func (bl *Blacklist) AddPermanentWithIP(p PeerID, ip, reason string) {
	reason = validateBlacklistReason(reason)
	ipKey := extractIPFromAddr(ip)
	snKey := subnetKeyFromIP(ipKey)

	bl.mu.Lock()
	// Peer map: same maxSize enforcement as AddPermanent.
	if _, exists := bl.peers[p]; !exists {
		if !bl.evictIfNeededLocked() {
			log.Printf("[SECURITY] Blacklist: AddPermanentWithIP rejected peer entry for %s — at capacity (%d permanent entries)",
				p, len(bl.peers))
		} else {
			bl.peers[p] = &blacklistEntry{reason: reason, permanent: true}
		}
	} else {
		bl.peers[p] = &blacklistEntry{reason: reason, permanent: true}
	}
	// IP map: independent maxSize. Always overwrite if exists; otherwise evict.
	if ipKey != "" {
		if _, exists := bl.ips[ipKey]; !exists {
			if bl.evictStringMapLocked(bl.ips) {
				bl.ips[ipKey] = &blacklistEntry{reason: reason, permanent: true}
			} else {
				log.Printf("[SECURITY] Blacklist: AddPermanentWithIP rejected IP entry %s — at capacity", ipKey)
			}
		} else {
			bl.ips[ipKey] = &blacklistEntry{reason: reason, permanent: true}
		}
	}
	// Subnet map: same as IP map. Empty snKey (non-IP input) is skipped.
	if snKey != "" {
		if _, exists := bl.subnets[snKey]; !exists {
			if bl.evictStringMapLocked(bl.subnets) {
				bl.subnets[snKey] = &blacklistEntry{reason: reason, permanent: true}
			} else {
				log.Printf("[SECURITY] Blacklist: AddPermanentWithIP rejected subnet entry %s — at capacity", snKey)
			}
		} else {
			bl.subnets[snKey] = &blacklistEntry{reason: reason, permanent: true}
		}
	}
	bl.mu.Unlock()
	bl.savePersistence()
}

// AddWithDurationWithIP adds a peer AND its IP / /24 subnet for a
// specific duration. See AddWithIP for the Sybil-resistance rationale.
func (bl *Blacklist) AddWithDurationWithIP(p PeerID, ip, reason string, duration time.Duration) {
	reason = validateBlacklistReason(reason)
	const maxBlacklistDuration = 365 * 24 * time.Hour
	if duration > maxBlacklistDuration {
		duration = maxBlacklistDuration
	} else if duration < 0 {
		duration = 0
	}
	ipKey := extractIPFromAddr(ip)
	snKey := subnetKeyFromIP(ipKey)
	expiresAt := time.Now().Add(duration)

	bl.mu.Lock()
	// Peer map.
	if _, exists := bl.peers[p]; !exists {
		bl.evictIfNeededLocked()
	}
	bl.peers[p] = &blacklistEntry{reason: reason, expiresAt: expiresAt, permanent: false}
	// IP map.
	if ipKey != "" {
		if _, exists := bl.ips[ipKey]; !exists {
			bl.evictStringMapLocked(bl.ips)
		}
		bl.ips[ipKey] = &blacklistEntry{reason: reason, expiresAt: expiresAt, permanent: false}
	}
	// Subnet map.
	if snKey != "" {
		if _, exists := bl.subnets[snKey]; !exists {
			bl.evictStringMapLocked(bl.subnets)
		}
		bl.subnets[snKey] = &blacklistEntry{reason: reason, expiresAt: expiresAt, permanent: false}
	}
	bl.mu.Unlock()
	if duration >= BlacklistPersistMinTTL {
		bl.savePersistence()
	}
}

// Remove removes a peer from the blacklist
func (bl *Blacklist) Remove(p PeerID) {
	bl.mu.Lock()
	delete(bl.peers, p)
	bl.mu.Unlock()
	// P2P-R11-M02: keep persistence file in sync with removals so a restart
	// does not resurrect an entry an operator just cleared.
	bl.savePersistence()
}

// RemoveWithIP removes a peer AND its IP / /24 subnet entries.
//
// P2P-C-02 (R29): when an operator-driven removal happens (e.g., peer is
// whitelisted, or the ban was a false positive), we must clear all three
// layers — otherwise the peer can immediately reconnect from the same IP
// but be rejected again because the IP/subnet entry is still active.
//
// Note: this does NOT remove the IP/subnet entries if OTHER peers from
// the same IP/subnet are still banned. Tracking "how many peers per IP
// are banned" would require a secondary index and is not worth the
// complexity — operators can call RemoveIP explicitly for that case.
func (bl *Blacklist) RemoveWithIP(p PeerID, ip string) {
	ipKey := extractIPFromAddr(ip)
	snKey := subnetKeyFromIP(ipKey)
	bl.mu.Lock()
	delete(bl.peers, p)
	if ipKey != "" {
		delete(bl.ips, ipKey)
	}
	if snKey != "" {
		delete(bl.subnets, snKey)
	}
	bl.mu.Unlock()
	bl.savePersistence()
}

// RemoveIP removes an IP entry (and its /24 subnet entry) from the
// blacklist, leaving any per-peer entries intact. Useful for operators
// who want to un-ban a specific IP without lifting peer-level bans.
//
// P2P-C-02 (R29): exposed as a public method so operators have an escape
// hatch when an IP ban inadvertently affects a legitimate user sharing
// the same /24 (e.g., a university dorm NAT).
func (bl *Blacklist) RemoveIP(ip string) {
	ipKey := extractIPFromAddr(ip)
	if ipKey == "" {
		return
	}
	snKey := subnetKeyFromIP(ipKey)
	bl.mu.Lock()
	delete(bl.ips, ipKey)
	if snKey != "" {
		delete(bl.subnets, snKey)
	}
	bl.mu.Unlock()
	bl.savePersistence()
}

// IsBlacklisted checks if a peer is blacklisted
func (bl *Blacklist) IsBlacklisted(p PeerID) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	entry, exists := bl.peers[p]
	if !exists {
		return false
	}

	if entry.permanent {
		return true
	}

	return time.Now().Before(entry.expiresAt)
}

// IsBlacklistedWithIP checks if a peer OR its IP OR its /24 subnet is
// blacklisted. Returns true if ANY of the three layers has an active
// (non-expired) entry.
//
// P2P-C-02 (R29): this is the Sybil-resistant variant of IsBlacklisted.
// Callers that have access to the peer's remote address SHOULD use this
// method instead of IsBlacklisted — otherwise an attacker rotating
// PeerIDs will pass the peer-only check while the IP/subnet entries sit
// unused.
//
// Empty `ip` falls back to peer-only check (same as IsBlacklisted).
func (bl *Blacklist) IsBlacklistedWithIP(p PeerID, ip string) bool {
	ipKey := extractIPFromAddr(ip)
	snKey := subnetKeyFromIP(ipKey)
	now := time.Now()

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	// Layer 1: peer.
	if entry, exists := bl.peers[p]; exists {
		if entry.permanent || now.Before(entry.expiresAt) {
			return true
		}
	}
	// Layer 2: IP. Empty ipKey = no IP info, skip.
	if ipKey != "" {
		if entry, exists := bl.ips[ipKey]; exists {
			if entry.permanent || now.Before(entry.expiresAt) {
				return true
			}
		}
	}
	// Layer 3: /24 subnet. Empty snKey = non-IP input, skip.
	if snKey != "" {
		if entry, exists := bl.subnets[snKey]; exists {
			if entry.permanent || now.Before(entry.expiresAt) {
				return true
			}
		}
	}
	return false
}

// GetReason returns the reason for blacklisting
func (bl *Blacklist) GetReason(p PeerID) string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	entry, exists := bl.peers[p]
	if !exists {
		return ""
	}
	return entry.reason
}

// List returns all blacklisted peers
func (bl *Blacklist) List() []PeerID {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	now := time.Now()
	result := make([]PeerID, 0, len(bl.peers))

	for p, entry := range bl.peers {
		if entry.permanent || now.Before(entry.expiresAt) {
			result = append(result, p)
		}
	}

	return result
}

// Stop stops the blacklist's background cleanup goroutine.
// audit-fix M-5: prevents goroutine leak.
// audit-fix CRIT-3: use sync.Once to prevent panic on double-close.
func (bl *Blacklist) Stop() {
	bl.stopOnce.Do(func() {
		close(bl.stopCh)
	})
}

// cleanup periodically removes expired entries.
//
// RPC-R9-M (2026-07-19) FIX: Previously the cleanup interval was hard-coded
// to 1 hour regardless of blacklist size. Under a short-burst DoS (e.g.
// attacker registers thousands of 1-minute bans), expired entries would
// linger in memory for up to 1 hour, holding the map at DefaultMaxBlacklistSize
// and blocking Add/IsBlacklisted callers (which acquire bl.mu for each op).
// Now the interval scales down as the map grows: a near-empty map still
// cleans up hourly, but a near-full map cleans up every minute so the
// inlined eviction path in Add/AddPermanent is rarely the only defense.
func (bl *Blacklist) cleanup() {
	const (
		minInterval = time.Minute
		maxInterval = time.Hour
		// Threshold above which we shorten the interval. Picked as 10% of
		// DefaultMaxBlacklistSize so the slowdown kicks in well before the
		// hard cap is reached.
		shrinkThreshold = DefaultMaxBlacklistSize / 10
	)

	interval := maxInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in Blacklist.cleanup: %v", r)
		}
	}()

	for {
		select {
		case <-ticker.C:
			bl.mu.Lock()
			now := time.Now()
			for p, entry := range bl.peers {
				if !entry.permanent && now.After(entry.expiresAt) {
					delete(bl.peers, p)
				}
			}
			// P2P-C-02 (R29): prune the IP/subnet maps so they don't leak
			// memory between Add-time evictions (which only run when a map
			// is at capacity). Without this, expired IP/subnet entries
			// could linger until the next Add fills the map.
			if bl.ips != nil {
				for ip, entry := range bl.ips {
					if !entry.permanent && now.After(entry.expiresAt) {
						delete(bl.ips, ip)
					}
				}
			}
			if bl.subnets != nil {
				for sn, entry := range bl.subnets {
					if !entry.permanent && now.After(entry.expiresAt) {
						delete(bl.subnets, sn)
					}
				}
			}
			size := len(bl.peers)
			bl.mu.Unlock()

			// Resize next interval based on observed size.
			newInterval := maxInterval
			if size >= shrinkThreshold {
				// Linear scale: at shrinkThreshold → 1h, at DefaultMaxBlacklistSize → ~6min.
				// Avoids overflow and stays well above the 10-second minimum.
				ratio := float64(size) / float64(DefaultMaxBlacklistSize)
				newInterval = time.Duration(float64(maxInterval) * (1.0 - 0.9*ratio))
				if newInterval < minInterval {
					newInterval = minInterval
				}
			}
			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
			}
		case <-bl.stopCh:
			return
		}
	}
}

// blacklistPersistRecord is the JSON shape of a single persisted entry.
// We do not persist the in-memory blacklistEntry directly because its
// expiresAt field uses time.Time which serializes awkwardly across
// monotonic-clock resets; persisting UnixNano is unambiguous.
//
// P2P-C-02 (R29): added Kind/Key fields to persist IP and subnet entries
// alongside peer entries. Legacy files (Kind="" or absent) are treated
// as Kind="peer" for backward compatibility — a node upgrading from an
// older version will simply re-load its peer bans on first start, then
// start persisting IP/subnet bans from new Add*WithIP calls.
type blacklistPersistRecord struct {
	Kind      string `json:"kind,omitempty"` // "peer" (default) | "ip" | "subnet"
	Key       string `json:"key"`            // peer ID / IP / subnet CIDR
	Reason    string `json:"reason"`
	ExpiresAt int64  `json:"expires_at"` // UnixNano; 0 for permanent
	Permanent bool   `json:"permanent"`

	// Peer is kept for backward-compat with old persistence files. New
	// writers always populate Key; Peer is mirrored from Key when Kind
	// is "peer" or empty. Old loaders read Peer when Key is empty.
	Peer string `json:"peer,omitempty"`
}

const (
	blacklistPersistKindPeer   = "peer"
	blacklistPersistKindIP     = "ip"
	blacklistPersistKindSubnet = "subnet"
)

// SetPersistencePath opts the Blacklist into persisting permanent + long-TTL
// bans to the given file path. After this call returns, every Add/AddPermanent/
// AddWithDuration (with TTL >= BlacklistPersistMinTTL)/Remove rewrites the
// file atomically (temp file + rename). The method also loads any existing
// persistence file at the given path so callers should invoke it AFTER the
// data directory is writable but BEFORE the host starts accepting connections.
//
// P2P-R11-M02 (2026-07-20) FIX: previously the blacklist lived only in
// memory; a node restart cleared all bans, allowing attackers to reconnect
// immediately. The fix is opt-in so existing tests (which construct a
// Blacklist via NewBlacklist) are unaffected.
//
// Errors: if the file does not exist, the load is silently skipped (first
// run). If the file exists but is corrupt, the load logs a warning and the
// blacklist starts empty — a corrupt persistence file must not block node
// startup.
func (bl *Blacklist) SetPersistencePath(path string) error {
	bl.mu.Lock()
	bl.persistencePath = path
	bl.mu.Unlock()

	if path == "" {
		return nil
	}
	return bl.loadPersistence()
}

// loadPersistence reads the persistence file at bl.persistencePath and merges
// its entries into bl.peers. Existing entries are preserved (in-memory wins
// over on-disk to honor operator-driven removals during the prior session).
// Caller MUST NOT hold bl.mu.
func (bl *Blacklist) loadPersistence() error {
	if bl.persistencePath == "" {
		return nil
	}
	data, err := os.ReadFile(bl.persistencePath)
	if err != nil {
		if os.IsNotExist(err) {
			// First run — nothing to load.
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var records []blacklistPersistRecord
	if err := json.Unmarshal(data, &records); err != nil {
		log.Printf("[WARN] Blacklist: failed to parse persistence file %s: %v (starting with empty blacklist)",
			bl.persistencePath, err)
		return nil
	}

	now := time.Now()
	bl.mu.Lock()
	defer bl.mu.Unlock()
	for _, rec := range records {
		// P2P-C-02 (R29): determine the kind. Legacy records (Kind="" and
		// non-empty Peer) are treated as peer records. New records always
		// populate Key and Kind.
		kind := rec.Kind
		key := rec.Key
		if kind == "" {
			kind = blacklistPersistKindPeer
		}
		if key == "" {
			// Backward compat: old files only had Peer.
			key = rec.Peer
		}
		if key == "" {
			continue
		}

		entry := &blacklistEntry{
			reason:    rec.Reason,
			permanent: rec.Permanent,
		}
		if !rec.Permanent {
			entry.expiresAt = time.Unix(0, rec.ExpiresAt)
			// Skip entries that already expired while the node was offline.
			if now.After(entry.expiresAt) {
				continue
			}
		}

		switch kind {
		case blacklistPersistKindPeer:
			// Skip entries already in memory (operator may have re-added them
			// with different parameters during this session).
			if _, exists := bl.peers[PeerID(key)]; exists {
				continue
			}
			bl.peers[PeerID(key)] = entry
		case blacklistPersistKindIP:
			if bl.ips == nil {
				bl.ips = make(map[string]*blacklistEntry)
			}
			if _, exists := bl.ips[key]; exists {
				continue
			}
			bl.ips[key] = entry
		case blacklistPersistKindSubnet:
			if bl.subnets == nil {
				bl.subnets = make(map[string]*blacklistEntry)
			}
			if _, exists := bl.subnets[key]; exists {
				continue
			}
			bl.subnets[key] = entry
		}
	}
	return nil
}

// savePersistence writes a snapshot of permanent + long-TTL entries to
// bl.persistencePath atomically (temp file + rename). Caller MUST NOT hold
// bl.mu. No-op when persistencePath is empty (the common case for tests and
// nodes that have not opted in).
//
// Errors are logged but not returned: a write failure does not block the
// caller's Add/Remove — the in-memory state is authoritative. The next
// successful save will pick up the change.
func (bl *Blacklist) savePersistence() {
	if bl.persistencePath == "" {
		return
	}

	now := time.Now()
	bl.mu.RLock()
	// P2P-C-02 (R29): include IP and subnet entries so a restart also
	// restores the Sybil-resistance layer. Capacity is sized for the
	// peer map (the largest of the three under normal operation).
	records := make([]blacklistPersistRecord, 0, len(bl.peers)+len(bl.ips)+len(bl.subnets))

	// Helper closure: appends a record if it meets the persistence
	// criteria (permanent, or non-permanent with remaining TTL >=
	// BlacklistPersistMinTTL).
	addRecord := func(kind, key string, entry *blacklistEntry) {
		if entry.permanent {
			records = append(records, blacklistPersistRecord{
				Kind:      kind,
				Key:       key,
				Reason:    entry.reason,
				Permanent: true,
			})
			return
		}
		// Skip entries that have already expired (don't resurrect them).
		if now.After(entry.expiresAt) {
			return
		}
		// Skip short-TTL entries — they would likely expire before the
		// next restart anyway, and writing them to disk on every Add
		// amplifies I/O during DoS attacks.
		remaining := entry.expiresAt.Sub(now)
		if remaining < BlacklistPersistMinTTL {
			return
		}
		records = append(records, blacklistPersistRecord{
			Kind:      kind,
			Key:       key,
			Reason:    entry.reason,
			ExpiresAt: entry.expiresAt.UnixNano(),
			Permanent: false,
		})
	}

	for p, entry := range bl.peers {
		addRecord(blacklistPersistKindPeer, string(p), entry)
	}
	for ip, entry := range bl.ips {
		addRecord(blacklistPersistKindIP, ip, entry)
	}
	for sn, entry := range bl.subnets {
		addRecord(blacklistPersistKindSubnet, sn, entry)
	}
	bl.mu.RUnlock()

	// Marshal outside the lock to minimize contention.
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		log.Printf("[WARN] Blacklist: failed to marshal persistence snapshot: %v", err)
		return
	}

	// Atomic write: temp file in the same directory, then rename. Rename
	// is atomic on POSIX; on Windows it is atomic as long as the target
	// does not exist (we use os.WriteFile + os.Rename which works in
	// practice — a crash leaves the temp file, which is harmless).
	dir := filepath.Dir(bl.persistencePath)
	tmp, err := os.CreateTemp(dir, ".blacklist-*.tmp")
	if err != nil {
		// Directory may not exist yet (e.g., fresh data dir). Try once
		// to create it, then retry.
		if mkErr := os.MkdirAll(dir, 0o700); mkErr == nil {
			tmp, err = os.CreateTemp(dir, ".blacklist-*.tmp")
		}
	}
	if err != nil {
		log.Printf("[WARN] Blacklist: failed to create temp persistence file: %v", err)
		return
	}
	tmpName := tmp.Name()
	// Always remove the temp file if we exit early via a write/rename error.
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		log.Printf("[WARN] Blacklist: failed to write persistence file: %v", err)
		return
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		log.Printf("[WARN] Blacklist: failed to close persistence temp file: %v", err)
		return
	}
	if err := os.Rename(tmpName, bl.persistencePath); err != nil {
		cleanup()
		log.Printf("[WARN] Blacklist: failed to rename persistence temp file: %v", err)
		return
	}
}

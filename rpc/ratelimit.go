// Quantaureum Node source, version 1.0.0.
// Package rpc provides JSON-RPC 2.0 server with rate limiting.
package rpc

import (
	"hash/fnv"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	// Enable rate limiting
	Enabled bool

	// Global rate limit (requests per second)
	GlobalRateLimit int

	// Per-IP rate limit (requests per second)
	PerIPRateLimit int

	// Per-method rate limits (method -> requests per second)
	PerMethodRateLimit map[string]int

	// Burst size (allows temporary bursts above rate limit)
	BurstSize int

	// Window duration for rate calculation
	Window time.Duration

	// Cleanup interval for old entries
	CleanupInterval time.Duration

	// Ban duration when rate limit exceeded multiple times
	BanDuration time.Duration

	// Number of violations before ban
	ViolationsBeforeBan int

	// audit-fix R2-L2: MaxTrackedIPs caps the ipLimits map to prevent OOM
	// under distributed DDoS with millions of unique source IPs.
	MaxTrackedIPs int

	// audit-fix INFO-2: TrustedProxies allows the rate limiter to extract
	// the real client IP via X-Forwarded-For when behind trusted proxies.
	TrustedProxies []string

	// R107-LOCAL-FANOUT (2026-09-04): ExemptIPs lists IPs / CIDRs that are
	// exempt from the *per-IP* bucket (and therefore from the violation ban).
	// The global limit and the per-method limits still apply, so an exempt
	// caller can never monopolise the node beyond GlobalRateLimit.
	//
	// Why this exists: on a validator that also hosts a co-located service
	// (the block explorer front-end talking to 127.0.0.1:8545), every request
	// from that service shares one bucket. A single page view that fans out
	// into a few hundred eth_getBlockByNumber calls therefore empties the
	// 100 req/s bucket, and 10 such empties ban 127.0.0.1 for BanDuration —
	// which takes the whole explorer to zero until the process is restarted.
	//
	// This is deliberately opt-in and NOT defaulted to loopback: when the node
	// sits behind a TLS-terminating reverse proxy it binds RPC to 127.0.0.1 and
	// *all* public traffic arrives from 127.0.0.1, so a loopback default would
	// silently disable per-IP limiting for the entire internet. Operators of
	// that topology should instead set TrustedProxies so real client IPs are
	// attributed, and leave ExemptIPs empty.
	ExemptIPs []string
}

// DefaultCleanupCutoffAge is the default age after which stale rate-limit
// entries are eligible for cleanup.  previously hardcoded as 5 minutes
// inline in cleanup(); extracted to a named constant for visibility and tuning.
const DefaultCleanupCutoffAge = 5 * time.Minute

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		Enabled:         true,
		GlobalRateLimit: 1000, // 1000 requests per second globally
		// L14-041 NOTE: PerIPRateLimit (100 req/s) applies uniformly to all
		// methods. This is adequate for read-only queries but too high for
		// compute-intensive methods (eth_call, eth_estimateGas). Those are
		// additionally constrained by PerMethodRateLimit (20 req/s) above.
		PerIPRateLimit: 100, // 100 requests per second per IP
		PerMethodRateLimit: map[string]int{
			// L15-018 FIX: Compute-intensive methods get a stricter rate limit
			// (20 req/s) to prevent abuse. These methods involve EVM execution
			// and are significantly more expensive than read-only queries.
			"eth_call":        20,
			"eth_estimateGas": 20,

			// R32-P3-02 FIX (2026-07-28): Extended method-level rate limiting
			// to cover transaction submission, security-sensitive operations,
			// and heavy query methods. Previously only eth_call and
			// eth_estimateGas had per-method limits; all other methods
			// relied solely on per-IP (100 req/s) and global (1000 req/s)
			// limits, which is too permissive for the following categories.

			// Transaction submission (10 req/s): prevents tx flooding where
			// an attacker spams the mempool with low-fee transactions to
			// fill blocks and starve legitimate users. 10 req/s per IP is
			// well above legitimate wallet usage (1-2 tx/s) but catches
			// automated flooding.
			"eth_sendRawTransaction": 10,
			"eth_sendTransaction":    10,

			// Heavy query methods (10 req/s): eth_getLogs can scan large
			// block ranges, consuming significant CPU and I/O. An attacker
			// can abuse this to degrade node performance with broad queries.
			"eth_getLogs": 10,

			// Security-sensitive key operations (2-5 req/s): these methods
			// handle private key material and should be called rarely.
			// A high rate indicates either a bug in the caller or an
			// attack attempting to brute-force key import/unlock.
			"personal_importRawKey":        2,
			"personal_unlockAccount":       5,
			"qau_signQuantumTransaction":   5,  // Dilithium3 signing is CPU-intensive
			"qau_verifyQuantumTransaction": 10, // Dilithium3 verification is CPU-intensive
		},
		BurstSize:           50, // Allow bursts of 50 requests
		Window:              time.Second,
		CleanupInterval:     time.Minute,
		BanDuration:         time.Hour,
		ViolationsBeforeBan: 10,
		MaxTrackedIPs:       100000, // audit-fix R2-L2
	}
}

// rateLimitEntry tracks rate limit state for an IP
// S1 FIX (2026-07-06): float64 tokens have more than sufficient precision for
// the rate ranges involved (50-1000 tokens). At 1000 req/s for 1 hour,
// accumulated tokens = 3.6M, which float64 tracks with ~10 decimal digits of
// precision — far exceeding the 1-token granularity needed. The burst cap
// also prevents unbounded accumulation. No integer refactor needed.
type rateLimitEntry struct {
	tokens      float64   // Current token count
	lastUpdate  time.Time // Last token update time
	violations  int       // Number of rate limit violations
	bannedUntil time.Time // Ban expiration time
}

// RateLimiter implements token bucket rate limiting
// R20-M8 FIX: Uses sharded IP tracking to reduce mutex contention under high concurrency.
type RateLimiter struct {
	mu     sync.RWMutex
	config *RateLimitConfig

	// R107-LOCAL-FANOUT: parsed form of config.ExemptIPs, rebuilt whenever the
	// config changes so the hot path never parses strings. Guarded by mu.
	exemptIPs  []net.IP
	exemptNets []*net.IPNet

	// Per-IP rate limiting - sharded to reduce lock contention
	// R20-M8 FIX: 16 shards reduce contention by distributing IP lookups
	ipShards   [16]map[string]*rateLimitEntry
	ipShardsMu [16]sync.Mutex

	// Global rate limiting
	// FIX: Dedicated mutex for global token bucket to avoid serializing
	// all requests through the shared rl.mu. Global, per-IP, and per-method
	// checks can now proceed concurrently.
	globalMu         sync.Mutex
	globalTokens     float64
	globalLastUpdate time.Time

	// Per-method rate limiting
	methodLimits map[string]*rateLimitEntry

	// Running state
	running  bool
	stopCh   chan struct{}
	stopOnce sync.Once // MEDIUM FIX: prevent double-close panic and Stop/Start race
}

// shardIndex returns the shard index for a given IP
// R25-H6 FIX: Use FNV hashing for better distribution across shards
// The previous hash function had uneven distribution for certain IP patterns
func (rl *RateLimiter) shardIndex(ip string) uint8 {
	fnvHash := fnv.New64a()
	fnvHash.Write([]byte(ip)) // #nosec G104 -- fnv.Hash.Write never returns an error //nolint:errcheck
	// ipShards has fixed size of 16 (defined as [16]map[string]*rateLimitEntry)
	return uint8(fnvHash.Sum64() % 16) //nolint:gosec,G115
}

// getOrCreateIPEntry gets or creates a rate limit entry for an IP using sharded locking
func (rl *RateLimiter) getOrCreateIPEntry(ip string, now time.Time) *rateLimitEntry {
	shardIdx := rl.shardIndex(ip)
	rl.ipShardsMu[shardIdx].Lock()
	defer rl.ipShardsMu[shardIdx].Unlock()

	entry, exists := rl.ipShards[shardIdx][ip]
	if !exists {
		entry = &rateLimitEntry{
			tokens:     float64(rl.config.BurstSize),
			lastUpdate: now,
		}
		rl.ipShards[shardIdx][ip] = entry
	}
	return entry
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	rl := &RateLimiter{
		config:           config,
		globalTokens:     float64(config.BurstSize),
		globalLastUpdate: time.Now(),
		methodLimits:     make(map[string]*rateLimitEntry),
		stopCh:           make(chan struct{}),
	}
	rl.exemptIPs, rl.exemptNets = parseExemptIPs(config.ExemptIPs)

	// R20-M8 FIX: Initialize sharded IP maps and mutexes directly on the struct
	// to avoid copying sync.Mutex values (go vet copylocks check).
	for i := range rl.ipShards {
		rl.ipShards[i] = make(map[string]*rateLimitEntry)
	}

	return rl
}

// Start starts the rate limiter cleanup goroutine.
// audit-fix  re-creates stopCh so the limiter can be stopped and restarted.
// MEDIUM FIX: Reset stopOnce when starting, so Stop can work again after restart.
func (rl *RateLimiter) Start() {
	rl.mu.Lock()
	if rl.running {
		rl.mu.Unlock()
		return
	}
	rl.running = true
	rl.stopCh = make(chan struct{}) // audit-fix  fresh channel for this lifecycle
	rl.stopOnce = sync.Once{}       // MEDIUM FIX: reset so Stop() can close the new channel
	rl.mu.Unlock()

	go rl.cleanupLoop()
}

// Stop stops the rate limiter
// MEDIUM FIX: Use sync.Once to prevent double-close panic and race with Start().
// Previously, concurrent Stop() calls could close stopCh twice (panic), and
// Stop() could race with Start() re-creating the channel.
func (rl *RateLimiter) Stop() {
	rl.mu.Lock()
	if !rl.running {
		rl.mu.Unlock()
		return
	}
	rl.running = false
	stopCh := rl.stopCh
	rl.mu.Unlock()

	rl.stopOnce.Do(func() {
		close(stopCh)
	})
}

// Allow checks if a request should be allowed
// R40-M7 FIX: Removed global lock (rl.mu.Lock) from the hot path. The previous
// implementation held rl.mu while acquiring shard locks, defeating the purpose of
// sharding. Now we only use shard-level locks for per-IP checks, and rl.mu.RLock
// for reading config (which rarely changes). The global lock is no longer needed
// because shardIndex is computed from the fixed-size array and config fields are
// read under RLock.
func (rl *RateLimiter) Allow(r *http.Request, method string) error {
	// R40-M7 FIX: Read config under RLock (not exclusive Lock) to avoid blocking.
	rl.mu.RLock()
	enabled := rl.config.Enabled
	trustedProxies := rl.config.TrustedProxies
	rl.mu.RUnlock()

	if !enabled {
		return nil
	}

	// audit-fix INFO-2: use getClientIPWithTrust so that behind trusted
	// proxies the real client IP is used for per-IP rate limiting.
	clientIP := getClientIPWithTrust(r, trustedProxies)

	// R107-LOCAL-FANOUT (2026-09-04): exempt callers skip the per-IP bucket and
	// the ban check entirely. The global and per-method limits below still apply.
	exempt := rl.isExemptIP(clientIP)

	// R40-M7 FIX: Check if IP is banned using only the shard lock (no global lock).
	if !exempt {
		shardIdx := rl.shardIndex(clientIP)
		rl.ipShardsMu[shardIdx].Lock()
		entry, exists := rl.ipShards[shardIdx][clientIP]
		if exists {
			now := time.Now()
			if now.Before(entry.bannedUntil) {
				rl.ipShardsMu[shardIdx].Unlock()
				return ErrRateLimitExceeded
			}
			// R100-BAN-NORECOVER (2026-08-30): the ban has lapsed — clear it AND
			// the violation counter. violations was otherwise only ever reset by
			// UnbanIP, which has no production callers, so a once-banned IP stayed
			// permanently one token shortfall away from another full ban. See
			// clearExpiredBanLocked.
			clearExpiredBanLocked(entry, now)
		}
		rl.ipShardsMu[shardIdx].Unlock()
	}

	// Check global rate limit (needs exclusive access to globalTokens)
	// FIX: Use dedicated globalMu instead of rl.mu to avoid blocking
	// config reads and per-method checks during global rate limiting.
	rl.globalMu.Lock()
	globalOK := rl.checkGlobalLimit()
	rl.globalMu.Unlock()
	if !globalOK {
		return ErrRateLimitExceeded
	}

	// Check per-IP rate limit (uses shard lock internally)
	if !exempt && !rl.checkIPLimit(clientIP) {
		return ErrRateLimitExceeded
	}

	// Check per-method rate limit
	rl.mu.RLock()
	limit, hasMethodLimit := rl.config.PerMethodRateLimit[method]
	rl.mu.RUnlock()
	if hasMethodLimit {
		rl.mu.Lock()
		methodOK := rl.checkMethodLimit(method, limit)
		rl.mu.Unlock()
		if !methodOK {
			return ErrRateLimitExceeded
		}
	}

	return nil
}

// checkGlobalLimit checks and updates global rate limit
func (rl *RateLimiter) checkGlobalLimit() bool {
	now := time.Now()
	elapsed := now.Sub(rl.globalLastUpdate).Seconds()

	// Add tokens based on elapsed time
	rl.globalTokens += elapsed * float64(rl.config.GlobalRateLimit)
	if rl.globalTokens > float64(rl.config.BurstSize) {
		rl.globalTokens = float64(rl.config.BurstSize)
	}
	rl.globalLastUpdate = now

	// Check if we have tokens
	if rl.globalTokens < 1 {
		return false
	}

	// Consume a token
	rl.globalTokens--
	return true
}

// checkIPLimit checks and updates per-IP rate limit
// R20-M8 FIX: Uses sharded locking to reduce mutex contention.
// Each shard has its own mutex, reducing lock contention under high concurrency.
func (rl *RateLimiter) checkIPLimit(ip string) bool {
	now := time.Now()

	// R20-M8 FIX: Use sharded entry access
	shardIdx := rl.shardIndex(ip)
	rl.ipShardsMu[shardIdx].Lock()
	entry, exists := rl.ipShards[shardIdx][ip]
	if !exists {
		// R20-M8 FIX: Per-shard capacity limit (MaxTrackedIPs / 16 shards)
		shardMaxIPs := rl.config.MaxTrackedIPs / 16
		if shardMaxIPs > 0 && len(rl.ipShards[shardIdx]) >= shardMaxIPs {
			// R18-H6 FIX: Always clean up stale entries BEFORE rejecting.
			// Multiple cleanup passes to increase chance of freeing space.
			for attempts := 0; attempts < 3; attempts++ {
				rl.cleanupStaleIPEntriesInShardLocked(shardIdx, now)
				if len(rl.ipShards[shardIdx]) < shardMaxIPs {
					break
				}
			}
			// Final check: if still at capacity after cleanup, check if this
			// specific IP was recently active (evict oldest entry for new IP)
			if len(rl.ipShards[shardIdx]) >= shardMaxIPs {
				var oldestIP string
				var oldestTime time.Time = time.Now().Add(time.Hour)
				for ip, e := range rl.ipShards[shardIdx] {
					if e.lastUpdate.Before(oldestTime) && now.After(e.bannedUntil) {
						oldestTime = e.lastUpdate
						oldestIP = ip
					}
				}
				// Only evict if the oldest entry is not banned and is older than 1 minute
				if oldestIP != "" && oldestTime.Before(now.Add(-time.Minute)) {
					delete(rl.ipShards[shardIdx], oldestIP)
				} else {
					// L9-017 FIX: Still at capacity with no good eviction candidate.
					// Fail closed: reject instead of allowing through. Previously this
					// returned true, which an attacker could trigger by flooding the
					// shard with unique IPs to bypass per-IP rate limiting. The global
					// limit (checked earlier in Allow()) still bounds overall traffic.
					rl.ipShardsMu[shardIdx].Unlock()
					return false
				}
			}
		}
		entry = &rateLimitEntry{
			tokens:     float64(rl.config.BurstSize),
			lastUpdate: now,
		}
		rl.ipShards[shardIdx][ip] = entry
	}

	// Add tokens based on elapsed time
	elapsed := now.Sub(entry.lastUpdate).Seconds()
	entry.tokens += elapsed * float64(rl.config.PerIPRateLimit)
	if entry.tokens > float64(rl.config.BurstSize) {
		entry.tokens = float64(rl.config.BurstSize)
	}
	entry.lastUpdate = now

	// Check if we have tokens
	if entry.tokens < 1 {
		// Record violation
		entry.violations++
		if entry.violations >= rl.config.ViolationsBeforeBan {
			entry.bannedUntil = now.Add(rl.config.BanDuration)
		}
		rl.ipShardsMu[shardIdx].Unlock()
		return false
	}

	// Consume a token
	entry.tokens--
	rl.ipShardsMu[shardIdx].Unlock()
	return true
}

// cleanupStaleIPEntriesInShardLocked removes stale entries from a specific shard
// Caller must hold the shard's lock.
func (rl *RateLimiter) cleanupStaleIPEntriesInShardLocked(shardIdx uint8, now time.Time) {
	window := now.Add(-time.Minute)
	cleaned := make(map[string]*rateLimitEntry)
	for ip, entry := range rl.ipShards[shardIdx] {
		// L9-018 FIX: Keep entries that are either recently active OR still banned.
		// Previously the AND logic removed actively-banned entries during cleanup,
		// letting banned IPs bypass their ban. Now only stale AND ban-expired
		// entries are removed.
		if entry.lastUpdate.After(window) || entry.bannedUntil.After(now) {
			cleaned[ip] = entry
		}
	}
	rl.ipShards[shardIdx] = cleaned
}

// checkMethodLimit checks and updates per-method rate limit
func (rl *RateLimiter) checkMethodLimit(method string, limit int) bool {
	now := time.Now()

	entry, exists := rl.methodLimits[method]
	if !exists {
		entry = &rateLimitEntry{
			tokens:     float64(rl.config.BurstSize),
			lastUpdate: now,
		}
		rl.methodLimits[method] = entry
	}

	// Add tokens based on elapsed time
	elapsed := now.Sub(entry.lastUpdate).Seconds()
	entry.tokens += elapsed * float64(limit)
	if entry.tokens > float64(rl.config.BurstSize) {
		entry.tokens = float64(rl.config.BurstSize)
	}
	entry.lastUpdate = now

	// Check if we have tokens
	if entry.tokens < 1 {
		return false
	}

	// Consume a token
	entry.tokens--
	return true
}

// GetStats returns rate limiter statistics.
// L10-017 FIX: Returns a value copy (not a pointer) to prevent callers from
// aliasing internal state and to avoid potential race conditions.
func (rl *RateLimiter) GetStats() RateLimitStats {
	// L9-055 FIX: Read global tokens and method count under rl.mu.RLock(),
	// then release before iterating shards. Holding rl.mu.RLock() while
	// acquiring shard locks creates unnecessary contention with cleanup()
	// which needs rl.mu.Lock() (write lock).
	rl.mu.RLock()
	globalTokens := rl.globalTokens
	trackedMethods := len(rl.methodLimits)
	rl.mu.RUnlock()

	// R20-M8 FIX: Count IPs across all shards (without holding rl.mu)
	totalIPs := 0
	bannedIPs := 0
	now := time.Now()
	for i := range rl.ipShards {
		rl.ipShardsMu[i].Lock()
		totalIPs += len(rl.ipShards[i])
		for _, entry := range rl.ipShards[i] {
			if now.Before(entry.bannedUntil) {
				bannedIPs++
			}
		}
		rl.ipShardsMu[i].Unlock()
	}

	return RateLimitStats{
		GlobalTokens:   globalTokens,
		TrackedIPs:     totalIPs,
		TrackedMethods: trackedMethods,
		BannedIPs:      bannedIPs,
	}
}

// RateLimitStats holds rate limiter statistics
type RateLimitStats struct {
	GlobalTokens   float64
	TrackedIPs     int
	TrackedMethods int
	BannedIPs      int
}

// UnbanIP removes a ban for an IP
// R20-M8 FIX: Uses sharded locking
func (rl *RateLimiter) UnbanIP(ip string) {
	shardIdx := rl.shardIndex(ip)
	rl.ipShardsMu[shardIdx].Lock()
	defer rl.ipShardsMu[shardIdx].Unlock()

	if entry, exists := rl.ipShards[shardIdx][ip]; exists {
		entry.bannedUntil = time.Time{}
		entry.violations = 0
	}
}

// IsBanned reports whether the IP currently has an active ban.
// R107-LOCAL-FANOUT (2026-09-04): added for operational visibility ("is the
// co-located service banned right now?") and to make ban state assertable in
// tests — previously the only way to observe it was to send a request and
// interpret the error, which cannot distinguish a ban from a spent bucket.
func (rl *RateLimiter) IsBanned(ip string) bool {
	shardIdx := rl.shardIndex(ip)
	rl.ipShardsMu[shardIdx].Lock()
	defer rl.ipShardsMu[shardIdx].Unlock()

	entry, exists := rl.ipShards[shardIdx][ip]
	if !exists {
		return false
	}
	return time.Now().Before(entry.bannedUntil)
}

// BanIP manually bans an IP
// R20-M8 FIX: Uses sharded locking
func (rl *RateLimiter) BanIP(ip string, duration time.Duration) {
	shardIdx := rl.shardIndex(ip)
	rl.ipShardsMu[shardIdx].Lock()
	defer rl.ipShardsMu[shardIdx].Unlock()

	entry, exists := rl.ipShards[shardIdx][ip]
	if !exists {
		entry = &rateLimitEntry{
			tokens:     float64(rl.config.BurstSize),
			lastUpdate: time.Now(),
		}
		rl.ipShards[shardIdx][ip] = entry
	}

	entry.bannedUntil = time.Now().Add(duration)
}

// SetMethodRateLimit sets a rate limit for a specific method
func (rl *RateLimiter) SetMethodRateLimit(method string, limit int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.config.PerMethodRateLimit[method] = limit
}

// SetEnabled enables or disables rate limiting
var rateLimiterEnabledImmutable = os.Getenv("QAU_RATELIMITER_IMMUTABLE") == "true"

func (rl *RateLimiter) SetEnabled(enabled bool) {
	if rateLimiterEnabledImmutable {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.config.Enabled = enabled
}

// UpdateConfig atomically replaces the rate limiter's configuration. It is
// safe to call at runtime while the limiter is serving requests: the request
// hot path reads config under rl.mu.RLock, and the swap happens under
// rl.mu.Lock, so readers always observe a consistent config pointer (no data
// race, unlike swapping the *RateLimiter on the Server). Used by node config
// hot-reload (audit-fix M6-3).
//
// When QAU_RATELIMITER_IMMUTABLE=true, the Enabled flag is preserved from the
// existing config (mirroring SetEnabled's guard) so a reload cannot disable
// rate limiting on a locked-down node.
//
// RPC-R9-M (2026-07-19) FIX: Sanitize timing fields before installation.
// CleanupInterval and BanDuration feed directly into time.NewTicker and
// time.Now().Add — both panic / overflow on negative or ~MaxInt64 values.
// Caller-supplied configs (env vars, JSON, RPC admin calls) cannot be
// trusted to stay within sane bounds, so we cap them here before swapping
// in. The defaults chosen by DefaultRateLimitConfig already fit; this guard
// only affects caller overrides.
func (rl *RateLimiter) UpdateConfig(cfg *RateLimitConfig) {
	if cfg == nil {
		cfg = DefaultRateLimitConfig()
	} else {
		// RPC-R9-M FIX: defensive copy + sanitize so the caller's struct
		// is not mutated in place and downstream code sees only safe values.
		sanitized := *cfg
		const (
			maxCleanupInterval = 24 * time.Hour
			minCleanupInterval = 1 * time.Second
			maxBanDuration     = 365 * 24 * time.Hour
		)
		if sanitized.CleanupInterval < minCleanupInterval ||
			sanitized.CleanupInterval > maxCleanupInterval {
			sanitized.CleanupInterval = 5 * time.Minute // default from DefaultRateLimitConfig
		}
		if sanitized.BanDuration < 0 || sanitized.BanDuration > maxBanDuration {
			sanitized.BanDuration = 24 * time.Hour // default from DefaultRateLimitConfig
		}
		cfg = &sanitized
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rateLimiterEnabledImmutable {
		cfg.Enabled = rl.config.Enabled
	}
	rl.config = cfg
	// R107-LOCAL-FANOUT: keep the parsed exemption list in sync with the config.
	rl.exemptIPs, rl.exemptNets = parseExemptIPs(cfg.ExemptIPs)
}

// parseExemptIPs converts the textual exemption list into bare IPs and CIDR
// networks. Unparsable entries are dropped here (node startup validates and
// rejects them loudly; this layer must not panic on a bad string), and an
// all-zero prefix is refused because it would exempt every client and turn
// per-IP limiting off entirely.
func parseExemptIPs(entries []string) ([]net.IP, []*net.IPNet) {
	if len(entries) == 0 {
		return nil, nil
	}
	ips := make([]net.IP, 0, len(entries))
	nets := make([]*net.IPNet, 0, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil || network == nil {
				continue
			}
			if ones, _ := network.Mask.Size(); ones == 0 {
				continue // refuse 0.0.0.0/0 and ::/0
			}
			nets = append(nets, network)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil && !ip.IsUnspecified() {
			ips = append(ips, ip)
		}
	}
	return ips, nets
}

// isExemptIP reports whether the client IP is exempt from per-IP limiting.
// Caller must NOT hold rl.mu (this takes RLock itself).
func (rl *RateLimiter) isExemptIP(clientIP string) bool {
	rl.mu.RLock()
	ips := rl.exemptIPs
	nets := rl.exemptNets
	rl.mu.RUnlock()

	if len(ips) == 0 && len(nets) == 0 {
		return false
	}
	// clientIP may carry a zone ("fe80::1%eth0") or, defensively, a port.
	host := clientIP
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, candidate := range ips {
		if candidate.Equal(ip) {
			return true
		}
	}
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// cleanupLoop periodically cleans up old entries
func (rl *RateLimiter) cleanupLoop() {
	// RPC-R42-CI-RACE-3: snapshot stopCh into a local variable BEFORE entering
	// the select loop. Previously each select iteration re-read the rl.stopCh
	// field (no lock), racing with a subsequent Start()/Stop() pair that
	// assigns rl.stopCh = make(chan struct{}) under rl.mu. The race was:
	//   Read  at ratelimit.go:598  (this goroutine, structural field read)
	//   Write at ratelimit.go:211  (rl.stopCh = make(chan struct{}))
	// Fix: capture stopCh exactly once at goroutine startup, then select on
	// the local. Start() spawns cleanupLoop AFTER releasing rl.mu, so the
	// assignment to rl.stopCh happens-before the snapshot read here; any
	// later reassignment by a future Start() (after Stop() resumed) just
	// spins up a NEW cleanupLoop goroutine with a NEW snapshot — we never
	// observe the field mutate from this goroutine again.
	rl.mu.RLock()
	stopCh := rl.stopCh
	rl.mu.RUnlock()

	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes old entries
// R20-M8 FIX: Uses sharded locking for IP cleanup
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-DefaultCleanupCutoffAge)

	// R20-M8 FIX: Clean up IP entries across all shards
	for i := range rl.ipShards {
		rl.ipShardsMu[i].Lock()
		for ip, entry := range rl.ipShards[i] {
			if entry.lastUpdate.Before(cutoff) && now.After(entry.bannedUntil) {
				delete(rl.ipShards[i], ip)
			}
		}
		rl.ipShardsMu[i].Unlock()
	}

	// Clean up method entries
	for method, entry := range rl.methodLimits {
		if entry.lastUpdate.Before(cutoff) {
			delete(rl.methodLimits, method)
		}
	}
}

// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

const maxRequestBodySize = 1 << 20 // 1MB - audit-fix MED-NEW-3: prevent memory exhaustion from large requests

// BRDG-FIX (2026-07-17): Per-IP rate limiting + failure-based ban.
// Without this, an attacker could brute-force the X-API-Key at >1000 req/s
// (sha256 comparison is cheap) or DoS the API with arbitrary keys. The
// token bucket limits each IP to apiRatePerSec sustained / apiBurst burst,
// and apiMaxFailures failed auth attempts within apiFailWindow ban the IP
// for apiBanDuration. This mirrors the audit report's recommendation
// (10 req/s, 10 failures/min → 1h ban).
const (
	apiRatePerSec  = 10.0
	apiBurst       = 20
	apiMaxFailures = 10
	apiFailWindow  = time.Minute
	apiBanDuration = time.Hour
)

// R43-BRIDGE-IP-01 FIX (2026-08-03): background TTL reaper for ipStates.
// The ipStates map grew unbounded across the full lifetime of the
// BridgeAPI: an external attacker probing with distinct source IPs
// (e.g. via a botnet) could grow the map beyond any bound → OOM. The
// reaper scans ipStates every ipCleanupInterval and removes entries that
// are BOTH (a) past their `firstFail + apiFailWindow` window AND not
// currently banned, and (b) have `bannedUntil` already in the past. Only
// NOT-currently-banned entries are removed so an active ban is never
// silently dropped by the reaper.
const ipCleanupInterval = time.Hour

// R43-BRIDGE-IP-01 FIX (2026-08-03): hard cap on ipStates. Even with the
// periodic reaper, a sustained attack can race ahead of the next tick.
// When len(ipStates) reaches this cap, getIPState / recordAuthFailure
// synchronously sweep the whole map (under the existing lock) to evict
// expired + banned-past entries BEFORE creating a new entry. Sweeps are
// O(n) but only triggered at the cap, so normal operation stays O(1).
const ipStatesMaxEntries = 200000

// ipRateState tracks per-IP rate-limit tokens and auth-failure counters.
// BRDG- fields are protected by ipLimiterMu in BridgeAPI.
type ipRateState struct {
	limiter     *RateLimiter
	failures    int
	firstFail   time.Time
	bannedUntil time.Time
}

type BridgeAPI struct {
	mu               sync.RWMutex
	bridge           *QuantumBridge
	relayer          *MessageRelayer
	assetLockManager *AssetLockManager
	validatorNetwork *ValidatorNetwork
	server           *http.Server
	running          bool
	apiKeyHash       string
	// BRDG- per-IP rate limit + ban state.
	ipLimiterMu sync.Mutex
	ipStates    map[string]*ipRateState
	// R43-BRIDGE-IP-01 FIX (2026-08-03): background TTL reaper goroutine.
	// stopCleanup is closed to signal the reaper to exit; cleanupWG is
	// waited on in Close() for clean shutdown. cleanupInterval is the
	// reaper's tick duration (overridable via newBridgeAPIWithCleanupInterval
	// for tests so we don't have to wait ipCleanupInterval = time.Hour).
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupWG       sync.WaitGroup
	// R43-BRIDGE-XFF-01 FIX (2026-08-03): TrustProxy gates whether
	// clientIP honors X-Forwarded-For. Default false = direct exposure;
	// a direct-exposure deployment inherits the spoofable XFF header
	// unless the operator explicitly enables TrustProxy (because they
	// sit behind Caddy / another trusted reverse proxy that overwrites
	// XFF). Protected by mu (RWMutex) for concurrent reads/writes.
	TrustProxy bool
	// R43-BRIDGE-XFF-01 FIX (2026-08-03): throttled once-per-IP-per-second
	// warning gate for "X-Forwarded-For seen but TrustProxy is false",
	// so operators get a hint to enable TrustProxy if behind a reverse
	// proxy without flooding the log. Protected by xffWarnMu.
	xffWarnMu   sync.Mutex
	xffWarnLast map[string]time.Time
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// NewBridgeAPI constructs a BridgeAPI with the default ipCleanupInterval
// reaper cadence (ipCleanupInterval = time.Hour).
func NewBridgeAPI(
	bridge *QuantumBridge,
	relayer *MessageRelayer,
	assetLockManager *AssetLockManager,
	validatorNetwork *ValidatorNetwork,
	apiKey string,
) *BridgeAPI {
	return newBridgeAPIWithCleanupInterval(bridge, relayer, assetLockManager, validatorNetwork, apiKey, ipCleanupInterval)
}

// newBridgeAPIWithCleanupInterval is the internal constructor that lets
// tests override the ipStates reaper cadence. R43-BRIDGE-IP-01 FIX
// (2026-08-03): exported-by-name-only (lowercase) so the public surface
// still goes through NewBridgeAPI with the production default.
func newBridgeAPIWithCleanupInterval(
	bridge *QuantumBridge,
	relayer *MessageRelayer,
	assetLockManager *AssetLockManager,
	validatorNetwork *ValidatorNetwork,
	apiKey string,
	cleanupInterval time.Duration,
) *BridgeAPI {
	if cleanupInterval <= 0 {
		cleanupInterval = ipCleanupInterval
	}
	return &BridgeAPI{
		bridge:           bridge,
		relayer:          relayer,
		assetLockManager: assetLockManager,
		validatorNetwork: validatorNetwork,
		apiKeyHash:       sha256Hex(apiKey),
		ipStates:         make(map[string]*ipRateState), // BRDG-
		cleanupInterval:  cleanupInterval,
		xffWarnLast:      make(map[string]time.Time),
	}
}

// SetTrustProxy enables/disables honoring X-Forwarded-For in clientIP.
// R43-BRIDGE-XFF-01 FIX (2026-08-03): thread-safe setter. Default is
// false (direct-exposure safe). Operators running behind a trusted
// reverse proxy (Caddy / nginx) that overwrites X-Forwarded-For MUST
// call SetTrustProxy(true) so the per-IP rate limiter + ban logic uses
// the real client IP. Calling SetTrustProxy(false) on a direct-exposure
// deployment prevents a spoofed XFF header from bypassing rate limits.
func (api *BridgeAPI) SetTrustProxy(enabled bool) {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.TrustProxy = enabled
}

// R43-BRIDGE-XFF-01 FIX (2026-08-03): clientIP is now a method on
// BridgeAPI instead of a free function. It honors X-Forwarded-For ONLY
// when api.TrustProxy is true (operator-opt-in via SetTrustProxy). In
// direct-exposure deployments (TrustProxy == false) the XFF header is
// ignored and the peer IP is taken from r.RemoteAddr with the port
// stripped — preventing a client from spoofing XFF to bypass the
// per-IP rate limiter / ban.
//
// When XFF is ignored because TrustProxy is false AND the request
// actually carries an X-Forwarded-For header, we log a throttled
// slog.Warn once per IP per second so an operator who is actually
// behind a reverse proxy gets a hint to enable SetTrustProxy. The
// throttle prevents a flooding attacker from spamming the log.
func (api *BridgeAPI) clientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	api.mu.RLock()
	trustProxy := api.TrustProxy
	api.mu.RUnlock()
	if trustProxy && xff != "" {
		// Use the first (leftmost) entry, which is the original client.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	if !trustProxy && xff != "" {
		// Direct-exposure deployment with an XFF header present: warn
		// the operator once per peer IP per second so they can enable
		// TrustProxy if they are actually behind a reverse proxy.
		peer := stripPort(r.RemoteAddr)
		api.warnXFFIgnored(peer)
	}
	// Strip the port from RemoteAddr (host:port).
	return stripPort(r.RemoteAddr)
}

// warnXFFIgnored emits a throttled slog.Warn for a peer IP that sent an
// X-Forwarded-For header while TrustProxy is false. R43-BRIDGE-XFF-01.
// At most one warning per peer IP per second to bound the log volume
// under attack. The peer IP used here is the r.RemoteAddr (the actual
// TCP peer) — not the (spoofable) XFF value — so an attacker cannot
// amplify the warn volume by varying the XFF header.
func (api *BridgeAPI) warnXFFIgnored(peer string) {
	now := time.Now()
	api.xffWarnMu.Lock()
	last, ok := api.xffWarnLast[peer]
	if ok && now.Sub(last) < time.Second {
		api.xffWarnMu.Unlock()
		return
	}
	api.xffWarnLast[peer] = now
	api.xffWarnMu.Unlock()
	slog.Warn("bridge API: X-Forwarded-For seen but TrustProxy is false; ignoring header",
		"peer", peer)
}

// stripPort removes the trailing :port from a host:port RemoteAddr.
// If there is no port, the input is returned unchanged.
func stripPort(host string) string {
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

// sweepExpiredIPStates removes ipStates entries that are BOTH:
//   - past their firstFail + apiFailWindow window (failure window
//     expired) and NOT currently banned, OR
//   - have a bannedUntil that is already in the past (ban lapsed).
//
// R43-BRIDGE-IP-01 FIX (2026-08-03): caller MUST hold api.ipLimiterMu.
// Entries that are currently banned (bannedUntil in the future) are
// KEPT so the reaper never silently drops an active ban.
func (api *BridgeAPI) sweepExpiredIPStates() int {
	now := time.Now()
	removed := 0
	for ip, st := range api.ipStates {
		// Active ban: keep. We never let the reaper drop an entry while
		// its ban window is still open, even if firstFail is old (an
		// attacker that hit the ban should stay out for apiBanDuration).
		if now.Before(st.bannedUntil) {
			continue
		}
		// Ban has lapsed OR no ban yet. Now check the failure window:
		// if firstFail is zero (never failed) or the failure window is
		// past, the entry is stale and can be reaped.
		if st.firstFail.IsZero() || now.Sub(st.firstFail) > apiFailWindow {
			delete(api.ipStates, ip)
			removed++
		}
	}
	return removed
}

// getIPState returns (or lazily creates) the per-IP rate-limit state.
// BRDG- caller must NOT hold ipLimiterMu.
// R43-BRIDGE-IP-01 FIX (2026-08-03): before creating a NEW entry, if
// the map has reached ipStatesMaxEntries, sweep expired/lapsed entries
// synchronously (fail-closed-then-reclaimed). This caps memory under
// sustained attack even between reaper ticks.
func (api *BridgeAPI) getIPState(ip string) *ipRateState {
	api.ipLimiterMu.Lock()
	defer api.ipLimiterMu.Unlock()
	st, ok := api.ipStates[ip]
	if !ok {
		if len(api.ipStates) >= ipStatesMaxEntries {
			removed := api.sweepExpiredIPStates()
			if removed > 0 {
				slog.Info("bridge API: synchronous ipStates sweep at cap reclaimed entries",
					"before", len(api.ipStates)+removed, "removed", removed, "cap", ipStatesMaxEntries)
			}
		}
		st = &ipRateState{
			limiter: newRateLimiter(int(apiRatePerSec), apiBurst),
		}
		api.ipStates[ip] = st
	}
	return st
}

// recordAuthFailure increments the per-IP failure counter and bans the IP
// when apiMaxFailures is reached within apiFailWindow.
// BRDG- caller must NOT hold ipLimiterMu.
// R43-BRIDGE-IP-01 FIX (2026-08-03): same synchronous sweep-at-cap guard
// as getIPState, so a flood of distinct-IP auth failures cannot grow the
// map past ipStatesMaxEntries between reaper ticks.
func (api *BridgeAPI) recordAuthFailure(ip string) {
	api.ipLimiterMu.Lock()
	defer api.ipLimiterMu.Unlock()
	st, ok := api.ipStates[ip]
	if !ok {
		if len(api.ipStates) >= ipStatesMaxEntries {
			removed := api.sweepExpiredIPStates()
			if removed > 0 {
				slog.Info("bridge API: synchronous ipStates sweep at cap reclaimed entries (recordAuthFailure)",
					"before", len(api.ipStates)+removed, "removed", removed, "cap", ipStatesMaxEntries)
			}
		}
		st = &ipRateState{
			limiter: newRateLimiter(int(apiRatePerSec), apiBurst),
		}
		api.ipStates[ip] = st
	}
	now := time.Now()
	// Reset the failure window if the first failure is too old.
	if !st.firstFail.IsZero() && now.Sub(st.firstFail) > apiFailWindow {
		st.failures = 0
		st.firstFail = time.Time{}
	}
	if st.firstFail.IsZero() {
		st.firstFail = now
	}
	st.failures++
	if st.failures >= apiMaxFailures {
		st.bannedUntil = now.Add(apiBanDuration)
		slog.Warn("bridge API: IP banned for excessive auth failures",
			"ip", ip, "failures", st.failures, "ban_until", st.bannedUntil)
	}
}

// isIPBanned returns true if the IP is currently within its ban window.
// BRDG- caller must NOT hold ipLimiterMu.
func (api *BridgeAPI) isIPBanned(ip string) bool {
	api.ipLimiterMu.Lock()
	defer api.ipLimiterMu.Unlock()
	st, ok := api.ipStates[ip]
	if !ok {
		return false
	}
	return time.Now().Before(st.bannedUntil)
}

// startIPReaper launches the background TTL reaper goroutine. Idempotent
// within a single Start cycle: re-launches are no-ops while stopCleanup
// is non-nil. R43-BRIDGE-IP-01 FIX (2026-08-03).
func (api *BridgeAPI) startIPReaper() {
	api.ipLimiterMu.Lock()
	if api.stopCleanup != nil {
		// Already running.
		api.ipLimiterMu.Unlock()
		return
	}
	api.stopCleanup = make(chan struct{})
	stopCh := api.stopCleanup
	interval := api.cleanupInterval
	api.ipLimiterMu.Unlock()

	api.cleanupWG.Add(1)
	go func() {
		defer api.cleanupWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				api.ipLimiterMu.Lock()
				removed := api.sweepExpiredIPStates()
				if removed > 0 {
					slog.Info("bridge API: periodic ipStates reaper removed entries",
						"removed", removed, "remaining", len(api.ipStates))
				}
				api.ipLimiterMu.Unlock()
			}
		}
	}()
}

// Close stops the background TTL reaper goroutine and waits for it to
// exit. Safe to call multiple times. R43-BRIDGE-IP-01 FIX (2026-08-03):
// public so callers (and tests) can stop the reaper without a full
// BridgeAPI.Stop() (which also stops the HTTP server).
func (api *BridgeAPI) Close() {
	api.ipLimiterMu.Lock()
	stopCh := api.stopCleanup
	api.stopCleanup = nil
	api.ipLimiterMu.Unlock()
	if stopCh == nil {
		return
	}
	close(stopCh)
	api.cleanupWG.Wait()
}

func (api *BridgeAPI) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if api.apiKeyHash == "" {
			writeError(w, http.StatusInternalServerError, "bridge API not configured with authentication")
			return
		}
		// BRDG-FIX (2026-07-17): Per-IP rate limiting + ban enforcement.
		// 1. Reject banned IPs immediately (no sha256 work → no CPU burn).
		// 2. Token-bucket limit each IP to apiRatePerSec / apiBurst.
		// 3. On auth failure, record it; apiMaxFailures within apiFailWindow
		//    bans the IP for apiBanDuration.
		ip := api.clientIP(r)
		if api.isIPBanned(ip) {
			writeError(w, http.StatusTooManyRequests, "rate limit: IP temporarily banned due to excessive auth failures")
			return
		}
		st := api.getIPState(ip)
		if !st.limiter.allow() {
			writeError(w, http.StatusTooManyRequests, "rate limit: too many requests")
			return
		}
		providedKey := r.Header.Get("X-API-Key")
		providedHash := sha256Hex(providedKey)
		if subtle.ConstantTimeCompare([]byte(api.apiKeyHash), []byte(providedHash)) != 1 {
			api.recordAuthFailure(ip) // BRDG- track failures for ban decision
			writeError(w, http.StatusUnauthorized, "unauthorized: invalid or missing API key")
			return
		}
		next(w, r)
	}
}

func (api *BridgeAPI) Start(addr string) error {
	api.mu.Lock()
	defer api.mu.Unlock()

	if api.running {
		return fmt.Errorf("bridge API already running")
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/bridge/status", api.authenticate(api.handleStatus))
	mux.HandleFunc("/api/v1/bridge/message", api.authenticate(api.handleMessage))
	mux.HandleFunc("/api/v1/bridge/messages", api.authenticate(api.handleMessages))
	mux.HandleFunc("/api/v1/bridge/lock", api.authenticate(api.handleLock))
	mux.HandleFunc("/api/v1/bridge/locks", api.authenticate(api.handleLocks))
	mux.HandleFunc("/api/v1/bridge/relay", api.authenticate(api.handleRelay))
	mux.HandleFunc("/api/v1/bridge/validators", api.authenticate(api.handleValidators))

	api.server = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second, // audit-fix MEDIUM: Slowloris header-DoS protection
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // audit-fix MEDIUM: 1 MiB header cap
	}

	api.running = true

	// R43-BRIDGE-IP-01 FIX (2026-08-03): start the background TTL reaper
	// for ipStates so the per-IP rate-limit + ban map does not grow
	// unbounded across the BridgeAPI's lifetime. Stopped in Stop()
	// (which calls Close()) for clean shutdown.
	api.startIPReaper()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("bridge API server goroutine panic", "error", r)
			}
		}()
		if err := api.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("bridge API server error", "error", err)
		}
	}()

	return nil
}

func (api *BridgeAPI) Stop() error {
	api.mu.Lock()
	defer api.mu.Unlock()

	if !api.running {
		return fmt.Errorf("bridge API not running")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := api.server.Shutdown(ctx)
	api.running = false
	// R43-BRIDGE-IP-01 FIX (2026-08-03): stop the ipStates reaper so we
	// don't leak a goroutine + ticker after the HTTP server is shut
	// down. Close() is idempotent and safe to call even if Start() never
	// launched the reaper (stopCleanup == nil → no-op).
	api.Close()
	return err
}

func (api *BridgeAPI) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	status := map[string]any{
		"bridge_running":  api.bridge.running,
		"relayer_running": api.relayer.running,
		"validator_count": len(api.validatorNetwork.GetValidatorSet().GetActiveValidators()),
		"timestamp":       time.Now().Unix(),
	}

	writeJSON(w, http.StatusOK, status)
}

func (api *BridgeAPI) handleMessage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		api.submitMessage(w, r)
	case http.MethodGet:
		api.getMessage(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (api *BridgeAPI) submitMessage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var msg BridgeMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		slog.Error("bridge API: invalid request body", "error", err)
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	if err := api.bridge.SubmitMessage(ctx, &msg); err != nil {
		slog.Error("bridge API: failed to submit message", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to submit message")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message_id": msg.ID,
		"status":     "submitted",
	})
}

func (api *BridgeAPI) getMessage(w http.ResponseWriter, r *http.Request) {
	msgID := r.URL.Query().Get("id")
	if msgID == "" {
		writeError(w, http.StatusBadRequest, "missing message id")
		return
	}

	ctx := r.Context()
	msg, err := api.bridge.GetMessage(ctx, msgID)
	if err != nil {
		slog.Error("bridge API: message not found", "error", err)
		writeError(w, http.StatusNotFound, "message not found")
		return
	}

	writeJSON(w, http.StatusOK, msg)
}

func (api *BridgeAPI) handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	statusStr := r.URL.Query().Get("status")
	chainStr := r.URL.Query().Get("chain")

	ctx := r.Context()

	if statusStr != "" {
		status := BridgeMessageStatus(statusStr)
		messages, err := api.bridge.GetMessagesByStatus(ctx, status)
		if err != nil {
			slog.Error("bridge API: failed to get messages by status", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get messages")
			return
		}
		writeJSON(w, http.StatusOK, messages)
		return
	}

	if chainStr != "" {
		isSource := r.URL.Query().Get("source") == "true"
		messages, err := api.bridge.GetMessagesByChain(ctx, ChainID(chainStr), isSource)
		if err != nil {
			slog.Error("bridge API: failed to get messages by chain", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to get messages")
			return
		}
		writeJSON(w, http.StatusOK, messages)
		return
	}

	writeError(w, http.StatusBadRequest, "missing status or chain parameter")
}

func (api *BridgeAPI) handleLock(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		api.createLock(w, r)
	case http.MethodGet:
		api.getLock(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (api *BridgeAPI) createLock(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	var lock AssetLock
	if err := json.NewDecoder(r.Body).Decode(&lock); err != nil {
		slog.Error("bridge API: invalid lock request body", "error", err)
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	if err := api.assetLockManager.LockAsset(ctx, &lock); err != nil {
		slog.Error("bridge API: failed to lock asset", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to lock asset")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"lock_id": lock.ID,
		"status":  "locked",
	})
}

func (api *BridgeAPI) getLock(w http.ResponseWriter, r *http.Request) {
	lockID := r.URL.Query().Get("id")
	if lockID == "" {
		writeError(w, http.StatusBadRequest, "missing lock id")
		return
	}

	lock, exists := api.assetLockManager.GetLock(lockID)
	if !exists {
		writeError(w, http.StatusNotFound, "lock not found")
		return
	}

	writeJSON(w, http.StatusOK, lock)
}

func (api *BridgeAPI) handleLocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	ownerStr := r.URL.Query().Get("owner")
	statusStr := r.URL.Query().Get("status")

	if ownerStr != "" {
		owner, err := types.ParseHexAddress(ownerStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid owner address")
			return
		}
		locks := api.assetLockManager.GetLocksByOwner(owner)
		writeJSON(w, http.StatusOK, locks)
		return
	}

	if statusStr != "" {
		statusInt, err := strconv.Atoi(statusStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid status value")
			return
		}
		locks := api.assetLockManager.GetLocksByStatus(LockStatus(statusInt))
		writeJSON(w, http.StatusOK, locks)
		return
	}

	writeError(w, http.StatusBadRequest, "missing owner or status parameter")
}

func (api *BridgeAPI) handleRelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	taskID := r.URL.Query().Get("task_id")
	if taskID != "" {
		task, exists := api.relayer.GetTask(taskID)
		if !exists {
			writeError(w, http.StatusNotFound, "task not found")
			return
		}
		writeJSON(w, http.StatusOK, task)
		return
	}

	tasks := api.relayer.GetPendingTasks()
	writeJSON(w, http.StatusOK, tasks)
}

func (api *BridgeAPI) handleValidators(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	validators := api.validatorNetwork.GetValidatorSet().GetActiveValidators()
	writeJSON(w, http.StatusOK, map[string]any{
		"validators":  validators,
		"total_stake": api.validatorNetwork.GetValidatorSet().GetTotalStake().String(),
		"threshold":   api.validatorNetwork.GetValidatorSet().GetThreshold(),
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

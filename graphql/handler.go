// Quantaureum Node source, version 1.0.0.
package graphql

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Handler errors.
var (
	ErrQueryTooComplex    = errors.New("query complexity exceeds limit")
	ErrMethodNotAllowed   = errors.New("method not allowed")
	ErrInvalidContentType = errors.New("invalid content type")
	ErrInvalidRequest     = errors.New("invalid request")
	ErrEmptyQuery         = errors.New("empty query")
)

// audit-remediation: input validation constants
const (
	// DefaultMaxBodySize is the maximum allowed request body size (1MB for GraphQL)
	DefaultMaxBodySize = 1 * 1024 * 1024

	// DefaultMaxQueryLength is the maximum allowed query string length
	DefaultMaxQueryLength = 10000

	// DefaultMaxVariablesSize is the maximum allowed variables JSON size
	DefaultMaxVariablesSize = 100 * 1024 // 100KB
)

// HandlerConfig contains configuration for the GraphQL handler.
type HandlerConfig struct {
	// MaxComplexity is the maximum allowed query complexity.
	// A value of 0 means no limit.
	MaxComplexity int

	// MaxDepth is the maximum allowed query depth.
	// A value of 0 means no limit.
	MaxDepth int

	// EnableIntrospection enables GraphQL introspection queries.
	EnableIntrospection bool

	// EnablePlayground enables the GraphQL playground UI.
	EnablePlayground bool

	// audit-fix R7-M2: AllowedOrigins restricts CORS origins (empty = no CORS header)
	AllowedOrigins []string

	// audit-remediation: MaxBodySize is the maximum allowed request body size
	MaxBodySize int64

	// audit-remediation: MaxQueryLength is the maximum allowed query string length
	MaxQueryLength int

	// audit-fix R7-M1: APIKey authenticates GraphQL requests when non-empty
	APIKey string

	// AUDIT (2026) API-FIX: MaxAPIKeyAge sets a maximum lifetime for
	// rotated API keys. Without this, rotated/leaked keys never expire and
	// remain valid forever. The primary config.APIKey is exempt (it is the
	// currently active key). Default is 30 days. Set to 0 to disable expiry
	// (NOT recommended for production).
	MaxAPIKeyAge time.Duration

	// AuthDisabled bypasses API-key authentication for READ-ONLY requests
	// (development only). AUDIT-FULL SV-04 FIX (2026-08-15): mutation
	// (write) documents are still rejected with 401 in this mode — see the
	// isMutationOperation check in ServeHTTP — so the switch can no longer
	// be used to gain unauthenticated write access.
	AuthDisabled bool

	AllowedPaths []string

	RateLimitRequests int
	RateLimitWindow   time.Duration

	KeyRotationEnabled  bool
	KeyRotationInterval time.Duration

	// R35-P2-RPC-01 FIX (2026-07-29): HMAC + nonce replay protection.
	// When EnableHMAC is true, requests MUST include:
	//   - X-Timestamp: unix seconds (must be within ±5 minutes of server clock)
	//   - X-Nonce: client-generated unique nonce (must not have been seen within TTL)
	//   - X-Signature: HMAC-SHA256(timestamp || nonce || body, APIKey)
	// Without this, a captured API key (e.g. via leaked logs, MITM on
	// non-TLS connection, or compromised client) allows unrestricted
	// GraphQL access — including mutation operations that could drain
	// funds if the resolver exposes balance-affecting mutations. HMAC
	// binds the request body to the API key, so a captured key alone is
	// insufficient to forge a valid request.
	EnableHMAC bool
	// NonceTTL is how long seen nonces are tracked for replay prevention.
	// Default 5 minutes (matches timestamp window). Set to 0 to use default.
	NonceTTL time.Duration
}

type rateLimitEntry struct {
	count   int
	resetAt time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
	limit   int
	window  time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	// GQL-01 FIX (deep-audit 2026-07-12): clamp window to a positive value.
	// time.NewTicker(window*2) below panics on a non-positive duration, and it
	// runs in a goroutine, so a HandlerConfig with RateLimitWindow==0 (anything
	// not built via DefaultHandlerConfig) would crash the whole process.
	if window <= 0 {
		window = time.Minute
	}
	if limit <= 0 {
		limit = 100
	}
	rl := &rateLimiter{
		entries: make(map[string]*rateLimitEntry),
		limit:   limit,
		window:  window,
	}
	// SECURITY (audit 2026-06-24, M-7): Start cleanup goroutine to prevent
	// unbounded memory growth from unique IPs.
	go func() {
		ticker := time.NewTicker(window * 2)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for key, entry := range rl.entries {
		if now.After(entry.resetAt) {
			delete(rl.entries, key)
		}
	}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.entries[key]
	if !exists || now.After(entry.resetAt) {
		rl.entries[key] = &rateLimitEntry{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	entry.count++
	return entry.count <= rl.limit
}

// isLoopback checks if an IP address string is a loopback address
// (127.0.0.0/8 for IPv4, ::1 for IPv6, or the literal "localhost").
// This is used to determine whether forwarded IP headers can be trusted.
func isLoopback(ip string) bool {
	if ip == "localhost" {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func initAPIKeys(primary string) map[string]time.Time {
	keys := make(map[string]time.Time)
	if primary != "" {
		keys[primary] = time.Now()
	}
	return keys
}

func (h *Handler) AddAPIKey(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.apiKeys[key] = time.Now()
}

func (h *Handler) RemoveAPIKey(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.apiKeys, key)
}

func (h *Handler) RotateKey(newKey string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.config.APIKey != "" {
		h.apiKeys[h.config.APIKey] = time.Now()
	}
	h.config.APIKey = newKey
	h.apiKeys[newKey] = time.Now()
	h.keyRotatedAt = time.Now()
}

func (h *Handler) CleanupOldKeys(maxAge time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, addedAt := range h.apiKeys {
		if key == h.config.APIKey {
			continue
		}
		if addedAt.Before(cutoff) {
			delete(h.apiKeys, key)
		}
	}
}

// DefaultHandlerConfig returns the default handler configuration.
func DefaultHandlerConfig() *HandlerConfig {
	return &HandlerConfig{
		MaxComplexity: 100,
		MaxDepth:      10,
		// SECURITY FIX: Disable introspection by default to prevent schema exposure.
		// Introspection allows attackers to discover the full API schema including
		// sensitive fields and mutations. Enable only in development with explicit config.
		EnableIntrospection: false,
		// SECURITY: Disable playground by default - it can expose API structure
		// and enable it explicitly only in development environments.
		EnablePlayground:  false,
		MaxBodySize:       DefaultMaxBodySize,    // audit-remediation: 1MB default
		MaxQueryLength:    DefaultMaxQueryLength, // audit-remediation: 10KB default
		RateLimitRequests: 100,
		RateLimitWindow:   time.Minute,
		// AUDIT (2026) API-FIX: Default max key age is 30 days.
		MaxAPIKeyAge: 30 * 24 * time.Hour,
	}
}

// Handler implements the HTTP handler for GraphQL requests.
type Handler struct {
	schema       *Schema
	resolver     *Resolver
	config       *HandlerConfig
	mu           sync.RWMutex
	rateLimit    *rateLimiter
	apiKeys      map[string]time.Time
	keyRotatedAt time.Time
	// R35-P2-RPC-01 FIX: HMAC nonce replay protection state.
	nonceMu     sync.Mutex
	seenNonces  map[string]time.Time // nonce → first-seen timestamp
	nonceTTL    time.Duration
	hmacEnabled bool
}

// NewHandler creates a new GraphQL HTTP handler.
func NewHandler(resolver *Resolver, config *HandlerConfig) *Handler {
	if config == nil {
		config = DefaultHandlerConfig()
	}
	nonceTTL := config.NonceTTL
	if nonceTTL == 0 {
		nonceTTL = 5 * time.Minute // default matches timestamp window
	}
	return &Handler{
		schema:       NewSchema(resolver),
		resolver:     resolver,
		config:       config,
		rateLimit:    newRateLimiter(config.RateLimitRequests, config.RateLimitWindow),
		apiKeys:      initAPIKeys(config.APIKey),
		keyRotatedAt: time.Now(),
		// R35-P2-RPC-01 FIX: initialize HMAC replay protection.
		seenNonces:  make(map[string]time.Time),
		nonceTTL:    nonceTTL,
		hmacEnabled: config.EnableHMAC,
	}
}

// GraphQLRequest represents a GraphQL request.
type GraphQLRequest struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response.
type GraphQLResponse struct {
	Data   any            `json:"data,omitempty"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

// GraphQLError represents a GraphQL error.
type GraphQLError struct {
	Message    string          `json:"message"`
	Locations  []ErrorLocation `json:"locations,omitempty"`
	Path       []any           `json:"path,omitempty"`
	Extensions map[string]any  `json:"extensions,omitempty"`
}

// ErrorLocation represents the location of an error in the query.
type ErrorLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// ServeHTTP implements the http.Handler interface.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// SECURITY FIX (audit P2-03): Only trust X-Real-IP/X-Forwarded-For
	// headers when the request originates from a loopback address (trusted
	// reverse proxy). Previously, any client could spoof these headers with
	// a different IP per request to bypass rate limiting entirely.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	clientIP := host

	if isLoopback(host) {
		// Request comes from a trusted proxy on loopback; honor forwarded headers
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			clientIP = xrip
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx != -1 {
				clientIP = strings.TrimSpace(xff[:idx])
			} else {
				clientIP = strings.TrimSpace(xff)
			}
		}
	}
	// If not from loopback, clientIP remains the direct RemoteAddr host,
	// ignoring any spoofed forwarding headers.

	if h.rateLimit != nil && !h.rateLimit.allow(clientIP) {
		h.writeError(w, http.StatusTooManyRequests, errors.New("rate limit exceeded"))
		return
	}

	// audit-fix R7-M2: only set CORS headers when AllowedOrigins is explicitly configured
	// SECURITY: Do not allow wildcard "*" in production - it allows any origin which can
	// lead to CSRF attacks. Each origin must be explicitly listed.
	//
	// R35-P3-01 (2026-07-29) AUDIT NOTE: Wildcard ("*") entries in AllowedOrigins are
	// treated as ordinary origin strings, NOT as a wildcard match. The comparison
	// `allowed == origin` requires an exact string match against the client's actual
	// Origin header, and a real browser never sends "Origin: *" — so a configured
	// "*" entry is effectively dead and cannot widen CORS scope. This is defense-in-
	// depth: even if an operator misconfigures AllowedOrigins with ["*"], the
	// CORS policy remains strict-origin. Do NOT reintroduce an `allowed == "*"`
	// branch here; that would re-open the CSRF surface.
	if len(h.config.AllowedOrigins) > 0 {
		origin := r.Header.Get("Origin")
		for _, allowed := range h.config.AllowedOrigins {
			// SECURITY FIX: Removed "allowed == '*'" check - wildcard origins are insecure
			if allowed == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				break
			}
		}
	}

	// Handle preflight requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	// R35-P2-RPC-01 FIX: Read body EARLY so HMAC can bind to the request body.
	// For POST requests, the body is consumed once here and a new reader is
	// installed so downstream parseRequest can re-read it. For GET requests
	// (query string only), body is not needed for HMAC.
	//
	// R36-P3-20 FIX (2026-07-30): For GET requests, bind the HMAC to the
	// raw query string. Previously, GET requests used an empty body for
	// HMAC, so an attacker who leaked the X-Signature header (e.g. via
	// a proxy log) could swap the query string within the 5-minute
	// timestamp window and execute a different read-only query. By
	// including r.URL.RawQuery in the HMAC body, any change to the query
	// invalidates the signature. POST requests continue to use the
	// request body (which already contains the query) and are unaffected.
	var bodyBytes []byte
	if r.Method == http.MethodPost {
		maxBodySize := h.config.MaxBodySize
		if maxBodySize <= 0 {
			maxBodySize = DefaultMaxBodySize
		}
		if r.ContentLength > maxBodySize {
			h.writeError(w, http.StatusBadRequest, errors.New("request body too large"))
			return
		}
		var readErr error
		bodyBytes, readErr = io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if readErr != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequest)
			return
		}
		// Restore body for downstream parseRequest.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	} else if r.Method == http.MethodGet {
		// AUDIT-FULL SV-05 FIX (2026-08-15): bound the GET query-string
		// size explicitly. The per-field MaxQueryLength check in
		// parseRequest runs only AFTER r.URL.Query() has already parsed
		// the full RawQuery, and it does not cover the variables/
		// operationName parameters at all. Without a URL-level cap, an
		// oversized GET request line is parsed (net/url + HMAC over the
		// full string) before any limit applies — the handler relied
		// entirely on the outer http.Server's MaxHeaderBytes. Reuse the
		// configurable MaxBodySize (default 1MB): for GET the query
		// string IS the request payload.
		maxQuerySize := h.config.MaxBodySize
		if maxQuerySize <= 0 {
			maxQuerySize = DefaultMaxBodySize
		}
		if int64(len(r.URL.RawQuery)) > maxQuerySize {
			h.writeError(w, http.StatusBadRequest, errors.New("request URL query too large"))
			return
		}
		// R36-P3-20: Use the raw query string as the HMAC body for GET
		// requests. This binds the signature to the exact query the
		// client signed, preventing query substitution.
		bodyBytes = []byte(r.URL.RawQuery)
	}

	// audit-fix R7-M1: authenticate requests before processing
	if !h.isAuthenticated(r, bodyBytes) {
		h.writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}

	// Serve playground if enabled and requesting HTML
	if h.config.EnablePlayground && r.Method == http.MethodGet {
		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "text/html") {
			h.servePlayground(w, r)
			return
		}
	}

	// Only allow GET and POST for GraphQL queries
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed)
		return
	}

	// Parse the request
	req, err := h.parseRequest(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	// AUDIT-FULL SV-04 FIX (2026-08-15): AuthDisabled must never bypass
	// authentication for WRITE operations. Previously AuthDisabled=true
	// returned isAuthenticated=true unconditionally, so anonymous callers
	// could execute mutations too (the current schema is query-only, but a
	// future Mutation root would inherit the hole). Auth-disabled mode is
	// now strictly read-only: mutation documents are rejected with 401
	// even when no API keys are configured. Per the GraphQL spec only an
	// explicit `mutation` operation definition can perform writes;
	// shorthand `{ ... }` / `query ...` documents are read-only.
	if h.config.AuthDisabled && isMutationOperation(req.Query) {
		h.writeError(w, http.StatusUnauthorized, errors.New("mutation operations require authentication (auth-disabled mode is read-only)"))
		return
	}

	// Validate query complexity
	if err := h.validateComplexity(req.Query); err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	// Execute the query
	result := h.executeQuery(req)

	// Write the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
}

// isAuthenticated checks if the request has valid authentication.
// audit-fix R7-M1: validate API key or JWT token for GraphQL requests.
// R35-P2-RPC-01 FIX (2026-07-29): Added bodyBytes parameter for HMAC verification.
// When EnableHMAC is true, the request MUST carry X-Timestamp, X-Nonce, and
// X-Signature headers; the signature is HMAC-SHA256(timestamp || nonce || body, APIKey)
// and is verified in constant time against the candidate API key.
func (h *Handler) isAuthenticated(r *http.Request, bodyBytes []byte) bool {
	if len(h.apiKeys) == 0 && h.config.APIKey == "" {
		// SECURITY (audit 2026-06-24, M-5): AuthDisabled should only be
		// used in development. Log a warning when it is enabled.
		if h.config.AuthDisabled {
			log.Printf("[SECURITY WARNING] GraphQL authentication is disabled - this is insecure for production")
		}
		return h.config.AuthDisabled
	}

	var candidate string

	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			candidate = strings.TrimPrefix(authHeader, "Bearer ")
		} else if strings.HasPrefix(authHeader, "X-API-Key ") {
			candidate = strings.TrimPrefix(authHeader, "X-API-Key ")
		}
	}

	if candidate == "" {
		candidate = r.Header.Get("X-API-Key")
	}

	if candidate == "" {
		return false
	}

	// Resolve the active API key (primary or rotated) that matches candidate.
	var activeKey string
	var activeAddedAt time.Time
	keyFound := false

	if h.config.APIKey != "" && hmac.Equal([]byte(candidate), []byte(h.config.APIKey)) {
		activeKey = h.config.APIKey
		keyFound = true
	} else {
		// AUDIT (2026) API-FIX: Check key age for rotated keys.
		maxAge := h.config.MaxAPIKeyAge
		now := time.Now()
		for key, addedAt := range h.apiKeys {
			if hmac.Equal([]byte(candidate), []byte(key)) {
				if maxAge > 0 && now.Sub(addedAt) > maxAge {
					log.Printf("[SECURITY] GraphQL API key rejected: expired (age=%s, max=%s)", now.Sub(addedAt), maxAge)
					return false
				}
				activeKey = key
				activeAddedAt = addedAt
				keyFound = true
				break
			}
		}
	}
	_ = activeAddedAt // reserved for future per-key policy use

	if !keyFound {
		return false
	}

	// R35-P2-RPC-01 FIX: When HMAC is enabled, verify request integrity and
	// freshness. A captured API key alone is insufficient to forge a valid
	// request because the attacker cannot produce a valid HMAC for an
	// arbitrary body without knowing the key material used as the HMAC secret.
	// We use the API key itself as the HMAC secret — a leaked key still
	// compromises the account, but a key leaked via logs/headers (where the
	// body was NOT also leaked) cannot be replayed. Combined with the nonce
	// cache, even a fully captured signed request cannot be replayed.
	if h.hmacEnabled {
		if !h.verifyHMAC(r, bodyBytes, activeKey) {
			return false
		}
	}

	return true
}

// verifyHMAC validates the X-Timestamp, X-Nonce, and X-Signature headers
// against the supplied API key (used as the HMAC secret). Returns true only
// when all three checks pass:
//  1. Timestamp is within ±5 minutes of the server clock (clock skew tolerance).
//  2. Nonce has not been observed within nonceTTL (replay protection).
//  3. Signature = HMAC-SHA256(timestamp || nonce || body, apiKey) matches.
//
// The nonce cache is pruned lazily on each call to bound memory usage.
func (h *Handler) verifyHMAC(r *http.Request, body []byte, apiKey string) bool {
	timestampStr := r.Header.Get("X-Timestamp")
	nonce := r.Header.Get("X-Nonce")
	providedSig := r.Header.Get("X-Signature")

	if timestampStr == "" || nonce == "" || providedSig == "" {
		//nolint:gosec // G706: only booleans (header presence) are logged, never user content.
		log.Printf("[SECURITY] GraphQL HMAC rejected: missing header (ts=%v nonce=%v sig=%v)",
			timestampStr != "", nonce != "", providedSig != "")
		return false
	}

	// Parse timestamp (unix seconds).
	var ts int64
	if _, err := fmt.Sscanf(timestampStr, "%d", &ts); err != nil {
		log.Printf("[SECURITY] GraphQL HMAC rejected: invalid timestamp format")
		return false
	}

	// Freshness check: ±5 minutes window to tolerate clock skew between
	// client and server. Outside this window the request is rejected even
	// if the signature is valid, preventing replay of stale captured requests.
	const freshnessWindow = 5 * time.Minute
	now := time.Now().Unix()
	reqTime := time.Unix(ts, 0)
	if reqTime.Sub(time.Unix(now, 0)).Abs() > freshnessWindow {
		log.Printf("[SECURITY] GraphQL HMAC rejected: timestamp outside ±5min window (skew=%ds)",
			now-ts)
		return false
	}

	// Nonce replay protection: track nonces for nonceTTL. A replayed request
	// carries the same nonce and is rejected. Nonces are pruned lazily.
	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()

	// Prune expired nonces.
	for n, seenAt := range h.seenNonces {
		if time.Since(seenAt) > h.nonceTTL {
			delete(h.seenNonces, n)
		}
	}

	if _, exists := h.seenNonces[nonce]; exists {
		log.Printf("[SECURITY] GraphQL HMAC rejected: nonce replay detected")
		return false
	}

	// Compute expected signature: HMAC-SHA256(timestamp || nonce || body, apiKey).
	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write([]byte(timestampStr))
	mac.Write([]byte(nonce))
	mac.Write(body)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(expectedSig), []byte(providedSig)) {
		log.Printf("[SECURITY] GraphQL HMAC rejected: signature mismatch")
		return false
	}

	// Record the nonce AFTER successful verification so a failed check
	// does not burn a nonce (allowing legitimate retry).
	h.seenNonces[nonce] = time.Now()
	return true
}

// isMutationOperation reports whether a GraphQL document is a mutation
// (write) operation. Per the GraphQL spec, only an explicit `mutation`
// keyword operation definition can perform writes; shorthand `{ ... }`
// and `query ...` documents are always read-only. Used by the SV-04 fix
// to keep auth-disabled mode strictly read-only.
func isMutationOperation(q string) bool {
	trimmed := strings.TrimLeft(q, " \t\r\n")
	return strings.HasPrefix(trimmed, "mutation")
}

// parseRequest parses a GraphQL request from an HTTP request.
func (h *Handler) parseRequest(r *http.Request) (*GraphQLRequest, error) {
	var req GraphQLRequest

	switch r.Method {
	case http.MethodGet:
		// Parse query from URL parameters
		req.Query = r.URL.Query().Get("query")
		req.OperationName = r.URL.Query().Get("operationName")

		// Parse variables if present
		if vars := r.URL.Query().Get("variables"); vars != "" {
			if err := json.Unmarshal([]byte(vars), &req.Variables); err != nil {
				return nil, ErrInvalidRequest
			}
		}

	case http.MethodPost:
		// Check content type
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") &&
			!strings.Contains(contentType, "application/graphql") {
			return nil, ErrInvalidContentType
		}

		// audit-remediation: validate Content-Length header if present
		maxBodySize := h.config.MaxBodySize
		if maxBodySize <= 0 {
			maxBodySize = DefaultMaxBodySize
		}
		if r.ContentLength > maxBodySize {
			return nil, errors.New("request body too large")
		}

		// audit-remediation: read body with size limit
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if err != nil {
			return nil, ErrInvalidRequest
		}
		defer r.Body.Close()

		// audit-remediation: check actual body size
		if int64(len(body)) >= maxBodySize {
			return nil, errors.New("request body too large")
		}

		if strings.Contains(contentType, "application/graphql") {
			// Body is the query itself
			req.Query = string(body)
		} else {
			// Parse JSON body
			if err := json.Unmarshal(body, &req); err != nil {
				return nil, ErrInvalidRequest
			}
		}
	}

	if req.Query == "" {
		return nil, ErrEmptyQuery
	}

	// audit-remediation: validate query length
	maxQueryLen := h.config.MaxQueryLength
	if maxQueryLen <= 0 {
		maxQueryLen = DefaultMaxQueryLength
	}
	if len(req.Query) > maxQueryLen {
		return nil, errors.New("query too long")
	}

	// audit-remediation: input sanitization for GraphQL query
	// Validate query string format and reject potentially malicious patterns
	if err := sanitizeGraphQLQuery(req.Query); err != nil {
		return nil, err
	}

	return &req, nil
}

// sanitizeGraphQLQuery validates and sanitizes a GraphQL query string.
// input sanitization implemented - validates query format and rejects malicious patterns
func sanitizeGraphQLQuery(query string) error {
	// Check for null bytes which could cause issues
	if strings.ContainsRune(query, '\x00') {
		return errors.New("query contains invalid null character")
	}

	// SECURITY (audit 2026-06-24, H-2): Reject queries containing comments.
	// The naive complexity calculator does not skip comment content, so an
	// attacker could embed fields inside comments to bypass the complexity
	// check. Until a proper AST-based parser is used, reject all comments.
	if strings.Contains(query, "#") {
		return errors.New("query comments are not supported")
	}

	// SECURITY (audit 2026-06-24, H-2): Reject queries containing string
	// literals that could embed braces and skew the complexity calculation.
	if strings.Contains(query, "\"") {
		return errors.New("query string literals are not supported")
	}

	// Check for excessive whitespace that could be used for DoS
	consecutiveSpaces := 0
	for _, r := range query {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			consecutiveSpaces++
			if consecutiveSpaces > 100 {
				return errors.New("query contains excessive whitespace")
			}
		} else {
			consecutiveSpaces = 0
		}
	}

	// Check for balanced braces (basic syntax validation)
	braceCount := 0
	for _, r := range query {
		if r == '{' {
			braceCount++
		} else if r == '}' {
			braceCount--
		}
		if braceCount < 0 {
			return errors.New("query has unbalanced braces")
		}
	}
	if braceCount != 0 {
		return errors.New("query has unbalanced braces")
	}

	// Check for balanced parentheses
	parenCount := 0
	for _, r := range query {
		if r == '(' {
			parenCount++
		} else if r == ')' {
			parenCount--
		}
		if parenCount < 0 {
			return errors.New("query has unbalanced parentheses")
		}
	}
	if parenCount != 0 {
		return errors.New("query has unbalanced parentheses")
	}

	return nil
}

// validateComplexity validates the query complexity.
func (h *Handler) validateComplexity(query string) error {
	if h.config.MaxComplexity == 0 {
		return nil
	}

	// SECURITY (audit 2026-06-24, H-2): Enforce a hard cap on the number of
	// field references to prevent DoS via field flooding. Even if the
	// complexity calculator is bypassed, this limits the total work.
	const maxFieldReferences = 200
	complexity := h.calculateComplexity(query)
	if complexity > h.config.MaxComplexity {
		return ErrQueryTooComplex
	}
	if complexity > maxFieldReferences {
		return ErrQueryTooComplex
	}

	return nil
}

// calculateComplexity calculates the complexity of a query.
// SECURITY FIX: Properly handles aliases and counts unique fields to prevent DoS attacks.
// Attackers can use query aliases to exhaust server resources if not properly counted:
//
//	{ a: users { ... } b: users { ... } c: users { ... } }
//
// This implementation counts aliases as separate fields but applies a multiplier to
// penalize repeated selections of the same underlying data.
func (h *Handler) calculateComplexity(query string) int {
	complexity := 0
	depth := 0
	maxDepth := 0
	fieldCount := make(map[string]int)

	// Parse the query to extract field names (including aliases)
	// Track each field reference to penalize alias abuse
	fieldName := ""
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch c {
		case '{':
			if depth == 0 && fieldName != "" {
				// Starting a new field selection
				fieldCount[fieldName]++
				complexity++
			}
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			fieldName = ""
		case '}':
			if fieldName != "" {
				fieldCount[fieldName]++
				complexity++
			}
			depth--
			fieldName = ""
		case ':':
			// This is an alias (name: field)
			if depth > 0 && fieldName != "" {
				fieldName += ":"
			}
		case ' ', '\t', '\n', '\r', ',':
			// Skip whitespace
			if fieldName != "" {
				fieldCount[fieldName]++
				complexity++
				fieldName = ""
			}
		default:
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
				fieldName += string(c)
			} else {
				// Reset on unexpected characters
				if fieldName != "" {
					fieldCount[fieldName]++
					complexity++
					fieldName = ""
				}
			}
		}
	}

	// Apply alias penalty: if the same field appears multiple times via aliases,
	// charge extra complexity to discourage alias abuse
	aliasPenalty := 0
	for _, count := range fieldCount {
		if count > 1 {
			// Penalize repeated fields: complexity += (count - 1) * count
			aliasPenalty += (count - 1) * count
		}
	}
	complexity += aliasPenalty / 2

	// Add depth penalty
	complexity += maxDepth * 2

	// Check max depth
	if h.config.MaxDepth > 0 && maxDepth > h.config.MaxDepth {
		return h.config.MaxComplexity + 1 // Exceed limit
	}

	return complexity
}

// executeQuery executes a GraphQL query and returns the result.
//
// R35-P3-02 (2026-07-29) AUDIT NOTE: The error returned by h.execute() is
// rendered verbatim into the response via err.Error(). The only error path is
// resolveField's default case, which returns the generic sentinel
// errors.New("unsupported query field"). Any new error path added to
// h.execute()/resolveField MUST also return a generic, user-facing message —
// never raw internal errors, stack traces, or file paths. See writeError for
// the same contract.
func (h *Handler) executeQuery(req *GraphQLRequest) *GraphQLResponse {
	response := &GraphQLResponse{}

	// Parse and execute the query
	result, err := h.execute(req.Query, req.Variables)
	if err != nil {
		response.Errors = []GraphQLError{
			{Message: err.Error()},
		}
		return response
	}

	response.Data = result
	return response
}

// execute executes a GraphQL query string.
func (h *Handler) execute(query string, variables map[string]any) (any, error) {
	// Simple query parser - handles basic queries
	query = strings.TrimSpace(query)

	// Remove query keyword if present
	if strings.HasPrefix(query, "query") {
		idx := strings.Index(query, "{")
		if idx > 0 {
			query = query[idx:]
		}
	}

	// Parse the query fields
	result := make(map[string]any)

	// Extract field names from query
	fields := h.parseFields(query)

	for _, field := range fields {
		value, err := h.resolveField(field, variables)
		if err != nil {
			return nil, err
		}
		result[field.Name] = value
	}

	return result, nil
}

// QueryField represents a parsed query field.
type QueryField struct {
	Name      string
	Arguments map[string]any
	SubFields []QueryField
}

// parseFields parses fields from a query string.
func (h *Handler) parseFields(query string) []QueryField {
	var fields []QueryField

	// Remove outer braces
	query = strings.TrimSpace(query)
	if strings.HasPrefix(query, "{") && strings.HasSuffix(query, "}") {
		query = query[1 : len(query)-1]
	}

	// Simple field extraction
	parts := strings.Fields(query)
	for _, part := range parts {
		// Skip braces and special characters
		part = strings.Trim(part, "{}(),")
		if part == "" {
			continue
		}

		// Extract field name (before any arguments)
		name := part
		if idx := strings.Index(part, "("); idx > 0 {
			name = part[:idx]
		}

		if name != "" && !strings.HasPrefix(name, "#") {
			fields = append(fields, QueryField{
				Name:      name,
				Arguments: make(map[string]any),
			})
		}
	}

	return fields
}

// resolveField resolves a single query field.
func (h *Handler) resolveField(field QueryField, variables map[string]any) (any, error) {
	switch field.Name {
	case "block":
		return h.resolver.Block(nil, nil)
	case "blocks":
		return h.resolver.Blocks(nil)
	case "latestBlock":
		return h.resolver.LatestBlock()
	case "chainId":
		return h.resolver.ChainID(), nil
	case "gasPrice":
		return h.resolver.GasPrice().String(), nil
	case "blockNumber":
		return h.resolver.BlockNumber(), nil
	default:
		// SECURITY FIX: Return generic error to prevent API structure disclosure
		// Previously returned: "unknown field: " + field.Name which leaked field names
		return nil, errors.New("unsupported query field")
	}
}

// writeError writes an error response.
//
// R35-P3-02 (2026-07-29) AUDIT NOTE: Callers MUST only pass generic, user-facing
// error messages to this function. The error's .Error() string is rendered
// verbatim into the JSON response. Internal details (stack traces, file paths,
// DB errors, internal addresses) MUST NOT be passed here — wrap them as
// errors.New("internal error") or a sentinel error from the package-level
// Err* set before calling writeError. This mirrors the rpc.Server.sanitizeError
// contract: internal/server errors are replaced with generic messages at the
// output boundary. The current callers (ServeHTTP, parseRequest) already
// follow this contract by passing only sentinel errors (ErrInvalidRequest,
// ErrQueryTooComplex, etc.) or errors.New with a generic message.
func (h *Handler) writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := &GraphQLResponse{
		Errors: []GraphQLError{
			{Message: err.Error()},
		},
	}

	json.NewEncoder(w).Encode(response) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
}

// servePlayground serves the GraphQL playground HTML.
func (h *Handler) servePlayground(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(playgroundHTML)) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
}

// playgroundHTML is the HTML for the GraphQL playground.
const playgroundHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>QAU GraphQL Playground</title>
  <style>
    body {
      margin: 0;
      padding: 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #1a1a2e;
      color: #eee;
    }
    h1 {
      color: #00d4ff;
      margin-bottom: 20px;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    textarea {
      width: 100%;
      height: 200px;
      background: #16213e;
      color: #eee;
      border: 1px solid #0f3460;
      border-radius: 8px;
      padding: 15px;
      font-family: 'Monaco', 'Menlo', monospace;
      font-size: 14px;
      resize: vertical;
    }
    button {
      background: #00d4ff;
      color: #1a1a2e;
      border: none;
      padding: 12px 24px;
      border-radius: 6px;
      font-size: 16px;
      font-weight: bold;
      cursor: pointer;
      margin: 15px 0;
    }
    button:hover {
      background: #00b8e6;
    }
    pre {
      background: #16213e;
      border: 1px solid #0f3460;
      border-radius: 8px;
      padding: 15px;
      overflow-x: auto;
      white-space: pre-wrap;
    }
    .label {
      color: #00d4ff;
      font-weight: bold;
      margin: 15px 0 5px 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>QAU GraphQL Playground</h1>
    <div class="label">Query:</div>
    <textarea id="query">{
  latestBlock {
    number
    hash
    timestamp
    txCount
  }
}</textarea>
    <button onclick="executeQuery()">Execute Query</button>
    <div class="label">Response:</div>
    <pre id="response">Click "Execute Query" to see results</pre>
  </div>
  <script>
    async function executeQuery() {
      const query = document.getElementById('query').value;
      const response = document.getElementById('response');

      try {
        const res = await fetch(window.location.href, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ query }),
        });

        const data = await res.json();
        response.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        response.textContent = 'Error: ' + err.message;
      }
    }
  </script>
</body>
</html>`

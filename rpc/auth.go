// Quantaureum Node source, version 1.0.0.
// Package rpc provides JSON-RPC 2.0 server with authentication and rate limiting.
package rpc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// SECURITY FIX Q-B-008: Use memguard for protected memory of HMAC secrets.
	// This places the secret in a locked mlock'd page that is excluded from
	// core dumps and swapped pages. is excluded from
	// core dumps and swapped pages, and provides explicit Destroy() for zeroing.
	"github.com/awnumar/memguard"
)

// Authentication errors
var (
	ErrAuthRequired      = errors.New("authentication required")
	ErrInvalidAPIKey     = errors.New("invalid API key")
	ErrAPIKeyExpired     = errors.New("API key expired")
	ErrIPNotAllowed      = errors.New("IP address not allowed")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	// P2P-R11-M05 (2026-07-20) FIX: distinct error for brute-force lockout so
	// monitoring can distinguish "throttled" from "locked-out-after-N-failures".
	ErrAuthLockedOut = errors.New("authentication locked out due to repeated failures")
)

// SECURITY: Nonce cache limits to prevent memory exhaustion
const (
	// MaxNonceCacheSize is the maximum number of unique nonces to track
	// SECURITY FIX: Prevents memory exhaustion from nonce flood attacks
	MaxNonceCacheSize = 100000

	// NonceMaxAge is how long to keep a nonce before evicting it
	NonceMaxAge = 6 * time.Minute

	// RateLimiterMaxAge is how long to keep a rate limiter entry before evicting it.
	// FIX: prevents unbounded memory growth from inactive API keys whose
	// entries never get removed (only deleted keys had their entries cleaned).
	RateLimiterMaxAge = 30 * time.Minute

	// P2P-R11-M05 (2026-07-20) FIX: brute-force protection constants.
	// After MaxAuthFailures consecutive failed authentications from a single
	// IP within AuthFailureWindow, that IP is locked out for AuthLockoutDuration.
	// API keys are 256-bit hashes so brute force is computationally infeasible,
	// but defense-in-depth is warranted: an attacker enumerating keys could
	// probe which keys exist via timing/error differences, or use the auth
	// endpoint for enumeration/dictionary attacks against weak user-chosen
	// API keys. A 10-attempt threshold is high enough to avoid false
	// positives from a misconfigured client retrying after transient errors,
	// while still blocking scripted brute force within seconds.
	MaxAuthFailures       = 10
	AuthFailureWindow     = 5 * time.Minute
	AuthLockoutDuration   = 15 * time.Minute
	AuthFailureCleanupAge = 30 * time.Minute
)

// authFailureEntry tracks consecutive authentication failures from a single IP.
// P2P-R11-M05 (2026-07-20) FIX: used by AuthManager to lock out IPs that
// repeatedly fail authentication. Successful auth resets the entry.
type authFailureEntry struct {
	count        int
	firstFailure time.Time
	lastFailure  time.Time
	lockedUntil  time.Time
}

// APIKeyInfo holds information about an API key
type APIKeyInfo struct {
	Key         string
	KeyHash     string // audit-fix M-1: SHA-256 hash of the key for secure storage
	Name        string
	Permissions []string // Allowed methods, empty means all
	IPWhitelist []string // Allowed IPs, empty means all
	RateLimit   int      // Requests per minute, 0 means default
	CreatedAt   time.Time
	ExpiresAt   time.Time // Zero means never expires
	// LOW-1 FIX: Use atomic operations for stats updated under RLock to prevent data races.
	// LastUsed stores Unix nanoseconds; use Load/Store with atomic.Int64.
	// UsageCount uses atomic.Uint64 for lock-free increment.
	lastUsedNano atomic.Int64
	UsageCount   atomic.Uint64
}

// LastUsedTime returns the LastUsed time as time.Time (thread-safe).
func (info *APIKeyInfo) LastUsedTime() time.Time {
	nano := info.lastUsedNano.Load()
	if nano == 0 {
		return time.Time{}
	}
	return time.Unix(0, nano)
}

// SetLastUsed sets the LastUsed timestamp (thread-safe).
func (info *APIKeyInfo) SetLastUsed(t time.Time) {
	info.lastUsedNano.Store(t.UnixNano())
}

// IncrementUsage atomically increments the usage count and returns the new value.
func (info *APIKeyInfo) IncrementUsage() uint64 {
	return info.UsageCount.Add(1)
}

// hashAPIKey computes a SHA-256 hash of the API key for secure storage.
// audit-fix M-1: keys are stored as hashes to prevent leakage if config is dumped.
func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	// Enable authentication
	Enabled bool

	// API keys (key -> info)
	APIKeys map[string]*APIKeyInfo

	// Global IP whitelist (empty means allow all)
	GlobalIPWhitelist []string

	// Methods that don't require authentication
	PublicMethods []string

	// Header name for API key
	APIKeyHeader string

	// Enable HMAC signature verification
	EnableHMAC bool

	// SECURITY FIX Q-B-008: HMAC secret is stored in a memguard.Enclave.
	// The raw bytes are never exposed in Go-managed memory; they are decrypted
	// only inside a memguard.LockedBuffer during verification and immediately
	// wiped afterward. This prevents extraction via memory dumps or core dumps.
	hmacSecretEnclave *memguard.Enclave

	// TrustedProxies is a list of trusted proxy IPs that can set X-Forwarded-For
	// If empty, X-Forwarded-For header is NOT trusted (use RemoteAddr directly)
	TrustedProxies []string

	// R38-P4 FIX: MaxBodySize is the maximum request body size for HMAC
	// verification. If 0, defaults to MaxRequestBodySize. This should match
	// the server's maxBodySize to prevent signature/handler-body divergence.
	MaxBodySize int64
}

// SetHMACSecret securely stores the HMAC secret in a memguard-protected Enclave.
// Call this before creating the AuthManager to enable HMAC signature verification.
// SECURITY FIX Q-B-008: The raw secret bytes are copied into protected memory
// and immediately wiped from the caller's slice. Enclave does not expose Destroy()
// so repeated calls overwrite the reference; the sealed data is protected until GC.
func (c *AuthConfig) SetHMACSecret(secret []byte) {
	c.hmacSecretEnclave = memguard.NewEnclave(secret)
}

// DefaultAuthConfig returns default authentication configuration
// NOTE: Authentication is enabled by default for security. Disable only for development.
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{ // #nosec G101 -- No hardcoded credentials; APIKeys is initialized as empty map
		Enabled: true, // Enabled by default for security
		APIKeys: make(map[string]*APIKeyInfo),
		PublicMethods: []string{
			// Read-only methods that don't require authentication (standard eth_ namespace)
			"web3_clientVersion",
			"web3_sha3", // R50-RP-03 FIX: Pure utility function, no side effects
			"net_version",
			"net_listening",
			"eth_chainId",
			"eth_blockNumber",
			"eth_syncing",
			"eth_gasPrice",
			"eth_getBalance",
			"eth_getTransactionCount",
			"eth_getCode",
			"eth_getStorageAt",
			"eth_getBlockByHash",
			"eth_getBlockByNumber",
			"eth_getBlockTransactionCountByHash",
			"eth_getBlockTransactionCountByNumber",
			"eth_getTransactionByHash",
			"eth_getTransactionByBlockHashAndIndex",
			"eth_getTransactionByBlockNumberAndIndex",
			"eth_getTransactionReceipt",
			"eth_getLogs",
			// RP-01 FIX: Standard eth_* filter methods. These are read-only
			// query/subscription helpers (filter lifecycle + polling) with no
			// chain-state mutation, so they do not require API-key auth.
			// Handlers registered in api.go (NewFilter/NewBlockFilter/etc.).
			"eth_newFilter",
			"eth_newBlockFilter",
			"eth_newPendingTransactionFilter",
			"eth_uninstallFilter",
			"eth_getFilterChanges",
			"eth_getFilterLogs",
			// R90-WS-PUBLIC (2026-08-30): the WebSocket subscription lifecycle is
			// the same category as the filter methods above — read-only,
			// no chain-state mutation — but it was never allowlisted, so on a
			// production node with rpcAuthEnabled=true every wallet subscription
			// was rejected with -32001 "authentication required". handleRequest in
			// websocket.go routes subscribe/unsubscribe through ValidateRequest
			// like any other method, so a public chain cannot serve push updates
			// (new heads, pending tx, logs) without these two entries. Found while
			// preparing the R90 reverse-proxy deployment; no devnet caught it
			// because every one of them ran with devMode=true (auth off).
			//
			// DoS surface is bounded independently of auth: handleSubscribe
			// enforces MaxSubscriptionsPerConn (10) per connection, and the rate
			// limiter runs on the WS path before dispatch.
			"eth_subscribe",
			"eth_unsubscribe",
			// R51-RP-01 FIX: Additional standard read-only methods that were
			// missing from PublicMethods, forcing API Key auth for no-side-effect
			// queries. Cross-referenced with all RegisterHandler calls across
			// api.go, fee_api.go, proof_api.go, and blob_api.go.
			// NOTE: txpool_content is intentionally excluded — it is an
			// AdminMethod per R50-RP-04.
			"eth_protocolVersion",
			"net_peerCount",
			"eth_feeHistory",
			"eth_maxPriorityFeePerGas",
			"txpool_status",
			// AUDIT (2026) API-01: eth_pendingTransactions and txpool_inspect
			// removed from public allowlist. Both return full pending transaction
			// details (same as admin-gated txpool_content), leaking the entire
			// mempool to unauthenticated callers. This breaks commit-reveal
			// front-running protection — attackers can see pending commits and
			// front-run them. txpool_status remains public (returns only counts).
			// eth_pendingTransactions and txpool_inspect now require admin auth.
			"eth_getProof",
			"eth_blobBaseFee",
			"eth_getBlobSidecar",
			// Transaction methods - public because security is enforced
			// at the signature/validation level, not the RPC level
			"eth_sendRawTransaction",
			"eth_estimateGas",
			"eth_call",
			// FIX: eth_createAccessList is a read-only EIP-2930 method
			// that simulates access list creation. It must be in the public methods
			// whitelist so external tools (Hardhat/Foundry) can use it without auth.
			"eth_createAccessList",
			// Quantaureum-unique public methods (kept under qau_ namespace)
			// P2-PRIVACY-ADMIN FIX (R29, 2026-07-26): qau_sendPrivacyTransaction
			// is intentionally NOT listed here — it takes (from, to, amount)
			// without a user-provided signature, so the node signs on behalf
			// of the user (like eth_sendTransaction), making it admin-only.
			// Listing it here would bypass the admin gate registered in
			// api.go via RegisterAdminMethod.
			// CRV2: qau_submitCommitment was deleted — commitments are ordinary
			// TxTypeCommit transactions submitted through eth_sendRawTransaction,
			// so there is no commitment RPC left to allowlist.
			"qau_sendUserOperation",
			"qau_estimateUserOperationGas",
			"qau_getUserOperationByHash",
			"qau_getUserOperationReceipt",
			"qau_supportedEntryPoints",
			// R48-RP-01 FIX: DeFi state-mutating methods use their own
			// Dilithium3 signature verification (verifyDeFiSignature), so
			// they are public at the RPC level — security is enforced at
			// the signature level, not the API key level.
			"qau_addLiquidity",
			"qau_removeLiquidity",
			"qau_swap",
			"qau_supply",
			"qau_withdraw",
			"qau_borrow",
			"qau_repay",
			"qau_liquidate",
			"qau_stakeFarm",
			"qau_unstakeFarm",
			"qau_harvestFarm",
			// R48-RP-02/03/04 FIX: Staking methods use their own Dilithium3
			// signature verification, so they are public at the RPC level —
			// security is enforced at the signature level.
			//
			// NOTE: "public at the RPC level" is
			// not the whole story. In non-dev mode node.go seeds
			// API.adminAddrs with the genesis validators and turns on
			// enforceAdminAuth, so requireAuthorizedUser rejects every other
			// address with -32003. On a production node these four methods are
			// therefore usable only by the validators, and a user wallet's
			// staking relay can fail. See docs/commit-reveal-v2-design.md §8.
			"qau_stake",
			"qau_unstake",
			"qau_claimRewards",
			"qau_compoundRewards",
			"qau_updateCommission",
			// R50-RP-02 FIX: Read-only qau_* methods that were missing from
			// PublicMethods, forcing API Key auth for no-side-effect queries.
			"qau_qposStatus",
			"qau_getStake",
			"qau_getStakingPools",
			"qau_getStakingStats",
			"qau_getUserStakes",
			"qau_getStakingContracts",
			"qau_getPendingRewards",
			"qau_getUnstakeStatus",
			"qau_getContractBalance",
			"qau_getContractList",
			"qau_getRewardPoolStatus",
			"qau_getTotalRewardsClaimed",
			"qau_verifyQuantumTransaction",
			"qau_scanPrivacy",
			"qau_getPrivacyBalance",
			// RP-03 FIX: Pure computation method — derives a stealth address
			// from public key material with no side effects. Handler in api.go.
			"qau_generateStealthAddress",
			// R51-RP-02 FIX: Read-only qau_* methods that were missing from
			// PublicMethods. Cross-referenced with ALL RegisterHandler calls
			// across the rpc package (multisig_api.go, governance_api.go,
			// economics_api.go, defi_api.go, qtd_api.go, quantum_api.go,
			// stardust_api.go, bridge_api.go, builder_api.go).
			// Admin-gated methods (generateKeyShares/getShare/signMessage/
			// verifySignature/registerMultisigWallet/createMultisigProposal/
			// approveMultisigProposal/executeMultisigProposal/createProposal/
			// castVote/finalizeProposal/executeProposal/claimDeFiIncentives/
			// liquidStake/liquidUnstake/bridgeGetPendingTransfers/
			// builder_submitBid) are intentionally EXCLUDED.
			// Multisig read-only queries (multisig_api.go)
			"qau_getMultisigWallet",
			"qau_isMultisigWallet",
			"qau_getPendingMultisigProposals",
			"qau_getMultisigProposal",
			"qau_getAllMultisigProposals",
			"qau_getProposalsForSigner",
			"qau_getIncomingMultisigTransfers",
			// Governance read-only queries (governance_api.go)
			"qau_getProposal",
			"qau_getActiveProposals",
			"qau_getProposalCount",
			"qau_getVote",
			"qau_getGovernanceConfig",
			"qau_getGovernanceParameters",
			"qau_getGovernanceParameter",
			// Economics read-only queries (economics_api.go)
			"qau_getInflationInfo",
			"qau_getSupply",
			"qau_getFeeDistribution",
			"qau_getRewardStats",
			"qau_getDeFiIncentives",
			"qau_getExchangeRate",
			"qau_getLiquidStakingPosition",
			// DeFi read-only queries (defi_api.go)
			"qau_getLiquidityPools",
			"qau_getLiquidityPool",
			"qau_getSwapQuote",
			"qau_getUserLPBalance",
			"qau_getLendingPools",
			"qau_getLendingPool",
			"qau_getUserLendingPosition",
			"qau_getYieldFarms",
			"qau_getYieldFarm",
			"qau_getFarmPendingReward",
			"qau_getUserFarmStake",
			// TSS read-only queries (qtd_api.go)
			"qau_tss_status",
			"qau_tss_getPublicKey",
			// Quantum read-only queries (quantum_api.go)
			"qau_quantumGetMPCStatus",
			"qau_quantumVerifyZKP",
			"qau_quantumGetKeyRotationStatus",
			// AUDIT (2026) API-02: qau_qrngGetRandom removed from public
			// allowlist. This endpoint drains quantum entropy (up to 1024 bytes
			// per call) and if the QRNG instance is shared with consensus
			// entropy, an attacker could correlate or predict consensus
			// randomness. It now requires admin authentication. Additionally,
			// the max bytes per call has been reduced from 1024 to 64.
			// Stardust finality read-only queries (stardust_api.go)
			"qau_stardust_getFinality",
			"qau_stardust_getChambers",
			"qau_stardust_getMinistryStatus",
			"qau_stardust_verifyFinality",
			"qau_stardust_getQTDFinalityStatus",
			"qau_stardust_getExecutiveChamber",
			"qau_stardust_getReviewChamber",
			"qau_stardust_getThreeChambersFlow",
			// Bridge read-only queries (bridge_api.go)
			"qau_bridgeGetStatus",
			"qau_bridgeGetSupportedChains",
			// Builder read-only queries (builder_api.go)
			"qau_builder_getSlotInfo",
			"qau_builder_getWinningBid",
			// RP-02 FIX: Rollup read-only queries (rollup_api.go).
			// qau_rollupGetTransactions was NOT added: a grep across the rpc
			// package found no handler registration for it (only
			// qau_rollupGetStatus, qau_rollupGetBatch, and qau_rollupGetStateRoot
			// are registered in rollup_api.go).
			"qau_rollupGetStatus",
			"qau_rollupGetBatch",
			"qau_rollupGetStateRoot", // FIX: missed in the earlier pass; added here
		},
		APIKeyHeader: "X-API-Key",
		// audit-fix C-4: CRITICAL - HMAC validation must be ENABLED by default for security
		// Production deployments MUST verify HMAC signatures on all non-public methods
		// Disabling HMAC creates a critical authentication bypass vulnerability
		EnableHMAC: true,
	}
}

// apiKeyRateEntry tracks per-key request rate within a sliding window.
type apiKeyRateEntry struct {
	count       int
	windowStart time.Time
}

// AuthManager manages API authentication
type AuthManager struct {
	mu     sync.RWMutex
	config *AuthConfig
	// audit-fix M-4: per-key rate limiting state (separate lock from config)
	rateMu       sync.Mutex
	rateLimiters map[string]*apiKeyRateEntry
	// FIX: rateLimiters map is now cleaned up by cleanupRateLimiters
	// goroutine (started in NewAuthManager). Entries whose windowStart is older
	// than RateLimiterMaxAge (30 min) are evicted to prevent unbounded growth.
	// audit-fix H-3: nonce cache to prevent HMAC replay within 5-min window
	nonceMu    sync.Mutex
	seenNonces map[string]time.Time // nonce -> first-seen timestamp
	// P2P-R11-M05 (2026-07-20) FIX: per-IP brute-force protection.
	// authFailures tracks consecutive failed authentications per IP. After
	// MaxAuthFailures within AuthFailureWindow, the IP is locked out for
	// AuthLockoutDuration. A successful auth resets the counter. This is
	// distinct from rateLimiters (which throttles per-key throughput on
	// successful auth) and from rpc/ratelimit.go (which throttles per-IP
	// request volume regardless of auth outcome).
	authFailuresMu sync.Mutex
	authFailures   map[string]*authFailureEntry
	// audit-fix N-3: stop channel for cleanupNonces goroutine
	stopCh   chan struct{}
	stopOnce sync.Once // audit-fix  prevent panic on double-close
	// HIGH FIX: Use atomic monotonic counter for replay protection instead of wall clock time
	// This provides monotonic clock behavior even when system clock jumps
	lastTimestampCounter atomic.Uint64 // monotonic counter for timestamp validation
	// RPC2-002 FIX: monotonicEpoch is the time at which AuthManager was created.
	// We use now.Sub(monotonicEpoch) for the internal replay counter, which
	// is immune to NTP clock rollback because Go's monotonic clock never goes
	// backwards. The wall-clock timestamp (tsNano/nowNano) is still used for
	// the 5-minute freshness window, but the CAS counter uses monotonic time.
	monotonicEpoch time.Time
	// RPC-004 FIX: whitelist of method names that may receive admin-level
	// authorization through ValidateAdminRequest. Populated via
	// RegisterAdminMethod (mirrors Server.RegisterAdminMethod). When nil (not
	// configured) the whitelist check is skipped for backward compatibility;
	// when populated, ValidateAdminRequest rejects any method not in the set —
	// defense-in-depth so admin authorization cannot be granted to a
	// non-admin method by a misrouted/direct call. Protected by am.mu.
	adminMethods map[string]bool
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(config *AuthConfig) *AuthManager {
	if config == nil {
		config = DefaultAuthConfig()
	}
	am := &AuthManager{
		config:       config,
		rateLimiters: make(map[string]*apiKeyRateEntry),
		seenNonces:   make(map[string]time.Time),
		authFailures: make(map[string]*authFailureEntry),
		stopCh:       make(chan struct{}),
	}
	// RPC2-002 FIX: lastTimestampCounter is in the same unit as
	// `monotonicNow = now.Sub(monotonicEpoch).Nanoseconds()` (verified in
	// verifyHMACWithNonce and verifyBatchHMACWithNonce), NOT wall-clock
	// nanoseconds. Initializing to wall-clock time made the CAS counter
	// astronomically larger than monotonicNow, so every request failed
	// with "timestamp must be monotonically increasing". Start at 0 so the
	// first request (monotonicNow ≈ 0) is accepted.
	am.lastTimestampCounter.Store(0)
	// RPC2-002 FIX: Record the monotonic time at creation for delta-based counter.
	am.monotonicEpoch = time.Now()
	// audit-fix H-3: start background goroutine to evict expired nonces
	go am.cleanupNonces()
	// FIX: start background goroutine to evict stale rate limiter entries
	go am.cleanupRateLimiters()
	// P2P-R11-M05 (2026-07-20) FIX: start background goroutine to evict
	// stale auth-failure entries (otherwise an attacker cycling IPs could
	// grow the map unbounded).
	go am.cleanupAuthFailures()
	return am
}

// checkAuthLockout returns ErrAuthLockedOut if the requesting IP is currently
// in a brute-force lockout window. P2P-R11-M05 (2026-07-20) FIX.
// Caller must NOT hold am.authFailuresMu.
func (am *AuthManager) checkAuthLockout(clientIP string) error {
	if clientIP == "" {
		return nil
	}
	am.authFailuresMu.Lock()
	defer am.authFailuresMu.Unlock()
	entry, exists := am.authFailures[clientIP]
	if !exists {
		return nil
	}
	if entry.lockedUntil.IsZero() {
		return nil
	}
	if time.Now().Before(entry.lockedUntil) {
		return ErrAuthLockedOut
	}
	return nil
}

// recordAuthFailure increments the per-IP failure counter and, if the
// threshold is reached, sets lockedUntil = now + AuthLockoutDuration.
// P2P-R11-M05 (2026-07-20) FIX. Caller must NOT hold am.authFailuresMu.
func (am *AuthManager) recordAuthFailure(clientIP string) {
	if clientIP == "" {
		return
	}
	now := time.Now()
	am.authFailuresMu.Lock()
	defer am.authFailuresMu.Unlock()
	entry, exists := am.authFailures[clientIP]
	if !exists {
		entry = &authFailureEntry{firstFailure: now}
		am.authFailures[clientIP] = entry
	}
	// Reset the window if the first failure is older than AuthFailureWindow —
	// this prevents an attacker from accumulating failures slowly over hours.
	if now.Sub(entry.firstFailure) > AuthFailureWindow {
		entry.count = 0
		entry.firstFailure = now
	}
	entry.count++
	entry.lastFailure = now
	if entry.count >= MaxAuthFailures {
		entry.lockedUntil = now.Add(AuthLockoutDuration)
		// Reset count so a second wave of failures after lockout expiry
		// requires another MaxAuthFailures events (not 0 from the previous
		// wave).
		entry.count = 0
		entry.firstFailure = now
	}
}

// resetAuthFailures clears the per-IP failure counter on successful auth.
// P2P-R11-M05 (2026-07-20) FIX. Caller must NOT hold am.authFailuresMu.
func (am *AuthManager) resetAuthFailures(clientIP string) {
	if clientIP == "" {
		return
	}
	am.authFailuresMu.Lock()
	defer am.authFailuresMu.Unlock()
	delete(am.authFailures, clientIP)
}

// cleanupAuthFailures periodically evicts auth-failure entries whose
// lastFailure is older than AuthFailureCleanupAge. P2P-R11-M05 (2026-07-20) FIX.
// Without this, an attacker cycling IPs could grow the map unbounded.
func (am *AuthManager) cleanupAuthFailures() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-am.stopCh:
			return
		case <-ticker.C:
			am.authFailuresMu.Lock()
			now := time.Now()
			for ip, entry := range am.authFailures {
				// Evict if the entry has no active lockout AND the last
				// failure is older than the cleanup age.
				if !entry.lockedUntil.IsZero() && now.Before(entry.lockedUntil) {
					continue
				}
				if now.Sub(entry.lastFailure) > AuthFailureCleanupAge {
					delete(am.authFailures, ip)
				}
			}
			am.authFailuresMu.Unlock()
		}
	}
}

// cleanupNonces periodically removes expired nonces from the seen set.
// audit-fix H-3: prevents unbounded memory growth of nonce cache.
// audit-fix N-3: respects stopCh for graceful shutdown.
func (am *AuthManager) cleanupNonces() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-am.stopCh:
			return
		case <-ticker.C:
			am.nonceMu.Lock()
			now := time.Now()
			for nonce, seen := range am.seenNonces {
				if now.Sub(seen) > NonceMaxAge { // keep 1 min beyond window
					delete(am.seenNonces, nonce)
				}
			}
			am.nonceMu.Unlock()
		}
	}
}

// cleanupRateLimiters periodically removes stale rate limiter entries.
// FIX: prevents unbounded memory growth of the rateLimiters map.
// Entries for API keys that are never deleted accumulate indefinitely.
// This goroutine evicts entries whose windowStart is older than
// RateLimiterMaxAge (30 minutes), similar to cleanupNonces.
func (am *AuthManager) cleanupRateLimiters() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-am.stopCh:
			return
		case <-ticker.C:
			am.rateMu.Lock()
			now := time.Now()
			for key, entry := range am.rateLimiters {
				if now.Sub(entry.windowStart) > RateLimiterMaxAge {
					delete(am.rateLimiters, key)
				}
			}
			am.rateMu.Unlock()
		}
	}
}

// Stop shuts down the AuthManager's background goroutines.
// audit-fix N-3: allows clean shutdown of cleanupNonces goroutine.
// audit-fix  uses sync.Once to prevent panic on double-close.
// audit-fix L-2: clears HMAC secret from memory on shutdown to prevent key leakage
// via memory dumps, core dumps, or swapped pages.
func (am *AuthManager) Stop() {
	am.stopOnce.Do(func() {
		close(am.stopCh)
	})
	// SECURITY FIX Q-B-008: Clear the memguard Enclave reference on shutdown.
	// Enclave data remains sealed/encrypted in protected memory until GC.
	// The LockedBuffer opened during Verify is already destroyed via defer.
	am.mu.Lock()
	if am.config != nil && am.config.hmacSecretEnclave != nil {
		am.config.hmacSecretEnclave = nil
	}
	am.mu.Unlock()
}

// sanitizedForStorage returns a copy of info suitable for long-lived storage:
// the plaintext Key is dropped and only KeyHash is retained.
// RPC-002 FIX (deep-audit 2026-07-03): the stored APIKeyInfo previously kept
// the plaintext key in memory for the lifetime of the key, so a heap dump or
// memory disclosure leaked every registered credential. Validation only needs
// the hash (lookups are by hashAPIKey of the presented key), so the stored
// entry never needs the plaintext. Atomic stat fields start fresh; usage
// stats accrue on the stored copy.
func sanitizedForStorage(info *APIKeyInfo) *APIKeyInfo {
	stored := &APIKeyInfo{
		KeyHash:     info.KeyHash,
		Name:        info.Name,
		Permissions: info.Permissions,
		IPWhitelist: info.IPWhitelist,
		RateLimit:   info.RateLimit,
		CreatedAt:   info.CreatedAt,
		ExpiresAt:   info.ExpiresAt,
	}
	stored.lastUsedNano.Store(info.lastUsedNano.Load())
	stored.UsageCount.Store(info.UsageCount.Load())
	return stored
}

// GenerateAPIKey generates a new API key.
// RPC-002 FIX: the returned APIKeyInfo carries the plaintext key exactly once
// so the caller can hand it to the user; the entry stored in the manager
// retains only the SHA-256 hash.
func (am *AuthManager) GenerateAPIKey(name string, permissions []string, expiresIn time.Duration) (*APIKeyInfo, error) {
	// Generate 32 random bytes
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}

	key := hex.EncodeToString(keyBytes)
	keyH := hashAPIKey(key)

	info := &APIKeyInfo{
		Key:         key,
		KeyHash:     keyH,
		Name:        name,
		Permissions: permissions,
		CreatedAt:   time.Now(),
	}

	if expiresIn > 0 {
		info.ExpiresAt = time.Now().Add(expiresIn)
	}

	// audit-fix M-1: store by hash to prevent key leakage if config is dumped
	// RPC-002 FIX: store a sanitized copy without the plaintext key
	am.mu.Lock()
	am.config.APIKeys[keyH] = sanitizedForStorage(info)
	am.mu.Unlock()

	return info, nil
}

// AddAPIKey adds an existing API key.
// RPC-002 FIX: only a sanitized copy (hash, no plaintext) is stored; the
// caller's struct is not retained or mutated.
func (am *AuthManager) AddAPIKey(info *APIKeyInfo) {
	am.mu.Lock()
	defer am.mu.Unlock()
	// audit-fix M-1: store by hash
	if info.KeyHash == "" {
		info.KeyHash = hashAPIKey(info.Key)
	}
	am.config.APIKeys[info.KeyHash] = sanitizedForStorage(info)
}

// RemoveAPIKey removes an API key
func (am *AuthManager) RemoveAPIKey(key string) {
	keyH := hashAPIKey(key)
	am.mu.Lock()
	delete(am.config.APIKeys, keyH)
	am.mu.Unlock()

	// audit-fix M-3: clean up rate limiter entry to prevent memory leak
	am.rateMu.Lock()
	delete(am.rateLimiters, keyH)
	am.rateMu.Unlock()
}

// IsPublicMethod reports whether the given method is in the configured public
// methods list and therefore does not require authentication.
// SECURITY FIX (P1): Exposed for batch request handling so the server can
// distinguish public from protected methods when authorizing each element of
// a batch individually.
func (am *AuthManager) IsPublicMethod(method string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	for _, m := range am.config.PublicMethods {
		if m == method {
			return true
		}
	}
	return false
}

// ValidateRequest validates an HTTP request, performing full authentication:
// API key verification, method permissions, IP whitelist, HMAC signature, and
// per-key rate limiting.
func (am *AuthManager) ValidateRequest(r *http.Request, method string) error {
	return am.validateRequest(r, method, true, true)
}

// AuthorizeMethod performs per-method authorization (API key, permissions, IP
// whitelist, expiration) WITHOUT HMAC signature verification or rate limiting.
// SECURITY FIX (P1): Used for batch requests where the HMAC signature covers
// the entire body and is verified once (via ValidateRequest on the first
// non-public method), but each subsequent non-public method must still be
// individually authorized.
func (am *AuthManager) AuthorizeMethod(r *http.Request, method string) error {
	return am.validateRequest(r, method, false, false)
}

// validateRequest is the shared authorization core. verifyHMAC controls whether
// the HMAC signature is checked (only once per batch). isFullValidation controls
// rate limiting and usage-stat updates (only for the primary validation pass).
func (am *AuthManager) validateRequest(r *http.Request, method string, verifyHMAC, isFullValidation bool) error {
	am.mu.RLock()
	defer am.mu.RUnlock()

	// Check if authentication is enabled
	if !am.config.Enabled {
		return nil
	}

	// Check if method is public
	for _, m := range am.config.PublicMethods {
		if m == method {
			return nil
		}
	}

	// P2P-R11-M05 (2026-07-20) FIX: brute-force lockout check BEFORE any
	// auth-state mutation. Once an IP hits MaxAuthFailures in a window, it
	// is locked out for AuthLockoutDuration regardless of which API key it
	// subsequently presents. Without this guard, an attacker could keep
	// cycling API keys against the same endpoint to bypass per-key throttling.
	clientIP := getClientIPWithTrust(r, am.config.TrustedProxies)
	if err := am.checkAuthLockout(clientIP); err != nil {
		return err
	}

	// Check global IP whitelist
	if len(am.config.GlobalIPWhitelist) > 0 {
		if !am.isIPAllowed(clientIP, am.config.GlobalIPWhitelist) {
			return ErrIPNotAllowed
		}
	}

	// Get API key from header only.
	// audit-fix R2-M3: removed URL query parameter fallback to prevent
	// API key leakage via server logs, browser history, and Referer headers.
	apiKey := r.Header.Get(am.config.APIKeyHeader)
	if apiKey == "" {
		// P2P-R11-M05: missing API key is treated as a failure. An attacker
		// probing without an API key should also be subject to lockout.
		am.recordAuthFailure(clientIP)
		return ErrAuthRequired
	}

	// audit-fix M-1: hash the provided key and look up by hash.
	// Constant-time iteration still used to prevent timing side-channels.
	// audit-fix H-3: direct map lookup by hash. Since API keys are stored by their
	// SHA-256 hash, timing of the map lookup reveals no information about the original
	// key (SHA-256 is a one-way function). This eliminates the key-count timing leak
	// from the previous iteration-based approach.
	apiKeyHash := hashAPIKey(apiKey)
	keyInfo := am.config.APIKeys[apiKeyHash]
	if keyInfo == nil {
		// P2P-R11-M05: invalid API key is a failure.
		am.recordAuthFailure(clientIP)
		return ErrInvalidAPIKey
	}

	// Check expiration
	if !keyInfo.ExpiresAt.IsZero() && time.Now().After(keyInfo.ExpiresAt) {
		// P2P-R11-M05: expired key is treated as a failure — an attacker
		// may have obtained a previously-valid key and is now brute-forcing
		// replacements. Conservative: count it.
		am.recordAuthFailure(clientIP)
		return ErrAPIKeyExpired
	}

	// Check IP whitelist for this key
	if len(keyInfo.IPWhitelist) > 0 {
		if !am.isIPAllowed(clientIP, keyInfo.IPWhitelist) {
			// P2P-R11-M05: IP not in this key's whitelist — count as failure.
			// An attacker with a leaked key from a different IP should be
			// locked out after probing from their own IP.
			am.recordAuthFailure(clientIP)
			return ErrIPNotAllowed
		}
	}

	// Check method permissions
	if len(keyInfo.Permissions) > 0 {
		allowed := false
		for _, perm := range keyInfo.Permissions {
			if perm == method || perm == "*" {
				allowed = true
				break
			}
			// Support wildcard patterns like "qau_*"
			if strings.HasSuffix(perm, "*") {
				prefix := strings.TrimSuffix(perm, "*")
				if strings.HasPrefix(method, prefix) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return NewError(ErrCodeUnauthorized, "method not allowed for this API key")
		}
	}

	// Verify HMAC signature if enabled and requested.
	// For batch requests, HMAC is verified only once (verifyHMAC=true on the
	// first non-public method) because the nonce is body-scoped and cannot be
	// reused across elements.
	if verifyHMAC && am.config.EnableHMAC {
		signature := r.Header.Get("X-Signature")
		timestamp := r.Header.Get("X-Timestamp")
		nonce := r.Header.Get("X-Nonce")

		// Read request body for signature verification.
		// R7-H5 FIX: read the body ONCE here, capped at exactly the same limit
		// the HTTP handler enforces, and reuse the same buffer downstream.
		// R38-P4 FIX: Use configurable MaxBodySize if set, otherwise default.
		// This prevents signature/handler-body divergence when MaxBodySize
		// is configured to a value other than the default 1 MiB.
		var maxBody int64 = MaxRequestBodySize
		if am.config.MaxBodySize > 0 {
			maxBody = am.config.MaxBodySize
		}
		var body []byte
		if r.Body != nil {
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, maxBody))
			if err != nil {
				return NewError(ErrCodeInvalidRequest, "failed to read request body")
			}
			r.Body = io.NopCloser(bytes.NewBuffer(body))
		}

		if err := am.verifyHMACWithNonce(method, apiKeyHash, timestamp, signature, nonce, body); err != nil {
			// P2P-R11-M05: HMAC signature mismatch is the strongest failure
			// signal — an attacker is actively trying forged signatures.
			am.recordAuthFailure(clientIP)
			return err
		}
	}

	// audit-fix M-4: enforce per-key rate limit using token bucket.
	// Only applied on the primary (full) validation pass to avoid charging a
	// single batch request multiple times against the per-key limit.
	if isFullValidation && keyInfo.RateLimit > 0 {
		am.rateMu.Lock()
		rlErr := am.checkRateLimitLocked(keyInfo.KeyHash, keyInfo.RateLimit)
		am.rateMu.Unlock()
		if rlErr != nil {
			return rlErr
		}
	}

	// LOW-1 FIX: Update usage stats using atomic operations under RLock.
	// Previous code used non-atomic field writes under RLock, causing a data race
	// (multiple goroutines read-lock concurrently and write the same fields).
	// Now UsageCount and lastUsedNano are atomic, so no race even under RLock.
	// Only updated on the primary validation pass to avoid double-counting a
	// single batch request.
	if isFullValidation {
		keyInfo.SetLastUsed(time.Now())
		keyInfo.IncrementUsage()
	}

	// P2P-R11-M05: clear the failure counter on successful auth so a single
	// success after a transient failure burst doesn't persist the failure
	// history (which could push the next failure past the threshold).
	if isFullValidation {
		am.resetAuthFailures(clientIP)
	}

	return nil
}

// checkRateLimitLocked implements a token bucket rate limiter.
// audit-fix M-4: replaces fixed sliding window to prevent 2x burst at window boundary.
// Tokens are replenished proportionally based on elapsed time.
// Caller must hold am.rateMu.
func (am *AuthManager) checkRateLimitLocked(key string, limit int) error {
	now := time.Now()
	entry := am.rateLimiters[key]
	if entry == nil {
		entry = &apiKeyRateEntry{count: 0, windowStart: now}
		am.rateLimiters[key] = entry
	}

	// Token bucket: replenish tokens based on elapsed time
	elapsed := now.Sub(entry.windowStart)
	if elapsed > 0 {
		// Replenish: limit tokens per minute.
		// RPC-003 FIX: Use integer arithmetic instead of float64 to avoid
		// floating-point rounding imprecision in token replenishment.
		// tokens = elapsed_ns * limit / minute_ns (truncated toward zero,
		// matching the previous int(float64) truncation but without FP error).
		// Overflow is not a concern: elapsed is bounded by RateLimiterMaxAge
		// (~30 min) and limit is a small per-minute request count.
		replenished := int(elapsed.Nanoseconds() * int64(limit) / time.Minute.Nanoseconds())
		if replenished > 0 {
			entry.count -= replenished
			if entry.count < 0 {
				entry.count = 0
			}
			entry.windowStart = now
		}
	}

	entry.count++
	if entry.count > limit {
		return ErrRateLimitExceeded
	}
	return nil
}

// isIPAllowed checks if an IP is in the whitelist
func (am *AuthManager) isIPAllowed(clientIP string, whitelist []string) bool {
	// FIX: reject empty or obviously invalid clientIP before matching
	if clientIP == "" {
		return false
	}
	for _, allowed := range whitelist {
		// Check for CIDR notation
		if strings.Contains(allowed, "/") {
			_, network, err := net.ParseCIDR(allowed)
			if err == nil {
				ip := net.ParseIP(clientIP)
				if ip != nil && network.Contains(ip) {
					return true
				}
			}
		} else {
			// Exact match
			if clientIP == allowed {
				return true
			}
		}
	}
	return false
}

// verifyHMACWithNonce verifies the HMAC signature with nonce-based replay protection.
// audit-fix H-3: requires a unique nonce per request to prevent replay within the 5-min window.
// R33 RPC-01 FIX (2026-07-28): apiKeyHash is now included in the HMAC computation
// to bind the signature to the API key identity, preventing cross-identity replay
// attacks where an attacker captures a valid signature from User A and replays
// it with their own (User B's) API key.
func (am *AuthManager) verifyHMACWithNonce(method, apiKeyHash, timestamp, signature, nonce string, body []byte) error {
	if signature == "" || timestamp == "" {
		return NewError(ErrCodeUnauthorized, "missing signature or timestamp")
	}
	if nonce == "" {
		return NewError(ErrCodeUnauthorized, "missing nonce (X-Nonce header required)")
	}
	// R33 RPC-01: apiKeyHash is required for identity binding.
	if apiKeyHash == "" {
		return NewError(ErrCodeUnauthorized, "missing API key for signature binding")
	}

	// Check timestamp freshness (within 5 minutes)
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return NewError(ErrCodeUnauthorized, "invalid timestamp format")
	}
	// RPC2-002 FIX: Use monotonic clock for timestamp validation. The parsed
	// timestamp is wall-clock only, but time.Now() includes a monotonic reading.
	// We use the monotonic delta (now.Sub(startupMonotonic)) as the internal
	// counter for CAS-based replay detection, making it immune to NTP rollback.
	now := time.Now()
	tsNano := uint64(ts.UnixNano())   //nolint:gosec,G115
	nowNano := uint64(now.UnixNano()) //nolint:gosec,G115
	// RPC2-002 FIX: Use monotonic-based counter instead of wall clock.
	// This prevents NTP rollback from regressing the counter.
	monotonicNow := uint64(now.Sub(am.monotonicEpoch).Nanoseconds()) //nolint:gosec,G115

	// Check: timestamp must not be older than 5 minutes
	if tsNano < nowNano-uint64(5*time.Minute) {
		return NewError(ErrCodeUnauthorized, "timestamp too old")
	}
	// Check: timestamp must not be more than 5 minutes in the future
	if tsNano > nowNano+uint64(5*time.Minute) {
		return NewError(ErrCodeUnauthorized, "timestamp too far in future")
	}
	// HIGH FIX (TOCTOU): Use CAS loop instead of Load+Store to prevent race condition.
	// Multiple concurrent goroutines could pass the monotonic check between Load and Store,
	// allowing timestamps to slip backwards. CAS ensures only one goroutine updates the
	// counter atomically, and all others retry with the latest value.
	// RPC2-002 FIX: Use monotonicNow instead of tsNano for the CAS counter.
	// monotonicNow is derived from Go's monotonic clock, which is immune to
	// NTP clock rollback. The wall-clock freshness check above still uses tsNano.
	for {
		lastCounter := am.lastTimestampCounter.Load()
		if monotonicNow <= lastCounter {
			// MEDIUM FIX (NTP rollback recovery): Allow small clock drift.
			// If the difference is within a tolerance window (30 seconds), skip the update
			// rather than rejecting outright. This prevents NTP clock rollback from
			// permanently blocking all HMAC authentication.
			drift := lastCounter - monotonicNow
			maxDrift := uint64(30 * time.Second)
			if drift > maxDrift {
				return NewError(ErrCodeUnauthorized, "timestamp must be monotonically increasing")
			}
			// Small drift within tolerance — accept but don't regress counter
			break
		}
		if am.lastTimestampCounter.CompareAndSwap(lastCounter, monotonicNow) {
			break
		}
		// CAS failed — another goroutine updated the counter; retry
	}

	// audit-fix H-3: check nonce uniqueness to prevent replay
	// SECURITY FIX: Also enforce max nonce cache size to prevent memory exhaustion
	am.nonceMu.Lock()
	if _, seen := am.seenNonces[nonce]; seen {
		am.nonceMu.Unlock()
		return NewError(ErrCodeUnauthorized, "nonce already used (replay detected)")
	}
	// R20-M10 FIX: When cache is 80%+ full, proactively evict oldest entries
	// instead of rejecting legitimate requests. This ensures headroom is maintained.
	// RPC-001 FIX: Eliminate TOCTOU race by performing sort UNDER the lock.
	// Previously, the lock was released for sorting and re-acquired, creating
	// a window where a concurrent goroutine could insert/evict the current
	// nonce. The sort is O(n log n) which is fast enough for a few thousand
	// entries (MaxNonceCacheSize is typically 10000). This eliminates the
	// race entirely at the cost of a slightly longer critical section.
	if len(am.seenNonces) >= MaxNonceCacheSize*80/100 {
		targetSize := MaxNonceCacheSize * 50 / 100
		type nonceEntry struct {
			nonce string
			ts    time.Time
		}
		entries := make([]nonceEntry, 0, len(am.seenNonces))
		for n, seen := range am.seenNonces {
			entries = append(entries, nonceEntry{n, seen})
		}
		// RPC-001 FIX: Sort UNDER the lock — no TOCTOU window
		sort.Slice(entries, func(i, j int) bool { return entries[i].ts.Before(entries[j].ts) })
		evictCount := len(entries) - targetSize
		for i := 0; i < evictCount; i++ {
			if entries[i].nonce == nonce {
				continue
			}
			delete(am.seenNonces, entries[i].nonce)
		}
	}
	// R20-M10 FIX: Only reject if cache is genuinely full after proactive eviction
	if len(am.seenNonces) >= MaxNonceCacheSize {
		am.nonceMu.Unlock()
		return NewError(ErrCodeUnauthorized, "nonce cache full, try again later")
	}
	// FIX: Do NOT add nonce to cache yet. The nonce must only be
	// consumed AFTER the HMAC signature is verified. Previously, the nonce
	// was added here (before authentication), allowing an attacker without
	// valid credentials to flood the cache with random nonces, causing DoS.
	// The nonce is now added at the end of the function, after signature
	// verification succeeds.
	am.nonceMu.Unlock()

	// SECURITY FIX Q-B-008: Open the HMAC secret from memguard Enclave.
	// The secret bytes only exist inside the LockedBuffer for the duration
	// of the HMAC computation and are automatically wiped when the buffer
	// is closed (defer below).
	if am.config.hmacSecretEnclave == nil {
		return NewError(ErrCodeUnauthorized, "HMAC secret not configured")
	}
	secretBuf, err := am.config.hmacSecretEnclave.Open()
	if err != nil {
		return NewError(ErrCodeUnauthorized, "failed to open HMAC secret")
	}
	defer secretBuf.Destroy()

	// Compute expected signature over method + apiKeyHash + timestamp + nonce + body hash.
	// R25-H5 FIX: Always include body hash, even for empty body, to prevent
	// signature format ambiguity that could be exploited in attacks.
	// R33 RPC-01 FIX (2026-07-28): Include apiKeyHash to bind the signature to
	// the API key identity. Without this, an attacker who captures a valid
	// signature from User A could replay it with their own API key (User B),
	// because the HMAC secret is shared across all keys. The apiKeyHash is
	// SHA-256 of the plaintext key, so it does not leak the key itself.
	mac := hmac.New(sha256.New, secretBuf.Bytes())
	mac.Write([]byte(method))
	mac.Write([]byte(apiKeyHash))
	mac.Write([]byte(timestamp))
	mac.Write([]byte(nonce))
	// Always include body hash - even empty body produces a valid SHA256 hash
	bodyHash := sha256.Sum256(body)
	mac.Write(bodyHash[:])
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	// Constant-time comparison
	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) != 1 {
		return NewError(ErrCodeUnauthorized, "invalid signature")
	}

	// FIX: Only consume the nonce AFTER successful signature verification.
	// This prevents unauthenticated attackers from exhausting the nonce cache.
	am.nonceMu.Lock()
	// Re-check: another goroutine may have added this nonce while we were
	// verifying the signature. If so, this is a replay.
	if _, seen := am.seenNonces[nonce]; seen {
		am.nonceMu.Unlock()
		return NewError(ErrCodeUnauthorized, "nonce already used (replay detected)")
	}
	am.seenNonces[nonce] = time.Now()
	am.nonceMu.Unlock()

	return nil
}

// ValidateBatchRequest validates a batch HTTP request, performing full
// authentication for the entire batch in one pass:
//   - API key verification (once)
//   - Method permissions for EACH non-public method
//   - IP whitelist
//   - HMAC signature covering ALL non-public method names (not just the first)
//   - Per-key rate limiting (once per batch, not per element)
//
// P1-13 (RPC-H3, 2026-07-19 FIX): Previously batch authentication verified
// HMAC only on the FIRST non-public method name (server.go line ~893),
// relying on bodyHash to cover the rest of the body. While bodyHash does
// transitively bind all method names, this is a fragile indirect dependency:
//
//  1. If a future refactor weakens or removes bodyHash (e.g. to support
//     streaming bodies), method substitution becomes possible.
//  2. The signature did not explicitly bind the semantic intent ("these are
//     the methods I am authorizing"), so audit logs and signature replay
//     detection could not reason about which methods were covered.
//  3. An attacker who captures a valid HMAC for method A could potentially
//     swap other methods in the batch (after the first non-public one) as
//     long as they pass the per-method authorization check.
//
// FIX: This method computes the HMAC over the CONCATENATION of all non-public
// method names (length-prefixed, then SHA-256'd), in addition to the body
// hash. The wire format is incompatible with single-request HMACs (which use
// the raw method string), so an attacker cannot reuse a single-request
// signature for a batch or vice versa.
//
// methods is the list of non-public method names in the batch (in order).
// If methods is empty, this is a no-op (all methods are public).
func (am *AuthManager) ValidateBatchRequest(r *http.Request, methods []string) error {
	if len(methods) == 0 {
		return nil
	}
	return am.validateBatchRequest(r, methods)
}

// validateBatchRequest is the internal implementation. It is split out so
// that future code can add admin-level batch authorization without touching
// the HMAC path.
//
// R35-P1-07 FIX (2026-07-29): Previously this batch path had NO brute-force
// protection — checkAuthLockout / recordAuthFailure / resetAuthFailures were
// only wired into the single-request validateRequest path. An attacker could
// hammer the batch endpoint with arbitrary API keys / forged HMACs without
// ever being locked out, because every batch attempt was a "free" probe.
// This fix mirrors the single-request protection:
//   - checkAuthLockout BEFORE any auth-state mutation (early reject)
//   - recordAuthFailure at every failure return point
//   - resetAuthFailures on successful auth
//
// The three helpers acquire am.authFailuresMu internally; the comment on each
// states "Caller must NOT hold am.authFailuresMu" — we only hold am.mu.RLock
// here, which is a different lock, so there is no lock-ordering issue.
func (am *AuthManager) validateBatchRequest(r *http.Request, methods []string) error {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if !am.config.Enabled {
		return nil
	}

	// R35-P1-07 FIX: brute-force lockout check BEFORE any auth-state mutation,
	// identical to the single-request path (validateRequest). Once an IP hits
	// MaxAuthFailures in a window it is locked out for AuthLockoutDuration
	// regardless of which API key it presents next.
	clientIP := getClientIPWithTrust(r, am.config.TrustedProxies)
	if err := am.checkAuthLockout(clientIP); err != nil {
		return err
	}

	// Verify each non-public method against API key permissions.
	// We do this BEFORE HMAC verification so that a permission error is
	// returned without consuming the nonce.
	apiKey := r.Header.Get(am.config.APIKeyHeader)
	if apiKey == "" {
		// R35-P1-07 FIX: missing API key is a brute-force probe — count it.
		am.recordAuthFailure(clientIP)
		return ErrAuthRequired
	}
	apiKeyHash := hashAPIKey(apiKey)
	keyInfo := am.config.APIKeys[apiKeyHash]
	if keyInfo == nil {
		// R35-P1-07 FIX: invalid API key — count it.
		am.recordAuthFailure(clientIP)
		return ErrInvalidAPIKey
	}
	if !keyInfo.ExpiresAt.IsZero() && time.Now().After(keyInfo.ExpiresAt) {
		// R35-P1-07 FIX: expired key — an attacker may be brute-forcing
		// replacements; conservatively count it.
		am.recordAuthFailure(clientIP)
		return ErrAPIKeyExpired
	}

	// Global IP whitelist
	if len(am.config.GlobalIPWhitelist) > 0 {
		if !am.isIPAllowed(clientIP, am.config.GlobalIPWhitelist) {
			// R35-P1-07 FIX: IP not allowed — count as failure.
			am.recordAuthFailure(clientIP)
			return ErrIPNotAllowed
		}
	}
	// Per-key IP whitelist
	if len(keyInfo.IPWhitelist) > 0 {
		if !am.isIPAllowed(clientIP, keyInfo.IPWhitelist) {
			// R35-P1-07 FIX: IP not in this key's whitelist — count as failure.
			am.recordAuthFailure(clientIP)
			return ErrIPNotAllowed
		}
	}

	// Per-method permission check for ALL methods in the batch.
	for _, method := range methods {
		if len(keyInfo.Permissions) > 0 {
			allowed := false
			for _, perm := range keyInfo.Permissions {
				if perm == method || perm == "*" {
					allowed = true
					break
				}
				if strings.HasSuffix(perm, "*") {
					prefix := strings.TrimSuffix(perm, "*")
					if strings.HasPrefix(method, prefix) {
						allowed = true
						break
					}
				}
			}
			if !allowed {
				return NewError(ErrCodeUnauthorized, "method not allowed for this API key")
			}
		}
	}

	// Per-key rate limiting (once per batch).
	// audit-fix M-4: enforce per-key rate limit using token bucket.
	// P1-13: applies once per batch (not per element) so a 100-element batch
	// consumes exactly 1 token, not 100.
	if keyInfo.RateLimit > 0 {
		am.rateMu.Lock()
		rlErr := am.checkRateLimitLocked(keyInfo.KeyHash, keyInfo.RateLimit)
		am.rateMu.Unlock()
		if rlErr != nil {
			return rlErr
		}
	}

	// P1-13: Update usage stats once per batch (same as isFullValidation path
	// in validateRequest). Atomic ops are safe under RLock.
	keyInfo.SetLastUsed(time.Now())
	keyInfo.IncrementUsage()

	// HMAC verification covering ALL method names.
	if am.config.EnableHMAC {
		signature := r.Header.Get("X-Signature")
		timestamp := r.Header.Get("X-Timestamp")
		nonce := r.Header.Get("X-Nonce")

		var maxBody int64 = MaxRequestBodySize
		if am.config.MaxBodySize > 0 {
			maxBody = am.config.MaxBodySize
		}
		var body []byte
		if r.Body != nil {
			var err error
			body, err = io.ReadAll(io.LimitReader(r.Body, maxBody))
			if err != nil {
				return NewError(ErrCodeInvalidRequest, "failed to read request body")
			}
			r.Body = io.NopCloser(bytes.NewBuffer(body))
		}

		if err := am.verifyBatchHMACWithNonce(methods, apiKeyHash, timestamp, signature, nonce, body); err != nil {
			// R35-P1-07 FIX: HMAC signature mismatch is the strongest failure
			// signal — an attacker is actively trying forged signatures.
			am.recordAuthFailure(clientIP)
			return err
		}
	}

	// R35-P1-07 FIX: clear the failure counter on successful auth so a
	// transient failure burst doesn't persist (mirrors single-request path).
	am.resetAuthFailures(clientIP)

	return nil
}

// verifyBatchHMACWithNonce verifies an HMAC signature that covers ALL non-public
// method names in a batch request, not just the first one.
//
// P1-13 (RPC-H3, 2026-07-19): The signature is computed as:
//
//	mac = HMAC(secret, "BATCHv1" || len(methods) || for each method: len || method || apiKeyHash || timestamp || nonce || SHA256(body))
//
// The "BATCHv1" prefix and length-prefixed encoding make this format
// incompatible with single-request HMACs (which use the raw method string
// in verifyHMACWithNonce). This prevents an attacker from reusing a
// single-request signature for a batch, or vice versa.
//
// Length-prefixing eliminates ambiguity when method names share prefixes
// (e.g. "eth_" vs "eth_blockNumber"): each method is encoded with its
// exact length, so the byte stream is unambiguous.
//
// R33 RPC-01 FIX (2026-07-28): apiKeyHash is now included in the HMAC
// computation to bind the signature to the API key identity, preventing
// cross-identity replay attacks (same fix as verifyHMACWithNonce).
func (am *AuthManager) verifyBatchHMACWithNonce(methods []string, apiKeyHash, timestamp, signature, nonce string, body []byte) error {
	if signature == "" || timestamp == "" {
		return NewError(ErrCodeUnauthorized, "missing signature or timestamp")
	}
	if nonce == "" {
		return NewError(ErrCodeUnauthorized, "missing nonce (X-Nonce header required)")
	}
	if len(methods) == 0 {
		return NewError(ErrCodeUnauthorized, "batch HMAC requires at least one method")
	}
	// R33 RPC-01: apiKeyHash is required for identity binding.
	if apiKeyHash == "" {
		return NewError(ErrCodeUnauthorized, "missing API key for signature binding")
	}

	// Check timestamp freshness (within 5 minutes) — same logic as
	// verifyHMACWithNonce. Duplicated here to keep the batch path
	// independent; a future refactor could extract a shared helper.
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return NewError(ErrCodeUnauthorized, "invalid timestamp format")
	}
	now := time.Now()
	tsNano := uint64(ts.UnixNano())                                  //nolint:gosec,G115
	nowNano := uint64(now.UnixNano())                                //nolint:gosec,G115
	monotonicNow := uint64(now.Sub(am.monotonicEpoch).Nanoseconds()) //nolint:gosec,G115

	if tsNano < nowNano-uint64(5*time.Minute) {
		return NewError(ErrCodeUnauthorized, "timestamp too old")
	}
	if tsNano > nowNano+uint64(5*time.Minute) {
		return NewError(ErrCodeUnauthorized, "timestamp too far in future")
	}
	for {
		lastCounter := am.lastTimestampCounter.Load()
		if monotonicNow <= lastCounter {
			drift := lastCounter - monotonicNow
			maxDrift := uint64(30 * time.Second)
			if drift > maxDrift {
				return NewError(ErrCodeUnauthorized, "timestamp must be monotonically increasing")
			}
			break
		}
		if am.lastTimestampCounter.CompareAndSwap(lastCounter, monotonicNow) {
			break
		}
	}

	// Nonce uniqueness check (consume only after signature verification).
	am.nonceMu.Lock()
	if _, seen := am.seenNonces[nonce]; seen {
		am.nonceMu.Unlock()
		return NewError(ErrCodeUnauthorized, "nonce already used (replay detected)")
	}
	if len(am.seenNonces) >= MaxNonceCacheSize*80/100 {
		targetSize := MaxNonceCacheSize * 50 / 100
		type nonceEntry struct {
			nonce string
			ts    time.Time
		}
		entries := make([]nonceEntry, 0, len(am.seenNonces))
		for n, seen := range am.seenNonces {
			entries = append(entries, nonceEntry{n, seen})
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].ts.Before(entries[j].ts) })
		evictCount := len(entries) - targetSize
		for i := 0; i < evictCount; i++ {
			if entries[i].nonce == nonce {
				continue
			}
			delete(am.seenNonces, entries[i].nonce)
		}
	}
	if len(am.seenNonces) >= MaxNonceCacheSize {
		am.nonceMu.Unlock()
		return NewError(ErrCodeUnauthorized, "nonce cache full, try again later")
	}
	am.nonceMu.Unlock()

	// Open HMAC secret from memguard Enclave.
	if am.config.hmacSecretEnclave == nil {
		return NewError(ErrCodeUnauthorized, "HMAC secret not configured")
	}
	secretBuf, err := am.config.hmacSecretEnclave.Open()
	if err != nil {
		return NewError(ErrCodeUnauthorized, "failed to open HMAC secret")
	}
	defer secretBuf.Destroy()

	// Compute expected signature over ALL method names (length-prefixed)
	// + apiKeyHash + timestamp + nonce + body hash.
	// R33 RPC-01 FIX: apiKeyHash is included to bind the signature to the
	// API key identity, preventing cross-identity replay.
	mac := hmac.New(sha256.New, secretBuf.Bytes())
	// "BATCHv1" prefix prevents cross-format confusion with single-request
	// HMACs (which start with the raw method string).
	mac.Write([]byte("BATCHv1"))
	// Number of methods (4 bytes, big-endian) bounds the method list so an
	// attacker cannot truncate the stream mid-method.
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(methods)))
	mac.Write(lenBuf[:])
	for _, method := range methods {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(method)))
		mac.Write(lenBuf[:])
		mac.Write([]byte(method))
	}
	// R33 RPC-01: Bind the signature to the API key identity.
	mac.Write([]byte(apiKeyHash))
	mac.Write([]byte(timestamp))
	mac.Write([]byte(nonce))
	bodyHash := sha256.Sum256(body)
	mac.Write(bodyHash[:])
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(signature), []byte(expectedSig)) != 1 {
		return NewError(ErrCodeUnauthorized, "invalid signature")
	}

	// Consume nonce after successful signature verification.
	am.nonceMu.Lock()
	if _, seen := am.seenNonces[nonce]; seen {
		am.nonceMu.Unlock()
		return NewError(ErrCodeUnauthorized, "nonce already used (replay detected)")
	}
	am.seenNonces[nonce] = time.Now()
	am.nonceMu.Unlock()

	return nil
}

// ValidateAdminRequest performs admin-level authorization for a request.
// RegisterAdminMethod records a method as a privileged admin method that may
// be authorized through ValidateAdminRequest.
// RPC-004 FIX: this whitelist is consulted by ValidateAdminRequest so that
// admin-level authorization is only ever granted for known admin methods,
// independent of the caller (defense-in-depth).
func (am *AuthManager) RegisterAdminMethod(method string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	if am.adminMethods == nil {
		am.adminMethods = make(map[string]bool)
	}
	am.adminMethods[method] = true
}

// HIGH FIX (admin bypass): This is called for admin methods regardless of transport.
// It validates that the API key has admin permissions AND the request comes from
// an authorized admin IP. Regular ValidateRequest only checks basic authentication.
func (am *AuthManager) ValidateAdminRequest(r *http.Request, method string) error {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if !am.config.Enabled {
		return nil
	}

	// RPC-004 FIX: enforce the admin method whitelist. When populated, only
	// methods explicitly registered via RegisterAdminMethod may receive
	// admin-level authorization. This is defense-in-depth: the server already
	// gates this call on isAdminMethod, but this check ensures authorization
	// cannot be bypassed by a misrouted/direct call. When the whitelist is not
	// configured (nil) the check is skipped for backward compatibility.
	if am.adminMethods != nil && !am.adminMethods[method] {
		return NewError(ErrCodeUnauthorized, "method is not a permitted admin method")
	}

	apiKey := r.Header.Get(am.config.APIKeyHeader)
	if apiKey == "" {
		return ErrAuthRequired
	}

	apiKeyHash := hashAPIKey(apiKey)
	keyInfo := am.config.APIKeys[apiKeyHash]
	if keyInfo == nil {
		return ErrInvalidAPIKey
	}

	// Check expiration
	if !keyInfo.ExpiresAt.IsZero() && time.Now().After(keyInfo.ExpiresAt) {
		return ErrAPIKeyExpired
	}

	// SECURITY: Admin methods require explicit admin permission ("admin" or "*")
	hasAdmin := false
	for _, perm := range keyInfo.Permissions {
		if perm == "admin" || perm == "*" {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		return errors.New("admin permission required for this method")
	}

	// SECURITY: Admin methods require IP whitelist to be configured and matched
	// If no IP whitelist on key, check global whitelist
	if len(keyInfo.IPWhitelist) > 0 {
		clientIP := getClientIPWithTrust(r, am.config.TrustedProxies)
		if !am.isIPAllowed(clientIP, keyInfo.IPWhitelist) {
			return ErrIPNotAllowed
		}
	} else if len(am.config.GlobalIPWhitelist) > 0 {
		clientIP := getClientIPWithTrust(r, am.config.TrustedProxies)
		if !am.isIPAllowed(clientIP, am.config.GlobalIPWhitelist) {
			return ErrIPNotAllowed
		}
	}

	// AUDIT (2026) API-05 FIX: Removed the duplicate HMAC verification
	// block that was previously here. ValidateRequest (called by handleHTTP
	// for HTTP transport, and by authenticateFromContext for non-HTTP
	// transport) already performs HMAC verification and consumes the nonce.
	// Re-calling verifyHMACWithNonce here caused a nonce double-consumption
	// bug: the second call always found the nonce in seenNonces and rejected
	// every admin request with "nonce already used (replay detected)" when
	// HMAC was enabled. The original  intent (admin requests must
	// pass HMAC) is still satisfied because ValidateRequest runs first in
	// both transport paths.

	// RPC4-001 FIX: Enforce per-key rate limit and update usage stats for
	// admin requests, matching validateRequest's behavior. Previously, admin
	// requests bypassed rate limiting entirely, allowing a compromised admin
	// key to flood the server without restriction.
	if keyInfo.RateLimit > 0 {
		am.rateMu.Lock()
		rlErr := am.checkRateLimitLocked(keyInfo.KeyHash, keyInfo.RateLimit)
		am.rateMu.Unlock()
		if rlErr != nil {
			return rlErr
		}
	}
	keyInfo.SetLastUsed(time.Now())
	keyInfo.IncrementUsage()

	return nil
}

// GetAPIKeyInfo returns information about an API key
// audit-fix R11-M2: hash the input key before lookup, since M-1 stores keys by hash.
// Previously this used the raw key as map key, which always returned nil after M-1.
func (am *AuthManager) GetAPIKeyInfo(key string) *APIKeyInfo {
	am.mu.RLock()
	defer am.mu.RUnlock()

	keyH := hashAPIKey(key)
	if info, exists := am.config.APIKeys[keyH]; exists {
		// Return a copy with atomic values read atomically.
		// RPC-002 FIX: Do NOT expose the plaintext Key to callers — it is a
		// secret credential. The Key is zeroed out and only the non-secret
		// KeyHash (SHA-256) is returned, so callers can still identify the key
		// without gaining access to the raw secret.
		copy := &APIKeyInfo{
			Key:     "", // RPC-002: plaintext key is never returned to callers
			KeyHash: keyH,
			Name:    info.Name,
			// RPC3-001 FIX: Deep copy slices to prevent callers from modifying
			// the internal APIKeyInfo state via the returned slice headers.
			Permissions: append([]string(nil), info.Permissions...),
			IPWhitelist: append([]string(nil), info.IPWhitelist...),
			RateLimit:   info.RateLimit,
			CreatedAt:   info.CreatedAt,
			ExpiresAt:   info.ExpiresAt,
		}
		copy.lastUsedNano.Store(info.lastUsedNano.Load())
		copy.UsageCount.Store(info.UsageCount.Load())
		return copy
	}
	return nil
}

// ListAPIKeys returns all API key names (not the keys themselves)
func (am *AuthManager) ListAPIKeys() []string {
	am.mu.RLock()
	defer am.mu.RUnlock()

	names := make([]string, 0, len(am.config.APIKeys))
	for _, info := range am.config.APIKeys {
		names = append(names, info.Name)
	}
	return names
}

// SetEnabled enables or disables authentication
var authEnabledImmutable bool
var authImmutableOnce sync.Once

func setAuthImmutable() {
	authImmutableOnce.Do(func() {
		authEnabledImmutable = true
	})
}

func (am *AuthManager) SetEnabled(enabled bool) {
	if authEnabledImmutable {
		return
	}
	am.mu.Lock()
	defer am.mu.Unlock()
	am.config.Enabled = enabled
}

// IsEnabled returns whether authentication is enabled
func (am *AuthManager) IsEnabled() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return am.config.Enabled
}

// getClientIP extracts the client IP from the request
// SECURITY: This function does NOT trust X-Forwarded-For by default.
// Use getClientIPWithTrust for trusted proxy scenarios.
func getClientIP(r *http.Request) string {
	// Always use RemoteAddr by default for security
	// X-Forwarded-For can be spoofed by clients
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// getClientIPWithTrust extracts client IP, optionally trusting proxy headers
// trustedProxies: list of trusted proxy IPs that can set X-Forwarded-For
func getClientIPWithTrust(r *http.Request, trustedProxies []string) string {
	// Get the direct connection IP first
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// If no trusted proxies configured, return direct IP
	if len(trustedProxies) == 0 {
		return remoteIP
	}

	// RPC-R9-M (2026-07-19) FIX: Reject over-broad trusted proxy entries.
	// A misconfiguration that includes "0.0.0.0/0" or "::/0" effectively
	// trusts X-Forwarded-For from any source — an attacker can then spoof
	// the header and bypass per-IP rate limiting entirely. Same for
	// the global-broadcast IPv4/IPv6 link-local blocks. We log once per
	// process (via sync.Once) so operators notice, but silently skip the
	// bad entry rather than crashing the server.
	safeProxies := filterUnsafeProxies(trustedProxies)

	// Check if the direct connection is from a trusted proxy
	isTrustedProxy := false
	for _, trusted := range safeProxies {
		if strings.Contains(trusted, "/") {
			// CIDR notation
			_, network, err := net.ParseCIDR(trusted)
			if err == nil {
				ip := net.ParseIP(remoteIP)
				if ip != nil && network.Contains(ip) {
					isTrustedProxy = true
					break
				}
			}
		} else if remoteIP == trusted {
			isTrustedProxy = true
			break
		}
	}

	// Only trust X-Forwarded-For if connection is from trusted proxy
	if isTrustedProxy {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// Take the first (client) IP in the list
			parts := strings.Split(xff, ",")
			clientIP := strings.TrimSpace(parts[0])
			// Validate it's a valid IP
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}

		// Check X-Real-IP as fallback
		xri := r.Header.Get("X-Real-IP")
		if xri != "" && net.ParseIP(xri) != nil {
			return xri
		}
	}

	return remoteIP
}

// filterUnsafeProxies returns the subset of `proxies` that are NOT
// broad enough to be a security foot-gun. RPC-R9-M (2026-07-19).
//
// Rejected entries (with a one-time WARN log):
//   - "0.0.0.0/0" and "::/0" (any IPv4 / any IPv6)
//   - "0.0.0.0/8", "::/8"    (bogon global)
//   - any /8 or shorter prefix (including all /1 ranges, etc.)
//
// /16 and shorter private ranges (10.0.0.0/8 etc.) are NOT rejected
// because operators legitimately deploy entire private subnets as
// trusted proxies (e.g. an internal Kubernetes cluster).
func filterUnsafeProxies(proxies []string) []string {
	if len(proxies) == 0 {
		return proxies
	}
	safe := make([]string, 0, len(proxies))
	for _, p := range proxies {
		if isUnsafeProxyCIDR(p) {
			unsafeProxyWarnOnce.Do(func() {
				log.Printf("[WARN] RPC-R9-M: rejecting unsafe trusted proxy entry %q — accepting it would let any client spoof X-Forwarded-For and bypass per-IP rate limiting", p)
			})
			continue
		}
		safe = append(safe, p)
	}
	return safe
}

var unsafeProxyWarnOnce sync.Once

// isUnsafeProxyCIDR reports whether the given trusted-proxy entry is broad
// enough to be considered unsafe (any host can claim to be a trusted proxy).
// Plain-IP entries (no "/") are always safe — they identify a single host.
func isUnsafeProxyCIDR(entry string) bool {
	if !strings.Contains(entry, "/") {
		return false
	}
	_, network, err := net.ParseCIDR(entry)
	if err != nil || network == nil {
		// Unparseable entry — treat as unsafe so caller doesn't accidentally
		// trust a malformed proxy spec.
		return true
	}
	ones, _ := network.Mask.Size()
	// /8 or shorter (IPv4) or /8 or shorter (IPv6 with global reach)
	// is treated as unsafe. The bogon 0.0.0.0/8 and ::/8 are caught here too.
	if ones <= 8 {
		return true
	}
	// Also reject the explicit "all IPv4" and "all IPv6" any-network.
	if network.IP.Equal(net.IPv4zero) && ones == 0 {
		return true
	}
	if network.IP.Equal(net.IPv6unspecified) && ones == 0 {
		return true
	}
	return false
}

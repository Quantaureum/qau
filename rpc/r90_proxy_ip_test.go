// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// R90-PROXY-IP behavioral regression.
//
// A node fronted by a TLS-terminating reverse proxy sees every request with
// RemoteAddr = <proxy>:<port>. Unless the proxy is listed in TrustedProxies,
// client-IP attribution returns the proxy address for all of them, so the
// PerIPRateLimit budget and the auth brute-force lockout are shared by every
// client behind it: one busy wallet starves the rest, and one attacker's auth
// failures lock out everybody.
//
// getClientIPWithTrust is the single attribution function used by both the rate
// limiter (ratelimit.go Allow) and the auth manager (auth.go validateRequest),
// so pinning it covers both consumers deterministically — unlike driving the
// token buckets, whose capacity is shared between the global and per-IP limits.

func r90ProxiedRequest(peerIP, forwardedFor string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = peerIP + ":54321"
	if forwardedFor != "" {
		r.Header.Set("X-Forwarded-For", forwardedFor)
	}
	return r
}

func TestR90_ClientIP_WithoutTrustedProxies_CollapsesToProxyAddress(t *testing.T) {
	// Two distinct real clients behind the same proxy. With no trusted proxies
	// the X-Forwarded-For header is correctly ignored (it is unauthenticated
	// input from an untrusted peer) — but that also means both are attributed
	// to the proxy, which is why rpcTrustedProxies must be set behind a proxy.
	a := getClientIPWithTrust(r90ProxiedRequest("127.0.0.1", "203.0.113.10"), nil)
	b := getClientIPWithTrust(r90ProxiedRequest("127.0.0.1", "198.51.100.20"), nil)
	if a != "127.0.0.1" || b != "127.0.0.1" {
		t.Fatalf("expected both to collapse to the proxy address, got %q and %q", a, b)
	}
	if a != b {
		t.Fatalf("attribution should be identical without trusted proxies: %q vs %q", a, b)
	}
}

func TestR90_ClientIP_WithTrustedProxy_AttributesPerRealClient(t *testing.T) {
	trusted := []string{"127.0.0.1"}
	a := getClientIPWithTrust(r90ProxiedRequest("127.0.0.1", "203.0.113.10"), trusted)
	b := getClientIPWithTrust(r90ProxiedRequest("127.0.0.1", "198.51.100.20"), trusted)
	if a != "203.0.113.10" {
		t.Fatalf("client A: got %q want 203.0.113.10", a)
	}
	if b != "198.51.100.20" {
		t.Fatalf("client B: got %q want 198.51.100.20", b)
	}
	if a == b {
		t.Fatal("distinct clients must get distinct buckets behind a trusted proxy")
	}
}

func TestR90_ClientIP_TrustedProxyViaCIDR(t *testing.T) {
	// Operators commonly express the proxy as a single-host CIDR.
	got := getClientIPWithTrust(r90ProxiedRequest("127.0.0.1", "203.0.113.10"),
		[]string{"127.0.0.1/32"})
	if got != "203.0.113.10" {
		t.Fatalf("got %q want 203.0.113.10", got)
	}
}

func TestR90_ClientIP_UntrustedPeerCannotSpoofForwardedFor(t *testing.T) {
	// Only the loopback proxy is trusted. A direct caller from the internet
	// must not be able to escape its own bucket by inventing the header.
	trusted := []string{"127.0.0.1"}
	a := getClientIPWithTrust(r90ProxiedRequest("203.0.113.99", "10.0.0.1"), trusted)
	b := getClientIPWithTrust(r90ProxiedRequest("203.0.113.99", "10.0.0.2"), trusted)
	if a != "203.0.113.99" || b != "203.0.113.99" {
		t.Fatalf("spoofed header must be ignored for untrusted peers, got %q and %q", a, b)
	}
}

func TestR90_ClientIP_OverBroadProxyEntryIsIgnored(t *testing.T) {
	// filterUnsafeProxies drops 0.0.0.0/0 at request time, so even if such an
	// entry reached the config it must not enable header spoofing. The node
	// layer additionally rejects it at startup (resolveRPCTrustedProxies).
	got := getClientIPWithTrust(r90ProxiedRequest("203.0.113.99", "10.0.0.1"),
		[]string{"0.0.0.0/0"})
	if got != "203.0.113.99" {
		t.Fatalf("over-broad trusted proxy must not enable spoofing, got %q", got)
	}
}

// TestR90_RateLimit_SharesBucketWithoutTrustedProxies drives the real limiter to
// show the operational consequence end-to-end: with the proxy untrusted, one
// client's traffic throttles a different client.
func TestR90_RateLimit_SharesBucketWithoutTrustedProxies(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	cfg.GlobalRateLimit = 10000
	cfg.PerIPRateLimit = 1
	cfg.BurstSize = 1
	cfg.PerMethodRateLimit = nil
	rl := NewRateLimiter(cfg)

	if err := rl.Allow(r90ProxiedRequest("127.0.0.1", "203.0.113.10"), "eth_blockNumber"); err != nil {
		t.Fatalf("first request should be allowed: %v", err)
	}
	if err := rl.Allow(r90ProxiedRequest("127.0.0.1", "198.51.100.20"), "eth_blockNumber"); err == nil {
		t.Fatal("expected a different client to be throttled by the first client's usage")
	}
}

// TestR90_PublicMethods_CoverWalletCriticalPath pins the anonymous-access
// contract for a public L1. With rpcAuthEnabled=true and no API keys issued
// (the production posture behind a reverse proxy), anything absent from
// PublicMethods is unreachable by wallets. Two subscription methods were
// missing, which silently disabled all WebSocket push updates.
func TestR90_PublicMethods_CoverWalletCriticalPath(t *testing.T) {
	cfg := DefaultAuthConfig()
	public := make(map[string]bool, len(cfg.PublicMethods))
	for _, m := range cfg.PublicMethods {
		public[m] = true
	}

	required := []string{
		// balance / nonce / code / state reads
		"eth_chainId", "eth_blockNumber", "eth_getBalance", "eth_getTransactionCount",
		"eth_getCode", "eth_getStorageAt", "eth_syncing",
		// blocks and receipts
		"eth_getBlockByNumber", "eth_getBlockByHash", "eth_getTransactionByHash",
		"eth_getTransactionReceipt",
		// fees, simulation and submission
		"eth_gasPrice", "eth_feeHistory", "eth_maxPriorityFeePerGas",
		"eth_estimateGas", "eth_call", "eth_sendRawTransaction",
		// logs and filters
		"eth_getLogs", "eth_newFilter", "eth_getFilterChanges", "eth_uninstallFilter",
		// R90-WS-PUBLIC: WebSocket push updates
		"eth_subscribe", "eth_unsubscribe",
		// staking screens
		"qau_getStake", "qau_getStakingPools", "qau_getUserStakes",
		"qau_getPendingRewards", "qau_stake", "qau_unstake",
		// node/network info
		"net_version", "net_peerCount", "web3_clientVersion",
	}
	for _, m := range required {
		if !public[m] {
			t.Errorf("%s must be in PublicMethods: wallets cannot use it once auth is enabled", m)
		}
	}

	// The complement must stay closed: node-signing, account management,
	// mempool disclosure and tracing are admin-only regardless of transport.
	forbidden := []string{
		"personal_importRawKey", "personal_unlockAccount", "personal_sendTransaction",
		"personal_newAccount", "personal_listAccounts",
		"eth_sendTransaction",                                         // node signs on the caller's behalf
		"qau_sendPrivacyTransaction",                                  // ditto (P2-PRIVACY-ADMIN)
		"txpool_content", "txpool_inspect", "eth_pendingTransactions", // mempool disclosure breaks commit-reveal
		"debug_traceTransaction", "debug_rollbackChainToHeight",
	}
	for _, m := range forbidden {
		if public[m] {
			t.Errorf("%s must NOT be public: it is admin-only", m)
		}
	}
}

// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"net"
	"strings"

	"github.com/quantaureum/qau/rpc"
)

// rpcTrustedProxiesEnv overrides Config.RPCTrustedProxies at runtime. Value is
// a comma-separated list of IPs or CIDR blocks.
const rpcTrustedProxiesEnv = "QAU_RPC_TRUSTED_PROXIES"

// resolveRPCTrustedProxies decides which reverse proxies the RPC layer may
// trust for client-IP attribution (the X-Forwarded-For header).
//
// R90-PROXY-IP (2026-08-30): needed for the reverse-proxy deployment topology.
// When a TLS-terminating proxy (Caddy) fronts the node, the node binds RPC to
// 127.0.0.1 and every request arrives with RemoteAddr = 127.0.0.1:<port>.
// getClientIPWithTrust returns that address verbatim while TrustedProxies is
// empty, which has two consequences on a public chain:
//
//  1. Per-IP rate limiting collapses into a single shared bucket. The default
//     PerIPRateLimit of 100 req/s then applies to ALL wallet users combined
//     instead of per user, so a handful of clients starve everybody else — and
//     one abusive client is indistinguishable from organic traffic.
//  2. The brute-force lockout (MaxAuthFailures per IP) and GlobalIPWhitelist
//     both key off the same collapsed address, so a single attacker's failures
//     lock out every legitimate caller behind the proxy.
//
// Neither is a confidentiality break — admin methods stay behind
// ValidateAdminRequest (API key + admin permission + admin method whitelist)
// regardless — but both are availability breaks that only appear once the node
// is actually fronted by a proxy, which no loopback-only test exercises.
//
// The policy is explicit opt-in and fails closed on malformed input:
//
//   - Empty list (default): trust nothing, use the direct connection IP. This
//     is the correct behavior for a directly-exposed or loopback-only node,
//     where an attacker could otherwise spoof X-Forwarded-For at will.
//   - Non-empty list: only requests whose direct peer matches an entry may
//     supply X-Forwarded-For. rpc.filterUnsafeProxies additionally drops
//     over-broad entries (0.0.0.0/0, ::/0, ...) at request time, but we reject
//     them here as well so a misconfiguration surfaces at startup instead of
//     silently degrading.
//
// An unparsable entry is an error rather than a silent drop: dropping it would
// quietly narrow the policy and reintroduce the collapsed-IP behavior that this
// setting exists to fix.
func resolveRPCTrustedProxies(configured []string, env string) ([]string, error) {
	entries := configured
	if trimmed := strings.TrimSpace(env); trimmed != "" {
		entries = strings.Split(trimmed, ",")
	}

	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if err := validateTrustedProxyEntry(entry); err != nil {
			return nil, err
		}
		if seen[entry] {
			continue
		}
		seen[entry] = true
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// validateTrustedProxyEntry accepts a bare IP or a CIDR block and rejects
// entries that would trust X-Forwarded-For from the whole internet.
func validateTrustedProxyEntry(entry string) error {
	if strings.Contains(entry, "/") {
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q in RPC trusted proxies: %w", entry, err)
		}
		ones, bits := network.Mask.Size()
		// A /0 prefix (or an all-zero mask) trusts every source address.
		if ones == 0 && bits > 0 {
			return fmt.Errorf("refusing over-broad RPC trusted proxy %q: it would trust X-Forwarded-For from any source", entry)
		}
		return nil
	}
	if ip := net.ParseIP(entry); ip == nil {
		return fmt.Errorf("invalid IP %q in RPC trusted proxies", entry)
	} else if ip.IsUnspecified() {
		return fmt.Errorf("refusing unspecified RPC trusted proxy %q", entry)
	}
	return nil
}

// newRPCAuthConfig returns the default auth configuration with the trusted-proxy
// policy applied. Extracted from Start() so the wiring is testable without
// booting a node: rpc.NewAuthManager(nil) silently falls back to
// DefaultAuthConfig, which carries no proxy policy at all, so a regression here
// is invisible from the outside.
func newRPCAuthConfig(trustedProxies []string) *rpc.AuthConfig {
	cfg := rpc.DefaultAuthConfig()
	cfg.TrustedProxies = trustedProxies
	return cfg
}

// newRPCRateLimitConfig returns the rate-limit configuration for this node:
// the rpc defaults, overlaid with the node's configurable limits, plus the
// trusted-proxy policy. Both consumers must agree: attributing auth failures
// per real client while attributing rate limits per proxy (or the reverse)
// would leave one of the two availability holes open.
//
// R107-LOCAL-FANOUT (2026-09-04): previously this returned the bare defaults,
// so perIpRequestsPerSecond / rateLimitExemptIPs & co. in config.json only took
// effect after a SIGHUP hot-reload and were silently ignored at startup.
func newRPCRateLimitConfig(cfg *Config, trustedProxies []string) *rpc.RateLimitConfig {
	rlCfg := buildRateLimitConfig(cfg)
	rlCfg.TrustedProxies = trustedProxies
	return rlCfg
}

// validateRateLimitExemptIPs checks the per-IP rate-limit exemption list.
// The syntax (bare IP or CIDR) and the fail-closed rules are identical to the
// trusted-proxy list: an unparsable entry or an over-broad prefix is an error,
// because silently dropping it would leave the operator believing a co-located
// service is exempt when it is not, and accepting 0.0.0.0/0 would disable
// per-IP limiting for the whole internet.
func validateRateLimitExemptIPs(entries []string) error {
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if err := validateTrustedProxyEntry(entry); err != nil {
			return fmt.Errorf("invalid rate-limit exempt entry: %w", err)
		}
	}
	return nil
}

// Quantaureum Node source, version 1.0.0.
package rpc

import "time"

// R100-BAN-NORECOVER (2026-08-30)
//
// A banned IP never returned to a clean state. entry.violations is incremented
// on every token shortfall (ratelimit.go:387) and reset in exactly one place —
// UnbanIP (:502) — which has ZERO production callers. So once a client
// accumulated ViolationsBeforeBan (10) violations, that counter stayed at or
// above the threshold for the process lifetime: after the 1-hour ban expired,
// the very next single token shortfall re-armed a full ban immediately, with no
// renewed burst of abuse required.
//
// The first offense was therefore permanent. Behind NAT, a CDN, or any shared
// egress address, one misbehaving client permanently denied service to everyone
// sharing that IP — and because getClientIPWithTrust honors X-Forwarded-For
// from trusted proxies, an attacker could choose whose address to poison.
//
// Found in operation: a verification script issued a few hundred
// eth_getBlockByNumber calls against N1's local RPC, tripped the limiter, and
// 127.0.0.1 stayed refused while the node was provably healthy (active, ERROR=0,
// height == ourHighestKnown, attesting every slot).
//
// NOT the mechanism, though it was assumed at first: retries during an active
// ban do NOT extend it. The ban check at :263 returns before reaching :387, so
// violations does not grow while banned. The defect is narrower than the
// self-perpetuating loop first suspected, and had to be verified rather than
// asserted.
//
// FIX: when a ban has lapsed, clear it and reset the violation counter, so the
// client resumes exactly as a never-banned client would. Clearing the state
// (rather than merely ignoring an expired timestamp) also keeps
// GetStats().BannedIPs honest and lets the MaxTrackedIPs eviction path at :350 —
// which refuses to evict entries it believes are banned — reclaim the slot.

// banState is the subset of rateLimitEntry this decision depends on. Extracted
// so the rule is testable without constructing a limiter, and so the two
// properties that matter are stated in one place:
//
//	an ACTIVE ban must keep refusing;
//	a LAPSED ban must leave no trace.
type banState struct {
	bannedUntil time.Time
	violations  int
}

// expiredBanShouldReset reports whether a ban has lapsed and its state must be
// cleared. A zero bannedUntil means "never banned" and needs no reset.
func expiredBanShouldReset(s banState, now time.Time) bool {
	if s.bannedUntil.IsZero() {
		return false
	}
	return now.After(s.bannedUntil) || now.Equal(s.bannedUntil)
}

// clearExpiredBanLocked resets a lapsed ban on the entry. Caller must hold the
// entry's shard lock. Returns true if state was cleared.
//
// Deliberately does NOT touch tokens: the token bucket refills on its own
// elapsed-time schedule and is the correct mechanism for pacing. Resetting it
// here would hand a just-unbanned client a free full burst.
func clearExpiredBanLocked(entry *rateLimitEntry, now time.Time) bool {
	if !expiredBanShouldReset(banState{bannedUntil: entry.bannedUntil, violations: entry.violations}, now) {
		return false
	}
	entry.bannedUntil = time.Time{}
	entry.violations = 0
	return true
}

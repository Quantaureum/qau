// Quantaureum Node source, version 1.0.0.
// Package bridge implements the Quantaureum Cross-Chain Bridge protocol.
// adaptive_timeout.go provides dynamic RPC timeout scaling based on chain
// health metrics.
//
// R7-OBS-1 (2026-07-18): Adaptive RPC timeouts for Bridge adapters.
// Audit observation (Low): "Edge case where extremely high network latency
// might cause premature timeout on valid transactions. Recommended to
// implement adaptive timeouts based on chain health metrics."
//
// This file wires the existing BridgeMetrics gauges (L1AnchorLag and
// LastMessageProcessedAt) into a single helper that returns a context
// timeout scaled to current chain conditions. Healthy state returns the
// base 15s; degraded state scales up to a 120s ceiling so that valid
// transactions are not prematurely failed under transient network stress.
package bridge

import "time"

const (
	// adaptiveTimeoutBase is the baseline RPC timeout. Matches the
	// pre-fix hardcoded value so behavior is unchanged when metrics
	// are healthy or unavailable.
	adaptiveTimeoutBase = 15 * time.Second
	// adaptiveTimeoutMax is the ceiling under degraded conditions.
	// 120s is chosen to be well above the httpClient.Timeout (30s) so
	// that the per-request context — not the client — is the operative
	// deadline under degraded conditions. Callers that want a tighter
	// ceiling can layer their own parent context deadline.
	adaptiveTimeoutMax = 120 * time.Second
	// Thresholds mirror the alert rules in metrics/metrics.go to keep
	// "alerting" and "timeout scaling" consistent.
	adaptiveAnchorLagThreshold   = 20.0  // blocks
	adaptiveProcStalledThreshold = 300.0 // seconds
)

// AdaptiveRPCTimeout returns a context timeout scaled by current chain health
// signals. Returns adaptiveTimeoutBase (15s) when m is nil or all signals are
// healthy; scales up to adaptiveTimeoutMax (120s) when degraded.
//
// Multipliers (compose multiplicatively):
//   - L1 anchor lag > 20 blocks           → 2.0x
//   - Last message processed > 300s ago   → 1.5x
//
// Worst-case composite: 15s * 2.0 * 1.5 = 45s (still under 120s ceiling).
// Cold start (LastMessageProcessedAt == 0) does NOT scale — avoids
// penalizing nodes that just started and have not yet processed a message.
//
// Nil-safe: returns adaptiveTimeoutBase when m is nil. This preserves the
// pre-fix behavior for adapters constructed without metrics wiring.
func (m *BridgeMetrics) AdaptiveRPCTimeout() time.Duration {
	if m == nil {
		return adaptiveTimeoutBase
	}

	// P3-BR-05 FIX (2026-08-03): combine the two degradation signals via
	// max() rather than multiplication. Previously both signals multiplied
	// (multiplier = 2.0 * 1.5 = 3.0 → worst case 15s * 3 = 45s), meaning
	// when BOTH conditions were degraded the timeout ballooned to ~45s
	// even though each signal individually only warranted 30s or 22.5s.
	// max() keeps the worst case at 30s while still raising the timeout
	// when EITHER signal degrades — the audit's "prefer max() over
	// multiplication" recommendation. The signals are independent (L1
	// anchor lag vs message processing staleness) and stacking them
	// multiplicatively implied a compounding degradation that does not
	// actually compound in practice.
	//
	// Each signal contributes its OWN multiplier (1.0 baseline, 2.0 for
	// L1 anchor lag, 1.5 for processing staleness); the effective
	// multiplier is max(sig1, sig2).
	sig1 := 1.0
	sig2 := 1.0

	// Signal 1: L1 anchor lag. High lag means the upstream chain is slow
	// to anchor Merkle roots, which typically indicates degraded L1
	// conditions or bridge relayer stress.
	if m.L1AnchorLagValue() > adaptiveAnchorLagThreshold {
		sig1 = 2.0
	}

	// Signal 2: Message processing staleness. Returns 0 on cold start
	// (LastMessageProcessedAt == 0), so cold-start nodes are not penalized.
	if m.MessageProcessingStalledValue() > adaptiveProcStalledThreshold {
		sig2 = 1.5
	}

	multiplier := sig1
	if sig2 > multiplier {
		multiplier = sig2
	}

	scaled := time.Duration(float64(adaptiveTimeoutBase) * multiplier)
	if scaled > adaptiveTimeoutMax {
		return adaptiveTimeoutMax
	}
	if scaled < adaptiveTimeoutBase {
		return adaptiveTimeoutBase
	}
	return scaled
}

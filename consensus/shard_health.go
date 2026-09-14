// Quantaureum Node source, version 1.0.0.
package consensus

// Shard Health Checks — P3-2 (2026-07-15)
//
// Provides structured health status for the shard subsystem. The health
// checker inspects all shards managed by a ShardManager and returns a
// ShardHealthReport describing:
//   - Overall status (healthy / degraded / unhealthy)
//   - Per-shard status (Active / Initializing / Stopped / Inactive)
//   - Block production staleness (no new block for N slots)
//   - Cross-shard message backlog (pending messages exceeding threshold)
//
// The report is designed to be exposed via the existing /health endpoint
// (metrics/health.go) or via a dedicated qau_shardHealth RPC method.
//
// Thresholds are configurable via ShardHealthConfig. Sensible defaults are
// provided by DefaultShardHealthConfig().

import (
	"fmt"
	"time"
)

// ShardHealthStatus represents the overall health of the shard subsystem.
type ShardHealthStatus string

const (
	// ShardHealthOK means all active shards are producing blocks and
	// processing cross-shard messages within thresholds.
	ShardHealthOK ShardHealthStatus = "ok"
	// ShardHealthDegraded means at least one shard has a non-critical issue
	// (e.g., elevated pending message count, slow block production).
	ShardHealthDegraded ShardHealthStatus = "degraded"
	// ShardHealthUnhealthy means at least one active shard has stalled
	// (no blocks for a long time) or the message backlog is critically high.
	ShardHealthUnhealthy ShardHealthStatus = "unhealthy"
)

// ShardHealthConfig configures the thresholds used by the health checker.
type ShardHealthConfig struct {
	// StalledSlotThreshold: if an active shard has not produced a block for
	// more than this many slot intervals, it is considered stalled.
	// Default: 5 (5 * ShardBlockInterval = 60 seconds at 12s slots).
	StalledSlotThreshold uint64

	// PendingMsgWarnThreshold: if pending cross-shard messages exceed this
	// count, the shard is marked degraded.
	// Default: 100.
	PendingMsgWarnThreshold int

	// PendingMsgCriticalThreshold: if pending cross-shard messages exceed
	// this count, the shard is marked unhealthy.
	// Default: 1000.
	PendingMsgCriticalThreshold int

	// SlotInterval: the expected time between consecutive slots. Used to
	// convert slot counts to wall-clock time for staleness checks.
	// Default: ShardBlockInterval seconds.
	SlotInterval time.Duration
}

// DefaultShardHealthConfig returns sensible default thresholds.
func DefaultShardHealthConfig() ShardHealthConfig {
	return ShardHealthConfig{
		StalledSlotThreshold:        5,
		PendingMsgWarnThreshold:     100,
		PendingMsgCriticalThreshold: 1000,
		SlotInterval:                time.Duration(ShardBlockInterval) * time.Second,
	}
}

// ShardHealthReport is the structured health report for the shard subsystem.
type ShardHealthReport struct {
	Status      ShardHealthStatus  `json:"status"`
	Timestamp   string             `json:"timestamp"`
	ShardCount  int                `json:"shardCount"`
	ActiveCount int                `json:"activeCount"`
	Shards      []ShardHealthEntry `json:"shards"`
}

// ShardHealthEntry describes the health of a single shard.
type ShardHealthEntry struct {
	ShardID         uint64   `json:"shardId"`
	Status          string   `json:"status"` // Active/Initializing/Inactive/Migrating
	LatestHeight    uint64   `json:"latestHeight"`
	ValidatorCount  int      `json:"validatorCount"`
	PendingMessages int      `json:"pendingMessages"`
	StalledSeconds  float64  `json:"stalledSeconds"`   // seconds since last block (estimated)
	IsStalled       bool     `json:"isStalled"`        // true if block production has stalled
	MsgBacklogLevel string   `json:"msgBacklogLevel"`  // "ok" / "warn" / "critical"
	Issues          []string `json:"issues,omitempty"` // human-readable issue descriptions
}

// ShardHealthChecker checks the health of all shards managed by a
// ShardManager. P3-2 (2026-07-15).
type ShardHealthChecker struct {
	manager *ShardManager
	config  ShardHealthConfig
}

// NewShardHealthChecker creates a ShardHealthChecker for the given manager
// with default thresholds.
func NewShardHealthChecker(manager *ShardManager) *ShardHealthChecker {
	return &ShardHealthChecker{
		manager: manager,
		config:  DefaultShardHealthConfig(),
	}
}

// NewShardHealthCheckerWithConfig creates a ShardHealthChecker with custom
// thresholds. Useful for testing or environments with different SLOs.
func NewShardHealthCheckerWithConfig(manager *ShardManager, cfg ShardHealthConfig) *ShardHealthChecker {
	return &ShardHealthChecker{
		manager: manager,
		config:  cfg,
	}
}

// Check returns a structured health report for all shards.
// When the manager is nil or sharding is disabled, returns a healthy report
// with zero shards (the subsystem is simply not active).
func (c *ShardHealthChecker) Check(now time.Time) *ShardHealthReport {
	report := &ShardHealthReport{
		Status:    ShardHealthOK,
		Timestamp: now.UTC().Format(time.RFC3339),
	}

	if c == nil || c.manager == nil {
		return report
	}

	c.manager.mu.RLock()
	defer c.manager.mu.RUnlock()

	report.ShardCount = len(c.manager.shards)

	for _, chain := range c.manager.shards {
		entry := c.checkChainLocked(chain, now)
		report.Shards = append(report.Shards, entry)

		if entry.Status == "Active" {
			report.ActiveCount++
		}

		// Aggregate status: unhealthy > degraded > ok.
		for _, issue := range entry.Issues {
			if entry.IsStalled || entry.MsgBacklogLevel == "critical" {
				report.Status = ShardHealthUnhealthy
			} else {
				if report.Status != ShardHealthUnhealthy {
					report.Status = ShardHealthDegraded
				}
			}
			_ = issue // issue text already in entry.Issues
		}
	}

	return report
}

// checkChainLocked builds a ShardHealthEntry for a single shard.
// Caller must hold sm.mu (read lock). P3-2 (2026-07-15).
func (c *ShardHealthChecker) checkChainLocked(chain *ShardChain, now time.Time) ShardHealthEntry {
	chain.mu.RLock()
	defer chain.mu.RUnlock()

	entry := ShardHealthEntry{
		ShardID:         chain.shardID,
		Status:          chain.status.String(),
		LatestHeight:    chain.latest,
		ValidatorCount:  len(chain.validators),
		PendingMessages: len(chain.pendingMsgs),
	}

	// Only active shards are checked for staleness and backlog. Initializing
	// or inactive shards are expected to have no block production.
	if chain.status != ShardStatusActive {
		return entry
	}

	// Estimate stalled time. SHRD-R5-08 (2026-07-17): prefer the local
	// receive time (ReceivedAt) over the proposer-self-reported header
	// timestamp. A malicious/faulty proposer could forge future or rolling
	// header timestamps to keep stalledDuration below the threshold forever,
	// hiding actual stalls from operators. ReceivedAt is stamped by the
	// node's own clock in ProposeBlock/ReceiveBlock, so it cannot be forged
	// by the proposer. If ReceivedAt is zero (block loaded from store on
	// restart, or pre-fix blocks), fall back to header timestamp (legacy).
	if chain.latest > 0 {
		if block, exists := chain.blocks[chain.latest]; exists && block.Header != nil {
			var referenceTime time.Time
			if block.ReceivedAt > 0 {
				referenceTime = time.Unix(0, block.ReceivedAt)
			} else {
				referenceTime = time.Unix(int64(block.Header.Timestamp), 0)
			}
			stalledDuration := now.Sub(referenceTime)
			entry.StalledSeconds = stalledDuration.Seconds()

			stalledThreshold := time.Duration(c.config.StalledSlotThreshold) * c.config.SlotInterval
			if stalledDuration > stalledThreshold {
				entry.IsStalled = true
				entry.Issues = append(entry.Issues,
					fmt.Sprintf("block production stalled: no new block for %.0fs (threshold %ds)",
						stalledDuration.Seconds(), int(stalledThreshold.Seconds())))
			}
		}
	}

	// Check cross-shard message backlog.
	switch {
	case entry.PendingMessages >= c.config.PendingMsgCriticalThreshold:
		entry.MsgBacklogLevel = "critical"
		entry.Issues = append(entry.Issues,
			fmt.Sprintf("cross-shard message backlog critical: %d pending (threshold %d)",
				entry.PendingMessages, c.config.PendingMsgCriticalThreshold))
	case entry.PendingMessages >= c.config.PendingMsgWarnThreshold:
		entry.MsgBacklogLevel = "warn"
		entry.Issues = append(entry.Issues,
			fmt.Sprintf("cross-shard message backlog elevated: %d pending (threshold %d)",
				entry.PendingMessages, c.config.PendingMsgWarnThreshold))
	default:
		entry.MsgBacklogLevel = "ok"
	}

	return entry
}

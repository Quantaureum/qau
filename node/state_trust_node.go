// Quantaureum Node source, version 1.0.0.
package node

// R87-STATE-TRUST (2026-08-29): node-level accessors for the local-state trust
// flag. See node/state_trust.go for the full rationale.

// markStateTrustBroken records a hard, non-self-healing loss of confidence in
// local state (currently: a failed fork rollback). Logs once, at ERROR.
func (n *Node) markStateTrustBroken(detail string) {
	if n == nil || n.stateTrust == nil {
		return
	}
	if n.stateTrust.breakHard(detail) {
		nodeLog.Error("R87-STATE-TRUST: local state is no longer trusted (%s). "+
			"This node will KEEP FOLLOWING the chain but will NOT produce blocks. "+
			"Operator action required: stop the node, delete the state directory and "+
			"re-sync (or restore a snapshot). Producing from diverged state would "+
			"push the divergence onto peers.", detail)
	}
}

// recordStateRootMismatch is called by the syncer for every block whose
// recomputed state root disagrees with the header. A sustained streak means
// local state has drifted away from the network, not that one block was odd.
func (n *Node) recordStateRootMismatch(height uint64) {
	if n == nil || n.stateTrust == nil {
		return
	}
	if n.stateTrust.recordMismatch(
		"sustained state-root mismatch streak while strictStateRoot is disabled") {
		nodeLog.Error("R87-STATE-TRUST: %d consecutive state-root mismatches "+
			"(latest at height %d). Local state has drifted from the network; "+
			"block production is now DISABLED. The chain is still being followed. "+
			"Operator action: re-sync this node. Note that the R63-STATE-ROOT-TRUST "+
			"workaround intentionally keeps sync advancing on mismatch, so this "+
			"counter is the only signal that the workaround has stopped being benign.",
			n.stateTrust.streak(), height)
	}
}

// recordStateRootMatch is called for every block whose recomputed root agrees
// with the header. It resets the mismatch streak and clears a soft break.
func (n *Node) recordStateRootMatch() {
	if n == nil || n.stateTrust == nil {
		return
	}
	n.stateTrust.recordMatch()
}

// IsStateTrusted reports whether local state is still considered consistent
// with the network. Block production is gated on this.
func (n *Node) IsStateTrusted() bool {
	if n == nil || n.stateTrust == nil {
		return true
	}
	return n.stateTrust.ok()
}

// StateTrustDetail returns a human-readable reason why state trust was lost,
// or "" when local state is trusted. Exposed for RPC/health reporting.
func (n *Node) StateTrustDetail() string {
	if n == nil || n.stateTrust == nil {
		return ""
	}
	r := n.stateTrust.reason()
	if r == nil {
		return ""
	}
	return r.Detail
}

// StateRootMismatchStreak returns the current consecutive-mismatch count.
func (n *Node) StateRootMismatchStreak() int {
	if n == nil || n.stateTrust == nil {
		return 0
	}
	return n.stateTrust.streak()
}

// shouldSkipForStateTrust reports whether the block producer must skip this
// slot because local state is no longer trusted (R87-STATE-TRUST). It also
// emits the operator-facing log line, rate-limited to one per 20 slots so a
// degraded node stays diagnosable without flooding the log.
//
// Kept as a method (rather than inline in tryProduceBlock) so the gate is
// directly testable without constructing a full producer.
func (bp *BlockProducer) shouldSkipForStateTrust(slot uint64) bool {
	if bp == nil || bp.node == nil {
		return false
	}
	if bp.node.IsStateTrusted() {
		return false
	}
	if slot%20 == 0 {
		bpLog.Error("tryProduceBlock: slot=%d SKIPPED — R87-STATE-TRUST: local state "+
			"is not trusted (%s). Still following the chain; production stays disabled "+
			"until this node is re-synced.", slot, bp.node.StateTrustDetail())
	}
	return true
}

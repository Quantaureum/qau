// Quantaureum Node source, version 1.0.0.
package node

// Cold-start anchor-custody recovery for the Dilithium3 v1 era.
//
// PROBLEM. A node whose data directory is restored from a snapshot (or whose
// chain data survives while <datadir>.threshold-v1 does not) boots with a
// canonical chain that already contains v1-era blocks but an EMPTY anchor
// custody. The custody table is seeded only by the import-time observer hook
// (onCanonicalBlockImported -> ObserveAnchoredGroupKey) and by the local
// share store at signer registration; historical boundary carriers already in
// the store are never re-imported at startup. The first group-signed header
// after the restore tip therefore finds no key in the v1 verification branch
// (core/block_validator.go), falls through to individual verification, and is
// rejected — and the node makes no progress until a fresh boundary carrier
// happens to arrive.
//
// FIX. At synchronous startup, when the v1 era is active and the custody
// holds no key at or after the activation epoch, walk the LOCAL canonical
// chain backward from the tip to the most recent epoch-boundary block that
// carries a QTDGroupKey anchor and adopt it through the existing
// ObserveAnchoredGroupKey discipline. The trust root is the local
// already-verified canonical chain — the same legitimacy source a fresh sync
// from genesis uses for its first anchor (see tdilithium3_v1_anchor_bootstrap.go).
// The replay is bounded (a fixed number of epoch boundaries) and gives up
// cleanly with a warning when no carrier is found.
//
// Scope discipline: this is a startup-only recovery. It adds no key source the
// import path does not already trust, does not touch the validation order, and
// a node whose custody already covers the era (an installed share, a
// configured trusted key, or an already-adopted anchor) exits before any scan.

import (
	"fmt"
	"os"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// tdilithium3V1CustodyReplayMaxEpochs bounds the backward scan for an anchor
// carrier: only the most recent N epoch boundaries of the local chain are
// examined, never the whole chain. One epoch is enough for the steady state
// (the tip's own boundary carrier); the extra epochs cover a chain whose
// recent boundaries were produced by non-armed proposers and carried no
// anchor.
const tdilithium3V1CustodyReplayMaxEpochs = 8

// rebuildTDilithium3V1CustodyFromLocalChain seeds the v1 anchor custody from
// the local canonical chain when the node would otherwise start the v1 era
// with no group public key at all. See the file comment for the failure shape
// and the trust model. Quiet no-op on healthy nodes.
func (n *Node) rebuildTDilithium3V1CustodyFromLocalChain() {
	if n == nil || n.config == nil || n.blockStore == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return
	}
	activation := n.config.TSSV1ProposalActivationEpoch
	if activation == 0 {
		return
	}
	qfs := n.blockProducer.QPOS().GetQTDFinality()
	if qfs == nil {
		return
	}
	if n.blockProducer.QPOS().GetCurrentEpoch() < activation {
		// The v1 verification branch is inert before the activation epoch;
		// there is nothing to recover yet.
		return
	}
	if qfs.HasGroupKeyCustodyAtOrAfter(activation) {
		// The custody already covers the era: a share, a trusted key, or an
		// adopted anchor is in place. No scan, no behavior change.
		return
	}
	tip, err := n.blockStore.GetLatestBlock()
	if err != nil || tip == nil || tip.Header == nil {
		nodeLog.Warn("Dilithium3 v1 custody rebuild skipped: local chain tip unavailable (err=%v)", err)
		return
	}
	carrier := n.findTDilithium3V1AnchorCarrier(tip.Header.Height, activation)
	if carrier == nil {
		nodeLog.Warn("Dilithium3 v1 custody rebuild found no epoch-boundary anchor carrier within the last %d epochs of the local chain (tip height %d); group-signed headers stay rejected until a boundary carrier is imported",
			tdilithium3V1CustodyReplayMaxEpochs, tip.Header.Height)
		return
	}
	if !qfs.ObserveAnchoredGroupKey(carrier.Header.Epoch, carrier.Header.QTDGroupKey, carrier.Header.QTDGroupKeyProof) {
		nodeLog.Warn("Dilithium3 v1 custody rebuild REFUSED the local chain's anchor carrier (epoch %d, height %d): the chained-adoption discipline rejected it",
			carrier.Header.Epoch, carrier.Header.Height)
		return
	}
	nodeLog.Info("Dilithium3 v1 group-key custody rebuilt from the local canonical chain: anchor carrier at height %d (epoch %d)",
		carrier.Header.Height, carrier.Header.Epoch)
}

// findTDilithium3V1AnchorCarrier walks the local canonical chain backward from
// tipHeight and returns the most recent epoch-boundary block (Slot at an epoch
// start) that carries a QTDGroupKey anchor, or nil when none exists within the
// bounded window or below the v1 activation epoch. A missing block (pruned or
// damaged chain data) ends the scan: history below it cannot supply a
// verifiable carrier.
func (n *Node) findTDilithium3V1AnchorCarrier(tipHeight, activation uint64) *encoding.Block {
	if n == nil || n.blockStore == nil {
		return nil
	}
	floorHeight := uint64(0)
	if tipHeight > tdilithium3V1CustodyReplayMaxEpochs*consensus.SlotsPerEpoch {
		floorHeight = tipHeight - tdilithium3V1CustodyReplayMaxEpochs*consensus.SlotsPerEpoch
	}
	for height := tipHeight; height >= floorHeight && height <= tipHeight; height-- {
		blk, err := n.blockStore.GetBlockByHeight(height)
		if err != nil || blk == nil || blk.Header == nil {
			return nil
		}
		header := blk.Header
		if header.Epoch < activation {
			// Reached the pre-v1 era: only a carrier at or after the
			// activation epoch may seed v1 custody.
			return nil
		}
		if header.Slot%consensus.SlotsPerEpoch == 0 && len(header.QTDGroupKey) > 0 {
			return blk
		}
	}
	return nil
}

// tdilithium3V1LocalShareStoreExists reports whether a Dilithium3 v1 threshold
// share store is present on disk (an active or a candidate share file). A
// missing store is what distinguishes an unrecoverable cold start (no custody,
// no share, no trusted key) from a healthy node.
func (n *Node) tdilithium3V1LocalShareStoreExists() bool {
	if n == nil || n.config == nil || n.config.DataDir == "" {
		return false
	}
	paths, err := newThresholdProtocolPaths(n.config.DataDir, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		return false
	}
	if _, err := os.Stat(paths.Active); err == nil {
		return true
	}
	if _, err := os.Stat(paths.CandidateHead); err == nil {
		return true
	}
	return false
}

// tdilithium3V1CustodyAdvice returns the operator-facing remediation when the
// v1 era is active but this node has no usable group-key source: the custody
// table holds no key at or after the activation epoch AND no local share store
// exists. ok=false means the node has a key source (or the era is not active)
// and needs no advice.
func (n *Node) tdilithium3V1CustodyAdvice() (string, bool) {
	if n == nil || n.config == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return "", false
	}
	activation := n.config.TSSV1ProposalActivationEpoch
	if activation == 0 {
		return "", false
	}
	if n.blockProducer.QPOS().GetCurrentEpoch() < activation {
		return "", false
	}
	qfs := n.blockProducer.QPOS().GetQTDFinality()
	if qfs == nil || qfs.HasGroupKeyCustodyAtOrAfter(activation) {
		return "", false
	}
	if n.tdilithium3V1LocalShareStoreExists() {
		return "", false
	}
	return fmt.Sprintf(
		"Dilithium3 v1 era is active (activation epoch %d) but this node has neither group-key custody nor a local threshold share store: every group-signed block will be rejected. Restore <%s>.threshold-v1 from a backup, or set tssV1TrustedGroupKey (with tssV1SealingActivationEpoch) to the armed ceremony's group public key.",
		activation, n.config.DataDir), true
}

// warnTDilithium3V1CustodyUnrecoverable logs a loud operator warning when the
// v1 era is active with no custody and no share store. Runs at startup after
// the custody rebuild, so a node the rebuild could not help sees the advice.
func (n *Node) warnTDilithium3V1CustodyUnrecoverable() {
	if advice, ok := n.tdilithium3V1CustodyAdvice(); ok {
		nodeLog.Warn("%s", advice)
	}
}

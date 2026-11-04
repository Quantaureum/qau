// Quantaureum Node source, version 1.0.0.
package node

import (
	"github.com/quantaureum/qau/consensus"
)

// consensusHardeningProbe supplies the canonical-chain evidence used by the
// QR-28 stalled-chain exemption and the QR-42 strict proposer verification.
//
// The epoch argument is the SOURCE epoch (selectionEpoch - 2): both callers
// ask "did epoch-2 produce any block?". The hardening gate is evaluated on
// the resulting selection epoch so the probe is inert on every legacy epoch
// and when the network-wide activation is not configured at all.
//
// A single node alone has no evidence that the network did not move on, so
// peers are required — the same condition as the producer path's
// stalledChainExemption in block_producer.go.
func (n *Node) consensusHardeningProbe(epoch uint64) bool {
	if n == nil || n.config == nil {
		return false
	}
	activation := n.config.ConsensusHardeningActivationEpoch
	if activation == 0 || epoch+2 < activation {
		return false
	}
	if n.p2pHost == nil || n.p2pHost.PeerCount() == 0 {
		return false
	}
	return n.canonicalChainHasNoBlockInEpoch(epoch)
}

// wireConsensusHardening installs the coordinated QR-22/42/40/28/21 batch on
// the consensus engine and its chambers coordinator. Called once during QPOS
// initialization, before the first epoch transition. With an unset activation
// epoch the gate stays 0 and no probe is installed, so every path keeps its
// legacy fail-closed behavior.
func (n *Node) wireConsensusHardening(qpos *consensus.QPOS, coordinator *consensus.ThreeChambersCoordinator) {
	if n == nil || n.config == nil || qpos == nil {
		return
	}
	epoch := n.config.ConsensusHardeningActivationEpoch
	qpos.SetConsensusHardeningEpoch(epoch)
	if epoch == 0 {
		return
	}
	probe := n.consensusHardeningProbe
	qpos.SetStalledChainProbe(probe)
	if coordinator != nil {
		coordinator.SetStalledChainProbe(probe)
	}
}

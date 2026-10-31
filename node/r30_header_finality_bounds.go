package node

import (
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// adoptHeaderFinality adopts the justified/finalized checkpoint epochs carried
// by a block header into qpos, but only when they are backed by the chain that
// header sits on.
//
// R30 F8 (2026-10-30) SAFETY: AdoptHeaderFinality is a monotonic ratchet — it
// takes any epoch larger than the local one and never lowers it — and the
// adopted finalized epoch becomes this node's finality floor. A header with an
// unbounded FinalizedEpoch would therefore pin the floor above every block this
// chain will ever produce, after which every reorg, store rollback and debug
// rollback is refused permanently; because this node stamps the adopted value
// into the headers it produces, the poison would then spread to every peer
// syncing from it.
//
// core.BlockValidator now rejects such headers at import (R30 F8), so the
// violations this guard can still see come from data already on disk: blocks
// stored before the rule existed, or a corrupted store. Seeding finality from
// the stored head at startup goes through here for exactly that reason.
//
// Adopting nothing is the fail-safe: local finality stays where the last valid
// block left it, which is always a floor some real ancestor satisfies.
func (n *Node) adoptHeaderFinality(qpos *consensus.QPOS, h *encoding.BlockHeader, blockHash types.Hash) bool {
	if qpos == nil || h == nil {
		return false
	}
	headerEpoch := consensus.SlotToEpoch(h.Slot)
	if !consensus.HeaderFinalityCheckpointsValid(h.JustifiedEpoch, h.FinalizedEpoch, headerEpoch) {
		nodeLog.Error("R30-F8: refusing unbacked finality checkpoints on block %d (slot %d, epoch %d): justified=%d finalized=%d",
			h.Height, h.Slot, headerEpoch, h.JustifiedEpoch, h.FinalizedEpoch)
		return false
	}
	qpos.AdoptHeaderFinality(h.JustifiedEpoch, h.FinalizedEpoch, blockHash)
	return true
}

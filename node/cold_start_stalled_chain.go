// Quantaureum Node source, version 1.0.0.
package node

import "github.com/quantaureum/qau/consensus"

// Cold-start guard exemption for an epoch without blocks.
//
// The proposer schedule of epoch E reads the VRF accumulator of epoch E-2,
// which is carried by the last block of that epoch. An epoch with no block has
// no accumulator on any node. When every validator is down for longer than two
// epochs, the first slots after the restart lie in epochs whose E-2 is empty,
// so every node's schedule is cold, every node refuses to propose, and the
// chain cannot restart by itself: the guard that protects a restarting node
// from contradicting peers that carry the accumulator has no such peer to
// protect it from. A single empty epoch in the middle of a chain does the same
// two epochs later.
//
// The guard may be relaxed exactly when no node can hold the accumulator: the
// canonical chain has no block in epoch E-2. Readiness is then a pure function
// of chain content, all nodes at the same head derive the same fallback
// shuffle and elect the same proposer, and receivers already trust the
// canonical proposer of a block whose schedule is cold (core.ElectionVerifier
// returns ErrProposerScheduleNotReady when acc[E-2] is missing). The relaxation
// also requires that the node has peers and none is ahead of it, the same
// conditions as the young-chain exemption of R80. The condition looks at the
// chain, not at the head: after the first block of the restarted chain the
// head lies in epoch E, yet E and E+1 still read the empty epochs E-2 and E-1,
// and production must go on. From epoch E+2 on the accumulator of epoch E
// exists and the guard resumes its normal role.

// coldStartChainWalkLimit bounds how many blocks below the head the walk
// visits. After a stall the blocks above the epoch in question are the few the
// restarted chain has produced since, so a short walk decides; past the limit
// the answer is "undecided" and the guard stays.
const coldStartChainWalkLimit = 4 * consensus.SlotsPerEpoch

// chainHasNoBlockInEpoch reports whether the canonical chain whose newest block
// has height headHeight holds no block in the epoch. slotAt returns the slot of
// the canonical block at a height. It walks down from the head, skipping blocks
// above the epoch, and decides at the first block that lies in or below it. An
// unreadable block or a walk past the limit decides nothing (false).
func chainHasNoBlockInEpoch(headHeight uint64, slotAt func(height uint64) (uint64, bool), epoch uint64) bool {
	height := headHeight
	for steps := 0; steps <= coldStartChainWalkLimit; steps++ {
		slot, ok := slotAt(height)
		if !ok {
			return false
		}
		blockEpoch := consensus.SlotToEpoch(slot)
		if blockEpoch == epoch {
			return false
		}
		if blockEpoch < epoch || height == 0 {
			return true
		}
		height--
	}
	return false
}

// canonicalChainHasNoBlockInEpoch applies chainHasNoBlockInEpoch to this node's
// canonical chain.
func (n *Node) canonicalChainHasNoBlockInEpoch(epoch uint64) bool {
	if n == nil || n.blockStore == nil {
		return false
	}
	head := n.currentBlock // one read: the head may move while the walk runs
	if head == nil || head.Header == nil {
		return false
	}
	return chainHasNoBlockInEpoch(head.Header.Height, func(height uint64) (uint64, bool) {
		header, err := n.blockStore.GetBlockHeader(height)
		if err != nil || header == nil {
			return 0, false
		}
		return header.Slot, true
	}, epoch)
}

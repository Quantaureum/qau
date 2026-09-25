// Quantaureum Node source, version 1.0.0.
package node

import (
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// R101-FINALITY-RESUME (2026-08-30)
//
// Reconstructs recently-completed epoch boundary roots from the canonical
// block store and injects them into QPOS (see consensus/r101_epoch_root_backfill.go
// for the deadlock this fixes). Called from checkSync on every pass; throttled
// to once per epoch by r101LastBackfillEpoch.
//
// Root reconstruction rule — MUST stay byte-compatible with the import path
// (node.go:8750-8755, block_producer.go:1554/3561):
//   - epoch starts on a boundary block (slot % SlotsPerEpoch == 0)
//     → root = that block's own hash          (SetEpochBlockRoot semantics)
//   - boundary slot missed → root = ParentHash of the epoch's first block
//     (EnsureEpochBlockRoot semantics: chain tip at epoch start)
//
// The epoch's FIRST block fully determines its root under both branches, so
// walking backwards and keeping the earliest-seen block per epoch is exact.

const (
	// r101BackfillHealthyEpochDepth is the normal completed-epoch window when
	// the live checkpoint roots are already known. Keeping this small avoids
	// repeatedly walking thousands of historical blocks on healthy nodes.
	r101BackfillHealthyEpochDepth = 4
	// r101BackfillEpochDepth is the emergency window when a checkpoint root is
	// missing. r101BackfillOldestEpoch extends it to the persisted checkpoint
	// when that checkpoint is older, so a long finality stall is recoverable.
	r101BackfillEpochDepth = 2048
	// r101BackfillMaxWalk is the normal backward block-scan budget. The
	// effective budget is raised to cover any dynamically extended epoch
	// window; a partial walk remains best-effort.
	r101BackfillMaxWalk = 65536
)

// maybeBackfillEpochRootsLocked is the checkSync entry point. No-op when:
// qpos not wired, head missing, chain younger than 2 epochs, or already ran
// for the head's epoch. Caller MUST hold s.mu (checkSync convention).
func (s *Syncer) maybeBackfillEpochRootsLocked() {
	if s.qpos == nil || s.blockStore == nil {
		return
	}
	head, err := s.blockStore.GetLatestBlock()
	if err != nil || head == nil || head.Header == nil {
		return
	}
	cur := head.Header.Epoch
	if cur < 2 || cur <= s.r101LastBackfillEpoch {
		return
	}

	roots := s.reconstructEpochRoots(head)
	if len(roots) > 0 {
		applied := s.qpos.BackfillEpochRoots(roots)
		if applied > 0 {
			syncLog.Info("R101: backfilled %d epoch boundary roots from canonical store (head=%d epoch=%d)",
				applied, head.Header.Height, cur)
		}
	}
	s.r101LastBackfillEpoch = cur
}

// reconstructEpochRoots walks backwards from head and derives the boundary
// root of each completed epoch in the dynamically selected recovery window.
// Best-effort: gaps or a truncated walk simply return fewer entries.
func (s *Syncer) reconstructEpochRoots(head *encoding.Block) map[uint64]types.Hash {
	cur := head.Header.Epoch
	justifiedEpoch := s.qpos.GetJustifiedEpoch()
	finalizedEpoch := s.qpos.GetFinalizedEpoch()
	checkpointRootsKnown := justifiedEpoch == 0 || s.qpos.HasEpochRoot(justifiedEpoch)
	if finalizedEpoch > 0 && !s.qpos.HasEpochRoot(finalizedEpoch) {
		checkpointRootsKnown = false
	}
	oldest := r101BackfillOldestEpoch(
		cur,
		justifiedEpoch,
		finalizedEpoch,
		checkpointRootsKnown,
	)

	// firstBlock[e] = the lowest-height block seen for epoch e (i.e. the
	// epoch's first block) — walking downward, overwrite on every sighting.
	firstBlock := make(map[uint64]*encoding.BlockHeader)
	h := head.Header.Height
	walked := uint64(0)
	maxWalk := r101BackfillMaxWalkFor(cur, oldest)
	for {
		blk, err := s.blockStore.GetBlockByHeight(h)
		if err != nil || blk == nil || blk.Header == nil {
			break // gap or store error: stop; partial result is fine
		}
		e := blk.Header.Epoch
		if e < oldest {
			break // reached below the backfill window
		}
		firstBlock[e] = blk.Header
		walked++
		if walked >= maxWalk || h == 0 {
			break
		}
		h--
	}

	roots := make(map[uint64]types.Hash, len(firstBlock))
	for e, hdr := range firstBlock {
		if e == cur {
			continue // epoch in progress: live import path owns it
		}
		if hdr.Slot%consensus.SlotsPerEpoch == 0 {
			roots[e] = block.ComputeBlockHash(hdr)
		} else {
			roots[e] = hdr.ParentHash
		}
	}
	return roots
}

// r101BackfillOldestEpoch returns the oldest completed epoch the node must
// reconstruct. The normal depth is a baseline, not a ceiling: a finality stall
// can leave justifiedEpoch thousands of epochs behind the head, and source
// attestations remain fail-closed until that epoch's canonical root is known.
// The finalized checkpoint is included as well because the QPOS finality ratchet
// may consult it while recovering.
func r101BackfillOldestEpoch(
	currentEpoch uint64,
	justifiedEpoch uint64,
	finalizedEpoch uint64,
	checkpointRootsKnown bool,
) uint64 {
	oldest := uint64(0)
	if checkpointRootsKnown {
		if currentEpoch >= r101BackfillHealthyEpochDepth {
			oldest = currentEpoch - r101BackfillHealthyEpochDepth
		}
		return oldest
	}
	if currentEpoch >= r101BackfillEpochDepth {
		oldest = currentEpoch - r101BackfillEpochDepth
	}

	checkpointOldest := justifiedEpoch
	if finalizedEpoch > 0 && finalizedEpoch < checkpointOldest {
		checkpointOldest = finalizedEpoch
	}
	if checkpointOldest > 0 && checkpointOldest < oldest {
		oldest = checkpointOldest
	}
	return oldest
}

// r101BackfillMaxWalkFor raises the walk cap when the computed epoch window is
// wider than the normal baseline. It adds one epoch of cushion for a missed
// boundary and one block for genesis. The multiplication is checked before use
// so an untrusted or corrupt epoch value cannot wrap the limit downward.
func r101BackfillMaxWalkFor(currentEpoch, oldestEpoch uint64) uint64 {
	baseline := uint64(r101BackfillMaxWalk)
	if currentEpoch <= oldestEpoch {
		return baseline
	}
	spanEpochs := currentEpoch - oldestEpoch + 1
	if spanEpochs > ^uint64(0)/consensus.SlotsPerEpoch {
		return ^uint64(0)
	}
	required := spanEpochs*consensus.SlotsPerEpoch + 1
	if required > baseline {
		return required
	}
	return baseline
}

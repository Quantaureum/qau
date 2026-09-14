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
	// r101BackfillEpochDepth: how many COMPLETED epochs behind the head to
	// reconstruct. 4 covers the ratchet's needs (justified source is within
	// the last 2-3 epochs in any healthy or stuck scenario reachable today).
	r101BackfillEpochDepth = 4
	// r101BackfillMaxWalk bounds the backward scan (blocks). 8 epochs of
	// every-slot blocks = 8*32; a partial walk still yields the deepest
	// epochs first-incomplete, which is harmless (best-effort).
	r101BackfillMaxWalk = 512
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
// root of each completed epoch in [cur-depth, cur-1]. Best-effort: gaps or a
// truncated walk simply return fewer entries.
func (s *Syncer) reconstructEpochRoots(head *encoding.Block) map[uint64]types.Hash {
	cur := head.Header.Epoch
	oldest := uint64(0)
	if cur >= r101BackfillEpochDepth {
		oldest = cur - r101BackfillEpochDepth
	}

	// firstBlock[e] = the lowest-height block seen for epoch e (i.e. the
	// epoch's first block) — walking downward, overwrite on every sighting.
	firstBlock := make(map[uint64]*encoding.BlockHeader)
	h := head.Header.Height
	walked := 0
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
		if walked >= r101BackfillMaxWalk || h == 0 {
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

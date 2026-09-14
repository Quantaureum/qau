// Quantaureum Node source, version 1.0.0.
package node

import (
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// calibratePersistedVRFAccumulators validates the R58 persisted VRF
// accumulator checkpoints against the block store after the R52 replay.
// R88-C (2026-08-30).
//
// Background: the persisted checkpoints are a snapshot of the previous
// session's in-memory epochVRFAccumulator map. A persisted value for an
// epoch may point at a block that no longer exists in the store (the
// previous session ended on a fork that R53 truncated, or the checkpoint
// predates a reorg). Bulk-loading them (the pre-R88-C behavior,
// SetAllEpochVRFAccumulators before the replay) poisoned acc[epoch] with
// fork-local entropy, which diverges the proposer shuffle for epoch+1/+2
// — the R88 fork class.
//
// Calibration rules (qpos is the freshly replayed QPOS):
//   - e ≤ replayedTipEpoch: the R52 replay already assigned the
//     authoritative value; the persisted entry is redundant → discard.
//   - e > replayedTipEpoch and blocks of epoch e survive in the store
//     above the replayed tip: the LAST surviving block's header value is
//     authoritative → assign it (kept if identical to the persisted value,
//     calibrated otherwise).
//   - e > replayedTipEpoch with NO surviving blocks: discard (fail-closed —
//     the R45 cold-start guard is safer than unverifiable fork entropy).
//
// Returns (kept, calibrated, discarded) counts for logging.
func calibratePersistedVRFAccumulators(
	qpos *consensus.QPOS,
	blockStore *block.BlockStore,
	persisted map[uint64]types.Hash,
	replayedTipEpoch uint64,
	continuousTip uint64,
	latestHeight uint64,
) (kept, calibrated, discarded int) {
	if qpos == nil || blockStore == nil || len(persisted) == 0 {
		return 0, 0, 0
	}
	for e := range persisted {
		if e <= replayedTipEpoch {
			// The replay already assigned the authoritative value for this
			// epoch — the persisted entry is redundant.
			discarded++
			continue
		}
		// Look for the last surviving block of epoch e ABOVE the replayed
		// tip (at or below it the replay already covered e).
		var chainAcc types.Hash
		found := false
		for h := latestHeight; h > continuousTip; h-- {
			blk, err := blockStore.GetBlockByHeight(h)
			if err != nil || blk == nil || blk.Header == nil {
				continue
			}
			if blk.Header.Epoch < e {
				// Epochs are monotonic with height — everything below is
				// from an earlier epoch; stop early.
				break
			}
			if blk.Header.Epoch == e {
				chainAcc = blk.Header.VRFAccumulator
				found = true
				break // first hit from the top = last block of the epoch
			}
		}
		if found {
			if chainAcc == persisted[e] {
				kept++
			} else {
				calibrated++
			}
			qpos.SetEpochVRFAccumulator(e, chainAcc)
		} else {
			discarded++
			nodeLog.Warn("R88-C: discarding persisted VRF accumulator for epoch %d — no surviving canonical block for that epoch (possible fork/R53 truncation); cold-start guard (R45) takes over",
				e)
		}
	}
	return kept, calibrated, discarded
}

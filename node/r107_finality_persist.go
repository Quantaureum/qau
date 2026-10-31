// Quantaureum Node source, version 1.0.0.
package node

import (
	"errors"
	"fmt"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
)

// configureQPOSFinalityPersistence loads the latest durable Casper FFG
// checkpoint and registers the QPOS callback that stores future transitions.
// The callback is installed only after the stored checkpoint has been
// validated, so corrupt state is ignored rather than overwriting live QPOS
// state during startup.
func configureQPOSFinalityPersistence(qpos *consensus.QPOS, store *block.BlockStore) error {
	if qpos == nil {
		return errors.New("configure qpos finality persistence: nil qpos")
	}
	if store == nil {
		return errors.New("configure qpos finality persistence: nil block store")
	}

	justifiedEpoch, finalizedEpoch, justifiedRoot, finalizedRoot, err := store.LoadFinalityState()
	if err != nil {
		if !errors.Is(err, block.ErrInvalidFinalityState) {
			return fmt.Errorf("load finality state: %w", err)
		}
		// A corrupt checkpoint is untrusted. Start from the genesis-safe zero
		// state, keep persistence enabled, and let the next validated canonical
		// transition replace the bad record. Transient database errors still
		// fail closed and must not be mistaken for corruption.
		justifiedEpoch = 0
		finalizedEpoch = 0
		justifiedRoot = types.Hash{}
		finalizedRoot = types.Hash{}
		bpLog.Warn("R107-FINALITY-PERSIST: invalid persisted checkpoint ignored; awaiting canonical recovery")
	}
	if err := qpos.RestoreFinalityState(
		justifiedEpoch,
		finalizedEpoch,
		justifiedRoot,
		finalizedRoot,
	); err != nil {
		return fmt.Errorf("restore finality state: %w", err)
	}

	pinFinalizedCheckpointSlot(qpos, store, finalizedRoot)

	qpos.SetFinalityPersistCallback(func(
		justifiedEpoch uint64,
		finalizedEpoch uint64,
		justifiedRoot types.Hash,
		finalizedRoot types.Hash,
	) error {
		return store.PutFinalityState(
			justifiedEpoch,
			finalizedEpoch,
			justifiedRoot,
			finalizedRoot,
		)
	})
	return nil
}

// pinFinalizedCheckpointSlot resolves the restored checkpoint BLOCK's slot from
// the block store and hands it to the QPOS (R30 F23).
//
// A restarted node resumes at its head, so the QPOS slot-root map — which is
// in-memory only — never learns where the restored checkpoint block sits. Every
// reorg decision would then compare the abandoned range against the finalized
// epoch's BOUNDARY slot, which is only an upper bound on the checkpoint's slot
// (R42-P3): on a chain that skipped that slot, legal reorgs in the
// (checkpoint, boundary] band were refused for as long as the node ran, which
// is exactly the F21 liveness defect.
//
// The lookup is advisory: when the block is not stored, or is stored but not
// canonical at its height, nothing is pinned and the conservative boundary-slot
// fallback stays in force (it can only refuse reorgs that are legal, never
// accept one that rewrites finality).
func pinFinalizedCheckpointSlot(qpos *consensus.QPOS, store *block.BlockStore, finalizedRoot types.Hash) {
	if qpos == nil || store == nil || finalizedRoot == (types.Hash{}) {
		return
	}
	blk, err := store.GetBlock(finalizedRoot)
	if err != nil || blk == nil || blk.Header == nil {
		bpLog.Warn("R30 F23: cannot resolve the finalized checkpoint block %x from the store (%v); reorg decisions will compare against the epoch boundary slot, which refuses reorgs above the checkpoint until the block is re-imported",
			finalizedRoot[:8], err)
		return
	}
	canonical, cerr := store.GetBlockHash(blk.Header.Height)
	if cerr != nil || canonical != finalizedRoot {
		bpLog.Warn("R30 F23: the finalized checkpoint block %x is stored but is not canonical at height %d (canonical=%x, err=%v); keeping the boundary-slot fallback",
			finalizedRoot[:8], blk.Header.Height, canonical[:8], cerr)
		return
	}
	if !qpos.SetFinalizedCheckpointSlot(finalizedRoot, blk.Header.Slot) {
		bpLog.Warn("R30 F23: the store's block %x at slot %d cannot be the finalized checkpoint (finalized root/epoch changed); keeping the boundary-slot fallback",
			finalizedRoot[:8], blk.Header.Slot)
		return
	}
	bpLog.Info("R30 F23: finalized checkpoint pinned at height %d slot %d (root %x)",
		blk.Header.Height, blk.Header.Slot, finalizedRoot[:8])
}

// persistedFinalityFitsStore reports whether the finalized checkpoint currently
// held by qpos can still be backed by store, i.e. whether the store holds a
// chain that reaches the finalized epoch. It returns a human-readable detail
// when it cannot.
//
// R30 F5 (2026-10-30): every finality update ratchets forward (tryUpdateFinality
// and AdoptHeaderFinality never lower an epoch), so a checkpoint that claims an
// epoch beyond the local head can never be corrected from disk. It then pins the
// finality floor above every local block, which makes rollbackBelowFinality and
// reanchorSlotRoots refuse every rollback — the node stops following the chain
// and can only be recovered by wiping its database. A checkpoint of epoch E is
// the root of a canonical block at or below slot E*SlotsPerEpoch, so the local
// head must be in epoch E or later for that block to exist here.
func persistedFinalityFitsStore(qpos *consensus.QPOS, store *block.BlockStore) (bool, string) {
	if qpos == nil || store == nil {
		return true, ""
	}
	finalizedEpoch := qpos.GetFinalizedEpoch()
	if finalizedEpoch == 0 {
		return true, ""
	}
	latest, err := store.GetLatestBlock()
	if err != nil || latest == nil || latest.Header == nil {
		return false, "the store has no head block to back the checkpoint"
	}
	headEpoch := consensus.SlotToEpoch(latest.Header.Slot)
	if finalizedEpoch > headEpoch {
		return false, fmt.Sprintf(
			"checkpoint finalizes epoch %d but the local head is height %d at slot %d (epoch %d)",
			finalizedEpoch, latest.Header.Height, latest.Header.Slot, headEpoch)
	}
	return true, ""
}

// checkPersistedFinalityBacking validates a restored checkpoint against the
// local block store and, when it cannot be backed, marks local state untrusted
// so this node stops producing blocks. The checkpoint itself is kept: it is
// fail-closed (a floor above every local block refuses reorgs rather than
// allowing them), and dropping it would let this node reorg history the network
// has already finalized. Returns true when the store backs the checkpoint.
func (n *Node) checkPersistedFinalityBacking(qpos *consensus.QPOS, store *block.BlockStore) bool {
	ok, detail := persistedFinalityFitsStore(qpos, store)
	if ok {
		return true
	}
	bpLog.Error("R30 F5: the durable finality checkpoint is not backed by this store (%s); "+
		"the finalize ratchet only moves forward, so it cannot be repaired from disk and it will block "+
		"every future rollback and re-sync", detail)
	n.markStateTrustBroken("durable finality checkpoint is not backed by the local block store: " + detail)
	return false
}

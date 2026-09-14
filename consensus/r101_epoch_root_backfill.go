// Quantaureum Node source, version 1.0.0.
package consensus

import "github.com/quantaureum/qau/types"

// R101-FINALITY-RESUME (2026-08-30)
//
// Symptom (mainnet, reproduced in TestR101_*): after any node restart at a
// non-genesis epoch, justifiedEpoch advances once (onto prevEpoch) and then
// FREEZES forever; finalizedEpoch stays 0; the Inactivity Leak never
// deactivates. Root cause: epochBlockRoots lives ONLY in memory. A restarted
// node never recorded the boundary root of the epoch its peers attest as
// Source. tryUpdateFinality (qpos_finality.go) fail-closed skips every
// attestation whose Source root cannot be verified against
// epochBlockRoots[Source.Epoch] (CORE-03 / CS-02 hardening — correct), so
// with the root missing, attestedWeight never accumulates and the
// ratchet deadlocks permanently.
//
// Fix: the node layer reconstructs the recent epochs' boundary roots from
// the canonical block store (the roots are a pure function of the stored
// blocks: each epoch's root is derived from that epoch's FIRST block — its
// own hash when it sits on a boundary slot, its ParentHash otherwise) and
// injects them here. This method is the single write path for backfilled
// roots.
//
// Semantics:
//   - OVERWRITE for already-known epochs (identical to the import path's
//     final value for completed epochs — SetEpochBlockRoot at the boundary
//     block; EnsureEpochBlockRoot pinning the parent hash when the boundary
//     slot was missed). Re-derivation from the same canonical chain always
//     yields the same value, so overwriting is a no-op for a healthy node.
//   - Epoch 0 is preserved if already registered (SetGenesisRoot's
//     immutable-once-set contract is NOT relaxed by this method).
//   - Zero roots are ignored (fail-closed: an unknown root must never
//     overwrite a known one).
//   - No per-entry pruning: inserting several historical epochs in a loop
//     through setEpochBlockRootLocked could trip the len>10 prune mid-loop
//     (prune cutoffs move with each insert when finalizedEpoch is small),
//     silently deleting entries inserted moments earlier. A bulk insert must
//     be atomic with respect to pruning; the regular import path keeps
//     pruning on subsequent blocks as before.
//
// Returns the number of entries applied (excluding epoch-0 conflicts and
// zero roots).
// HasEpochRoot reports whether a (non-zero) boundary root is known for the
// given epoch. Read-only diagnostic used by node-level backfill tests and
// future finality-stall diagnostics (e.g. "justified epoch root present?").
func (q *QPOS) HasEpochRoot(epoch uint64) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	r, ok := q.epochBlockRoots[epoch]
	return ok && r != (types.Hash{})
}

func (q *QPOS) BackfillEpochRoots(roots map[uint64]types.Hash) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	applied := 0
	for e, r := range roots {
		if r == (types.Hash{}) {
			continue
		}
		if e == 0 {
			if existing, ok := q.epochBlockRoots[0]; ok && existing != (types.Hash{}) {
				// Genesis root already registered — immutable (SetGenesisRoot
				// contract). The canonical-store value is identical on the
				// same chain; a DIFFERENT value would indicate the node is on
				// the wrong chain, in which case we must not silently swap it.
				continue
			}
		}
		q.epochBlockRoots[e] = r
		applied++
	}
	return applied
}

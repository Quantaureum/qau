// Quantaureum Node source, version 1.0.0.
package node

import (
	"github.com/quantaureum/qau/types"
)

// vrfAccumulatorSource is the minimal interface needed by
// selectDACommitteeSeed. Defined here (not in consensus/) to avoid adding
// a reverse dependency from consensus → node. QPOS satisfies this
// interface; tests use a stub.
//
// DA-R5-03 (2026-07-16).
type vrfAccumulatorSource interface {
	GetEpochVRFAccumulator(epoch uint64) types.Hash
	GetFinalizedEpoch() uint64
	GetRANDAO() types.Hash
}

// selectDACommitteeSeed implements the three-tier seed selection that
// eliminates last-revealer bias in the DA committee shuffle (DA-R5-03).
//
// See node.go (initDanksharding) for the full rationale. This helper is
// extracted so the selection logic can be unit-tested without spinning up
// a full Node + QPOS instance.
//
// Tier 1 (preferred): finalizedEpoch's accumulator (immutable).
// Tier 2 (fallback):  epoch-1's accumulator (complete, matches proposer shuffle).
// Tier 3 (last resort): RANDAO (startup/initial sync).
//
// qpos may be nil — returns the zero hash (matches the nil-guard in
// initDanksharding's closure).
func selectDACommitteeSeed(qpos vrfAccumulatorSource, epoch uint64) types.Hash {
	if qpos == nil {
		return types.Hash{}
	}
	finalizedEpoch := qpos.GetFinalizedEpoch()
	if finalizedEpoch > 0 && finalizedEpoch < epoch {
		if acc := qpos.GetEpochVRFAccumulator(finalizedEpoch); acc != (types.Hash{}) {
			return acc
		}
	}
	if epoch > 0 {
		if acc := qpos.GetEpochVRFAccumulator(epoch - 1); acc != (types.Hash{}) {
			return acc
		}
	}
	return qpos.GetRANDAO()
}

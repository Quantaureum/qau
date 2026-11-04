// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/binary"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
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

// consensusHardeningEpochReader is implemented by *consensus.QPOS. Keeping it
// as an optional type assertion preserves the minimal vrfAccumulatorSource
// interface used by the legacy tests' stubs.
type consensusHardeningEpochReader interface {
	ConsensusHardeningEpoch() uint64
}

// selectDACommitteeSeedPure derives the DA committee seed as a pure function
// of chain data (audit QR-22). Unlike the three-tier legacy selection it never
// reads node-local finality progress and never falls back to the node-local
// RANDAO mix, so two honest nodes at the same head derive the same committee
// regardless of when they first compute it.
//
// Empty-epoch fallback is keccak(epoch), the same deterministic, publicly
// computable convention the proposer shuffle uses when an accumulator is
// missing. It costs one epoch of schedule predictability but cannot fork.
func selectDACommitteeSeedPure(qpos vrfAccumulatorSource, epoch uint64) types.Hash {
	if qpos == nil {
		return types.Hash{}
	}
	if epoch > 0 {
		if acc := qpos.GetEpochVRFAccumulator(epoch - 1); acc != (types.Hash{}) {
			return acc
		}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	h := sha3.NewLegacyKeccak256()
	h.Write(buf[:])
	var seed types.Hash
	copy(seed[:], h.Sum(nil))
	return seed
}

// selectDACommitteeSeedGated is the production entry point. Below the
// coordinated activation epoch it is byte-identical to the legacy three-tier
// selection; from that epoch on it uses the pure chain-derived seed.
func selectDACommitteeSeedGated(qpos vrfAccumulatorSource, epoch uint64) types.Hash {
	if qpos == nil {
		return types.Hash{}
	}
	if reader, ok := qpos.(consensusHardeningEpochReader); ok {
		n := reader.ConsensusHardeningEpoch()
		if n > 0 && epoch >= n {
			return selectDACommitteeSeedPure(qpos, epoch)
		}
	}
	return selectDACommitteeSeed(qpos, epoch)
}

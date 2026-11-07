// Quantaureum Node source, version 1.0.0.
package node

import (
	"sort"
	"sync/atomic"

	"github.com/quantaureum/qau/consensus"
)

// M4-F4: canonical index order for epoch reward crediting.
//
// The epoch census embedded in a boundary block stores per-validator rewards as
// arrays indexed by the PROPOSER's validator-set order. Every consumer
// translates rewards[idx] to its own validators[idx] address. ValidatorSet
// assigns indices by insertion order:
//
//   - genesis and restart paths insert in address-sorted order (NewValidatorSet
//     sorts; syncQPOSValidatorsFromStaking appends sorted — R87-VSET-ORDER);
//   - the live staking path (QPOS.AddStakingValidator) APPENDS a newly staked
//     validator at the tail, which is not its sorted position.
//
// A node that applied a post-genesis stake therefore holds a different order
// from a node that restarted with the same membership, and one census index
// resolves to two different addresses. This is a consensus-semantics change, so
// it is gated: epochRewardsCanonicalOrderActivation is the first epoch whose
// rewards are translated through the address-sorted set. 0 (the default)
// disables the canonical path entirely — the legacy live-order translation
// stays byte-for-byte identical.
var epochRewardsCanonicalOrderActivation atomic.Uint64

// SetEpochRewardsCanonicalOrderActivation installs the activation epoch.
// 0 keeps the legacy (live-order) translation. It must be set from node
// startup config, before any block is applied.
func SetEpochRewardsCanonicalOrderActivation(epoch uint64) {
	epochRewardsCanonicalOrderActivation.Store(epoch)
}

// EpochRewardsCanonicalOrderActivation returns the activation epoch (0 = disabled).
func EpochRewardsCanonicalOrderActivation() uint64 {
	return epochRewardsCanonicalOrderActivation.Load()
}

// epochRewardsUseCanonicalOrder reports whether rewards for epoch must be
// translated through the address-sorted validator order.
func epochRewardsUseCanonicalOrder(epoch uint64) bool {
	activation := epochRewardsCanonicalOrderActivation.Load()
	return activation != 0 && epoch >= activation
}

// epochRewardTargets returns the validator slice whose order translates the
// census indices for the given epoch.
//
// Legacy (default): the live slice itself, unchanged — identical order and no
// copy, so the crediting loop sees exactly what it saw before this switch
// existed. Canonical (epoch >= activation): an address-sorted copy; the live
// set is never mutated.
func epochRewardTargets(vList []*consensus.Validator, epoch uint64) []*consensus.Validator {
	if !epochRewardsUseCanonicalOrder(epoch) {
		return vList
	}
	sorted := append([]*consensus.Validator(nil), vList...)
	sort.Slice(sorted, func(i, j int) bool {
		return bytesLess(sorted[i].Address[:], sorted[j].Address[:])
	})
	return sorted
}

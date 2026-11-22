// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"sort"
	"sync/atomic"

	"github.com/quantaureum/qau/types"
)

// M4-F4: canonical index domain for epoch reward derivation.
//
// The epoch census embedded in an epoch-boundary block header carries
// per-validator data indexed by a validator-set POSITION, and the reward
// formula resolves those positions against a node-local validator slice.
// ValidatorSet assigns positions by INSERTION order:
//
//   - genesis and restart paths insert in address-sorted order
//     (NewValidatorSet sorts; the node's startup staking sync appends
//     sorted — R87-VSET-ORDER);
//   - the live staking path APPENDS a newly staked validator at the tail,
//     which is not necessarily its sorted position.
//
// A node that applied a post-genesis stake therefore holds a different order
// from a node that restarted with the same membership, and one census index
// resolves to two different validators — a different reward AMOUNT (the base
// reward is derived from the stake at that position) AND a different
// RECIPIENT — for the very same on-chain census. That is the M4 state-root
// divergence: it first appears at an epoch-boundary block (frequently empty
// on a low-traffic chain) and every subsequent block mismatches.
//
// The fix is a CANONICAL index domain: for epochs at or after the activation
// epoch, every consumer resolves census indices against the ADDRESS-SORTED
// validator slice — the one order every node derives identically from the
// same membership. Both the reward computation (this layer,
// computeEpochRewardsUnlocked) and the balance crediting (node layer,
// epochRewardTargets) resolve through the same sorted slice, so the derived
// rewards — and therefore the state root — no longer depend on the node's
// insertion history.
//
// This is a consensus-semantics change, so it is gated:
// epochRewardsCanonicalOrderActivation is the first epoch that uses the
// canonical order. 0 (the default) disables the canonical path entirely — the
// legacy live-order translation stays byte-for-byte identical. The value must
// be identical on every node of the network (node.Config
// .EpochRewardsCanonicalOrderActivationEpoch); a divergent value forks the
// chain at the activation epoch.
var epochRewardsCanonicalOrderActivation atomic.Uint64

// SetEpochRewardsCanonicalOrderActivation installs the activation epoch.
// 0 keeps the legacy (live-order) translation. It must be set from node
// startup config before any block is applied or produced.
func SetEpochRewardsCanonicalOrderActivation(epoch uint64) {
	epochRewardsCanonicalOrderActivation.Store(epoch)
}

// EpochRewardsCanonicalOrderActivation returns the activation epoch
// (0 = disabled).
func EpochRewardsCanonicalOrderActivation() uint64 {
	return epochRewardsCanonicalOrderActivation.Load()
}

// EpochRewardsUseCanonicalOrder reports whether rewards for epoch must be
// derived through the address-sorted validator order.
func EpochRewardsUseCanonicalOrder(epoch uint64) bool {
	activation := epochRewardsCanonicalOrderActivation.Load()
	return activation != 0 && epoch >= activation
}

// SortValidatorsByAddress returns an address-sorted COPY of vList; the input
// slice is never mutated. This comparator is the single definition of the
// canonical validator order shared by the reward computation and the
// crediting paths.
func SortValidatorsByAddress(vList []*Validator) []*Validator {
	sorted := append([]*Validator(nil), vList...)
	sort.Slice(sorted, func(i, j int) bool {
		return validatorAddressLess(sorted[i].Address, sorted[j].Address)
	})
	return sorted
}

// CanonicalRewardValidators returns the validator slice whose positions are
// the reward index domain for the given epoch: the address-sorted copy when
// the epoch is at/after the activation, otherwise the input slice unchanged
// (legacy behavior, no copy).
func CanonicalRewardValidators(epoch uint64, vList []*Validator) []*Validator {
	if !EpochRewardsUseCanonicalOrder(epoch) {
		return vList
	}
	return SortValidatorsByAddress(vList)
}

// validatorAddressLess reports whether a < b by address bytes.
func validatorAddressLess(a, b types.Address) bool {
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

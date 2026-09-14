// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"sort"

	"github.com/quantaureum/qau/types"
)

// R87-VSET-ORDER (2026-08-29): deterministic ordering helpers for validator-set
// reconstruction.
//
// syncQPOSValidatorsFromStaking rebuilds the QPOS validator set at startup from
// stakingManager.GetActiveValidators(), which returns a Go map — iterating it
// in map order made the APPEND ORDER of post-genesis (staked) validators depend
// on map layout, which differs per process start. The ValidatorSet assigns
// consensus indices by insertion order, and epoch rewards credit
// rewards.AttesterRewards[idx] to validators[idx], so two nodes that restarted
// with different map layouts would credit the SAME census indices to DIFFERENT
// addresses — permanent state-root divergence, the same failure class as
// R87-M4. With ≥2 staked validators and one restart, divergence is guaranteed.
//
// Everything that feeds the validator set at startup must therefore be sorted
// by address bytes. Genesis validators are unaffected (NewValidatorSet sorts
// them), but the append order after them must also be deterministic.

// sortedStakerAddrs returns the addresses of active stakers sorted by address
// bytes, so the map's iteration order is never leaked into consensus indices.
func sortedStakerAddrs(stakers map[types.Address]*big.Int) []types.Address {
	addrs := make([]types.Address, 0, len(stakers))
	for addr := range stakers {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool {
		return bytesLess(addrs[i][:], addrs[j][:])
	})
	return addrs
}

// bytesLess reports whether a < b lexicographically.
func bytesLess(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

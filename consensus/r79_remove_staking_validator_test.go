// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// R79-UNSTAKE-VSET (2026-08-28): QPOS.RemoveStakingValidator is the symmetric
// counterpart of AddStakingValidator. Without it, the staking-tx sync path had
// no way to drop a fully-unstaked validator from the live consensus set, so
// nodes ended up with different sets, elected different proposers for the same
// slot, and the chain forked at every slot.
// ─────────────────────────────────────────────────────────────────────────────

func TestR79_RemoveStakingValidator(t *testing.T) {
	// The shuffle / committee caches are only used when the set is larger than
	// SlotsPerEpoch, so build a set big enough for the cache-invalidation part
	// of the contract to be observable.
	seed := make([]*Validator, 0, int(SlotsPerEpoch)+8)
	stake := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	for i := 0; i < int(SlotsPerEpoch)+8; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		seed = append(seed, &Validator{
			Address:    addr,
			Stake:      new(big.Int).Set(stake),
			Active:     true,
			Commission: 100,
		})
	}
	vs, err := NewValidatorSet(seed)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	q, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	a := types.Address{0xaa}
	b := types.Address{0xbb}
	q.AddStakingValidator(a, stake)
	q.AddStakingValidator(b, stake)
	if q.GetValidatorSet().GetValidator(a) == nil {
		t.Fatal("precondition: validator a missing after AddStakingValidator")
	}
	sizeBefore := q.GetValidatorSet().Size()

	// Warm the shuffle / committee caches so we can prove they are dropped.
	q.ShuffleValidators(1)
	if _, err := q.GetCommitteeForSlot(1); err != nil {
		t.Logf("GetCommitteeForSlot warm-up: %v", err)
	}
	if len(q.shuffleCache) == 0 && len(q.committeeCache) == 0 {
		t.Fatal("neither cache warmed up; the invalidation assertions below would be vacuous")
	}

	if !q.RemoveStakingValidator(a) {
		t.Fatal("RemoveStakingValidator returned false for a present validator")
	}
	if q.GetValidatorSet().GetValidator(a) != nil {
		t.Fatal("validator a still present after RemoveStakingValidator")
	}
	if q.GetValidatorSet().GetValidator(b) == nil {
		t.Fatal("RemoveStakingValidator removed the wrong validator")
	}
	if got := q.GetValidatorSet().Size(); got != sizeBefore-1 {
		t.Fatalf("set size = %d, want %d", got, sizeBefore-1)
	}
	if len(q.shuffleCache) != 0 {
		t.Fatal("shuffle cache was not invalidated (stale proposer election)")
	}
	if len(q.committeeCache) != 0 {
		t.Fatal("committee cache was not invalidated (stale committee membership)")
	}

	// Removing an absent address is a no-op that still reports false.
	if q.RemoveStakingValidator(types.Address{0xff}) {
		t.Fatal("RemoveStakingValidator returned true for an absent address")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R85-CHAMBER-MINIMUM (2026-08-28): the Three Chambers arithmetic only closes
// from 6 validators. On the 3-validator devnet the Review Chamber could never
// reach its supermajority, so only the single Executive node advanced
// justified/finalized while the others reported justifiedEpoch=0 forever —
// which looked like a finality bug but is a validator-count floor.
// ─────────────────────────────────────────────────────────────────────────────

func TestR85_MinValidatorsForChambersMatchesExecutiveArithmetic(t *testing.T) {
	// executive <= n/3 - 1 with the executive clamped to >= 1: the first n for
	// which a non-clamped executive exists is MinValidatorsForChambers.
	for n := 1; n < MinValidatorsForChambers; n++ {
		if got := executiveSizeForValidatorCount(n); got != 1 {
			t.Fatalf("n=%d: executive size = %d, want the clamped value 1", n, got)
		}
		if n/3-1 >= 1 {
			t.Fatalf("n=%d: the arithmetic already closes below the documented minimum %d",
				n, MinValidatorsForChambers)
		}
	}

	if n := MinValidatorsForChambers; n/3-1 != 1 {
		t.Fatalf("n=%d: expected executive = n/3-1 = 1, got %d", n, n/3-1)
	}
	if got := executiveSizeForValidatorCount(MinValidatorsForChambers); got != 1 {
		t.Fatalf("n=%d: executive size = %d, want 1", MinValidatorsForChambers, got)
	}

	// Above the minimum the executive grows as documented (n=9 -> 2, n=12 -> 3).
	for n, want := range map[int]int{9: 2, 12: 3, 30: 3} {
		if got := executiveSizeForValidatorCount(n); got != want {
			t.Fatalf("n=%d: executive size = %d, want %d", n, got, want)
		}
	}
}

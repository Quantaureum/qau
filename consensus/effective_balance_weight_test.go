package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// Effective-balance consensus-weight integration tests. These verify that the
// weighted-proposer table (the live proposer-election surface) uses the capped
// effective balance rather than raw stake once the cutover epoch is active.

// ebNewQPOS builds a QPOS over validators with the given QAU stakes and the
// given weighted/effective-balance cutover epoch.
func ebNewQPOS(t *testing.T, qauStakes []int64, cutover uint64) *QPOS {
	t.Helper()
	vals := make([]*Validator, len(qauStakes))
	for i, s := range qauStakes {
		vals[i] = &Validator{
			Address: types.Address{byte(i + 1)},
			Stake:   new(big.Int).Mul(big.NewInt(s), big.NewInt(1e18)),
			Active:  true,
		}
	}
	vs, err := NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	q, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	if err := SetGenesisTime(1788110700); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
	q.SetGenesisRoot(types.Hash{0x42})
	q.SetWeightedProposerCutover(cutover)
	return q
}

// TestEB_TableCapsWeightAtMaxEffectiveBalance: when the effective-balance
// regime is active, the weighted table must record each validator's weight as
// min(floor(stake), MaxEffectiveBalance). A 6000-QAU validator and a 2048-QAU
// validator must therefore carry identical table weight (2048), while below
// the cutover the table uses raw stake (6000 vs 2048).
func TestEB_TableCapsWeightAtMaxEffectiveBalance(t *testing.T) {
	// Above cutover: effective-balance regime active.
	q := ebNewQPOS(t, []int64{6000, 2048}, 0)
	q.mu.Lock()
	table := q.buildWeightedEpochTableLocked(0)
	q.mu.Unlock()
	if len(table.cum) != 2 {
		t.Fatalf("expected 2 eligible validators, got %d", len(table.cum))
	}
	// cum[0] is validator 0's weight; cum[1]-cum[0] is validator 1's weight.
	w0 := new(big.Int).Set(table.cum[0])
	w1 := new(big.Int).Sub(table.cum[1], table.cum[0])
	want := MaxEffectiveBalance // 2048 QAU
	if w0.Cmp(want) != 0 {
		t.Fatalf("validator0 (6000 stake) weight = %v, want capped %v", w0, want)
	}
	if w1.Cmp(want) != 0 {
		t.Fatalf("validator1 (2048 stake) weight = %v, want %v", w1, want)
	}
	if table.total.Cmp(new(big.Int).Mul(want, big.NewInt(2))) != 0 {
		t.Fatalf("total weight = %v, want %v", table.total, new(big.Int).Mul(want, big.NewInt(2)))
	}
}

// TestEB_LegacyBelowCutoverUsesRawStake: below the cutover the table must
// remain byte-identical to legacy raw-stake behavior (no capping).
func TestEB_LegacyBelowCutoverUsesRawStake(t *testing.T) {
	q := ebNewQPOS(t, []int64{6000, 2048}, ^uint64(0)) // feature OFF
	q.mu.Lock()
	table := q.buildWeightedEpochTableLocked(0)
	q.mu.Unlock()
	w0 := new(big.Int).Set(table.cum[0])
	w1 := new(big.Int).Sub(table.cum[1], table.cum[0])
	if w0.Cmp(qau(6000)) != 0 {
		t.Fatalf("legacy validator0 weight = %v, want raw 6000", w0)
	}
	if w1.Cmp(qau(2048)) != 0 {
		t.Fatalf("legacy validator1 weight = %v, want raw 2048", w1)
	}
}

// TestEB_ConsensusWeightHelperGating verifies the gating helper directly.
func TestEB_ConsensusWeightHelperGating(t *testing.T) {
	qOn := ebNewQPOS(t, []int64{6000}, 0)
	if got := qOn.consensusWeight(qau(6000), 0); got.Cmp(qau(2048)) != 0 {
		t.Fatalf("regime on: consensusWeight(6000) = %v, want 2048", got)
	}
	qOff := ebNewQPOS(t, []int64{6000}, ^uint64(0))
	if got := qOff.consensusWeight(qau(6000), 0); got.Cmp(qau(6000)) != 0 {
		t.Fatalf("regime off: consensusWeight(6000) = %v, want raw 6000", got)
	}
}

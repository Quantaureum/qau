package consensus

import (
	"math/big"
	"testing"
)

func qau(n int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18))
}

func TestEffectiveBalance(t *testing.T) {
	tests := []struct {
		name  string
		stake *big.Int
		want  *big.Int
	}{
		{"nil", nil, big.NewInt(0)},
		{"zero", big.NewInt(0), big.NewInt(0)},
		{"negative", big.NewInt(-1), big.NewInt(0)},
		{"below one increment", big.NewInt(5e17), big.NewInt(0)}, // 0.5 QAU rounds to 0
		{"exactly min activation", qau(32), qau(32)},
		{"hundred", qau(100), qau(100)},
		{"just below cap", qau(2047), qau(2047)},
		{"exactly cap", qau(2048), qau(2048)},
		{"above cap grandfathered", qau(6000), qau(2048)},
		{"far above cap", qau(6600000), qau(2048)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveBalance(tc.stake)
			if got.Cmp(tc.want) != 0 {
				t.Fatalf("EffectiveBalance(%v) = %v, want %v", tc.stake, got, tc.want)
			}
		})
	}
}

func TestEffectiveBalanceRoundsDown(t *testing.T) {
	// 100.75 QAU must round down to 100 QAU.
	stake := new(big.Int).Add(qau(100), big.NewInt(75e16))
	got := EffectiveBalance(stake)
	if got.Cmp(qau(100)) != 0 {
		t.Fatalf("rounding: got %v, want %v", got, qau(100))
	}
}

func TestEffectiveBalanceDoesNotMutateInput(t *testing.T) {
	stake := qau(6000)
	orig := new(big.Int).Set(stake)
	_ = EffectiveBalance(stake)
	if stake.Cmp(orig) != 0 {
		t.Fatalf("input mutated: %v != %v", stake, orig)
	}
}

func TestEffectiveBalanceReturnsFreshInt(t *testing.T) {
	// Mutating the result must not corrupt the shared MaxEffectiveBalance.
	got := EffectiveBalance(qau(6000))
	got.Add(got, qau(1))
	if MaxEffectiveBalance.Cmp(qau(2048)) != 0 {
		t.Fatalf("MaxEffectiveBalance corrupted: %v", MaxEffectiveBalance)
	}
}

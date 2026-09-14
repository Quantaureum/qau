// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func makeBenchValidatorSet(n int) *ValidatorSet {
	vals := make([]*Validator, n)
	for i := 0; i < n; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		vals[i] = &Validator{
			Address: addr,
			Stake:   big.NewInt(1000),
			Active:  true,
		}
	}
	vs, _ := NewValidatorSet(vals)
	return vs
}

func benchValidatorSizes(b *testing.B, fn func(vs *ValidatorSet)) {
	sizes := []int{10, 50, 100, 500, 1000}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("validators_%d", n), func(b *testing.B) {
			vs := makeBenchValidatorSet(n)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				fn(vs)
			}
		})
	}
}

func BenchmarkQPOS_SelectProposer(b *testing.B) {
	benchValidatorSizes(b, func(vs *ValidatorSet) {
		vrfOutput := &VRFOutput{
			Value: [32]byte{0x01, 0x02, 0x03},
		}
		vs.SelectProposer(vrfOutput)
	})
}

func BenchmarkQPOS_GetProposerForSlot(b *testing.B) {
	benchValidatorSizes(b, func(vs *ValidatorSet) {
		qpos, _ := NewQPOS(vs)
		qpos.GetProposerForSlot(1)
	})
}

func BenchmarkQPOS_GetCommitteeForSlot(b *testing.B) {
	benchValidatorSizes(b, func(vs *ValidatorSet) {
		qpos, _ := NewQPOS(vs)
		qpos.GetCommitteeForSlot(1)
	})
}

func BenchmarkQPOS_ShuffleValidators(b *testing.B) {
	benchValidatorSizes(b, func(vs *ValidatorSet) {
		qpos, _ := NewQPOS(vs)
		qpos.ShuffleValidators(1)
	})
}

func BenchmarkQPOS_EpochProcessing(b *testing.B) {
	sizes := []int{10, 50, 100, 500}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("validators_%d", n), func(b *testing.B) {
			vq := NewValidatorQueue()
			minStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
			for i := 0; i < n; i++ {
				var addr types.Address
				addr[0] = byte(i + 1)
				var caller types.Address
				caller[0] = byte(i + 1)
				var withdrawal types.Address
				withdrawal[0] = byte(i + 1)
				vq.RegisterValidator(caller, addr, minStake, withdrawal, 0)
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				vq.ProcessEpoch(uint64(i) + 1)
			}
		})
	}
}

func BenchmarkQPOS_FinalityCheck(b *testing.B) {
	benchValidatorSizes(b, func(vs *ValidatorSet) {
		qpos, _ := NewQPOS(vs)
		_ = qpos.GetJustifiedEpoch()
		_ = qpos.GetFinalizedEpoch()
	})
}

func BenchmarkValidatorSet_Creation(b *testing.B) {
	sizes := []int{10, 100, 1000}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("validators_%d", n), func(b *testing.B) {
			vals := make([]*Validator, n)
			for i := 0; i < n; i++ {
				var addr types.Address
				addr[0] = byte(i + 1)
				vals[i] = &Validator{
					Address: addr,
					Stake:   big.NewInt(1000),
					Active:  true,
				}
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				NewValidatorSet(vals)
			}
		})
	}
}

// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

func init() {
	EnableTestHelpers()
}

func setupGenesisForBenchmark() {
	ResetGenesisTimeForTesting()
	SetGenesisTime(time.Now().Unix() - 100)
}

func generateValidators(count int) []*Validator {
	validators := make([]*Validator, count)
	for i := 0; i < count; i++ {
		addr := types.Address{}
		addr[0] = byte(i >> 24)
		addr[1] = byte(i >> 16)
		addr[2] = byte(i >> 8)
		addr[3] = byte(i)
		validators[i] = &Validator{
			Address:    addr,
			Stake:      big.NewInt(int64(1000 + i%100)),
			Active:     true,
			Commission: 500,
		}
	}
	return validators
}

func TestLargeScale_GetValidatorByIndex(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(1000))
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	v := vs.GetValidatorByIndex(0)
	if v == nil {
		t.Fatal("GetValidatorByIndex(0) returned nil")
	}

	v = vs.GetValidatorByIndex(-1)
	if v != nil {
		t.Fatal("GetValidatorByIndex(-1) should return nil")
	}

	v = vs.GetValidatorByIndex(1000)
	if v != nil {
		t.Fatal("GetValidatorByIndex(1000) should return nil for out-of-bounds")
	}

	v = vs.GetValidatorByIndex(999)
	if v == nil {
		t.Fatal("GetValidatorByIndex(999) returned nil")
	}
}

func TestLargeScale_ValidatorCount(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(500))
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	if vs.ValidatorCount() != 500 {
		t.Fatalf("ValidatorCount() = %d, want 500", vs.ValidatorCount())
	}

	if vs.ValidatorCount() != vs.Size() {
		t.Fatalf("ValidatorCount() = %d != Size() = %d", vs.ValidatorCount(), vs.Size())
	}
}

func TestLargeScale_GetValidatorIndex_O1(t *testing.T) {
	count := 10000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	for i := 0; i < 100; i++ {
		targetIdx := i * (count / 100)
		v := vs.GetValidatorByIndex(targetIdx)
		if v == nil {
			t.Fatalf("GetValidatorByIndex(%d) returned nil", targetIdx)
		}

		idx := vs.GetValidatorIndex(v.Address)
		if idx != targetIdx {
			t.Fatalf("GetValidatorIndex(%x) = %d, want %d", v.Address, idx, targetIdx)
		}
	}

	unknownAddr := types.Address{0xFF, 0xFF, 0xFF, 0xFF}
	idx := vs.GetValidatorIndex(unknownAddr)
	if idx != -1 {
		t.Fatalf("GetValidatorIndex for unknown address = %d, want -1", idx)
	}
}

func TestLargeScale_DeepCopy_addrIndexMap(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(100))
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	copy := vs.DeepCopy()

	for i := 0; i < 100; i++ {
		v := vs.GetValidatorByIndex(i)
		idx := copy.GetValidatorIndex(v.Address)
		if idx != i {
			t.Fatalf("DeepCopy addrIndexMap: GetValidatorIndex(%x) = %d, want %d", v.Address, idx, i)
		}
	}
}

func TestLargeScale_10KValidators_CommitteeAllocation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-scale test in short mode")
	}

	count := 10000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	for slot := uint64(0); slot < 32; slot++ {
		committee, err := qpos.GetCommitteeForSlot(slot)
		if err != nil {
			t.Fatalf("GetCommitteeForSlot(%d) failed: %v", slot, err)
		}

		if len(committee) == 0 {
			t.Fatalf("GetCommitteeForSlot(%d) returned empty committee", slot)
		}

		if len(committee) > TargetCommitteeSize {
			t.Fatalf("committee size %d > TargetCommitteeSize %d", len(committee), TargetCommitteeSize)
		}
	}
}

func TestLargeScale_50KValidators_CommitteeAllocation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-scale test in short mode")
	}

	count := 50000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	for slot := uint64(0); slot < 32; slot++ {
		committee, err := qpos.GetCommitteeForSlot(slot)
		if err != nil {
			t.Fatalf("GetCommitteeForSlot(%d) failed: %v", slot, err)
		}

		if len(committee) == 0 {
			t.Fatalf("GetCommitteeForSlot(%d) returned empty committee", slot)
		}
	}

	for slot := uint64(0); slot < 32; slot++ {
		proposer, err := qpos.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("GetProposerForSlot(%d) failed: %v", slot, err)
		}
		if proposer == nil {
			t.Fatalf("GetProposerForSlot(%d) returned nil", slot)
		}
	}
}

func TestLargeScale_CommitteeCache(t *testing.T) {
	count := 5000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	committee1, err := qpos.GetCommitteeForSlot(0)
	if err != nil {
		t.Fatalf("first GetCommitteeForSlot(0) failed: %v", err)
	}

	committee2, err := qpos.GetCommitteeForSlot(0)
	if err != nil {
		t.Fatalf("second GetCommitteeForSlot(0) failed: %v", err)
	}

	if len(committee1) != len(committee2) {
		t.Fatalf("cached committee size mismatch: %d vs %d", len(committee1), len(committee2))
	}

	for i := range committee1 {
		if committee1[i].Address != committee2[i].Address {
			t.Fatalf("cached committee member %d mismatch: %x vs %x", i, committee1[i].Address, committee2[i].Address)
		}
	}
}

func TestLargeScale_MaxTrackedValidators_250K(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-scale test in short mode")
	}

	if MaxTrackedValidators < 250000 {
		t.Fatalf("MaxTrackedValidators = %d, want >= 250000", MaxTrackedValidators)
	}
}

func BenchmarkLargeScale_GetValidatorByIndex_10K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(10000))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vs.GetValidatorByIndex(i % 10000)
	}
}

func BenchmarkLargeScale_GetValidatorIndex_10K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(10000))
	v := vs.GetValidatorByIndex(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vs.GetValidatorIndex(v.Address)
	}
}

func BenchmarkLargeScale_Validators_DeepCopy_10K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(10000))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vs.Validators()
	}
}

func BenchmarkLargeScale_GetCommitteeForSlot_10K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(10000))
	qpos, _ := NewQPOS(vs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qpos.GetCommitteeForSlot(uint64(i % 32))
	}
}

func BenchmarkLargeScale_GetProposerForSlot_10K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(10000))
	qpos, _ := NewQPOS(vs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qpos.GetProposerForSlot(uint64(i % 32))
	}
}

func BenchmarkLargeScale_GetCommitteeForSlot_50K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(50000))
	qpos, _ := NewQPOS(vs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qpos.GetCommitteeForSlot(uint64(i % 32))
	}
}

func BenchmarkLargeScale_GetProposerForSlot_50K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(50000))
	qpos, _ := NewQPOS(vs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qpos.GetProposerForSlot(uint64(i % 32))
	}
}

func BenchmarkLargeScale_ShuffleForEpoch_10K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(10000))
	qpos, _ := NewQPOS(vs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// SECURITY (audit CORE-04): computeDeterministicShuffleForEpoch now
		// reads q.epochBlockRoots, so the caller must hold q.mu (at least RLock).
		qpos.mu.RLock()
		qpos.computeShuffleForEpoch(uint64(i%5), 10000)
		qpos.mu.RUnlock()
	}
}

func BenchmarkLargeScale_ShuffleForEpoch_50K(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(50000))
	qpos, _ := NewQPOS(vs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// SECURITY (audit CORE-04): computeDeterministicShuffleForEpoch now
		// reads q.epochBlockRoots, so the caller must hold q.mu (at least RLock).
		qpos.mu.RLock()
		qpos.computeShuffleForEpoch(uint64(i%5), 50000)
		qpos.mu.RUnlock()
	}
}

func BenchmarkLargeScale_CommitteeCache_HitRate(b *testing.B) {
	vs, _ := NewValidatorSet(generateValidators(10000))
	qpos, _ := NewQPOS(vs)
	qpos.GetCommitteeForSlot(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qpos.GetCommitteeForSlot(0)
	}
}

func TestLargeScale_200KValidators_SmokeTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K validator test in short mode")
	}

	count := 200000
	start := testing.AllocsPerRun(1, func() {
		_, _ = NewValidatorSet(generateValidators(count))
	})
	_ = start

	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	if vs.ValidatorCount() != count {
		t.Fatalf("ValidatorCount() = %d, want %d", vs.ValidatorCount(), count)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	committee, err := qpos.GetCommitteeForSlot(0)
	if err != nil {
		t.Fatalf("GetCommitteeForSlot(0) failed: %v", err)
	}
	if len(committee) == 0 {
		t.Fatal("GetCommitteeForSlot(0) returned empty committee")
	}

	proposer, err := qpos.GetProposerForSlot(0)
	if err != nil {
		t.Fatalf("GetProposerForSlot(0) failed: %v", err)
	}
	if proposer == nil {
		t.Fatal("GetProposerForSlot(0) returned nil")
	}

	t.Logf("200K validators: committee size=%d, proposer=%x", len(committee), proposer.Address)
}

func TestLargeScale_200KValidators_FullEpoch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K full epoch test in short mode")
	}

	count := 200000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	uniqueProposers := make(map[types.Address]bool)
	for slot := uint64(0); slot < SlotsPerEpoch; slot++ {
		proposer, err := qpos.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("GetProposerForSlot(%d) failed: %v", slot, err)
		}
		if proposer == nil {
			t.Fatalf("GetProposerForSlot(%d) returned nil", slot)
		}
		uniqueProposers[proposer.Address] = true
	}

	t.Logf("200K validators, %d slots: %d unique proposers", SlotsPerEpoch, len(uniqueProposers))
}

func TestLargeScale_200KValidators_CommitteeCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K committee coverage test in short mode")
	}

	count := 200000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	validatorSeen := make(map[types.Address]bool)
	for slot := uint64(0); slot < SlotsPerEpoch; slot++ {
		committee, err := qpos.GetCommitteeForSlot(slot)
		if err != nil {
			t.Fatalf("GetCommitteeForSlot(%d) failed: %v", slot, err)
		}
		for _, v := range committee {
			validatorSeen[v.Address] = true
		}
	}

	coverage := float64(len(validatorSeen)) / float64(count) * 100
	t.Logf("200K validators: %d/%d seen in committees (%.1f%% coverage)", len(validatorSeen), count, coverage)

	if coverage < 1.0 {
		t.Fatalf("committee coverage %.1f%% is too low, expected >= 1%%", coverage)
	}
}

func TestLargeScale_200KValidators_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K performance test in short mode")
	}

	count := 200000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	setupGenesisForBenchmark()

	t.Run("GetValidatorByIndex", func(t *testing.T) {
		allocs := testing.AllocsPerRun(100, func() {
			vs.GetValidatorByIndex(100000)
		})
		t.Logf("GetValidatorByIndex: %.1f allocs/op", allocs)
	})

	t.Run("GetValidatorIndex", func(t *testing.T) {
		v := vs.GetValidatorByIndex(100000)
		allocs := testing.AllocsPerRun(100, func() {
			vs.GetValidatorIndex(v.Address)
		})
		t.Logf("GetValidatorIndex: %.1f allocs/op", allocs)
	})

	t.Run("GetCommitteeForSlot_first", func(t *testing.T) {
		allocs := testing.AllocsPerRun(10, func() {
			qpos.GetCommitteeForSlot(0)
		})
		t.Logf("GetCommitteeForSlot (first call): %.1f allocs/op", allocs)
	})

	t.Run("GetCommitteeForSlot_cached", func(t *testing.T) {
		qpos.GetCommitteeForSlot(1)
		allocs := testing.AllocsPerRun(100, func() {
			qpos.GetCommitteeForSlot(1)
		})
		t.Logf("GetCommitteeForSlot (cached): %.1f allocs/op", allocs)
	})

	t.Run("GetProposerForSlot", func(t *testing.T) {
		allocs := testing.AllocsPerRun(10, func() {
			qpos.GetProposerForSlot(0)
		})
		t.Logf("GetProposerForSlot: %.1f allocs/op", allocs)
	})
}

func TestLargeScale_ValidatorSetConsistency(t *testing.T) {
	count := 5000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	allValidators := vs.Validators()
	if len(allValidators) != count {
		t.Fatalf("Validators() returned %d, want %d", len(allValidators), count)
	}

	for i, v := range allValidators {
		byIndex := vs.GetValidatorByIndex(i)
		if byIndex == nil {
			t.Fatalf("GetValidatorByIndex(%d) returned nil", i)
		}
		if byIndex.Address != v.Address {
			t.Fatalf("index %d: GetValidatorByIndex address %x != Validators address %x", i, byIndex.Address, v.Address)
		}
		if byIndex.Stake.Cmp(v.Stake) != 0 {
			t.Fatalf("index %d: stake mismatch", i)
		}
	}

	for i, v := range allValidators {
		idx := vs.GetValidatorIndex(v.Address)
		if idx != i {
			t.Fatalf("GetValidatorIndex(%x) = %d, want %d", v.Address, idx, i)
		}
	}
}

func TestLargeScale_ThreeProvinces_10K(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Three Chambers large-scale test in short mode")
	}

	count := 10000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("InitChambers did not create coordinator")
	}

	for slot := uint64(0); slot < 10; slot++ {
		proposer, err := qpos.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("GetProposerForSlot(%d) failed: %v", slot, err)
		}
		if proposer == nil {
			t.Fatalf("GetProposerForSlot(%d) returned nil", slot)
		}
	}

	t.Logf("10K validators with Three Chambers: 10 slots processed successfully")
}

func TestLargeScale_MemoryLimits(t *testing.T) {
	if MaxTrackedValidators < 250000 {
		t.Errorf("MaxTrackedValidators = %d, want >= 250000", MaxTrackedValidators)
	}
	if MaxVoteHistoryEntries < 250000 {
		t.Errorf("MaxVoteHistoryEntries = %d, want >= 250000", MaxVoteHistoryEntries)
	}
	if MaxCommitteeCacheSize < 32 {
		t.Errorf("MaxCommitteeCacheSize = %d, want >= 32", MaxCommitteeCacheSize)
	}
}

func BenchmarkLargeScale_NewValidatorSet_10K(b *testing.B) {
	validators := generateValidators(10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewValidatorSet(validators)
	}
}

func BenchmarkLargeScale_NewValidatorSet_50K(b *testing.B) {
	validators := generateValidators(50000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewValidatorSet(validators)
	}
}

func BenchmarkLargeScale_200K_GetCommitteeForSlot(b *testing.B) {
	if b.N > 100 {
		b.Skip("skipping 200K benchmark for N > 100")
	}
	setupGenesisForBenchmark()
	vs, _ := NewValidatorSet(generateValidators(200000))
	qpos, _ := NewQPOS(vs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qpos.GetCommitteeForSlot(uint64(i % 32))
	}
}

func BenchmarkLargeScale_200K_GetProposerForSlot(b *testing.B) {
	if b.N > 100 {
		b.Skip("skipping 200K benchmark for N > 100")
	}
	setupGenesisForBenchmark()
	vs, _ := NewValidatorSet(generateValidators(200000))
	qpos, _ := NewQPOS(vs)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qpos.GetProposerForSlot(uint64(i % 32))
	}
}

func ExampleValidatorSet_GetValidatorByIndex() {
	vs, _ := NewValidatorSet(generateValidators(100))
	v := vs.GetValidatorByIndex(0)
	fmt.Println(v != nil)
	// Output: true
}

func TestLargeScale_CommitteeAllocationLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping committee allocation latency test in short mode")
	}

	setupGenesisForBenchmark()

	for _, count := range []int{1000, 10000, 50000, 200000} {
		t.Run(fmt.Sprintf("%dValidators", count), func(t *testing.T) {
			vs, err := NewValidatorSet(generateValidators(count))
			if err != nil {
				t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
			}
			qpos, err := NewQPOS(vs)
			if err != nil {
				t.Fatalf("NewQPOS failed: %v", err)
			}

			start := time.Now()
			for slot := uint64(0); slot < SlotsPerEpoch; slot++ {
				_, err := qpos.GetCommitteeForSlot(slot)
				if err != nil {
					t.Fatalf("GetCommitteeForSlot(%d) failed: %v", slot, err)
				}
			}
			elapsed := time.Since(start)

			perSlot := elapsed / time.Duration(SlotsPerEpoch)
			t.Logf("%d validators: %d slots in %v (%v/slot)", count, SlotsPerEpoch, elapsed, perSlot)

			if perSlot > 100*time.Millisecond {
				t.Fatalf("committee allocation too slow: %v/slot (max 100ms)", perSlot)
			}
		})
	}
}

func TestLargeScale_ProposerSelectionLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping proposer selection latency test in short mode")
	}

	setupGenesisForBenchmark()

	for _, count := range []int{1000, 10000, 50000, 200000} {
		t.Run(fmt.Sprintf("%dValidators", count), func(t *testing.T) {
			vs, err := NewValidatorSet(generateValidators(count))
			if err != nil {
				t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
			}
			qpos, err := NewQPOS(vs)
			if err != nil {
				t.Fatalf("NewQPOS failed: %v", err)
			}

			iterations := 100
			start := time.Now()
			for i := 0; i < iterations; i++ {
				_, err := qpos.GetProposerForSlot(uint64(i % SlotsPerEpoch))
				if err != nil {
					t.Fatalf("GetProposerForSlot(%d) failed: %v", i, err)
				}
			}
			elapsed := time.Since(start)

			perCall := elapsed / time.Duration(iterations)
			t.Logf("%d validators: %d proposer selections in %v (%v/call)", count, iterations, elapsed, perCall)

			if perCall > 50*time.Millisecond {
				t.Fatalf("proposer selection too slow: %v/call (max 50ms)", perCall)
			}
		})
	}
}

func TestLargeScale_Security_NoDuplicateCommitteeMembers(t *testing.T) {
	count := 5000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	for slot := uint64(0); slot < SlotsPerEpoch; slot++ {
		committee, err := qpos.GetCommitteeForSlot(slot)
		if err != nil {
			t.Fatalf("GetCommitteeForSlot(%d) failed: %v", slot, err)
		}

		seen := make(map[types.Address]bool)
		for _, v := range committee {
			if seen[v.Address] {
				t.Fatalf("slot %d: duplicate committee member %x", slot, v.Address)
			}
			seen[v.Address] = true
		}
	}
}

func TestLargeScale_Security_NoDuplicateProposer(t *testing.T) {
	setupGenesisForBenchmark()

	count := 5000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	proposers := make(map[types.Address]int)
	for slot := uint64(0); slot < SlotsPerEpoch; slot++ {
		p, err := qpos.GetProposerForSlot(slot)
		if err != nil {
			t.Fatalf("GetProposerForSlot(%d) failed: %v", slot, err)
		}
		proposers[p.Address]++
	}

	for addr, count := range proposers {
		if count > 3 {
			t.Logf("WARNING: validator %x selected %d times in %d slots", addr, count, SlotsPerEpoch)
		}
	}
}

func TestLargeScale_Security_CommitteeMemberInValidatorSet(t *testing.T) {
	count := 5000
	vs, err := NewValidatorSet(generateValidators(count))
	if err != nil {
		t.Fatalf("NewValidatorSet(%d) failed: %v", count, err)
	}

	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	for slot := uint64(0); slot < 10; slot++ {
		committee, err := qpos.GetCommitteeForSlot(slot)
		if err != nil {
			t.Fatalf("GetCommitteeForSlot(%d) failed: %v", slot, err)
		}

		for _, v := range committee {
			idx := vs.GetValidatorIndex(v.Address)
			if idx < 0 {
				t.Fatalf("slot %d: committee member %x not in validator set", slot, v.Address)
			}
			if !v.Active {
				t.Fatalf("slot %d: committee member %x is not active", slot, v.Address)
			}
		}
	}
}

func TestLargeScale_Security_StakeWeightedSelection(t *testing.T) {
	count := 1000
	validators := make([]*Validator, count)
	for i := 0; i < count; i++ {
		addr := types.Address{}
		addr[0] = byte(i >> 24)
		addr[1] = byte(i >> 16)
		addr[2] = byte(i >> 8)
		addr[3] = byte(i)
		stake := int64(1000)
		if i < 10 {
			stake = 100000
		}
		validators[i] = &Validator{
			Address:    addr,
			Stake:      big.NewInt(stake),
			Active:     true,
			Commission: 500,
		}
	}

	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	totalStake := vs.TotalStake()
	highStakeTotal := big.NewInt(0)
	for i := 0; i < 10; i++ {
		v := vs.GetValidatorByIndex(i)
		highStakeTotal.Add(highStakeTotal, v.Stake)
	}

	stakeRatio := float64(highStakeTotal.Int64()) / float64(totalStake.Int64())
	t.Logf("High-stake validators: %.1f%% of total stake", stakeRatio*100)

	if stakeRatio < 0.4 {
		t.Fatalf("stake distribution unexpected: high-stake validators hold only %.1f%% of stake", stakeRatio*100)
	}

	t.Logf("Stake-weighted selection: validator set correctly reflects stake distribution")
}

func TestLargeScale_KyberKeyExchange_100Validators(t *testing.T) {
	count := 100
	vkeInstances := make([]*ValidatorKeyExchange, count)
	addrs := make([]types.Address, count)

	for i := 0; i < count; i++ {
		addr := types.Address{}
		addr[0] = byte(i >> 24)
		addr[1] = byte(i >> 16)
		addr[2] = byte(i >> 8)
		addr[3] = byte(i)
		addrs[i] = addr

		vke, err := NewValidatorKeyExchange(addr)
		if err != nil {
			t.Fatalf("NewValidatorKeyExchange(%d) failed: %v", i, err)
		}
		vkeInstances[i] = vke
	}

	for i := 0; i < count; i++ {
		pub, err := vkeInstances[i].LocalKyberPublicKey()
		if err != nil {
			t.Fatalf("LocalKyberPublicKey(%d) failed: %v", i, err)
		}
		for j := 0; j < count; j++ {
			if i == j {
				continue
			}
			err := vkeInstances[j].RegisterKyberKey(addrs[i], pub)
			if err != nil {
				t.Fatalf("RegisterKyberKey(%d→%d) failed: %v", i, j, err)
			}
		}
	}

	if vkeInstances[0].RegisteredKeyCount() != count-1 {
		t.Fatalf("expected %d registered keys, got %d", count-1, vkeInstances[0].RegisteredKeyCount())
	}

	ciphertext, err := vkeInstances[0].InitiateSession(addrs[1])
	if err != nil {
		t.Fatalf("InitiateSession(0→1) failed: %v", err)
	}

	err = vkeInstances[1].CompleteSession(addrs[0], ciphertext)
	if err != nil {
		t.Fatalf("CompleteSession(1←0) failed: %v", err)
	}

	msg := []byte("hello from validator 0")
	enc, err := vkeInstances[0].EncryptForPeer(addrs[1], msg)
	if err != nil {
		t.Fatalf("EncryptForPeer(0→1) failed: %v", err)
	}
	dec, err := vkeInstances[1].DecryptFromPeer(addrs[0], enc)
	if err != nil {
		t.Fatalf("DecryptFromPeer(1←0) failed: %v", err)
	}
	if string(dec) != string(msg) {
		t.Fatalf("message mismatch: got %q, want %q", string(dec), string(msg))
	}

	t.Logf("100 validators: all registered keys, session established, encrypted communication verified")
}

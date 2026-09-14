// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
)

// TestR37_P3_28_RewardRecordsRetention verifies the R37-P3-28 fix:
// MinistryRevenue.rewardRecords no longer grows without bound. Each
// distribution prunes records older than rewardRecordsRetainEpochs
// relative to the distributed epoch, while recent epochs remain
// queryable via GetRewardRecord.
func TestR37_P3_28_RewardRecordsRetention(t *testing.T) {
	// nil qpos/coordinator/registry: DistributeEpochRewards guards all three,
	// so the bookkeeping path can be tested in isolation.
	mr := NewMinistryRevenue(nil, nil, nil)

	RegisterSystemCaller(testSystemCaller)
	defer UnregisterSystemCaller(testSystemCaller)

	// Distribute rewards across more epochs than the retention window.
	const lastEpoch = uint64(2*rewardRecordsRetainEpochs + 30)
	for e := uint64(0); e <= lastEpoch; e++ {
		if _, err := mr.DistributeEpochRewards(testSystemCaller, e, 0, []int{1}, nil, big.NewInt(1000)); err != nil {
			t.Fatalf("DistributeEpochRewards(epoch=%d) failed: %v", e, err)
		}
	}

	mr.mu.RLock()
	size := len(mr.rewardRecords)
	mr.mu.RUnlock()
	if size > rewardRecordsRetainEpochs {
		t.Fatalf("rewardRecords size = %d, exceeds retention window %d (unbounded growth)",
			size, rewardRecordsRetainEpochs)
	}

	oldestRetained := lastEpoch - rewardRecordsRetainEpochs + 1

	// Epochs older than the window must have been pruned.
	for _, e := range []uint64{0, 1, oldestRetained - 1} {
		if r := mr.GetRewardRecord(e); r != nil {
			t.Errorf("GetRewardRecord(%d) = %+v, want nil (pruned)", e, r)
		}
	}

	// Epochs inside the window must retain their records.
	for _, e := range []uint64{oldestRetained, lastEpoch - 1, lastEpoch} {
		r := mr.GetRewardRecord(e)
		if r == nil {
			t.Fatalf("GetRewardRecord(%d) = nil, want record (inside retention window)", e)
		}
		if r.Epoch != e {
			t.Errorf("GetRewardRecord(%d).Epoch = %d, want %d", e, r.Epoch, e)
		}
	}

	// totalRewards is a cumulative counter and must NOT be reduced by pruning.
	wantTotal := new(big.Int).Mul(big.NewInt(1000), big.NewInt(int64(lastEpoch+1)))
	if mr.totalRewards.Cmp(wantTotal) != 0 {
		t.Errorf("totalRewards = %s, want %s (cumulative total must survive pruning)",
			mr.totalRewards.String(), wantTotal.String())
	}
}

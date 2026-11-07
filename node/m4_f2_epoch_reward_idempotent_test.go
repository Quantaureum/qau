// M4-F2 regression: applying the same epoch-boundary block twice must credit
// the epoch rewards exactly once. Before the idempotency marker a retried /
// replayed boundary block paid the same epoch a second time and produced a
// state root that no other node could reproduce.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// m4f2_epochBoundaryBlock reuses the R60 fixture shape: slot 64 → epoch 2,
// prevEpoch 1, with an embedded census so rewards are non-zero.
func m4f2_epochBoundaryBlock(addr0 types.Address) *encoding.Block {
	header := &encoding.BlockHeader{
		Version:        1,
		Height:         64,
		Slot:           64,
		Epoch:          2,
		Timestamp:      1700000000 + 64*12,
		ChainID:        1333,
		ProposerAddr:   addr0,
		GasLimit:       30000000,
		Attestations:   r60_epoch1Census(),
		StateRoot:      types.Hash{},
		ReceiptRoot:    types.Hash{},
		GasUsed:        0,
		VRFAccumulator: consensus.ComputeNextVRFAccumulator(types.Hash{}, 0, 2, types.Hash{0x01}),
	}
	return &encoding.Block{Header: header, Transactions: nil}
}

func TestM4F2_EpochRewardsCreditedOncePerEpoch(t *testing.T) {
	s, _, _ := r38p1_08_newSyncerWithStore(t)
	s.SetQPOS(r60_buildQPOS(t))

	addr0 := types.Address{0x01}
	addr1 := types.Address{0x02}
	baseline := big.NewInt(1000)
	s.stateDB.SetBalance(addr0, new(big.Int).Set(baseline))
	s.stateDB.SetBalance(addr1, new(big.Int).Set(baseline))

	blk := m4f2_epochBoundaryBlock(addr0)

	// First application (rebuild path: skipStateRootValidation=true).
	if err := s.applyBlockInternal(blk, true); err != nil {
		t.Fatalf("first apply failed: %v", err)
	}
	first0 := new(big.Int).Set(s.stateDB.GetBalance(addr0))
	first1 := new(big.Int).Set(s.stateDB.GetBalance(addr1))
	if first0.Cmp(baseline) == 0 || first1.Cmp(baseline) == 0 {
		t.Fatalf("fixture broken: rewards were not credited on the first apply (addr0=%s addr1=%s baseline=%s)",
			first0, first1, baseline)
	}
	if !s.stateDB.EpochRewardApplied(1) {
		t.Fatal("M4-F2: no epoch-reward marker after the first apply")
	}

	// Replay the SAME boundary block — the M4 retry shape.
	if err := s.applyBlockInternal(blk, true); err != nil {
		t.Fatalf("replay apply failed: %v", err)
	}
	if got := s.stateDB.GetBalance(addr0); got.Cmp(first0) != 0 {
		t.Fatalf("M4-F2 NOT FIXED: epoch rewards were credited twice (addr0 %s → %s)", first0, got)
	}
	if got := s.stateDB.GetBalance(addr1); got.Cmp(first1) != 0 {
		t.Fatalf("M4-F2 NOT FIXED: epoch rewards were credited twice (addr1 %s → %s)", first1, got)
	}
}

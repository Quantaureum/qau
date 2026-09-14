// Quantaureum Node source, version 1.0.0.
// Package node — R60-EPH-REBUILD-FIX regression test (2026-08-09).
//
// Root cause: R58 gated
// applyEpochRewards behind `!skipStateRootValidation`, so during a from-scratch
// rebuild (rebuildRange calls applyBlockInternal(blk, true)) epoch rewards were
// skipped. Rebuild replays ONLY blocks not yet in state (R57 resumes from
// lastCommittedHeight+1), so their rewards are NOT yet credited — skipping them
// left the rebuilt state diverged from the proposer's (which DID apply rewards
// in buildBlock), producing a permanent state-root mismatch → rebuild↔resync
// death loop.
//
// This test asserts the Ethereum-aligned contract: epoch rewards are a
// deterministic part of an epoch-boundary block's state transition and MUST be
// applied on EVERY application path — including rebuild (skipStateRootValidation
// = true). If R58-style gating is reintroduced, the validator balance stays 0
// and this test fails (RED).
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// r60_buildQPOS builds a QPOS with 2 active validators (like
// consensus.buildCensusTestQPOS but local to the node package).
func r60_buildQPOS(t *testing.T) *consensus.QPOS {
	t.Helper()
	stake := new(big.Int).Mul(big.NewInt(6000), big.NewInt(1_000_000_000_000_000_000))
	validators := make([]*consensus.Validator, 2)
	for i := 0; i < 2; i++ {
		validators[i] = &consensus.Validator{
			Address:        types.Address{byte(i + 1)},
			Stake:          new(big.Int).Set(stake),
			Active:         true,
			PublicKeyBytes: []byte{0xAA, 0xBB, byte(i + 1)},
		}
	}
	vs, err := consensus.NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	q, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	return q
}

// r60_epoch1Census builds a deterministic attestation census for epoch 1
// (slots 32..63) plus a committed proposer table, so rewards are non-zero.
func r60_epoch1Census() []byte {
	var atts []*consensus.Attestation
	proposers := map[uint64]int{}
	for vi := 0; vi < 2; vi++ {
		slot := uint64(32 + vi)
		atts = append(atts, &consensus.Attestation{
			Slot:            slot,
			BeaconBlockRoot: types.Hash{byte(vi + 1)},
			Source:          consensus.AttestationCheckpoint{Epoch: 0, Root: types.Hash{0x11}},
			Target:          consensus.AttestationCheckpoint{Epoch: 1, Root: types.Hash{0x22}},
			ValidatorIndex:  vi,
			Signature:       []byte{0xDE, 0xAD, byte(vi + 1)},
			KeyVersion:      1,
		})
		proposers[slot] = vi
	}
	return consensus.SerializeAttestationCensus(atts, proposers)
}

// TestR60RebuildAppliesEpochRewards is the RED regression test for the R58
// from-scratch rebuild bug. It drives applyBlockInternal(blk, true) — the
// rebuild path — with an epoch-boundary block (slot 64, prevEpoch 1) carrying
// an embedded census. The validator's balance MUST increase: skipping rewards
// during rebuild (the R58 behavior) diverges the rebuilt state from the
// proposer's and deadlocks the node.
func TestR60RebuildAppliesEpochRewards(t *testing.T) {
	s, _, _ := r38p1_08_newSyncerWithStore(t)
	q := r60_buildQPOS(t)
	s.SetQPOS(q)

	// Seed the validators with a known baseline balance so we can assert the
	// delta unambiguously.
	addr0 := types.Address{0x01}
	addr1 := types.Address{0x02}
	baseline := big.NewInt(1000)
	s.stateDB.SetBalance(addr0, new(big.Int).Set(baseline))
	s.stateDB.SetBalance(addr1, new(big.Int).Set(baseline))

	// Epoch-boundary block: slot 64 → epoch 2, prevEpoch 1 (rewards are
	// non-zero for epoch≥1). Census embedded in Header.Attestations.
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
	blk := &encoding.Block{Header: header, Transactions: nil}

	// Rebuild path: skipStateRootValidation=true. This is exactly the path
	// that R58 broke — it must still apply epoch rewards.
	if err := s.applyBlockInternal(blk, true); err != nil {
		t.Fatalf("applyBlockInternal(rebuild) returned error: %v", err)
	}

	bal0 := s.stateDB.GetBalance(addr0)
	bal1 := s.stateDB.GetBalance(addr1)
	if bal0.Cmp(baseline) <= 0 {
		t.Fatalf("R60 regression: validator 0 balance did not increase during rebuild (baseline=%s now=%s) — "+
			"epoch rewards were skipped on the rebuild path, which diverges the rebuilt state from the proposer's",
			baseline, bal0)
	}
	if bal1.Cmp(baseline) <= 0 {
		t.Fatalf("R60 regression: validator 1 balance did not increase during rebuild (baseline=%s now=%s)",
			baseline, bal1)
	}
	t.Logf("rebuild applied epoch rewards: addr0 %s → %s, addr1 %s → %s", baseline, bal0, baseline, bal1)
}

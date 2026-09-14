// Quantaureum Node source, version 1.0.0.
// Package node — R88-C regression tests: persisted VRF accumulator
// checkpoints are CALIBRATED against the block store instead of being
// bulk-loaded verbatim on restart.
//
// Pre-R88-C behavior (the bug): node.go loaded the persisted checkpoints and
// called SetAllEpochVRFAccumulators BEFORE the R52 replay. A persisted value
// for an epoch whose blocks no longer exist in the store (previous session
// ended on a fork that R53 truncated / the checkpoint predates a reorg)
// survived as fork-local entropy: acc[epoch] was non-zero but WRONG, the
// R45 cold-start guard saw a "present" accumulator and did not fire, and
// the proposer shuffle for epoch+1/+2 diverged from every peer — the R88
// fork class.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// r88cBlock builds a minimal block header at the given height/epoch carrying
// the given accumulator.
func r88cBlock(height, epoch uint64, acc types.Hash) *encoding.Block {
	return &encoding.Block{
		Header: &encoding.BlockHeader{
			Height:         height,
			Epoch:          epoch,
			Slot:           epoch*consensus.SlotsPerEpoch + height%consensus.SlotsPerEpoch,
			VRFAccumulator: acc,
			ProposerAddr:   types.Address{0xaa},
		},
	}
}

// TestR88C_PersistedCheckpointCalibratedToChain verifies: a persisted
// checkpoint that DISAGREES with the surviving canonical block of its epoch
// is overwritten with the on-chain header value (calibrated), and one that
// agrees is kept.
func TestR88C_PersistedCheckpointCalibratedToChain(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())

	// Fragmented chain: replay covers blocks 1..4 (epoch 10), the store also
	// holds blocks 5..6 (epoch 11) above the (R53-truncated) replay tip.
	accA := types.Hash{0x0A}
	for h := uint64(1); h <= 4; h++ {
		if err := bs.PutBlock(r88cBlock(h, 10, accA)); err != nil {
			t.Fatalf("PutBlock(%d): %v", h, err)
		}
	}
	accChain := types.Hash{0x11}
	if err := bs.PutBlock(r88cBlock(5, 11, types.Hash{0x10})); err != nil {
		t.Fatalf("PutBlock(5): %v", err)
	}
	if err := bs.PutBlock(r88cBlock(6, 11, accChain)); err != nil { // last of epoch 11
		t.Fatalf("PutBlock(6): %v", err)
	}

	qpos, err := consensus.NewQPOS(r88BPValidatorSet(t))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	// Simulate the completed R52 replay: epoch 10 assigned.
	qpos.SetEpochVRFAccumulator(10, accA)

	// Persisted checkpoints: epoch 10 (redundant — replay covered it),
	// epoch 11 with a WRONG fork-local value, epoch 12 with the correct one.
	persisted := map[uint64]types.Hash{
		10: {0xEE}, // redundant
		11: {0xFF}, // WRONG (fork-local)
		12: {0x22}, // matches the last surviving epoch-12 block below
	}
	if err := bs.PutBlock(r88cBlock(7, 12, types.Hash{0x21})); err != nil {
		t.Fatalf("PutBlock(7): %v", err)
	}
	if err := bs.PutBlock(r88cBlock(8, 12, types.Hash{0x22})); err != nil { // last of epoch 12
		t.Fatalf("PutBlock(8): %v", err)
	}

	kept, calibrated, discarded := calibratePersistedVRFAccumulators(qpos, bs, persisted, 10, 4, 8)

	if kept != 1 || calibrated != 1 || discarded != 1 {
		t.Fatalf("expected kept=1 calibrated=1 discarded=1, got kept=%d calibrated=%d discarded=%d", kept, calibrated, discarded)
	}

	// Epoch 11: the WRONG persisted value must be replaced by the chain value.
	if got := qpos.GetEpochVRFAccumulator(11); got != accChain {
		t.Fatalf("acc[11] = %x, want chain value %x (persisted fork value must be calibrated away)", got[:4], accChain[:4])
	}
	// Epoch 12: kept (persisted == chain).
	acc12 := types.Hash{0x22}
	if got := qpos.GetEpochVRFAccumulator(12); got != acc12 {
		t.Fatalf("acc[12] = %x, want %x", got[:4], acc12[:4])
	}
	// Epoch 10: the replay value survives (redundant persisted entry discarded).
	if got := qpos.GetEpochVRFAccumulator(10); got != accA {
		t.Fatalf("acc[10] = %x, want replay value %x", got[:4], accA[:4])
	}
}

// TestR88C_PersistedCheckpointWithoutBlocksDiscarded verifies the
// fail-closed rule: a persisted checkpoint for an epoch with NO surviving
// blocks in the store (the block was on a fork that R53 truncated) is
// DISCARDED — the epoch stays cold so the R45 guard refuses to act on it,
// instead of trusting unverifiable fork-local entropy.
//
// Fails without the R88-C fix: the pre-fix bulk-load (SetAllEpochVRFAccumulators)
// populated acc[epoch] with the fork value, defeating the cold-start guard.
func TestR88C_PersistedCheckpointWithoutBlocksDiscarded(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())

	accA := types.Hash{0x0A}
	if err := bs.PutBlock(r88cBlock(1, 10, accA)); err != nil {
		t.Fatalf("PutBlock(1): %v", err)
	}

	qpos, err := consensus.NewQPOS(r88BPValidatorSet(t))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.SetEpochVRFAccumulator(10, accA) // replay result

	// Epoch 13's blocks were on the truncated fork — nothing survives above
	// the replay tip. The persisted checkpoint still carries the fork value.
	forkAcc := types.Hash{0xDD}
	persisted := map[uint64]types.Hash{13: forkAcc}

	_, _, discarded := calibratePersistedVRFAccumulators(qpos, bs, persisted, 10, 1, 1)
	if discarded != 1 {
		t.Fatalf("expected the orphan epoch-13 checkpoint to be discarded, got discarded=%d", discarded)
	}

	// acc[13] must remain unset: the R45 cold-start guard then refuses to
	// act on the epoch instead of electing from fork entropy.
	if got := qpos.GetEpochVRFAccumulator(13); got != (types.Hash{}) {
		t.Fatalf("acc[13] = %x, want zero (fail-closed discard); the pre-R88-C bulk-load populated fork entropy",
			got[:4])
	}
	// Trigger a proposer lookup for an epoch that needs acc[13] (15 = 13+2):
	// the lookup must fall back to the cold-start path and MARK the epoch, so
	// the producer/validator guard refuses to act on the fallback shuffle.
	if _, err := qpos.GetProposerForSlot(15 * consensus.SlotsPerEpoch); err != nil {
		t.Fatalf("GetProposerForSlot(cold epoch): %v", err)
	}
	if qpos.IsProposerScheduleReadyForEpoch(15) {
		t.Fatal("epoch 15 (needs acc[13]) must be cold-start after discarding the fork checkpoint")
	}
}

// TestR88C_EmptyInputsNoop verifies the calibration is a no-op for nil/empty
// inputs (defensive: startup calls it unconditionally).
func TestR88C_EmptyInputsNoop(t *testing.T) {
	qpos, _ := consensus.NewQPOS(r88BPValidatorSet(t))
	kept, calibrated, discarded := calibratePersistedVRFAccumulators(qpos, nil, nil, 5, 5, 5)
	if kept != 0 || calibrated != 0 || discarded != 0 {
		t.Fatalf("expected all-zero counts for nil inputs, got %d/%d/%d", kept, calibrated, discarded)
	}
}

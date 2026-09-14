// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R101-FINALITY-RESUME regression tests for finality recovery after a restart.
// They verify that restoring derivable epoch roots lets a node resume the
// justification ratchet.

// r101SetupQPOS builds a 6-validator chain and registers the genesis root.
func r101SetupQPOS(t *testing.T, genesisTime int64) *QPOS {
	t.Helper()
	vals := make([]*Validator, 6)
	for i := range vals {
		vals[i] = &Validator{
			Address: types.Address{byte(i + 1)},
			Stake:   new(big.Int).Mul(big.NewInt(6000), big.NewInt(1e18)),
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
	if err := SetGenesisTime(genesisTime); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
	q.SetGenesisRoot(types.Hash{0xaa})
	return q
}

// r101AdvanceEpoch simulates one epoch on a node that IS importing blocks:
// records the epoch boundary root (import-path semantics), feeds full-weight
// attestations for prevEpoch citing the current justified checkpoint, advances
// the head time, and runs the finality check. Returns (justified, finalized).
func r101AdvanceEpoch(t *testing.T, q *QPOS, genesisTime int64, epoch uint64, rootFn func(uint64) types.Hash) (uint64, uint64) {
	t.Helper()
	// Node is online, so it records this epoch's boundary root at import time.
	q.SetEpochBlockRoot(epoch, rootFn(epoch))

	prev := epoch - 1
	q.mu.Lock()
	srcEpoch := q.justifiedEpoch
	srcRoot := q.epochBlockRoots[srcEpoch]
	if srcEpoch == 0 {
		srcRoot = types.Hash{0xaa}
	}
	for s := EpochStartSlot(prev); s < EpochStartSlot(prev)+SlotsPerEpoch; s++ {
		for vi := 0; vi < 6; vi++ {
			q.attestations[s] = append(q.attestations[s], &Attestation{
				Slot:            s,
				BeaconBlockRoot: rootFn(prev),
				Source:          AttestationCheckpoint{Epoch: srcEpoch, Root: srcRoot},
				Target:          AttestationCheckpoint{Epoch: prev, Root: rootFn(prev)},
				ValidatorIndex:  vi,
			})
		}
		q.slotBlockRoots[s] = rootFn(prev)
	}
	q.mu.Unlock()

	// Head time at the end of `epoch` so tryUpdateFinality sees prevEpoch.
	q.SetLastKnownBlockTime(genesisTime + int64((epoch*SlotsPerEpoch+SlotsPerEpoch-1)*12))
	j, f, _ := q.CheckFinality()
	return j, f
}

// TestR101_RestartStuckWithoutRootsRegression pins the recovery behavior.
// After the R105-FINALITY-TARGET-BINDING fix, counting no
// longer requires per-slot canonical roots, so a restarted node is
// SELF-HEALING even without the backfill: epoch 27 itself remains
// unjustifiable (its boundary root was never recorded pre-restart) but
// justification ratchets from epoch 28 onward, one epoch behind, and
// finalization follows. This test pins that recovered behavior and guards
// against regressions that would re-introduce the freeze.
func TestR101_RestartStuckWithoutRoots(t *testing.T) {
	gt := int64(1788110700)
	q := r101SetupQPOS(t, gt)
	rootFn := func(e uint64) types.Hash { return types.Hash{0xb0, byte(e)} }

	j, f := uint64(0), uint64(0)
	// Cold start at epoch 28: the only recorded root beyond genesis.
	for epoch := uint64(28); epoch <= 35; epoch++ {
		j, f = r101AdvanceEpoch(t, q, gt, epoch, rootFn)
		t.Logf("[ctrl] epoch=%d justified=%d finalized=%d", epoch, j, f)
	}
	// Justification must NOT be frozen: it ratchets every epoch post-R105.
	if j != 34 {
		t.Fatalf("post-R105: justification must ratchet (want 34), got %d", j)
	}
	if f != 33 {
		t.Fatalf("post-R105: finalization must follow (want 33), got %d", f)
	}
}

// TestR101_BackfillRevivesFinality: same restart, but the node backfills the
// recent epochs' roots from the canonical store (the R101 fix). With the
// backfilled boundary roots, the already-justified checkpoint at 27 becomes
// immediately verifiable as a vote source AND prevEpoch=27 becomes
// justifiable right at epoch 28 — recovering one epoch earlier than the
// no-backfill path. Then finality ratchets: finalize 28 at epoch 30 etc.
func TestR101_BackfillRevivesFinality(t *testing.T) {
	gt := int64(1788110700)
	q := r101SetupQPOS(t, gt)
	rootFn := func(e uint64) types.Hash { return types.Hash{0xb0, byte(e)} }

	// Cold start at epoch 28; no roots recorded yet.
	j, _ := r101AdvanceEpoch(t, q, gt, 28, rootFn)
	if j != 0 {
		t.Fatalf("precondition: want unjustified (0), got %d", j)
	}

	// The fix: backfill the last completed epochs (as reconstructed from the
	// canonical block store by node.reconstructEpochRoots).
	applied := q.BackfillEpochRoots(map[uint64]types.Hash{
		24: rootFn(24), 25: rootFn(25), 26: rootFn(26), 27: rootFn(27), // justified epoch
	})
	if applied != 4 {
		t.Fatalf("BackfillEpochRoots applied %d entries, want 4", applied)
	}
	// Restore the justified pointer to 27, simulating a node that adopted the
	// network checkpoint after losing only local state.
	q.mu.Lock()
	q.justifiedEpoch = 27
	q.justifiedRoot = q.epochBlockRoots[27]
	q.mu.Unlock()

	// Epoch 29: attestations citing Source=(27, backfilled root) verify, and
	// target 28's boundary root is known → justify 28.
	j, f := r101AdvanceEpoch(t, q, gt, 29, rootFn)
	if j != 28 {
		t.Fatalf("after backfill: expected justified=28, got %d (finalized=%d)", j, f)
	}
	// Two consecutive justifications → finalize the older one.
	j, f = r101AdvanceEpoch(t, q, gt, 30, rootFn)
	if j != 29 || f != 28 {
		t.Fatalf("finality must resume: got justified=%d finalized=%d, want 29/28", j, f)
	}
	// And it keeps ratcheting.
	_, f = r101AdvanceEpoch(t, q, gt, 31, rootFn)
	if f != 29 {
		t.Fatalf("finality must keep advancing: got finalized=%d, want 29", f)
	}
}

// TestR101_BackfillGenesisImmutable: epoch-0 backfill must not overwrite an
// already-registered genesis root (SetGenesisRoot immutable-once contract).
func TestR101_BackfillGenesisImmutable(t *testing.T) {
	gt := int64(1788110700)
	q := r101SetupQPOS(t, gt)
	genesisRoot := types.Hash{0xaa}

	applied := q.BackfillEpochRoots(map[uint64]types.Hash{
		0: {0xff}, // hostile/foreign-chain value must be refused
		7: {0x77}, // normal entry must apply
	})
	if applied != 1 {
		t.Fatalf("applied = %d, want 1 (genesis refused, epoch 7 applied)", applied)
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.epochBlockRoots[0] != genesisRoot {
		t.Fatalf("genesis root overwritten: got %x want %x", q.epochBlockRoots[0], genesisRoot)
	}
	if q.epochBlockRoots[7] != (types.Hash{0x77}) {
		t.Fatalf("epoch 7 root missing after backfill")
	}
}

// TestR101_BackfillIgnoresZeroRoots: a zero root must never clobber state.
func TestR101_BackfillIgnoresZeroRoots(t *testing.T) {
	gt := int64(1788110700)
	q := r101SetupQPOS(t, gt)
	q.SetEpochBlockRoot(9, types.Hash{0x99})

	if applied := q.BackfillEpochRoots(map[uint64]types.Hash{9: {}, 10: {}}); applied != 0 {
		t.Fatalf("zero-root backfill applied %d entries, want 0", applied)
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.epochBlockRoots[9] != (types.Hash{0x99}) {
		t.Fatalf("epoch 9 root clobbered by zero backfill")
	}
	if _, exists := q.epochBlockRoots[10]; exists {
		t.Fatalf("zero root for epoch 10 must not be stored")
	}
}

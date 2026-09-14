// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestR105_JustifyAdvancesWithBoundaryTargets covers the finality-stall class:
// since the R42-P4 fix, every attestation in an epoch votes
// for the SAME boundary target root (not the per-slot block root). But
// tryUpdateFinality compared att.Target.Root against the per-slot canonical
// root, so any slot whose canonical root is recorded (i.e. every produced
// slot) silently discarded its attestations. On a healthy chain this zeroes
// the attested stake → justification freezes.
//
// On live nodes the producer's own attestation for the epoch-boundary slot
// is typically skipped (CreateAttestation runs before the boundary block is
// imported → nil target root), so even the one coincidentally matching slot
// contributes nothing. This test mimics that: boundary-slot votes omitted.
//
// Expected behavior after R105: Target.Root is bound to the canonical epoch
// boundary root (getEpochBlockRootLocked(prevEpoch)); the per-slot canonical
// root, when known, pins att.BeaconBlockRoot instead. Justification then
// advances one epoch per epoch with 6/6 validators voting.
func TestR105_JustifyAdvancesWithBoundaryTargets(t *testing.T) {
	q, keys := setupQPOSWithKeys(6)
	SetAttestationNetworkID(1668)
	idxs := make([]int, 6)
	for i, k := range keys {
		idxs[i] = findValidatorIndex(q, k.Public.Address())
		if idxs[i] < 0 {
			t.Fatalf("validator %d not found", i)
		}
	}

	// Anchor genesis so wall-clock epoch ≈ 10 for ProcessAttestation's
	// slot-window validation.
	genesisTs := time.Now().Unix() - int64(10*SlotsPerEpoch*uint64(SlotDuration.Seconds()))
	if err := SetGenesisTime(genesisTs); err != nil {
		t.Fatal(err)
	}

	chainRoot := func(slot uint64) types.Hash {
		return types.Hash{byte(slot), byte(slot >> 8), byte(slot >> 16), 0xCD}
	}
	// Provide canonical boundary roots for epochs 8..11 (source binding).
	for e := uint64(8); e <= 11; e++ {
		q.SetEpochBlockRoot(e, chainRoot(e*SlotsPerEpoch))
	}

	// cur = target epoch being attested; CheckFinality is evaluated with the
	// head pinned to the following epoch so tryUpdateFinality justifies cur.
	for cur := uint64(9); cur <= 10; cur++ {
		for off := uint64(0); off < SlotsPerEpoch; off++ {
			slot := cur*SlotsPerEpoch + off
			if slot > q.GetCurrentSlot()+1 {
				// wall-clock anchor: skip slots that have not arrived yet.
				continue
			}
			q.SetSlotBlockRoot(slot, chainRoot(slot))
			if off == 0 {
				// Mimic live behavior: nobody successfully creates an
				// attestation at the exact boundary slot (target root not
				// yet imported at attestation time).
				continue
			}
			for vi0 := 0; vi0 < 6; vi0++ {
				att := q.CreateAttestation(slot, chainRoot(slot), idxs[vi0])
				if att == nil {
					t.Fatalf("CreateAttestation returned nil at slot %d", slot)
				}
				if err := q.SignAttestation(att, keys[vi0].Private); err != nil {
					t.Fatal(err)
				}
				if err := q.ProcessAttestation(att); err != nil {
					// Once justification jumps mid-epoch (async QTD/quorum
					// path), remaining votes for this epoch carry
					// Source.Epoch == Target.Epoch and are correctly rejected.
					// Tolerate exactly that case; any other error fails.
					if errors.Is(err, ErrInvalidAttestation) {
						continue
					}
					t.Fatalf("ProcessAttestation slot %d vi0 %d: %v", slot, vi0, err)
				}
			}
		}
		// Pin the block-derived clock to the next epoch so prevEpoch == cur.
		atomic.StoreInt64(&q.lastKnownBlockTime,
			genesisTs+int64((cur+1)*SlotsPerEpoch*uint64(SlotDuration.Seconds()))+1)
		q.CheckFinality()
		t.Logf("after cur=%d: justified=%d finalized=%d", cur, q.GetJustifiedEpoch(), q.GetFinalizedEpoch())
		// Tolerate async-jump races: justification may land at cur or cur+1.
		if j := q.GetJustifiedEpoch(); j < cur {
			t.Fatalf("after epoch %d: justified=%d (< %d) — finality frozen", cur, j, cur)
		}
	}
	if f := q.GetFinalizedEpoch(); f < 9 {
		t.Fatalf("finalized=%d, want >= 9 (two consecutive justified epochs)", f)
	}
}

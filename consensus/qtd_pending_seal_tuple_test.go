// Quantaureum Node source, version 1.0.0.
package consensus

// GetPendingSeal is a read accessor that returns a copy, and the Dilithium3 v1
// seal executor reads the domain-separation tuple from that copy to build the
// message it signs. A copy that silently drops ChainID and Epoch reports zero
// there, and a zero tuple means "legacy pending seal with no canonical message",
// so the executor refuses the seal and the four-signer session never runs. The
// field is written correctly at the RequestSeal site; this test pins that the
// accessor does not lose it on the way out.

import "testing"

// TestGetPendingSealPreservesDomainSeparationTuple requires the pending-seal
// snapshot to carry the chain ID and epoch the signing path signs over. A
// truncated copy here turns every seal into a silent no-op.
func TestGetPendingSealPreservesDomainSeparationTuple(t *testing.T) {
	const (
		chainID = uint64(1333)
		epoch   = uint64(29)
		slot    = uint64(29*SlotsPerEpoch + 7)
	)
	blockHash := [32]byte{0x5a}
	qfs := &QTDFinalityState{
		pendingSeals: map[uint64]*PendingSeal{
			slot: {
				Slot:          slot,
				BlockHash:     blockHash,
				RequiredCount: 4,
				ChainID:       chainID,
				Epoch:         epoch,
			},
		},
	}

	pending := qfs.GetPendingSeal(slot)
	if pending == nil {
		t.Fatalf("GetPendingSeal(%d) = nil, want the stored record", slot)
	}
	if pending.ChainID != chainID {
		t.Fatalf("GetPendingSeal(%d).ChainID = %d, want %d", slot, pending.ChainID, chainID)
	}
	if pending.Epoch != epoch {
		t.Fatalf("GetPendingSeal(%d).Epoch = %d, want %d", slot, pending.Epoch, epoch)
	}
	// The rest of the snapshot must still be intact: the copy is a full copy.
	if pending.Slot != slot {
		t.Fatalf("GetPendingSeal(%d).Slot = %d, want %d", slot, pending.Slot, slot)
	}
	if pending.BlockHash != blockHash {
		t.Fatalf("GetPendingSeal(%d).BlockHash = %x, want %x", slot, pending.BlockHash, blockHash)
	}
	if pending.RequiredCount != 4 {
		t.Fatalf("GetPendingSeal(%d).RequiredCount = %d, want 4", slot, pending.RequiredCount)
	}
}

// TestGetPendingSealAbsentSlotIsNil requires a slot with no pending seal to
// report nil rather than a zero record, so the signing path's "no pending seal"
// branch stays distinct from the "legacy zero tuple" branch.
func TestGetPendingSealAbsentSlotIsNil(t *testing.T) {
	qfs := &QTDFinalityState{pendingSeals: map[uint64]*PendingSeal{}}
	if pending := qfs.GetPendingSeal(1234); pending != nil {
		t.Fatalf("GetPendingSeal(1234) = %+v, want nil for an absent slot", pending)
	}
}

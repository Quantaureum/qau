// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R101-FINALITY-RESUME node-side tests: the backward-walk reconstruction must
// produce values byte-compatible with the live import path, including the
// missed-boundary-slot branch (EnsureEpochBlockRoot → ParentHash of the
// epoch's first block).

// r101BuildChain stores heights [0..139] with a SKIPPED boundary slot at 96
// (epoch-3 boundary). Heights/slots: h<=94 → slot=h; h>=95 → slot=h+2, so
// height 95 carries slot 97 (first block of epoch 3, non-boundary) and the
// head (height 139, slot 141) sits inside epoch 4.
func r101BuildChain(t *testing.T, s *Syncer) map[int]*encoding.BlockHeader {
	t.Helper()
	bs := s.blockStore
	headers := make(map[int]*encoding.BlockHeader)
	var prevHash types.Hash
	for h := 0; h <= 139; h++ {
		slot := uint64(h)
		if h >= 95 {
			slot = uint64(h + 2)
		}
		hdr := &encoding.BlockHeader{
			Height:     uint64(h),
			Slot:       slot,
			Epoch:      slot / consensus.SlotsPerEpoch,
			ParentHash: prevHash,
			Timestamp:  1788110700 + int64(slot)*12,
		}
		blk := &encoding.Block{Header: hdr}
		if err := bs.PutBlockWithIndex(blk); err != nil {
			t.Fatalf("PutBlockWithIndex height=%d: %v", h, err)
		}
		headers[h] = hdr
		prevHash = block.ComputeBlockHash(hdr)
	}
	return headers
}

func r101NewSyncerWithQPOS(t *testing.T) (*Syncer, *consensus.QPOS) {
	t.Helper()
	bs := block.NewBlockStore(db.NewMemDB())
	s := NewSyncer(nil, bs, nil, nil, 1668)
	vals := make([]*consensus.Validator, 6)
	for i := range vals {
		vals[i] = &consensus.Validator{
			Address: types.Address{byte(i + 1)},
			Stake:   new(big.Int).Mul(big.NewInt(6000), big.NewInt(1e18)),
			Active:  true,
		}
	}
	vs, err := consensus.NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	q, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	s.SetQPOS(q)
	return s, q
}

// TestR101_ReconstructMatchesImportSemantics: boundary-slot epochs → own hash;
// epoch with a missed boundary slot → ParentHash of its first block; the
// in-progress epoch must NOT be backfilled.
func TestR101_ReconstructMatchesImportSemantics(t *testing.T) {
	s, _ := r101NewSyncerWithQPOS(t)
	headers := r101BuildChain(t, s)

	head, err := s.blockStore.GetLatestBlock()
	if err != nil || head == nil {
		t.Fatalf("GetLatestBlock: %v", err)
	}
	if head.Header.Epoch != 4 {
		t.Fatalf("precondition: head epoch = %d, want 4", head.Header.Epoch)
	}

	roots := s.reconstructEpochRoots(head)

	if _, ok := roots[4]; ok {
		t.Fatalf("in-progress epoch 4 must not be backfilled")
	}
	if got, want := roots[1], block.ComputeBlockHash(headers[32]); got != want {
		t.Fatalf("epoch 1 (boundary slot 32): got %x… want own-hash %x…", got[:4], want[:4])
	}
	if got, want := roots[2], block.ComputeBlockHash(headers[64]); got != want {
		t.Fatalf("epoch 2 (boundary slot 64): got %x… want own-hash %x…", got[:4], want[:4])
	}
	// Epoch 3 boundary slot 96 was skipped: root = ParentHash of its first
	// block (height 95, slot 97) — i.e. the hash of height 94.
	if got, want := roots[3], block.ComputeBlockHash(headers[94]); got != want {
		t.Fatalf("epoch 3 (missed boundary): got %x… want parent-hash %x…", got[:4], want[:4])
	}
	if got, want := roots[0], block.ComputeBlockHash(headers[0]); got != want {
		t.Fatalf("epoch 0: got %x… want genesis hash %x…", got[:4], want[:4])
	}
}

// TestR101_CheckSyncBackfillsOncePerEpoch drives the public entry point:
// after backfill, qpos must know roots for epochs 0..3 (genesis included
// unless already registered), must skip epoch 4, and a repeated call in the
// same epoch must be a no-op.
func TestR101_CheckSyncBackfillsOncePerEpoch(t *testing.T) {
	s, q := r101NewSyncerWithQPOS(t)
	headers := r101BuildChain(t, s)

	s.maybeBackfillEpochRootsLocked()
	for e := uint64(0); e <= 3; e++ {
		if !q.HasEpochRoot(e) {
			t.Fatalf("epoch %d root missing after backfill", e)
		}
	}
	if q.HasEpochRoot(4) {
		t.Fatalf("in-progress epoch 4 must not be injected")
	}
	if s.r101LastBackfillEpoch != 4 {
		t.Fatalf("throttle marker = %d, want 4", s.r101LastBackfillEpoch)
	}

	// Second pass in the same epoch: throttled (marker unchanged; would need
	// a new head epoch to re-run). Extend the chain into epoch 5 and verify
	// the new pass picks epoch 4 up.
	// epoch 5 starts at slot 160; slot = h+2 so h must reach 158. Extend to 160.
	// Keep the parent chain continuous with the fixture's real tip.
	prevHash := block.ComputeBlockHash(headers[139])
	for h := 140; h <= 160; h++ {
		hdr := &encoding.BlockHeader{
			Height:     uint64(h),
			Slot:       uint64(h + 2),
			Epoch:      uint64(h+2) / consensus.SlotsPerEpoch,
			ParentHash: prevHash,
			Timestamp:  1788110700 + int64(h+2)*12,
		}
		if err := s.blockStore.PutBlockWithIndex(&encoding.Block{Header: hdr}); err != nil {
			t.Fatalf("extend chain height=%d: %v", h, err)
		}
		prevHash = block.ComputeBlockHash(hdr)
	}
	s.maybeBackfillEpochRootsLocked()
	if s.r101LastBackfillEpoch != 5 {
		t.Fatalf("throttle marker after epoch 5 pass = %d, want 5", s.r101LastBackfillEpoch)
	}
	if !q.HasEpochRoot(4) {
		t.Fatalf("epoch 4 root missing after the chain advanced into epoch 5")
	}
}

func TestR101_BackfillOldestEpochCoversStalledCheckpoint(t *testing.T) {
	tests := []struct {
		name                 string
		currentEpoch         uint64
		justifiedEpoch       uint64
		finalizedEpoch       uint64
		checkpointRootsKnown bool
		expectedOldest       uint64
	}{
		{
			name:                 "healthy checkpoint uses small normal window",
			currentEpoch:         100,
			justifiedEpoch:       90,
			finalizedEpoch:       89,
			checkpointRootsKnown: true,
			expectedOldest:       96,
		},
		{
			name:                 "deep stalled checkpoint extends depth",
			currentEpoch:         3589,
			justifiedEpoch:       1465,
			finalizedEpoch:       1464,
			checkpointRootsKnown: false,
			expectedOldest:       1464,
		},
		{
			name:                 "missing justified root extends without finalized checkpoint",
			currentEpoch:         3589,
			justifiedEpoch:       1465,
			finalizedEpoch:       0,
			checkpointRootsKnown: false,
			expectedOldest:       1465,
		},
		{
			name:                 "known deep checkpoint roots keep healthy window",
			currentEpoch:         3589,
			justifiedEpoch:       1465,
			finalizedEpoch:       1464,
			checkpointRootsKnown: true,
			expectedOldest:       3585,
		},
		{
			name:                 "near-head checkpoint keeps healthy window",
			currentEpoch:         4000,
			justifiedEpoch:       3998,
			finalizedEpoch:       3997,
			checkpointRootsKnown: true,
			expectedOldest:       3996,
		},
		{
			name:                 "genesis checkpoints do not expand scan",
			currentEpoch:         4000,
			justifiedEpoch:       0,
			finalizedEpoch:       0,
			checkpointRootsKnown: true,
			expectedOldest:       3996,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r101BackfillOldestEpoch(
				tt.currentEpoch,
				tt.justifiedEpoch,
				tt.finalizedEpoch,
				tt.checkpointRootsKnown,
			); got != tt.expectedOldest {
				t.Fatalf(
					"r101BackfillOldestEpoch(%d, %d, %d, rootsKnown=%t) = %d, want %d",
					tt.currentEpoch,
					tt.justifiedEpoch,
					tt.finalizedEpoch,
					tt.checkpointRootsKnown,
					got,
					tt.expectedOldest,
				)
			}
		})
	}
}

func TestR101_BackfillMaxWalkCoversStalledCheckpoint(t *testing.T) {
	// A checkpoint stalled 2,125 completed epochs behind the head needs a
	// little more than 68,000 blocks. A fixed 65,536-block budget covers only
	// 2,048 every-slot epochs and would stop before the source root.
	const currentEpoch = uint64(5000)
	const oldestEpoch = uint64(2875)
	const expectedWalk = uint64(2126*consensus.SlotsPerEpoch + 1)

	if got := r101BackfillMaxWalkFor(currentEpoch, oldestEpoch); got != expectedWalk {
		t.Fatalf("r101BackfillMaxWalkFor(%d, %d) = %d, want %d",
			currentEpoch, oldestEpoch, got, expectedWalk)
	}
	if got := r101BackfillMaxWalkFor(100, 96); got != r101BackfillMaxWalk {
		t.Fatalf("r101BackfillMaxWalkFor(100, 96) = %d, want baseline %d", got, r101BackfillMaxWalk)
	}
}

func TestR101_BackfillNoQPOS(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	s := NewSyncer(nil, bs, nil, nil, 1668)
	// No SetQPOS. Must not panic.
	s.maybeBackfillEpochRootsLocked()
}

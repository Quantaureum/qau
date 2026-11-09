package node

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
)

// newREG03Syncer builds a syncer whose genesis block is offset by
// genesisOffset seconds relative to now.
func newREG03Syncer(t *testing.T, genesisOffset int64, drift, interval time.Duration) *Syncer {
	t.Helper()
	bs := block.NewBlockStore(db.NewMemDB())
	genesis := &encoding.Block{Header: &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		ChainID:   1668,
		Timestamp: time.Now().Unix() + genesisOffset,
	}}
	if err := bs.PutBlock(genesis); err != nil {
		t.Fatalf("PutBlock genesis: %v", err)
	}
	s := NewSyncer(nil, bs, nil, nil, 1668)
	s.SetStatusHeightBounds(drift, interval)
	return s
}

// REG-03 regression: the plausibility bound must be configurable (drift
// allowance + block-rate floor) instead of a hard-coded 12s / 2-epoch window.
func TestREG03_BoundsAreConfigurable(t *testing.T) {
	s := newREG03Syncer(t, -1200, time.Minute, 12*time.Second)
	got, ok := s.maxCredibleHeight()
	if !ok {
		t.Fatal("expected a credible bound")
	}
	want := uint64((1200+60)/12) + statusHeightSlackBlocks
	if got < want || got > want+1 {
		t.Fatalf("bound=%d want ~%d (drift=1m/interval=12s)", got, want)
	}

	s.SetStatusHeightBounds(5*time.Minute, 12*time.Second)
	got2, ok := s.maxCredibleHeight()
	if !ok {
		t.Fatal("expected a credible bound")
	}
	if got2 <= got {
		t.Fatalf("larger drift allowance must raise the bound: %d vs %d", got2, got)
	}
}

// REG-03 regression: a clock rolled back behind genesis must degrade to the
// drift allowance instead of forcing a hard 2-epoch reject of every peer.
func TestREG03_ClockRollbackStillYieldsPositiveBound(t *testing.T) {
	s := newREG03Syncer(t, 3600, 10*time.Minute, 12*time.Second)
	got, ok := s.maxCredibleHeight()
	if !ok {
		t.Fatal("expected a credible bound")
	}
	want := uint64((10*60)/12) + statusHeightSlackBlocks
	if got != want {
		t.Fatalf("rollback bound=%d want %d", got, want)
	}
	if got <= statusHeightSlackBlocks {
		t.Fatalf("rollback bound %d must exceed the slack-only floor %d", got, statusHeightSlackBlocks)
	}
}

// REG-03 regression: an over-limit claim is dropped for that peer only. It
// must not be stored, must not enable sync on its own, and must not disturb
// other peers or the existing target height.
func TestREG03_OverLimitClaimDoesNotPoisonOtherPeers(t *testing.T) {
	s := newREG03Syncer(t, -1200, time.Minute, 12*time.Second)

	s.HandleStatusMessage(&p2p.StatusMessage{NetworkID: 1668, BestHeight: 1 << 40}, p2p.PeerID("attacker"))
	if s.IsSyncing() {
		t.Fatal("an implausible claim alone must not enable the sync/production gate")
	}
	if !s.peerStatusReceived {
		t.Fatal("a well-formed status must still unblock cold-start sync")
	}
	if _, ok := s.peerHeights[p2p.PeerID("attacker")]; ok {
		t.Fatal("an implausible claim must not be recorded as a peer height")
	}

	s.HandleStatusMessage(&p2p.StatusMessage{NetworkID: 1668, BestHeight: 100}, p2p.PeerID("honest"))
	if !s.IsSyncing() {
		t.Fatal("a credible peer height must still enable sync mode")
	}
	if s.highestKnown != 100 {
		t.Fatalf("highestKnown=%d want 100", s.highestKnown)
	}

	s.HandleStatusMessage(&p2p.StatusMessage{NetworkID: 1668, BestHeight: 1 << 40}, p2p.PeerID("attacker2"))
	if len(s.peerHeights) != 1 {
		t.Fatalf("an over-limit claim must not add a peer height, got %d entries", len(s.peerHeights))
	}
	if s.highestKnown != 100 {
		t.Fatalf("an over-limit claim must not raise highestKnown: got %d want 100", s.highestKnown)
	}
}

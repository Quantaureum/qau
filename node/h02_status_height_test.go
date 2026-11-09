package node

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
)

// H-02 regression: an advertised height that the chain cannot physically have
// reached given the genesis timestamp and block interval must be rejected
// before it reaches the sync state machine. Before the fix a peer could claim
// BestHeight = 10^9 and pin the node in syncing mode forever.
func TestH02_HandleStatusMessageRejectsImplausibleHeight(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	genesis := &encoding.Block{Header: &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		ChainID:   1668,
		Timestamp: time.Now().Unix() - 1200, // ~100 blocks at 12s/block
	}}
	if err := bs.PutBlock(genesis); err != nil {
		t.Fatalf("PutBlock genesis: %v", err)
	}

	s := NewSyncer(nil, bs, nil, nil, 1668)

	s.HandleStatusMessage(&p2p.StatusMessage{
		NetworkID:  1668,
		BestHeight: 1 << 40,
	}, p2p.PeerID("attacker"))
	if s.IsSyncing() {
		t.Fatal("implausible height must not enable the sync/production gate")
	}

	s.HandleStatusMessage(&p2p.StatusMessage{
		NetworkID:  1668,
		BestHeight: 100,
	}, p2p.PeerID("honest"))
	if !s.IsSyncing() {
		t.Fatal("credible height must still enable sync mode")
	}
}

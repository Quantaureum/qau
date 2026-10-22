// Quantaureum Node source, version 1.0.0.
package node

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/state"
)

// R7-01 (2026-10-21 seventh-round audit): the block producer builds on a copy of
// the state database. Copy() shares the durable database, so that copy used to
// write the block-under-construction straight onto the live disk and a discarded
// build left the orphan behind. CopyForBuild buffers those writes and Promote
// replays them at the moment the block is adopted.
//
// The state-layer tests pin CopyForBuild/Promote themselves; this test pins the
// producer wiring, because the fix only protects the chain if the adopting code
// path actually promotes. A producer that adopts an un-promoted copy strands the
// block's durable writes in a buffer nothing will ever replay.

func TestR7_01_ProducedBlockIsPromotedToDurableState(t *testing.T) {
	cfg := &Config{
		Name:      "test-r7-01-produce",
		DataDir:   filepath.Join(t.TempDir(), "qau-r7produce"),
		NetworkID: DevnetNetworkID,
		DevMode:   true,
	}
	cfg.KeyRotation.BackupDir = filepath.Join(cfg.DataDir, "keys", "backup")
	cfg.TLSCertRotation.BackupDir = filepath.Join(cfg.DataDir, "certs", "backup")

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	defer closeNodeDB(n)

	n.initDataDir()
	n.initDatabase()
	n.loadGenesis()
	n.initState()

	if n.stateDB == nil {
		t.Fatal("node has no state database after initState")
	}
	parent := n.CurrentBlock()
	if parent == nil {
		t.Fatal("node has no current block after loadGenesis")
	}
	parentHeight := parent.Header.Height

	bp := NewBlockProducer(n, 3*time.Second)
	bp.produceBlock(parentHeight + 1)

	produced := n.CurrentBlock()
	if produced.Header.Height != parentHeight+1 {
		t.Fatalf("the DevMode producer did not build block %d (still at %d) — this test pins "+
			"the producer's R7-01 wiring, so re-check it if the production path changes",
			parentHeight+1, produced.Header.Height)
	}

	if n.stateDB.ProvisionalForTesting() {
		t.Errorf("the adopted build state is still provisional: the producer replaced node.stateDB "+
			"without Promote(), so block %d's durable writes live only in that copy's buffer",
			produced.Header.Height)
	}
	if keys, size := n.stateDB.BufferedDurableWritesForTesting(); keys != 0 || size != 0 {
		t.Errorf("adopted build state still holds %d buffered durable writes (%d bytes)", keys, size)
	}

	// Restart-equivalent view: a second StateDB over the same shared database can
	// only see the produced block if the promotion replayed the buffer to disk.
	restarted := state.NewStateDB(n.stateDB.DurableDatabaseForTesting())
	if got := restarted.LastCommittedHeight(); got != produced.Header.Height {
		t.Errorf("durable last-committed height after producing block %d = %d — the producer's "+
			"commit never reached the shared database", produced.Header.Height, got)
	}
}

// Quantaureum Node source, version 1.0.0.
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R87-M4-RESTART regression tests.
//
// lastCommittedHeight was in-memory only, so a restart reported zero while
// the persisted state was mid-chain. The baseline clamp then replayed from
// genesis on top of the existing state. Persisting the height makes the
// reported committed height truthful across restarts.
func TestR87LCH_CommitPersistsAcrossReopen(t *testing.T) {
	tmp := t.TempDir()
	addr := types.BytesToAddress([]byte{0x77})

	bdb1, err := db.NewBoltDB(tmp)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	s1 := NewStateDB(bdb1)
	for h := uint64(1); h <= 5; h++ {
		s1.SetBalance(addr, big.NewInt(int64(100+h)))
		if _, err := s1.CommitWithBlock(h); err != nil {
			t.Fatalf("CommitWithBlock(%d): %v", h, err)
		}
	}
	if got := s1.LastCommittedHeight(); got != 5 {
		t.Fatalf("in-memory lch = %d, want 5", got)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen from the same directory: the height must be restored, otherwise
	// rebuildState clamps its baseline to genesis after every restart.
	bdb2, err := db.NewBoltDB(tmp)
	if err != nil {
		t.Fatalf("NewBoltDB (reopen): %v", err)
	}
	s2 := NewStateDB(bdb2)
	defer s2.Close()
	if got := s2.LastCommittedHeight(); got != 5 {
		t.Fatalf("R87-M4-RESTART: after reopen lch = %d, want 5. Without the "+
			"persisted height a restart makes rebuildState replay from genesis "+
			"on top of the existing mid-chain state (nonce rejections and gas "+
			"failures cause permanent state-root mismatches)", got)
	}
}

func TestR87LCH_RollbackPersistsAcrossReopen(t *testing.T) {
	tmp := t.TempDir()
	addr := types.BytesToAddress([]byte{0x78})

	bdb1, err := db.NewBoltDB(tmp)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	s1 := NewStateDB(bdb1)
	for h := uint64(1); h <= 5; h++ {
		s1.SetBalance(addr, big.NewInt(int64(100+h)))
		if _, err := s1.CommitWithBlock(h); err != nil {
			t.Fatalf("CommitWithBlock(%d): %v", h, err)
		}
	}
	// Fork rollback to height 3: state becomes the post-block-2 state.
	if err := s1.RollbackToHeight(3); err != nil {
		t.Fatalf("RollbackToHeight(3): %v", err)
	}
	if got := s1.LastCommittedHeight(); got != 2 {
		t.Fatalf("in-memory lch after rollback = %d, want 2", got)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	bdb2, err := db.NewBoltDB(tmp)
	if err != nil {
		t.Fatalf("NewBoltDB (reopen): %v", err)
	}
	s2 := NewStateDB(bdb2)
	defer s2.Close()
	if got := s2.LastCommittedHeight(); got != 2 {
		t.Fatalf("R87-M4-RESTART: after reopen lch = %d, want 2. A crash after a "+
			"fork rollback but before the next commit would restart with the "+
			"pre-rollback height and rebuildState would skip the rolled-back "+
			"blocks", got)
	}
}

func TestR87LCH_HeightlessCommitDoesNotClobber(t *testing.T) {
	tmp := t.TempDir()
	addr := types.BytesToAddress([]byte{0x79})

	bdb1, err := db.NewBoltDB(tmp)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	s1 := NewStateDB(bdb1)
	s1.SetBalance(addr, big.NewInt(1))
	if _, err := s1.CommitWithBlock(7); err != nil {
		t.Fatalf("CommitWithBlock(7): %v", err)
	}
	// A heightless Commit has transaction-level snapshot semantics and must
	// not overwrite the block-level marker with zero.
	s1.SetBalance(addr, big.NewInt(2))
	if _, err := s1.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	bdb2, err := db.NewBoltDB(tmp)
	if err != nil {
		t.Fatalf("NewBoltDB (reopen): %v", err)
	}
	s2 := NewStateDB(bdb2)
	defer s2.Close()
	if got := s2.LastCommittedHeight(); got != 7 {
		t.Fatalf("after heightless Commit + reopen, lch = %d, want 7 (heightless "+
			"commits must not clobber the block-level height marker)", got)
	}
}

func TestR87LCH_MemDBStaysZeroByDefault(t *testing.T) {
	// Fresh in-memory StateDB (unit tests, tools): no persisted height, lch 0.
	s := NewStateDB()
	defer s.Close()
	if got := s.LastCommittedHeight(); got != 0 {
		t.Fatalf("fresh StateDB lch = %d, want 0", got)
	}
}

package block

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

func TestR107_FinalityPersist_RoundTrip(t *testing.T) {
	dbPath := t.TempDir()
	database, err := db.NewFileDB(dbPath)
	if err != nil {
		t.Fatalf("NewFileDB: %v", err)
	}
	store := NewBlockStore(database)
	justifiedRoot := types.Hash{0x11}
	finalizedRoot := types.Hash{0x22}

	if err := store.PutFinalityState(1465, 1464, justifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("PutFinalityState: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close first database: %v", err)
	}

	restartedDB, err := db.NewFileDB(dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	t.Cleanup(func() { _ = restartedDB.Close() })
	restarted := NewBlockStore(restartedDB)
	gotJustified, gotFinalized, gotJustifiedRoot, gotFinalizedRoot, err := restarted.LoadFinalityState()
	if err != nil {
		t.Fatalf("LoadFinalityState: %v", err)
	}
	if gotJustified != 1465 || gotFinalized != 1464 {
		t.Fatalf("epochs = (%d, %d), want (1465, 1464)", gotJustified, gotFinalized)
	}
	if gotJustifiedRoot != justifiedRoot || gotFinalizedRoot != finalizedRoot {
		t.Fatalf("roots = (%x, %x), want (%x, %x)",
			gotJustifiedRoot[:4], gotFinalizedRoot[:4], justifiedRoot[:4], finalizedRoot[:4])
	}
}

func TestR107_FinalityPersist_NotPresent(t *testing.T) {
	store := NewBlockStore(db.NewMemDB())
	_, _, _, _, err := store.LoadFinalityState()
	if err != nil {
		t.Fatalf("LoadFinalityState on empty store: %v", err)
	}
}

func TestR107_FinalityPersist_RejectsInconsistentEqualCheckpoints(t *testing.T) {
	store := NewBlockStore(db.NewMemDB())
	if err := store.PutFinalityState(5, 5, types.Hash{0x11}, types.Hash{0x22}); !errors.Is(err, ErrInvalidFinalityState) {
		t.Fatalf("equal non-genesis checkpoint error = %v, want %v", err, ErrInvalidFinalityState)
	}
	if err := store.PutFinalityState(0, 0, types.Hash{0x11}, types.Hash{0x22}); !errors.Is(err, ErrInvalidFinalityState) {
		t.Fatalf("equal genesis checkpoint error = %v, want %v", err, ErrInvalidFinalityState)
	}
}

func TestR107_FinalityPersist_AllowsUnfinalizedRootCorrection(t *testing.T) {
	store := NewBlockStore(db.NewMemDB())
	oldJustifiedRoot := types.Hash{0x11}
	newJustifiedRoot := types.Hash{0x33}
	finalizedRoot := types.Hash{0x22}
	if err := store.PutFinalityState(100, 99, oldJustifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("first PutFinalityState: %v", err)
	}
	if err := store.PutFinalityState(100, 99, newJustifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("update unfinalized justified root: %v", err)
	}

	justified, finalized, gotJustifiedRoot, gotFinalizedRoot, err := store.LoadFinalityState()
	if err != nil {
		t.Fatalf("LoadFinalityState: %v", err)
	}
	if justified != 100 || finalized != 99 || gotJustifiedRoot != newJustifiedRoot || gotFinalizedRoot != finalizedRoot {
		t.Fatalf(
			"state after unfinalized root correction = (%d, %d, %x, %x), want (100, 99, %x, %x)",
			justified,
			finalized,
			gotJustifiedRoot[:4],
			gotFinalizedRoot[:4],
			newJustifiedRoot[:4],
			finalizedRoot[:4],
		)
	}
}

func TestR107_FinalityPersist_RejectsFinalizedRootRewrite(t *testing.T) {
	store := NewBlockStore(db.NewMemDB())
	justifiedRoot := types.Hash{0x11}
	finalizedRoot := types.Hash{0x22}
	if err := store.PutFinalityState(100, 99, justifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("first PutFinalityState: %v", err)
	}
	if err := store.PutFinalityState(100, 99, justifiedRoot, types.Hash{0xEE}); !errors.Is(err, ErrFinalityConflict) {
		t.Fatalf("conflicting finalized root error = %v, want %v", err, ErrFinalityConflict)
	}
}

func TestR107_FinalityPersist_ReplacesInvalidRecordWithCanonicalState(t *testing.T) {
	store := NewBlockStore(db.NewMemDB())
	if err := store.GetDB().Put(finalityPrefix, []byte("corrupt")); err != nil {
		t.Fatalf("seed corrupt finality state: %v", err)
	}

	justifiedRoot := types.Hash{0x11}
	finalizedRoot := types.Hash{0x22}
	if err := store.PutFinalityState(100, 99, justifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("replace corrupt finality state: %v", err)
	}
	justified, finalized, gotJustifiedRoot, gotFinalizedRoot, err := store.LoadFinalityState()
	if err != nil {
		t.Fatalf("LoadFinalityState after replacement: %v", err)
	}
	if justified != 100 || finalized != 99 || gotJustifiedRoot != justifiedRoot || gotFinalizedRoot != finalizedRoot {
		t.Fatalf(
			"state after replacement = (%d, %d, %x, %x), want (100, 99, %x, %x)",
			justified,
			finalized,
			gotJustifiedRoot[:4],
			gotFinalizedRoot[:4],
			justifiedRoot[:4],
			finalizedRoot[:4],
		)
	}
}

func TestR107_FinalityPersist_RejectsRollback(t *testing.T) {
	store := NewBlockStore(db.NewMemDB())
	if err := store.PutFinalityState(100, 99, types.Hash{0x01}, types.Hash{0x02}); err != nil {
		t.Fatalf("first PutFinalityState: %v", err)
	}
	if err := store.PutFinalityState(200, 199, types.Hash{0x03}, types.Hash{0x04}); err != nil {
		t.Fatalf("advance PutFinalityState: %v", err)
	}
	if err := store.PutFinalityState(150, 149, types.Hash{0xEE}, types.Hash{0xEE}); err == nil {
		t.Fatal("rollback PutFinalityState succeeded, want rejection")
	}

	justified, finalized, _, _, err := store.LoadFinalityState()
	if err != nil {
		t.Fatalf("LoadFinalityState after rejected rollback: %v", err)
	}
	if justified != 200 || finalized != 199 {
		t.Fatalf("epochs after rejected rollback = (%d, %d), want (200, 199)", justified, finalized)
	}
}

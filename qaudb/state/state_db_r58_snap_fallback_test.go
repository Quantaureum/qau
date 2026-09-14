// Quantaureum Node source, version 1.0.0.
package state

import (
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R58-SNAP-FALLBACK regression tests (2026-08-18): after a snap-sync
// state-root mismatch, the syncer must be able to surgically discard exactly
// the keys the snap session wrote (ClearSnapImport) while preserving
// pre-existing good state from a prior rebuildState — so the full-sync
// fallback re-executes cleanly without reading pivot-era accounts.
//
// Without precise cleanup, keys written by a failed snap import can leak into
// the subsequent full-sync re-execution and prevent state-root verification.

func TestR58_SnapFallback_ClearDeletesOnlyImportedKeys(t *testing.T) {
	memDB := db.NewMemDB()
	sdb := NewStateDB(memDB)

	// Pre-existing good state (e.g. from a prior rebuildState) written
	// outside any snap session — must survive the rollback.
	goodAddr := testAddr(0xAA)
	goodKey := append(accountPrefix, goodAddr[:]...)
	if err := memDB.Put(goodKey, []byte("good")); err != nil {
		t.Fatalf("seed good key: %v", err)
	}

	// Start a snap session and import accounts / storage / code.
	sdb.BeginSnapImport()
	snapAddr := testAddr(0xBB)
	if err := sdb.ImportAccount(snapAddr, []byte("snap-account")); err != nil {
		t.Fatalf("ImportAccount: %v", err)
	}
	storageKey := append(storagePrefix, snapAddr[:]...)
	storageKey = append(storageKey, 0xFF)
	stKey := types.Hash{0x01}
	storageKey = append(storageKey, stKey[:]...)
	if err := sdb.ImportStorage(snapAddr, stKey, types.Hash{0x02}); err != nil {
		t.Fatalf("ImportStorage: %v", err)
	}
	codeHash := types.Hash{0x03}
	codeKey := append(codePrefix, codeHash[:]...)
	if err := sdb.ImportCode(codeHash, []byte("snap-code")); err != nil {
		t.Fatalf("ImportCode: %v", err)
	}

	// Sanity: all keys present before the rollback.
	if _, err := memDB.Get(goodKey); err != nil {
		t.Fatalf("good key missing before rollback: %v", err)
	}
	if _, err := memDB.Get(append(accountPrefix, snapAddr[:]...)); err != nil {
		t.Fatalf("snap account key missing before rollback: %v", err)
	}
	if _, err := memDB.Get(storageKey); err != nil {
		t.Fatalf("snap storage key missing before rollback: %v", err)
	}
	if _, err := memDB.Get(codeKey); err != nil {
		t.Fatalf("snap code key missing before rollback: %v", err)
	}

	// Roll back the failed snap session.
	if err := sdb.ClearSnapImport(); err != nil {
		t.Fatalf("ClearSnapImport: %v", err)
	}

	// Imported keys must be gone.
	if _, err := memDB.Get(append(accountPrefix, snapAddr[:]...)); err == nil {
		t.Fatal("snap account key still present after ClearSnapImport")
	}
	if _, err := memDB.Get(storageKey); err == nil {
		t.Fatal("snap storage key still present after ClearSnapImport")
	}
	if _, err := memDB.Get(codeKey); err == nil {
		t.Fatal("snap code key still present after ClearSnapImport")
	}
	// Pre-existing good state must survive.
	if v, err := memDB.Get(goodKey); err != nil || string(v) != "good" {
		t.Fatalf("good key lost after ClearSnapImport: v=%q err=%v", v, err)
	}

	// A second ClearSnapImport with nothing recorded must be a no-op.
	if err := sdb.ClearSnapImport(); err != nil {
		t.Fatalf("second ClearSnapImport: %v", err)
	}
}

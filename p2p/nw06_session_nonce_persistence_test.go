// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestNW06_SessionNonceTracker_SurvivesRestart is the regression test for
// AUDIT-FULL NW-06 (2026-08-14): the tracker's replay window was memory-only,
// so a restart forgot every recorded (addr, peer, nonce) tuple and a replayed
// status frame inside the freshness window was accepted once more. With a
// persister installed, the tracked set must be snapshotted on every mutation
// and reloaded on (re)start.
func TestNW06_SessionNonceTracker_SurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session_nonces.json")

	tk := NewSessionNonceTracker()
	if err := tk.SetPersister(NewFileSessionNoncePersister(path)); err != nil {
		t.Fatalf("SetPersister on fresh store: %v", err)
	}

	addr := types.Address{0x21}
	peer := PeerID("peer-NW06")
	nonce := [16]byte{0x01, 0x02, 0x03}

	if tk.Seen(addr, peer, nonce) {
		t.Fatal("first sighting flagged as replay")
	}
	if !tk.Seen(addr, peer, nonce) {
		t.Fatal("second sighting of same tuple not flagged as replay")
	}

	// NW-06 core assertion: a NEW tracker over the SAME persisted store
	// (simulated restart) must still remember the tuple.
	tk2 := NewSessionNonceTracker()
	if err := tk2.SetPersister(NewFileSessionNoncePersister(path)); err != nil {
		t.Fatalf("SetPersister on restart: %v", err)
	}
	if !tk2.Seen(addr, peer, nonce) {
		t.Fatal("NW-06 NOT FIXED: persisted nonce forgotten after restart — replay accepted")
	}
	// A distinct tuple remains new even after the restart.
	if tk2.Seen(addr, peer, [16]byte{0xFF}) {
		t.Fatal("distinct nonce wrongly flagged as replay after restart")
	}
}

// TestNW06_SessionNonceTracker_DefaultStaysInMemory verifies the default
// (no persister) keeps the legacy memory-only behavior and creates no files.
func TestNW06_SessionNonceTracker_DefaultStaysInMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session_nonces.json")

	tk := NewSessionNonceTracker()
	addr := types.Address{0x22}
	nonce := [16]byte{0x0A}
	if tk.Seen(addr, "p", nonce) {
		t.Fatal("first sighting flagged as replay")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("default (no persister) must not write any file, stat err=%v", err)
	}
	// Simulated restart WITHOUT persistence: tuple forgotten (documented
	// legacy behavior — the hook is opt-in).
	tk2 := NewSessionNonceTracker()
	if tk2.Seen(addr, "p", nonce) {
		t.Fatal("memory-only tracker remembered tuple across instances")
	}
}

// TestNW06_SessionNonceTracker_TrimPersistsShrunkSnapshot verifies Trim
// persists the shrunk snapshot so pruned entries do not resurrect on
// restart (they must NOT be accepted as fresh after being evicted... they
// are forgotten — which the freshness window already bounds; the key
// property tested here is file/store agreement after Trim).
func TestNW06_SessionNonceTracker_TrimPersistsShrunkSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session_nonces.json")

	tk := NewSessionNonceTracker()
	if err := tk.SetPersister(NewFileSessionNoncePersister(path)); err != nil {
		t.Fatalf("SetPersister: %v", err)
	}
	for i := 0; i < 10; i++ {
		nonce := [16]byte{}
		nonce[0] = byte(i)
		tk.Seen(types.Address{byte(i)}, "p", nonce)
	}
	if got := tk.Len(); got != 10 {
		t.Fatalf("precondition: Len=%d, want 10", got)
	}
	tk.Trim(4)
	if got := tk.Len(); got > 4 {
		t.Fatalf("Trim(4) left %d entries", got)
	}

	// The persisted store must agree with the post-Trim in-memory set:
	// a restart loads exactly Len() entries.
	tk2 := NewSessionNonceTracker()
	if err := tk2.SetPersister(NewFileSessionNoncePersister(path)); err != nil {
		t.Fatalf("SetPersister after trim: %v", err)
	}
	if got := tk2.Len(); got != tk.Len() {
		t.Fatalf("NW-06 NOT FIXED: post-Trim snapshot diverged — in-memory=%d, reloaded=%d", tk.Len(), got)
	}
}

// TestNW06_FilePersister_CorruptEntriesSkipped verifies a store with
// corrupt entries (bad hex / wrong length) loads the valid remainder
// instead of failing the whole file.
func TestNW06_FilePersister_CorruptEntriesSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session_nonces.json")

	p := NewFileSessionNoncePersister(path)
	var good [56]byte
	good[0] = 0xAB
	if err := p.Save([][56]byte{good}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Rewrite the store with one valid + two corrupt entries (bad hex
	// character, wrong length).
	var short [8]byte
	store := `["` + hex.EncodeToString(good[:]) + `","zz","` + hex.EncodeToString(short[:]) + `"]`
	if err := os.WriteFile(path, []byte(store), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := p.Load()
	if err != nil {
		t.Fatalf("Load with corrupt entries must not fail: %v", err)
	}
	if len(keys) != 1 || keys[0] != good {
		t.Fatalf("corrupt entries not skipped: got %d keys, want 1 valid", len(keys))
	}
}

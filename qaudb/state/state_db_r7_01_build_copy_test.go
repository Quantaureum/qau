// Quantaureum Node source, version 1.0.0.
package state

import (
	"encoding/binary"
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R7-01 (2026-10-21 seventh-round audit): block_producer.go builds a block on
// StateDB.Copy() and calls CommitWithBlock on that copy, but Copy() shared the
// durable database with the live instance. When the chain tip moved while the
// block was being built, tryProduceBlock logged "discarding" and returned —
// after the discarded block's accounts, storage, contract code, commit-pending
// marker and last-committed height/root had already been written to the disk
// the live StateDB reads through to on every cache miss, and that RecoverConsistency
// rebuilds the state trie from at startup. The before-images needed to undo it
// were on the copy that got thrown away.
//
// CopyForBuild() buffers a build copy's durable writes and Promote() replays
// them when the block is adopted. These tests pin both halves: a discarded
// build leaves nothing behind, and an adopted one produces byte-identical
// durable state to committing on the main instance.

func persistedCommittedHeight(t *testing.T, raw db.Database) uint64 {
	t.Helper()
	data, err := raw.Get(lastCommittedHeightKey)
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return 0
		}
		t.Fatalf("read %q: %v", lastCommittedHeightKey, err)
	}
	if len(data) != 8 {
		t.Fatalf("%q length = %d, want 8", lastCommittedHeightKey, len(data))
	}
	return binary.BigEndian.Uint64(data)
}

func diskAccount(t *testing.T, raw db.Database, addr types.Address) (*Account, error) {
	t.Helper()
	data, err := raw.Get(append(accountPrefix, addr[:]...))
	if err != nil {
		return nil, err
	}
	var acc Account
	if err := decodeAccount(data, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}

func TestR7_01_DiscardedBuildCopyLeavesNoDurableTrace(t *testing.T) {
	raw := db.NewMemDB()
	live := NewStateDB(raw)

	alice := types.Address{0xa1}
	bob := types.Address{0xb0}
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}
	baselineHeight := persistedCommittedHeight(t, raw)
	if baselineHeight != 1 {
		t.Fatalf("baseline persisted height = %d, want 1", baselineHeight)
	}
	vnodesBefore := countDiskKeys(raw, []byte("vnode:"))

	// The producer builds block 2 on an isolated copy and commits it there.
	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	if !build.ProvisionalForTesting() {
		t.Fatal("CopyForBuild copy is not provisional — its commits would reach live disk state")
	}
	if live.ProvisionalForTesting() {
		t.Fatal("CopyForBuild must not make the source instance provisional")
	}

	build.SetBalance(bob, big.NewInt(777))
	if _, err := build.CommitWithBlock(2); err != nil {
		t.Fatalf("build copy CommitWithBlock(2): %v", err)
	}

	keys, size := build.BufferedDurableWritesForTesting()
	if keys == 0 || size == 0 {
		t.Fatalf("build copy buffered nothing (keys=%d bytes=%d) — its commit wrote through to the shared database", keys, size)
	}

	// The Verkle tree's persistent database is part of the same durable layer:
	// node writes have to be buffered too, or a discarded build still leaves its
	// tree nodes on the disk the live tree resolves missing nodes from.
	if build.stateTrie == nil || live.stateTrie == nil {
		t.Fatal("test fixture must build both instances with a state trie")
	}
	if build.stateTrie.PersistentDB() == live.stateTrie.PersistentDB() {
		t.Error("build copy's Verkle tree still flushes node writes into the live database")
	}
	if got := countDiskKeys(raw, []byte("vnode:")); got != vnodesBefore {
		t.Errorf("discarded build wrote %d Verkle nodes to the shared disk (was %d)", got, vnodesBefore)
	}

	// Discarded: tryProduceBlock found the tip had moved. Nothing of block 2
	// may be durable, and the live instance must keep serving block 1.
	if _, err := diskAccount(t, raw, bob); !errors.Is(err, db.ErrKeyNotFound) {
		t.Errorf("discarded build persisted bob to disk (err=%v), want the account to stay absent", err)
	}
	if got := persistedCommittedHeight(t, raw); got != 1 {
		t.Errorf("discarded build advanced the durable last-committed height to %d, want 1", got)
	}
	live.ClearCacheForTesting()
	if bal := live.GetBalance(bob); bal.Sign() != 0 {
		t.Errorf("live state reads the discarded build's balance for bob (%s), want 0", bal)
	}

	// Adopting instead promotes the same buffered writes.
	if err := build.Promote(); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if build.ProvisionalForTesting() {
		t.Error("copy is still provisional after Promote — later commits would buffer forever")
	}
	acc, err := diskAccount(t, raw, bob)
	if err != nil {
		t.Fatalf("after Promote bob is still missing from disk: %v", err)
	}
	if acc.Balance.Cmp(big.NewInt(777)) != 0 {
		t.Errorf("after Promote disk balance = %s, want 777", acc.Balance)
	}
	if got := persistedCommittedHeight(t, raw); got != 2 {
		t.Errorf("after Promote durable last-committed height = %d, want 2", got)
	}
	if build.stateTrie.PersistentDB() != live.stateTrie.PersistentDB() {
		t.Error("Promote did not return the build copy's Verkle tree to the shared database — its later commits would buffer forever")
	}
	if got := countDiskKeys(raw, []byte("vnode:")); got <= vnodesBefore {
		t.Errorf("after Promote the shared disk still holds %d Verkle nodes (baseline %d) — the buffered tree writes never landed", got, vnodesBefore)
	}
	live.ClearCacheForTesting()
	if bal := live.GetBalance(bob); bal.Cmp(big.NewInt(777)) != 0 {
		t.Errorf("live state reads bob = %s after adoption, want 777", bal)
	}
}

// TestR7_01_PromotedBuildCopyMatchesMainCommitRoot is the divergence guard for
// the fix itself. The proposer/validator topology of
// node/r87_stateroot_copy_test.go, run through CopyForBuild + Promote: the
// header root must be what a validator recomputes on its main stateDB, and the
// promoted disk must reconstruct that same root after a restart.
func TestR7_01_PromotedBuildCopyMatchesMainCommitRoot(t *testing.T) {
	alice := types.Address{0xa1}
	bob := types.Address{0xb0}
	slot := types.Hash{0x01}
	value := types.Hash{0x2a}

	proposerRaw := db.NewMemDB()
	proposer := NewStateDB(proposerRaw)
	validator := NewStateDB(db.NewMemDB())
	for _, sdb := range []*StateDB{proposer, validator} {
		sdb.SetBalance(alice, big.NewInt(1_000_000))
		if _, err := sdb.CommitWithBlock(1); err != nil {
			t.Fatalf("baseline CommitWithBlock(1): %v", err)
		}
	}

	// Proposer: build block 2 on an isolated copy, commit, adopt.
	build := proposer.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	applyR7BuildBlock(t, build, alice, bob, slot, value)
	producerRoot, err := build.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("proposer CommitWithBlock(2): %v", err)
	}
	if err := build.Promote(); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	// Validator: the same block on its main stateDB.
	applyR7BuildBlock(t, validator, alice, bob, slot, value)
	validatorRoot, err := validator.CommitWithBlock(2)
	if err != nil {
		t.Fatalf("validator CommitWithBlock(2): %v", err)
	}

	if producerRoot != validatorRoot {
		t.Fatalf("R7-01 isolation changed the state root: proposer=%x validator=%x", producerRoot, validatorRoot)
	}
	if build.Root() != validatorRoot {
		t.Errorf("promoted build copy root = %x, want %x", build.Root(), validatorRoot)
	}

	// The durable result must be byte-equivalent to what a main-path commit
	// leaves: a fresh instance over the same disk recovers the same root, the
	// same balance and the same storage slot.
	restarted := NewStateDB(proposerRaw)
	if got := restarted.Root(); got != validatorRoot {
		t.Errorf("root recovered from the promoted disk = %x, want %x", got, validatorRoot)
	}
	if got := restarted.GetBalance(bob); got.Cmp(big.NewInt(4_000)) != 0 {
		t.Errorf("recovered bob balance = %s, want 4000", got)
	}
	restarted.ClearCacheForTesting()
	if got := restarted.GetState(alice, slot); got != value {
		t.Errorf("recovered storage = %x, want %x", got, value)
	}
}

func applyR7BuildBlock(t *testing.T, sdb *StateDB, alice, bob types.Address, slot, value types.Hash) {
	t.Helper()
	sdb.SetBalance(bob, big.NewInt(4_000))
	if err := sdb.SubBalance(alice, big.NewInt(4_000)); err != nil {
		t.Fatalf("SubBalance(alice): %v", err)
	}
	sdb.SetStorage(alice, slot, value)
}

// TestR7_01_BuildCopySeesItsOwnCommittedStorage pins the read-your-writes the
// build depends on. Commit clears dirtyStorage, so the second commit rebuilds
// the account's storage root by iterating the storage prefix: if the buffered
// first commit were invisible to that iteration, the root would silently drop
// the slot and the header would carry a root no validator reproduces.
func TestR7_01_BuildCopySeesItsOwnCommittedStorage(t *testing.T) {
	raw := db.NewMemDB()
	live := NewStateDB(raw)
	alice := types.Address{0xa1}
	first := types.Hash{0x11}
	second := types.Hash{0x22}

	live.SetBalance(alice, big.NewInt(1))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	build := live.CopyForBuild()
	build.SetStorage(alice, first, types.Hash{0xAA})
	if _, err := build.CommitWithBlock(2); err != nil {
		t.Fatalf("build CommitWithBlock(2): %v", err)
	}

	// The slot the copy already committed is readable, and it is not on disk.
	build.ClearCacheForTesting()
	if got := build.GetState(alice, first); got != (types.Hash{0xAA}) {
		t.Fatalf("build copy lost its own committed storage: got %x", got)
	}
	if _, err := raw.Get(storageKeyOf(alice, first)); !errors.Is(err, db.ErrKeyNotFound) {
		t.Errorf("buffered storage reached the shared disk before Promote (err=%v)", err)
	}

	// A second commit must still see the first one's slot when it recomputes
	// the storage root.
	build.SetStorage(alice, second, types.Hash{0xBB})
	stagedRoot, err := build.CommitWithBlock(3)
	if err != nil {
		t.Fatalf("build CommitWithBlock(3): %v", err)
	}

	// Same sequence on a plain main-path instance.
	reference := NewStateDB(db.NewMemDB())
	reference.SetBalance(alice, big.NewInt(1))
	if _, err := reference.CommitWithBlock(1); err != nil {
		t.Fatalf("reference CommitWithBlock(1): %v", err)
	}
	reference.SetStorage(alice, first, types.Hash{0xAA})
	if _, err := reference.CommitWithBlock(2); err != nil {
		t.Fatalf("reference CommitWithBlock(2): %v", err)
	}
	reference.SetStorage(alice, second, types.Hash{0xBB})
	referenceRoot, err := reference.CommitWithBlock(3)
	if err != nil {
		t.Fatalf("reference CommitWithBlock(3): %v", err)
	}

	if stagedRoot != referenceRoot {
		t.Errorf("isolated build root = %x, main-path root = %x — the buffered write set is not readable as durable state",
			stagedRoot, referenceRoot)
	}

	if err := build.Promote(); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	restarted := NewStateDB(raw)
	if got := restarted.Root(); got != referenceRoot {
		t.Errorf("promoted disk root = %x, want %x", got, referenceRoot)
	}
	restarted.ClearCacheForTesting()
	if got := restarted.GetState(alice, first); got != (types.Hash{0xAA}) {
		t.Errorf("after promotion the first slot is missing from disk: got %x", got)
	}
}

func storageKeyOf(addr types.Address, key types.Hash) []byte {
	storageKey := append([]byte{}, storagePrefix...)
	storageKey = append(storageKey, addr[:]...)
	storageKey = append(storageKey, 0xFF)
	storageKey = append(storageKey, key[:]...)
	return storageKey
}

// countDiskKeys counts entries under prefix. "vnode:" mirrors trie.vnodePrefix,
// the key prefix the Verkle tree gives its node writes; it is spelled out here
// because the assertion is about the SHARED database, not about the tree.
func countDiskKeys(raw db.Database, prefix []byte) int {
	iter := raw.NewIterator(prefix, nil)
	defer iter.Release()
	n := 0
	for iter.Next() {
		n++
	}
	return n
}

// TestR7_01_CopyOfBuildCopySharesItsBuffer covers the nested case: a copy taken
// from a provisional instance must keep buffering into the same write set, or
// the outer build's staged block would be stranded.
func TestR7_01_CopyOfBuildCopySharesItsBuffer(t *testing.T) {
	raw := db.NewMemDB()
	live := NewStateDB(raw)
	alice := types.Address{0xa1}
	live.SetBalance(alice, big.NewInt(5))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	outer := live.CopyForBuild()
	inner := outer.CopyForBuild()
	if !inner.ProvisionalForTesting() {
		t.Fatal("nested build copy lost its provisional flag")
	}

	nested := types.Address{0xc1}
	inner.SetBalance(nested, big.NewInt(9))
	if _, err := inner.CommitWithBlock(2); err != nil {
		t.Fatalf("nested CommitWithBlock(2): %v", err)
	}

	outer.ClearCacheForTesting()
	if got := outer.GetBalance(nested); got.Cmp(big.NewInt(9)) != 0 {
		t.Errorf("outer copy does not see the nested commit (got %s, want 9) — the buffers diverged", got)
	}
	if _, err := diskAccount(t, raw, nested); !errors.Is(err, db.ErrKeyNotFound) {
		t.Errorf("nested buffered write reached the shared disk (err=%v)", err)
	}

	// Promoting the outer copy must carry the nested write with it, because it
	// is part of the same buffered set.
	if err := outer.Promote(); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if _, err := diskAccount(t, raw, nested); err != nil {
		t.Errorf("after Promote the nested account is missing from disk: %v", err)
	}
}

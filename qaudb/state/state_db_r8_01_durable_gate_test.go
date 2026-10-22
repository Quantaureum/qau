// Quantaureum Node source, version 1.0.0.
package state

import (
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R8-01 (2026-10-21 eighth-round audit): StateDB.Copy() shares the durable
// database (R7-01 established that) and every StateDB guarded its own s.mu, so
// two instances writing that database had no common lock at all. R7-01's
// buffer made the block producer a deferred writer instead of an immediate one,
// but Promote still replayed whenever the producer decided to adopt — while
// node.handleIncomingBlock calls syncer.ProcessBlock WITHOUT holding n.mu and
// switches the head only afterwards, so an import could commit block N between
// the producer's tip check and its promote. The producer's replay would then
// land block N-1-shaped accounts, a stale Verkle root and a stale height anchor
// on top of the state the sync path just made durable: a database belonging to
// neither chain, which RecoverConsistency cannot detect because the corruption
// is self-consistent as far as the anchor is concerned.
//
// The fix has two halves, both pinned here:
//   - one writer gate per database, inherited by every copy, taken by Commit,
//     PruneState, RollbackToHeight, Promote and the snap-import writers (R8-03),
//     so a durable write is a composite that nobody else can interleave;
//   - a staleness fence: a build copy remembers the durable anchor of the
//     database it branched from and Promote refuses, before writing anything,
//     if that anchor has moved.

// r801GateSpy wraps a database and records any durable write that arrives while
// the writer gate is free — which is exactly the interleaving R8-01 removes. It
// is the only kind of assertion that proves the gate is taken: a mutex cannot be
// observed from a completion test, but a write can be observed at the moment it
// happens.
type r801GateSpy struct {
	db.Database
	mu        sync.Mutex
	gate      *sync.Mutex
	observed  int
	violation string
}

func (s *r801GateSpy) attach(gate *sync.Mutex) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gate = gate
}

func (s *r801GateSpy) note(op string, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observed++
	if s.gate == nil {
		return
	}
	// TryLock fails whenever the mutex is held, including by this goroutine, so
	// success means this write reached the disk outside any writer's critical
	// section.
	if s.gate.TryLock() {
		s.gate.Unlock()
		if s.violation == "" {
			s.violation = op + " " + string(key)
		}
	}
}

func (s *r801GateSpy) Put(key, value []byte) error {
	s.note("Put", key)
	return s.Database.Put(key, value)
}

func (s *r801GateSpy) Delete(key []byte) error {
	s.note("Delete", key)
	return s.Database.Delete(key)
}

func (s *r801GateSpy) NewBatch() db.Batch { return &r801BatchSpy{database: s} }

func (s *r801GateSpy) stats() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.observed, s.violation
}

type r801BatchSpy struct {
	database *r801GateSpy
	batch    db.Batch
	keys     []string
}

func (b *r801BatchSpy) inner() db.Batch {
	if b.batch == nil {
		b.batch = b.database.Database.NewBatch()
	}
	return b.batch
}

func (b *r801BatchSpy) Put(key, value []byte) error {
	b.keys = append(b.keys, string(key))
	return b.inner().Put(key, value)
}

func (b *r801BatchSpy) Delete(key []byte) error {
	b.keys = append(b.keys, string(key))
	return b.inner().Delete(key)
}

// recordAndRun notes the keys the batch is about to make durable, so the gate
// is observed at the instant the compound write happens rather than after it.
func (b *r801BatchSpy) recordAndRun(action string, fn func() error) error {
	if len(b.keys) == 0 {
		return fn()
	}
	b.database.note(action, []byte(strings.Join(b.keys, ",")))
	return fn()
}

func (b *r801BatchSpy) Write() error {
	err := b.recordAndRun("batch.Write", b.inner().Write)
	b.keys = nil
	return err
}

func (b *r801BatchSpy) Flush() error {
	err := b.recordAndRun("batch.Flush", b.inner().Flush)
	b.keys = nil
	return err
}
func (b *r801BatchSpy) ValueSize() int { return b.inner().ValueSize() }

func (b *r801BatchSpy) Reset() {
	b.keys = nil
	if b.batch != nil {
		b.batch.Reset()
	}
}

// r801AssertBlocksBehindGate runs fn and requires it to make no progress while
// the gate is held elsewhere, then to finish once the gate is released.
func r801AssertBlocksBehindGate(t *testing.T, name string, gate *sync.Mutex, fn func() error) {
	t.Helper()

	gate.Lock()
	done := make(chan error, 1)
	go func() { done <- fn() }()

	select {
	case err := <-done:
		gate.Unlock()
		t.Fatalf("%s completed while another writer held the durable-writer gate (err=%v) — durable writes are not serialized", name, err)
	case <-time.After(200 * time.Millisecond):
	}

	gate.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s failed once the gate was released: %v", name, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("%s never resumed after the gate was released — it is not waiting on the gate it inherits", name)
	}
}

func TestR8_01_EveryInstanceOnOneDatabaseSharesOneWriterGate(t *testing.T) {
	raw := db.NewMemDB()
	live := NewStateDB(raw)

	gate := live.DurableWriterGateForTesting()
	if gate == nil {
		t.Fatal("a StateDB over a database has no durable-writer gate, so nothing serializes its writes with anybody else's")
	}

	nestedBuild := live.CopyForBuild()
	if nestedBuild == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	inner := nestedBuild.CopyForBuild()

	cases := []struct {
		name string
		sdb  *StateDB
	}{
		{"Copy()", live.Copy()},
		{"CopyForBuild()", live.CopyForBuild()},
		{"CopyForBuild of a build copy", inner},
	}
	for _, c := range cases {
		if c.sdb == nil {
			t.Fatalf("%s returned nil", c.name)
		}
		if c.sdb.DurableWriterGateForTesting() != gate {
			t.Errorf("%s got a different writer gate — the copy would write to the shared database concurrently with the instance it came from", c.name)
		}
	}

	// A nested build copy fences against the OUTER anchor: its writes join the
	// outer buffer and promoting it replays that shared buffer onto the real
	// base, so its staleness is the outer copy's staleness.
	if inner.buildAnchor != nestedBuild.buildAnchor {
		t.Errorf("nested build copy fenced against %+v, outer copy fenced against %+v — the two would disagree about when the base moved",
			inner.buildAnchor, nestedBuild.buildAnchor)
	}
	if want := readDurableAnchor(raw); nestedBuild.buildAnchor != want {
		t.Errorf("build copy captured anchor %+v, but the database reports %+v", nestedBuild.buildAnchor, want)
	}
}

func TestR8_01_PromoteIsRefusedOnceAnotherWriterMovesTheDurableHeight(t *testing.T) {
	raw := db.NewMemDB()
	live := NewStateDB(raw)

	alice := types.Address{0xa1}
	bob := types.Address{0xb0}
	carol := types.Address{0xc3}

	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	build.SetBalance(bob, big.NewInt(777))
	if _, err := build.CommitWithBlock(2); err != nil {
		t.Fatalf("build copy CommitWithBlock(2): %v", err)
	}

	// The import path: node.handleIncomingBlock reaches ProcessBlock without
	// n.mu and commits block 2 on the live instance while this locally built
	// block 2 is still waiting to be promoted.
	live.SetBalance(carol, big.NewInt(500))
	if _, err := live.CommitWithBlock(2); err != nil {
		t.Fatalf("import CommitWithBlock(2): %v", err)
	}
	vnodesImported := countDiskKeys(raw, []byte("vnode:"))
	anchorAfterImport := readDurableAnchor(raw)

	err := build.Promote()
	if !errors.Is(err, ErrStaleBuildState) {
		t.Fatalf("Promote of a stale build copy = %v, want ErrStaleBuildState — the buffered block would be replayed onto imported state", err)
	}
	if !strings.Contains(err.Error(), "durable height moved from 1 to 2") {
		t.Errorf("staleness error = %q, want it to name the height drift it detected", err)
	}

	// Refused means untouched: the fence runs before the Verkle flush, before the
	// commit-pending marker and before the replay.
	if _, err := diskAccount(t, raw, bob); !errors.Is(err, db.ErrKeyNotFound) {
		t.Errorf("the refused promote wrote the stale build's account to the shared disk (err=%v)", err)
	}
	if _, err := raw.Get(commitPendingKey); !errors.Is(err, db.ErrKeyNotFound) {
		t.Errorf("the refused promote staged the commit-pending marker (err=%v) — a crash after that would make the next startup rebuild from a state nobody committed", err)
	}
	if got := countDiskKeys(raw, []byte("vnode:")); got != vnodesImported {
		t.Errorf("the refused promote flushed %d Verkle node(s) onto the imported database (was %d)", got, vnodesImported)
	}
	if got := readDurableAnchor(raw); got != anchorAfterImport {
		t.Errorf("the refused promote moved the durable anchor from %+v to %+v", anchorAfterImport, got)
	}
	if got := persistedCommittedHeight(t, raw); got != 2 {
		t.Errorf("durable height = %d after the refused promote, want the imported 2", got)
	}

	// The copy is still inspectable and retryable: a refused fence is not a
	// partially applied replay.
	if !build.ProvisionalForTesting() {
		t.Error("the copy lost its provisional flag even though the promote was refused — later commits would now write straight to live state")
	}
	if keys, _ := build.BufferedDurableWritesForTesting(); keys == 0 {
		t.Error("the refused promote dropped the buffered writes; the stale block's effect is now unrecoverable and unauditable")
	}

	live.ClearCacheForTesting()
	if bal := live.GetBalance(bob); bal.Sign() != 0 {
		t.Errorf("the live instance reads the discarded build's bob balance %s, want 0", bal)
	}
	if bal := live.GetBalance(carol); bal.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("the imported block's carol balance = %s after the refused promote, want 500", bal)
	}
}

func TestR8_01_PromoteIsRefusedWhenOnlyTheDurableRootMoved(t *testing.T) {
	// The height leg cannot catch every writer: a commit that carries no block
	// height (genesis, boot replay, shutdown flush) rewrites the root anchor and
	// leaves the height alone. The fence compares the whole anchor, so this too
	// is refused rather than replayed on top of.
	raw := db.NewMemDB()
	live := NewStateDB(raw)

	alice := types.Address{0xa1}
	dave := types.Address{0xd4}

	live.SetBalance(alice, big.NewInt(1000))
	rootBaseline, err := live.CommitWithBlock(1)
	if err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	if _, err := build.CommitWithBlock(2); err != nil {
		t.Fatalf("build copy CommitWithBlock(2): %v", err)
	}

	side := NewStateDB(raw)
	side.SetBalance(dave, big.NewInt(7))
	rootMoved, err := side.Commit()
	if err != nil {
		t.Fatalf("second writer's heightless Commit: %v", err)
	}
	if rootMoved == rootBaseline {
		t.Fatal("fixture: the second writer did not change the durable root, so this case proves nothing")
	}
	if got := persistedCommittedHeight(t, raw); got != 1 {
		t.Fatalf("fixture: the heightless commit also moved the durable height to %d; the root leg of the fence is not being exercised", got)
	}

	err = build.Promote()
	if !errors.Is(err, ErrStaleBuildState) {
		t.Fatalf("Promote = %v, want ErrStaleBuildState: the root the copy was branched from is no longer what the database holds", err)
	}
	if !strings.Contains(err.Error(), "durable root changed") {
		t.Errorf("staleness error = %q, want it to name the root drift it detected", err)
	}
	if _, err := diskAccount(t, raw, types.Address{0xb0}); !errors.Is(err, db.ErrKeyNotFound) {
		t.Errorf("the refused promote wrote buffered data to disk anyway (err=%v)", err)
	}
}

func TestR8_01_ForkRollbackInvalidatesAPendingBuildState(t *testing.T) {
	raw := db.NewMemDB()
	live := NewStateDB(raw)

	alice := types.Address{0xa1}
	bob := types.Address{0xb0}
	eve := types.Address{0xe5}

	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("CommitWithBlock(1): %v", err)
	}
	live.SetBalance(bob, big.NewInt(20))
	if _, err := live.CommitWithBlock(2); err != nil {
		t.Fatalf("CommitWithBlock(2): %v", err)
	}

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}

	// The node rolls block 2 back. Before R8-01 the pending build copy knew
	// nothing about it and would still have replayed onto the rolled-forward
	// height it had captured.
	if err := live.RollbackToHeight(2); err != nil {
		t.Fatalf("RollbackToHeight(2): %v", err)
	}
	if got := persistedCommittedHeight(t, raw); got != 1 {
		t.Fatalf("fixture: durable height after the rollback = %d, want 1", got)
	}

	build.SetBalance(eve, big.NewInt(3))
	if _, err := build.CommitWithBlock(3); err != nil {
		t.Fatalf("build copy CommitWithBlock(3): %v", err)
	}
	err := build.Promote()
	if !errors.Is(err, ErrStaleBuildState) {
		t.Fatalf("Promote after a fork rollback = %v, want ErrStaleBuildState", err)
	}
	if !strings.Contains(err.Error(), "durable height moved from 2 to 1") {
		t.Errorf("staleness error = %q, want it to name the rollback", err)
	}
	if _, err := diskAccount(t, raw, eve); !errors.Is(err, db.ErrKeyNotFound) {
		t.Errorf("the rolled-back-then-promoted build persisted eve anyway (err=%v)", err)
	}
}

func TestR8_01_DurableWritersWaitForTheGate(t *testing.T) {
	raw := db.NewMemDB()
	live := NewStateDB(raw)
	gate := live.DurableWriterGateForTesting()
	if gate == nil {
		t.Fatal("no writer gate to hold")
	}

	alice := types.Address{0xa1}
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("CommitWithBlock(1): %v", err)
	}

	// Commit is where an import puts a block durably; Promote is where a local
	// build does. They must queue behind each other, not interleave. Commit is
	// called directly rather than through CommitWithBlock so that this pins the
	// gate of the composite write itself — the wrapper would still be held up by
	// PruneState's gate and could not tell which of the two serialized the work.
	r801AssertBlocksBehindGate(t, "live Commit(2)", gate, func() error {
		_, err := live.Commit(2)
		return err
	})

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	bob := types.Address{0xb0}
	build.SetBalance(bob, big.NewInt(777))
	if _, err := build.CommitWithBlock(3); err != nil {
		t.Fatalf("build copy CommitWithBlock(3): %v", err)
	}
	r801AssertBlocksBehindGate(t, "Promote", gate, build.Promote)

	if _, err := diskAccount(t, raw, bob); err != nil {
		t.Errorf("bob is missing after the gated promote: %v", err)
	}
}

func TestR8_01_NoDurableWriteReachesTheDatabaseWithTheGateFree(t *testing.T) {
	spy := &r801GateSpy{Database: db.NewMemDB()}
	live := NewStateDB(spy)
	spy.attach(live.DurableWriterGateForTesting())

	alice := types.Address{0xa1}
	bob := types.Address{0xb0}
	slot := types.Hash{0x01}

	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("CommitWithBlock(1): %v", err)
	}
	live.SetStorage(alice, slot, types.Hash{0xAA})
	if _, err := live.CommitWithBlock(2); err != nil {
		t.Fatalf("CommitWithBlock(2): %v", err)
	}

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	build.SetBalance(bob, big.NewInt(777))
	if _, err := build.CommitWithBlock(3); err != nil {
		t.Fatalf("build copy CommitWithBlock(3): %v", err)
	}
	if err := build.Promote(); err != nil {
		t.Fatalf("Promote: %v", err)
	}

	// Roll back the block that carried real before-images, so this exercises the
	// rollback's durable writes and not just its early-return path.
	if err := live.RollbackToHeight(2); err != nil {
		t.Fatalf("RollbackToHeight(2): %v", err)
	}
	if err := live.PruneState(3); err != nil {
		t.Fatalf("PruneState(3): %v", err)
	}

	// R8-03: the snap-import path writes raw account/storage/code keys straight to
	// this database from the p2p handlers. It holds no anchor the staleness fence
	// reads, so the gate is the only thing keeping it out of a promote replay.
	snapAddr := types.Address{0xd7}
	if err := live.ImportAccount(snapAddr, make([]byte, 40)); err != nil {
		t.Fatalf("ImportAccount: %v", err)
	}
	if err := live.ImportStorage(snapAddr, types.Hash{0x02}, types.Hash{0xBB}); err != nil {
		t.Fatalf("ImportStorage: %v", err)
	}
	if err := live.ImportCode(types.Hash{0xcc}, []byte{0x60, 0x00}); err != nil {
		t.Fatalf("ImportCode: %v", err)
	}
	if err := live.ClearSnapImport(); err != nil {
		t.Fatalf("ClearSnapImport: %v", err)
	}

	observed, violation := spy.stats()
	if observed == 0 {
		t.Fatal("the spy saw no durable write at all — this test would pass on an unguarded database")
	}
	if violation != "" {
		t.Errorf("durable write %q reached the database while the writer gate was free: some state-lifecycle path writes without going through the gate, so it can interleave with a promote replay", violation)
	}
}

// R8-03: the snap-import writers are the fourth durable writer on a node's
// database, driven by p2p SnapState/SnapBytecode/SnapStorage handlers on their
// own goroutines. Because they leave lastCommittedHeight/lastCommittedRoot
// alone, Promote's staleness fence is blind to them — the writer gate is the only
// mechanism that keeps an import out of a promote replay (and the replay out of
// the discard ClearSnapImport performs when snap state fails root verification).
func TestR8_03_SnapImportWritersWaitForTheGate(t *testing.T) {
	raw := db.NewMemDB()
	live := NewStateDB(raw)
	gate := live.DurableWriterGateForTesting()
	if gate == nil {
		t.Fatal("no writer gate to hold")
	}

	alice := types.Address{0xa1}
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("CommitWithBlock(1): %v", err)
	}

	snapAddr := types.Address{0xd7}
	snapKey := append(accountPrefix, snapAddr[:]...)
	live.BeginSnapImport()

	r801AssertBlocksBehindGate(t, "ImportAccount", gate, func() error {
		return live.ImportAccount(snapAddr, make([]byte, 40))
	})
	if countDiskKeys(raw, snapKey) != 1 {
		t.Fatal("ImportAccount did not reach the database — the assertions below would pass vacuously")
	}
	r801AssertBlocksBehindGate(t, "ImportStorage", gate, func() error {
		return live.ImportStorage(snapAddr, types.Hash{0x01}, types.Hash{0xBB})
	})
	r801AssertBlocksBehindGate(t, "ImportCode", gate, func() error {
		return live.ImportCode(types.Hash{0xcc}, []byte{0x60, 0x00})
	})
	// The three imports above each landed once their gate was released, so the
	// session ledger is non-empty and this really is a deleting run.
	r801AssertBlocksBehindGate(t, "ClearSnapImport", gate, live.ClearSnapImport)

	if countDiskKeys(raw, snapKey) != 0 {
		t.Error("the snap account survived ClearSnapImport — the gated discard did not run")
	}
}

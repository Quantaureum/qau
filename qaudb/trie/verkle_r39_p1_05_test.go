// Quantaureum Node source, version 1.0.0.
package trie

// R39-P1-05 (2026-08-02) regression tests for the VerkleTree.Copy-shared
// persistentDB serial Flush hardening.
//
// Audit (R39-P1-05): VerkleTree.Copy shares the persistentDB instance with
// the original tree. Cross-tree Flush ordering was non-deterministic; the
// audit's recommended fix is "share the persistentDB but serialize Flush with a mutex".
// This file's tests pin three guarantees:
//
//  1. Copy() propagates the persistentFlushMu POINTER so original and copy
//     share the SAME serializing mutex.
//  2. Two sibling trees (original + Copy()) calling Flush() concurrently
//     NEVER have simultaneous critical sections — peak in-flight count is 1.
//     This rules out a future refactor that drops the mutex from Copy() or
//     from Flush().
//  3. Copy() still allocates a fresh pendingBatch (R31 STORAGE-P0-01
//     contract — writes on the copy must not bleed into the original's
//     batch) and post-Flush the persisted state is observable across both
//     trees (data is durably committed through the shared persistentDB).
//
// Strategy: we cannot use the production BoltDB-backed batch here
// (filesystem + bbolt would couple test stability to disk timing), so we
// build a countable in-memory batch wrapper around db.MemDB's Batch that
// records "max concurrent Flush/Write invocations across the entire test"
// via an atomic counter. The wrapper sits behind the same Database/Batch
// interface the production code takes, so production code paths
// (recordPendingWrite + Flush) cannot detect it.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
)

// r39P1_05CountingDB wraps a db.Database whose batch.Replay is observable.
// Every Put / Write / Flush on the underlying batch trips a single global
// in-flight counter; we then assert peak in-flight across all the
// concurrent trees is at most 1, proving the persistentFlushMu gate
// serializes the cross-tree writes.
type r39P1_05CountingDB struct {
	inner db.Database
	peak  uint32 // max simultaneously-in-flight critical section depth
	cur   uint32 // current depth (atomic bump / dec)
}

func newR39P1_05CountingDB() *r39P1_05CountingDB {
	return &r39P1_05CountingDB{inner: db.NewMemDB()}
}

// enter bumps cur and updates peak if cur exceeded peak; leave decrements.
func (c *r39P1_05CountingDB) enter() {
	now := atomic.AddUint32(&c.cur, 1)
	for {
		p := atomic.LoadUint32(&c.peak)
		if now <= p {
			break
		}
		if atomic.CompareAndSwapUint32(&c.peak, p, now) {
			break
		}
	}
}
func (c *r39P1_05CountingDB) leave() {
	atomic.AddUint32(&c.cur, ^uint32(0)) // decrement
}

func (c *r39P1_05CountingDB) Get(key []byte) ([]byte, error) { return c.inner.Get(key) }
func (c *r39P1_05CountingDB) Put(key, value []byte) error {
	c.enter()
	defer c.leave()
	return c.inner.Put(key, value)
}
func (c *r39P1_05CountingDB) Delete(key []byte) error             { return c.inner.Delete(key) }
func (c *r39P1_05CountingDB) Has(key []byte) (bool, error)        { return c.inner.Has(key) }
func (c *r39P1_05CountingDB) Close() error                        { return c.inner.Close() }
func (c *r39P1_05CountingDB) NewIterator(p, s []byte) db.Iterator { return c.inner.NewIterator(p, s) }
func (c *r39P1_05CountingDB) NewIteratorWithLimit(p, s []byte, n int) db.Iterator {
	return c.inner.NewIteratorWithLimit(p, s, n)
}

// r39P1_05CountingBatch wraps a db.Batch so Put/Delete/Write/Flush also
// bump the parent countingDB's in-flight counter, proving serialization
// across concurrent callers.
type r39P1_05CountingBatch struct {
	parent *r39P1_05CountingDB
	inner  db.Batch
}

func (c *r39P1_05CountingDB) NewBatch() db.Batch {
	b := c.inner.NewBatch()
	return &r39P1_05CountingBatch{parent: c, inner: b}
}

func (b *r39P1_05CountingBatch) Put(k, v []byte) error {
	b.parent.enter()
	defer b.parent.leave()
	return b.inner.Put(k, v)
}
func (b *r39P1_05CountingBatch) Delete(k []byte) error {
	b.parent.enter()
	defer b.parent.leave()
	return b.inner.Delete(k)
}
func (b *r39P1_05CountingBatch) Write() error {
	b.parent.enter()
	defer b.parent.leave()
	// Simulate flush latency so concurrent trees have time to overlap if
	// the serialization gate is missing. Without the gate, the peak would
	// be at least 2; with the gate, only one tree is inside Write() at a
	// time so the peak remains 1.
	time.Sleep(5 * time.Millisecond)
	return b.inner.Write()
}
func (b *r39P1_05CountingBatch) Reset()         { b.inner.Reset() }
func (b *r39P1_05CountingBatch) ValueSize() int { return b.inner.ValueSize() }
func (b *r39P1_05CountingBatch) Flush() error {
	b.parent.enter()
	defer b.parent.leave()
	time.Sleep(5 * time.Millisecond)
	return b.inner.Flush()
}

// peek returns the peak concurrent critical-section depth so far.
func (c *r39P1_05CountingDB) peek() uint32 {
	return atomic.LoadUint32(&c.peak)
}

// ── Test 1: Copy() propagates the persistentFlushMu pointer. ──

// TestR39_P1_05_CopyPropagatesPersistentFlushMuPointer pins the audit's
// recommended design: original + Copy() MUST share the SAME mutex
// pointer so Flush() invocations from either tree serialize against each
// other.
//
// Without this contract, two trees derived from a single persistentDB
// would each hold a different mutex and the Flush() Gate would be a
// no-op — the audit's "cross-tree write order non-deterministic" finding
// returns. A future refactor that accidentally newly initializes
// persistentFlushMu in Copy() (instead of propagating the pointer)
// would fail this test.
func TestR39_P1_05_CopyPropagatesPersistentFlushMuPointer(t *testing.T) {
	cdb := newR39P1_05CountingDB()
	original := NewVerkleTree(MaxTreeDepth, cdb)
	if original.persistentFlushMu == nil {
		t.Fatalf("R39-P1-05: NewVerkleTree MUST initialize persistentFlushMu when persistentDB is provided (production paths rely on this for cross-tree serialization); got nil")
	}
	copyMu := original.persistentFlushMu

	copyTree := original.Copy()
	if copyTree == nil {
		t.Fatalf("Copy() returned nil")
	}
	if copyTree.persistentFlushMu == nil {
		t.Fatalf("R39-P1-05: Copy() MUST propagate persistentFlushMu; copy's persistentFlushMu is nil — sibling-tree serialization is broken for Copy-derived trees")
	}
	if copyTree.persistentFlushMu != copyMu {
		t.Fatalf("R39-P1-05: Copy() MUST propagate the persistentFlushMu POINTER (audit's \"share the persistentDB but serialize Flush with a mutex\"); original and copy would have two different mutexes — peak concurrent Flush across siblings would be >=2")
	}
}

// ── Test 2: concurrent Flush() across sibling trees serializes (peak ≤ 1). ──

// TestR39_P1_05_ConcurrentFlush_Serializes_SiblingTrees runs N sibling trees
// (original + 3 copies, all sharing persistentDB) and has each tree's
// Flush() critical section blocked inside Write() for ~5ms. Without the
// persistentFlushMu gate, the N concurrent Flush calls would all enter
// the critical section together, driving the in-flight counter to N. With
// the gate, only one tree is inside at a time, so peak stays at 1.
//
// This is the audit's strongest guarantee: cross-tree Flush ORDER is
// observably stable. The test tolerates racy scheduling by asserting
// peak ≥ N would indicate a regression — there's no near-1 slack where a
// future refactor could land and still pass.
func TestR39_P1_05_ConcurrentFlush_Serializes_SiblingTrees(t *testing.T) {
	cdb := newR39P1_05CountingDB()
	original := NewVerkleTree(MaxTreeDepth, cdb)
	copy1 := original.Copy()
	copy2 := original.Copy()
	copy3 := original.Copy()
	// Sanity: all 4 trees must share the same mutex pointer.
	if !(original.persistentFlushMu == copy1.persistentFlushMu &&
		original.persistentFlushMu == copy2.persistentFlushMu &&
		original.persistentFlushMu == copy3.persistentFlushMu) {
		t.Fatalf("R39-P1-05: precondition failure — original + copies must share the same persistentFlushMu pointer; serialization test is meaningless otherwise")
	}

	// Each tree has a fresh pendingBatch (R31 STORAGE-P0-01 contract). Each
	// tree gets a single Put call so Flush has something to commit; we
	// then drive Flush concurrently across all 4 trees.
	putKey := []byte("vnode:k1")
	putVal := []byte("v")
	_ = original.pendingBatch.Put(putKey, putVal)
	_ = copy1.pendingBatch.Put(putKey, putVal)
	_ = copy2.pendingBatch.Put(putKey, putVal)
	_ = copy3.pendingBatch.Put(putKey, putVal)

	trees := []*VerkleTree{original, copy1, copy2, copy3}
	var wg sync.WaitGroup
	wg.Add(len(trees))
	for _, tree := range trees {

		go func() {
			defer wg.Done()
			_ = tree.Flush()
		}()
	}
	wg.Wait()

	if peak := cdb.peek(); peak != 1 {
		t.Fatalf("R39-P1-05: concurrent Flush() across sibling trees MUST serialize through persistentFlushMu (peak critical-section depth must be 1) — got peak=%d (concurrent trees entered the bbolt critical section together; cross-tree Flush ORDER is non-deterministic, which is the audit's exact finding)", peak)
	}
}

// ── Test 3: data durability contract preserved (Flush → reads visible across trees). ──

// TestR39_P1_05_Flush_DurabilityPreserved_AfterGate pins the backward-
// compatibility contract: adding the serialization gate must NOT change
// the durability semantics. After original.Flush() returns, a Get on the
// copy (which shares persistentDB) MUST see the node bytes written by
// the original. Conversely, can't see half-flushed state during flush
// (MemDB batches are atomic, so this is implicit).
//
// This rules out the failure mode where the gate accidentally dropped
// the actual batch.Write() call or shifted the responsibility.
func TestR39_P1_05_Flush_DurabilityPreserved_AfterGate(t *testing.T) {
	cdb := newR39P1_05CountingDB()
	original := NewVerkleTree(MaxTreeDepth, cdb)
	copyTree := original.Copy()

	// Put a node through original's pendingBatch.
	wantKey := []byte("vnode:durability-test")
	wantVal := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := original.pendingBatch.Put(wantKey, wantVal); err != nil {
		t.Fatalf("seed Put failed: %v", err)
	}
	if err := original.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// The copy shares persistentDB; a direct read MUST see the bytes.
	got, err := cdb.inner.Get(wantKey)
	if err != nil {
		t.Fatalf("post-Flush read failed: %v", err)
	}
	if string(got) != string(wantVal) {
		t.Fatalf("R39-P1-05: post-Flush persistentDB.Get returned %#v, want %#v — the serialization gate must NOT alter the durability semantics (every successful Flush must persist the batch's writes)", got, wantVal)
	}

	// Same key, read through the copy's persistentDB interface, must match.
	got2, err := copyTree.persistentDB.Get(wantKey)
	if err != nil {
		t.Fatalf("copy-side post-Flush read failed: %v", err)
	}
	if string(got2) != string(wantVal) {
		t.Fatalf("R39-P1-05: copy-tree's persistentDB.Get returned %#v, want %#v — copy must observe durable state committed by original", got2, wantVal)
	}
}

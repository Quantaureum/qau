// Quantaureum Node source, version 1.0.0.
package db

import (
	"errors"
	"sort"
	"sync"
)

// Capture is a write-buffering overlay in front of another Database.
//
// R7-01 (2026-10-21 seventh-round audit): StateDB.Copy() is documented as
// "isolated block building", but it only isolates the in-memory layers. The
// copy inherited the SAME durable Database (and the Verkle tree inherited the
// same persistentDB), so buildBlock's CommitWithBlock wrote the block being
// proposed straight onto the shared disk. When the tip changed while building
// — the ordinary race where a peer's block for the same height arrives first —
// tryProduceBlock discarded the copy and returned, leaving that non-authoritative
// state durable: the live StateDB reads through to the same disk on every cache
// miss, and RecoverConsistency rebuilds the trie by iterating that disk at
// startup. The undo records the discarded copy had collected (its beforeImages)
// died with it, so nothing could revert those writes.
//
// A Capture makes the isolation real: every read still sees the base, plus this
// instance's own buffered writes (read-your-writes, which is what the copy saw
// once its batch.Write() had landed), and every write is buffered instead of
// reaching the base. ApplyToBase replays the net effect in key order at the
// moment — and only at the moment — the block is adopted. A copy that is
// discarded simply goes away, taking its buffered writes with it.
//
// Close() intentionally does NOT close the base: a discarded copy must never
// tear the database out from under the live instance.
type Capture struct {
	base Database

	mu       sync.RWMutex
	entries  map[string]captureEntry
	buffered int  // total value bytes currently buffered
	applied  bool // ApplyToBase succeeded — writes now pass through
}

type captureEntry struct {
	value   []byte
	deleted bool
}

// NewCapture returns an overlay that reads through to base and buffers writes.
func NewCapture(base Database) *Capture {
	return &Capture{
		base:    base,
		entries: make(map[string]captureEntry),
	}
}

// Base returns the underlying database the capture reads through to (and that
// ApplyToBase writes into).
func (c *Capture) Base() Database {
	return c.base
}

// BufferedKeys reports how many distinct keys currently hold a buffered write.
func (c *Capture) BufferedKeys() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// BufferedBytes reports the total value bytes currently buffered. Used to size
// the memory a block-building copy can hold.
func (c *Capture) BufferedBytes() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.buffered
}

// Get returns the buffered value when this capture has one for the key, and
// otherwise falls through to the base. A buffered delete shadows the base value
// with ErrKeyNotFound, exactly as if the delete had been durable.
func (c *Capture) Get(key []byte) ([]byte, error) {
	c.mu.RLock()
	entry, ok := c.entries[string(key)]
	c.mu.RUnlock()

	if ok {
		if entry.deleted {
			return nil, ErrKeyNotFound
		}
		return append([]byte(nil), entry.value...), nil
	}
	return c.base.Get(key)
}

// Put buffers a write. After ApplyToBase has succeeded the overlay degrades to
// a pass-through proxy, so a late writer can never silently lose data.
func (c *Capture) Put(key, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.applied {
		return c.base.Put(key, value)
	}
	return c.bufferPutLocked(key, value)
}

// Delete buffers a tombstone. See Put for the post-apply pass-through behavior.
func (c *Capture) Delete(key []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.applied {
		return c.base.Delete(key)
	}
	return c.bufferDeleteLocked(key)
}

func (c *Capture) bufferPutLocked(key, value []byte) error {
	k := string(key)
	if prev, ok := c.entries[k]; ok {
		if !prev.deleted {
			c.buffered -= len(prev.value)
		}
	}
	copied := append([]byte(nil), value...)
	c.entries[k] = captureEntry{value: copied}
	c.buffered += len(copied)
	return nil
}

func (c *Capture) bufferDeleteLocked(key []byte) error {
	k := string(key)
	if prev, ok := c.entries[k]; ok {
		if !prev.deleted {
			c.buffered -= len(prev.value)
		}
	}
	c.entries[k] = captureEntry{deleted: true}
	return nil
}

// Has reports existence under the same read-your-writes rule as Get.
func (c *Capture) Has(key []byte) (bool, error) {
	c.mu.RLock()
	entry, ok := c.entries[string(key)]
	c.mu.RUnlock()

	if ok {
		return !entry.deleted, nil
	}
	return c.base.Has(key)
}

// Close is a no-op: the base database is shared with the live StateDB and must
// outlive any individual copy.
func (c *Capture) Close() error {
	return nil
}

// NewBatch returns a batch whose ops become visible to this capture only when
// Write/Flush is called, mirroring the underlying databases. The batch never
// reports ErrBatchFull (it buffers in memory), which keeps the buffered write
// set of one block build in a single replayable unit.
func (c *Capture) NewBatch() Batch {
	return &captureBatch{c: c}
}

// NewIterator iterates base + buffered writes in key order, unbounded.
func (c *Capture) NewIterator(prefix []byte, start []byte) Iterator {
	return c.NewIteratorWithLimit(prefix, start, 0)
}

// NewIteratorWithLimit merges the base iterator with the buffered set: a
// buffered value overrides the base entry for the same key, a buffered
// tombstone removes it. limit > 0 truncates the MERGED result and reports
// ErrIteratorTruncated, matching the concrete implementations — callers such as
// computeStorageRoot depend on that error to avoid hashing a partial key set
// into a state root.
func (c *Capture) NewIteratorWithLimit(prefix []byte, start []byte, limit int) Iterator {
	merged, err := c.mergedView(prefix, start)
	if err != nil {
		return &memIterator{err: err}
	}

	var truncated bool
	if limit > 0 && len(merged) > limit {
		merged = merged[:limit]
		truncated = true
	}

	it := &memIterator{items: merged, index: -1}
	if truncated {
		it.err = ErrIteratorTruncated
	}
	return it
}

// mergedView materializes every key under prefix (>= start) with the buffered
// writes applied on top of the base entries, sorted by key.
func (c *Capture) mergedView(prefix []byte, start []byte) ([]iterItem, error) {
	// Snapshot the buffered subset first, then read the base without holding
	// c.mu: a base iterator may itself be expensive and the live instance keeps
	// committing into the same base while this copy builds.
	c.mu.RLock()
	buffered := make(map[string]captureEntry)
	if len(c.entries) > 0 {
		pfx, st := string(prefix), string(start)
		for k, entry := range c.entries {
			if len(pfx) > 0 && (len(k) < len(pfx) || k[:len(pfx)] != pfx) {
				continue
			}
			if start != nil && k < st {
				continue
			}
			buffered[k] = entry
		}
	}
	c.mu.RUnlock()

	// A capture with no buffered writes is a straight pass-through — including
	// for the closed-database error, which the base iterator reports.
	if len(buffered) == 0 {
		return c.baseView(prefix, start)
	}

	baseItems, err := c.baseView(prefix, start)
	if err != nil {
		return nil, err
	}

	byKey := make(map[string][]byte, len(baseItems)+len(buffered))
	for _, item := range baseItems {
		byKey[string(item.key)] = item.value
	}
	for k, entry := range buffered {
		if entry.deleted {
			delete(byKey, k)
			continue
		}
		byKey[k] = entry.value
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	items := make([]iterItem, 0, len(keys))
	for _, k := range keys {
		items = append(items, iterItem{key: []byte(k), value: byKey[k]})
	}
	return items, nil
}

func (c *Capture) baseView(prefix []byte, start []byte) ([]iterItem, error) {
	iter := c.base.NewIteratorWithLimit(prefix, start, 0)
	defer iter.Release()

	items := make([]iterItem, 0)
	for iter.Next() {
		items = append(items, iterItem{
			key:   append([]byte(nil), iter.Key()...),
			value: append([]byte(nil), iter.Value()...),
		})
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return items, nil
}

// ApplyToBase replays every buffered write into the base database.
//
// control (R8-02, 2026-10-21 eighth-round audit) names the keys that describe
// WHAT IS durable — the state layer's commit-pending marker and its
// last-committed height/root anchor. Those keys are prefixed with a byte that
// sorts before every data prefix, so a plain key-order replay applies them
// FIRST: once the buffered set is large enough to hit the base's batch limits
// the replay spans several transactions, and a replay that fails partway would
// leave the base advertising the new height and root (with the recovery marker
// already cleared) while only part of the accounts and trie nodes behind them
// were applied. Callers that stage durability metadata must pass a predicate so
// that metadata is applied last, in one batch. nil keeps raw key-order
// behavior, which is fine for buffers that carry no durability metadata.
//
// Data keys are applied first and may be split across transactions — the
// buffered set of one full block can legitimately exceed the base's batch
// limits. The control keys of one logical commit are a handful of small values,
// so that pass refuses to split and they land together or not at all.
//
// On error the buffer is left intact (minus whatever the base applied before
// failing) and the capture stays un-applied: applied data cannot be un-written,
// so the caller must fail closed. The marker a caller stages before calling
// this is what makes a partial replay detectable on the next startup.
func (c *Capture) ApplyToBase(control func(key string) bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.applied {
		return nil
	}
	if len(c.entries) == 0 {
		c.applied = true
		return nil
	}

	var dataKeys, controlKeys []string
	for k := range c.entries {
		if control != nil && control(k) {
			controlKeys = append(controlKeys, k)
		} else {
			dataKeys = append(dataKeys, k)
		}
	}
	sort.Strings(dataKeys)
	sort.Strings(controlKeys)

	if err := c.replayLocked(dataKeys, true); err != nil {
		return err
	}
	if err := c.replayLocked(controlKeys, false); err != nil {
		return err
	}

	c.entries = make(map[string]captureEntry)
	c.buffered = 0
	c.applied = true
	return nil
}

// replayLocked writes keys into the base in the given order. allowSplit lets a
// large data set span several transactions; the metadata pass keeps the whole
// set in one batch so a logical commit's anchor writes are atomic.
func (c *Capture) replayLocked(keys []string, allowSplit bool) error {
	if len(keys) == 0 {
		return nil
	}
	batch := c.base.NewBatch()
	for _, k := range keys {
		entry := c.entries[k]
		var err error
		if entry.deleted {
			err = batch.Delete([]byte(k))
		} else {
			err = batch.Put([]byte(k), entry.value)
		}
		if err != nil {
			if !errors.Is(err, ErrBatchFull) || !allowSplit {
				return err
			}
			if flushErr := batch.Flush(); flushErr != nil {
				return flushErr
			}
			if entry.deleted {
				err = batch.Delete([]byte(k))
			} else {
				err = batch.Put([]byte(k), entry.value)
			}
			if err != nil {
				return err
			}
		}
	}
	return batch.Write()
}

// captureBatch buffers ops until Write/Flush makes them visible to the capture.
type captureBatch struct {
	c    *Capture
	ops  []batchOp
	size int
}

func (b *captureBatch) Put(key, value []byte) error {
	b.ops = append(b.ops, batchOp{
		key:   append([]byte(nil), key...),
		value: append([]byte(nil), value...),
	})
	b.size += len(value)
	return nil
}

func (b *captureBatch) Delete(key []byte) error {
	b.ops = append(b.ops, batchOp{key: append([]byte(nil), key...), delete: true})
	return nil
}

func (b *captureBatch) Write() error {
	b.c.mu.Lock()
	defer b.c.mu.Unlock()
	for _, op := range b.ops {
		if op.delete {
			if b.c.applied {
				if err := b.c.base.Delete(op.key); err != nil {
					return err
				}
				continue
			}
			if err := b.c.bufferDeleteLocked(op.key); err != nil {
				return err
			}
			continue
		}
		if b.c.applied {
			if err := b.c.base.Put(op.key, op.value); err != nil {
				return err
			}
			continue
		}
		if err := b.c.bufferPutLocked(op.key, op.value); err != nil {
			return err
		}
	}
	return nil
}

func (b *captureBatch) Flush() error {
	if err := b.Write(); err != nil {
		return err
	}
	b.Reset()
	return nil
}

func (b *captureBatch) Reset() {
	b.ops = b.ops[:0]
	b.size = 0
}

func (b *captureBatch) ValueSize() int {
	return b.size
}

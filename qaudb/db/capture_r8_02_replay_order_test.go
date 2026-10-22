// Quantaureum Node source, version 1.0.0.
package db

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// R8-02 (2026-10-21 eighth-round audit): ApplyToBase used to replay the whole
// buffered set in raw key order, splitting into several transactions as soon as
// the base reported ErrBatchFull. The state layer keys its durability metadata
// with '_' ("_commit_pending_", "_last_committed_height_", "_last_committed_root_")
// which sorts BEFORE the data prefixes "a"/"c"/"s", so the very first shard
// published the new height and root and cleared the recovery marker — and if a
// later shard failed (or the process died) the base was left claiming a height
// whose accounts and trie nodes were never applied, with no marker for
// RecoverConsistency to notice. Promote is the caller that stages those keys, so
// the replay must apply data first and metadata last, in one transaction.

// r802Base records which keys reached the base in which transaction, can force
// the batch to split, and can fail one key.
type r802Base struct {
	Database
	mu      sync.Mutex
	limit   int
	failKey string
	flushes [][]string
}

func (b *r802Base) NewBatch() Batch { return &r802Batch{base: b} }

func (b *r802Base) recorded() [][]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([][]string, len(b.flushes))
	copy(out, b.flushes)
	return out
}

type r802Batch struct {
	base *r802Base
	ops  []batchOp
}

func (b *r802Batch) appendOp(op batchOp) error {
	if string(op.key) == b.base.failKey {
		return errors.New("simulated disk fault")
	}
	b.base.mu.Lock()
	defer b.base.mu.Unlock()
	if b.base.limit > 0 && len(b.ops) >= b.base.limit {
		return ErrBatchFull
	}
	b.ops = append(b.ops, op)
	return nil
}

func (b *r802Batch) Put(key, value []byte) error {
	return b.appendOp(batchOp{key: append([]byte(nil), key...), value: append([]byte(nil), value...)})
}

func (b *r802Batch) Delete(key []byte) error {
	return b.appendOp(batchOp{key: append([]byte(nil), key...), delete: true})
}

func (b *r802Batch) commit() error {
	b.base.mu.Lock()
	ops := b.ops
	b.ops = nil
	b.base.mu.Unlock()
	if len(ops) == 0 {
		return nil
	}
	keys := make([]string, 0, len(ops))
	for _, op := range ops {
		var err error
		if op.delete {
			err = b.base.Database.Delete(op.key)
		} else {
			err = b.base.Database.Put(op.key, op.value)
		}
		if err != nil {
			return err
		}
		keys = append(keys, string(op.key))
	}
	b.base.mu.Lock()
	b.base.flushes = append(b.base.flushes, keys)
	b.base.mu.Unlock()
	return nil
}

func (b *r802Batch) Write() error { return b.commit() }
func (b *r802Batch) Flush() error { return b.commit() }
func (b *r802Batch) Reset()       { b.ops = nil }

func (b *r802Batch) ValueSize() int {
	total := 0
	for _, op := range b.ops {
		total += len(op.value)
	}
	return total
}

var r802Control = func(key string) bool { return strings.HasPrefix(key, "_") }

// r802Stage puts the same mixed data/metadata write set into a fresh capture.
func r802Stage(t *testing.T, c *Capture) {
	t.Helper()
	for _, kv := range [][2]string{
		{"_commit_pending_", ""},
		{"_last_committed_height_", "2"},
		{"_last_committed_root_", "root2"},
		{"a1", "1"},
		{"a2", "2"},
		{"a3", "3"},
		{"a4", "4"},
		{"s1", "x"},
	} {
		mustPut(t, c, kv[0], kv[1])
	}
	// The real promote replay deletes the marker instead of writing it empty.
	if err := c.Delete([]byte("_commit_pending_")); err != nil {
		t.Fatalf("Delete marker: %v", err)
	}
}

func TestR8_02_ApplyToBaseDefersDurabilityMetadataToTheFinalTransaction(t *testing.T) {
	// limit=3 forces the five data keys to span several transactions while the
	// three metadata keys still fit in one (mirroring the real batch caps, which
	// one commit's metadata always fits under).
	base := &r802Base{Database: NewMemDB(), limit: 3}
	c := NewCapture(base)
	r802Stage(t, c)

	if err := c.ApplyToBase(r802Control); err != nil {
		t.Fatalf("ApplyToBase: %v", err)
	}

	shards := base.recorded()
	if len(shards) < 3 {
		t.Fatalf("replay produced %d transaction(s); the ordering property is only interesting when the "+
			"buffered set actually spans several", len(shards))
	}
	for i, shard := range shards[:len(shards)-1] {
		for _, k := range shard {
			if strings.HasPrefix(k, "_") {
				t.Errorf("durability metadata %q reached the base in transaction %d of %d, before the data "+
					"behind it was fully applied", k, i+1, len(shards))
			}
		}
	}
	last := shards[len(shards)-1]
	got := map[string]bool{}
	for _, k := range last {
		got[k] = true
	}
	for _, k := range []string{"_commit_pending_", "_last_committed_height_", "_last_committed_root_"} {
		if !got[k] {
			t.Errorf("%q is not in the final transaction — one logical commit's metadata must land together", k)
		}
	}
	if len(last) != 3 {
		t.Errorf("final transaction carries %d key(s) %v, want the 3 metadata keys only", len(last), last)
	}
	// Everything was applied exactly once across the shards.
	for _, k := range []string{"a1", "a2", "a3", "a4", "s1"} {
		if v := mustGet(t, base, k); v == "" {
			t.Errorf("data key %q never reached the base", k)
		}
	}
}

func TestR8_02_FailedReplayNeverPublishesTheAnchor(t *testing.T) {
	// What the old raw key order did: the metadata sorts first, so a replay that
	// dies on a data key still leaves the height and root durable. Kept as the
	// documented failure mode this fix removes.
	torn := &r802Base{Database: NewMemDB(), limit: 1, failKey: "a2"}
	tc := NewCapture(torn)
	r802Stage(t, tc)
	if err := tc.ApplyToBase(nil); err == nil {
		t.Fatal("fixture: the injected disk fault was expected to abort a control=nil replay")
	}
	if _, err := torn.Get([]byte("_last_committed_height_")); err != nil {
		t.Fatal("fixture: control=nil replay was supposed to publish the anchor before dying on data")
	}
	if _, err := torn.Get([]byte("s1")); err == nil {
		t.Fatal("fixture: the replay was supposed to die before the later data keys")
	}
	t.Log("control=nil replay published the anchor while data was missing (the R8-02 failure mode)")

	// With the metadata deferred, the same failure leaves the base exactly where
	// it was: no anchor for a state that was never fully applied.
	safe := &r802Base{Database: NewMemDB(), limit: 1, failKey: "a2"}
	sc := NewCapture(safe)
	r802Stage(t, sc)
	if err := sc.ApplyToBase(r802Control); err == nil {
		t.Fatal("ApplyToBase: expected the injected disk fault to abort the replay")
	}
	for _, k := range []string{"_commit_pending_", "_last_committed_height_", "_last_committed_root_"} {
		if _, err := safe.Get([]byte(k)); err == nil {
			t.Errorf("%q reached the base although the replay failed (%v)", k, err)
		}
	}
	if sc.BufferedKeys() == 0 {
		t.Error("failed replay dropped the buffer; the caller can no longer inspect or retry what did not land")
	}
}

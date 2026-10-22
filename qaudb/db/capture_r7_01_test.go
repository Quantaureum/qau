// Quantaureum Node source, version 1.0.0.
package db

import (
	"errors"
	"testing"
)

// R7-01 (2026-10-21 seventh-round audit): StateDB.Copy() shares the durable
// database with the original, so the block producer's CommitWithBlock on a
// copy wrote a block that might still be discarded straight onto the live
// disk. Capture is the buffer that keeps those writes out of the shared
// database until the block is adopted. These tests pin the buffer's own
// semantics: read-your-writes without leaking to the base, tombstones that
// shadow base values, merged iteration in key order (the property
// computeStorageRoot depends on to hash the same slot set the producer's
// earlier commit staged), batch ops becoming visible only at Write, and
// ApplyToBase reproducing the net effect in the base.

func mustPut(t *testing.T, d Database, key, value string) {
	t.Helper()
	if err := d.Put([]byte(key), []byte(value)); err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
}

func mustGet(t *testing.T, d Database, key string) string {
	t.Helper()
	data, err := d.Get([]byte(key))
	if err != nil {
		t.Fatalf("Get(%q): %v", key, err)
	}
	return string(data)
}

func assertMissing(t *testing.T, d Database, key string) {
	t.Helper()
	_, err := d.Get([]byte(key))
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(%q) = err %v, want ErrKeyNotFound", key, err)
	}
}

func collectIterator(it Iterator) ([]string, []string, error) {
	var keys, values []string
	for it.Next() {
		keys = append(keys, string(it.Key()))
		values = append(values, string(it.Value()))
	}
	err := it.Error()
	it.Release()
	return keys, values, err
}

func TestR7_01_CaptureBuffersWritesUntilApplyToBase(t *testing.T) {
	base := NewMemDB()
	mustPut(t, base, "a", "base-a")

	c := NewCapture(base)
	mustPut(t, c, "a", "staged-a")
	mustPut(t, c, "b", "staged-b")

	// The copy sees its own writes...
	if got := mustGet(t, c, "a"); got != "staged-a" {
		t.Errorf("capture read of overwritten key = %q, want staged-a", got)
	}
	if got := mustGet(t, c, "b"); got != "staged-b" {
		t.Errorf("capture read of new key = %q, want staged-b", got)
	}
	// ...and falls through for keys it never touched.
	mustPut(t, base, "z", "base-z")
	if got := mustGet(t, c, "z"); got != "base-z" {
		t.Errorf("capture read of untouched key = %q, want base-z", got)
	}

	// The shared database has seen nothing.
	if got := mustGet(t, base, "a"); got != "base-a" {
		t.Errorf("base was mutated before ApplyToBase: got %q, want base-a", got)
	}
	assertMissing(t, base, "b")

	keys, size := c.BufferedKeys(), c.BufferedBytes()
	if keys != 2 || size != len("staged-a")+len("staged-b") {
		t.Errorf("buffer accounting = (%d keys, %d bytes), want (2, %d)",
			keys, size, len("staged-a")+len("staged-b"))
	}

	if err := c.ApplyToBase(nil); err != nil {
		t.Fatalf("ApplyToBase: %v", err)
	}
	if got := mustGet(t, base, "a"); got != "staged-a" {
		t.Errorf("after apply, base a = %q, want staged-a", got)
	}
	if got := mustGet(t, base, "b"); got != "staged-b" {
		t.Errorf("after apply, base b = %q, want staged-b", got)
	}
	if c.BufferedKeys() != 0 {
		t.Errorf("buffer not drained after ApplyToBase: %d keys left", c.BufferedKeys())
	}
}

func TestR7_01_CaptureTombstoneShadowsBaseValue(t *testing.T) {
	base := NewMemDB()
	mustPut(t, base, "acct", "live")

	c := NewCapture(base)
	if err := c.Delete([]byte("acct")); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	assertMissing(t, c, "acct")
	if ok, err := c.Has([]byte("acct")); err != nil || ok {
		t.Errorf("Has of tombstoned key = (%v, %v), want (false, nil)", ok, err)
	}
	// The base is untouched until the delete is adopted.
	if got := mustGet(t, base, "acct"); got != "live" {
		t.Errorf("base deleted before ApplyToBase: got %q", got)
	}

	if err := c.ApplyToBase(nil); err != nil {
		t.Fatalf("ApplyToBase: %v", err)
	}
	assertMissing(t, base, "acct")
}

func TestR7_01_CaptureIteratorMergesBufferedWrites(t *testing.T) {
	base := NewMemDB()
	mustPut(t, base, "k1", "base-1")
	mustPut(t, base, "k3", "base-3")
	mustPut(t, base, "k5", "base-5")

	c := NewCapture(base)
	mustPut(t, c, "k2", "staged-2")
	mustPut(t, c, "k3", "staged-3")
	if err := c.Delete([]byte("k5")); err != nil {
		t.Fatalf("Delete k5: %v", err)
	}

	keys, values, err := collectIterator(c.NewIterator([]byte("k"), nil))
	if err != nil {
		t.Fatalf("merged iterator error: %v", err)
	}
	wantKeys := []string{"k1", "k2", "k3"}
	wantValues := []string{"base-1", "staged-2", "staged-3"}
	if len(keys) != len(wantKeys) {
		t.Fatalf("merged iterator = %v / %v, want %v / %v", keys, values, wantKeys, wantValues)
	}
	for i := range wantKeys {
		if keys[i] != wantKeys[i] || values[i] != wantValues[i] {
			t.Errorf("merged iterator entry %d = (%s, %s), want (%s, %s)",
				i, keys[i], values[i], wantKeys[i], wantValues[i])
		}
	}

	// start is inclusive, exactly like the concrete databases.
	keys, _, err = collectIterator(c.NewIterator([]byte("k"), []byte("k2")))
	if err != nil {
		t.Fatalf("iterator with start error: %v", err)
	}
	if len(keys) != 2 || keys[0] != "k2" || keys[1] != "k3" {
		t.Errorf("iterator from k2 = %v, want [k2 k3]", keys)
	}

	// A limit truncates the MERGED set and reports it, so a caller that hashes
	// what it iterated (computeStorageRoot) fails closed instead of producing a
	// root over a partial key set.
	it := c.NewIteratorWithLimit([]byte("k"), nil, 2)
	limited, _, err := collectIterator(it)
	if !errors.Is(err, ErrIteratorTruncated) {
		t.Errorf("limited iterator error = %v, want ErrIteratorTruncated", err)
	}
	if len(limited) != 2 {
		t.Errorf("limited iterator returned %d entries, want 2", len(limited))
	}

	// Unlimited iteration is the complete merged view.
	full, _, err := collectIterator(c.NewIteratorWithLimit([]byte("k"), nil, 0))
	if err != nil {
		t.Fatalf("unlimited iterator error: %v", err)
	}
	if len(full) != 3 {
		t.Errorf("unlimited iterator returned %v, want 3 merged entries", full)
	}
}

func TestR7_01_CaptureBatchOpsBecomeVisibleOnWrite(t *testing.T) {
	base := NewMemDB()
	c := NewCapture(base)

	batch := c.NewBatch()
	if err := batch.Put([]byte("x"), []byte("1")); err != nil {
		t.Fatalf("batch.Put: %v", err)
	}
	// Mirrors a real batch: staged, not yet applied.
	assertMissing(t, c, "x")

	if err := batch.Write(); err != nil {
		t.Fatalf("batch.Write: %v", err)
	}
	if got := mustGet(t, c, "x"); got != "1" {
		t.Errorf("after Write, capture x = %q, want 1", got)
	}
	assertMissing(t, base, "x")

	// Last write wins across batches, in order, including deletes.
	b2 := c.NewBatch()
	if err := b2.Put([]byte("x"), []byte("2")); err != nil {
		t.Fatalf("batch2.Put: %v", err)
	}
	if err := b2.Delete([]byte("y")); err != nil {
		t.Fatalf("batch2.Delete: %v", err)
	}
	if err := b2.Write(); err != nil {
		t.Fatalf("batch2.Write: %v", err)
	}
	if err := c.ApplyToBase(nil); err != nil {
		t.Fatalf("ApplyToBase: %v", err)
	}
	if got := mustGet(t, base, "x"); got != "2" {
		t.Errorf("after apply, base x = %q, want 2 (last buffered write)", got)
	}
}

func TestR7_01_CaptureCloseLeavesBaseOpen(t *testing.T) {
	base := NewMemDB()
	mustPut(t, base, "keep", "value")

	c := NewCapture(base)
	mustPut(t, c, "buffered", "value")
	if err := c.Close(); err != nil {
		t.Fatalf("Capture.Close: %v", err)
	}
	// A discarded build copy must never tear the shared database out from
	// under the live StateDB.
	if got := mustGet(t, base, "keep"); got != "value" {
		t.Errorf("base unusable after Capture.Close: read returned %q", got)
	}
	assertMissing(t, base, "buffered")
}

func TestR7_01_CaptureWritesAfterApplyReachBaseDirectly(t *testing.T) {
	base := NewMemDB()
	c := NewCapture(base)
	mustPut(t, c, "first", "1")
	if err := c.ApplyToBase(nil); err != nil {
		t.Fatalf("ApplyToBase: %v", err)
	}

	// Promotion is one-way: a writer that keeps the overlay afterwards must
	// still land on the base instead of buffering into something nobody will
	// ever replay.
	mustPut(t, c, "second", "2")
	if got := mustGet(t, base, "second"); got != "2" {
		t.Errorf("post-apply write did not reach the base: got %q", got)
	}
}

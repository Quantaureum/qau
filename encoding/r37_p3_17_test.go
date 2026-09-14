// Quantaureum Node source, version 1.0.0.
// Package encoding - R37-P3-17 regression tests.
//
// BlobStorage.GetCell and PersistentBlobStorage.GetCell previously only
// checked blobIndex < len(entry.Commitments): a negative blobIndex passed
// that check and indexed entry.Commitments[-1], panicking with an
// index-out-of-range. The R37-P3-17 fix requires blobIndex >= 0, returning
// a nil commitment for out-of-range indices.
package encoding

import (
	"testing"
)

// r37TestEntry builds a minimal BlobStorageEntry with one original column
// and one commitment.
func r37TestEntry(slot uint64, blobIndex int) *BlobStorageEntry {
	return &BlobStorageEntry{
		Slot:      slot,
		BlobIndex: blobIndex,
		Matrix: SparseBlobMatrix{
			OriginalColumns: make([]BlobCellsExtended, 1),
			OriginalCount:   1,
		},
		Commitments: make([]KZGCommitment, 1),
	}
}

// TestR37_P3_17_BlobStorage_GetCell_NegativeBlobIndex verifies that
// BlobStorage.GetCell with blobIndex = -1 returns a nil commitment instead
// of panicking on entry.Commitments[-1].
func TestR37_P3_17_BlobStorage_GetCell_NegativeBlobIndex(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BlobStorage.GetCell panicked on blobIndex=-1: %v (should return nil commitment)", r)
		}
	}()
	s := NewBlobStorage()
	s.entries[s.key(1, -1)] = r37TestEntry(1, -1)

	cell, commitment, err := s.GetCell(1, -1, 0, 0)
	if err != nil {
		t.Fatalf("GetCell returned error: %v", err)
	}
	if cell == nil {
		t.Errorf("GetCell returned nil cell, want non-nil")
	}
	if commitment != nil {
		t.Errorf("GetCell with blobIndex=-1 returned non-nil commitment, want nil")
	}
}

// TestR37_P3_17_BlobStorage_GetCell_ValidBlobIndex verifies that a valid
// blobIndex still returns the commitment (no regression from the guard).
func TestR37_P3_17_BlobStorage_GetCell_ValidBlobIndex(t *testing.T) {
	s := NewBlobStorage()
	s.entries[s.key(1, 0)] = r37TestEntry(1, 0)

	_, commitment, err := s.GetCell(1, 0, 0, 0)
	if err != nil {
		t.Fatalf("GetCell returned error: %v", err)
	}
	if commitment == nil {
		t.Errorf("GetCell with blobIndex=0 returned nil commitment, want non-nil")
	}
}

// TestR37_P3_17_PersistentBlobStorage_GetCell_NegativeBlobIndex verifies
// that PersistentBlobStorage.GetCell with blobIndex = -1 returns a nil
// commitment instead of panicking.
func TestR37_P3_17_PersistentBlobStorage_GetCell_NegativeBlobIndex(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PersistentBlobStorage.GetCell panicked on blobIndex=-1: %v (should return nil commitment)", r)
		}
	}()
	s := NewPersistentBlobStorage(nil)
	s.cache[s.key(1, -1)] = r37TestEntry(1, -1)

	cell, commitment, err := s.GetCell(1, -1, 0, 0)
	if err != nil {
		t.Fatalf("GetCell returned error: %v", err)
	}
	if cell == nil {
		t.Errorf("GetCell returned nil cell, want non-nil")
	}
	if commitment != nil {
		t.Errorf("GetCell with blobIndex=-1 returned non-nil commitment, want nil")
	}
}

// TestR37_P3_17_PersistentBlobStorage_GetCell_ValidBlobIndex verifies that
// a valid blobIndex still returns the commitment (no regression).
func TestR37_P3_17_PersistentBlobStorage_GetCell_ValidBlobIndex(t *testing.T) {
	s := NewPersistentBlobStorage(nil)
	s.cache[s.key(1, 0)] = r37TestEntry(1, 0)

	_, commitment, err := s.GetCell(1, 0, 0, 0)
	if err != nil {
		t.Fatalf("GetCell returned error: %v", err)
	}
	if commitment == nil {
		t.Errorf("GetCell with blobIndex=0 returned nil commitment, want non-nil")
	}
}

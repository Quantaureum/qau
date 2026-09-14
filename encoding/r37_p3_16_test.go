// Quantaureum Node source, version 1.0.0.
// Package encoding - R37-P3-16 regression tests.
//
// decodePersistentEntry previously did not bound commitCount: an unchecked
// large value makes commitCount*48 overflow int (wrapping negative on
// 32-bit builds), bypassing the length check and enabling a massive
// allocation / panic in the loops that follow. The R37-P3-16 fix caps both
// commitCount and originalCount at MaxBlobColumnsExt.
package encoding

import (
	"encoding/binary"
	"testing"
)

// r37BuildPersistentEntryBytes builds a serialized persistent entry header
// with the given commitCount / originalCount, padded to the size the decoder
// would expect for legitimate values.
func r37BuildPersistentEntryBytes(commitCount, originalCount uint32, legit bool) []byte {
	size := 28
	if legit {
		size += int(commitCount)*48 + int(originalCount)*CellsPerBlobExtended*CellSize
	}
	data := make([]byte, size)
	// slot (8 bytes) — leave zero.
	binary.BigEndian.PutUint32(data[8:12], 0) // blobIndex
	// storedAtNano (8 bytes) — leave zero.
	binary.BigEndian.PutUint32(data[20:24], commitCount)
	binary.BigEndian.PutUint32(data[24:28], originalCount)
	return data
}

// TestR37_P3_16_decodePersistentEntry_RejectsHugeCommitCount verifies that
// decodePersistentEntry rejects commitCount = 2^32-1 instead of overflowing
// the expectedSize computation and panicking on a huge allocation.
func TestR37_P3_16_decodePersistentEntry_RejectsHugeCommitCount(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decodePersistentEntry panicked on commitCount=2^32-1: %v (should return error)", r)
		}
	}()
	data := r37BuildPersistentEntryBytes(0xFFFFFFFF, 0, false)
	_, err := decodePersistentEntry(data)
	if err == nil {
		t.Errorf("decodePersistentEntry with commitCount=2^32-1 returned nil error, want error")
	}
}

// TestR37_P3_16_decodePersistentEntry_RejectsCommitCountAboveMax verifies
// that commitCount just above MaxBlobColumnsExt is rejected.
func TestR37_P3_16_decodePersistentEntry_RejectsCommitCountAboveMax(t *testing.T) {
	data := r37BuildPersistentEntryBytes(uint32(MaxBlobColumnsExt)+1, 0, true)
	_, err := decodePersistentEntry(data)
	if err == nil {
		t.Errorf("decodePersistentEntry with commitCount=MaxBlobColumnsExt+1 returned nil error, want error")
	}
}

// TestR37_P3_16_decodePersistentEntry_RejectsHugeOriginalCount verifies
// that originalCount is bounded by the same guard.
func TestR37_P3_16_decodePersistentEntry_RejectsHugeOriginalCount(t *testing.T) {
	data := r37BuildPersistentEntryBytes(1, 0xFFFFFFFF, false)
	_, err := decodePersistentEntry(data)
	if err == nil {
		t.Errorf("decodePersistentEntry with originalCount=2^32-1 returned nil error, want error")
	}
}

// TestR37_P3_16_decodePersistentEntry_AcceptsCommitCountAtMax verifies the
// boundary: commitCount == MaxBlobColumnsExt with sufficient data must
// decode successfully.
func TestR37_P3_16_decodePersistentEntry_AcceptsCommitCountAtMax(t *testing.T) {
	data := r37BuildPersistentEntryBytes(uint32(MaxBlobColumnsExt), 0, true)
	entry, err := decodePersistentEntry(data)
	if err != nil {
		t.Fatalf("decodePersistentEntry with commitCount=MaxBlobColumnsExt returned error: %v", err)
	}
	if len(entry.Commitments) != MaxBlobColumnsExt {
		t.Errorf("len(Commitments) = %d, want %d", len(entry.Commitments), MaxBlobColumnsExt)
	}
}

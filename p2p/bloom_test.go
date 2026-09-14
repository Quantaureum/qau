// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
)

func TestBloomFilterAddContains(t *testing.T) {
	bf := NewBloomFilter(nil)

	data := []byte("test-data")
	bf.Add(data)

	if !bf.Contains(data) {
		t.Error("Contains should return true after Add")
	}

	unknown := []byte("unknown-data")
	if bf.Contains(unknown) {
		t.Error("Contains should return false for unknown data")
	}
}

func TestBloomFilterAddIfNotPresent(t *testing.T) {
	bf := NewBloomFilter(nil)

	data := []byte("test-data")
	added := bf.AddIfNotPresent(data)
	if !added {
		t.Error("AddIfNotPresent should return true for new data")
	}

	added = bf.AddIfNotPresent(data)
	if added {
		t.Error("AddIfNotPresent should return false for existing data")
	}
}

func TestBloomFilterReset(t *testing.T) {
	bf := NewBloomFilter(nil)

	data := []byte("test-data")
	bf.Add(data)
	bf.Reset()

	if bf.Contains(data) {
		t.Error("Contains should return false after Reset")
	}
	if bf.Count() != 0 {
		t.Errorf("Count = %d, want 0 after Reset", bf.Count())
	}
}

func TestBloomFilterCount(t *testing.T) {
	bf := NewBloomFilter(nil)

	if bf.Count() != 0 {
		t.Errorf("Count = %d, want 0", bf.Count())
	}

	bf.Add([]byte("data1"))
	bf.Add([]byte("data2"))
	bf.Add([]byte("data3"))

	if bf.Count() != 3 {
		t.Errorf("Count = %d, want 3", bf.Count())
	}
}

func TestBloomFilterSize(t *testing.T) {
	bf := NewBloomFilter(&BloomFilterConfig{
		ExpectedItems:     1000,
		FalsePositiveRate: 0.01,
	})

	if bf.Size() == 0 {
		t.Error("Size should not be 0")
	}
}

func TestBloomFilterHashFunctions(t *testing.T) {
	bf := NewBloomFilter(nil)

	if bf.HashFunctions() < 1 {
		t.Error("HashFunctions should be at least 1")
	}
}

func TestBloomFilterSerializeDeserialize(t *testing.T) {
	bf := NewBloomFilter(nil)
	bf.Add([]byte("test1"))
	bf.Add([]byte("test2"))

	serialized := bf.Serialize()
	deserialized, err := DeserializeBloomFilter(serialized)
	if err != nil {
		t.Fatalf("DeserializeBloomFilter failed: %v", err)
	}

	if !deserialized.Contains([]byte("test1")) {
		t.Error("deserialized filter should contain test1")
	}
	if !deserialized.Contains([]byte("test2")) {
		t.Error("deserialized filter should contain test2")
	}
	if deserialized.Count() != bf.Count() {
		t.Errorf("Count mismatch: %d vs %d", deserialized.Count(), bf.Count())
	}
}

func TestDeserializeBloomFilterTooShort(t *testing.T) {
	_, err := DeserializeBloomFilter([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestDeserializeBloomFilterInvalidSize(t *testing.T) {
	// Create data with invalid size (not multiple of 8)
	data := make([]byte, 20)
	// size = 7 (not multiple of 8)
	data[0] = 0
	data[1] = 0
	data[2] = 0
	data[3] = 0
	data[4] = 0
	data[5] = 0
	data[6] = 0
	data[7] = 7
	// hashFns = 3
	data[8] = 0
	data[9] = 0
	data[10] = 0
	data[11] = 3
	// count = 0
	data[12] = 0
	data[13] = 0
	data[14] = 0
	data[15] = 0
	data[16] = 0
	data[17] = 0
	data[18] = 0
	data[19] = 0

	_, err := DeserializeBloomFilter(data)
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage for invalid size, got %v", err)
	}
}

func TestDeserializeBloomFilterInvalidHashFns(t *testing.T) {
	// hashFns = 0 (invalid)
	data := make([]byte, 20)
	// size = 8 (valid, multiple of 8)
	data[7] = 8
	// hashFns = 0 (invalid)
	data[11] = 0
	// bits
	bitsData := make([]byte, 1)
	data = append(data, bitsData...)

	_, err := DeserializeBloomFilter(data)
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage for invalid hashFns, got %v", err)
	}
}

func TestBloomFilterClone(t *testing.T) {
	bf := NewBloomFilter(nil)
	bf.Add([]byte("test"))

	clone := bf.Clone()
	if !clone.Contains([]byte("test")) {
		t.Error("clone should contain test")
	}
	if clone.Count() != bf.Count() {
		t.Errorf("clone count = %d, want %d", clone.Count(), bf.Count())
	}
}

func TestBloomFilterMerge(t *testing.T) {
	bf1 := NewBloomFilterWithSize(1024, 3)
	bf2 := NewBloomFilterWithSize(1024, 3)

	bf1.Add([]byte("data1"))
	bf2.Add([]byte("data2"))

	ok := bf1.Merge(bf2)
	if !ok {
		t.Error("Merge should succeed for same-size filters")
	}

	if !bf1.Contains([]byte("data1")) {
		t.Error("merged filter should contain data1")
	}
	if !bf1.Contains([]byte("data2")) {
		t.Error("merged filter should contain data2")
	}
}

func TestBloomFilterMergeDifferentSize(t *testing.T) {
	bf1 := NewBloomFilterWithSize(1024, 3)
	bf2 := NewBloomFilterWithSize(2048, 3)

	ok := bf1.Merge(bf2)
	if ok {
		t.Error("Merge should fail for different-size filters")
	}
}

func TestBloomFilterEstimatedFalsePositiveRate(t *testing.T) {
	bf := NewBloomFilter(nil)
	fpr := bf.EstimatedFalsePositiveRate()
	if fpr < 0 || fpr > 1 {
		t.Errorf("FPR = %f, should be between 0 and 1", fpr)
	}
}

func TestBloomFilterFillRatio(t *testing.T) {
	bf := NewBloomFilter(nil)
	fr := bf.FillRatio()
	if fr < 0 || fr > 1 {
		t.Errorf("FillRatio = %f, should be between 0 and 1", fr)
	}
}

func TestNewBloomFilterWithSize(t *testing.T) {
	bf := NewBloomFilterWithSize(1024, 5)
	if bf.Size() != 1024 {
		t.Errorf("Size = %d, want 1024", bf.Size())
	}
	if bf.HashFunctions() != 5 {
		t.Errorf("HashFunctions = %d, want 5", bf.HashFunctions())
	}
}

func TestNewBloomFilterWithSizeMinValues(t *testing.T) {
	bf := NewBloomFilterWithSize(4, 0) // Below minimum
	if bf.Size() < 8 {
		t.Errorf("Size = %d, should be at least 8", bf.Size())
	}
	if bf.HashFunctions() < 1 {
		t.Error("HashFunctions should be at least 1")
	}
}

func TestNewBloomFilterNilConfig(t *testing.T) {
	bf := NewBloomFilter(nil)
	if bf == nil {
		t.Error("NewBloomFilter(nil) should not return nil")
	}
}

func TestNewBloomFilterInvalidConfig(t *testing.T) {
	bf := NewBloomFilter(&BloomFilterConfig{
		ExpectedItems:     0,
		FalsePositiveRate: 0,
	})
	if bf == nil {
		t.Error("NewBloomFilter with invalid config should use defaults")
	}
}

func TestMessageDeduplicator(t *testing.T) {
	md := NewMessageDeduplicator(1000, 0.01)

	hash1 := []byte("hash1")
	hash2 := []byte("hash2")

	if md.IsDuplicate(hash1) {
		t.Error("hash1 should not be duplicate initially")
	}

	md.MarkSeen(hash1)

	if !md.IsDuplicate(hash1) {
		t.Error("hash1 should be duplicate after MarkSeen")
	}
	if md.IsDuplicate(hash2) {
		t.Error("hash2 should not be duplicate")
	}
}

func TestMessageDeduplicatorMarkSeenIfNew(t *testing.T) {
	md := NewMessageDeduplicator(1000, 0.01)

	hash1 := []byte("hash1")

	if !md.MarkSeenIfNew(hash1) {
		t.Error("MarkSeenIfNew should return true for new hash")
	}
	if md.MarkSeenIfNew(hash1) {
		t.Error("MarkSeenIfNew should return false for existing hash")
	}
}

func TestMessageDeduplicatorReset(t *testing.T) {
	md := NewMessageDeduplicator(1000, 0.01)

	hash1 := []byte("hash1")
	md.MarkSeen(hash1)
	md.Reset()

	if md.IsDuplicate(hash1) {
		t.Error("hash1 should not be duplicate after Reset")
	}
}

func TestMessageDeduplicatorStats(t *testing.T) {
	md := NewMessageDeduplicator(1000, 0.01)
	md.MarkSeen([]byte("hash1"))
	md.MarkSeen([]byte("hash2"))

	count, fillRatio, fpr := md.Stats()
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if fillRatio < 0 || fillRatio > 1 {
		t.Errorf("fillRatio = %f, should be between 0 and 1", fillRatio)
	}
	if fpr < 0 || fpr > 1 {
		t.Errorf("fpr = %f, should be between 0 and 1", fpr)
	}
}

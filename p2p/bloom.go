// Quantaureum Node source, version 1.0.0.
// Package p2p provides peer-to-peer networking functionality for QAU blockchain.
package p2p

import (
	"encoding/binary"
	"math"
	"sync"
)

// BloomFilter implements a probabilistic data structure for fast membership testing.
// It is used for message deduplication in P2P networking to quickly filter out
// already-seen messages without storing all message hashes.
type BloomFilter struct {
	bits    []byte // Bit array
	size    uint64 // Number of bits
	hashFns int    // Number of hash functions
	count   uint64 // Number of items added
	mu      sync.RWMutex
}

// BloomFilterConfig contains configuration for creating a BloomFilter
type BloomFilterConfig struct {
	// ExpectedItems is the expected number of items to be added
	ExpectedItems uint64
	// FalsePositiveRate is the desired false positive rate (0 < rate < 1)
	FalsePositiveRate float64
}

// DefaultBloomFilterConfig returns a default configuration suitable for P2P deduplication
func DefaultBloomFilterConfig() *BloomFilterConfig {
	return &BloomFilterConfig{
		ExpectedItems:     100000, // 100K messages
		FalsePositiveRate: 0.01,   // 1% false positive rate
	}
}

// NewBloomFilter creates a new BloomFilter with the given configuration.
// The size and number of hash functions are calculated to achieve the desired
// false positive rate for the expected number of items.
func NewBloomFilter(config *BloomFilterConfig) *BloomFilter {
	if config == nil {
		config = DefaultBloomFilterConfig()
	}

	// Calculate optimal size and hash functions
	// m = -n * ln(p) / (ln(2)^2)
	// k = (m/n) * ln(2)
	n := float64(config.ExpectedItems)
	p := config.FalsePositiveRate

	// Ensure valid parameters
	if n <= 0 {
		n = 100000
	}
	if p <= 0 || p >= 1 {
		p = 0.01
	}

	ln2 := math.Log(2)
	ln2Sq := ln2 * ln2

	// Calculate optimal bit array size
	m := -n * math.Log(p) / ln2Sq
	size := uint64(math.Ceil(m))

	// Round up to nearest byte
	size = ((size + 7) / 8) * 8

	// Calculate optimal number of hash functions
	k := (float64(size) / n) * ln2
	hashFns := int(math.Ceil(k))
	if hashFns < 1 {
		hashFns = 1
	}
	if hashFns > 30 {
		hashFns = 30 // Cap at 30 hash functions
	}

	return &BloomFilter{
		bits:    make([]byte, size/8),
		size:    size,
		hashFns: hashFns,
		count:   0,
	}
}

// NewBloomFilterWithSize creates a BloomFilter with explicit size and hash function count.
// This is useful when you need precise control over the filter parameters.
func NewBloomFilterWithSize(sizeBits uint64, hashFns int) *BloomFilter {
	if sizeBits < 8 {
		sizeBits = 8
	}
	// Round up to nearest byte
	sizeBits = ((sizeBits + 7) / 8) * 8

	if hashFns < 1 {
		hashFns = 1
	}
	if hashFns > 30 {
		hashFns = 30
	}

	return &BloomFilter{
		bits:    make([]byte, sizeBits/8),
		size:    sizeBits,
		hashFns: hashFns,
		count:   0,
	}
}

// Add adds an item to the bloom filter.
func (bf *BloomFilter) Add(data []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	bf.addUnsafe(data)
}

// addUnsafe adds an item without locking (caller must hold lock)
// R33 P2-11 FIX (2026-07-28): Guard against zero-value BloomFilter{} which
// has size=0, causing division-by-zero panic in the modulo operation.
func (bf *BloomFilter) addUnsafe(data []byte) {
	if bf.size == 0 || bf.hashFns == 0 {
		return // no-op on uninitialized filter
	}
	for i := 0; i < bf.hashFns; i++ {
		idx := bf.hash(data, i) % bf.size
		bf.setBit(idx)
	}
	bf.count++
}

// Contains checks if an item might be in the bloom filter.
// Returns true if the item might be present (with possible false positives),
// or false if the item is definitely not present.
func (bf *BloomFilter) Contains(data []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	return bf.containsUnsafe(data)
}

// containsUnsafe checks membership without locking (caller must hold lock)
// R33 P2-11 FIX (2026-07-28): Guard against zero-value BloomFilter{} which
// has size=0, causing division-by-zero panic.
func (bf *BloomFilter) containsUnsafe(data []byte) bool {
	if bf.size == 0 || bf.hashFns == 0 {
		return false // uninitialized filter contains nothing
	}
	for i := 0; i < bf.hashFns; i++ {
		idx := bf.hash(data, i) % bf.size
		if !bf.getBit(idx) {
			return false
		}
	}
	return true
}

// AddIfNotPresent adds an item only if it's not already present.
// Returns true if the item was added (was not present), false if it might already exist.
func (bf *BloomFilter) AddIfNotPresent(data []byte) bool {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	if bf.containsUnsafe(data) {
		return false
	}
	bf.addUnsafe(data)
	return true
}

// Reset clears all bits in the bloom filter.
func (bf *BloomFilter) Reset() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.count = 0
}

// Count returns the number of items added to the filter.
// Note: This is the number of Add() calls, not the number of unique items.
func (bf *BloomFilter) Count() uint64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.count
}

// Size returns the size of the bit array in bits.
func (bf *BloomFilter) Size() uint64 {
	return bf.size
}

// HashFunctions returns the number of hash functions used.
func (bf *BloomFilter) HashFunctions() int {
	return bf.hashFns
}

// EstimatedFalsePositiveRate returns the estimated false positive rate
// based on the current fill ratio.
// R33 P2-11 FIX (2026-07-28): Guard against size==0 to prevent NaN.
func (bf *BloomFilter) EstimatedFalsePositiveRate() float64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	if bf.size == 0 {
		return 0
	}

	// Count set bits
	setBits := uint64(0)
	for _, b := range bf.bits {
		setBits += uint64(popCount(b)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	}

	// Calculate fill ratio
	fillRatio := float64(setBits) / float64(bf.size)

	// Estimated FPR = fillRatio^k
	return math.Pow(fillRatio, float64(bf.hashFns))
}

// FillRatio returns the ratio of set bits to total bits.
// R33 P2-11 FIX (2026-07-28): Guard against size==0 to prevent NaN.
func (bf *BloomFilter) FillRatio() float64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	if bf.size == 0 {
		return 0
	}

	setBits := uint64(0)
	for _, b := range bf.bits {
		setBits += uint64(popCount(b)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	}

	return float64(setBits) / float64(bf.size)
}

// setBit sets the bit at the given index.
func (bf *BloomFilter) setBit(idx uint64) {
	byteIdx := idx / 8
	bitIdx := idx % 8
	bf.bits[byteIdx] |= 1 << bitIdx
}

// getBit returns true if the bit at the given index is set.
func (bf *BloomFilter) getBit(idx uint64) bool {
	byteIdx := idx / 8
	bitIdx := idx % 8
	return (bf.bits[byteIdx] & (1 << bitIdx)) != 0
}

// hash computes the i-th hash of the data using double hashing technique.
// h_i(x) = h1(x) + i * h2(x)
func (bf *BloomFilter) hash(data []byte, i int) uint64 {
	// Use FNV-1a for h1 and a modified version for h2
	h1 := fnv1a64(data)
	h2 := fnv1a64Modified(data)

	return h1 + uint64(i)*h2 // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// fnv1a64 computes FNV-1a 64-bit hash
func fnv1a64(data []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)

	hash := uint64(offset64)
	for _, b := range data {
		hash ^= uint64(b)
		hash *= prime64
	}
	return hash
}

// fnv1a64Modified computes a modified FNV-1a hash for double hashing
func fnv1a64Modified(data []byte) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)

	// Start with a different offset and process in reverse
	hash := uint64(offset64 ^ 0x5555555555555555)
	for i := len(data) - 1; i >= 0; i-- {
		hash ^= uint64(data[i])
		hash *= prime64
	}
	return hash | 1 // Ensure odd number for better distribution
}

// popCount returns the number of set bits in a byte (population count)
func popCount(b byte) int {
	count := 0
	for b != 0 {
		count += int(b & 1)
		b >>= 1
	}
	return count
}

// Merge merges another bloom filter into this one (OR operation).
// Both filters must have the same size and number of hash functions.
// R33 P2-16 FIX (2026-07-28): Added nil checks for both bf and other to
// prevent nil pointer dereference panics.
func (bf *BloomFilter) Merge(other *BloomFilter) bool {
	if bf == nil || other == nil {
		return false
	}
	if bf.size != other.size || bf.hashFns != other.hashFns {
		return false
	}

	bf.mu.Lock()
	other.mu.RLock()
	defer bf.mu.Unlock()
	defer other.mu.RUnlock()

	for i := range bf.bits {
		bf.bits[i] |= other.bits[i]
	}
	bf.count += other.count

	return true
}

// Clone creates a copy of the bloom filter.
func (bf *BloomFilter) Clone() *BloomFilter {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	clone := &BloomFilter{
		bits:    make([]byte, len(bf.bits)),
		size:    bf.size,
		hashFns: bf.hashFns,
		count:   bf.count,
	}
	copy(clone.bits, bf.bits)
	return clone
}

// Serialize serializes the bloom filter to bytes.
func (bf *BloomFilter) Serialize() []byte {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	// Format: size (8 bytes) + hashFns (4 bytes) + count (8 bytes) + bits
	result := make([]byte, 20+len(bf.bits))
	binary.BigEndian.PutUint64(result[0:8], bf.size)
	binary.BigEndian.PutUint32(result[8:12], uint32(bf.hashFns)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	binary.BigEndian.PutUint64(result[12:20], bf.count)
	copy(result[20:], bf.bits)
	return result
}

// DeserializeBloomFilter deserializes a bloom filter from bytes.
// #nosec audit-remediation R12-4: validate hashFns and size from untrusted data
func DeserializeBloomFilter(data []byte) (*BloomFilter, error) {
	if len(data) < 20 {
		return nil, ErrMalformedMessage
	}

	size := binary.BigEndian.Uint64(data[0:8])
	hashFns := int(binary.BigEndian.Uint32(data[8:12]))
	count := binary.BigEndian.Uint64(data[12:20])

	// Validate size: must be >= 8 and a multiple of 8 to prevent division-by-zero
	// and out-of-bounds panics in setBit/getBit operations
	if size < 8 || size%8 != 0 {
		return nil, ErrMalformedMessage
	}

	// Validate hashFns: must be 1-30 (same caps as NewBloomFilter/NewBloomFilterWithSize)
	// An uncapped value from untrusted wire data causes CPU DoS in Add/Contains loops
	if hashFns < 1 || hashFns > 30 {
		return nil, ErrMalformedMessage
	}

	expectedBitsLen := size / 8
	if uint64(len(data)-20) != expectedBitsLen { // #nosec G115 -- length is always non-negative
		return nil, ErrMalformedMessage
	}

	bf := &BloomFilter{
		bits:    make([]byte, expectedBitsLen),
		size:    size,
		hashFns: hashFns,
		count:   count,
	}
	copy(bf.bits, data[20:])

	return bf, nil
}

// MessageDeduplicator uses a bloom filter for efficient message deduplication.
type MessageDeduplicator struct {
	filter *BloomFilter
}

// NewMessageDeduplicator creates a new message deduplicator.
func NewMessageDeduplicator(expectedMessages uint64, falsePositiveRate float64) *MessageDeduplicator {
	return &MessageDeduplicator{
		filter: NewBloomFilter(&BloomFilterConfig{
			ExpectedItems:     expectedMessages,
			FalsePositiveRate: falsePositiveRate,
		}),
	}
}

// IsDuplicate checks if a message has been seen before.
// Returns true if the message is likely a duplicate.
func (md *MessageDeduplicator) IsDuplicate(msgHash []byte) bool {
	return md.filter.Contains(msgHash)
}

// MarkSeen marks a message as seen.
func (md *MessageDeduplicator) MarkSeen(msgHash []byte) {
	md.filter.Add(msgHash)
}

// MarkSeenIfNew marks a message as seen only if it's new.
// Returns true if the message was new (and is now marked), false if it was already seen.
func (md *MessageDeduplicator) MarkSeenIfNew(msgHash []byte) bool {
	return md.filter.AddIfNotPresent(msgHash)
}

// Reset clears all seen messages.
func (md *MessageDeduplicator) Reset() {
	md.filter.Reset()
}

// Stats returns statistics about the deduplicator.
func (md *MessageDeduplicator) Stats() (count uint64, fillRatio float64, estimatedFPR float64) {
	return md.filter.Count(), md.filter.FillRatio(), md.filter.EstimatedFalsePositiveRate()
}

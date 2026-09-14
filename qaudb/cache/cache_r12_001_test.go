// Quantaureum Node source, version 1.0.0.
// CACHE-R12-001 (2026-07-20): Regression tests for multi-level cache
// memory byte tracking.
//
// Background: Before this fix, MultiLevelCacheConfig.L*MaxMemory fields
// were declared as `any` but never read by NewMultiLevelCache. A single
// Put of a 1 GB []byte would be stored regardless of the configured
// memory limit, allowing OOM via large values.
//
// The fix:
//  1. Changed L*MaxMemory from `any` to `int64` (typed).
//  2. Added LRUCache memory tracking (currentMemory, sizeFunc).
//  3. Wired up L*MaxMemory in NewMultiLevelCache via NewLRUCacheWithMemoryLimit.
//  4. DefaultSizeFunc tracks []byte and string exactly.
//  5. Oversized entries (size > maxMemory) are rejected before insertion.
//  6. Memory-based eviction runs after count-based eviction.
package cache

import (
	"testing"
	"time"
)

// --- DefaultSizeFunc tests ------------------------------------------------

func TestCACHE_R12001_DefaultSizeFunc_ByteSlice(t *testing.T) {
	if got := DefaultSizeFunc([]byte("hello")); got != 5 {
		t.Errorf("expected 5, got %d", got)
	}
}

func TestCACHE_R12001_DefaultSizeFunc_String(t *testing.T) {
	if got := DefaultSizeFunc("hello world"); got != 11 {
		t.Errorf("expected 11, got %d", got)
	}
}

func TestCACHE_R12001_DefaultSizeFunc_Nil(t *testing.T) {
	if got := DefaultSizeFunc(nil); got != 0 {
		t.Errorf("expected 0 for nil, got %d", got)
	}
}

func TestCACHE_R12001_DefaultSizeFunc_OtherTypesReturnZero(t *testing.T) {
	// Integers, structs, etc. return 0 — rely on count-based eviction.
	if got := DefaultSizeFunc(42); got != 0 {
		t.Errorf("expected 0 for int, got %d", got)
	}
	type custom struct{ X int }
	if got := DefaultSizeFunc(custom{X: 1}); got != 0 {
		t.Errorf("expected 0 for struct, got %d", got)
	}
}

// --- LRUCache memory tracking tests ---------------------------------------

// TestCACHE_R12001_LRUCache_RejectsOversizedEntry verifies that a single
// entry larger than maxMemory is rejected (not stored).
func TestCACHE_R12001_LRUCache_RejectsOversizedEntry(t *testing.T) {
	// maxMemory = 100 bytes, entry = 200 bytes → reject.
	c := NewLRUCacheWithMemoryLimit(10, 100, DefaultSizeFunc)
	bigValue := make([]byte, 200)
	c.Put("big", bigValue, 0)

	if _, ok := c.Get("big"); ok {
		t.Error("oversized entry was stored despite exceeding maxMemory")
	}
	if c.Len() != 0 {
		t.Errorf("expected len=0 after rejected Put, got %d", c.Len())
	}
	if c.MemoryUsage() != 0 {
		t.Errorf("expected memory=0 after rejected Put, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_AcceptsEntryWithinLimit verifies that an
// entry within the memory limit is stored and counted.
func TestCACHE_R12001_LRUCache_AcceptsEntryWithinLimit(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 100, DefaultSizeFunc)
	smallValue := make([]byte, 50)
	c.Put("small", smallValue, 0)

	if _, ok := c.Get("small"); !ok {
		t.Error("entry within limit was not stored")
	}
	if c.Len() != 1 {
		t.Errorf("expected len=1, got %d", c.Len())
	}
	if c.MemoryUsage() != 50 {
		t.Errorf("expected memory=50, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_EvictsForMemory verifies that entries are
// evicted (LRU order) when adding a new entry would exceed maxMemory.
func TestCACHE_R12001_LRUCache_EvictsForMemory(t *testing.T) {
	// maxMemory = 100 bytes, capacity = 10 (count limit won't fire).
	// Put 3 entries of 40 bytes each: 40 + 40 = 80 (ok), third would
	// total 120 > 100, so LRU (first entry) is evicted.
	c := NewLRUCacheWithMemoryLimit(10, 100, DefaultSizeFunc)

	v1 := make([]byte, 40)
	v2 := make([]byte, 40)
	v3 := make([]byte, 40)

	c.Put("k1", v1, 0)
	c.Put("k2", v2, 0)
	// Now memory = 80, count = 2.
	if c.MemoryUsage() != 80 {
		t.Errorf("after 2 puts, expected memory=80, got %d", c.MemoryUsage())
	}

	// Put k3: needs 40 more, 80 + 40 = 120 > 100 → evict k1 (LRU).
	c.Put("k3", v3, 0)

	// k1 should be evicted, k2 and k3 should remain.
	if _, ok := c.Get("k1"); ok {
		t.Error("k1 should have been evicted to free memory")
	}
	if _, ok := c.Get("k2"); !ok {
		t.Error("k2 should still be present")
	}
	if _, ok := c.Get("k3"); !ok {
		t.Error("k3 should be present")
	}
	if c.MemoryUsage() != 80 {
		t.Errorf("after eviction, expected memory=80, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_UpdateExistingAdjustsMemory verifies that
// updating an existing entry subtracts the old size and adds the new size.
func TestCACHE_R12001_LRUCache_UpdateExistingAdjustsMemory(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 1000, DefaultSizeFunc)

	c.Put("k", make([]byte, 100), 0)
	if c.MemoryUsage() != 100 {
		t.Errorf("expected 100, got %d", c.MemoryUsage())
	}

	// Update with smaller value.
	c.Put("k", make([]byte, 50), 0)
	if c.MemoryUsage() != 50 {
		t.Errorf("after shrink, expected 50, got %d", c.MemoryUsage())
	}

	// Update with larger value.
	c.Put("k", make([]byte, 200), 0)
	if c.MemoryUsage() != 200 {
		t.Errorf("after grow, expected 200, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_DeleteReleasesMemory verifies that Delete
// subtracts the deleted entry's memory.
func TestCACHE_R12001_LRUCache_DeleteReleasesMemory(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 1000, DefaultSizeFunc)
	c.Put("k", make([]byte, 100), 0)
	if c.MemoryUsage() != 100 {
		t.Errorf("expected 100, got %d", c.MemoryUsage())
	}

	c.Delete("k")
	if c.MemoryUsage() != 0 {
		t.Errorf("after delete, expected 0, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_ClearResetsMemory verifies that Clear
// resets currentMemory to 0.
func TestCACHE_R12001_LRUCache_ClearResetsMemory(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 1000, DefaultSizeFunc)
	c.Put("k1", make([]byte, 100), 0)
	c.Put("k2", make([]byte, 200), 0)
	c.Clear()
	if c.MemoryUsage() != 0 {
		t.Errorf("after clear, expected 0, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_ExpiryReleasesMemory verifies that when Get
// encounters an expired entry, it subtracts the memory.
func TestCACHE_R12001_LRUCache_ExpiryReleasesMemory(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 1000, DefaultSizeFunc)
	c.Put("k", make([]byte, 100), 10*time.Millisecond)
	if c.MemoryUsage() != 100 {
		t.Errorf("expected 100, got %d", c.MemoryUsage())
	}

	// Wait for expiry.
	time.Sleep(20 * time.Millisecond)

	// Get should detect expiry and remove the entry.
	if _, ok := c.Get("k"); ok {
		t.Error("expected expiry to make entry unavailable")
	}
	if c.MemoryUsage() != 0 {
		t.Errorf("after expiry, expected 0, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_NoMemoryTrackingWhenMaxMemoryZero verifies
// that maxMemory=0 disables memory tracking (legacy behavior).
func TestCACHE_R12001_LRUCache_NoMemoryTrackingWhenMaxMemoryZero(t *testing.T) {
	c := NewLRUCache(10) // no memory limit
	c.Put("k", make([]byte, 100), 0)
	if c.MemoryUsage() != 0 {
		t.Errorf("expected 0 (memory tracking disabled), got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_NoMemoryTrackingWhenSizeFuncNil verifies
// that nil sizeFunc disables memory tracking even if maxMemory > 0.
func TestCACHE_R12001_LRUCache_NoMemoryTrackingWhenSizeFuncNil(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 100, nil)
	c.Put("k", make([]byte, 200), 0)
	// Without sizeFunc, the entry is stored regardless of maxMemory.
	if _, ok := c.Get("k"); !ok {
		t.Error("entry should be stored when sizeFunc is nil")
	}
	if c.MemoryUsage() != 0 {
		t.Errorf("expected 0 (sizeFunc nil), got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_LRUCache_CountEvictionStillWorks verifies that
// count-based eviction still fires alongside memory-based eviction.
func TestCACHE_R12001_LRUCache_CountEvictionStillWorks(t *testing.T) {
	// capacity=2, maxMemory=1000 (memory won't fire with small values).
	c := NewLRUCacheWithMemoryLimit(2, 1000, DefaultSizeFunc)
	c.Put("k1", []byte("a"), 0)
	c.Put("k2", []byte("b"), 0)
	c.Put("k3", []byte("c"), 0) // should evict k1 (count-based)

	if _, ok := c.Get("k1"); ok {
		t.Error("k1 should have been evicted by count-based LRU")
	}
	if c.Len() != 2 {
		t.Errorf("expected len=2, got %d", c.Len())
	}
}

// TestCACHE_R12001_LRUCache_BothEvictionsApply verifies that both
// count-based and memory-based eviction apply simultaneously.
func TestCACHE_R12001_LRUCache_BothEvictionsApply(t *testing.T) {
	// capacity=5, maxMemory=30. Each entry = 10 bytes.
	// After 3 puts: count=3, memory=30 (at limit).
	// 4th put: count=4 (under capacity), memory would be 40 > 30 → evict LRU.
	c := NewLRUCacheWithMemoryLimit(5, 30, DefaultSizeFunc)
	c.Put("k1", make([]byte, 10), 0)
	c.Put("k2", make([]byte, 10), 0)
	c.Put("k3", make([]byte, 10), 0)
	// Memory = 30, count = 3.
	c.Put("k4", make([]byte, 10), 0)
	// Memory would be 40 > 30 → evict k1. After: k2,k3,k4 = 30.

	if _, ok := c.Get("k1"); ok {
		t.Error("k1 should be evicted by memory-based LRU")
	}
	if c.Len() != 3 {
		t.Errorf("expected len=3, got %d", c.Len())
	}
	if c.MemoryUsage() != 30 {
		t.Errorf("expected memory=30, got %d", c.MemoryUsage())
	}
}

// --- MultiLevelCache integration tests ------------------------------------

// TestCACHE_R12001_MultiLevel_WiresUpMaxMemory verifies that
// NewMultiLevelCache actually wires up L*MaxMemory to the underlying
// LRU caches (the original bug — fields were declared but unused).
func TestCACHE_R12001_MultiLevel_WiresUpMaxMemory(t *testing.T) {
	config := &MultiLevelCacheConfig{
		L1Capacity:  10,
		L2Capacity:  100,
		L3Capacity:  1000,
		L1MaxMemory: 100,
		L2MaxMemory: 1000,
		L3MaxMemory: 10000,
	}
	c := NewMultiLevelCache(config)

	if c.l1.MaxMemory() != 100 {
		t.Errorf("L1 maxMemory not wired: expected 100, got %d", c.l1.MaxMemory())
	}
	if c.l2.MaxMemory() != 1000 {
		t.Errorf("L2 maxMemory not wired: expected 1000, got %d", c.l2.MaxMemory())
	}
	if c.l3.MaxMemory() != 10000 {
		t.Errorf("L3 maxMemory not wired: expected 10000, got %d", c.l3.MaxMemory())
	}
}

// TestCACHE_R12001_MultiLevel_DefaultConfigHasMemoryLimits verifies
// that DefaultMultiLevelCacheConfig sets sensible memory limits.
func TestCACHE_R12001_MultiLevel_DefaultConfigHasMemoryLimits(t *testing.T) {
	config := DefaultMultiLevelCacheConfig()
	if config.L1MaxMemory <= 0 {
		t.Error("default L1MaxMemory should be > 0")
	}
	if config.L2MaxMemory <= 0 {
		t.Error("default L2MaxMemory should be > 0")
	}
	if config.L3MaxMemory <= 0 {
		t.Error("default L3MaxMemory should be > 0")
	}
	if config.SizeFunc == nil {
		t.Error("default SizeFunc should be non-nil")
	}
}

// TestCACHE_R12001_MultiLevel_L1RejectsOversizedEntry verifies the
// end-to-end behavior: a Put into L1 of an oversized []byte is rejected.
func TestCACHE_R12001_MultiLevel_L1RejectsOversizedEntry(t *testing.T) {
	config := &MultiLevelCacheConfig{
		L1Capacity:  10,
		L2Capacity:  100,
		L3Capacity:  1000,
		L1MaxMemory: 100,
		L2MaxMemory: 1000,
		L3MaxMemory: 10000,
	}
	c := NewMultiLevelCache(config)

	// 200-byte []byte exceeds L1's 100-byte limit → rejected.
	c.PutHot("big", make([]byte, 200))
	if _, ok := c.Get("big"); ok {
		t.Error("oversized L1 entry should have been rejected")
	}
}

// TestCACHE_R12001_MultiLevel_L1AcceptsEntryWithinLimit verifies that
// a normal-sized entry is stored in L1.
func TestCACHE_R12001_MultiLevel_L1AcceptsEntryWithinLimit(t *testing.T) {
	config := &MultiLevelCacheConfig{
		L1Capacity:  10,
		L2Capacity:  100,
		L3Capacity:  1000,
		L1MaxMemory: 100,
		L2MaxMemory: 1000,
		L3MaxMemory: 10000,
	}
	c := NewMultiLevelCache(config)

	c.PutHot("k", make([]byte, 50))
	if _, ok := c.Get("k"); !ok {
		t.Error("entry within limit should be stored")
	}
}

// TestCACHE_R12001_MultiLevel_MaxSizeOverridesCapacity verifies that
// L*MaxSize (when > 0) overrides L*Capacity.
func TestCACHE_R12001_MultiLevel_MaxSizeOverridesCapacity(t *testing.T) {
	config := &MultiLevelCacheConfig{
		L1Capacity: 1000,
		L1MaxSize:  3, // overrides capacity → effective capacity = 3
	}
	c := NewMultiLevelCache(config)

	c.PutHot("k1", []byte("a"))
	c.PutHot("k2", []byte("b"))
	c.PutHot("k3", []byte("c"))
	c.PutHot("k4", []byte("d")) // should evict k1

	if _, ok := c.Get("k1"); ok {
		t.Error("k1 should be evicted when L1MaxSize=3 overrides L1Capacity=1000")
	}
	if c.l1.Len() != 3 {
		t.Errorf("expected len=3, got %d", c.l1.Len())
	}
}

// TestCACHE_R12001_MultiLevel_PutPreservingExpiryTracksMemory verifies
// that the promotion path (PutPreservingExpiry) also tracks memory.
func TestCACHE_R12001_MultiLevel_PutPreservingExpiryTracksMemory(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 1000, DefaultSizeFunc)
	c.PutPreservingExpiry("k", make([]byte, 100), time.Minute, time.Time{})
	if c.MemoryUsage() != 100 {
		t.Errorf("expected 100, got %d", c.MemoryUsage())
	}

	// Update with smaller value.
	c.PutPreservingExpiry("k", make([]byte, 50), time.Minute, time.Time{})
	if c.MemoryUsage() != 50 {
		t.Errorf("expected 50 after shrink, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_MultiLevel_StringValueTracked verifies that string
// values are also tracked by DefaultSizeFunc.
func TestCACHE_R12001_MultiLevel_StringValueTracked(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 1000, DefaultSizeFunc)
	c.Put("k", "hello world", 0)
	if c.MemoryUsage() != 11 {
		t.Errorf("expected 11 for string, got %d", c.MemoryUsage())
	}
}

// TestCACHE_R12001_MultiLevel_NonByteValueNotTracked verifies that
// types not handled by DefaultSizeFunc (e.g., int) don't count toward
// memory, but are still subject to count-based eviction.
func TestCACHE_R12001_MultiLevel_NonByteValueNotTracked(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(2, 100, DefaultSizeFunc)
	c.Put("k1", 42, 0)
	c.Put("k2", 99, 0)
	// Memory = 0 (int not tracked), count = 2.
	if c.MemoryUsage() != 0 {
		t.Errorf("expected 0 for int values, got %d", c.MemoryUsage())
	}
	// 3rd put triggers count-based eviction.
	c.Put("k3", 100, 0)
	if _, ok := c.Get("k1"); ok {
		t.Error("k1 should have been evicted by count-based LRU")
	}
}

// TestCACHE_R12001_MultiLevel_MemoryDoesNotUnderflow verifies that
// memory tracking never goes negative (defensive clamp).
func TestCACHE_R12001_MultiLevel_MemoryDoesNotUnderflow(t *testing.T) {
	c := NewLRUCacheWithMemoryLimit(10, 1000, DefaultSizeFunc)
	c.Put("k", make([]byte, 100), 0)
	// Simulate a bug by manually corrupting currentMemory.
	c.mu.Lock()
	c.currentMemory = 50 // less than actual entry size
	c.mu.Unlock()
	c.Delete("k")
	if c.MemoryUsage() != 0 {
		t.Errorf("after delete with underflow, expected 0 (clamped), got %d", c.MemoryUsage())
	}
}

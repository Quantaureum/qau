// Quantaureum Node source, version 1.0.0.
package cache

import (
	"testing"
	"time"
)

func TestNewLRUCache(t *testing.T) {
	c := NewLRUCache(10)
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.Len() != 0 {
		t.Errorf("expected 0, got %d", c.Len())
	}
}

func TestLRUPutGet(t *testing.T) {
	c := NewLRUCache(10)
	c.Put("key1", "value1", 0)

	v, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected to find key1")
	}
	if v != "value1" {
		t.Errorf("expected value1, got %v", v)
	}
}

func TestLRUGetNotFound(t *testing.T) {
	c := NewLRUCache(10)
	_, ok := c.Get("missing")
	if ok {
		t.Error("expected not found")
	}
}

func TestLRUGetExpired(t *testing.T) {
	c := NewLRUCache(10)
	c.Put("key1", "value1", 10*time.Millisecond)

	time.Sleep(20 * time.Millisecond)

	_, ok := c.Get("key1")
	if ok {
		t.Error("expected expired key to be not found")
	}
	if c.Len() != 0 {
		t.Errorf("expired item should be removed from cache, got %d", c.Len())
	}
}

func TestLRUEviction(t *testing.T) {
	c := NewLRUCache(2)
	c.Put("key1", "v1", 0)
	c.Put("key2", "v2", 0)
	c.Put("key3", "v3", 0)

	if c.Len() != 2 {
		t.Errorf("expected 2 items, got %d", c.Len())
	}
	_, ok := c.Get("key1")
	if ok {
		t.Error("key1 should have been evicted")
	}
}

func TestLRUDelete(t *testing.T) {
	c := NewLRUCache(10)
	c.Put("key1", "v1", 0)
	c.Delete("key1")

	if c.Len() != 0 {
		t.Errorf("expected 0, got %d", c.Len())
	}
	_, ok := c.Get("key1")
	if ok {
		t.Error("expected not found after delete")
	}
}

func TestLRUClear(t *testing.T) {
	c := NewLRUCache(10)
	c.Put("k1", "v1", 0)
	c.Put("k2", "v2", 0)
	c.Clear()

	if c.Len() != 0 {
		t.Errorf("expected 0, got %d", c.Len())
	}
}

func TestLRUOverwrite(t *testing.T) {
	c := NewLRUCache(10)
	c.Put("key1", "v1", 0)
	c.Put("key1", "v2", 0)

	v, ok := c.Get("key1")
	if !ok || v != "v2" {
		t.Errorf("expected v2, got %v", v)
	}
	if c.Len() != 1 {
		t.Errorf("expected 1 item, got %d", c.Len())
	}
}

func TestDefaultMultiLevelCacheConfig(t *testing.T) {
	cfg := DefaultMultiLevelCacheConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.L1Capacity != 1000 {
		t.Errorf("expected 1000, got %d", cfg.L1Capacity)
	}
	if cfg.L2Capacity != 10000 {
		t.Errorf("expected 10000, got %d", cfg.L2Capacity)
	}
	if cfg.L3Capacity != 100000 {
		t.Errorf("expected 100000, got %d", cfg.L3Capacity)
	}
}

func TestNewMultiLevelCache(t *testing.T) {
	c := NewMultiLevelCache(nil)
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.Size() != 0 {
		t.Errorf("expected 0, got %d", c.Size())
	}
}

func TestMultiLevelPutHot(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.PutHot("key1", "value1")

	v, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected to find key")
	}
	if v != "value1" {
		t.Errorf("expected value1, got %v", v)
	}
}

func TestMultiLevelPutWarm(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.PutWarm("key1", "value1")

	v, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected to find key")
	}
	if v != "value1" {
		t.Errorf("expected value1, got %v", v)
	}
}

func TestMultiLevelPutCold(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.PutCold("key1", "value1")

	v, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected to find key")
	}
	if v != "value1" {
		t.Errorf("expected value1, got %v", v)
	}
}

func TestMultiLevelPromotion(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.PutCold("key1", "cold_value")

	v, ok := c.Get("key1")
	if !ok || v != "cold_value" {
		t.Errorf("expected cold_value, got %v", v)
	}

	v2, ok2 := c.l2.Get("key1")
	if !ok2 || v2 != "cold_value" {
		t.Error("cold value should be promoted to L2 after access from L3")
	}
}

func TestMultiLevelDelete(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.PutHot("key1", "v1")
	c.PutWarm("key1", "v1")
	c.PutCold("key1", "v1")
	c.Delete("key1")

	if c.Size() != 0 {
		t.Errorf("expected 0 items, got %d", c.Size())
	}
}

func TestMultiLevelClear(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.PutHot("k1", "v1")
	c.PutWarm("k2", "v2")
	c.PutCold("k3", "v3")
	c.Clear()

	if c.Size() != 0 {
		t.Errorf("expected 0, got %d", c.Size())
	}
	hits, misses, _ := c.Stats()
	if hits != 0 || misses != 0 {
		t.Error("stats should be reset after clear")
	}
}

func TestMultiLevelStats(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.PutHot("k1", "v1")
	c.Get("k1")
	c.Get("missing")

	hits, misses, hitRate := c.Stats()
	if hits != 1 {
		t.Errorf("expected 1 hit, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 miss, got %d", misses)
	}
	if hitRate != 0.5 {
		t.Errorf("expected 0.5, got %f", hitRate)
	}
}

func TestMultiLevelSize(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.PutHot("k1", "v1")
	c.PutWarm("k2", "v2")
	c.PutCold("k3", "v3")

	if c.Size() != 3 {
		t.Errorf("expected 3, got %d", c.Size())
	}
}

func TestMultiLevelPut_DefaultLevel(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.Put("k1", "v1", CacheLevel(99))

	v, ok := c.l1.Get("k1")
	if !ok || v != "v1" {
		t.Error("default level should put to L1")
	}
}

func TestMultiLevelStats_ZeroHitRate(t *testing.T) {
	c := NewMultiLevelCache(nil)
	c.Get("never_exists")
	c.Get("also_missing")

	hits, misses, hitRate := c.Stats()
	if hits != 0 {
		t.Errorf("expected 0 hits, got %d", hits)
	}
	if misses != 2 {
		t.Errorf("expected 2 misses, got %d", misses)
	}
	if hitRate != 0.0 {
		t.Errorf("expected hitRate 0, got %f", hitRate)
	}
}

func TestMultiLevelGet_Miss(t *testing.T) {
	c := NewMultiLevelCache(nil)
	v, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected miss")
	}
	if v != nil {
		t.Error("expected nil value")
	}

	hits, misses, _ := c.Stats()
	if hits != 0 {
		t.Errorf("expected 0 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 miss, got %d", misses)
	}
}

func TestLRU_EvictSingleElement(t *testing.T) {
	c := NewLRUCache(1)
	c.Put("only", "value", 0)
	c.Put("new", "replaced", 0)

	v, ok := c.Get("new")
	if !ok || v != "replaced" {
		t.Error("new key should exist")
	}

	_, ok = c.Get("only")
	if ok {
		t.Error("old key should be evicted")
	}
}

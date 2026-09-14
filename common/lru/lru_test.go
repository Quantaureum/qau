// Quantaureum Node source, version 1.0.0.
package lru

import (
	"testing"
)

func TestNew(t *testing.T) {
	c := New[string, int](100)
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.Len() != 0 {
		t.Errorf("expected 0 items, got %d", c.Len())
	}
	if c.MaxSize() != 100 {
		t.Errorf("expected max 100, got %d", c.MaxSize())
	}
}

func TestNew_ZeroSize(t *testing.T) {
	c := New[int, string](0)
	if c.MaxSize() != 100 {
		t.Errorf("expected default 100, got %d", c.MaxSize())
	}
}

func TestNew_NegativeSize(t *testing.T) {
	c := New[int, string](-1)
	if c.MaxSize() != 100 {
		t.Errorf("expected default 100, got %d", c.MaxSize())
	}
}

func TestPutAndGet(t *testing.T) {
	c := New[string, int](10)
	c.Put("a", 1)
	c.Put("b", 2)

	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Errorf("expected (1, true), got (%d, %v)", v, ok)
	}

	v, ok = c.Get("b")
	if !ok || v != 2 {
		t.Errorf("expected (2, true), got (%d, %v)", v, ok)
	}
}

func TestGet_NotFound(t *testing.T) {
	c := New[string, int](10)
	v, ok := c.Get("missing")
	if ok {
		t.Errorf("expected not found, got %d", v)
	}
}

func TestPut_Update(t *testing.T) {
	c := New[string, int](10)
	c.Put("a", 1)
	c.Put("a", 10)

	v, ok := c.Get("a")
	if !ok || v != 10 {
		t.Errorf("expected (10, true), got (%d, %v)", v, ok)
	}
	if c.Len() != 1 {
		t.Errorf("expected 1 item, got %d", c.Len())
	}
}

func TestPeek(t *testing.T) {
	c := New[string, int](10)
	c.Put("a", 1)
	c.Put("b", 2)

	v, ok := c.Peek("a")
	if !ok || v != 1 {
		t.Errorf("expected (1, true), got (%d, %v)", v, ok)
	}
	if c.Len() != 2 {
		t.Errorf("expected 2 items after peek, got %d", c.Len())
	}

	v, ok = c.Peek("missing")
	if ok {
		t.Errorf("expected not found, got %d", v)
	}
}

func TestRemove(t *testing.T) {
	c := New[string, int](10)
	c.Put("a", 1)
	c.Put("b", 2)

	if !c.Remove("a") {
		t.Error("expected true for remove")
	}
	if c.Len() != 1 {
		t.Errorf("expected 1 item, got %d", c.Len())
	}
	if c.Remove("missing") {
		t.Error("expected false for missing key")
	}
}

func TestContains(t *testing.T) {
	c := New[string, int](10)
	c.Put("a", 1)

	if !c.Contains("a") {
		t.Error("expected to contain 'a'")
	}
	if c.Contains("b") {
		t.Error("expected not to contain 'b'")
	}
}

func TestKeys(t *testing.T) {
	c := New[string, int](10)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	keys := c.Keys()
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}
	if keys[0] != "c" {
		t.Errorf("expected most recent 'c', got %s", keys[0])
	}
}

func TestClear(t *testing.T) {
	c := New[string, int](10)
	c.Put("a", 1)
	c.Put("b", 2)

	c.Clear()
	if c.Len() != 0 {
		t.Errorf("expected 0 items, got %d", c.Len())
	}
	if c.Contains("a") {
		t.Error("should not contain 'a' after clear")
	}
}

func TestEviction(t *testing.T) {
	c := New[int, int](3)
	c.Put(1, 100)
	c.Put(2, 200)
	c.Put(3, 300)
	c.Put(4, 400)

	if c.Len() != 3 {
		t.Errorf("expected 3 items, got %d", c.Len())
	}
	if c.Contains(1) {
		t.Error("key 1 should have been evicted (oldest)")
	}
	if !c.Contains(2) && !c.Contains(3) && !c.Contains(4) {
		t.Error("at least some newer keys should remain")
	}
}

func TestLRUOrder(t *testing.T) {
	c := New[int, int](3)
	c.Put(1, 100)
	c.Put(2, 200)
	c.Put(3, 300)

	c.Get(1)

	c.Put(4, 400)

	if c.Contains(2) {
		t.Error("key 2 should have been evicted (now least recent after key 1 access)")
	}
	if !c.Contains(1) {
		t.Error("key 1 should remain (was recently accessed)")
	}
}

func TestGetOrPut_Existing(t *testing.T) {
	c := New[string, int](10)
	c.Put("a", 1)

	v, existed := c.GetOrPut("a", 100)
	if !existed {
		t.Error("expected existed=true")
	}
	if v != 1 {
		t.Errorf("expected 1, got %d", v)
	}
}

func TestGetOrPut_New(t *testing.T) {
	c := New[string, int](10)

	v, existed := c.GetOrPut("b", 200)
	if existed {
		t.Error("expected existed=false")
	}
	if v != 200 {
		t.Errorf("expected 200, got %d", v)
	}
}

func TestMaxSize(t *testing.T) {
	c := New[int, int](50)
	if c.MaxSize() != 50 {
		t.Errorf("expected 50, got %d", c.MaxSize())
	}
}

func TestLen(t *testing.T) {
	c := New[int, int](10)
	if c.Len() != 0 {
		t.Errorf("expected 0, got %d", c.Len())
	}
	c.Put(1, 100)
	if c.Len() != 1 {
		t.Errorf("expected 1, got %d", c.Len())
	}
}

func TestPut_DuplicateKey(t *testing.T) {
	c := New[int, int](3)
	c.Put(1, 100)
	c.Put(2, 200)
	c.Put(3, 300)
	c.Put(2, 250)

	c.Put(4, 400)
	if c.Len() != 3 {
		t.Errorf("expected 3 items, got %d", c.Len())
	}
	if !c.Contains(2) {
		t.Error("key 2 should remain (updated, moved to front)")
	}
	if c.Contains(1) {
		t.Error("key 1 should be evicted (was least recent)")
	}
}

func TestGet_MovesToFront(t *testing.T) {
	c := New[int, int](3)
	c.Put(1, 100)
	c.Put(2, 200)
	c.Put(3, 300)
	c.Get(1)

	keys := c.Keys()
	if keys[0] != 1 {
		t.Errorf("key 1 should be most recent after Get, got %d", keys[0])
	}
}

func TestPeek_DoesNotMove(t *testing.T) {
	c := New[int, int](3)
	c.Put(1, 100)
	c.Put(2, 200)
	c.Put(3, 300)

	c.Peek(2)

	keys := c.Keys()
	if keys[0] != 3 {
		t.Errorf("key 3 should still be most recent after Peek(2), got %d", keys[0])
	}
}

func TestStringCache(t *testing.T) {
	c := New[string, string](5)
	c.Put("hello", "world")
	v, ok := c.Get("hello")
	if !ok || v != "world" {
		t.Errorf("expected world, got %s", v)
	}
}

func TestFloatCache(t *testing.T) {
	c := New[int, float64](5)
	c.Put(1, 3.14)
	v, ok := c.Get(1)
	if !ok || v != 3.14 {
		t.Errorf("expected 3.14, got %f", v)
	}
}

func TestStructCache(t *testing.T) {
	type Point struct{ X, Y int }
	c := New[string, Point](5)
	c.Put("origin", Point{0, 0})
	v, ok := c.Get("origin")
	if !ok || v.X != 0 || v.Y != 0 {
		t.Errorf("expected (0,0), got (%d,%d)", v.X, v.Y)
	}
}

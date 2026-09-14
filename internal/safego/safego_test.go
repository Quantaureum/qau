// Quantaureum Node source, version 1.0.0.
package safego

import (
	"sync"
	"testing"
	"time"
)

func TestGo_Normal(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	called := false
	Go(func() {
		defer wg.Done()
		called = true
	})
	wg.Wait()
	if !called {
		t.Error("function was not called")
	}
}

func TestGo_PanicRecovery(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		Go(func() {
			panic("test panic")
		})
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("test timed out - panic may not have been recovered")
	}
}

func TestGo_Multiple(t *testing.T) {
	var wg sync.WaitGroup
	counter := 0
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		Go(func() {
			defer wg.Done()
			mu.Lock()
			counter++
			mu.Unlock()
		})
	}
	wg.Wait()
	if counter != 10 {
		t.Errorf("expected 10, got %d", counter)
	}
}

func TestGo_NilFunction(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	Go(nil)
	go func() {
		time.Sleep(500 * time.Millisecond)
		wg.Done()
	}()
	wg.Wait()
}

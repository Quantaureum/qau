// Quantaureum Node source, version 1.0.0.
package jit

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type PrecompileEntry struct {
	CodeHash [32]byte
	Code     []byte
	Priority int
	AddedAt  time.Time
}

type PrecompileQueue struct {
	mu       sync.Mutex
	queue    []*PrecompileEntry
	maxSize  int
	compiler *JITCompiler
	stopCh   chan struct{}
	wg       sync.WaitGroup
	stopOnce sync.Once

	// R37-P3-22 FIX (2026-07-31): use atomic counters to eliminate the data
	// race between processOne() (worker goroutine) and Stats() (caller
	// goroutine). Previously both accessed precompiled/skipped without
	// synchronization.
	precompiled atomic.Uint64
	skipped     atomic.Uint64
}

func NewPrecompileQueue(compiler *JITCompiler, maxSize int) *PrecompileQueue {
	if maxSize <= 0 {
		maxSize = 128
	}
	return &PrecompileQueue{
		queue:    make([]*PrecompileEntry, 0, maxSize),
		maxSize:  maxSize,
		compiler: compiler,
		stopCh:   make(chan struct{}),
	}
}

func (q *PrecompileQueue) Enqueue(codeHash [32]byte, code []byte, priority int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, entry := range q.queue {
		if entry.CodeHash == codeHash {
			if priority > entry.Priority {
				entry.Priority = priority
			}
			return
		}
	}

	if q.compiler.Cache() != nil {
		if _, ok := q.compiler.Cache().Get(codeHash); ok {
			q.skipped.Add(1)
			return
		}
	}

	if len(q.queue) >= q.maxSize {
		minIdx := 0
		for i, entry := range q.queue {
			if entry.Priority < q.queue[minIdx].Priority {
				minIdx = i
			}
		}
		q.queue[minIdx] = &PrecompileEntry{
			CodeHash: codeHash,
			Code:     code,
			Priority: priority,
			AddedAt:  time.Now(),
		}
		return
	}

	q.queue = append(q.queue, &PrecompileEntry{
		CodeHash: codeHash,
		Code:     code,
		Priority: priority,
		AddedAt:  time.Now(),
	})
}

func (q *PrecompileQueue) Dequeue() *PrecompileEntry {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) == 0 {
		return nil
	}

	bestIdx := 0
	for i, entry := range q.queue {
		if entry.Priority > q.queue[bestIdx].Priority {
			bestIdx = i
		}
	}

	entry := q.queue[bestIdx]
	q.queue[bestIdx] = q.queue[len(q.queue)-1]
	q.queue = q.queue[:len(q.queue)-1]
	return entry
}

func (q *PrecompileQueue) Start(interval time.Duration) {
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Precompile queue worker panic: %v\n", r)
			}
		}()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				q.processOne()
			case <-q.stopCh:
				return
			}
		}
	}()
}

func (q *PrecompileQueue) processOne() {
	// QVM-L01 (R8 2026-07-19) FIX: Per-iteration panic recovery so a single
	// malicious byte-code triggering a panic in q.compiler.Compile cannot
	// kill the worker goroutine for the rest of the node's lifetime.
	// Previously the only recover() was at the goroutine level (Start), so
	// the first panic in Compile would terminate all future precompilation.
	var codeHash [32]byte
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Precompile queue processOne panic (entry codehash %x): %v\n",
				codeHash, r)
		}
	}()

	entry := q.Dequeue()
	if entry == nil {
		return
	}
	codeHash = entry.CodeHash

	_, err := q.compiler.Compile(entry.Code)
	if err == nil {
		q.precompiled.Add(1)
	}
}

func (q *PrecompileQueue) PrecompileBatch(codes [][]byte) int {
	count := 0
	for _, code := range codes {
		_, err := q.compiler.Compile(code)
		if err == nil {
			count++
		}
	}
	return count
}

func (q *PrecompileQueue) Stats() (precompiled, skipped uint64, queueLen int) {
	q.mu.Lock()
	queueLen = len(q.queue)
	q.mu.Unlock()
	return q.precompiled.Load(), q.skipped.Load(), queueLen
}

// Stop stops the precompile queue worker. It is safe to call multiple times;
// only the first call has effect.
// R37-P3-23 FIX (2026-07-31): use sync.Once to prevent panic on double-close
// of the stop channel.
func (q *PrecompileQueue) Stop() {
	q.stopOnce.Do(func() {
		close(q.stopCh)
	})
	q.wg.Wait()
}

func (q *PrecompileQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.queue)
}

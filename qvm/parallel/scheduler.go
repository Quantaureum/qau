// Quantaureum Node source, version 1.0.0.
// Package parallel implements Block-STM parallel transaction execution.
package parallel

import (
	"sync"
	"sync/atomic"
)

// TxStatus represents the status of a transaction.
type TxStatus int32

const (
	TxStatusPending TxStatus = iota
	TxStatusExecuting
	TxStatusExecuted
	TxStatusValidating
	TxStatusValidated
	TxStatusAborted
)

// TxState holds the state of a transaction during parallel execution.
type TxState struct {
	Status      int32 // atomic TxStatus
	Incarnation int32 // atomic incarnation number

	// Read set: keys read during execution
	ReadSet []ReadDescriptor

	// Write set: keys written during execution
	WriteSet []WriteDescriptor

	mu sync.Mutex
}

// Scheduler manages the execution order of transactions.
type Scheduler struct {
	numTxs int
	states []*TxState

	// Number of completed transactions
	completed int32

	// Dependency tracking
	dependencies sync.Map   // txIndex -> []int (dependent tx indices)
	depMu        sync.Mutex // R40-M3 FIX: protects dependency updates

	// Channels for coordination
	execCh   chan int
	validCh  chan int
	doneCh   chan struct{}
	doneOnce sync.Once
}

// NewScheduler creates a new scheduler for n transactions.
func NewScheduler(numTxs int) *Scheduler {
	states := make([]*TxState, numTxs)
	for i := range states {
		states[i] = &TxState{
			Status:      int32(TxStatusPending),
			Incarnation: 0,
		}
	}

	return &Scheduler{
		numTxs:  numTxs,
		states:  states,
		execCh:  make(chan int, numTxs),
		validCh: make(chan int, numTxs),
		doneCh:  make(chan struct{}),
	}
}

// Start initializes the scheduler and queues initial executions.
func (s *Scheduler) Start() {
	// Queue all transactions for execution
	for i := 0; i < s.numTxs; i++ {
		// QVM-M02 (R8 2026-07-19 FIX): Use non-blocking send with
		// doneCh escape. execCh is buffered to numTxs so this never
		// blocks under normal operation, but if Shutdown() is called
		// concurrently (e.g., test cleanup racing with Start) the
		// blocking send would deadlock. select-against-doneCh lets
		// the loop exit cleanly.
		select {
		case s.execCh <- i:
		case <-s.doneCh:
			return
		}
	}
}

// NextExecution returns the next transaction to execute.
// Returns -1 if no transaction is available.
func (s *Scheduler) NextExecution() int {
	for {
		select {
		case txIdx := <-s.execCh:
			state := s.states[txIdx]
			if atomic.CompareAndSwapInt32(&state.Status, int32(TxStatusPending), int32(TxStatusExecuting)) ||
				atomic.CompareAndSwapInt32(&state.Status, int32(TxStatusAborted), int32(TxStatusExecuting)) {
				return txIdx
			}
			// Transaction already being processed, loop to try again
			continue
		default:
			return -1
		}
	}
}

// NextValidation returns the next transaction to validate.
// Returns -1 if no transaction is available.
func (s *Scheduler) NextValidation() int {
	for {
		select {
		case txIdx := <-s.validCh:
			state := s.states[txIdx]
			if atomic.CompareAndSwapInt32(&state.Status, int32(TxStatusExecuted), int32(TxStatusValidating)) {
				return txIdx
			}
			// Transaction status changed, loop to try again
			continue
		default:
			return -1
		}
	}
}

// FinishExecution marks a transaction as executed.
func (s *Scheduler) FinishExecution(txIdx int, readSet []ReadDescriptor, writeSet []WriteDescriptor) {
	state := s.states[txIdx]

	state.mu.Lock()
	state.ReadSet = readSet
	state.WriteSet = writeSet
	state.mu.Unlock()

	atomic.StoreInt32(&state.Status, int32(TxStatusExecuted))

	// Queue for validation.
	// QVM-M02 (R8 2026-07-19 FIX): Use non-blocking send against
	// doneCh. validCh is buffered to numTxs so this never blocks under
	// normal operation, but if all validators have exited (e.g.,
	// parent executor shutdown race) the blocking send would deadlock
	// FinishExecution's caller. Selecting against doneCh lets the
	// send exit cleanly when all txs are already complete (doneCh
	// closed by FinishValidation) — in that case the validation queue
	// is being drained / torn down and we don't need to enqueue.
	select {
	case s.validCh <- txIdx:
	case <-s.doneCh:
		return
	}
}

// FinishValidation marks a transaction as validated.
func (s *Scheduler) FinishValidation(txIdx int, valid bool) {
	state := s.states[txIdx]

	if valid {
		atomic.StoreInt32(&state.Status, int32(TxStatusValidated))
		newCompleted := atomic.AddInt32(&s.completed, 1)

		// Check if all transactions are complete
		if newCompleted == int32(s.numTxs) { //nolint:gosec,G115
			s.doneOnce.Do(func() {
				close(s.doneCh)
			})
		}
	} else {
		// Abort and re-execute
		s.AbortTransaction(txIdx)
	}
}

// AbortTransaction aborts a transaction and schedules re-execution.
// audit-fix R10-L2: uses iterative BFS instead of recursion to prevent stack overflow
// when dependency chains are long.
func (s *Scheduler) AbortTransaction(txIdx int) {
	// Use a queue for iterative cascading abort instead of recursion
	queue := []int{txIdx}
	visited := make(map[int]struct{})

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if _, seen := visited[current]; seen {
			continue
		}
		visited[current] = struct{}{}

		state := s.states[current]

		// If aborting a validated transaction, decrement the completed counter
		if TxStatus(atomic.LoadInt32(&state.Status)) == TxStatusValidated {
			atomic.AddInt32(&s.completed, -1)
		}

		// Increment incarnation
		atomic.AddInt32(&state.Incarnation, 1)

		// Clear read/write sets
		state.mu.Lock()
		state.ReadSet = nil
		state.WriteSet = nil
		state.mu.Unlock()

		atomic.StoreInt32(&state.Status, int32(TxStatusAborted))

		// Re-queue for execution.
		// QVM-M02 (R8 2026-07-19 FIX): Use non-blocking send against
		// doneCh. Cascading aborts can enqueue many items into execCh
		// (up to numTxs unique tx indices, plus potential duplicates
		// from re-aborts of the same tx across multiple validation
		// rounds). If execCh's buffer (size numTxs) is temporarily
		// full because the consumer is slow / shutdown, the blocking
		// send would deadlock AbortTransaction's caller (typically the
		// validator goroutine), stalling the entire scheduler.
		// Selecting against doneCh lets the send exit cleanly when all
		// txs are already complete (doneCh closed by FinishValidation).
		select {
		case s.execCh <- current:
		case <-s.doneCh:
			return
		}

		// Enqueue dependent transactions for abort
		// HIGH-4 FIX: Use atomic CAS to prevent race between status check and queue
		// Also explicitly set status to Aborted to ensure re-execution
		if deps, ok := s.dependencies.Load(current); ok {
			for _, depIdx := range deps.([]int) {
				depState := s.states[depIdx]
				status := TxStatus(atomic.LoadInt32(&depState.Status))
				// Only cascade abort to transactions that are not yet completed
				if status == TxStatusExecuted || status == TxStatusValidating || status == TxStatusValidated {
					// Atomically transition to Aborted to ensure re-execution
					// This prevents race where status changes between check and queue
					if atomic.CompareAndSwapInt32(&depState.Status, int32(status), int32(TxStatusAborted)) {
						// R36-P3-6 FIX (2026-07-30): If the dependent was
						// Validated, it had already incremented s.completed
						// (MarkValidated line 161). The top-of-loop decrement
						// (line 196) only runs for the queue head (current),
						// NOT for cascade-aborted dependents — so the completed
						// counter was left inflated, causing FinishValidation
						// to never fire (newCompleted never reaches numTxs) and
						// the scheduler to deadlock. Decrement here to mirror
						// the line-196 logic for cascade-aborted Validated txs.
						if status == TxStatusValidated {
							atomic.AddInt32(&s.completed, -1)
						}
						queue = append(queue, depIdx)
					}
				}
			}
		}
	}
}

// AddDependency records that txIdx depends on depIdx.
// R40-M3 FIX: Replace CAS-based approach with sync.Map + sync.Mutex.
// The previous CAS used slice value comparison via sync.Map.CompareAndSwap,
// which compares slice headers (pointer+len+cap) not contents. If another
// goroutine modifies the slice between Load and CAS, the update is lost.
func (s *Scheduler) AddDependency(txIdx, depIdx int) {
	s.depMu.Lock()
	defer s.depMu.Unlock()

	value, _ := s.dependencies.LoadOrStore(depIdx, []int{txIdx})
	deps := value.([]int)

	// Check if already present
	for _, d := range deps {
		if d == txIdx {
			return
		}
	}

	newDeps := make([]int, len(deps)+1)
	copy(newDeps, deps)
	newDeps[len(deps)] = txIdx
	s.dependencies.Store(depIdx, newDeps)
}

// GetState returns the state of a transaction.
func (s *Scheduler) GetState(txIdx int) *TxState {
	return s.states[txIdx]
}

// GetIncarnation returns the current incarnation of a transaction.
func (s *Scheduler) GetIncarnation(txIdx int) int {
	return int(atomic.LoadInt32(&s.states[txIdx].Incarnation))
}

// IsComplete returns true if all transactions are validated.
func (s *Scheduler) IsComplete() bool {
	return atomic.LoadInt32(&s.completed) == int32(s.numTxs) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// Done returns a channel that is closed when all transactions are complete.
func (s *Scheduler) Done() <-chan struct{} {
	return s.doneCh
}

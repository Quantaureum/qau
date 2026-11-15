// Quantaureum Node source, version 1.0.0.
package node

// Concurrency-semantics pinning tests for the networked signing request
// schedule (TSS-R3-B-1 cadence lever follow-up). The networked schedule
// submits every candidate slot CONCURRENTLY (one goroutine per candidate,
// first accepted signature wins and cancels the rest) — the reference
// in-process schedule is sequential, and these tests pin the networked
// schedule's concurrent shape so a future refactor cannot silently
// reintroduce a serial walk:
//
//   - candidates start concurrently: every candidate's Start() is entered
//     while all others are still in-flight (a serial walk deadlocks the
//     barrier and fails the test);
//   - first-win cleanup: when one candidate signs, the cancelled siblings'
//     parties are Finished (one-time material consumed) — no record leaks;
//   - per-candidate session identity: every candidate carries its own session
//     id (the slot index enters the derivation), so concurrent candidates
//     cannot share a session.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3ScheduleBarrierSlot wraps a scripted slot and blocks its Start
// until the barrier releases, so the test can observe whether all J
// candidates enter Start concurrently. A serial schedule deadlocks here.
type tdilithium3ScheduleBarrierSlot struct {
	inner   tdilithium3SigningSlot
	mu      *sync.Mutex
	entered *int
	release chan struct{}
}

func (slot *tdilithium3ScheduleBarrierSlot) Start() error {
	slot.mu.Lock()
	*slot.entered++
	slot.mu.Unlock()
	// Hold Start until the test releases the barrier (after it observed all
	// candidates entered): a serial walk would block candidate 1 forever
	// while the others are never built.
	<-slot.release
	return slot.inner.Start()
}

func (slot *tdilithium3ScheduleBarrierSlot) Drain() []dilithium3v1.SigningExecutorRoundMessage {
	return slot.inner.Drain()
}

func (slot *tdilithium3ScheduleBarrierSlot) Deliver(senderID uint32, kind uint16, payload []byte) error {
	return slot.inner.Deliver(senderID, kind, payload)
}

func (slot *tdilithium3ScheduleBarrierSlot) Done() bool {
	return slot.inner.Done()
}

func (slot *tdilithium3ScheduleBarrierSlot) Filtered() bool {
	return slot.inner.Filtered()
}

func (slot *tdilithium3ScheduleBarrierSlot) Finish() ([]byte, error) {
	return slot.inner.Finish()
}

// TestTDilithium3SigningScheduleCandidatesStartConcurrently pins the
// schedule's concurrent candidate submission: all J candidates enter Start()
// while the others are in-flight. A serial walk (one candidate at a time)
// would block the barrier and fail the wait below.
func TestTDilithium3SigningScheduleCandidatesStartConcurrently(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	var mu sync.Mutex
	entered := 0
	release := make(chan struct{})

	script := tdilithium3SigningScheduleTestScript{} // every slot stays in flight
	factory, _ := tdilithium3SigningScheduleTestFactory(t, script)
	// Wrap the scripted factory: every candidate's slot blocks in Start until
	// all candidates have entered (counted via entered/release).
	decorated := func(slot uint16) (
		tdilithium3SigningSlot, *tdilithium3SigningTransport, *tdilithium3SigningInbox, error,
	) {
		innerSlot, transport, inbox, err := factory(slot)
		if err != nil {
			return nil, nil, nil, err
		}
		return &tdilithium3ScheduleBarrierSlot{
			inner: innerSlot, mu: &mu, entered: &entered, release: release,
		}, transport, inbox, nil
	}

	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(
		node, decorated, dilithium3v1.SigningParallelSlots, 300*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, runErr := schedule.run(context.Background())
		done <- runErr
	}()

	// Wait until EVERY candidate has entered Start while blocked on the
	// barrier — impossible under a serial walk (candidate 1 would hold it
	// forever) — then release. Every candidate starves at its (short)
	// deadline; the request ends exhausted, the scripted all-in-flight
	// outcome.
	if !waitForScheduleBarrier(&mu, &entered, dilithium3v1.SigningParallelSlots, 5*time.Second) {
		mu.Lock()
		got := entered
		mu.Unlock()
		t.Fatalf("only %d candidates entered Start concurrently within the wait (serial walk?)", got)
	}
	close(release)
	select {
	case runErr := <-done:
		t.Logf("request ended: %v", runErr)
		if runErr == nil {
			t.Fatal("an all-in-flight window produced a signature")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the request did not end after the barrier release")
	}

	mu.Lock()
	total := entered
	mu.Unlock()
	if total != dilithium3v1.SigningParallelSlots {
		t.Fatalf("%d candidates entered Start, want %d", total, dilithium3v1.SigningParallelSlots)
	}
}

// waitForScheduleBarrier polls the shared entered counter until it reaches
// the committee's parallel-slot count, or the timeout elapses.
func waitForScheduleBarrier(mu *sync.Mutex, entered *int, want int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := *entered
		mu.Unlock()
		if got >= want {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestTDilithium3SigningScheduleFirstWinFinishesCancelledCandidates pins the
// first-win cleanup: when the last candidate accepts, the cancelled siblings
// (still in flight) are starved by the cancellation and their parties are
// Finished — the one-time material is consumed, nothing leaks.
func TestTDilithium3SigningScheduleFirstWinFinishesCancelledCandidates(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	const totalSlots = 5
	acceptAt := uint16(totalSlots) // the LAST candidate accepts

	script := tdilithium3SigningScheduleTestScript{acceptAt: acceptAt}
	factory, built := tdilithium3SigningScheduleTestFactory(t, script)

	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	schedule, err := newTDilithium3SigningRequestSchedule(node, factory, totalSlots, 2*time.Second)
	if err != nil {
		t.Fatalf("schedule: %v", err)
	}
	signature, _, runErr := schedule.run(context.Background())
	if runErr != nil {
		t.Fatalf("run: %v", runErr)
	}
	if len(signature) == 0 {
		t.Fatal("the accepting candidate returned no signature")
	}

	stubs := *built
	if len(stubs) != totalSlots {
		t.Fatalf("%d candidates built, want %d", len(stubs), totalSlots)
	}
	winner := stubs[acceptAt-1]
	if winner.wasBurned() {
		t.Fatal("the winning candidate's material was burned")
	}
	// The schedule returns on first-win while the cancelled siblings are
	// still draining their contexts; their drivers starve-and-Finish a
	// moment later. Poll for the cleanup instead of asserting it
	// synchronously — a permanent failure here would be a material leak.
	if !waitFor(2*time.Second, func() bool {
		for index, stub := range stubs {
			if index == int(acceptAt)-1 {
				continue
			}
			if !stub.wasStarted() {
				return false
			}
			if !stub.wasBurned() {
				return false
			}
		}
		return true
	}) {
		for index, stub := range stubs {
			if !stub.wasStarted() {
				t.Fatalf("cancelled candidate %d never started", index+1)
			}
			if !stub.wasBurned() {
				t.Fatalf("cancelled candidate %d was not Finished (material leak)", index+1)
			}
		}
	}
}

// TestTDilithium3SigningScheduleSessionIDsUniquePerCandidate pins the
// per-candidate session identity: every candidate slot derives its own
// session id (the slot index enters the derivation), so concurrent candidates
// cannot share a session, and the schedule carries no cross-candidate state
// that a shared id could corrupt.
func TestTDilithium3SigningScheduleSessionIDsUniquePerCandidate(t *testing.T) {
	const totalSlots = 5
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	script := tdilithium3SigningScheduleTestScript{acceptAt: 1}
	factory, _ := tdilithium3SigningScheduleTestFactory(t, script)

	seen := make(map[[32]byte]uint16)
	for slot := uint16(1); slot <= totalSlots; slot++ {
		_, transport, _, err := factory(slot)
		if err != nil {
			t.Fatalf("candidate %d factory: %v", slot, err)
		}
		if transport == nil {
			t.Fatalf("candidate %d built no transport", slot)
		}
		sessionID := transport.context.SessionID
		if previous, duplicate := seen[sessionID]; duplicate {
			t.Fatalf("candidates %d and %d share session id %x", previous, slot, sessionID)
		}
		seen[sessionID] = slot
	}
}

// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// blockingReshareRunner implements both runner interfaces. RunDistributedReshare
// blocks until release is closed so tests can observe the state machine while
// a rotation is in flight.
type blockingReshareRunner struct {
	release chan struct{}
	started chan struct{}
	key     []byte
	err     error

	mu           sync.Mutex
	reshareCalls int
	gotOld       []int
	gotNew       []int
	gotThreshold int
}

func (r *blockingReshareRunner) RunDistributedDKG(epoch uint64, threshold, total int) ([]byte, error) {
	return r.key, nil
}

func (r *blockingReshareRunner) RunDistributedReshare(epoch uint64, oldIDs, newIDs []int, threshold int) ([]byte, error) {
	r.mu.Lock()
	r.reshareCalls++
	r.gotOld = append([]int(nil), oldIDs...)
	r.gotNew = append([]int(nil), newIDs...)
	r.gotThreshold = threshold
	first := r.reshareCalls == 1
	r.mu.Unlock()
	if first {
		close(r.started)
	}
	<-r.release
	return r.key, r.err
}

func (r *blockingReshareRunner) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reshareCalls
}

func newReshareTestCoordinator(t *testing.T, validators int) (*ValidatorSet, *ThreeChambersCoordinator, *ExecutiveChamber) {
	t.Helper()
	vs := createTestValidatorSet(t, validators)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	return vs, coordinator, coordinator.GetExecutiveChamber()
}

func waitForActive(executive *ExecutiveChamber, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if executive.IsActive() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return executive.IsActive()
}

// The epoch transition is called from the block production and import paths
// under the node lock, so a rotation must never block it. The chamber must
// stay in DKGRunning until the rotation finishes, the slot-tick completion
// path must not activate it in the meantime, and the holder set must follow
// the committee.
func TestTransitionExecutiveForEpoch_ReshareRunsAsynchronously(t *testing.T) {
	vs, coordinator, executive := newReshareTestCoordinator(t, 10) // executive size 2
	key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	runner := &blockingReshareRunner{release: make(chan struct{}), started: make(chan struct{}), key: key}
	coordinator.SetRequireDistributedDKG(true)
	coordinator.SetDistributedDKGRunner(runner)

	start := time.Now()
	if err := coordinator.TransitionExecutiveForEpoch(1, vs, key); err != nil {
		t.Fatalf("TransitionExecutiveForEpoch: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("TransitionExecutiveForEpoch blocked for %v while the rotation ran", elapsed)
	}

	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("reshare runner was not invoked")
	}
	if executive.IsActive() {
		t.Fatal("executive chamber activated before the rotation finished")
	}
	if executive.State() != ExecutiveDKGRunning {
		t.Fatalf("executive state = %v, want DKGRunning while rotation is in flight", executive.State())
	}
	if coordinator.CompleteDKGViaDistributedRunner(1) {
		t.Fatal("CompleteDKGViaDistributedRunner activated the chamber during a rotation")
	}
	if epoch, inFlight := coordinator.ReshareInFlight(); !inFlight || epoch != 1 {
		t.Fatalf("ReshareInFlight = (%d, %v), want (1, true)", epoch, inFlight)
	}

	members := executive.Members()
	if len(members) != 2 {
		t.Fatalf("executive members = %v, want 2 members for 10 validators", members)
	}
	wantNew := make([]int, len(members))
	for i, m := range members {
		wantNew[i] = m + 1
	}
	runner.mu.Lock()
	gotOld, gotNew, gotThreshold := runner.gotOld, runner.gotNew, runner.gotThreshold
	runner.mu.Unlock()
	if len(gotOld) != 10 || gotOld[0] != 1 || gotOld[9] != 10 {
		t.Fatalf("old holder set = %v, want 1..10 (genesis DKG set)", gotOld)
	}
	if !sameParticipantSet(gotNew, wantNew) {
		t.Fatalf("new holder set = %v, want committee %v", gotNew, wantNew)
	}
	if gotThreshold != 2 {
		t.Fatalf("threshold = %d, want 2", gotThreshold)
	}

	close(runner.release)
	if !waitForActive(executive, 5*time.Second) {
		t.Fatal("executive chamber not activated after the rotation finished")
	}
	if !sameParticipantSet(coordinator.HolderParticipantIDs(), wantNew) {
		t.Fatalf("tracked holders = %v, want %v", coordinator.HolderParticipantIDs(), wantNew)
	}
	if _, inFlight := coordinator.ReshareInFlight(); inFlight {
		t.Fatal("rotation still reported in flight after completion")
	}
	// Same epoch again (import path after production path): idempotent.
	if err := coordinator.TransitionExecutiveForEpoch(1, vs, key); err != nil {
		t.Fatalf("second TransitionExecutiveForEpoch: %v", err)
	}
	if runner.calls() != 1 {
		t.Fatalf("reshare runner called %d times, want 1", runner.calls())
	}
}

func TestTriggerDKGRefusesWhileReshareIsInFlight(t *testing.T) {
	vs, coordinator, executive := newReshareTestCoordinator(t, 10)
	key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	runner := &blockingReshareRunner{release: make(chan struct{}), started: make(chan struct{}), key: key}
	defer close(runner.release)
	coordinator.SetRequireDistributedDKG(false)
	coordinator.SetDistributedDKGRunner(runner)

	if err := coordinator.TransitionExecutiveForEpoch(1, vs, key); err != nil {
		t.Fatalf("TransitionExecutiveForEpoch: %v", err)
	}
	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("reshare runner was not invoked")
	}

	if coordinator.TriggerDKG(key) {
		t.Fatal("TriggerDKG activated the chamber while reshare was in flight")
	}
	if executive.IsActive() {
		t.Fatal("executive chamber activated before reshare completed")
	}
}

// A failed rotation in distributed mode must leave the chamber pending for the
// epoch: neither the transition nor the slot-tick completion path may activate
// a committee that does not hold shares.
func TestTransitionExecutiveForEpoch_ReshareFailureKeepsChamberPending(t *testing.T) {
	vs, coordinator, executive := newReshareTestCoordinator(t, 10)
	key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	release := make(chan struct{})
	close(release)
	runner := &blockingReshareRunner{release: release, started: make(chan struct{}), key: nil, err: errors.New("peers unreachable")}
	coordinator.SetRequireDistributedDKG(true)
	coordinator.SetDistributedDKGRunner(runner)

	if err := coordinator.TransitionExecutiveForEpoch(1, vs, key); err != nil {
		t.Fatalf("TransitionExecutiveForEpoch: %v", err)
	}
	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("reshare runner was not invoked")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, inFlight := coordinator.ReshareInFlight(); !inFlight {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if executive.IsActive() {
		t.Fatal("executive chamber activated although the rotation failed")
	}
	if coordinator.CompleteDKGViaDistributedRunner(1) {
		t.Fatal("CompleteDKGViaDistributedRunner activated a committee whose rotation failed")
	}
}

// Small validator sets elect a one-member committee. A single holder cannot
// carry a threshold, so no rotation runs: the genesis holder set stays and
// the chamber is activated immediately with the existing group key.
func TestTransitionExecutiveForEpoch_SingleMemberCommitteeSkipsReshare(t *testing.T) {
	vs, coordinator, executive := newReshareTestCoordinator(t, 6) // executive size 1
	key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	release := make(chan struct{})
	close(release)
	runner := &blockingReshareRunner{release: release, started: make(chan struct{}), key: key}
	coordinator.SetRequireDistributedDKG(true)
	coordinator.SetDistributedDKGRunner(runner)

	if err := coordinator.TransitionExecutiveForEpoch(1, vs, key); err != nil {
		t.Fatalf("TransitionExecutiveForEpoch: %v", err)
	}
	if !executive.IsActive() {
		t.Fatal("executive chamber should activate immediately without a rotation")
	}
	if runner.calls() != 0 {
		t.Fatalf("reshare runner called %d times for a one-member committee, want 0", runner.calls())
	}
	if holders := coordinator.HolderParticipantIDs(); len(holders) != 0 {
		t.Fatalf("holder set = %v, want empty (genesis set)", holders)
	}
}

func TestEpochReshareRejectsUnsuccessfulResultWithoutProductionGate(t *testing.T) {
	currentKey := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	for _, test := range []struct {
		name string
		key  []byte
		err  error
	}{
		{name: "transport failure", err: errors.New("peer unavailable")},
		{name: "empty result"},
		{name: "changed group key", key: bytes.Repeat([]byte{0x43}, minGroupPublicKeyLen)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, coordinator, executive := newReshareTestCoordinator(t, 10)
			if err := executive.SetMembers([]int{0, 1}, 1); err != nil {
				t.Fatal(err)
			}
			release := make(chan struct{})
			close(release)
			runner := &blockingReshareRunner{release: release, started: make(chan struct{}), key: test.key, err: test.err}
			coordinator.SetRequireDistributedDKG(false)
			coordinator.SetDistributedDKGRunner(runner)
			coordinator.beginEpochReshare(1, []int{1, 2})
			coordinator.runEpochReshare(runner, 1, []int{1, 2, 3}, []int{1, 2}, 2, currentKey)
			if executive.IsActive() {
				t.Fatal("failed reshare activated a committee without valid replacement shares")
			}
			if coordinator.TriggerDKG(currentKey) || coordinator.CompleteDKGViaDistributedRunner(1) {
				t.Fatal("DKG completion bypassed the failed reshare")
			}
		})
	}
}

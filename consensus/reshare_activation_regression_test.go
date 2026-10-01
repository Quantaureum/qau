// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestReshareRepeatedTransitionCannotActivatePendingCommittee(t *testing.T) {
	validators, coordinator, executive := newReshareTestCoordinator(t, 10)
	key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	runner := &blockingReshareRunner{release: make(chan struct{}), started: make(chan struct{}), key: key}
	defer close(runner.release)
	coordinator.SetDistributedDKGRunner(runner)
	coordinator.SetRequireDistributedDKG(true)
	if err := coordinator.TransitionExecutiveForEpoch(1, validators, key); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("rotation did not start")
	}
	if holders := coordinator.HolderParticipantIDs(); len(holders) != 0 {
		t.Errorf("published uninstalled holders: %v", holders)
	}
	if err := coordinator.TransitionExecutiveForEpoch(1, validators, key); err != nil {
		t.Fatal(err)
	}
	if executive.IsActive() {
		t.Fatal("repeated transition bypassed the pending rotation")
	}
}

func TestReshareFailureCannotBeBypassedByEpochTransition(t *testing.T) {
	for _, nextEpoch := range []uint64{1, 2} {
		t.Run(fmt.Sprint(nextEpoch), func(t *testing.T) {
			validators, coordinator, executive := newReshareTestCoordinator(t, 10)
			coordinator.epochExecutive[1] = []int{0, 1}
			coordinator.epochExecutive[2] = []int{0, 1}
			key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
			release := make(chan struct{})
			close(release)
			runner := &blockingReshareRunner{release: release, started: make(chan struct{}), err: errors.New("delivery failed")}
			coordinator.SetDistributedDKGRunner(runner)
			coordinator.SetRequireDistributedDKG(true)
			if err := executive.SetMembers([]int{0, 1}, 1); err != nil {
				t.Fatal(err)
			}
			coordinator.holderParticipantIDs = []int{3, 4}
			if !coordinator.beginEpochReshare(1, []int{1, 2}) {
				t.Fatal("rotation did not start")
			}
			coordinator.runEpochReshare(runner, 1, []int{3, 4}, []int{1, 2}, 2, key)
			if !sameParticipantSet(coordinator.HolderParticipantIDs(), []int{3, 4}) {
				t.Error("failed rotation replaced committed holders")
			}
			if err := coordinator.TransitionExecutiveForEpoch(nextEpoch, validators, key); err != nil {
				t.Fatal(err)
			}
			if executive.Epoch() != 1 || executive.IsActive() {
				t.Fatal("epoch transition bypassed unresolved generation")
			}
			if coordinator.CompleteDKGViaDistributedRunner(nextEpoch) || coordinator.TriggerDKG(key) {
				t.Fatal("fallback completion bypassed failed generation")
			}
		})
	}
}

func TestReshareInFlightCannotBeSkippedByNewEpoch(t *testing.T) {
	validators, coordinator, executive := newReshareTestCoordinator(t, 10)
	coordinator.epochExecutive[2] = []int{4, 5}
	key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	runner := &blockingReshareRunner{release: make(chan struct{}), started: make(chan struct{}), key: key}
	defer close(runner.release)
	coordinator.SetDistributedDKGRunner(runner)
	coordinator.SetRequireDistributedDKG(true)
	if err := coordinator.TransitionExecutiveForEpoch(1, validators, key); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("rotation did not start")
	}
	if err := coordinator.TransitionExecutiveForEpoch(2, validators, key); err != nil {
		t.Fatal(err)
	}
	if executive.Epoch() != 1 {
		t.Fatal("new epoch displaced an unresolved rotation")
	}
	if coordinator.CompleteDKGViaDistributedRunner(2) {
		t.Fatal("new epoch activated without replacement shares")
	}
}

type delayedDKGCompletion struct {
	started chan struct{}
	release chan struct{}
	key     []byte
}

func (runner *delayedDKGCompletion) RunDistributedDKG(uint64, int, int) ([]byte, error) {
	close(runner.started)
	<-runner.release
	return runner.key, nil
}

func TestDKGCompletionRejectsResultAfterEpochChanges(t *testing.T) {
	_, coordinator, executive := newReshareTestCoordinator(t, 10)
	key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	runner := &delayedDKGCompletion{started: make(chan struct{}), release: make(chan struct{}), key: key}
	coordinator.SetDistributedDKGRunner(runner)
	if err := executive.SetMembers([]int{0, 1}, 1); err != nil {
		t.Fatal(err)
	}
	completed := make(chan bool, 1)
	go func() { completed <- coordinator.CompleteDKGViaDistributedRunner(1) }()
	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("DKG did not start")
	}
	if err := executive.SetMembers([]int{2, 3}, 2); err != nil {
		t.Fatal(err)
	}
	close(runner.release)
	select {
	case activated := <-completed:
		if activated || executive.IsActive() {
			t.Fatal("stale DKG result activated a different epoch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DKG completion blocked")
	}
}

func TestExecutiveTransitionCannotRollBackEpoch(t *testing.T) {
	validators, coordinator, executive := newReshareTestCoordinator(t, 6)
	coordinator.epochExecutive[2] = []int{0}
	key := bytes.Repeat([]byte{0x42}, minGroupPublicKeyLen)
	if err := coordinator.TransitionExecutiveForEpoch(2, validators, key); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.TransitionExecutiveForEpoch(1, validators, key); err != nil {
		t.Fatal(err)
	}
	if executive.Epoch() != 2 || !executive.IsActive() {
		t.Fatal("stale transition rolled back the active epoch")
	}
}

func TestRestoreHolderParticipantIDsValidatesCommittedSet(t *testing.T) {
	_, coordinator, _ := newReshareTestCoordinator(t, 10)
	if err := coordinator.RestoreHolderParticipantIDs([]int{7, 4}); err != nil {
		t.Fatal(err)
	}
	if !sameParticipantSet(coordinator.HolderParticipantIDs(), []int{4, 7}) {
		t.Fatalf("restored holders = %v", coordinator.HolderParticipantIDs())
	}
	if err := coordinator.RestoreHolderParticipantIDs([]int{4, 4}); err == nil {
		t.Fatal("duplicate holder set was accepted")
	}
	if !sameParticipantSet(coordinator.HolderParticipantIDs(), []int{4, 7}) {
		t.Fatal("invalid restore changed committed holders")
	}
	if !coordinator.beginEpochReshare(2, []int{1, 2}) {
		t.Fatal("rotation did not start")
	}
	if err := coordinator.RestoreHolderParticipantIDs([]int{1, 2}); err == nil {
		t.Fatal("holder restore replaced an in-flight generation")
	}
}

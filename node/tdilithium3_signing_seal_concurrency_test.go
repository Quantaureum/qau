// Quantaureum Node source, version 1.0.0.
package node

// The seal executor drives distinct slots' sessions concurrently: the node's
// authenticated inbox is keyed by session id, so several slots can be sealed at
// once without their messages crossing. An earlier design ran one session at a
// time on a single inbox field, so starting slot N+1 had to cancel slot N --
// which, on a twelve-second slot cadence, made a node abandon a slot its peers
// were still on and surfaced only as an unrelated-looking "missing commit".
//
// These tests require the acquire path to admit concurrent slots up to its
// bound and to never cancel another slot's session.

import (
	"context"
	"testing"
	"time"
)

// TestAcquireAdmitsConcurrentSlots requires two different slots to each hold a
// seal-signing permit at the same time, with neither cancelling the other. This
// is the property that lets a node keep finishing slot N while slot N+1 starts.
func TestAcquireAdmitsConcurrentSlots(t *testing.T) {
	node := &Node{}
	ctx := context.Background()

	firstCtx, firstCancel := context.WithCancel(ctx)
	defer firstCancel()
	secondCtx, secondCancel := context.WithCancel(ctx)
	defer secondCancel()
	node.tdilithium3SealSigningSessions = map[uint64]*tdilithium3SealSigningSession{
		100: {attempt: 0, cancel: firstCancel},
		112: {attempt: 0, cancel: secondCancel},
	}

	if !node.acquireTDilithium3SealSigning(firstCtx, 100) {
		t.Fatal("slot 100 could not take a seal-signing permit")
	}
	// The second slot must acquire without waiting on or cancelling the first.
	waiting, cancelWaiting := context.WithTimeout(ctx, time.Second)
	defer cancelWaiting()
	if !node.acquireTDilithium3SealSigning(waiting, 112) {
		t.Fatal("slot 112 could not take a concurrent seal-signing permit")
	}
	if firstCtx.Err() != nil {
		t.Fatal("acquiring slot 112 cancelled slot 100's session")
	}
	if secondCtx.Err() != nil {
		t.Fatal("acquiring slot 112 cancelled its own session")
	}
	node.releaseTDilithium3SealSigning()
	node.releaseTDilithium3SealSigning()
}

// TestAcquireBoundsConcurrency requires the permit count to cap goroutine
// fan-out: once the bound is taken, a further acquire blocks until a release,
// rather than running unbounded sessions.
func TestAcquireBoundsConcurrency(t *testing.T) {
	node := &Node{}
	ctx := context.Background()
	for slot := 0; slot < tdilithium3SealSigningMaxConcurrentSlots; slot++ {
		if !node.acquireTDilithium3SealSigning(ctx, uint64(slot)) {
			t.Fatalf("permit %d within the bound was refused", slot)
		}
	}
	// The next acquire must block: the bound is full.
	blocked, cancelBlocked := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelBlocked()
	if node.acquireTDilithium3SealSigning(blocked, uint64(tdilithium3SealSigningMaxConcurrentSlots)) {
		t.Fatal("acquire exceeded the concurrency bound")
	}
	// A release frees exactly one permit, which the next acquire then takes.
	node.releaseTDilithium3SealSigning()
	freed, cancelFreed := context.WithTimeout(ctx, time.Second)
	defer cancelFreed()
	if !node.acquireTDilithium3SealSigning(freed, uint64(tdilithium3SealSigningMaxConcurrentSlots)) {
		t.Fatal("a freed permit was not reusable")
	}
	for slot := 0; slot < tdilithium3SealSigningMaxConcurrentSlots; slot++ {
		node.releaseTDilithium3SealSigning()
	}
}

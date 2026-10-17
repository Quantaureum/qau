package node

import (
	"sync/atomic"
	"testing"

	"github.com/quantaureum/qau/encoding"
)

func r111bHeaderAt(height uint64) *encoding.BlockHeader {
	h := &encoding.BlockHeader{}
	h.Height = height
	h.Epoch = height / 32
	return h
}

// R111B-SNAP-FAIL-CLOSED (2026-10-18): reproduces the twice-observed mainnet
// incident where a snap session finished with a nil pivot header, the state-root
// verification was silently skipped, and the node permanently followed the chain
// on poisoned state (nonce walls at the first replayed transaction, R87 production
// lockout). The fix must treat a missing pivot header exactly like a root
// mismatch: abort the snap session, discard the session's imports, and force
// full sync so checkSync can never re-trigger snap for this gap.
func TestCompleteSnapSync_NilPivotHeaderFailsClosed(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1668)

	// Session state as observed in both incidents: a snap session is running
	// toward a target block, the pivot header never became available (the
	// block store had not reached the pivot and no skeleton header arrived).
	s.mu.Lock()
	s.snapSyncing = true
	s.snapTargetBlock = 251_047
	s.snapTargetHeader = nil
	s.mu.Unlock()
	if atomic.LoadInt32(&s.fullSyncMode) == 1 {
		t.Fatal("precondition: full sync mode must be off")
	}

	s.completeSnapSync()

	s.mu.RLock()
	stillSyncing := s.snapSyncing
	completed := s.snapSyncCompleted
	target := s.snapTargetBlock
	s.mu.RUnlock()

	if stillSyncing {
		t.Fatal("snap session must be aborted when the pivot header is missing")
	}
	if completed {
		t.Fatal("snapSyncCompleted must NOT be set: an unverified import is not a success")
	}
	if target == 0 {
		t.Fatal("sanity: snapTargetBlock should be preserved for diagnostics")
	}
	if atomic.LoadInt32(&s.fullSyncMode) != 1 {
		t.Fatal("full sync mode must be forced so checkSync cannot re-trigger snap")
	}
}

// With a pivot header present the guard must NOT fire: the session proceeds to
// the normal completion path (nil blockValidator harness skips the root compare,
// R62 advance is skipped by currentHeight >= target, and the session completes).
// Guards against over-tightening the fail-closed check.
func TestCompleteSnapSync_NilPivotHeaderGuardDoesNotFireWithHeader(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1668)

	s.mu.Lock()
	s.snapSyncing = true
	s.snapTargetBlock = 100
	s.snapTargetHeader = r111bHeaderAt(100)
	s.currentHeight = 100 // R62 advance already satisfied -> no blockStore access
	s.mu.Unlock()

	s.completeSnapSync()

	s.mu.RLock()
	completed := s.snapSyncCompleted
	stillSyncing := s.snapSyncing
	s.mu.RUnlock()

	if !completed {
		t.Fatal("a session WITH a pivot header must complete (snapSyncCompleted=true)")
	}
	if stillSyncing {
		t.Fatal("session must clear snapSyncing on the happy path")
	}
	if atomic.LoadInt32(&s.fullSyncMode) == 1 {
		t.Fatal("happy path must not force full sync")
	}
}

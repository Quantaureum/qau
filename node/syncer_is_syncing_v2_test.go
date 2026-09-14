// Quantaureum Node source, version 1.0.0.
package node

import (
	"sync/atomic"
	"testing"
)

// TestSyncer_IsSyncing_ActiveWithoutPeers verifies R38-Plan Batch 0.4:
// once an active sync session sets syncActive to 1, IsSyncing() reports
// true regardless of peer count. The earlier R38-SYNC FIX cleared the
// flag when peerCount==0, so `syncActive==1 with zero peers` was
// incorrectly reported as false — exactly the regression this test
// guards against.
//
// We rely only on IsSyncing's authoritative syncActive short-circuit,
// which returns before any nil-blockStore dereference. The assertion is
// therefore safe to run with the minimal NewSyncer(nil, ...).
func TestSyncer_IsSyncing_ActiveWithoutPeers(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	if s == nil {
		t.Fatal("expected non-nil Syncer")
	}
	// R38-Plan Batch 0.4 invariant: once syncActive==1, IsSyncing() must
	// return true before any downstream (peer/blockStore) predicate touches
	// — so a node that just lost all peers still reports the active sync
	// session, letting the block producer's own single-node grace path drive
	// recovery. The earlier R38-SYNC FIX cleared syncActive on peerCount==0,
	// reporting `syncActive==1 with zero peers` as false.
	atomic.StoreInt32(&s.syncActive, 1)
	if !s.IsSyncing() {
		t.Error("R38-Plan Batch 0.4: IsSyncing() should be true while syncActive==1 even with zero peers")
	}
	atomic.StoreInt32(&s.syncActive, 0)
}

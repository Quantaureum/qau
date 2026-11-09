package node

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p"
)

// TestRun4_StatusRateLimitAndDedup is the regression guard for the run-4 F-1
// mitigation: unauthenticated status frames must not be processable at line
// rate, and identical block-request ranges must not fan out on every frame.
// This is a mitigation, not authentication of the status source.
func TestRun4_StatusRateLimitAndDedup(t *testing.T) {
	s := &Syncer{}
	peer := p2p.PeerID("peer-1")
	t0 := time.Unix(1000, 0)

	if !s.allowPeerStatus(peer, t0) {
		t.Fatal("first status from a peer must be accepted")
	}
	if s.allowPeerStatus(peer, t0.Add(200*time.Millisecond)) {
		t.Fatal("second status within the per-peer interval must be dropped")
	}
	if !s.allowPeerStatus(peer, t0.Add(2*time.Second)) {
		t.Fatal("status after the per-peer interval must be accepted")
	}

	if !s.allowStatusRangeRequest(10, 20, t0) {
		t.Fatal("first request range must be issued")
	}
	if s.allowStatusRangeRequest(10, 20, t0.Add(5*time.Second)) {
		t.Fatal("identical request range inside the dedup window must be suppressed")
	}
	if !s.allowStatusRangeRequest(10, 21, t0.Add(5*time.Second)) {
		t.Fatal("a different range must still be issued")
	}
	if !s.allowStatusRangeRequest(10, 20, t0.Add(31*time.Second)) {
		t.Fatal("the same range must be issuable again after the dedup window")
	}
}

package p2p

import (
	"sync"
	"testing"
	"time"
)

// P2P-R31-PANIC regression: a concurrent broadcast while a peer is being torn
// down must never panic with "send on closed channel". The field incident:
// writeLoop's defer closed sendCh BEFORE the peer left h.peers, so broadcast
// (holding only RLock) iterated the map, found the dying peer, and sent on
// the closed channel — killing a mainnet validator process.
//
// With the R31 fix (closeSendCh no longer closes), this interleaving is
// structurally impossible; this test executes it anyway so a future change
// that reintroduces closure fails loudly here instead of in production.
func TestR31_BroadcastDuringTeardownDoesNotPanic(t *testing.T) {
	h := &Host{
		peers: make(map[PeerID]*Peer),
	}
	peer := &Peer{
		ID:        PeerID("crash-peer"),
		Connected: true,
		sendCh:    make(chan []byte, 1), // tiny buffer: fills immediately
		ctx:       nil,
	}
	h.peers[peer.ID] = peer

	var wg sync.WaitGroup
	stop := make(chan struct{})
	panicked := make(chan interface{}, 1)

	// Concurrent broadcaster: what the TSS signing driver does in production.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				// The exact production call shape (BroadcastTSS -> broadcast).
				_ = h.BroadcastTSS(97, []byte("payload"))
			}
		}
	}()

	// Concurrent teardown storm: closeSendCh + map removal, as readLoop's
	// and disconnectPeer's defers interleave in production.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { close(stop) }()
		for i := 0; i < 500; i++ {
			peer.closeSendCh()
			h.peersMu.Lock()
			delete(h.peers, peer.ID)
			h.peersMu.Unlock()
			h.peersMu.Lock()
			h.peers[peer.ID] = peer
			h.peersMu.Unlock()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case p := <-panicked:
		t.Fatalf("panic during broadcast/teardown race: %v", p)
	case <-time.After(10 * time.Second):
		t.Fatal("test hung: broadcast or teardown deadlocked")
	}
}

// The R31 retirement must be idempotent across concurrent callers (readLoop
// defer and disconnectPeer both invoke it in production).
func TestR31_CloseSendChIdempotentConcurrent(t *testing.T) {
	p := &Peer{sendCh: make(chan []byte, 4), ID: PeerID("once")}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); p.closeSendCh() }()
	}
	wg.Wait()
	// Channel must still be open and usable (no close under the new regime):
	select {
	case p.sendCh <- []byte("still-open"):
	default:
		t.Fatal("sendCh unexpectedly unusable after retirement")
	}
}

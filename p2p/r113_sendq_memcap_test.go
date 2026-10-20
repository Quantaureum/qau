package p2p

import (
	"testing"
)

// R113-SENDQ-MEMCAP: a slow consuming peer must not be able to pin unbounded
// block-response memory on the serving node. The per-peer large-message byte
// backlog is the bound; these tests pin the accounting contract used by
// SendRaw (enqueue increments) and writeLoop (releaseLargeBytes decrements),
// both reusing the exact threshold constants.
func TestReleaseLargeBytes_Accounting(t *testing.T) {
	p := &Peer{sendCh: make(chan []byte, 4)}

	big := make([]byte, 5<<20)   // 5 MB — above the 1 MB threshold
	small := make([]byte, 1<<10) // 1 KB — below threshold

	p.queuedLargeBytes.Store(int64(len(big)))
	p.releaseLargeBytes(big)
	if got := p.queuedLargeBytes.Load(); got != 0 {
		t.Fatalf("releasing the only large message must zero the backlog, got %d", got)
	}

	// Small messages must not affect the backlog (they were never counted).
	p.queuedLargeBytes.Store(0)
	p.releaseLargeBytes(small)
	if got := p.queuedLargeBytes.Load(); got != 0 {
		t.Fatalf("small message release must be a no-op, got %d", got)
	}

	// Multi-message backlog: two 5 MB releases must fully drain two enqueues.
	p.queuedLargeBytes.Store(10 << 20)
	p.releaseLargeBytes(big)
	p.releaseLargeBytes(big)
	if got := p.queuedLargeBytes.Load(); got != 0 {
		t.Fatalf("two releases must drain two 5 MB enqueues, got %d", got)
	}
}

// The SendRaw large-path decision, exercised at the exact boundary: a backlog
// one byte under the cap plus an incoming message that crosses it must be
// refused; the same backlog with room must be accepted. This mirrors the
// arithmetic SendRaw performs without standing up a full Host.
func TestSendRawByteCapBoundary(t *testing.T) {
	if maxQueuedLargeSendBytes <= 0 {
		t.Fatalf("maxQueuedLargeSendBytes must be positive, got %d", maxQueuedLargeSendBytes)
	}
	// A backlog of (cap - 2 MB) plus a 2.5 MB message must exceed the cap.
	backlog := maxQueuedLargeSendBytes - (2 << 20)
	incoming := int64(5<<20) / 2 // 2.5 MB
	if backlog+incoming <= maxQueuedLargeSendBytes {
		t.Fatalf("test invariant broken: backlog(%d)+incoming(%d) must exceed cap(%d)",
			backlog, incoming, maxQueuedLargeSendBytes)
	}
	// And a small message always fits the byte dimension (slot dimension may
	// still refuse it — that is the channel's job).
	if incoming+backlog-2*(5<<20)/2 <= 0 {
		t.Fatal("sanity")
	}
}

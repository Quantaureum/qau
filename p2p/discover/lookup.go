// Quantaureum Node source, version 1.0.0.
package discover

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/quantaureum/qau/p2p/enode"
)

const (
	alpha         = 3
	lookupTimeout = 30 * time.Second
	lookupRetries = 3
)

var errLookupClosed = errors.New("lookup closed")

type queryFunc func(*enode.Node) ([]*enode.Node, error)

type lookup struct {
	tab       *Table
	target    enode.ID
	queryFunc queryFunc

	asked map[enode.ID]bool
	seen  map[enode.ID]bool
	reply chan []*enode.Node

	result      nodesByDistance
	replyBuffer []*enode.Node
	queries     int

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
}

func NewLookup(ctx context.Context, tab *Table, target enode.ID, q queryFunc) *lookup {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	it := &lookup{
		tab:       tab,
		target:    target,
		queryFunc: q,
		asked:     make(map[enode.ID]bool),
		seen:      make(map[enode.ID]bool),
		result:    nodesByDistance{target: target},
		reply:     make(chan []*enode.Node, alpha),
		ctx:       ctx,
		cancel:    cancel,
	}

	it.asked[tab.selfID] = true
	it.seen[tab.selfID] = true

	closest := tab.findClosest(target, bucketSize)
	it.addNodes(closest)

	return it
}

func (it *lookup) Run() []*enode.Node {
	defer it.cancel()
	for it.advance() {
	}
	return it.result.entries
}

func (it *lookup) advance() bool {
	for it.startQueries() {
		select {
		case nodes := <-it.reply:
			it.mu.Lock()
			it.queries--
			it.mu.Unlock()
			it.addNodes(nodes)
		case <-it.ctx.Done():
			it.shutdown()
			return false
		}
	}

	it.mu.Lock()
	pending := it.queries
	it.mu.Unlock()
	for pending > 0 {
		select {
		case nodes := <-it.reply:
			it.mu.Lock()
			it.queries--
			pending = it.queries
			it.mu.Unlock()
			it.addNodes(nodes)
		case <-it.ctx.Done():
			it.shutdown()
			return false
		}
	}

	return len(it.replyBuffer) > 0
}

func (it *lookup) addNodes(nodes []*enode.Node) {
	it.mu.Lock()
	defer it.mu.Unlock()

	it.replyBuffer = it.replyBuffer[:0]
	for _, n := range nodes {
		if n != nil && !it.seen[n.ID()] {
			it.seen[n.ID()] = true
			it.result.push(n, bucketSize)
			it.replyBuffer = append(it.replyBuffer, n)
		}
	}
}

func (it *lookup) shutdown() {
	it.mu.Lock()
	defer it.mu.Unlock()

	if it.closed {
		return
	}
	it.closed = true

	for it.queries > 0 {
		<-it.reply
		it.queries--
	}
	it.queryFunc = nil
	it.replyBuffer = nil
}

func (it *lookup) startQueries() bool {
	it.mu.Lock()
	defer it.mu.Unlock()

	if it.queryFunc == nil || it.closed {
		return false
	}

	for i := 0; i < len(it.result.entries) && it.queries < alpha; i++ {
		n := it.result.entries[i]
		if !it.asked[n.ID()] {
			it.asked[n.ID()] = true
			it.queries++
			go it.query(n, it.reply)
		}
	}

	return it.queries > 0
}

func (it *lookup) query(n *enode.Node, reply chan<- []*enode.Node) {
	// CRIT-08 (R17, 2026-07-23): Short-lived per-node query goroutine
	// launched by lookup.advance. A panic in queryFunc or trackFailedQuery
	// would crash the node. The recover logs and sends nil to reply so the
	// lookup iterator doesn't block forever waiting for a response that
	// will never come. The lookup will treat nil as "no nodes found" and
	// continue with other candidates.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "discover lookup.query panic recovered (node=%s): %v\n", n.ID().String(), r)
			// Best-effort: send nil so the iterator advances. Use
			// non-blocking send with ctx fallback to avoid blocking
			// the recovering goroutine if reply is full.
			select {
			case reply <- nil:
			case <-it.ctx.Done():
			}
		}
	}()
	r, err := it.queryFunc(n)
	if err != nil && !errors.Is(err, errLookupClosed) {
		it.tab.trackFailedQuery(n.ID())
	}
	select {
	case reply <- r:
	case <-it.ctx.Done():
	}
}

type nodesByDistance struct {
	target  enode.ID
	entries []*enode.Node
}

func (h *nodesByDistance) push(n *enode.Node, maxElems int) {
	ix := sortSearch(len(h.entries), func(i int) bool {
		return DistanceCmp(h.target, h.entries[i].ID(), n.ID()) > 0
	})

	// R33 P2P-04 FIX (2026-07-28): If ix >= maxElems, the new node is farther
	// than all existing entries and the list is at capacity — skip it.
	// Without this check, copy(h.entries[ix+1:], ...) panics with
	// "slice bounds out of range" when ix == len(h.entries) == maxElems,
	// which can be triggered by a remote peer sending crafted node responses.
	if ix >= maxElems {
		return
	}

	if len(h.entries) < maxElems {
		h.entries = append(h.entries, n)
	}
	// Safe: ix < maxElems, and after potential append len(h.entries) <= maxElems.
	// ix+1 <= len(h.entries) in all reachable paths here.
	copy(h.entries[ix+1:], h.entries[ix:])
	h.entries[ix] = n

	if len(h.entries) > maxElems {
		h.entries = h.entries[:maxElems]
	}
}

func sortSearch(n int, f func(int) bool) int {
	i, j := 0, n
	for i < j {
		h := int(uint(i+j) >> 1)
		if !f(h) {
			i = h + 1
		} else {
			j = h
		}
	}
	return i
}

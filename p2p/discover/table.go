// Quantaureum Node source, version 1.0.0.
// Package discover implements the node discovery protocol based on Kademlia DHT.
package discover

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/p2p/enode"
)

const (
	// hashBits is the number of bits in a node ID
	hashBits = 256

	// nBuckets is the number of buckets in the routing table
	nBuckets = hashBits

	// bucketSize is the maximum number of nodes in a bucket
	bucketSize = 16

	// maxReplacements is the maximum number of replacement nodes per bucket
	maxReplacements = 10

	// udpProbeTimeout is the maximum time to wait for a bucket-eviction
	// probe (PING) response before declaring the oldest entry stale.
	// R32-P1-06 FIX (2026-07-28).
	udpProbeTimeout = 5 * time.Second
)

var (
	// ErrTableClosed is returned when operations are attempted on a closed table
	ErrTableClosed = errors.New("table closed")

	// ErrNodeNotFound is returned when a node is not found in the table
	ErrNodeNotFound = errors.New("node not found")

	// ErrSelfLookup is returned when trying to lookup our own node
	ErrSelfLookup = errors.New("cannot lookup self")
)

// Config holds the configuration for the discovery table
type Config struct {
	// SelfID is the ID of the local node
	SelfID enode.ID

	// BootstrapNodes are the initial nodes to connect to
	BootstrapNodes []*enode.Node

	// MaxNodes is the maximum number of nodes to store
	MaxNodes int

	// SkipIDValidation skips cryptographic ID validation (for scale testing only)
	SkipIDValidation bool
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxNodes: nBuckets * bucketSize,
	}
}

// bucket holds nodes with a specific distance range from the local node
type bucket struct {
	entries      []*enode.Node
	replacements []*enode.Node
	lastUpdated  time.Time
}

// Table is a Kademlia-like routing table for node discovery
type Table struct {
	mu      sync.RWMutex
	selfID  enode.ID
	buckets [nBuckets]*bucket
	closed  bool
	stopCh  chan struct{} // audit-fix: stop channel for reputationDecayLoop goroutine

	// Sybil attack protection
	reputationMgr *ReputationManager

	// Callbacks
	onNodeAdded   func(*enode.Node)
	onNodeRemoved func(*enode.Node)

	// R32-P1-06 FIX (2026-07-28): Pinger interface for bucket-eviction
	// probes. When set, a full bucket triggers a ping of the oldest entry;
	// if the ping fails (node offline/unreachable), the oldest entry is
	// evicted and the new node takes its place. If pinger is nil (tests /
	// not yet wired), falls back to adding to the replacements list.
	pinger Pinger

	// skipIDValidation skips crypto ID validation (for scale testing)
	skipIDValidation bool
}

// Pinger probes a node's liveness. Implemented by *UDPTransport.
// R32-P1-06 FIX (2026-07-28): Used by Table.addNode to evict stale
// entries from full buckets instead of silently dropping new nodes.
type Pinger interface {
	Ping(node *enode.Node) error
}

// NewTable creates a new discovery table
func NewTable(cfg *Config) (*Table, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	t := &Table{
		selfID:           cfg.SelfID,
		reputationMgr:    NewReputationManager(),
		stopCh:           make(chan struct{}),
		skipIDValidation: cfg.SkipIDValidation,
	}

	// Initialize buckets
	for i := range t.buckets {
		t.buckets[i] = &bucket{
			entries:      make([]*enode.Node, 0, bucketSize),
			replacements: make([]*enode.Node, 0, maxReplacements),
		}
	}

	// Start reputation decay goroutine
	go t.reputationDecayLoop()

	// Add bootstrap nodes (skip validation for bootstrap nodes, like Ethereum)
	for _, n := range cfg.BootstrapNodes {
		t.AddTrustedNode(n) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
	}

	return t, nil
}

// Self returns the local node ID
func (t *Table) Self() enode.ID {
	return t.selfID
}

// Close closes the table
func (t *Table) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	// Signal reputation decay goroutine to stop immediately
	close(t.stopCh)
}

// Len returns the total number of nodes in the table
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	count := 0
	for _, b := range t.buckets {
		count += len(b.entries)
	}
	return count
}

// AddNode adds a node to the table
func (t *Table) AddNode(n *enode.Node) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrTableClosed
	}

	return t.addNode(n)
}

// AddTrustedNode adds a trusted node to the table, skipping ENR signature validation.
// This is used for bootstrap peers and persisted nodes that are known to be valid.
// Like Ethereum, bootstrap nodes are trusted without full ENR verification.
func (t *Table) AddTrustedNode(n *enode.Node) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrTableClosed
	}

	if n == nil {
		return nil
	}

	// Don't add ourselves
	if n.ID() == t.selfID {
		return nil
	}

	// R33 P2P-05 FIX (2026-07-28): Reject unroutable IPs (bogon, private,
	// loopback, etc.) even for trusted nodes. Without this, a corrupted
	// persisted node file or misconfigured bootstrap list could inject
	// unroutable addresses into the routing table, wasting bucket slots
	// and potentially causing DHT routing failures.
	if ip := n.IP(); ip != nil && enode.IsUnroutableIP(ip) {
		return fmt.Errorf("node IP %s is unroutable", ip)
	}

	// Give initial reputation
	reputation := t.reputationMgr.GetReputation(n.ID())
	if reputation == 0 {
		t.reputationMgr.IncreaseReputation(n.ID(), MinReputationThreshold)
	}

	// Find the appropriate bucket
	bucketIdx := t.bucketIndex(n.ID())
	b := t.buckets[bucketIdx]

	// Check if node already exists
	for i, entry := range b.entries {
		if entry.ID() == n.ID() {
			// Move to front
			copy(b.entries[1:i+1], b.entries[:i])
			b.entries[0] = n
			b.lastUpdated = time.Now()
			return nil
		}
	}

	// Add to bucket if not full
	if len(b.entries) < bucketSize {
		b.entries = append([]*enode.Node{n}, b.entries...)
		b.lastUpdated = time.Now()
		if t.onNodeAdded != nil {
			t.onNodeAdded(n)
		}
		return nil
	}

	// Bucket is full, add to replacements
	for i, entry := range b.replacements {
		if entry.ID() == n.ID() {
			copy(b.replacements[1:i+1], b.replacements[:i])
			b.replacements[0] = n
			return nil
		}
	}

	if len(b.replacements) < maxReplacements {
		b.replacements = append([]*enode.Node{n}, b.replacements...)
	}

	return nil
}

// addNode adds a node without locking (internal use)
func (t *Table) addNode(n *enode.Node) error {
	if n == nil {
		return nil
	}

	// Don't add ourselves
	if n.ID() == t.selfID {
		return nil
	}

	// Validate node ID (skip for scale testing)
	if !t.skipIDValidation {
		if err := ValidateNodeID(n); err != nil {
			// Decrease reputation for invalid node ID
			t.reputationMgr.DecreaseReputation(n.ID(), 10)
			return fmt.Errorf("node validation failed: %w", err)
		}
	}

	// Check reputation threshold (allow bootstrap nodes to bypass)
	reputation := t.reputationMgr.GetReputation(n.ID())
	if reputation < MinReputationThreshold {
		// New nodes start with 0 reputation, give them initial credit
		if reputation == 0 {
			t.reputationMgr.IncreaseReputation(n.ID(), MinReputationThreshold)
		} else {
			return ErrInsufficientReputation
		}
	}

	// Check IP connection limits
	if n.IP() != nil {
		if err := t.reputationMgr.RecordIPConnection(n.IP().String()); err != nil {
			return err
		}
	}

	// Find the appropriate bucket
	bucketIdx := t.bucketIndex(n.ID())
	b := t.buckets[bucketIdx]

	// Check if node already exists
	for i, entry := range b.entries {
		if entry.ID() == n.ID() {
			// Move to front (most recently seen)
			copy(b.entries[1:i+1], b.entries[:i])
			b.entries[0] = n
			b.lastUpdated = time.Now()
			// Increase reputation for active nodes
			t.reputationMgr.IncreaseReputation(n.ID(), 1)
			return nil
		}
	}

	// Add to bucket if not full
	if len(b.entries) < bucketSize {
		b.entries = append([]*enode.Node{n}, b.entries...)
		b.lastUpdated = time.Now()
		if t.onNodeAdded != nil {
			t.onNodeAdded(n)
		}
		// Increase reputation for successfully added nodes
		t.reputationMgr.IncreaseReputation(n.ID(), 2)
		return nil
	}

	// R32-P1-06 FIX (2026-07-28): Bucket is full. Instead of silently
	// dropping the new node, probe the oldest entry (tail of b.entries).
	// If it doesn't respond, evict it and add the new node in its place.
	// This prevents stale/offline nodes from permanently occupying bucket
	// slots. The ping runs asynchronously to avoid blocking addNode (which
	// holds t.mu) on a multi-second network round-trip.
	if t.pinger != nil && len(b.entries) > 0 {
		oldest := b.entries[len(b.entries)-1]
		// Add to replacements first so the probe can promote it on success.
		alreadyInReplacements := false
		for i, entry := range b.replacements {
			if entry.ID() == n.ID() {
				copy(b.replacements[1:i+1], b.replacements[:i])
				b.replacements[0] = n
				alreadyInReplacements = true
				break
			}
		}
		if !alreadyInReplacements && len(b.replacements) < maxReplacements {
			b.replacements = append([]*enode.Node{n}, b.replacements...)
		}
		// Async probe: if oldest fails to respond, evict it and promote
		// the new node (or the most recent replacement) into entries.
		newNodeID := n.ID()
		go t.probeAndEvict(bucketIdx, oldest, newNodeID)
		return nil
	}

	// Bucket is full and no pinger configured — add to replacements
	for i, entry := range b.replacements {
		if entry.ID() == n.ID() {
			// Already in replacements, move to front
			copy(b.replacements[1:i+1], b.replacements[:i])
			b.replacements[0] = n
			return nil
		}
	}

	if len(b.replacements) < maxReplacements {
		b.replacements = append([]*enode.Node{n}, b.replacements...)
	}

	return nil
}

// probeAndEvict pings an oldest bucket entry; on failure, evicts it and
// promotes the most recent replacement node into the bucket.
// R32-P1-06 FIX (2026-07-28).
func (t *Table) probeAndEvict(bucketIdx int, oldest *enode.Node, candidateID enode.ID) {
	// Snapshot the pinger under the lock to avoid races with SetPinger(nil).
	t.mu.RLock()
	pinger := t.pinger
	t.mu.RUnlock()
	if pinger == nil {
		return
	}

	// Ping with a bounded timeout (defensive — Ping already has its own
	// timeout, but we add a safety net in case the implementation blocks).
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("ping panic: %v", r)
			}
		}()
		done <- pinger.Ping(oldest)
	}()

	select {
	case err := <-done:
		if err == nil {
			// Oldest is alive — keep it, no eviction.
			return
		}
	case <-time.After(udpProbeTimeout):
		// Treat as failure.
	}

	// Oldest failed to respond — evict and promote a replacement.
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	b := t.buckets[bucketIdx]
	// Verify the oldest is still the tail (it might have been moved or
	// removed by concurrent operations).
	if len(b.entries) == 0 || b.entries[len(b.entries)-1].ID() != oldest.ID() {
		return
	}
	// Evict the oldest.
	b.entries = b.entries[:len(b.entries)-1]
	if t.onNodeRemoved != nil {
		t.onNodeRemoved(oldest)
	}
	// Promote the most recent replacement (front of replacements slice) if
	// it's still the candidate. If a different node is at the front, prefer
	// the candidate by searching for it.
	promoted := false
	for i, rep := range b.replacements {
		if rep.ID() == candidateID {
			// Remove from replacements.
			b.replacements = append(b.replacements[:i], b.replacements[i+1:]...)
			// Add to entries.
			b.entries = append([]*enode.Node{rep}, b.entries...)
			b.lastUpdated = time.Now()
			if t.onNodeAdded != nil {
				t.onNodeAdded(rep)
			}
			promoted = true
			break
		}
	}
	if !promoted && len(b.replacements) > 0 {
		// Fall back to the front of replacements.
		rep := b.replacements[0]
		b.replacements = b.replacements[1:]
		b.entries = append([]*enode.Node{rep}, b.entries...)
		b.lastUpdated = time.Now()
		if t.onNodeAdded != nil {
			t.onNodeAdded(rep)
		}
	}
}

// RemoveNode removes a node from the table
func (t *Table) RemoveNode(id enode.ID) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrTableClosed
	}

	bucketIdx := t.bucketIndex(id)
	b := t.buckets[bucketIdx]

	// Find and remove from entries
	for i, entry := range b.entries {
		if entry.ID() == id {
			removed := b.entries[i]
			b.entries = append(b.entries[:i], b.entries[i+1:]...)

			// Promote a replacement if available
			if len(b.replacements) > 0 {
				b.entries = append(b.entries, b.replacements[0])
				b.replacements = b.replacements[1:]
			}

			// P3-P2P-01 FIX (R29, 2026-07-26): Wire ReleaseIPConnection
			// into the actual node removal path. Previously this method
			// was never called by the P2P layer, causing ipCounts and
			// subnetCounts in ReputationManager to only grow (relieved
			// only by hourly decayIPCounts). Now every node removal
			// releases its IP slot, so honest peers whose connections
			// drop are not artificially locked out by stale counters.
			if removed != nil {
				if ip := removed.IP(); ip != nil {
					t.reputationMgr.ReleaseIPConnection(ip.String())
				}
			}

			if t.onNodeRemoved != nil {
				t.onNodeRemoved(removed)
			}
			return nil
		}
	}

	// Also check replacements
	for i, entry := range b.replacements {
		if entry.ID() == id {
			b.replacements = append(b.replacements[:i], b.replacements[i+1:]...)

			// P3-P2P-01 FIX (R29, 2026-07-26): Release IP slot when a
			// replacement entry is removed too.
			if entry != nil {
				if ip := entry.IP(); ip != nil {
					t.reputationMgr.ReleaseIPConnection(ip.String())
				}
			}
			return nil
		}
	}

	return ErrNodeNotFound
}

// ReleaseIPConnection releases an IP connection slot in the reputation manager.
//
// FIX (2026-07-27): the earlier fix already invoked
// reputationMgr.ReleaseIPConnection on the removeNode path, but when a P2P-layer peer disconnects the discovery table entry
// is not necessarily removed, so the IP count only ever grows (with only decayIPCounts as a backstop).
// This method is exposed to the P2P Host for Peer.disconnectCleanup, ensuring active-connection teardown
// immediately releases the discovery-layer IP/subnet counts, preventing honest peers from being locked out by stale counters.
//
// addr accepts "host:port" / "[v6]:port" / bare-IP forms (compatible with net.SplitHostPort).
// If parsing fails the original string is passed through, and ReleaseIPConnection's internal ipToSubnet handles it.
func (t *Table) ReleaseIPConnection(addr string) {
	if t == nil || addr == "" {
		return
	}
	ip := addr
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		ip = host
	}
	t.reputationMgr.ReleaseIPConnection(ip)
}

// GetNode returns a node by ID
func (t *Table) GetNode(id enode.ID) (*enode.Node, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return nil, ErrTableClosed
	}

	bucketIdx := t.bucketIndex(id)
	b := t.buckets[bucketIdx]

	for _, entry := range b.entries {
		if entry.ID() == id {
			return entry, nil
		}
	}

	return nil, ErrNodeNotFound
}

// Resolve looks up a node by ID and returns it if found
func (t *Table) Resolve(n *enode.Node) *enode.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed || n == nil {
		return nil
	}

	bucketIdx := t.bucketIndex(n.ID())
	b := t.buckets[bucketIdx]

	for _, entry := range b.entries {
		if entry.ID() == n.ID() {
			return entry
		}
	}

	return nil
}

func (t *Table) ResolveID(target enode.ID) *enode.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return nil
	}

	bucketIdx := t.bucketIndex(target)
	b := t.buckets[bucketIdx]

	for _, entry := range b.entries {
		if entry.ID() == target {
			return entry
		}
	}

	return nil
}

func (t *Table) ReadRandomNodes(n int) []*enode.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var all []*enode.Node
	for _, b := range t.buckets {
		all = append(all, b.entries...)
	}

	if len(all) <= n {
		return all
	}

	// SECURITY: Use crypto/rand for shuffling instead of math/rand.
	// math/rand uses a predictable PRNG seed, which could allow attackers
	// to predict which nodes will be selected and manipulate peer selection.
	cryptoShuffle(len(all), func(i, j int) {
		all[i], all[j] = all[j], all[i]
	})

	return all[:n]
}

// cryptoRandUint32 reads 4 bytes from crypto/rand and returns the uint32 value.
// It retries up to 8 times on read error; returning (0, false) if all attempts fail.
func cryptoRandUint32() (uint32, bool) {
	var b [4]byte
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := cryptorand.Read(b[:]); err == nil {
			return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
		}
	}
	return 0, false
}

// cryptoShuffle shuffles a slice using crypto/rand for unpredictable randomization.
// This replaces math/rand.Shuffle which uses a deterministic PRNG.
//
// SECURITY (NW-09): This function never falls back to math/rand. If crypto/rand
// temporarily fails, the affected index is left un-swapped rather than introducing a
// predictable PRNG. Leaving an element in place does not leak any predictable state
// and merely reduces randomization quality for that single index.
func cryptoShuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		v, ok := cryptoRandUint32()
		if !ok {
			// crypto/rand unavailable: leave element i in place. Do NOT fall back
			// to math/rand (that was the NW-09 vulnerability) since doing so makes
			// peer selection predictable.
			continue
		}
		// Modular reduction with rejection sampling to avoid modulo bias.
		max := uint32(0xFFFFFFFF - (0xFFFFFFFF % (i + 1)))
		for v >= max {
			// Bias threshold exceeded: re-read from crypto/rand instead of
			// falling back to math/rand. Bounded retries avoid infinite loops.
			v, ok = cryptoRandUint32()
			if !ok {
				break
			}
		}
		if !ok {
			// Exhausted retries on rejection: skip swap for this index rather
			// than using a biased/predictable value.
			continue
		}
		j := int(v % uint32(i+1))
		swap(i, j)
	}
}

// Lookup returns the closest nodes to the target ID
func (t *Table) Lookup(target enode.ID) []*enode.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return nil
	}

	// Don't lookup ourselves
	if target == t.selfID {
		return nil
	}

	return t.closest(target, bucketSize)
}

// closest returns the n closest nodes to the target
func (t *Table) closest(target enode.ID, n int) []*enode.Node {
	// Collect all nodes
	var nodes []*enode.Node
	for _, b := range t.buckets {
		nodes = append(nodes, b.entries...)
	}

	// Sort by distance to target
	sort.Slice(nodes, func(i, j int) bool {
		return DistanceCmp(target, nodes[i].ID(), nodes[j].ID()) < 0
	})

	// Return at most n nodes
	if len(nodes) > n {
		nodes = nodes[:n]
	}

	return nodes
}

// Nodes returns all nodes in the table
func (t *Table) Nodes() []*enode.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.nodesLocked()
}

// nodesLocked returns all nodes without acquiring the lock.
// audit-fix R7-H1: extracted to prevent recursive RLock deadlock.
func (t *Table) nodesLocked() []*enode.Node {
	var nodes []*enode.Node
	for _, b := range t.buckets {
		nodes = append(nodes, b.entries...)
	}
	return nodes
}

// RandomNodes returns n random nodes from the table
func (t *Table) RandomNodes(n int) []*enode.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// audit-fix R7-H1: use nodesLocked instead of Nodes() to avoid recursive RLock deadlock
	nodes := t.nodesLocked()
	if len(nodes) <= n {
		return nodes
	}

	// Fisher-Yates shuffle
	for i := len(nodes) - 1; i > 0; i-- {
		j := randInt(i + 1)
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}

	return nodes[:n]
}

// bucketIndex returns the bucket index for a node ID
func (t *Table) bucketIndex(id enode.ID) int {
	d := logDistance(t.selfID, id)
	if d <= 0 {
		return 0
	}
	if d >= nBuckets {
		return nBuckets - 1
	}
	return d - 1
}

// SetNodeAddedCallback sets the callback for when a node is added
func (t *Table) SetNodeAddedCallback(cb func(*enode.Node)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onNodeAdded = cb
}

// SetNodeRemovedCallback sets the callback for when a node is removed
func (t *Table) SetNodeRemovedCallback(cb func(*enode.Node)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onNodeRemoved = cb
}

// SetPinger wires the bucket-eviction pinger.
// R32-P1-06 FIX (2026-07-28): When set, a full bucket will ping its oldest
// entry; if the ping fails, the entry is evicted and the new node is added.
// This prevents stale/offline nodes from permanently occupying bucket slots
// and blocking honest new nodes from joining the routing table.
func (t *Table) SetPinger(p Pinger) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pinger = p
}

// BucketInfo returns information about a specific bucket
func (t *Table) BucketInfo(idx int) (entries int, replacements int) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if idx < 0 || idx >= nBuckets {
		return 0, 0
	}

	b := t.buckets[idx]
	return len(b.entries), len(b.replacements)
}

// logDistance returns the logarithmic distance between two node IDs
// This is the position of the highest bit that differs
func logDistance(a, b enode.ID) int {
	for i := range a {
		x := a[i] ^ b[i]
		if x != 0 {
			// Find the highest bit set
			for j := 7; j >= 0; j-- {
				if x&(1<<j) != 0 {
					return (len(a)-1-i)*8 + j + 1
				}
			}
		}
	}
	return 0
}

// randInt returns a random integer in [0, n)
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 4)
	if _, err := cryptorand.Read(b); err != nil {
		return 0
	}
	return int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) % n
}

// DistanceCmp compares the distances of a and b to target
// Returns -1 if a is closer, 1 if b is closer, 0 if equal
func DistanceCmp(target, a, b enode.ID) int {
	for i := range target {
		da := a[i] ^ target[i]
		db := b[i] ^ target[i]
		if da < db {
			return -1
		}
		if da > db {
			return 1
		}
	}
	return 0
}

func (t *Table) findClosest(target enode.ID, n int) []*enode.Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var nodes []*enode.Node
	for _, b := range t.buckets {
		nodes = append(nodes, b.entries...)
	}

	sort.Slice(nodes, func(i, j int) bool {
		return DistanceCmp(target, nodes[i].ID(), nodes[j].ID()) < 0
	})

	if len(nodes) > n {
		nodes = nodes[:n]
	}
	return nodes
}

func (t *Table) trackFailedQuery(id enode.ID) {
	t.reputationMgr.DecreaseReputation(id, 5)
}

func (t *Table) UpdateNodeActivity(id enode.ID) {
	t.mu.Lock()
	defer t.mu.Unlock()

	bucketIdx := t.bucketIndex(id)
	b := t.buckets[bucketIdx]

	for i, entry := range b.entries {
		if entry.ID() == id {
			copy(b.entries[1:i+1], b.entries[:i])
			b.entries[0] = entry
			b.lastUpdated = time.Now()
			t.reputationMgr.IncreaseReputation(id, 1)
			return
		}
	}
}

func (t *Table) FindClosest(target enode.ID, n int) []*enode.Node {
	return t.findClosest(target, n)
}

type persistedNode struct {
	ID  string `json:"id"`
	IP  string `json:"ip"`
	TCP int    `json:"tcp"`
}

func (t *Table) SaveNodes(path string) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var nodes []persistedNode
	seen := make(map[enode.ID]bool)
	for _, b := range t.buckets {
		for _, n := range b.entries {
			if seen[n.ID()] {
				continue
			}
			seen[n.ID()] = true
			nodes = append(nodes, persistedNode{
				ID:  n.ID().Hex(),
				IP:  n.IP().String(),
				TCP: n.TCP(),
			})
		}
	}

	data, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	// AUDIT (2026) L-01 FIX: 0600 instead of 0644. The node table is
	// not secret material, but owner-only permissions align with every
	// other persistence path in the codebase and avoid leaking peer
	// topology to other local users.
	return os.WriteFile(path, data, 0600)
}

func (t *Table) LoadNodes(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var nodes []persistedNode
	if err := json.Unmarshal(data, &nodes); err != nil {
		return err
	}

	for _, pn := range nodes {
		var id enode.ID
		idBytes, err := hex.DecodeString(pn.ID)
		if err != nil || len(idBytes) != 32 {
			continue
		}
		copy(id[:], idBytes)

		ip := net.ParseIP(pn.IP)
		if ip == nil {
			continue
		}
		// R33 P2P-06 FIX (2026-07-28): Reject unroutable IPs from persisted
		// node files. A corrupted or tampered file could contain private/loopback
		// addresses that waste bucket slots and cause routing failures.
		if enode.IsUnroutableIP(ip) {
			continue
		}
		if pn.TCP <= 0 || pn.TCP > 65535 {
			continue
		}

		n := enode.NewNode(id, ip, pn.TCP, pn.TCP)
		// AUDIT (2026) R4-P2P-01 FIX: Use AddTrustedNode for persisted
		// nodes. Persisted nodes were already validated when first admitted,
		// so trusting them on reload is consistent with the doc comment on
		// AddTrustedNode ("persisted nodes that are known to be valid").
		// Previously, LoadNodes called AddNode, which runs ValidateNodeID —
		// and ValidateNodeID requires an ENR record that persisted nodes
		// lack (they only carry ID+IP+port). This caused every persisted
		// node to be rejected on restart, leaving only bootstrap nodes in
		// the routing table (eclipse risk).
		t.AddTrustedNode(n)
	}
	return nil
}

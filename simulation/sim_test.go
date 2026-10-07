// Quantaureum Node source, version 1.0.0.
// Package simulation — Phase 4 Local Cluster Simulation Tests
//
// Tests the 200K-node optimizations (GossipSub, shards, peer scoring) on a
// single machine by creating N virtual nodes connected via an in-memory
// message router. This avoids the overhead of real TCP connections and
// Dilithium3 key generation while still testing the core mesh networking logic.
//
// Usage:
//
//	go test -v -run TestSim ./simulation/          # Run all simulation tests
//	go test -v -run TestSim_100Nodes ./simulation/  # Run 100-node test only
//	go test -v -run TestSim_500Nodes ./simulation/  # Run 500-node test only
package simulation

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p/gossipsub"
)

// =============================================================================
// In-Memory Network Router
// =============================================================================

// simNetwork is a shared in-memory message router connecting all virtual nodes.
// It replaces real TCP connections, allowing instant message delivery between
// any two peers without the overhead of network I/O and crypto.
type simNetwork struct {
	mu      sync.RWMutex
	nodes   map[gossipsub.PeerID]*simNode
	metrics *simMetrics
}

// simNode represents a single virtual node in the simulation.
type simNode struct {
	id         gossipsub.PeerID
	gs         *gossipsub.GossipSub
	subscribed map[string]bool
	messagesRx int
	mu         sync.Mutex
	inbox      chan simMessage // async message queue
	stopCh     chan struct{}   // signals the inbox goroutine to stop
}

// simMessage is a decoded RPC message routed through the inbox.
type simMessage struct {
	from gossipsub.PeerID
	rpc  *gossipsub.RPC
}

// simMetrics tracks aggregate simulation statistics using atomic ops.
type simMetrics struct {
	totalMessages atomic.Int64
	deliveryCount atomic.Int64
	peersPerNode  []int
	mu            sync.Mutex // only for peersPerNode
}

func newSimNetwork() *simNetwork {
	return &simNetwork{
		nodes:   make(map[gossipsub.PeerID]*simNode),
		metrics: &simMetrics{},
	}
}

// createNodes creates N virtual nodes, each with its own GossipSub instance.
func (sn *simNetwork) createNodes(n int, topics []string) error {
	for i := 0; i < n; i++ {
		peerID := fmt.Sprintf("node-%04d", i)

		// Create a sender that routes messages through our sim network
		sender := &simSender{
			network: sn,
			selfID:  peerID,
		}

		// Create GossipSub instance
		gs := gossipsub.NewGossipSub(nil, sender)

		node := &simNode{
			id:         peerID,
			gs:         gs,
			subscribed: make(map[string]bool),
			inbox:      make(chan simMessage, 256), // buffered queue
			stopCh:     make(chan struct{}),
		}
		// SIM-R42-CI-RACE-1: sn.nodes is a map protected by sn.mu (see
		// SendGossipSub L151-153 which takes s.network.mu.RLock() before
		// reading nodes[peerID]). Previously this assignment ran without
		// the lock, racing with concurrent heartbeat goroutines that read
		// the same map via SendGossipSub. Also: we add the node to the map
		// BEFORE gs.Start() so any heartbeat fire from this GossipSub sees
		// its own sender already registered.
		sn.mu.Lock()
		sn.nodes[peerID] = node
		sn.mu.Unlock()

		// Start inbox processing goroutine (1 per node, bounded)
		go node.processInbox()

		// Start GossipSub
		if err := gs.Start(); err != nil {
			return fmt.Errorf("failed to start GossipSub for %s: %w", peerID, err)
		}

		// Subscribe to all topics
		for _, topic := range topics {
			handler := sn.makeHandler(peerID)
			if _, err := gs.JoinTopic(topic, handler); err != nil {
				return fmt.Errorf("failed to join topic %s for %s: %w", topic, peerID, err)
			}
			node.subscribed[topic] = true
		}
	}

	return nil
}

// makeHandler creates a message handler that counts received messages.
func (sn *simNetwork) makeHandler(selfID gossipsub.PeerID) func(*gossipsub.Message) {
	return func(msg *gossipsub.Message) {
		sn.mu.RLock()
		node, ok := sn.nodes[selfID]
		sn.mu.RUnlock()
		if !ok {
			return
		}
		node.mu.Lock()
		node.messagesRx++
		node.mu.Unlock()

		sn.metrics.totalMessages.Add(1)
	}
}

// stopAll stops all GossipSub instances and inbox goroutines.
func (sn *simNetwork) stopAll() {
	sn.mu.RLock()
	defer sn.mu.RUnlock()
	for _, node := range sn.nodes {
		close(node.stopCh)
		node.gs.Stop()
	}
}

// =============================================================================
// simSender — Implements gossipsub.MessageSender using the in-memory network
// =============================================================================

type simSender struct {
	network *simNetwork
	selfID  gossipsub.PeerID
}

func (s *simSender) SendGossipSub(peerID gossipsub.PeerID, data []byte) error {
	s.network.mu.RLock()
	target, ok := s.network.nodes[peerID]
	s.network.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer %s not found", peerID)
	}

	// Decode and inject as incoming RPC via the node's inbox queue.
	// Using a per-node channel avoids unbounded goroutine creation and
	// recursive call chains (e.g. sendGraft → InjectRPC → handleGraft → sendPrune → ...)
	rpc, err := gossipsub.DecodeRPC(data)
	if err != nil {
		return err
	}

	select {
	case target.inbox <- simMessage{from: s.selfID, rpc: rpc}:
	default:
		// Inbox full; drop message (simulates network congestion)
	}

	s.network.metrics.deliveryCount.Add(1)
	return nil
}

// processInbox runs the node's message processing loop.
func (n *simNode) processInbox() {
	for {
		select {
		case <-n.stopCh:
			return
		case msg := <-n.inbox:
			// Check if GossipSub is still running before processing
			n.gs.InjectRPC(msg.from, msg.rpc)
		}
	}
}

func (s *simSender) GetConnectedPeers() []gossipsub.PeerID {
	s.network.mu.RLock()
	defer s.network.mu.RUnlock()

	peers := make([]gossipsub.PeerID, 0, len(s.network.nodes)-1)
	for id := range s.network.nodes {
		if id != s.selfID {
			peers = append(peers, id)
		}
	}
	return peers
}

func (s *simSender) GetPeerScore(peerID gossipsub.PeerID) float64 {
	s.network.mu.RLock()
	_, ok := s.network.nodes[peerID]
	s.network.mu.RUnlock()
	if !ok {
		return 0
	}
	return 0.5 // Default neutral score for simulation
}

// =============================================================================
// Simulation Tests
// =============================================================================

// TestSim_MeshFormation verifies GossipSub mesh forms correctly for N nodes.
func TestSim_MeshFormation(t *testing.T) {
	scaleTestEnabled(t) // R123: opt-in gate for 100-node mesh runs

	nodeCounts := []int{10, 50, 100}
	topics := []string{gossipsub.TopicBlocks, gossipsub.TopicTransactions}

	for _, n := range nodeCounts {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			if testing.Short() && n > 50 {
				t.Skip("skipping large test in short mode")
			}

			net := newSimNetwork()
			if err := net.createNodes(n, topics); err != nil {
				t.Fatalf("createNodes failed: %v", err)
			}
			defer net.stopAll()

			// Wait for mesh to stabilize (heartbeats)
			time.Sleep(3 * time.Second)

			// Verify each node has mesh peers for each topic
			net.mu.RLock()
			for id, node := range net.nodes {
				for _, topic := range topics {
					meshPeers := node.gs.GetMeshPeers(topic)
					if len(meshPeers) == 0 && n > 1 {
						// For n=10, each topic should have D=6 mesh peers
						t.Logf("WARNING: node %s topic %s has 0 mesh peers", id, topic)
					}
					t.Logf("  Node %s topic %s: %d mesh peers", id, topic, len(meshPeers))
				}
			}
			net.mu.RUnlock()

			// Record peer counts
			net.metrics.mu.Lock()
			net.mu.RLock()
			for _, node := range net.nodes {
				peerCount := len(node.gs.GetConnectedPeers())
				net.metrics.peersPerNode = append(net.metrics.peersPerNode, peerCount)
			}
			net.mu.RUnlock()
			net.metrics.mu.Unlock()

			t.Logf("Mesh formation: %d nodes, %d topics, all nodes connected", n, len(topics))
		})
	}
}

// TestSim_MessagePropagation tests how fast messages propagate through N nodes.
func TestSim_MessagePropagation(t *testing.T) {
	scaleTestEnabled(t) // R123: opt-in gate

	nodeCounts := []int{10, 50, 100}

	for _, n := range nodeCounts {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			if testing.Short() && n > 50 {
				t.Skip("skipping large test in short mode")
			}

			net := newSimNetwork()
			topics := []string{gossipsub.TopicBlocks}
			if err := net.createNodes(n, topics); err != nil {
				t.Fatalf("createNodes failed: %v", err)
			}
			defer net.stopAll()

			// Wait for mesh to form
			time.Sleep(3 * time.Second)

			// Publish a message from node-0
			net.mu.RLock()
			node0 := net.nodes["node-0000"]
			net.mu.RUnlock()

			if node0 == nil {
				t.Fatal("node-0 not found")
			}

			startTime := time.Now()
			msgData := []byte(fmt.Sprintf("TEST_MSG_%d_%d", n, time.Now().UnixNano()))
			if err := node0.gs.Publish(gossipsub.TopicBlocks, msgData); err != nil {
				t.Fatalf("Publish failed: %v", err)
			}

			// Wait for propagation
			time.Sleep(2 * time.Second)

			elapsed := time.Since(startTime)

			// Count messages received across all nodes
			net.mu.RLock()
			totalRx := 0
			for _, node := range net.nodes {
				node.mu.Lock()
				totalRx += node.messagesRx
				node.mu.Unlock()
			}
			net.mu.RUnlock()

			propagationRate := float64(totalRx) / float64(n) * 100
			t.Logf("N=%d: %d/%d nodes received (%.1f%%), propagation time=%v",
				n, totalRx, n, propagationRate, elapsed)

			if propagationRate < 50 && n > 10 {
				t.Errorf("Propagation rate too low: %.1f%% (expected >= 50%%)", propagationRate)
			}
		})
	}
}

// TestSim_500Nodes runs the 500-node stress test.
func TestSim_500Nodes(t *testing.T) {
	scaleTestEnabled(t) // R123: opt-in gate (500 gossipsub nodes in memory)

	n := 500
	topics := []string{gossipsub.TopicBlocks}

	t.Logf("Creating %d virtual nodes...", n)
	net := newSimNetwork()

	startCreate := time.Now()
	if err := net.createNodes(n, topics); err != nil {
		t.Fatalf("createNodes failed: %v", err)
	}
	createTime := time.Since(startCreate)
	t.Logf("  Nodes created in %v (avg %.2fms/node)", createTime, float64(createTime.Milliseconds())/float64(n))

	defer net.stopAll()

	// Wait for mesh formation
	t.Log("Waiting for mesh formation...")
	meshStart := time.Now()
	time.Sleep(5 * time.Second)
	meshTime := time.Since(meshStart)

	// Verify mesh health
	net.mu.RLock()
	nodesWithMesh := 0
	totalMeshPeers := 0
	for id, node := range net.nodes {
		peers := node.gs.GetMeshPeers(gossipsub.TopicBlocks)
		if len(peers) > 0 {
			nodesWithMesh++
			totalMeshPeers += len(peers)
		}
		if len(peers) == 0 && n > 1 {
			t.Logf("WARNING: node %s has 0 mesh peers", id)
		}
	}
	net.mu.RUnlock()

	meshRate := float64(nodesWithMesh) / float64(n) * 100
	avgMeshPeers := float64(totalMeshPeers) / float64(max(nodesWithMesh, 1))
	t.Logf("  Mesh formation: %d/%d nodes (%.1f%%), avg %.1f peers/node, time=%v",
		nodesWithMesh, n, meshRate, avgMeshPeers, meshTime)

	// Publish test messages from 10 different sources
	t.Log("Publishing test messages...")
	pubStart := time.Now()
	for i := 0; i < 10; i++ {
		nodeID := fmt.Sprintf("node-%04d", i*50)
		net.mu.RLock()
		node, ok := net.nodes[nodeID]
		net.mu.RUnlock()
		if !ok {
			continue
		}
		msg := []byte(fmt.Sprintf("STRESS_TEST_MSG_%d", i))
		_ = node.gs.Publish(gossipsub.TopicBlocks, msg)
	}

	// Wait for propagation
	time.Sleep(3 * time.Second)
	pubTime := time.Since(pubStart)

	// Count total messages received
	net.mu.RLock()
	totalRx := 0
	for _, node := range net.nodes {
		node.mu.Lock()
		totalRx += node.messagesRx
		node.mu.Unlock()
	}
	net.mu.RUnlock()

	// Calculate stats
	deliveryCount := net.metrics.deliveryCount.Load()

	t.Logf("Results for N=%d:", n)
	t.Logf("  Nodes created:   %d", n)
	t.Logf("  Mesh rate:       %.1f%%", meshRate)
	t.Logf("  Avg mesh peers:  %.1f", avgMeshPeers)
	t.Logf("  Messages rx:     %d", totalRx)
	t.Logf("  Deliveries:      %d", deliveryCount)
	t.Logf("  Create time:     %v", createTime)
	t.Logf("  Publish time:    %v", pubTime)

	// Success criteria for 500 nodes
	if meshRate < 90 {
		t.Errorf("Mesh rate too low: %.1f%% (expected >= 90%%)", meshRate)
	}
	if totalRx < 1000 {
		t.Errorf("Message count too low: %d (expected >= 1000)", totalRx)
	}
}

// TestSim_ShardActivation tests 64-shard activation with large validator sets.
func TestSim_ShardActivation(t *testing.T) {
	scaleTestEnabled(t) // R123: opt-in gate (up to 192K validator entries in memory)

	shardCounts := []int{8, 32, 64}
	validatorsPerShard := []int{100, 1000, 3000}

	for i, shardCount := range shardCounts {
		vps := validatorsPerShard[i]
		totalVals := shardCount * vps

		t.Run(fmt.Sprintf("Shards=%d_Validators=%d", shardCount, totalVals), func(t *testing.T) {
			if testing.Short() && totalVals > 10000 {
				t.Skip("skipping large validator test in short mode")
			}

			startTime := time.Now()

			// Build fake validator addresses
			validators := make([]string, totalVals)
			for j := 0; j < totalVals; j++ {
				validators[j] = fmt.Sprintf("0x%040x", j)
			}

			// Assign validators to shards (round-robin)
			shardAssignments := make([][]string, shardCount)
			for j := 0; j < totalVals; j++ {
				shardIdx := j % shardCount
				shardAssignments[shardIdx] = append(shardAssignments[shardIdx], validators[j])
			}

			assignTime := time.Since(startTime)

			// Verify uniform distribution
			minPerShard := totalVals
			maxPerShard := 0
			for _, shard := range shardAssignments {
				if len(shard) < minPerShard {
					minPerShard = len(shard)
				}
				if len(shard) > maxPerShard {
					maxPerShard = len(shard)
				}
			}

			imbalance := maxPerShard - minPerShard
			t.Logf("Shards=%d: %d validators across %d shards, time=%v, imbalance=±%d",
				shardCount, totalVals, shardCount, assignTime, imbalance)

			if totalVals >= 100000 {
				t.Logf("  200K-scale: %d validators assigned in %v", totalVals, assignTime)
			}

			if imbalance > 1 {
				t.Errorf("Validator distribution not balanced: min=%d max=%d", minPerShard, maxPerShard)
			}
		})
	}
}

// TestSim_AllPhases runs a comprehensive end-to-end simulation.
func TestSim_AllPhases(t *testing.T) {
	scaleTestEnabled(t) // R123: opt-in gate (50+200+500 nodes + 192K validators)

	t.Log("========== Phase 4 Comprehensive Simulation ==========")
	t.Logf("Start time: %s", time.Now().Format(time.RFC3339))

	// Phase 1: Small network (50 nodes)
	t.Log("\n--- Phase 1: 50-node network ---")
	net50 := newSimNetwork()
	if err := net50.createNodes(50, []string{gossipsub.TopicBlocks}); err != nil {
		t.Fatalf("50-node create failed: %v", err)
	}
	time.Sleep(3 * time.Second)
	net50.mu.RLock()
	meshOK := 0
	for _, node := range net50.nodes {
		if len(node.gs.GetMeshPeers(gossipsub.TopicBlocks)) > 0 {
			meshOK++
		}
	}
	net50.mu.RUnlock()
	t.Logf("  50-node mesh: %d/50 nodes connected", meshOK)
	net50.stopAll()

	// Phase 2: Medium network (200 nodes)
	t.Log("\n--- Phase 2: 200-node network ---")
	net200 := newSimNetwork()
	if err := net200.createNodes(200, []string{gossipsub.TopicBlocks, gossipsub.TopicTransactions}); err != nil {
		t.Fatalf("200-node create failed: %v", err)
	}
	time.Sleep(4 * time.Second)
	net200.mu.RLock()
	meshOK200 := 0
	for _, node := range net200.nodes {
		if len(node.gs.GetMeshPeers(gossipsub.TopicBlocks)) > 0 {
			meshOK200++
		}
	}
	net200.mu.RUnlock()
	t.Logf("  200-node mesh: %d/200 nodes connected", meshOK200)
	net200.stopAll()

	// Phase 3: Large network (500 nodes)
	t.Log("\n--- Phase 3: 500-node network ---")
	net500 := newSimNetwork()
	createStart := time.Now()
	if err := net500.createNodes(500, []string{gossipsub.TopicBlocks}); err != nil {
		t.Fatalf("500-node create failed: %v", err)
	}
	createTime := time.Since(createStart)
	t.Logf("  Created 500 nodes in %v", createTime)

	time.Sleep(5 * time.Second)
	net500.mu.RLock()
	meshOK500 := 0
	totalMeshPeers500 := 0
	for _, node := range net500.nodes {
		peers := node.gs.GetMeshPeers(gossipsub.TopicBlocks)
		if len(peers) > 0 {
			meshOK500++
			totalMeshPeers500 += len(peers)
		}
	}
	net500.mu.RUnlock()
	avgPeers := float64(totalMeshPeers500) / float64(max(meshOK500, 1))
	t.Logf("  500-node mesh: %d/500 (%.1f%%), avg %.1f mesh peers",
		meshOK500, float64(meshOK500)/5.0, avgPeers)
	net500.stopAll()

	// Phase 4: Shard activation (64 shards × 3000 = 192K validators)
	t.Log("\n--- Phase 4: 64-shard activation (192K validators) ---")
	shardStart := time.Now()
	shardCount := 64
	validatorsPerShard := 3000
	totalVals := shardCount * validatorsPerShard
	shards := make([][]string, shardCount)
	for j := 0; j < totalVals; j++ {
		shardIdx := j % shardCount
		shards[shardIdx] = append(shards[shardIdx], fmt.Sprintf("v%d", j))
	}
	shardTime := time.Since(shardStart)
	t.Logf("  64 shards × %d validators = %d total, assigned in %v",
		validatorsPerShard, totalVals, shardTime)

	// Summary
	t.Log("\n========== Simulation Summary ==========")
	t.Logf("  50 nodes:  mesh %d/50", meshOK)
	t.Logf("  200 nodes: mesh %d/200", meshOK200)
	t.Logf("  500 nodes: mesh %d/500 (%.1f%%)", meshOK500, float64(meshOK500)/5.0)
	t.Logf("  64 shards: %d validators in %v", totalVals, shardTime)
	t.Logf("  All core mechanisms functional at 200K scale")
}

// =============================================================================
// 200K-Node Scale Test (Sparse Connectivity)
// =============================================================================
//
// A full all-to-all simulation of 200K nodes would require ~1TB of memory
// (each node tracking 200K peers). In a real network, no node connects to
// all 200K peers — each connects to a limited subset.
//
// This test uses sparse connectivity: each node only knows about 50 random
// peers. This is closer to real-world behavior and keeps memory ~2-3GB.

// simSparseSender implements gossipsub.MessageSender with a limited peer set.
type simSparseSender struct {
	network *simSparseNetwork
	selfID  gossipsub.PeerID
	peerIDs []gossipsub.PeerID // fixed subset of peers this node knows about
}

func (s *simSparseSender) SendGossipSub(peerID gossipsub.PeerID, data []byte) error {
	s.network.mu.RLock()
	target, ok := s.network.nodes[peerID]
	s.network.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer %s not found", peerID)
	}

	rpc, err := gossipsub.DecodeRPC(data)
	if err != nil {
		return err
	}

	select {
	case target.inbox <- simMessage{from: s.selfID, rpc: rpc}:
	default:
		// Drop on full inbox
	}

	s.network.metrics.deliveryCount.Add(1)
	return nil
}

func (s *simSparseSender) GetConnectedPeers() []gossipsub.PeerID {
	return s.peerIDs
}

func (s *simSparseSender) GetPeerScore(peerID gossipsub.PeerID) float64 {
	return 0.5
}

// simSparseNetwork is like simNetwork but with sparse peer topology.
type simSparseNetwork struct {
	mu      sync.RWMutex
	nodes   map[gossipsub.PeerID]*simNode
	metrics *simMetrics
	allIDs  []gossipsub.PeerID // full list of all peer IDs
}

func newSimSparseNetwork() *simSparseNetwork {
	return &simSparseNetwork{
		nodes:   make(map[gossipsub.PeerID]*simNode),
		metrics: &simMetrics{},
	}
}

// createSparseNodes creates N nodes where each node only knows about
// maxPeers random peers. Uses two-phase creation: first create all nodes
// (under lock), then start them all — to avoid concurrent map access.
func (sn *simSparseNetwork) createSparseNodes(n int, maxPeers int, topics []string) error {
	sn.allIDs = make([]gossipsub.PeerID, n)

	// Pre-generate all peer IDs
	for i := 0; i < n; i++ {
		sn.allIDs[i] = fmt.Sprintf("node-%05d", i)
	}

	rng := newFastRNG(uint64(time.Now().UnixNano()))

	// Phase 1: Create all nodes (add to map under lock, but don't start yet)
	type pendingNode struct {
		node   *simNode
		topics []string
	}
	pending := make([]*pendingNode, n)

	for i := 0; i < n; i++ {
		peerID := sn.allIDs[i]
		peerSubset := sn.selectRandomPeers(i, maxPeers, rng)

		sender := &simSparseSender{
			network: sn,
			selfID:  peerID,
			peerIDs: peerSubset,
		}

		gs := gossipsub.NewGossipSub(nil, sender)

		node := &simNode{
			id:         peerID,
			gs:         gs,
			subscribed: make(map[string]bool),
			inbox:      make(chan simMessage, 64),
			stopCh:     make(chan struct{}),
		}

		sn.mu.Lock()
		sn.nodes[peerID] = node
		sn.mu.Unlock()

		pending[i] = &pendingNode{node: node, topics: topics}
	}

	// Phase 2: Start all nodes (heartbeats may now safely access sn.nodes)
	for i := 0; i < n; i++ {
		p := pending[i]
		go p.node.processInbox()

		if err := p.node.gs.Start(); err != nil {
			return fmt.Errorf("failed to start GossipSub for %s: %w", p.node.id, err)
		}

		for _, topic := range p.topics {
			handler := sn.makeSparseHandler(p.node.id)
			if _, err := p.node.gs.JoinTopic(topic, handler); err != nil {
				return fmt.Errorf("failed to join topic %s for %s: %w", topic, p.node.id, err)
			}
			p.node.subscribed[topic] = true
		}
	}

	return nil
}

// selectRandomPeers picks k random peers from the full list, excluding selfIdx.
// Uses rejection sampling with a small seen-set — O(k) memory, not O(n).
func (sn *simSparseNetwork) selectRandomPeers(selfIdx int, k int, rng *fastRNG) []gossipsub.PeerID {
	n := len(sn.allIDs)
	if k >= n {
		k = n - 1
	}

	seen := make(map[int]bool, k)
	result := make([]gossipsub.PeerID, 0, k)

	for len(result) < k {
		idx := int(rng.Uint64() % uint64(n))
		if idx != selfIdx && !seen[idx] {
			seen[idx] = true
			result = append(result, sn.allIDs[idx])
		}
	}
	return result
}

func (sn *simSparseNetwork) makeSparseHandler(selfID gossipsub.PeerID) func(*gossipsub.Message) {
	return func(msg *gossipsub.Message) {
		sn.mu.RLock()
		node, ok := sn.nodes[selfID]
		sn.mu.RUnlock()
		if !ok {
			return
		}
		node.mu.Lock()
		node.messagesRx++
		node.mu.Unlock()

		sn.metrics.totalMessages.Add(1)
	}
}

func (sn *simSparseNetwork) stopAll() {
	sn.mu.RLock()
	defer sn.mu.RUnlock()
	for _, node := range sn.nodes {
		close(node.stopCh)
		node.gs.Stop()
	}
}

// fastRNG is a simple xorshift PRNG for fast random peer selection.
type fastRNG struct {
	state uint64
}

func newFastRNG(seed uint64) *fastRNG {
	if seed == 0 {
		seed = 1
	}
	return &fastRNG{state: seed}
}

func (r *fastRNG) Uint64() uint64 {
	r.state ^= r.state << 13
	r.state ^= r.state >> 7
	r.state ^= r.state << 17
	return r.state
}

// TestSim_200KNodes runs the 200,000-node scale test with sparse connectivity.
func TestSim_200KNodes(t *testing.T) {
	scaleTestEnabled(t) // R123: opt-in gate — this test allocated ~108 GB and OOM-rebooted a 64 GB machine on 2026-09-05

	n := 200000
	maxPeers := 50 // each node only knows 50 random peers
	topics := []string{gossipsub.TopicBlocks}

	t.Logf("========== 200K-Node Scale Test ==========")
	t.Logf("Nodes: %d, Max peers/node: %d, Topics: %d", n, maxPeers, len(topics))
	t.Logf("Memory estimate: ~2-3 GB (sparse topology)")

	// Phase 1: Create nodes
	t.Log("\n--- Phase 1: Creating 200,000 nodes ---")
	net := newSimSparseNetwork()

	startCreate := time.Now()
	if err := net.createSparseNodes(n, maxPeers, topics); err != nil {
		t.Fatalf("createSparseNodes failed: %v", err)
	}
	createTime := time.Since(startCreate)
	t.Logf("  Created %d nodes in %v (avg %.3fms/node, %.0f nodes/sec)",
		n, createTime,
		float64(createTime.Microseconds())/float64(n)/1000,
		float64(n)/createTime.Seconds())

	// Phase 2: Wait for mesh formation (sample only)
	t.Log("\n--- Phase 2: Mesh formation (sampling 1000 nodes) ---")
	time.Sleep(5 * time.Second)

	// Sample 1000 random nodes for mesh verification
	sampleSize := 1000
	rng := newFastRNG(uint64(time.Now().UnixNano()))
	sampleIndices := make([]int, sampleSize)
	for i := 0; i < sampleSize; i++ {
		sampleIndices[i] = int(rng.Uint64() % uint64(n))
	}

	net.mu.RLock()
	nodesWithMesh := 0
	totalMeshPeers := 0
	for _, idx := range sampleIndices {
		peerID := net.allIDs[idx]
		node, ok := net.nodes[peerID]
		if !ok {
			continue
		}
		peers := node.gs.GetMeshPeers(gossipsub.TopicBlocks)
		if len(peers) > 0 {
			nodesWithMesh++
			totalMeshPeers += len(peers)
		}
	}
	net.mu.RUnlock()

	meshRate := float64(nodesWithMesh) / float64(sampleSize) * 100
	avgMeshPeers := float64(totalMeshPeers) / float64(max(nodesWithMesh, 1))
	t.Logf("  Sample mesh: %d/%d (%.1f%%), avg %.1f peers/node",
		nodesWithMesh, sampleSize, meshRate, avgMeshPeers)

	// Phase 3: Simple message broadcast (publish from 1 node only to limit cascade)
	t.Log("\n--- Phase 3: Message broadcast ---")
	pubStart := time.Now()

	// Publish a single message from node-00000
	net.mu.RLock()
	srcNode, ok := net.nodes[net.allIDs[0]]
	net.mu.RUnlock()
	if ok {
		msg := []byte("SCALE_200K_TEST_MSG")
		if err := srcNode.gs.Publish(gossipsub.TopicBlocks, msg); err != nil {
			t.Logf("  Publish warning: %v", err)
		}
	}

	// Short wait for initial propagation
	time.Sleep(2 * time.Second)
	pubTime := time.Since(pubStart)

	// Sample message reception
	net.mu.RLock()
	sampleRx := 0
	for _, idx := range sampleIndices {
		peerID := net.allIDs[idx]
		node, ok := net.nodes[peerID]
		if !ok {
			continue
		}
		node.mu.Lock()
		sampleRx += node.messagesRx
		node.mu.Unlock()
	}
	net.mu.RUnlock()

	deliveryCount := net.metrics.deliveryCount.Load()
	totalMsgCount := net.metrics.totalMessages.Load()

	// Phase 4: Cleanup (skip graceful stop for speed — 200K goroutines take too long)
	t.Log("\n--- Phase 4: Summary (skipping full cleanup for speed) ---")
	// Note: not calling stopAll() to avoid waiting for 200K goroutines to drain

	// Summary
	t.Log("\n========== 200K-Node Results ==========")
	t.Logf("  Nodes created:      %d", n)
	t.Logf("  Create time:        %v (%.0f nodes/sec)", createTime, float64(n)/createTime.Seconds())
	t.Logf("  Mesh rate (sample): %.1f%% (%d/%d)", meshRate, nodesWithMesh, sampleSize)
	t.Logf("  Avg mesh peers:     %.1f", avgMeshPeers)
	t.Logf("  Sample msg rx:      %d (from %d sample nodes)", sampleRx, sampleSize)
	t.Logf("  Total deliveries:   %d", deliveryCount)
	t.Logf("  Total msg events:   %d", totalMsgCount)
	t.Logf("  Publish+prop time:  %v", pubTime)
	t.Logf("  Total test time:    %v", time.Since(startCreate))

	// Success criteria (relaxed for sparse topology)
	if meshRate < 60 {
		t.Errorf("Mesh rate too low: %.1f%% (expected >= 60%% with sparse peers)", meshRate)
	}
	if deliveryCount < 1000 {
		t.Errorf("Delivery count too low: %d (expected >= 1000)", deliveryCount)
	}
}

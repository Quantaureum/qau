// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ======================== mock infrastructure ========================

// mockNode simulates a P2P node
type mockNode struct {
	id          PeerID
	blocks      map[uint64]*encoding.BlockHeader
	peers       map[PeerID]*mockNode
	mu          sync.RWMutex
	crashed     atomic.Bool
	partitioned atomic.Bool
	byzantine   atomic.Bool
	delay       time.Duration
	diskFull    atomic.Bool
	committed   map[types.Hash]bool // committed transactions
	balance     map[types.Address]uint64
}

func newMockNode(id PeerID) *mockNode {
	return &mockNode{
		id:        id,
		blocks:    make(map[uint64]*encoding.BlockHeader),
		peers:     make(map[PeerID]*mockNode),
		committed: make(map[types.Hash]bool),
		balance:   make(map[types.Address]uint64),
	}
}

// addPeer adds a peer
func (n *mockNode) addPeer(peer *mockNode) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.peers[peer.id] = peer
}

// proposeBlock proposes a new block
func (n *mockNode) proposeBlock(height uint64, txHashes []types.Hash) error {
	if n.crashed.Load() {
		return errors.New("node has crashed")
	}
	if n.diskFull.Load() {
		return errors.New("disk full")
	}

	header := &encoding.BlockHeader{
		Height:    height,
		Timestamp: time.Now().Unix(),
	}

	n.mu.Lock()
	n.blocks[height] = header
	for _, h := range txHashes {
		n.committed[h] = true
	}
	n.mu.Unlock()

	return nil
}

// getBlock fetches a block
func (n *mockNode) getBlock(height uint64) (*encoding.BlockHeader, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	b, ok := n.blocks[height]
	return b, ok
}

// getCommittedTx fetches committed transactions
func (n *mockNode) getCommittedTx(hash types.Hash) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.committed[hash]
}

// sendBlock sends a block to a peer (and propagates committed transactions)
func (n *mockNode) sendBlock(height uint64, txHashes ...types.Hash) error {
	if n.crashed.Load() {
		return errors.New("node has crashed")
	}
	if n.partitioned.Load() {
		return errors.New("network partition")
	}

	n.mu.RLock()
	block, ok := n.blocks[height]
	peers := make([]*mockNode, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	n.mu.RUnlock()

	if !ok {
		return errors.New("block does not exist")
	}

	// simulate Byzantine behavior: send an invalid block
	if n.byzantine.Load() {
		invalidBlock := &encoding.BlockHeader{
			Height:    height,
			Timestamp: 0, // invalid timestamp
		}
		for _, peer := range peers {
			if peer.crashed.Load() || peer.partitioned.Load() {
				continue
			}
			time.Sleep(n.delay)
			peer.mu.Lock()
			peer.blocks[height] = invalidBlock
			peer.mu.Unlock()
		}
		return nil
	}

	for _, peer := range peers {
		if peer.crashed.Load() || peer.partitioned.Load() {
			continue
		}
		time.Sleep(n.delay)
		peer.mu.Lock()
		peer.blocks[height] = block
		for _, txHash := range txHashes {
			peer.committed[txHash] = true
		}
		peer.mu.Unlock()
	}

	return nil
}

// verifyBlock checks block validity
func (n *mockNode) verifyBlock(height uint64) bool {
	n.mu.RLock()
	block, ok := n.blocks[height]
	n.mu.RUnlock()

	if !ok || block == nil {
		return false
	}

	// check timestamp validity
	if block.Timestamp <= 0 {
		return false
	}

	// check height continuity
	if height > 0 {
		n.mu.RLock()
		prevBlock, prevOk := n.blocks[height-1]
		n.mu.RUnlock()
		if prevOk && prevBlock != nil {
			if block.Timestamp < prevBlock.Timestamp {
				return false
			}
		}
	}

	return true
}

// mockNetwork simulates the P2P network
type mockNetwork struct {
	nodes map[PeerID]*mockNode
	mu    sync.RWMutex
}

func newMockNetwork() *mockNetwork {
	return &mockNetwork{
		nodes: make(map[PeerID]*mockNode),
	}
}

func (net *mockNetwork) addNode(node *mockNode) {
	net.mu.Lock()
	defer net.mu.Unlock()
	net.nodes[node.id] = node
}

func (net *mockNetwork) connectAll() {
	net.mu.RLock()
	defer net.mu.RUnlock()
	for _, node := range net.nodes {
		for _, peer := range net.nodes {
			if node.id != peer.id {
				node.addPeer(peer)
			}
		}
	}
}

// ======================== test 1: network partition ========================

// TestNetworkPartition simulates a network partition
// verifies state consistency after partition heals, with no double-spends
func TestNetworkPartition(t *testing.T) {
	// create a 4-node network
	net := newMockNetwork()
	nodes := make([]*mockNode, 4)
	for i := 0; i < 4; i++ {
		id := PeerID(fmt.Sprintf("node-%d", i))
		nodes[i] = newMockNode(id)
		net.addNode(nodes[i])
	}
	net.connectAll()

	// initial balances
	testAddr := types.BytesToAddress([]byte{0x01})
	nodes[0].mu.Lock()
	nodes[0].balance[testAddr] = 1000
	nodes[0].mu.Unlock()

	// phase 1: normal block production
	tx1 := types.Keccak256Hash([]byte("tx1"))
	if err := nodes[0].proposeBlock(1, []types.Hash{tx1}); err != nil {
		t.Fatalf("proposing block 1 failed: %v", err)
	}
	nodes[0].sendBlock(1, tx1)

	// verify all nodes received block 1
	for i, node := range nodes {
		if _, ok := node.getBlock(1); !ok {
			t.Errorf("node %d did not receive block 1", i)
		}
	}

	// phase 2: simulate a partition (nodes 0,1 split from 2,3)
	nodes[0].partitioned.Store(true)
	nodes[1].partitioned.Store(true)
	// note: nodes across the partition cannot reach each other

	// partition A (nodes 0,1) produces block 2
	tx2 := types.Keccak256Hash([]byte("tx2"))
	if err := nodes[0].proposeBlock(2, []types.Hash{tx2}); err != nil {
		t.Fatalf("partition A failed to propose block 2: %v", err)
	}
	// propagate within partition A
	nodes[0].mu.RLock()
	block2 := nodes[0].blocks[2]
	nodes[0].mu.RUnlock()
	nodes[1].mu.Lock()
	nodes[1].blocks[2] = block2
	nodes[1].committed[tx2] = true
	nodes[1].mu.Unlock()

	// verify partition B (nodes 2,3) did NOT receive block 2
	for _, node := range []*mockNode{nodes[2], nodes[3]} {
		if _, ok := node.getBlock(2); ok {
			t.Error("during the partition, partition B must not receive partition A's blocks")
		}
	}

	// phase 3: heal the partition
	nodes[0].partitioned.Store(false)
	nodes[1].partitioned.Store(false)

	// propagate block 2 after healing
	nodes[0].sendBlock(2, tx2)

	// verify all nodes agree after the partition heals
	for i, node := range nodes {
		if _, ok := node.getBlock(2); !ok {
			t.Errorf("after healing, node %d should have block 2", i)
		}
	}

	// verify no double-spend (the same transaction is never committed twice)
	for _, node := range nodes {
		count := 0
		node.mu.RLock()
		for _, committed := range node.committed {
			if committed {
				count++
			}
		}
		node.mu.RUnlock()
		// there should be exactly two transactions, tx1 and tx2
		if count != 2 {
			t.Errorf("node %s double-spent: committed %d transactions, expected 2", node.id, count)
		}
	}
}

// ======================== test 2: node crash recovery ========================

// TestNodeCrashRecovery simulates node crash and recovery
// verifies correct recovery after restart, with no committed transactions lost
func TestNodeCrashRecovery(t *testing.T) {
	net := newMockNetwork()
	nodes := make([]*mockNode, 3)
	for i := 0; i < 3; i++ {
		id := PeerID(fmt.Sprintf("node-%d", i))
		nodes[i] = newMockNode(id)
		net.addNode(nodes[i])
	}
	net.connectAll()

	// phase 1: normal block production
	tx1 := types.Keccak256Hash([]byte("tx-crash-1"))
	if err := nodes[0].proposeBlock(1, []types.Hash{tx1}); err != nil {
		t.Fatalf("proposing block 1 failed: %v", err)
	}
	nodes[0].sendBlock(1, tx1)

	// phase 2: node 2 crashes while processing block 2
	tx2 := types.Keccak256Hash([]byte("tx-crash-2"))
	if err := nodes[0].proposeBlock(2, []types.Hash{tx2}); err != nil {
		t.Fatalf("proposing block 2 failed: %v", err)
	}

	// node 2 crashes
	nodes[2].crashed.Store(true)

	// other nodes propagate normally
	nodes[0].sendBlock(2, tx2)

	// verify the crashed node did not receive block 2
	if _, ok := nodes[2].getBlock(2); ok {
		t.Error("the crashed node must not receive block 2")
	}

	// phase 3: node 2 recovers
	nodes[2].crashed.Store(false)

	// simulate recovery: sync missing blocks from other nodes
	for height := uint64(1); height <= 2; height++ {
		for _, peer := range []*mockNode{nodes[0], nodes[1]} {
			if block, ok := peer.getBlock(height); ok {
				nodes[2].mu.Lock()
				nodes[2].blocks[height] = block
				// sync committed transactions
				for txHash, committed := range peer.committed {
					if committed {
						nodes[2].committed[txHash] = true
					}
				}
				nodes[2].mu.Unlock()
				break
			}
		}
	}

	// verify node 2 has all blocks after recovery
	for height := uint64(1); height <= 2; height++ {
		if _, ok := nodes[2].getBlock(height); !ok {
			t.Errorf("after recovery, node 2 should have block %d", height)
		}
	}

	// verify no committed transactions were lost
	for _, node := range nodes[:2] {
		if !node.getCommittedTx(tx1) {
			t.Error("tx1 should be committed")
		}
		if !node.getCommittedTx(tx2) {
			t.Error("tx2 should be committed")
		}
	}
}

// ======================== test 3: Byzantine node ========================

// TestByzantineNode simulates a Byzantine node
// verifies honest nodes reject invalid blocks and consensus keeps working
func TestByzantineNode(t *testing.T) {
	net := newMockNetwork()
	nodes := make([]*mockNode, 4)
	for i := 0; i < 4; i++ {
		id := PeerID(fmt.Sprintf("node-%d", i))
		nodes[i] = newMockNode(id)
		net.addNode(nodes[i])
	}
	net.connectAll()

	// node 3 is the Byzantine node
	nodes[3].byzantine.Store(true)

	// phase 1: honest nodes produce normally
	tx1 := types.Keccak256Hash([]byte("tx-byz-1"))
	if err := nodes[0].proposeBlock(1, []types.Hash{tx1}); err != nil {
		t.Fatalf("proposing block 1 failed: %v", err)
	}
	nodes[0].sendBlock(1, tx1)

	// verify honest nodes received the valid block
	for i := 0; i < 3; i++ {
		if !nodes[i].verifyBlock(1) {
			t.Errorf("honest node %d should accept block 1", i)
		}
	}

	// phase 2: the Byzantine node sends an invalid block
	if err := nodes[3].proposeBlock(2, []types.Hash{}); err != nil {
		t.Fatalf("Byzantine node failed to propose block 2: %v", err)
	}
	nodes[3].sendBlock(2)

	// verify honest nodes reject the invalid block
	for i := 0; i < 3; i++ {
		if nodes[i].verifyBlock(2) {
			t.Errorf("honest node %d should reject the Byzantine node's invalid block", i)
		}
	}

	// phase 3: honest nodes continue producing normally
	tx2 := types.Keccak256Hash([]byte("tx-byz-2"))
	if err := nodes[0].proposeBlock(2, []types.Hash{tx2}); err != nil {
		t.Fatalf("honest nodes failed to propose block 2: %v", err)
	}
	// let only honest nodes propagate
	for _, peer := range []*mockNode{nodes[1], nodes[2]} {
		nodes[0].mu.RLock()
		block := nodes[0].blocks[2]
		nodes[0].mu.RUnlock()
		peer.mu.Lock()
		peer.blocks[2] = block
		peer.committed[tx2] = true
		peer.mu.Unlock()
	}

	// verify honest-node consensus keeps working
	for i := 0; i < 3; i++ {
		if !nodes[i].verifyBlock(2) {
			t.Errorf("honest node %d should accept valid block 2", i)
		}
	}
}

// ======================== test 4: slow network ========================

// TestSlowNetwork simulates a high-latency network
// verifies timeouts are handled correctly, with no deadlocks
func TestSlowNetwork(t *testing.T) {
	net := newMockNetwork()
	nodes := make([]*mockNode, 3)
	for i := 0; i < 3; i++ {
		id := PeerID(fmt.Sprintf("node-%d", i))
		nodes[i] = newMockNode(id)
		net.addNode(nodes[i])
	}
	net.connectAll()

	// set high latency
	for _, node := range nodes {
		node.delay = 50 * time.Millisecond
	}

	// use a timeout context to prevent deadlocks
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// produce and propagate under high latency
	done := make(chan bool, 1)
	go func() {
		tx1 := types.Keccak256Hash([]byte("tx-slow-1"))
		if err := nodes[0].proposeBlock(1, []types.Hash{tx1}); err != nil {
			done <- false
			return
		}
		nodes[0].sendBlock(1, tx1)
		done <- true
	}()

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("block production failed under high latency")
		}
	case <-ctx.Done():
		t.Fatal("operation timed out under high latency; possible deadlock")
	}

	// verify the block eventually reaches all nodes
	for i, node := range nodes {
		if _, ok := node.getBlock(1); !ok {
			t.Errorf("under high latency, node %d should eventually receive block 1", i)
		}
	}

	// verify repeated production does not deadlock
	for height := uint64(2); height <= 5; height++ {
		tx := types.Keccak256Hash([]byte(fmt.Sprintf("tx-slow-%d", height)))
		if err := nodes[0].proposeBlock(height, []types.Hash{tx}); err != nil {
			t.Fatalf("under high latency, proposing block %d failed: %v", height, err)
		}
		nodes[0].sendBlock(height, tx)
	}

	// verify all blocks propagated
	for i, node := range nodes {
		for height := uint64(1); height <= 5; height++ {
			if _, ok := node.getBlock(height); !ok {
				t.Errorf("node %d is missing block %d", i, height)
			}
		}
	}
}

// ======================== test 5: disk full ========================

// TestDiskFull simulates a full disk
// verifies graceful degradation and recovery
func TestDiskFull(t *testing.T) {
	net := newMockNetwork()
	nodes := make([]*mockNode, 3)
	for i := 0; i < 3; i++ {
		id := PeerID(fmt.Sprintf("node-%d", i))
		nodes[i] = newMockNode(id)
		net.addNode(nodes[i])
	}
	net.connectAll()

	// phase 1: normal block production
	tx1 := types.Keccak256Hash([]byte("tx-disk-1"))
	if err := nodes[0].proposeBlock(1, []types.Hash{tx1}); err != nil {
		t.Fatalf("proposing block 1 failed: %v", err)
	}
	nodes[0].sendBlock(1)

	// phase 2: node 1's disk is full
	nodes[1].diskFull.Store(true)

	// node 1's block production should fail
	tx2 := types.Keccak256Hash([]byte("tx-disk-2"))
	if err := nodes[1].proposeBlock(2, []types.Hash{tx2}); err == nil {
		t.Error("with a full disk, proposing a new block must fail")
	}

	// other nodes should keep working
	if err := nodes[0].proposeBlock(2, []types.Hash{tx2}); err != nil {
		t.Fatalf("normal node failed to propose block 2: %v", err)
	}
	nodes[0].sendBlock(2)

	// verify the disk-full node can still receive blocks (it just cannot write)
	// in a real implementation, a disk-full node may only cache in memory
	if _, ok := nodes[1].getBlock(2); !ok {
		t.Error("the disk-full node should still buffer blocks in memory")
	}

	// phase 3: disk space recovered
	nodes[1].diskFull.Store(false)

	// after recovery, node 1 should produce normally again
	tx3 := types.Keccak256Hash([]byte("tx-disk-3"))
	if err := nodes[1].proposeBlock(3, []types.Hash{tx3}); err != nil {
		t.Fatalf("proposing block 3 after disk recovery failed: %v", err)
	}

	// verify work continues normally after recovery
	if !nodes[1].getCommittedTx(tx3) {
		t.Error("after recovery, tx3 should be committed")
	}
}

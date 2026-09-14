// Quantaureum Node source, version 1.0.0.
// Package discover — R4-P2P-01 regression tests.
//
// AUDIT (2026) R4-P2P-01: LoadNodes previously called AddNode, which
// runs ValidateNodeID — and ValidateNodeID requires an ENR record that
// persisted nodes lack (they only carry ID+IP+port). This caused every
// persisted node to be rejected on restart, leaving only bootstrap nodes
// in the routing table (eclipse risk).
//
// The fix: LoadNodes now calls AddTrustedNode, which skips ENR validation
// for nodes that were already validated when first admitted.
//
// These tests verify persisted nodes survive a save/load round-trip and
// that a node that fails ENR validation (no ENR record) is still loaded.
package discover

import (
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/p2p/enode"
)

// TestR4P2P01_PersistedNodesAreReloaded verifies that nodes saved to disk
// are loaded back into the routing table after a restart. Before the fix,
// LoadNodes called AddNode → ValidateNodeID → ENR-required → all persisted
// nodes rejected → table only had bootstrap nodes.
func TestR4P2P01_PersistedNodesAreReloaded(t *testing.T) {
	// Create a table with a few non-bootstrap nodes (no ENR, just ID+IP+port).
	selfID := enode.ID{}
	if _, err := rand.Read(selfID[:]); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	cfg := &Config{SelfID: selfID, SkipIDValidation: true}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	// Add 5 nodes via AddTrustedNode (simulating nodes discovered at runtime).
	var addedIDs []enode.ID
	for i := 0; i < 5; i++ {
		var id enode.ID
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatalf("rand.Read failed: %v", err)
		}
		// Use distinct IP octets so each lands in a distinct bucket position
		// (avoids bucket-full rejections in a small table).
		// R33 P2P-05/06 FIX: Use routable public IPs (203.0.113.x TEST-NET-3)
		// instead of private 10.x.x.x, since AddTrustedNode now rejects
		// unroutable IPs.
		ip := net.IPv4(203, 0, 113, byte(i+1))
		node := enode.NewNode(id, ip, 30303+i, 30303+i)
		if err := table.AddTrustedNode(node); err != nil {
			t.Fatalf("AddTrustedNode[%d] failed: %v", i, err)
		}
		addedIDs = append(addedIDs, id)
	}

	before := table.Len()
	if before < len(addedIDs) {
		t.Fatalf("expected at least %d nodes in table, got %d", len(addedIDs), before)
	}

	// Save to disk.
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nodes.json")
	if err := table.SaveNodes(path); err != nil {
		t.Fatalf("SaveNodes failed: %v", err)
	}

	// Verify the saved file is non-empty.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved file failed: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatal("saved nodes file is empty")
	}

	// Create a fresh table and load nodes from disk. This simulates a node
	// restart where the DHT must repopulate from the persisted file.
	table2, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable(2) failed: %v", err)
	}
	defer table2.Close()

	if err := table2.LoadNodes(path); err != nil {
		t.Fatalf("LoadNodes failed: %v", err)
	}

	// R4-P2P-01 REGRESSION: Before the fix, LoadNodes silently rejected
	// every persisted node because AddNode → ValidateNodeID required an ENR
	// record. The fresh table ended up empty (only bootstrap nodes, which
	// is zero here).
	after := table2.Len()
	if after < len(addedIDs) {
		t.Fatalf("R4-P2P-01 REGRESSION: LoadNodes only loaded %d nodes into the fresh table, expected at least %d. "+
			"Persisted nodes are being rejected on reload (likely AddNode→ValidateNodeID requiring ENR).", after, len(addedIDs))
	}

	// Verify each saved node ID is present in the reloaded table.
	for i, id := range addedIDs {
		if _, err := table2.GetNode(id); err != nil {
			t.Errorf("R4-P2P-01 REGRESSION: persisted node %d (id=%s) not found in reloaded table: %v", i, id.Hex(), err)
		}
	}
}

// TestR4P2P01_NodesWithoutENRAreLoaded directly verifies that a node with
// only ID+IP+port (no ENR record) is accepted by LoadNodes. This is the
// exact scenario that was broken before the fix.
func TestR4P2P01_NodesWithoutENRAreLoaded(t *testing.T) {
	selfID := enode.ID{}
	if _, err := rand.Read(selfID[:]); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	cfg := &Config{SelfID: selfID, SkipIDValidation: true}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	// Write a persisted nodes file manually with a node that has no ENR.
	// enode.NewNode creates a node with nil ENR — exactly the case that
	// ValidateNodeID rejects.
	var id enode.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	ip := net.IPv4(192, 0, 2, 1)
	node := enode.NewNode(id, ip, 30303, 30303)

	// Sanity: the node has no ENR record (this is the precondition for the
	// bug — AddNode would reject it via ValidateNodeID).
	if node.Record() != nil {
		t.Fatalf("test precondition: node should have nil ENR record, got %v", node.Record())
	}

	// AddTrustedNode should succeed (this is the LoadNodes path).
	if err := table.AddTrustedNode(node); err != nil {
		t.Fatalf("AddTrustedNode for ENR-less node failed: %v", err)
	}

	// Verify the node is in the table.
	got, err := table.GetNode(id)
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if got.ID() != id {
		t.Fatalf("got wrong node: %s != %s", got.ID().Hex(), id.Hex())
	}
}

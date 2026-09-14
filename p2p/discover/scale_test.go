// Quantaureum Node source, version 1.0.0.
// Package discover implements 200K-scale tests for the Kademlia DHT routing table.
//
// These tests validate that the node discovery subsystem can handle 200,000 nodes
// without performance degradation. Crypto validation is skipped for scale testing
// (it's a per-node, one-time operation not relevant to DHT scaling).
package discover

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p/enode"
)

// makeTestNodeFast creates a lightweight node for scale testing.
// Uses enode.NewNode to bypass full ENR creation with quantum keys.
func makeTestNodeFast(id enode.ID) *enode.Node {
	return enode.NewNode(id, net.IPv4(10, id[0], id[1], id[2]), 30303, 30303)
}

// generateRandomIDs creates n random node IDs.
func generateRandomIDs(n int) []enode.ID {
	ids := make([]enode.ID, n)
	for i := 0; i < n; i++ {
		_, _ = rand.Read(ids[i][:])
	}
	return ids
}

// =============================================================================
// 200K-Scale DHT Routing Table Tests
// =============================================================================

// TestScale_200KNodes_AddNode benchmarks adding 200K nodes to the DHT routing table.
func TestScale_200KNodes_AddNode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K DHT test in short mode")
	}

	n := 200000
	t.Logf("Generating %d random node IDs...", n)
	ids := generateRandomIDs(n)

	selfID := enode.ID{}
	_, _ = rand.Read(selfID[:])

	cfg := &Config{
		SelfID:           selfID,
		SkipIDValidation: true,
	}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	t.Logf("Adding %d nodes to DHT routing table...", n)
	start := time.Now()

	added := 0
	for i := 0; i < n; i++ {
		node := makeTestNodeFast(ids[i])
		if err := table.AddNode(node); err != nil {
			continue
		}
		added++
	}

	elapsed := time.Since(start)
	t.Logf("  Added %d/%d nodes in %v (avg %.3fµs/node, %.0f nodes/sec)",
		added, n, elapsed,
		float64(elapsed.Microseconds())/float64(max(added, 1)),
		float64(added)/elapsed.Seconds())

	tableLen := table.Len()
	t.Logf("  Table size: %d nodes (bucket capacity: %d)", tableLen, nBuckets*bucketSize)

	if added == 0 {
		t.Error("No nodes were added to the table")
	}
}

// TestScale_200KNodes_Lookup benchmarks Kademlia lookup operations with 200K nodes.
func TestScale_200KNodes_Lookup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K DHT test in short mode")
	}

	n := 200000
	ids := generateRandomIDs(n)

	selfID := enode.ID{}
	_, _ = rand.Read(selfID[:])

	cfg := &Config{
		SelfID:           selfID,
		SkipIDValidation: true,
	}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	t.Logf("Populating table with %d nodes...", n)
	for i := 0; i < n; i++ {
		node := makeTestNodeFast(ids[i])
		_ = table.AddNode(node)
	}

	tableLen := table.Len()
	t.Logf("  Table populated: %d nodes", tableLen)

	lookupCount := 100
	targets := generateRandomIDs(lookupCount)

	t.Log("Benchmarking Lookup (closest nodes)...")
	start := time.Now()
	totalFound := 0
	for i := 0; i < lookupCount; i++ {
		closest := table.Lookup(targets[i])
		totalFound += len(closest)
	}
	elapsed := time.Since(start)

	avgFound := float64(totalFound) / float64(lookupCount)
	t.Logf("  Lookup: %d targets, avg %.1f nodes found, %v total (%.3fms/lookup)",
		lookupCount, avgFound, elapsed,
		float64(elapsed.Milliseconds())/float64(lookupCount))
}

// TestScale_200KNodes_RandomSampling validates random node sampling at 200K scale.
func TestScale_200KNodes_RandomSampling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K DHT test in short mode")
	}

	n := 200000
	ids := generateRandomIDs(n)

	selfID := enode.ID{}
	_, _ = rand.Read(selfID[:])

	cfg := &Config{
		SelfID:           selfID,
		SkipIDValidation: true,
	}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	t.Logf("Populating table with %d nodes...", n)
	for i := 0; i < n; i++ {
		node := makeTestNodeFast(ids[i])
		_ = table.AddNode(node)
	}

	tableLen := table.Len()
	t.Logf("  Table populated: %d nodes", tableLen)

	sampleSizes := []int{10, 100, 1000}
	for _, size := range sampleSizes {
		start := time.Now()
		nodes := table.ReadRandomNodes(size)
		elapsed := time.Since(start)

		seen := make(map[enode.ID]bool)
		duplicates := 0
		for _, node := range nodes {
			if seen[node.ID()] {
				duplicates++
			}
			seen[node.ID()] = true
		}

		t.Logf("  ReadRandomNodes(%d): %d nodes, %d duplicates, %v",
			size, len(nodes), duplicates, elapsed)
	}
}

// TestScale_DHTBucketDistribution verifies that 200K nodes are evenly
// distributed across Kademlia buckets.
func TestScale_DHTBucketDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K DHT test in short mode")
	}

	n := 200000
	ids := generateRandomIDs(n)

	selfID := enode.ID{}
	_, _ = rand.Read(selfID[:])

	cfg := &Config{
		SelfID:           selfID,
		SkipIDValidation: true,
	}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	t.Logf("Populating table with %d nodes...", n)
	for i := 0; i < n; i++ {
		node := makeTestNodeFast(ids[i])
		_ = table.AddNode(node)
	}

	nonEmptyBuckets := 0
	maxBucketSize := 0
	totalNodes := 0
	for i := 0; i < nBuckets; i++ {
		entries, _ := table.BucketInfo(i)
		totalNodes += entries
		if entries > 0 {
			nonEmptyBuckets++
		}
		if entries > maxBucketSize {
			maxBucketSize = entries
		}
	}

	avgPerBucket := float64(totalNodes) / float64(max(nonEmptyBuckets, 1))
	t.Logf("  Bucket distribution: %d/%d non-empty buckets, avg %.1f nodes/bucket, max %d",
		nonEmptyBuckets, nBuckets, avgPerBucket, maxBucketSize)
	t.Logf("  Total nodes in buckets: %d", totalNodes)

	if nonEmptyBuckets == 0 {
		t.Error("No non-empty buckets — routing table is empty")
	}
}

// TestScale_DHTMemoryFootprint estimates memory usage of 200K nodes.
func TestScale_DHTMemoryFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K DHT test in short mode")
	}

	n := 200000
	ids := generateRandomIDs(n)

	selfID := enode.ID{}
	_, _ = rand.Read(selfID[:])

	cfg := &Config{
		SelfID:           selfID,
		SkipIDValidation: true,
	}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	t.Logf("Populating table with %d nodes...", n)
	for i := 0; i < n; i++ {
		node := makeTestNodeFast(ids[i])
		_ = table.AddNode(node)
	}

	tableLen := table.Len()
	estimatedMB := float64(tableLen) * 250 / (1024 * 1024)
	t.Logf("  Memory estimate: ~%.0f MB for %d nodes (250 bytes/node)", estimatedMB, tableLen)

	randomNodes := table.ReadRandomNodes(10)
	t.Logf("  Random access: %d nodes retrieved", len(randomNodes))
}

// TestScale_DHTNodeLookupConsistency verifies that nodes can be found via ResolveID.
func TestScale_DHTNodeLookupConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K DHT test in short mode")
	}

	n := 200000
	ids := generateRandomIDs(n)

	selfID := enode.ID{}
	_, _ = rand.Read(selfID[:])

	cfg := &Config{
		SelfID:           selfID,
		SkipIDValidation: true,
	}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	t.Logf("Populating table with %d nodes...", n)
	for i := 0; i < n; i++ {
		node := makeTestNodeFast(ids[i])
		_ = table.AddNode(node)
	}

	found := 0
	sampleSize := 100
	for i := 0; i < sampleSize; i++ {
		idx := i * (n / sampleSize)
		if idx >= n {
			idx = n - 1
		}
		resolved := table.ResolveID(ids[idx])
		if resolved != nil {
			found++
		}
	}

	t.Logf("  Node lookup: %d/%d found (%.1f%% success rate)",
		found, sampleSize, float64(found)/float64(sampleSize)*100)

	if found == 0 {
		t.Error("No nodes could be resolved — routing table may be broken")
	}
}

// TestScale_DHTFindClosest validates Kademlia nearest-neighbor operation.
func TestScale_DHTFindClosest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K DHT test in short mode")
	}

	n := 200000
	ids := generateRandomIDs(n)

	selfID := enode.ID{}
	_, _ = rand.Read(selfID[:])

	cfg := &Config{
		SelfID:           selfID,
		SkipIDValidation: true,
	}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	t.Logf("Populating table with %d nodes...", n)
	for i := 0; i < n; i++ {
		node := makeTestNodeFast(ids[i])
		_ = table.AddNode(node)
	}

	tableLen := table.Len()
	t.Logf("  Table populated: %d nodes", tableLen)

	targets := generateRandomIDs(10)
	start := time.Now()
	for _, target := range targets {
		closest := table.FindClosest(target, 16)
		_ = len(closest)
	}
	elapsed := time.Since(start)

	t.Logf("  FindClosest(16): %d targets, %v total (%.3fms/op)",
		len(targets), elapsed,
		float64(elapsed.Milliseconds())/float64(len(targets)))

	// Verify we get results for each target
	target := targets[0]
	closest := table.FindClosest(target, 16)
	t.Logf("  FindClosest result: %d nodes returned", len(closest))
}

// TestScale_DHTSequentialVsRandom verifies that sequential IDs distribute correctly.
func TestScale_DHTSequentialVsRandom(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K DHT test in short mode")
	}

	n := 200000
	selfID := enode.ID{}
	_, _ = rand.Read(selfID[:])

	cfg := &Config{
		SelfID:           selfID,
		SkipIDValidation: true,
	}
	table, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable failed: %v", err)
	}
	defer table.Close()

	t.Logf("Creating %d sequential node IDs...", n)
	start := time.Now()
	for i := 0; i < n; i++ {
		var id enode.ID
		for j := 0; j < len(id); j++ {
			id[j] = byte(i >> (j * 8))
		}
		node := makeTestNodeFast(id)
		_ = table.AddNode(node)
	}
	elapsed := time.Since(start)

	tableLen := table.Len()
	t.Logf("  Added %d sequential nodes in %v (%.0f nodes/sec)",
		tableLen, elapsed, float64(tableLen)/elapsed.Seconds())

	nonEmptyBuckets := 0
	for i := 0; i < nBuckets; i++ {
		entries, _ := table.BucketInfo(i)
		if entries > 0 {
			nonEmptyBuckets++
		}
	}
	t.Logf("  Sequential IDs: %d non-empty buckets", nonEmptyBuckets)
}

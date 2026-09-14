// Quantaureum Node source, version 1.0.0.
//go:build integration

package node

import (
	"context"
	"testing"
	"time"

	"github.com/quantaureum/qau/rpc"
)

func devTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false
	cfg.DevBlocks = true
	cfg.BlockInterval = 1
	return cfg
}

func TestSingleNode_StartStop(t *testing.T) {
	cfg := devTestConfig(t)

	node, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	defer closeNodeDB(node)

	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	time.Sleep(2 * time.Second)

	if err := node.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestSingleNode_BlockProduction(t *testing.T) {
	cfg := devTestConfig(t)

	node, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	defer closeNodeDB(node)

	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer node.Stop()

	deadline := time.Now().Add(30 * time.Second)
	for {
		height, err := node.blockStore.GetLatestHeight()
		if err != nil {
			t.Fatalf("GetLatestHeight: %v", err)
		}
		if height >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected at least 1 block produced, got height %d", height)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func TestSingleNode_GenesisInitialized(t *testing.T) {
	cfg := devTestConfig(t)

	node, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	defer closeNodeDB(node)

	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer node.Stop()

	genesis, err := node.blockStore.GetBlockByHeight(0)
	if err != nil {
		t.Fatalf("GetBlockByHeight(0): %v", err)
	}
	if genesis == nil {
		t.Fatal("genesis block should exist")
	}
	if genesis.Header.Height != 0 {
		t.Errorf("genesis block height should be 0, got %d", genesis.Header.Height)
	}
}

func TestSingleNode_RPCEndpoint(t *testing.T) {
	cfg := devTestConfig(t)
	cfg.RPCEnabled = true
	cfg.RPCAddr = "127.0.0.1:0"

	node, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	defer closeNodeDB(node)

	if err := node.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer node.Stop()

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp := node.rpcServer.HandleRequest(ctx, &rpc.Request{
		JSONRPC: "2.0",
		Method:  "eth_blockNumber",
		ID:      1,
	})
	if resp == nil {
		t.Fatal("expected non-nil response from eth_blockNumber")
	}
	if resp.Error != nil {
		t.Fatalf("RPC error: %d %s", resp.Error.Code, resp.Error.Message)
	}
}

func TestSingleNode_StatePersistence(t *testing.T) {
	dataDir := t.TempDir()

	cfg := devTestConfig(t)
	cfg.DataDir = dataDir

	node1, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode (first run): %v", err)
	}
	defer closeNodeDB(node1)
	if err := node1.Start(); err != nil {
		t.Fatalf("Start (first run): %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var height1 uint64
	for {
		height1, _ = node1.blockStore.GetLatestHeight()
		if height1 >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected at least 1 block, got %d", height1)
		}
		time.Sleep(250 * time.Millisecond)
	}
	node1.Stop()

	cfg2 := devTestConfig(t)
	cfg2.DataDir = dataDir

	node2, err := NewNode(cfg2)
	if err != nil {
		t.Fatalf("NewNode (second run): %v", err)
	}
	defer closeNodeDB(node2)
	if err := node2.Start(); err != nil {
		t.Fatalf("Start (second run): %v", err)
	}
	defer node2.Stop()

	time.Sleep(1 * time.Second)

	height2, _ := node2.blockStore.GetLatestHeight()
	if height2 < height1 {
		t.Errorf("state not persisted: expected height >= %d, got %d", height1, height2)
	}
}

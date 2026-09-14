// Quantaureum Node source, version 1.0.0.
package perf

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/common"
	"github.com/quantaureum/qau/types"
)

func TestMerkleCache(t *testing.T) {
	t.Run("NewMerkleCache", func(t *testing.T) {
		mc := NewMerkleCache(100)
		if mc == nil {
			t.Fatal("NewMerkleCache returned nil")
		}
	})

	t.Run("PutAndGet", func(t *testing.T) {
		mc := NewMerkleCache(100)
		node := &TrieNode{
			Hash:     common.Hash{1},
			NodeType: NodeTypeLeaf,
			Value:    []byte("test"),
		}
		mc.PutNode(node)

		retrieved, ok := mc.GetNode(common.Hash{1})
		if !ok {
			t.Fatal("node not found")
		}
		if string(retrieved.Value) != "test" {
			t.Errorf("expected 'test', got '%s'", retrieved.Value)
		}
	})

	t.Run("GetNotFound", func(t *testing.T) {
		mc := NewMerkleCache(100)
		_, ok := mc.GetNode(common.Hash{99})
		if ok {
			t.Error("should not find nonexistent node")
		}
	})

	t.Run("Invalidate", func(t *testing.T) {
		mc := NewMerkleCache(100)
		node := &TrieNode{Hash: common.Hash{1}, Value: []byte("test")}
		mc.PutNode(node)
		mc.Invalidate(common.Hash{1})

		_, ok := mc.GetNode(common.Hash{1})
		if ok {
			t.Error("node should have been invalidated")
		}
	})

	t.Run("FlushDirty", func(t *testing.T) {
		mc := NewMerkleCache(100)
		node := &TrieNode{Hash: common.Hash{1}, Dirty: true}
		mc.PutNode(node)

		dirty := mc.FlushDirty()
		if len(dirty) != 1 {
			t.Errorf("expected 1 dirty node, got %d", len(dirty))
		}
		if dirty[0].Dirty {
			t.Error("flushed node should not be dirty")
		}
	})

	t.Run("Stats", func(t *testing.T) {
		mc := NewMerkleCache(100)
		node := &TrieNode{Hash: common.Hash{1}}
		mc.PutNode(node)
		mc.GetNode(common.Hash{1})
		mc.GetNode(common.Hash{99})

		hits, misses, _ := mc.Stats()
		if hits != 1 {
			t.Errorf("expected 1 hit, got %d", hits)
		}
		if misses != 1 {
			t.Errorf("expected 1 miss, got %d", misses)
		}
	})

	t.Run("HitRate", func(t *testing.T) {
		mc := NewMerkleCache(100)
		if mc.HitRate() != 0 {
			t.Error("hit rate should be 0 for empty cache")
		}

		node := &TrieNode{Hash: common.Hash{1}}
		mc.PutNode(node)
		mc.GetNode(common.Hash{1})
		mc.GetNode(common.Hash{99})

		rate := mc.HitRate()
		if rate != 0.5 {
			t.Errorf("expected hit rate 0.5, got %f", rate)
		}
	})

	t.Run("ProofCache", func(t *testing.T) {
		mc := NewMerkleCache(100)
		rootHash := common.Hash{1}
		proof := [][]byte{[]byte("proof1"), []byte("proof2")}

		mc.PutProof(rootHash, proof)
		retrieved, ok := mc.GetProof(rootHash)
		if !ok {
			t.Fatal("proof not found")
		}
		if len(retrieved) != 2 {
			t.Errorf("expected 2 proof elements, got %d", len(retrieved))
		}
	})
}

func TestParallelStateAccess(t *testing.T) {
	t.Run("NewParallelStateAccess", func(t *testing.T) {
		psa := NewParallelStateAccess()
		if psa == nil {
			t.Fatal("NewParallelStateAccess returned nil")
		}
	})

	t.Run("WriteAndRead", func(t *testing.T) {
		psa := NewParallelStateAccess()
		key := common.Hash{1}
		value := []byte("hello")

		psa.Write(key, value)
		retrieved, ok := psa.Read(key)
		if !ok {
			t.Fatal("value not found")
		}
		if string(retrieved) != "hello" {
			t.Errorf("expected 'hello', got '%s'", retrieved)
		}
	})

	t.Run("ReadNotFound", func(t *testing.T) {
		psa := NewParallelStateAccess()
		_, ok := psa.Read(common.Hash{99})
		if ok {
			t.Error("should not find nonexistent key")
		}
	})

	t.Run("BatchRead", func(t *testing.T) {
		psa := NewParallelStateAccess()
		psa.Write(common.Hash{1}, []byte("a"))
		psa.Write(common.Hash{2}, []byte("b"))
		psa.Write(common.Hash{3}, []byte("c"))

		keys := []common.Hash{{1}, {2}, {3}, {99}}
		result := psa.BatchRead(keys)
		if len(result) != 3 {
			t.Errorf("expected 3 results, got %d", len(result))
		}
	})

	t.Run("BatchWrite", func(t *testing.T) {
		psa := NewParallelStateAccess()
		updates := map[common.Hash][]byte{
			{1}: []byte("x"),
			{2}: []byte("y"),
			{3}: []byte("z"),
		}
		psa.BatchWrite(updates)

		if psa.Size() != 3 {
			t.Errorf("expected size 3, got %d", psa.Size())
		}
	})

	t.Run("Snapshot", func(t *testing.T) {
		psa := NewParallelStateAccess()
		psa.Write(common.Hash{1}, []byte("data"))

		snap := psa.Snapshot()
		if len(snap) != 1 {
			t.Errorf("expected 1 entry in snapshot, got %d", len(snap))
		}

		psa.Write(common.Hash{1}, []byte("modified"))
		if string(snap[common.Hash{1}]) != "data" {
			t.Error("snapshot should not reflect modifications")
		}
	})
}

func TestNetworkOptimizer(t *testing.T) {
	t.Run("NewNetworkOptimizer", func(t *testing.T) {
		no := NewNetworkOptimizer(CompressionDefault)
		if no == nil {
			t.Fatal("NewNetworkOptimizer returned nil")
		}
	})

	t.Run("CompressDecompress", func(t *testing.T) {
		no := NewNetworkOptimizer(CompressionDefault)
		data := []byte("hello world hello world hello world")

		compressed, err := no.Compress(data)
		if err != nil {
			t.Fatalf("Compress failed: %v", err)
		}

		decompressed, err := no.Decompress(compressed)
		if err != nil {
			t.Fatalf("Decompress failed: %v", err)
		}

		if string(decompressed) != string(data) {
			t.Errorf("expected '%s', got '%s'", data, decompressed)
		}
	})

	t.Run("CompressNone", func(t *testing.T) {
		no := NewNetworkOptimizer(CompressionNone)
		data := []byte("test")

		compressed, _ := no.Compress(data)
		if string(compressed) != "test" {
			t.Error("no compression should return original data")
		}
	})

	t.Run("CompressionRatio", func(t *testing.T) {
		no := NewNetworkOptimizer(CompressionBest)
		data := make([]byte, 10000)
		for i := range data {
			data[i] = byte(i % 256)
		}

		no.Compress(data)
		ratio := no.CompressionRatio()
		if ratio <= 0 {
			t.Error("compression ratio should be positive for random data")
		}
	})

	t.Run("GetStats", func(t *testing.T) {
		no := NewNetworkOptimizer(CompressionBest)
		data := make([]byte, 10000)
		for i := range data {
			data[i] = byte(i % 256)
		}
		no.Compress(data)

		stats := no.GetStats()
		if stats.TotalBytes == 0 {
			t.Error("stats should track total bytes after compression")
		}
	})
}

func TestMessageBatcher(t *testing.T) {
	t.Run("NewMessageBatcher", func(t *testing.T) {
		mb := NewMessageBatcher(10, time.Second)
		if mb == nil {
			t.Fatal("NewMessageBatcher returned nil")
		}
	})

	t.Run("BatchBySize", func(t *testing.T) {
		mb := NewMessageBatcher(3, time.Hour)

		if batch := mb.Add([]byte("a")); batch != nil {
			t.Error("should not flush at size 1")
		}
		if batch := mb.Add([]byte("b")); batch != nil {
			t.Error("should not flush at size 2")
		}

		batch := mb.Add([]byte("c"))
		if batch == nil {
			t.Fatal("should flush at size 3")
		}
		if len(batch) != 3 {
			t.Errorf("expected batch size 3, got %d", len(batch))
		}
	})

	t.Run("ForceFlush", func(t *testing.T) {
		mb := NewMessageBatcher(10, time.Hour)
		mb.Add([]byte("a"))
		mb.Add([]byte("b"))

		batch := mb.ForceFlush()
		if len(batch) != 2 {
			t.Errorf("expected batch size 2, got %d", len(batch))
		}
		if mb.Size() != 0 {
			t.Error("buffer should be empty after flush")
		}
	})
}

func TestAdaptiveThrottle(t *testing.T) {
	t.Run("NewAdaptiveThrottle", func(t *testing.T) {
		at := NewAdaptiveThrottle(10, 100)
		if at == nil {
			t.Fatal("NewAdaptiveThrottle returned nil")
		}
	})

	t.Run("Allow", func(t *testing.T) {
		at := NewAdaptiveThrottle(100, 1000)
		if !at.Allow() {
			t.Error("should allow first request")
		}
	})

	t.Run("AdjustRate", func(t *testing.T) {
		at := NewAdaptiveThrottle(10, 100)
		at.AdjustRate(0.5)
		at.AdjustRate(0.5)
		lowRate := at.GetCurrentRate()

		at.AdjustRate(0.99)
		if at.GetCurrentRate() <= lowRate {
			t.Error("rate should increase with high success rate")
		}
	})
}

func TestOptimizedTxPool(t *testing.T) {
	t.Run("NewOptimizedTxPool", func(t *testing.T) {
		tp := NewOptimizedTxPool(1000, 64)
		if tp == nil {
			t.Fatal("NewOptimizedTxPool returned nil")
		}
	})

	t.Run("Add", func(t *testing.T) {
		tp := NewOptimizedTxPool(1000, 64)
		tx := &PrioritizedTx{
			Hash:     common.Hash{1},
			From:     types.Address{1},
			Nonce:    0,
			GasPrice: big.NewInt(100),
			Priority: TxPriorityNormal,
			Size:     100,
		}

		err := tp.Add(tx)
		if err != nil {
			t.Fatalf("Add failed: %v", err)
		}
		if tp.Size() != 1 {
			t.Errorf("expected size 1, got %d", tp.Size())
		}
	})

	t.Run("AddDuplicate", func(t *testing.T) {
		tp := NewOptimizedTxPool(1000, 64)
		tx := &PrioritizedTx{
			Hash:     common.Hash{1},
			From:     types.Address{1},
			Nonce:    0,
			GasPrice: big.NewInt(100),
			Priority: TxPriorityNormal,
		}

		tp.Add(tx)
		err := tp.Add(tx)
		if err != nil {
			t.Fatalf("Add duplicate failed: %v", err)
		}
		if tp.Size() != 1 {
			t.Errorf("expected size 1 after duplicate, got %d", tp.Size())
		}
	})

	t.Run("GetBest", func(t *testing.T) {
		tp := NewOptimizedTxPool(1000, 64)

		tp.Add(&PrioritizedTx{
			Hash: common.Hash{1}, From: types.Address{1}, Nonce: 0,
			GasPrice: big.NewInt(100), Priority: TxPriorityNormal, Size: 100,
		})
		tp.Add(&PrioritizedTx{
			Hash: common.Hash{2}, From: types.Address{2}, Nonce: 0,
			GasPrice: big.NewInt(200), Priority: TxPriorityHigh, Size: 100,
		})
		tp.Add(&PrioritizedTx{
			Hash: common.Hash{3}, From: types.Address{3}, Nonce: 0,
			GasPrice: big.NewInt(50), Priority: TxPriorityLow, Size: 100,
		})

		best := tp.GetBest(2)
		if len(best) != 2 {
			t.Errorf("expected 2 best txs, got %d", len(best))
		}
		if best[0].Priority != TxPriorityHigh {
			t.Error("first tx should have highest priority")
		}
	})

	t.Run("Remove", func(t *testing.T) {
		tp := NewOptimizedTxPool(1000, 64)
		tx := &PrioritizedTx{
			Hash: common.Hash{1}, From: types.Address{1}, Nonce: 0,
			GasPrice: big.NewInt(100), Priority: TxPriorityNormal, Size: 100,
		}
		tp.Add(tx)
		tp.Remove(common.Hash{1})

		if tp.Size() != 0 {
			t.Errorf("expected size 0 after remove, got %d", tp.Size())
		}
	})

	t.Run("GetByAddress", func(t *testing.T) {
		tp := NewOptimizedTxPool(1000, 64)
		addr := types.Address{1}

		tp.Add(&PrioritizedTx{
			Hash: common.Hash{1}, From: addr, Nonce: 0,
			GasPrice: big.NewInt(100), Priority: TxPriorityNormal, Size: 100,
		})
		tp.Add(&PrioritizedTx{
			Hash: common.Hash{2}, From: addr, Nonce: 1,
			GasPrice: big.NewInt(200), Priority: TxPriorityNormal, Size: 100,
		})

		txs := tp.GetByAddress(addr)
		if len(txs) != 2 {
			t.Errorf("expected 2 txs for address, got %d", len(txs))
		}
	})

	t.Run("PendingCount", func(t *testing.T) {
		tp := NewOptimizedTxPool(1000, 64)
		if tp.PendingCount() != 0 {
			t.Error("expected 0 pending initially")
		}

		tp.Add(&PrioritizedTx{
			Hash: common.Hash{1}, From: types.Address{1}, Nonce: 0,
			GasPrice: big.NewInt(100), Priority: TxPriorityNormal, Size: 100,
		})
		if tp.PendingCount() != 1 {
			t.Errorf("expected 1 pending, got %d", tp.PendingCount())
		}
	})
}

func TestParallelTxValidator(t *testing.T) {
	t.Run("NewParallelTxValidator", func(t *testing.T) {
		pv := NewParallelTxValidator(4)
		if pv == nil {
			t.Fatal("NewParallelTxValidator returned nil")
		}
	})

	t.Run("ValidateBatch", func(t *testing.T) {
		pv := NewParallelTxValidator(4)
		txs := []*PrioritizedTx{
			{Hash: common.Hash{1}, GasPrice: big.NewInt(100), Size: 100},
			{Hash: common.Hash{2}, GasPrice: big.NewInt(200), Size: 100},
			{Hash: common.Hash{3}, GasPrice: nil, Size: 100},
			{Hash: common.Hash{4}, GasPrice: big.NewInt(300), Size: 200000},
		}

		valid := pv.ValidateBatch(txs)
		if len(valid) != 2 {
			t.Errorf("expected 2 valid txs, got %d", len(valid))
		}
	})
}

func TestParallelBlockValidator(t *testing.T) {
	t.Run("NewParallelBlockValidator", func(t *testing.T) {
		pbv := NewParallelBlockValidator(4)
		if pbv == nil {
			t.Fatal("NewParallelBlockValidator returned nil")
		}
	})

	t.Run("ValidateBlocks", func(t *testing.T) {
		pbv := NewParallelBlockValidator(4)
		hashes := []common.Hash{{1}, {2}, {3}}

		validateFn := func(h common.Hash) (bool, error) {
			return h[0]%2 == 0, nil
		}

		results := pbv.ValidateBlocks(hashes, validateFn)
		if len(results) != 3 {
			t.Errorf("expected 3 results, got %d", len(results))
		}
	})
}

func TestConsensusPipeline(t *testing.T) {
	t.Run("NewConsensusPipeline", func(t *testing.T) {
		cp := NewConsensusPipeline(10)
		if cp == nil {
			t.Fatal("NewConsensusPipeline returned nil")
		}
	})

	t.Run("AddStage", func(t *testing.T) {
		cp := NewConsensusPipeline(10)
		cp.AddStage("validate", func(b *PipelineBlock) error {
			return nil
		})
	})

	t.Run("StartStop", func(t *testing.T) {
		cp := NewConsensusPipeline(10)
		cp.AddStage("validate", func(b *PipelineBlock) error {
			return nil
		})

		cp.Start()
		time.Sleep(10 * time.Millisecond)
		cp.Stop()
	})

	t.Run("SubmitAndReceive", func(t *testing.T) {
		cp := NewConsensusPipeline(10)
		processed := false

		cp.AddStage("validate", func(b *PipelineBlock) error {
			processed = true
			return nil
		})

		cp.Start()
		defer cp.Stop()

		block := &PipelineBlock{
			Hash:   common.Hash{1},
			Height: 100,
		}
		cp.Submit(block)

		select {
		case result := <-cp.Output():
			if result.Error != nil {
				t.Errorf("unexpected error: %v", result.Error)
			}
			if !processed {
				t.Error("stage was not processed")
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for pipeline output")
		}
	})
}

func TestBatchVerifier(t *testing.T) {
	t.Run("NewBatchVerifier", func(t *testing.T) {
		bv := NewBatchVerifier(10)
		if bv == nil {
			t.Fatal("NewBatchVerifier returned nil")
		}
	})

	t.Run("AddTask", func(t *testing.T) {
		bv := NewBatchVerifier(2)

		bv.AddTask(&VerificationTask{
			ID:        "task-1",
			Signature: []byte("sig"),
			PubKey:    []byte("key"),
		})
		bv.AddTask(&VerificationTask{
			ID:        "task-2",
			Signature: []byte("sig"),
			PubKey:    []byte("key"),
		})

		count := 0
		timeout := time.After(time.Second)

		for count < 2 {
			select {
			case result := <-bv.Results():
				_ = result
				count++
			case <-timeout:
				t.Fatalf("timeout waiting for results, got %d", count)
			}
		}
	})

	t.Run("Flush", func(t *testing.T) {
		bv := NewBatchVerifier(10)
		bv.AddTask(&VerificationTask{
			ID:        "task-1",
			Signature: []byte("sig"),
			PubKey:    []byte("key"),
		})
		bv.Flush()

		select {
		case result := <-bv.Results():
			_ = result
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for flush result")
		}
	})
}

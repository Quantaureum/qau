// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"testing"
)

func TestBroadcasterNew(t *testing.T) {
	b := NewBroadcaster(nil)
	if b == nil {
		t.Fatal("NewBroadcaster returned nil")
	}
	defer b.Stop()
}

func TestBroadcasterMarkBlockSeen(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	data := []byte("block-data")

	if b.IsBlockSeen(data) {
		t.Error("block should not be seen initially")
	}

	b.MarkBlockSeen(data)

	if !b.IsBlockSeen(data) {
		t.Error("block should be seen after MarkBlockSeen")
	}
}

func TestBroadcasterMarkTxSeen(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	data := []byte("tx-data")

	if b.IsTxSeen(data) {
		t.Error("tx should not be seen initially")
	}

	b.MarkTxSeen(data)

	if !b.IsTxSeen(data) {
		t.Error("tx should be seen after MarkTxSeen")
	}
}

func TestBroadcasterMarkVoteSeen(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	data := []byte("vote-data")

	if b.IsVoteSeen(data) {
		t.Error("vote should not be seen initially")
	}

	b.MarkVoteSeen(data)

	if !b.IsVoteSeen(data) {
		t.Error("vote should be seen after MarkVoteSeen")
	}
}

func TestBroadcasterDeduplication(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	data := []byte("block-data")
	b.MarkBlockSeen(data)

	// Second mark should not cause issues
	b.MarkBlockSeen(data)

	if !b.IsBlockSeen(data) {
		t.Error("block should still be seen after second mark")
	}
}

func TestBroadcasterDifferentData(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	data1 := []byte("block-data-1")
	data2 := []byte("block-data-2")

	b.MarkBlockSeen(data1)

	if b.IsBlockSeen(data2) {
		t.Error("different data should not be seen")
	}
}

func TestBroadcasterStop(t *testing.T) {
	b := NewBroadcaster(nil)
	b.Stop()
	// Double stop should not panic
	b.Stop()
}

func TestHashData(t *testing.T) {
	data := []byte("test data")
	hash1 := hashData(data)
	hash2 := hashData(data)

	if hash1 != hash2 {
		t.Error("hashData should be deterministic")
	}

	differentData := []byte("different data")
	hash3 := hashData(differentData)
	if hash1 == hash3 {
		t.Error("different data should produce different hashes")
	}
}

func TestBroadcasterBroadcastBlockNoHost(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	// Without a host, BroadcastBlock should panic or return error
	// We test this by verifying the broadcaster works without a host for dedup
	data := []byte("block-data")
	b.MarkBlockSeen(data)

	// Already seen block should be a no-op
	err := b.BroadcastBlock(context.Background(), data)
	if err != nil {
		t.Errorf("BroadcastBlock for seen block should not error: %v", err)
	}
}

func TestBroadcasterBroadcastTxNoHost(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	data := []byte("tx-data")
	b.MarkTxSeen(data)

	err := b.BroadcastTransaction(context.Background(), data)
	if err != nil {
		t.Errorf("BroadcastTransaction for seen tx should not error: %v", err)
	}
}

func TestBroadcasterBroadcastVoteNoHost(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	data := []byte("vote-data")
	b.MarkVoteSeen(data)

	err := b.BroadcastVote(context.Background(), data)
	if err != nil {
		t.Errorf("BroadcastVote for seen vote should not error: %v", err)
	}
}

func TestBroadcasterBroadcastBlockDedup(t *testing.T) {
	b := NewBroadcaster(nil)
	defer b.Stop()

	data := []byte("block-data")
	b.MarkBlockSeen(data)

	// Should return nil (already seen, no-op)
	err := b.BroadcastBlock(context.Background(), data)
	if err != nil {
		t.Errorf("BroadcastBlock for seen block should return nil: %v", err)
	}
}

// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"testing"
	"time"
)

func TestPriorityQueueEnqueueDequeue(t *testing.T) {
	pq := NewPriorityQueue(DefaultPriorityQueueConfig())

	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block")})
	pq.Enqueue(&Message{Type: MsgTypeTransaction, Payload: []byte("tx")})
	pq.Enqueue(&Message{Type: MsgTypeVote, Payload: []byte("vote")})

	ctx := context.Background()

	// Block and Vote are high priority, Transaction is low
	msg, err := pq.Dequeue(ctx)
	if err != nil {
		t.Fatalf("Dequeue failed: %v", err)
	}
	// First should be a high priority message (block or vote)
	if msg.Type != MsgTypeBlock && msg.Type != MsgTypeVote {
		t.Errorf("first message type = %d, expected high priority", msg.Type)
	}
}

func TestPriorityQueueOrdering(t *testing.T) {
	pq := NewPriorityQueue(DefaultPriorityQueueConfig())

	// Enqueue low priority first, then high priority
	pq.Enqueue(&Message{Type: MsgTypeTransaction, Payload: []byte("tx")}) // low
	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block")})    // high

	ctx := context.Background()
	msg, _ := pq.Dequeue(ctx)
	if msg.Type != MsgTypeBlock {
		t.Errorf("expected block (high priority) first, got type %d", msg.Type)
	}
}

func TestPriorityQueueOverridePriority(t *testing.T) {
	pq := NewPriorityQueue(DefaultPriorityQueueConfig())

	// Override transaction to critical priority
	pq.Enqueue(&Message{Type: MsgTypeTransaction, Payload: []byte("critical-tx")}, PriorityCritical)
	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block")}) // high priority

	ctx := context.Background()
	msg, _ := pq.Dequeue(ctx)
	if msg.Type != MsgTypeTransaction {
		t.Errorf("expected critical tx first, got type %d", msg.Type)
	}
}

func TestPriorityQueueLen(t *testing.T) {
	pq := NewPriorityQueue(DefaultPriorityQueueConfig())

	if pq.Len() != 0 {
		t.Errorf("Len = %d, want 0", pq.Len())
	}

	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block")})
	pq.Enqueue(&Message{Type: MsgTypeVote, Payload: []byte("vote")})

	if pq.Len() != 2 {
		t.Errorf("Len = %d, want 2", pq.Len())
	}
}

func TestPriorityQueueDequeueBatch(t *testing.T) {
	cfg := DefaultPriorityQueueConfig()
	cfg.BatchSize = 3
	pq := NewPriorityQueue(cfg)

	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("b1")})
	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("b2")})
	pq.Enqueue(&Message{Type: MsgTypeVote, Payload: []byte("v1")})

	ctx := context.Background()
	batch, err := pq.DequeueBatch(ctx)
	if err != nil {
		t.Fatalf("DequeueBatch failed: %v", err)
	}
	if len(batch) < 1 {
		t.Errorf("batch size = %d, want at least 1", len(batch))
	}
}

func TestPriorityQueueDequeueCancel(t *testing.T) {
	pq := NewPriorityQueue(DefaultPriorityQueueConfig())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := pq.Dequeue(ctx)
	if err == nil {
		t.Error("expected error from canceled context")
	}
}

func TestPriorityQueueStats(t *testing.T) {
	pq := NewPriorityQueue(DefaultPriorityQueueConfig())

	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block")})
	pq.Enqueue(&Message{Type: MsgTypeTransaction, Payload: []byte("tx")})

	stats := pq.Stats()
	if stats.TotalEnqueued != 2 {
		t.Errorf("TotalEnqueued = %d, want 2", stats.TotalEnqueued)
	}
	if stats.CurrentSize != 2 {
		t.Errorf("CurrentSize = %d, want 2", stats.CurrentSize)
	}
}

func TestPriorityQueueDropOnFull(t *testing.T) {
	cfg := DefaultPriorityQueueConfig()
	cfg.MaxQueueSize = 2
	pq := NewPriorityQueue(cfg)

	pq.Enqueue(&Message{Type: MsgTypeTransaction, Payload: []byte("tx1")}) // low
	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block1")})    // high

	// Adding a third should drop the lowest priority
	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block2")}) // high

	stats := pq.Stats()
	if stats.TotalDropped != 1 {
		t.Errorf("TotalDropped = %d, want 1", stats.TotalDropped)
	}
}

func TestPriorityQueueNilConfig(t *testing.T) {
	pq := NewPriorityQueue(nil)
	if pq == nil {
		t.Error("NewPriorityQueue(nil) should not return nil")
	}
}

func TestMsgTypePriority(t *testing.T) {
	tests := []struct {
		msgType  uint8
		expected MessagePriority
	}{
		{MsgTypeCheckpointSig, PriorityCritical},
		{MsgTypeBlock, PriorityHigh},
		{MsgTypeVote, PriorityHigh},
		{MsgTypeAttestation, PriorityHigh},
		{MsgTypeStatus, PriorityMedium},
		{MsgTypePing, PriorityMedium},
		{MsgTypePong, PriorityMedium},
		{MsgTypeTransaction, PriorityLow},
		{MsgTypeFindNode, PriorityLow},
		{99, PriorityLow}, // unknown type
	}

	for _, tt := range tests {
		result := msgTypePriority(tt.msgType)
		if result != tt.expected {
			t.Errorf("msgTypePriority(%d) = %d, want %d", tt.msgType, result, tt.expected)
		}
	}
}

func TestPriorityQueueFIFOWithinSamePriority(t *testing.T) {
	pq := NewPriorityQueue(DefaultPriorityQueueConfig())

	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block1")})
	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block2")})
	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block3")})

	ctx := context.Background()
	msg1, _ := pq.Dequeue(ctx)
	msg2, _ := pq.Dequeue(ctx)
	msg3, _ := pq.Dequeue(ctx)

	if string(msg1.Payload) != "block1" {
		t.Errorf("expected block1 first, got %q", string(msg1.Payload))
	}
	if string(msg2.Payload) != "block2" {
		t.Errorf("expected block2 second, got %q", string(msg2.Payload))
	}
	if string(msg3.Payload) != "block3" {
		t.Errorf("expected block3 third, got %q", string(msg3.Payload))
	}
}

func TestPriorityQueueDequeueBatchTimeout(t *testing.T) {
	cfg := DefaultPriorityQueueConfig()
	cfg.BatchSize = 10
	cfg.MaxWaitTime = 10 * time.Millisecond
	pq := NewPriorityQueue(cfg)

	pq.Enqueue(&Message{Type: MsgTypeBlock, Payload: []byte("block")})

	ctx := context.Background()
	batch, err := pq.DequeueBatch(ctx)
	if err != nil {
		t.Fatalf("DequeueBatch failed: %v", err)
	}
	// Should return the one message even though batch size is 10
	if len(batch) != 1 {
		t.Errorf("batch size = %d, want 1", len(batch))
	}
}

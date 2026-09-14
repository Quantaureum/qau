// Quantaureum Node source, version 1.0.0.
// Package p2p provides priority-based message queue for P2P broadcasting.
//
// PriorityQueue ensures that high-priority messages (consensus votes, blocks)
// are sent before low-priority messages (transactions, sync data).
// This is critical for consensus liveness: a flood of transactions should
// never delay consensus messages that are needed for block finalization.
//
// Inspired by Hyperliquid's data flow pipeline, adapted for Quantaureum's
// three-chamber architecture where consensus messages must arrive promptly
// for the Review Chamber and Seal Chamber to function.
package p2p

import (
	"container/heap"
	"context"
	"sync"
	"time"
)

// MessagePriority defines the priority level of a P2P message.
type MessagePriority int

const (
	// PriorityCritical is for messages that must be delivered immediately.
	// Used for: QTD finality signatures, checkpoint signatures.
	PriorityCritical MessagePriority = 0

	// PriorityHigh is for consensus-critical messages.
	// Used for: blocks, votes, attestations.
	PriorityHigh MessagePriority = 1

	// PriorityMedium is for protocol messages.
	// Used for: status, ping/pong, block requests.
	PriorityMedium MessagePriority = 2

	// PriorityLow is for non-urgent messages.
	// Used for: transactions, sync data, discovery.
	PriorityLow MessagePriority = 3
)

// msgTypePriority maps message types to their default priority.
func msgTypePriority(msgType uint8) MessagePriority {
	switch msgType {
	// Critical: QTD finality and checkpoint signatures
	case MsgTypeCheckpointSig:
		return PriorityCritical

	// High: consensus messages
	case MsgTypeBlock, MsgTypeVote, MsgTypeAttestation,
		MsgTypeAggregateAttest, MsgTypeProposerSlashing,
		MsgTypeAttesterSlashing, MsgTypeCheckpointReq,
		// HIGH-01 (R18, 2026-07-23): QTD seal announcements carry
		// finality-critical data and must be delivered promptly.
		MsgTypeQTDSealAnnouncement:
		return PriorityHigh

	// Medium: protocol messages
	case MsgTypeStatus, MsgTypePing, MsgTypePong,
		MsgTypeBlockReq, MsgTypeBlockResp,
		MsgTypeChallenge, MsgTypeChallengeResponse,
		MsgTypeProtocolNegotiate, MsgTypeProtocolNegotiateResp:
		return PriorityMedium

	// Low: everything else (transactions, sync, discovery)
	default:
		return PriorityLow
	}
}

// queuedMessage wraps a Message with priority and ordering metadata.
type queuedMessage struct {
	msg      *Message
	priority MessagePriority
	seqNum   uint64 // Global sequence number for FIFO within same priority
	enqueued time.Time
}

// priorityQueue implements heap.Interface for priority-based ordering.
// Messages are ordered by: priority (lower = higher priority), then seqNum (FIFO).
type priorityQueue []*queuedMessage

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	if pq[i].priority != pq[j].priority {
		return pq[i].priority < pq[j].priority // Lower number = higher priority
	}
	return pq[i].seqNum < pq[j].seqNum // FIFO within same priority
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *priorityQueue) Push(x any) {
	item := x.(*queuedMessage)
	*pq = append(*pq, item)
}

func (pq *priorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	*pq = old[0 : n-1]
	return item
}

// PriorityQueueConfig holds configuration for the priority queue.
type PriorityQueueConfig struct {
	// MaxQueueSize is the maximum number of messages in the queue.
	// When full, lowest-priority messages are dropped.
	MaxQueueSize int

	// BatchSize is the maximum number of messages to dequeue at once.
	BatchSize int

	// MaxWaitTime is the maximum time to wait before dequeuing a partial batch.
	MaxWaitTime time.Duration
}

// DefaultPriorityQueueConfig returns sensible defaults.
func DefaultPriorityQueueConfig() *PriorityQueueConfig {
	return &PriorityQueueConfig{
		MaxQueueSize: 10000,
		BatchSize:    64,
		MaxWaitTime:  10 * time.Millisecond,
	}
}

// PriorityQueue is a thread-safe priority queue for P2P messages.
type PriorityQueue struct {
	mu     sync.Mutex
	pq     priorityQueue
	config *PriorityQueueConfig
	seqNum uint64

	// Signal channel for blocking dequeue
	notify chan struct{}

	// Stats
	totalEnqueued uint64
	totalDequeued uint64
	totalDropped  uint64

	// Per-priority counters
	enqueuedByPriority [4]uint64
	dequeuedByPriority [4]uint64
}

// NewPriorityQueue creates a new PriorityQueue.
func NewPriorityQueue(cfg *PriorityQueueConfig) *PriorityQueue {
	if cfg == nil {
		cfg = DefaultPriorityQueueConfig()
	}

	pq := &PriorityQueue{
		pq:     make(priorityQueue, 0, cfg.MaxQueueSize),
		config: cfg,
		notify: make(chan struct{}, 1),
	}

	heap.Init(&pq.pq)
	return pq
}

// Enqueue adds a message to the priority queue.
// The message's priority is determined by its type, but can be overridden.
func (pq *PriorityQueue) Enqueue(msg *Message, overridePriority ...MessagePriority) {
	priority := msgTypePriority(msg.Type)
	if len(overridePriority) > 0 {
		priority = overridePriority[0]
	}

	pq.mu.Lock()
	defer pq.mu.Unlock()

	// Check if queue is full
	if len(pq.pq) >= pq.config.MaxQueueSize {
		// Drop the lowest priority message
		pq.dropLowestPriority()
		pq.totalDropped++
	}

	pq.seqNum++
	item := &queuedMessage{
		msg:      msg,
		priority: priority,
		seqNum:   pq.seqNum,
		enqueued: time.Now(),
	}

	heap.Push(&pq.pq, item)
	pq.totalEnqueued++
	if int(priority) < len(pq.enqueuedByPriority) {
		pq.enqueuedByPriority[priority]++
	}

	// Notify waiting dequeuer
	select {
	case pq.notify <- struct{}{}:
	default:
	}
}

// Dequeue removes and returns the highest-priority message.
// Blocks until a message is available or context is canceled.
func (pq *PriorityQueue) Dequeue(ctx context.Context) (*Message, error) {
	for {
		pq.mu.Lock()
		if len(pq.pq) > 0 {
			item := heap.Pop(&pq.pq).(*queuedMessage)
			pq.totalDequeued++
			if int(item.priority) < len(pq.dequeuedByPriority) {
				pq.dequeuedByPriority[item.priority]++
			}
			pq.mu.Unlock()
			return item.msg, nil
		}
		pq.mu.Unlock()

		// Wait for notification or context cancellation
		select {
		case <-pq.notify:
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// DequeueBatch removes and returns up to batchSize highest-priority messages.
// Returns immediately if any messages are available, waits up to maxWaitTime
// for more messages to fill the batch.
func (pq *PriorityQueue) DequeueBatch(ctx context.Context) ([]*Message, error) {
	// Wait for at least one message
	msg, err := pq.Dequeue(ctx)
	if err != nil {
		return nil, err
	}
	batch := []*Message{msg}

	// Try to fill the batch without blocking
	deadline := time.After(pq.config.MaxWaitTime)
	for len(batch) < pq.config.BatchSize {
		select {
		case <-deadline:
			return batch, nil
		default:
		}

		pq.mu.Lock()
		if len(pq.pq) > 0 {
			item := heap.Pop(&pq.pq).(*queuedMessage)
			pq.totalDequeued++
			if int(item.priority) < len(pq.dequeuedByPriority) {
				pq.dequeuedByPriority[item.priority]++
			}
			pq.mu.Unlock()
			batch = append(batch, item.msg)
		} else {
			pq.mu.Unlock()
			return batch, nil
		}
	}

	return batch, nil
}

// Len returns the number of messages in the queue.
func (pq *PriorityQueue) Len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.pq)
}

// Stats returns queue statistics.
type QueueStats struct {
	TotalEnqueued      uint64
	TotalDequeued      uint64
	TotalDropped       uint64
	CurrentSize        int
	EnqueuedByPriority [4]uint64
	DequeuedByPriority [4]uint64
}

// Stats returns current queue statistics.
func (pq *PriorityQueue) Stats() QueueStats {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	return QueueStats{
		TotalEnqueued:      pq.totalEnqueued,
		TotalDequeued:      pq.totalDequeued,
		TotalDropped:       pq.totalDropped,
		CurrentSize:        len(pq.pq),
		EnqueuedByPriority: pq.enqueuedByPriority,
		DequeuedByPriority: pq.dequeuedByPriority,
	}
}

// dropLowestPriority removes the lowest-priority message from the queue.
// Must be called with pq.mu held.
func (pq *PriorityQueue) dropLowestPriority() {
	if len(pq.pq) == 0 {
		return
	}

	// Find the lowest priority message (highest number = lowest priority)
	lowestIdx := 0
	lowestPriority := pq.pq[0].priority
	lowestSeqNum := pq.pq[0].seqNum

	for i, item := range pq.pq {
		if item.priority > lowestPriority ||
			(item.priority == lowestPriority && item.seqNum > lowestSeqNum) {
			lowestIdx = i
			lowestPriority = item.priority
			lowestSeqNum = item.seqNum
		}
	}

	// Remove the lowest priority item
	heap.Remove(&pq.pq, lowestIdx)
}

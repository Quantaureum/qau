// Quantaureum Node source, version 1.0.0.
package gossipsub

import (
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Mock MessageSender for testing
// =============================================================================

// mockSender is a test fake for the MessageSender interface. Its fields are
// accessed from multiple goroutines (the test main goroutine + heartbeat
// goroutines spawned by performHeartbeat → sendGraft → SendGossipSub), so a
// mutex protects all map/slice mutations to prevent "concurrent map writes"
// fatal errors (R30, 2026-07-26).
type mockSender struct {
	mu           sync.Mutex
	sentMessages map[PeerID][][]byte
	peerIDs      []PeerID
	peerScores   map[PeerID]float64
}

func newMockSender() *mockSender {
	return &mockSender{
		sentMessages: make(map[PeerID][][]byte),
		peerIDs:      []PeerID{"peer1", "peer2", "peer3", "peer4", "peer5", "peer6", "peer7", "peer8", "peer9", "peer10"},
		peerScores:   make(map[PeerID]float64),
	}
}

func (m *mockSender) SendGossipSub(peerID PeerID, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMessages[peerID] = append(m.sentMessages[peerID], data)
	return nil
}

func (m *mockSender) GetConnectedPeers() []PeerID {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy to avoid callers mutating the slice while the lock is
	// released (defensive against data races on the returned slice).
	out := make([]PeerID, len(m.peerIDs))
	copy(out, m.peerIDs)
	return out
}

func (m *mockSender) GetPeerScore(peerID PeerID) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if score, ok := m.peerScores[peerID]; ok {
		return score
	}
	return 0
}

func (m *mockSender) addPeer(id PeerID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peerIDs = append(m.peerIDs, id)
}

func (m *mockSender) removePeer(id PeerID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, p := range m.peerIDs {
		if p == id {
			m.peerIDs = append(m.peerIDs[:i], m.peerIDs[i+1:]...)
			break
		}
	}
}

// =============================================================================
// Tests
// =============================================================================

func TestNewGossipSub(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)

	if gs == nil {
		t.Fatal("NewGossipSub returned nil")
	}
	if gs.cfg.D != GossipSubD {
		t.Errorf("expected D=%d, got %d", GossipSubD, gs.cfg.D)
	}

	gs.Stop()
}

func TestGossipSubStartStop(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)

	if err := gs.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Double start should fail
	if err := gs.Start(); err == nil {
		t.Error("expected error on double start")
	}

	gs.Stop()

	// Stop after stop should be safe
	gs.Stop()
}

func TestJoinLeaveTopic(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	msgReceived := make(chan *Message, 1)
	handler := func(msg *Message) {
		msgReceived <- msg
	}

	topic, err := gs.JoinTopic(TopicBlocks, handler)
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}
	if topic == nil {
		t.Fatal("JoinTopic returned nil topic")
	}
	if topic.name != TopicBlocks {
		t.Errorf("expected topic name %s, got %s", TopicBlocks, topic.name)
	}

	// Duplicate join should fail
	_, err = gs.JoinTopic(TopicBlocks, handler)
	if err == nil {
		t.Error("expected error on duplicate join")
	}

	// Leave topic
	if err := gs.LeaveTopic(TopicBlocks); err != nil {
		t.Fatalf("LeaveTopic failed: %v", err)
	}

	// Leave non-existent topic should fail
	if err := gs.LeaveTopic(TopicBlocks); err == nil {
		t.Error("expected error on leaving non-existent topic")
	}
}

func TestPublishMessage(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	msgReceived := make(chan *Message, 10)
	handler := func(msg *Message) {
		msgReceived <- msg
	}

	_, err := gs.JoinTopic(TopicBlocks, handler)
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Wait for mesh to build
	time.Sleep(100 * time.Millisecond)

	err = gs.Publish(TopicBlocks, []byte("test block data"))
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Publish to non-existent topic
	err = gs.Publish("nonexistent", []byte("data"))
	if err == nil {
		t.Error("expected error on publishing to non-existent topic")
	}
}

func TestHandleRPC(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	msgReceived := make(chan *Message, 10)
	handler := func(msg *Message) {
		msgReceived <- msg
	}

	_, err := gs.JoinTopic(TopicBlocks, handler)
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Send a GRAFT from a peer
	rpc := &RPC{
		Control: &ControlMessage{
			Graft: []*ControlGraft{{Topic: TopicBlocks}},
		},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}

	err = gs.HandleRPC("peer1", data)
	if err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Send a message from the peer
	rpc = &RPC{
		Messages: []*Message{{
			ID:    ComputeMessageID(TopicBlocks, []byte("hello")),
			Topic: TopicBlocks,
			Data:  []byte("hello"),
			SeqNo: 1,
		}},
	}
	data, err = EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}

	err = gs.HandleRPC("peer1", data)
	if err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Should receive the message via handler
	select {
	case msg := <-msgReceived:
		if string(msg.Data) != "hello" {
			t.Errorf("expected 'hello', got '%s'", string(msg.Data))
		}
		if msg.From != "peer1" {
			t.Errorf("expected from 'peer1', got '%s'", msg.From)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestEncodeDecodeRPC(t *testing.T) {
	msgID := ComputeMessageID(TopicBlocks, []byte("test"))

	rpc := &RPC{
		Messages: []*Message{
			{
				ID:    msgID,
				Topic: TopicBlocks,
				Data:  []byte("test data"),
				SeqNo: 42,
			},
		},
		Control: &ControlMessage{
			Graft: []*ControlGraft{{Topic: TopicBlocks}},
			Prune: []*ControlPrune{{Topic: TopicVotes, Reason: "test"}},
			IHave: []*ControlIHave{{
				Topic:      TopicBlocks,
				MessageIDs: []MessageID{msgID},
			}},
		},
	}

	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}

	decoded, err := DecodeRPC(data)
	if err != nil {
		t.Fatalf("DecodeRPC failed: %v", err)
	}

	if len(decoded.Messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(decoded.Messages))
	}
	if decoded.Messages[0].SeqNo != 42 {
		t.Errorf("expected seqno 42, got %d", decoded.Messages[0].SeqNo)
	}
	if decoded.Messages[0].Topic != TopicBlocks {
		t.Errorf("expected topic '%s', got '%s'", TopicBlocks, decoded.Messages[0].Topic)
	}
	if string(decoded.Messages[0].Data) != "test data" {
		t.Errorf("expected 'test data', got '%s'", string(decoded.Messages[0].Data))
	}

	if decoded.Control == nil {
		t.Fatal("expected control messages")
	}
	if len(decoded.Control.Graft) != 1 {
		t.Errorf("expected 1 graft, got %d", len(decoded.Control.Graft))
	}
	if len(decoded.Control.Prune) != 1 {
		t.Errorf("expected 1 prune, got %d", len(decoded.Control.Prune))
	}
	if len(decoded.Control.IHave) != 1 {
		t.Errorf("expected 1 ihave, got %d", len(decoded.Control.IHave))
	}
}

func TestEncodeDecodeRPCMessagesOnly(t *testing.T) {
	rpc := &RPC{
		Messages: []*Message{
			{ID: ComputeMessageID(TopicBlocks, []byte("msg1")), Topic: TopicBlocks, Data: []byte("msg1"), SeqNo: 1},
			{ID: ComputeMessageID(TopicBlocks, []byte("msg2")), Topic: TopicBlocks, Data: []byte("msg2"), SeqNo: 2},
		},
	}

	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}

	decoded, err := DecodeRPC(data)
	if err != nil {
		t.Fatalf("DecodeRPC failed: %v", err)
	}

	if len(decoded.Messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(decoded.Messages))
	}
	if decoded.Control != nil {
		t.Error("expected no control messages")
	}
}

func TestEncodeDecodeRPCIWANT(t *testing.T) {
	msgID1 := ComputeMessageID(TopicBlocks, []byte("want1"))
	msgID2 := ComputeMessageID(TopicBlocks, []byte("want2"))

	rpc := &RPC{
		Control: &ControlMessage{
			IWant: []*ControlIWant{{
				MessageIDs: []MessageID{msgID1, msgID2},
			}},
		},
	}

	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}

	decoded, err := DecodeRPC(data)
	if err != nil {
		t.Fatalf("DecodeRPC failed: %v", err)
	}

	if len(decoded.Messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(decoded.Messages))
	}
	if decoded.Control == nil {
		t.Fatal("expected control messages")
	}
	if len(decoded.Control.IWant) != 1 {
		t.Errorf("expected 1 iwant, got %d", len(decoded.Control.IWant))
	}
	if len(decoded.Control.IWant[0].MessageIDs) != 2 {
		t.Errorf("expected 2 message IDs, got %d", len(decoded.Control.IWant[0].MessageIDs))
	}
}

func TestComputeMessageID(t *testing.T) {
	id1 := ComputeMessageID(TopicBlocks, []byte("data1"))
	id2 := ComputeMessageID(TopicBlocks, []byte("data1"))
	id3 := ComputeMessageID(TopicBlocks, []byte("data2"))
	id4 := ComputeMessageID(TopicVotes, []byte("data1"))

	// Same input should produce same ID
	if id1 != id2 {
		t.Error("same input produced different IDs")
	}

	// Different data should produce different ID
	if id1 == id3 {
		t.Error("different data produced same ID")
	}

	// Different topic should produce different ID
	if id1 == id4 {
		t.Error("different topic produced same ID")
	}
}

func TestMessageCache(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)

	handler := func(msg *Message) {}
	topic, _ := gs.JoinTopic(TopicBlocks, handler)

	// AUDIT (2026) R3-P2P-04 FIX: HistoryLength bumped from 5 to 100,
	// so insert HistoryLength+10 messages to exercise eviction.
	total := gs.cfg.HistoryLength + 10
	for i := 0; i < total; i++ {
		msg := &Message{
			ID:    ComputeMessageID(TopicBlocks, []byte{byte(i)}),
			Topic: TopicBlocks,
			Data:  []byte{byte(i)},
			SeqNo: uint64(i),
		}
		topic.cacheMessage(msg)
	}

	topic.cacheMu.RLock()
	cacheLen := len(topic.messageCache)
	topic.cacheMu.RUnlock()

	if cacheLen != gs.cfg.HistoryLength {
		t.Errorf("expected cache length %d, got %d", gs.cfg.HistoryLength, cacheLen)
	}

	// Cache should keep most recent messages: the very first inserted
	// (index 0) should have been evicted once the cap was reached.
	firstCached := topic.findCachedMessage(ComputeMessageID(TopicBlocks, []byte{0}))
	if firstCached != nil {
		t.Error("oldest message should have been evicted")
	}

	lastCached := topic.findCachedMessage(ComputeMessageID(TopicBlocks, []byte{byte(total - 1)}))
	if lastCached == nil {
		t.Error("newest message should be in cache")
	}
}

// TestSeenMessagesDedup verifies the dedicated dedup cache rejects duplicates
// even when the IHAVE cache has already rolled them out.
// AUDIT (2026) R3-P2P-04 FIX: Previously both functions shared the
// 5-entry messageCache slice, so a burst of >5 unique messages followed by
// a duplicate of the first would slip past dedup. Now seenMessages is a
// TTL-bounded map that survives IHAVE eviction.
func TestSeenMessagesDedup(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	handler := func(msg *Message) {}
	topic, _ := gs.JoinTopic(TopicBlocks, handler)

	// Insert more than HistoryLength unique messages, then re-insert the
	// first one. The IHAVE cache will have evicted it by then, but the
	// dedup cache (seenMessages) must still recognize it as seen.
	firstID := ComputeMessageID(TopicBlocks, []byte("first"))
	topic.cacheMessage(&Message{ID: firstID, Topic: TopicBlocks, Data: []byte("first"), SeqNo: 1})
	for i := 0; i < gs.cfg.HistoryLength+5; i++ {
		topic.cacheMessage(&Message{
			ID:    ComputeMessageID(TopicBlocks, []byte{byte(i)}),
			Topic: TopicBlocks,
			Data:  []byte{byte(i)},
			SeqNo: uint64(i + 2),
		})
	}

	// The first message should no longer be in the IHAVE cache.
	if topic.findCachedMessage(firstID) != nil {
		t.Fatal("first message should have been evicted from IHAVE cache")
	}

	// But the dedup cache must still recognize it as seen.
	topic.cacheMu.RLock()
	seen := topic.hasSeenMessage(firstID)
	topic.cacheMu.RUnlock()
	if !seen {
		t.Fatal("dedup cache should still recognize first message as seen (TTL not expired)")
	}
}

// TestSeenMessagesTTLPrune verifies the TTL pruner evicts expired entries.
func TestSeenMessagesTTLPrune(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	// Use a short TTL for test speed.
	gs.cfg.MessageDedupTTL = 100 * time.Millisecond
	handler := func(msg *Message) {}
	topic, _ := gs.JoinTopic(TopicBlocks, handler)

	id := ComputeMessageID(TopicBlocks, []byte("ttl-test"))
	topic.cacheMessage(&Message{ID: id, Topic: TopicBlocks, Data: []byte("ttl-test"), SeqNo: 1})

	topic.cacheMu.RLock()
	seenBefore := topic.hasSeenMessage(id)
	topic.cacheMu.RUnlock()
	if !seenBefore {
		t.Fatal("entry should be seen immediately after insert")
	}

	// Wait for TTL to expire, then prune.
	time.Sleep(150 * time.Millisecond)
	topic.PruneSeenMessages()

	topic.cacheMu.RLock()
	seenAfter := topic.hasSeenMessage(id)
	topic.cacheMu.RUnlock()
	if seenAfter {
		t.Fatal("entry should be evicted after TTL expiry")
	}
}

func TestPeerScorer(t *testing.T) {
	ps := NewPeerScorer()

	// Initial score should be 0
	score := ps.GetScore("peer1")
	if score != 0 {
		t.Errorf("expected initial score 0, got %f", score)
	}

	// Record some deliveries
	for i := 0; i < 20; i++ {
		ps.RecordMessageSent("peer1")
	}
	for i := 0; i < 18; i++ {
		ps.RecordMessageDelivery("peer1", TopicBlocks)
	}

	// Score should improve
	score = ps.GetScore("peer1")
	if score <= 0 {
		t.Errorf("expected positive score after good delivery, got %f", score)
	}

	// Record mesh join
	ps.RecordMeshJoin("peer1", TopicBlocks)

	// Get detailed scores
	total, delivery, latency, uptime, topics := ps.GetScoreDetailed("peer1")
	if total <= 0 {
		t.Errorf("expected positive total score, got %f", total)
	}
	if delivery <= 0 {
		t.Errorf("expected positive delivery score, got %f", delivery)
	}
	_ = latency
	_ = uptime
	_ = topics
}

func TestPeerScorerCleanup(t *testing.T) {
	ps := NewPeerScorer()

	ps.RecordMessageDelivery("old_peer", TopicBlocks)

	// Wait a bit so the peer becomes stale
	time.Sleep(10 * time.Millisecond)

	// Cleanup with very short max age (1 nanosecond from now)
	// old_peer's lastSeen is ~10ms ago, so it should be before now-1ns
	removed := ps.CleanupStalePeers(1 * time.Nanosecond)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d (old_peer should be stale)", removed)
	}

	if ps.PeerCount() != 0 {
		t.Errorf("expected 0 peers after cleanup, got %d", ps.PeerCount())
	}
}

func TestSyncPeers(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	// Initial sync
	gs.syncPeers()
	gs.peersMu.RLock()
	peerCount := len(gs.peers)
	gs.peersMu.RUnlock()

	if peerCount != 10 {
		t.Errorf("expected 10 peers after sync, got %d", peerCount)
	}

	// Add a new peer
	sender.addPeer("peer11")
	gs.syncPeers()
	gs.peersMu.RLock()
	peerCount = len(gs.peers)
	gs.peersMu.RUnlock()

	if peerCount != 11 {
		t.Errorf("expected 11 peers after adding, got %d", peerCount)
	}

	// Remove a peer
	sender.removePeer("peer1")
	gs.syncPeers()
	gs.peersMu.RLock()
	peerCount = len(gs.peers)
	gs.peersMu.RUnlock()

	if peerCount != 10 {
		t.Errorf("expected 10 peers after removal, got %d", peerCount)
	}
}

func TestEmptyRPC(t *testing.T) {
	data, err := EncodeRPC(&RPC{})
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}

	decoded, err := DecodeRPC(data)
	if err != nil {
		t.Fatalf("DecodeRPC failed: %v", err)
	}

	if len(decoded.Messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(decoded.Messages))
	}
}

func TestDecodeRPCTruncated(t *testing.T) {
	// Test with too-short data
	_, err := DecodeRPC([]byte{0x00})
	if err == nil {
		t.Error("expected error for truncated RPC data")
	}
}

func TestShuffleSlice(t *testing.T) {
	s := []PeerID{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	original := make([]PeerID, len(s))
	copy(original, s)

	shuffleSlice(s)

	// Length should be the same
	if len(s) != len(original) {
		t.Errorf("expected length %d, got %d", len(original), len(s))
	}

	// All elements should still be present
	elemMap := make(map[PeerID]bool)
	for _, v := range original {
		elemMap[v] = true
	}
	for _, v := range s {
		if !elemMap[v] {
			t.Errorf("unexpected element %s after shuffle", v)
		}
	}

	// With 10 elements, there's a very small chance the order stays the same
	// But this is a statistical test, so we just check the function doesn't panic
}

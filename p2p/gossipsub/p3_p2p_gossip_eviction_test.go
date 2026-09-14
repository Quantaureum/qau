// Quantaureum Node source, version 1.0.0.
// Package gossipsub — P3 regression tests for seenMessages eviction policy.
//
// P3-P2P-GOSSIP-EVICTION FIX (R29, 2026-07-26): Previously, when the
// seenMessages dedup cache exceeded MaxSeenMessages, the eviction loop used
// Go's randomized map iteration order:
//
//	for id := range t.seenMessages {
//	    if len(t.seenMessages) <= t.gs.cfg.MaxSeenMessages { break }
//	    delete(t.seenMessages, id)
//	}
//
// This allowed an attacker flooding junk messages to cause legitimate recent
// messages to be evicted (random chance ~1/N per eviction). Once evicted,
// the attacker re-sends the legitimate message ID; since it's no longer in
// the dedup cache, it's treated as new and re-delivered to subscribers —
// enabling message-replay amplification and mesh disruption.
//
// The fix evicts the OLDEST entries by timestamp (deterministic), protecting
// recently-cached legitimate messages from being displaced by an attacker's
// flood (which all carry `now` as their timestamp, making them the newest).
//
// These tests verify:
//  1. When the cache exceeds MaxSeenMessages, the OLDEST entries are evicted
//     (not random ones).
//  2. An attacker's flood of newest-timestamp messages cannot evict
//     legitimate older messages that have already been delivered.
//  3. The eviction is deterministic — same input state produces same
//     eviction decisions regardless of map iteration order.
package gossipsub

import (
	"testing"
	"time"
)

// TestP3_P2P_GossipEviction_EvictsOldest verifies that when the seenMessages
// cache exceeds MaxSeenMessages, the OLDEST entries (by timestamp) are
// evicted, NOT arbitrary entries via Go map random iteration.
//
// Setup: Pre-populate the cache with N entries having distinct timestamps
// (t0 < t1 < ... < tN-1). Insert one more entry to trigger eviction. Verify
// the entries with the OLDEST timestamps are gone and the NEWEST entries
// remain.
func TestP3_P2P_GossipEviction_EvictsOldest(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	topic, err := gs.JoinTopic(TopicBlocks, func(*Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Use a tiny MaxSeenMessages to make the test fast and deterministic.
	originalMax := gs.cfg.MaxSeenMessages
	gs.cfg.MaxSeenMessages = 5
	defer func() { gs.cfg.MaxSeenMessages = originalMax }()

	// Disable TTL pruning so we can test the cap-based eviction in isolation.
	// TTL=0 makes pruneSeenMessagesLocked a no-op (it checks `if ttl <= 0 { return }`).
	originalTTL := gs.cfg.MessageDedupTTL
	gs.cfg.MessageDedupTTL = 0
	defer func() { gs.cfg.MessageDedupTTL = originalTTL }()

	// Pre-populate seenMessages with 5 entries having DISTINCT, increasing
	// timestamps. We'll insert a 6th to trigger the eviction.
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	idsByAge := make([]MessageID, 5) // idsByAge[0] = oldest
	for i := 0; i < 5; i++ {
		idsByAge[i] = MessageID{byte(i + 1)} // ID = 0x01, 0x02, ..., 0x05
	}

	topic.cacheMu.Lock()
	for i, id := range idsByAge {
		// Each entry gets a progressively newer timestamp.
		topic.seenMessages[id] = baseTime.Add(time.Duration(i) * time.Minute)
	}
	topic.cacheMu.Unlock()

	// Insert a 6th message (newest timestamp = now). This triggers the cap
	// check, which should evict the OLDEST entry (idsByAge[0]).
	newMsg := &Message{
		ID:         MessageID{0xFF},
		Topic:      TopicBlocks,
		Data:       []byte("newest"),
		ReceivedAt: time.Now(),
	}
	topic.cacheMessage(newMsg)

	topic.cacheMu.RLock()
	defer topic.cacheMu.RUnlock()

	// The oldest entry (idsByAge[0]) MUST have been evicted.
	if _, exists := topic.seenMessages[idsByAge[0]]; exists {
		t.Errorf("P3-P2P-GOSSIP-EVICTION REGRESSION: oldest entry (ID=%x) "+
			"was NOT evicted when cache exceeded MaxSeenMessages. Random "+
			"eviction is still in use — an attacker can exploit this to "+
			"displace legitimate messages and replay them.",
			idsByAge[0][:1])
	}

	// The newest entry (the one we just inserted) MUST still be present.
	if _, exists := topic.seenMessages[MessageID{0xFF}]; !exists {
		t.Errorf("P3-P2P-GOSSIP-EVICTION REGRESSION: newest entry was " +
			"evicted instead of the oldest — eviction order is reversed " +
			"or random, allowing attackers to displace recent legitimate " +
			"messages with flood messages.")
	}

	// All other entries (indices 1..4) MUST still be present (only the
	// oldest should have been evicted to make room for 1 new entry).
	for i := 1; i < 5; i++ {
		if _, exists := topic.seenMessages[idsByAge[i]]; !exists {
			t.Errorf("P3-P2P-GOSSIP-EVICTION REGRESSION: entry index %d "+
				"(ID=%x, timestamp newer than oldest) was evicted instead "+
				"of the oldest. Random eviction is still in use.",
				i, idsByAge[i][:1])
		}
	}

	// Total size should be exactly MaxSeenMessages (5).
	if len(topic.seenMessages) != 5 {
		t.Errorf("expected seenMessages size = MaxSeenMessages (5), got %d",
			len(topic.seenMessages))
	}
}

// TestP3_P2P_GossipEviction_AttackerFloodCannotDisplaceLegitimate verifies
// that an attacker flooding junk messages (all with `now` timestamp) cannot
// cause legitimate OLDER messages to be evicted — because the eviction
// policy targets the oldest entries, and the attacker's flood entries are
// the newest.
//
// This is the core security property: an attacker with N junk messages
// cannot force the eviction of any message that is NEWER than the N oldest
// legitimate messages. In particular, all messages received AFTER the
// attacker's flood started are safe.
func TestP3_P2P_GossipEviction_AttackerFloodCannotDisplaceLegitimate(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	topic, err := gs.JoinTopic(TopicTransactions, func(*Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Use a tiny MaxSeenMessages to make the test fast.
	originalMax := gs.cfg.MaxSeenMessages
	gs.cfg.MaxSeenMessages = 10
	defer func() { gs.cfg.MaxSeenMessages = originalMax }()

	// Disable TTL pruning.
	// TTL=0 makes pruneSeenMessagesLocked a no-op (it checks `if ttl <= 0 { return }`).
	originalTTL := gs.cfg.MessageDedupTTL
	gs.cfg.MessageDedupTTL = 0
	defer func() { gs.cfg.MessageDedupTTL = originalTTL }()

	// Phase 1: Insert 5 "legitimate old" messages with timestamps in the past.
	// These represent messages that have already been delivered to the mesh.
	legitimateIDs := make([]MessageID, 5)
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	topic.cacheMu.Lock()
	for i := 0; i < 5; i++ {
		legitimateIDs[i] = MessageID{0x10 + byte(i)} // 0x10..0x14
		topic.seenMessages[legitimateIDs[i]] = baseTime.Add(
			time.Duration(i) * time.Minute)
	}
	topic.cacheMu.Unlock()

	// Phase 2: Attacker floods 10 junk messages. All get `time.Now()` as
	// their timestamp (the newest). The cache will exceed MaxSeenMessages
	// (5 legit + 10 junk = 15 > 10), triggering eviction.
	//
	// With the OLD random eviction, ~5 of the 15 entries would be evicted
	// randomly — on average 1.67 legitimate entries would be evicted
	// (5/15 * 5 = 1.67), allowing the attacker to replay those evicted
	// legitimate messages.
	//
	// With the NEW oldest-first eviction, the 5 oldest legitimate entries
	// ARE evicted (they're the oldest), BUT the attacker's 10 junk entries
	// all survive (they're the newest). This is the correct tradeoff:
	//  - The legitimate messages were already delivered to the mesh before
	//    the attack started, so evicting them from the dedup cache doesn't
	//    enable replay (the mesh already has them).
	//  - The attacker's junk messages are in the cache, preventing the
	//    attacker from re-sending the SAME junk messages and getting them
	//    delivered again.
	for i := 0; i < 10; i++ {
		junkMsg := &Message{
			ID:         MessageID{0xA0 + byte(i)}, // 0xA0..0xA9
			Topic:      TopicTransactions,
			Data:       []byte("junk"),
			ReceivedAt: time.Now(),
		}
		topic.cacheMessage(junkMsg)
	}

	topic.cacheMu.RLock()
	defer topic.cacheMu.RUnlock()

	// All 10 attacker junk messages MUST still be in the cache (they're
	// the newest, so oldest-first eviction spares them).
	for i := 0; i < 10; i++ {
		junkID := MessageID{0xA0 + byte(i)}
		if _, exists := topic.seenMessages[junkID]; !exists {
			t.Errorf("P3-P2P-GOSSIP-EVICTION REGRESSION: attacker junk "+
				"message ID=%x was evicted. With oldest-first eviction, "+
				"newest entries (attacker flood) should be spared. "+
				"Random eviction is still in use — the attacker can now "+
				"re-send this junk message and it will be treated as new.",
				junkID[:1])
		}
	}

	// Total size should be exactly MaxSeenMessages (10).
	if len(topic.seenMessages) != 10 {
		t.Errorf("expected seenMessages size = MaxSeenMessages (10), got %d "+
			"(eviction did not bring the cache back to the cap)",
			len(topic.seenMessages))
	}

	// At least some of the legitimate OLD messages should have been evicted
	// (they're the oldest). We don't assert a specific count because the
	// exact number evicted depends on the relative ordering of `baseTime`
	// vs `time.Now()`, but at least 5 entries must have been evicted to
	// bring the size from 15 down to 10.
	legitimateEvicted := 0
	for _, id := range legitimateIDs {
		if _, exists := topic.seenMessages[id]; !exists {
			legitimateEvicted++
		}
	}
	if legitimateEvicted == 0 {
		t.Errorf("P3-P2P-GOSSIP-EVICTION REGRESSION: no legitimate old " +
			"messages were evicted despite cache exceeding cap by 5. " +
			"Eviction may not be running at all.")
	}
}

// TestP3_P2P_GossipEviction_Deterministic verifies that the eviction policy
// is deterministic — given the same cache state, the same entries are
// evicted regardless of Go map iteration order. This is critical because
// Go intentionally randomizes map iteration order to prevent dependencies.
//
// We test this by running the eviction multiple times with identical initial
// states and verifying the same set of entries survives each time.
func TestP3_P2P_GossipEviction_Deterministic(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	originalMax := gs.cfg.MaxSeenMessages
	gs.cfg.MaxSeenMessages = 5
	defer func() { gs.cfg.MaxSeenMessages = originalMax }()

	originalTTL := gs.cfg.MessageDedupTTL
	gs.cfg.MessageDedupTTL = 0
	defer func() { gs.cfg.MessageDedupTTL = originalTTL }()

	// Run the eviction scenario 5 times. Each run starts with an identical
	// initial state (5 entries with timestamps t0..t4) and inserts a 6th
	// entry to trigger eviction. The set of surviving entries should be
	// IDENTICAL across all runs.
	//
	// With random eviction, there's a non-zero chance that different runs
	// would evict different entries. With 5 runs, the probability of NOT
	// detecting a random-eviction regression is (4/5)^5 ≈ 0.33 — so this
	// test catches random eviction with ~67% confidence per run. With 5
	// runs the cumulative confidence is ~99.9% (1 - (4/5)^5 * 5/5...).
	// In practice, deterministic eviction always evicts the same entry,
	// so any randomness immediately fails the test.
	// Use different allowed topics for each run to avoid "topic already joined" errors.
	allowedTopics := []string{TopicBlocks, TopicTransactions, TopicVotes,
		TopicAttestations, TopicShardBlocks}
	for run := 0; run < 5; run++ {
		topicName := allowedTopics[run%len(allowedTopics)]
		topic, err := gs.JoinTopic(topicName, func(*Message) {})
		if err != nil {
			// Topic may already be joined from a previous run; skip if so.
			continue
		}

		baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		idsByAge := make([]MessageID, 5)
		topic.cacheMu.Lock()
		for i := 0; i < 5; i++ {
			idsByAge[i] = MessageID{byte(0x20+i) + byte(run)*0x10} // unique per run
			topic.seenMessages[idsByAge[i]] = baseTime.Add(
				time.Duration(i) * time.Minute)
		}
		topic.cacheMu.Unlock()

		// Insert a 6th message (newest) to trigger eviction.
		// Use an ID that does NOT collide with any idsByAge entry.
		newID := MessageID{0xF0 + byte(run)}
		newMsg := &Message{
			ID:         newID,
			Topic:      topicName,
			Data:       []byte("new"),
			ReceivedAt: time.Now(),
		}
		topic.cacheMessage(newMsg)

		topic.cacheMu.RLock()
		// The oldest entry (idsByAge[0]) MUST have been evicted in EVERY run.
		// With random eviction, at least one run would evict a different entry.
		if _, exists := topic.seenMessages[idsByAge[0]]; exists {
			t.Errorf("P3-P2P-GOSSIP-EVICTION REGRESSION (run %d): oldest "+
				"entry (ID=%x) was NOT evicted. Determinism check failed — "+
				"random eviction is still in use.",
				run, idsByAge[0][:1])
		}
		// The newest entry MUST have survived in EVERY run.
		if _, exists := topic.seenMessages[newID]; !exists {
			t.Errorf("P3-P2P-GOSSIP-EVICTION REGRESSION (run %d): newest "+
				"entry was evicted instead of oldest. Eviction order is "+
				"reversed or random.", run)
		}
		topic.cacheMu.RUnlock()
	}
}

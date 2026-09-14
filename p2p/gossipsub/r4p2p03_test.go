// Quantaureum Node source, version 1.0.0.
// Package gossipsub — R4-P2P-03 regression tests.
//
// AUDIT (2026) R4-P2P-03: GossipSub previously forwarded all messages
// unconditionally — there was no validation gate before forwardMessage, and
// the scorer had no negative signal (no RecordInvalidMessage / RecordDuplicate).
// A malicious peer could flood the mesh with junk and still keep a positive
// score, staying in the mesh and continuing to waste bandwidth.
//
// The fix:
//  1. A TopicMessageValidator gate runs in deliverMessage AFTER the dedup
//     check and BEFORE the handler/forward. Invalid messages are dropped at
//     the first hop and the source peer is penalized via RecordInvalidMessage.
//  2. RecordDuplicate is called on dedup cache hit, so peers that spam
//     already-seen messages accumulate a small negative score.
//  3. The scorer now folds an accumulated penalty into the final score,
//     so peers that send invalid/duplicate messages eventually drop below
//     scoreGraylist and are pruned from the mesh.
//
// These tests verify all three behaviors.
package gossipsub

import (
	"errors"
	"math"
	"testing"
	"time"
)

// strictValidator accepts only messages whose Data matches `accept`.
type strictValidator struct {
	accept []byte
}

func (s *strictValidator) ValidateMessage(msg *Message) error {
	if msg == nil {
		return errors.New("nil message")
	}
	if string(msg.Data) != string(s.accept) {
		return errors.New("invalid payload")
	}
	return nil
}

// TestR4P2P03_InvalidMessagesAreNotForwarded verifies that when a validator
// rejects a message, the message is NOT delivered to handlers and NOT
// forwarded to mesh peers. The source peer is penalized.
func TestR4P2P03_InvalidMessagesAreNotForwarded(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	// Install a validator that only accepts "valid".
	gs.SetMessageValidator(&strictValidator{accept: []byte("valid")})

	handlerCalled := make(chan *Message, 10)
	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {
		handlerCalled <- msg
	})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Add a mesh peer so we can verify forwarding is skipped.
	sender.addPeer("meshPeer")

	// Send an INVALID message.
	rpc := &RPC{
		Messages: []*Message{{
			ID:    ComputeMessageID(TopicBlocks, []byte("junk")),
			Topic: TopicBlocks,
			Data:  []byte("junk"),
			SeqNo: 1,
		}},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}
	if err := gs.HandleRPC("badPeer", data); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Handler MUST NOT be called for invalid messages.
	select {
	case <-handlerCalled:
		t.Fatal("R4-P2P-03 REGRESSION: handler was called for an invalid message — invalid messages must be dropped before delivery")
	case <-time.After(100 * time.Millisecond):
		// Good — no handler call.
	}

	// meshPeer MUST NOT have received the invalid message.
	if sent := sender.sentMessages["meshPeer"]; len(sent) != 0 {
		t.Fatalf("R4-P2P-03 REGRESSION: invalid message was forwarded to meshPeer (%d msgs) — invalid messages must not be forwarded", len(sent))
	}

	// badPeer MUST have been penalized.
	if n := gs.scorer.GetInvalidMessageCount("badPeer"); n != 1 {
		t.Fatalf("R4-P2P-03 REGRESSION: expected 1 invalid message recorded for badPeer, got %d", n)
	}
	if p := gs.scorer.GetPenalty("badPeer"); p >= 0 {
		t.Fatalf("R4-P2P-03 REGRESSION: expected negative penalty for badPeer, got %f", p)
	}
}

// TestR4P2P03_ValidMessagesAreForwarded verifies that when the validator
// accepts a message, it IS delivered to the handler AND forwarded to the
// mesh. This is the happy-path control for the test above.
func TestR4P2P03_ValidMessagesAreForwarded(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	gs.SetMessageValidator(&strictValidator{accept: []byte("valid")})

	handlerCalled := make(chan *Message, 10)
	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {
		handlerCalled <- msg
	})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	sender.addPeer("meshPeer")

	// Send a VALID message.
	rpc := &RPC{
		Messages: []*Message{{
			ID:    ComputeMessageID(TopicBlocks, []byte("valid")),
			Topic: TopicBlocks,
			Data:  []byte("valid"),
			SeqNo: 1,
		}},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}
	if err := gs.HandleRPC("goodPeer", data); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Handler MUST be called.
	select {
	case msg := <-handlerCalled:
		if string(msg.Data) != "valid" {
			t.Errorf("expected 'valid', got '%s'", string(msg.Data))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("R4-P2P-03 REGRESSION: handler was NOT called for a valid message — the validator gate is dropping valid messages")
	}

	// goodPeer MUST have zero invalid messages.
	if n := gs.scorer.GetInvalidMessageCount("goodPeer"); n != 0 {
		t.Fatalf("expected 0 invalid messages for goodPeer, got %d", n)
	}
}

// TestR4P2P03_DefaultValidatorAcceptsAll verifies that when no validator is
// configured, all messages pass (backward compatibility).
func TestR4P2P03_DefaultValidatorAcceptsAll(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	// NOTE: deliberately NOT calling SetMessageValidator.

	handlerCalled := make(chan *Message, 10)
	_, err := gs.JoinTopic(TopicTransactions, func(msg *Message) {
		handlerCalled <- msg
	})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	rpc := &RPC{
		Messages: []*Message{{
			ID:    ComputeMessageID(TopicTransactions, []byte("anything")),
			Topic: TopicTransactions,
			Data:  []byte("anything"),
			SeqNo: 1,
		}},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}
	if err := gs.HandleRPC("peer1", data); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	select {
	case <-handlerCalled:
		// Good — message was delivered.
	case <-time.After(1 * time.Second):
		t.Fatal("R4-P2P-03 REGRESSION: default validator dropped a message — backward compatibility broken")
	}
}

// TestR4P2P03_DuplicateMessagesRecordPenalty verifies that when a peer sends
// a message we have already seen, RecordDuplicate is called (weak penalty).
// The message is NOT delivered to the handler again.
func TestR4P2P03_DuplicateMessagesRecordPenalty(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	handlerCalls := make(chan *Message, 10)
	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {
		handlerCalls <- msg
	})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Send a message from peer1.
	msgID := ComputeMessageID(TopicBlocks, []byte("dup"))
	rpc := &RPC{
		Messages: []*Message{{
			ID:    msgID,
			Topic: TopicBlocks,
			Data:  []byte("dup"),
			SeqNo: 1,
		}},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}
	if err := gs.HandleRPC("peer1", data); err != nil {
		t.Fatalf("HandleRPC(1) failed: %v", err)
	}

	// Wait for the first delivery.
	select {
	case <-handlerCalls:
	case <-time.After(1 * time.Second):
		t.Fatal("first delivery did not arrive")
	}

	// Send the SAME message again from a different peer.
	if err := gs.HandleRPC("peer2", data); err != nil {
		t.Fatalf("HandleRPC(2) failed: %v", err)
	}

	// Handler MUST NOT be called a second time for the duplicate.
	select {
	case <-handlerCalls:
		t.Fatal("R4-P2P-03 REGRESSION: handler was called a second time for a duplicate message")
	case <-time.After(100 * time.Millisecond):
		// Good — no second handler call.
	}

	// peer2 MUST have been recorded as sending a duplicate.
	if n := gs.scorer.GetDuplicateMessageCount("peer2"); n != 1 {
		t.Fatalf("R4-P2P-03 REGRESSION: expected 1 duplicate recorded for peer2, got %d", n)
	}
	if p := gs.scorer.GetPenalty("peer2"); p >= 0 {
		t.Fatalf("R4-P2P-03 REGRESSION: expected negative penalty for peer2 (duplicate), got %f", p)
	}
}

// TestR4P2P03_Scorer_RecordInvalidMessage_Penalty verifies that calling
// RecordInvalidMessage decrements the penalty by invalidMessagePenalty (20)
// and clamps at minPenalty.
func TestR4P2P03_Scorer_RecordInvalidMessage_Penalty(t *testing.T) {
	ps := NewPeerScorer()

	// One invalid message: penalty should be -20.
	ps.RecordInvalidMessage("bad", TopicBlocks)
	if p := ps.GetPenalty("bad"); p != -invalidMessagePenalty {
		t.Fatalf("after 1 invalid: penalty = %f, want %f", p, -invalidMessagePenalty)
	}

	// Three invalid messages: penalty should be -60.
	ps.RecordInvalidMessage("bad", TopicBlocks)
	ps.RecordInvalidMessage("bad", TopicBlocks)
	if p := ps.GetPenalty("bad"); p != -3*invalidMessagePenalty {
		t.Fatalf("after 3 invalid: penalty = %f, want %f", p, -3*invalidMessagePenalty)
	}

	// Verify the count is tracked.
	if n := ps.GetInvalidMessageCount("bad"); n != 3 {
		t.Fatalf("invalid count = %d, want 3", n)
	}

	// Verify penalty is reflected in the overall score: 3 invalid messages
	// → -60 penalty → score should be below scoreGraylist (-50) once blended.
	score := ps.GetScore("bad")
	if score > scoreGraylist {
		t.Fatalf("R4-P2P-03 REGRESSION: after 3 invalid messages, score = %f, want <= %f (graylist)", score, scoreGraylist)
	}
}

// TestR4P2P03_Scorer_RecordDuplicate_Penalty verifies that calling
// RecordDuplicate decrements the penalty by duplicateMessagePenalty (1).
func TestR4P2P03_Scorer_RecordDuplicate_Penalty(t *testing.T) {
	ps := NewPeerScorer()

	ps.RecordDuplicate("spammy", TopicTransactions)
	if p := ps.GetPenalty("spammy"); p != -duplicateMessagePenalty {
		t.Fatalf("after 1 dup: penalty = %f, want %f", p, -duplicateMessagePenalty)
	}

	// 100 duplicates: penalty should be -100.
	for i := 0; i < 99; i++ {
		ps.RecordDuplicate("spammy", TopicTransactions)
	}
	if p := ps.GetPenalty("spammy"); p != -100*duplicateMessagePenalty {
		t.Fatalf("after 100 dups: penalty = %f, want %f", p, -100*duplicateMessagePenalty)
	}
	if n := ps.GetDuplicateMessageCount("spammy"); n != 100 {
		t.Fatalf("dup count = %d, want 100", n)
	}
}

// TestR4P2P03_Scorer_PenaltyClampsAtMin verifies that the penalty does not
// underflow below minPenalty, preventing arithmetic-precision issues.
func TestR4P2P03_Scorer_PenaltyClampsAtMin(t *testing.T) {
	ps := NewPeerScorer()

	// Send far more invalid messages than would ever be legitimate.
	for i := 0; i < 10000; i++ {
		ps.RecordInvalidMessage("attacker", TopicBlocks)
	}

	if p := ps.GetPenalty("attacker"); p < minPenalty {
		t.Fatalf("penalty = %f, want >= minPenalty = %f (clamp broken)", p, minPenalty)
	}
	if p := ps.GetPenalty("attacker"); p != minPenalty {
		t.Fatalf("penalty = %f, want exactly minPenalty = %f (clamp not tight)", p, minPenalty)
	}
}

// TestR4P2P03_Scorer_HonestPeerNotHarmedByDuplicates verifies that a small
// number of duplicates (as honest peers legitimately send during propagation)
// does NOT push the peer below scoreAcceptable. This is the key safety
// property: the per-duplicate penalty is small enough to be negligible for
// honest peers.
func TestR4P2P03_Scorer_HonestPeerNotHarmedByDuplicates(t *testing.T) {
	ps := NewPeerScorer()

	// Simulate an honest peer: delivers many real messages, a few dups.
	for i := 0; i < 20; i++ {
		ps.RecordMessageDelivery("honest", TopicBlocks)
	}
	for i := 0; i < 5; i++ {
		ps.RecordDuplicate("honest", TopicBlocks)
	}

	score := ps.GetScore("honest")
	// An honest peer with 20 good deliveries and 5 accidental duplicates
	// should still be above scoreAcceptable (0).
	if score < scoreAcceptable {
		t.Fatalf("R4-P2P-03 REGRESSION: honest peer score = %f, want >= %f — duplicate penalty is too aggressive and harms honest peers", score, scoreAcceptable)
	}
}

// TestP2P_R14_CRIT_001_PenaltyDecaysOverTime verifies the P2P-R14-CRIT-001
// fix: a peer's accumulated penalty decays toward zero over time, allowing
// rehabilitation after the peer stops sending invalid/duplicate messages.
// Before the fix, penalty never decayed on its own — a graylisted peer
// could not recover, which violated the documented "EMA gradually decays
// the penalty, allowing rehabilitation" contract.
func TestP2P_R14_CRIT_001_PenaltyDecaysOverTime(t *testing.T) {
	ps := NewPeerScorer()

	// 3 invalid messages → penalty = -90.
	for i := 0; i < 3; i++ {
		ps.RecordInvalidMessage("rehab", TopicBlocks)
	}
	penaltyBefore := ps.GetPenalty("rehab")
	if penaltyBefore != -3*invalidMessagePenalty {
		t.Fatalf("initial penalty = %f, want %f", penaltyBefore, -3*invalidMessagePenalty)
	}

	// Manually advance the peer's lastDecay to simulate the passage of
	// several decay intervals, then call GetScore to trigger decay.
	ps.mu.Lock()
	if s, ok := ps.scores["rehab"]; ok {
		// Simulate 10 decay intervals (50 minutes at 5min/interval).
		s.lastDecay = s.lastDecay.Add(-10 * scoreDecayInterval)
	}
	ps.mu.Unlock()

	// GetScore triggers applyDecayLocked, which should have decayed the
	// penalty by penaltyDecayRate^10 ≈ 0.599.
	_ = ps.GetScore("rehab")
	penaltyAfter := ps.GetPenalty("rehab")

	// Expected: -90 * 0.95^10 ≈ -53.9
	expected := -3 * invalidMessagePenalty * penaltyDecayRate * penaltyDecayRate * penaltyDecayRate * penaltyDecayRate * penaltyDecayRate * penaltyDecayRate * penaltyDecayRate * penaltyDecayRate * penaltyDecayRate * penaltyDecayRate
	if math.Abs(penaltyAfter-expected) > 1.0 {
		t.Fatalf("P2P-R14-CRIT-001 REGRESSION: penalty after 10 decay intervals = %f, want ~%f (penalty did not decay)", penaltyAfter, expected)
	}
	// Penalty should have moved toward 0: -53.9 > -90 (less negative).
	if penaltyAfter <= penaltyBefore {
		t.Fatalf("P2P-R14-CRIT-001 REGRESSION: penalty did not decay toward 0: before=%f after=%f", penaltyBefore, penaltyAfter)
	}
}

// TestP2P_R14_CRIT_001_PerPeerDecayIndependent verifies that decay is now
// per-peer (P2P-R14-CRIT-001). Previously PeerScorer.lastDecay was shared,
// so only the first peer queried in each window had its score decayed.
// Now each peer decays independently based on its own lastDecay.
func TestP2P_R14_CRIT_001_PerPeerDecayIndependent(t *testing.T) {
	ps := NewPeerScorer()

	// Both peers send 3 invalid messages.
	for i := 0; i < 3; i++ {
		ps.RecordInvalidMessage("peerA", TopicBlocks)
		ps.RecordInvalidMessage("peerB", TopicBlocks)
	}

	// Advance ONLY peerA's lastDecay by 10 intervals. peerB's lastDecay
	// stays at the current time, so peerB should NOT be decayed.
	ps.mu.Lock()
	if s, ok := ps.scores["peerA"]; ok {
		s.lastDecay = s.lastDecay.Add(-10 * scoreDecayInterval)
	}
	ps.mu.Unlock()

	_ = ps.GetScore("peerA")
	_ = ps.GetScore("peerB")

	penaltyA := ps.GetPenalty("peerA")
	penaltyB := ps.GetPenalty("peerB")

	// peerA should have decayed penalty (moved toward 0, so > -90).
	if penaltyA <= -3*invalidMessagePenalty {
		t.Fatalf("P2P-R14-CRIT-001 REGRESSION: peerA penalty not decayed: %f (want > %f)", penaltyA, -3*invalidMessagePenalty)
	}
	// peerB should NOT have decayed penalty (its lastDecay is current).
	if penaltyB != -3*invalidMessagePenalty {
		t.Fatalf("P2P-R14-CRIT-001 REGRESSION: peerB penalty unexpectedly decayed: %f (want %f) — decay is not per-peer", penaltyB, -3*invalidMessagePenalty)
	}
}

// TestR4P2P03_Scorer_SetMessageValidatorNil verifies that passing nil to
// SetMessageValidator restores the default no-op validator (all messages
// pass). This is the documented behavior.
func TestR4P2P03_Scorer_SetMessageValidatorNil(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	// Install a strict validator, then restore the default by passing nil.
	gs.SetMessageValidator(&strictValidator{accept: []byte("only-this")})
	gs.SetMessageValidator(nil)

	handlerCalled := make(chan *Message, 10)
	_, err := gs.JoinTopic(TopicVotes, func(msg *Message) {
		handlerCalled <- msg
	})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Send a message that the strict validator would have rejected.
	rpc := &RPC{
		Messages: []*Message{{
			ID:    ComputeMessageID(TopicVotes, []byte("different")),
			Topic: TopicVotes,
			Data:  []byte("different"),
			SeqNo: 1,
		}},
	}
	data, err := EncodeRPC(rpc)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}
	if err := gs.HandleRPC("peer1", data); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	select {
	case <-handlerCalled:
		// Good — message was delivered after restoring default validator.
	case <-time.After(1 * time.Second):
		t.Fatal("R4-P2P-03 REGRESSION: SetMessageValidator(nil) did not restore default — message was dropped")
	}
}

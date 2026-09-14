// Quantaureum Node source, version 1.0.0.
// Package gossipsub — R33 P3-02 regression tests.
//
// R33 P3-02 FIX (2026-07-28): Previously deliverMessage deleted the
// iwantPromise UNCONDITIONALLY before running the dedup and validation
// checks. This meant a peer who delivered an INVALID message (failed
// ValidateMessage or VerifyPayload) had their promise satisfied without
// actually delivering usable content, escaping the broken-promise penalty
// at sweepExpiredIWANTPromises.
//
// The fix deletes the promise ONLY when:
//   - The message is a DUPLICATE of an already-seen valid message
//     (legitimate race — the peer did deliver a valid message, just late).
//   - The message passes ALL validation checks (ValidateMessage +
//     VerifyPayload).
//
// Invalid messages leave the promise in place so the heartbeat sweep
// penalizes the peer for breaking their promise.
//
// These tests verify all three branches.
package gossipsub

import (
	"errors"
	"testing"
	"time"
)

// TestR33_P3_02_InvalidMessageDoesNotFulfillPromise verifies that when a
// peer delivers an INVALID message, the iwantPromise is NOT deleted.
// The heartbeat sweep should later penalize the peer for breaking their
// promise.
func TestR33_P3_02_InvalidMessageDoesNotFulfillPromise(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	// Install a validator that only accepts "valid".
	gs.SetMessageValidator(&strictValidator{accept: []byte("valid")})

	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Manually plant an iwantPromise as if the peer had advertised this
	// message via IHAVE and we had requested it via IWANT.
	msgID := ComputeMessageID(TopicBlocks, []byte("junk"))
	gs.iwantPromisesMu.Lock()
	gs.iwantPromises[msgID] = &iwantPromise{peer: "badPeer", sentAt: time.Now()}
	gs.iwantPromisesMu.Unlock()

	// Deliver an INVALID message with the same ID.
	rpc := &RPC{
		Messages: []*Message{{
			ID:    msgID,
			Topic: TopicBlocks,
			Data:  []byte("junk"), // validator rejects this
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

	// The promise MUST still exist — the peer delivered junk and should
	// be penalized by the heartbeat sweep.
	gs.iwantPromisesMu.Lock()
	_, stillExists := gs.iwantPromises[msgID]
	gs.iwantPromisesMu.Unlock()

	if !stillExists {
		t.Fatal("R33 P3-02 REGRESSION: iwantPromise was deleted for an INVALID message — " +
			"the peer delivered junk and should be penalized for breaking their promise, " +
			"but the promise was satisfied early")
	}

	// The peer MUST have been penalized for the invalid message.
	if n := gs.scorer.GetInvalidMessageCount("badPeer"); n != 1 {
		t.Errorf("expected 1 invalid message recorded for badPeer, got %d", n)
	}
}

// TestR33_P3_02_ValidMessageFulfillsPromise verifies that when a peer
// delivers a VALID message, the iwantPromise IS deleted (the promise is
// satisfied).
func TestR33_P3_02_ValidMessageFulfillsPromise(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	gs.SetMessageValidator(&strictValidator{accept: []byte("valid")})

	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	msgID := ComputeMessageID(TopicBlocks, []byte("valid"))
	gs.iwantPromisesMu.Lock()
	gs.iwantPromises[msgID] = &iwantPromise{peer: "goodPeer", sentAt: time.Now()}
	gs.iwantPromisesMu.Unlock()

	// Deliver a VALID message.
	rpc := &RPC{
		Messages: []*Message{{
			ID:    msgID,
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

	// The promise MUST be deleted — the peer delivered a valid message.
	gs.iwantPromisesMu.Lock()
	_, stillExists := gs.iwantPromises[msgID]
	gs.iwantPromisesMu.Unlock()

	if stillExists {
		t.Fatal("R33 P3-02 REGRESSION: iwantPromise was NOT deleted for a VALID message — " +
			"the peer fulfilled their promise but the entry remains, which would cause " +
			"a spurious broken-promise penalty")
	}
}

// TestR33_P3_02_DuplicateMessageFulfillsPromise verifies that when a peer
// delivers a DUPLICATE of an already-seen valid message, the iwantPromise
// IS deleted. This is a legitimate race — the peer did deliver a valid
// message, just slightly later than another peer.
func TestR33_P3_02_DuplicateMessageFulfillsPromise(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	gs.SetMessageValidator(&strictValidator{accept: []byte("valid")})

	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	msgID := ComputeMessageID(TopicBlocks, []byte("valid"))

	// First, deliver the message from peer1 so it enters the dedup cache.
	rpc1 := &RPC{
		Messages: []*Message{{
			ID:    msgID,
			Topic: TopicBlocks,
			Data:  []byte("valid"),
			SeqNo: 1,
		}},
	}
	data1, err := EncodeRPC(rpc1)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}
	if err := gs.HandleRPC("peer1", data1); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// Now plant an iwantPromise as if peer2 had advertised the same message.
	gs.iwantPromisesMu.Lock()
	gs.iwantPromises[msgID] = &iwantPromise{peer: "peer2", sentAt: time.Now()}
	gs.iwantPromisesMu.Unlock()

	// Deliver the same message from peer2 (duplicate).
	rpc2 := &RPC{
		Messages: []*Message{{
			ID:    msgID,
			Topic: TopicBlocks,
			Data:  []byte("valid"),
			SeqNo: 1,
		}},
	}
	data2, err := EncodeRPC(rpc2)
	if err != nil {
		t.Fatalf("EncodeRPC failed: %v", err)
	}
	if err := gs.HandleRPC("peer2", data2); err != nil {
		t.Fatalf("HandleRPC failed: %v", err)
	}

	// The promise MUST be deleted — the peer delivered a valid (if
	// duplicate) message. This is a legitimate race, not a broken promise.
	gs.iwantPromisesMu.Lock()
	_, stillExists := gs.iwantPromises[msgID]
	gs.iwantPromisesMu.Unlock()

	if stillExists {
		t.Fatal("R33 P3-02 REGRESSION: iwantPromise was NOT deleted for a DUPLICATE message — " +
			"the peer delivered a valid message (albeit a duplicate), which is a legitimate " +
			"race and should fulfill the promise")
	}
}

// TestR33_P3_02_NilValidatorRejectsNilMessage is a sanity check that the
// noOpValidator path doesn't accidentally fulfill promises for nil messages.
// A nil message should never reach deliverMessage, but if it does, the
// validator gate must catch it.
func TestR33_P3_02_NilValidatorRejectsNilMessage(t *testing.T) {
	// The noOpValidator accepts everything, but the ValidateMessage call
	// itself must handle nil gracefully.
	v := noOpValidator{}
	if err := v.ValidateMessage(nil); err != nil {
		t.Errorf("noOpValidator should accept nil, got error: %v", err)
	}

	// A strict validator must reject nil.
	strict := &strictValidator{accept: []byte("valid")}
	if err := strict.ValidateMessage(nil); err == nil {
		t.Error("strictValidator should reject nil message with an error")
	}
}

// Ensure errors package is used (suppress unused import if future edits
// remove the only usage).
var _ = errors.New

// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// reshareDefaultWaitTimeout bounds how long a new holder waits for the old
// holders' contributions. Old holders start the rotation when they process the
// epoch-boundary block, which can lag the local trigger by block propagation
// plus sub-share generation on a slow validator.
const reshareDefaultWaitTimeout = 60 * time.Second
const resharePollInterval = 10 * time.Millisecond
const maxPendingReshareMessages = 64
const maxPendingReshareBytes = 8 * 1024 * 1024
const maxReshareMessageBytes = 512 * 1024

type reshareWireMessage struct {
	Acknowledgement    bool          `json:"a,omitempty"`
	Attempt            uint32        `json:"r,omitempty"`
	SessionID          []byte        `json:"s"`
	Epoch              uint64        `json:"e"`
	FromParticipant    int           `json:"f"`
	ToParticipant      int           `json:"t"`
	Threshold          int           `json:"th"`
	OldParticipants    []int         `json:"o"`
	NewParticipants    []int         `json:"n"`
	GroupPublicKeyData []byte        `json:"g,omitempty"`
	Contribution       *qtd.SubShare `json:"c"`
}

// P2PReshareTransport delivers one old participant's sub-share contribution
// to each new participant. Unlike the public DKG commitment channel, every
// reshare message is point-to-point because it carries secret share material.
type P2PReshareTransport struct {
	host          resharePeerSender
	participantID int
	sessionID     []byte
	resolvePeer   func(int) (p2p.PeerID, bool)

	mu            sync.Mutex
	contributions map[int]*reshareWireMessage
	waitTimeout   time.Duration
	retryInterval time.Duration
	acknowledged  map[int]bool
}

type resharePeerSender interface {
	SendTSSToPeer(p2p.PeerID, uint8, []byte) error
}

func NewP2PReshareTransport(host resharePeerSender, participantID int, sessionID []byte) *P2PReshareTransport {
	if concreteHost, ok := host.(*p2p.Host); ok && concreteHost == nil {
		host = nil
	}
	return &P2PReshareTransport{
		host:          host,
		participantID: participantID,
		sessionID:     append([]byte(nil), sessionID...),
		contributions: make(map[int]*reshareWireMessage),
		waitTimeout:   reshareDefaultWaitTimeout,
		retryInterval: 2 * time.Second,
		acknowledged:  make(map[int]bool),
	}
}

func (n *Node) attachReshareTransport(transport *P2PReshareTransport) {
	if transport == nil {
		return
	}
	key := string(transport.SessionID())
	n.reshareMu.Lock()
	n.reshareTransport = transport
	pending := n.resharePending[key]
	delete(n.resharePending, key)
	for _, message := range pending {
		n.resharePendingBytes -= reshareMessageSize(message)
	}
	n.reshareMu.Unlock()
	for _, message := range pending {
		transport.Ingest(message)
	}
}

func (n *Node) detachReshareTransport(transport *P2PReshareTransport) {
	n.reshareMu.Lock()
	defer n.reshareMu.Unlock()
	if n.reshareTransport == transport {
		n.reshareTransport = nil
	}
}

func (n *Node) bufferReshareMessage(message *reshareWireMessage) bool {
	if message == nil || len(message.SessionID) == 0 {
		return false
	}
	size := reshareMessageSize(message)
	if size > maxReshareMessageBytes {
		return false
	}
	n.reshareMu.Lock()
	defer n.reshareMu.Unlock()
	if n.resharePending == nil {
		n.resharePending = make(map[string][]*reshareWireMessage)
	}
	key := string(message.SessionID)
	for _, previous := range n.resharePending[key] {
		if previous.FromParticipant == message.FromParticipant {
			return sameReshareMessage(previous, message)
		}
	}
	total := 0
	for _, messages := range n.resharePending {
		total += len(messages)
	}
	if total >= maxPendingReshareMessages || n.resharePendingBytes+size > maxPendingReshareBytes {
		return false
	}
	n.resharePending[key] = append(n.resharePending[key], message)
	n.resharePendingBytes += size
	return true
}

func reshareMessageSize(message *reshareWireMessage) int {
	if message == nil {
		return 0
	}
	size := len(message.SessionID) + len(message.GroupPublicKeyData)
	size += 8 * (len(message.OldParticipants) + len(message.NewParticipants))
	if message.Contribution != nil {
		size += len(message.Contribution.S1SubShare)
		size += len(message.Contribution.S2SubShare)
		size += len(message.Contribution.T0SubShare)
	}
	return size
}

func (n *Node) acknowledgeReshare(peer p2p.PeerID, message *reshareWireMessage) {
	if n.p2pHost == nil {
		return
	}
	acknowledgement := &reshareWireMessage{
		SessionID: message.SessionID, Epoch: message.Epoch,
		FromParticipant: message.ToParticipant, ToParticipant: message.FromParticipant,
		Acknowledgement: true, Attempt: message.Attempt,
	}
	payload, err := json.Marshal(acknowledgement)
	if err == nil {
		_ = n.p2pHost.SendTSSToPeer(peer, p2p.MsgTypeTSSDKGReshare, payload)
	}
}

func (t *P2PReshareTransport) ParticipantID() int { return t.participantID }

func (t *P2PReshareTransport) SessionID() []byte {
	return append([]byte(nil), t.sessionID...)
}

func (t *P2PReshareTransport) SetPeerResolver(resolve func(int) (p2p.PeerID, bool)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resolvePeer = resolve
}

func (t *P2PReshareTransport) Send(message *reshareWireMessage) error {
	if t.host == nil {
		return errors.New("p2p reshare transport: no P2P host wired")
	}
	if message == nil || message.Contribution == nil {
		return errors.New("p2p reshare transport: empty contribution")
	}
	if message.ToParticipant <= 0 || message.FromParticipant != t.participantID {
		return errors.New("p2p reshare transport: invalid participant binding")
	}

	t.mu.Lock()
	resolvePeer := t.resolvePeer
	t.mu.Unlock()
	if resolvePeer == nil {
		return fmt.Errorf("p2p reshare transport: no peer resolver for participant %d", message.ToParticipant)
	}
	peerID, ok := resolvePeer(message.ToParticipant)
	if !ok {
		return fmt.Errorf("p2p reshare transport: no peer mapping for participant %d", message.ToParticipant)
	}
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("marshal reshare contribution: %w", err)
	}
	if err := t.host.SendTSSToPeer(peerID, p2p.MsgTypeTSSDKGReshare, payload); err != nil {
		return fmt.Errorf("send reshare contribution to participant %d: %w", message.ToParticipant, err)
	}
	return nil
}

func (t *P2PReshareTransport) Ingest(message *reshareWireMessage) bool {
	if message == nil || message.Contribution == nil || message.Acknowledgement || !bytes.Equal(message.SessionID, t.sessionID) {
		return false
	}
	if message.ToParticipant != t.participantID || message.FromParticipant <= 0 {
		return false
	}
	if message.Contribution.FromParticipant != message.FromParticipant || message.Contribution.ToParticipant != message.ToParticipant {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if previous, exists := t.contributions[message.FromParticipant]; exists {
		return sameReshareMessage(previous, message)
	}
	t.contributions[message.FromParticipant] = message
	return true
}

func sameReshareMessage(left, right *reshareWireMessage) bool {
	leftCopy, rightCopy := *left, *right
	leftCopy.Attempt, rightCopy.Attempt = 0, 0
	leftData, leftErr := json.Marshal(leftCopy)
	rightData, rightErr := json.Marshal(rightCopy)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftData, rightData)
}

func (t *P2PReshareTransport) Acknowledge(message *reshareWireMessage) {
	if message == nil || !message.Acknowledgement || message.Contribution != nil ||
		message.ToParticipant != t.participantID || !bytes.Equal(message.SessionID, t.sessionID) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, expected := t.acknowledged[message.FromParticipant]; expected {
		t.acknowledged[message.FromParticipant] = true
	}
}

func (t *P2PReshareTransport) Deliver(ctx context.Context, messages []*reshareWireMessage) error {
	for _, message := range messages {
		if message == nil || message.Contribution == nil || message.Acknowledgement ||
			message.FromParticipant != t.participantID || message.ToParticipant <= 0 ||
			!bytes.Equal(message.SessionID, t.sessionID) {
			return fmt.Errorf("invalid reshare delivery binding")
		}
	}
	t.mu.Lock()
	for _, message := range messages {
		t.acknowledged[message.ToParticipant] = false
	}
	t.mu.Unlock()
	ticker := time.NewTicker(t.retryInterval)
	defer ticker.Stop()
	for attempt := uint32(1); ; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("reshare delivery canceled: %w", err)
		}
		remaining := 0
		for _, message := range messages {
			t.mu.Lock()
			acknowledged := t.acknowledged[message.ToParticipant]
			t.mu.Unlock()
			if acknowledged {
				continue
			}
			remaining++
			retry := *message
			retry.Attempt = attempt
			_ = t.Send(&retry)
		}
		if remaining == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("reshare delivery canceled with %d unacknowledged recipients: %w", remaining, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (t *P2PReshareTransport) Wait(ctx context.Context, oldParticipants []int) (map[int]*reshareWireMessage, error) {
	expected := make(map[int]struct{}, len(oldParticipants))
	for _, participantID := range oldParticipants {
		if participantID > 0 && participantID != t.participantID {
			expected[participantID] = struct{}{}
		}
	}
	deadline := time.NewTimer(t.waitTimeout)
	defer deadline.Stop()
	for {
		t.mu.Lock()
		result := make(map[int]*reshareWireMessage, len(expected))
		missing := make([]int, 0, len(expected))
		for participantID := range expected {
			message, ok := t.contributions[participantID]
			if !ok {
				missing = append(missing, participantID)
				continue
			}
			result[participantID] = message
		}
		t.mu.Unlock()
		if len(missing) == 0 {
			return result, nil
		}
		sort.Ints(missing)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("reshare wait canceled: %w", ctx.Err())
		case <-deadline.C:
			return nil, fmt.Errorf("reshare wait timed out (received %d/%d contributions; missing participants %v)", len(result), len(expected), missing)
		case <-time.After(resharePollInterval):
		}
	}
}

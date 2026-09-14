// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// ============================================================================
// Task 5 — node-layer distributed DKG wiring: P2PDKGTransport
//
// DKGTransport (wallet/tss/dkg_transport.go) abstracts cross-participant
// message exchange for the distributed DKG runner. The node layer provides
// this P2P implementation:
//
//   - SendCommitment broadcasts the Round1 commitment (public data, safe to
//     gossip) as a JSON qtd.Round1CommitmentMessage on
//     p2p.MsgTypeTSSDKGCommitment.
//   - SendShare delivers the Round1 open + Shamir share point-to-point to the
//     recipient participant (private material — NEVER broadcast) as a JSON
//     qtd.Round1OpenMessage on p2p.MsgTypeTSSDKGAck. Delivery resolves the
//     recipient's participant ID to a P2P peer via the injected peer resolver
//     (wired from the validator set by node.go); fail-closed when unmapped.
//   - Incoming messages are routed here from handleTSSMessage via
//     IngestCommitment / IngestShare; WaitCommitments / WaitShares block until
//     all other participants' messages arrive (or the wait timeout expires).
//
// When the TSSDistributedDKG switch is OFF (default), this transport is never
// wired and node behavior is unchanged.
// ============================================================================

// dkgDefaultWaitTimeout bounds WaitCommitments / WaitShares so a stalled
// participant cannot block the DKG driver forever.
const dkgDefaultWaitTimeout = 30 * time.Second

// dkgWaitPollInterval is how often WaitCommitments / WaitShares re-checks
// for newly ingested messages.
const dkgWaitPollInterval = 10 * time.Millisecond

// P2PDKGTransport implements wallet-layer tss.DKGTransport over the P2P
// network. It is created by DKGCoordinator and driven by the TSSManager's
// generateKeySharesDistributed path.
type P2PDKGTransport struct {
	// host is the P2P host used for message delivery. nil disables all
	// outbound sends (tests use nil hosts to verify fail-closed behavior).
	host *p2p.Host

	// participantID is this node's participant ID in the DKG round (1-based).
	participantID int
	// sessionID identifies this DKG session (validated cryptographically by
	// the runner; the transport only uses it for diagnostics/logging).
	sessionID []byte

	// resolvePeer maps a recipient participant ID to its P2P peer ID for
	// point-to-point share delivery. Wired by node.go from the validator set.
	// nil or a missing entry ⇒ fail-closed (shares are private and must
	// never be broadcast).
	resolvePeer func(participantID int) (p2p.PeerID, bool)

	mu          sync.Mutex
	commitments map[int]*qtd.Round1CommitmentMessage
	shares      map[int]*qtd.Round1OpenMessage
	waitTimeout time.Duration
}

// NewP2PDKGTransport constructs a P2P DKG transport for the given host,
// participant ID and session. host may be nil (outbound sends then fail
// closed with a clear error — used by tests and to surface mis-wiring).
func NewP2PDKGTransport(host *p2p.Host, participantID int, sessionID []byte) *P2PDKGTransport {
	return &P2PDKGTransport{
		host:          host,
		participantID: participantID,
		sessionID:     append([]byte(nil), sessionID...),
		commitments:   make(map[int]*qtd.Round1CommitmentMessage),
		shares:        make(map[int]*qtd.Round1OpenMessage),
		waitTimeout:   dkgDefaultWaitTimeout,
	}
}

// ParticipantID returns this participant's ID in the DKG round (1..total).
func (t *P2PDKGTransport) ParticipantID() int { return t.participantID }

// SetPeerResolver installs the participantID → P2P PeerID resolver used for
// point-to-point share delivery. Wired by the node layer from the validator
// set (validator index +1 = participant ID). Without it, SendShare fails
// closed rather than leaking private shares over broadcast.
func (t *P2PDKGTransport) SetPeerResolver(resolve func(participantID int) (p2p.PeerID, bool)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.resolvePeer = resolve
}

// SendCommitment broadcasts the Round1 commitment to all participants.
// Commitments are public (lattice-hard to invert), so gossip is safe and
// avoids needing a full peer map for every participant.
func (t *P2PDKGTransport) SendCommitment(peerID int, msg *qtd.Round1CommitmentMessage) error {
	if t.host == nil {
		return fmt.Errorf("p2p dkg transport: no P2P host wired; cannot send commitment to participant %d", peerID)
	}
	data, err := marshalDKGMessage(msg)
	if err != nil {
		return fmt.Errorf("p2p dkg transport: marshal commitment: %w", err)
	}
	if err := t.host.BroadcastTSS(p2p.MsgTypeTSSDKGCommitment, data); err != nil {
		return fmt.Errorf("p2p dkg transport: broadcast commitment: %w", err)
	}
	return nil
}

// SendShare delivers the Round1 open + Shamir share point-to-point to the
// recipient participant. Shares are private key material — they MUST NOT be
// broadcast. The recipient is resolved to a P2P peer via SetPeerResolver and
// delivered with SendTSSToPeer (encrypted transport).
func (t *P2PDKGTransport) SendShare(peerID int, msg *qtd.Round1OpenMessage) error {
	if t.host == nil {
		return fmt.Errorf("p2p dkg transport: no P2P host wired; cannot send share to participant %d", peerID)
	}
	t.mu.Lock()
	resolve := t.resolvePeer
	t.mu.Unlock()
	if resolve == nil {
		return fmt.Errorf("p2p dkg transport: no peer resolver wired; refusing to deliver private share for participant %d", peerID)
	}
	peer, ok := resolve(peerID)
	if !ok {
		return fmt.Errorf("p2p dkg transport: no P2P peer mapping for participant %d; refusing to deliver private share", peerID)
	}
	data, err := marshalDKGMessage(msg)
	if err != nil {
		return fmt.Errorf("p2p dkg transport: marshal share: %w", err)
	}
	if err := t.host.SendTSSToPeer(peer, p2p.MsgTypeTSSDKGAck, data); err != nil {
		return fmt.Errorf("p2p dkg transport: send share to participant %d: %w", peerID, err)
	}
	return nil
}

// IngestCommitment records an incoming Round1 commitment from another
// participant. Called by the node's handleTSSMessage routing path.
func (t *P2PDKGTransport) IngestCommitment(msg *qtd.Round1CommitmentMessage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if msg == nil || msg.ParticipantID <= 0 {
		return
	}
	t.commitments[msg.ParticipantID] = msg
}

// IngestShare records an incoming Round1 open + share from another
// participant. Called by the node's handleTSSMessage routing path.
func (t *P2PDKGTransport) IngestShare(msg *qtd.Round1OpenMessage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if msg == nil || msg.ParticipantID <= 0 {
		return
	}
	t.shares[msg.ParticipantID] = msg
}

// WaitCommitments blocks until the total-1 commitments from the other
// participants have been ingested (excluding this participant's own ID), or
// until the wait timeout expires. Returns a map keyed by participant ID.
func (t *P2PDKGTransport) WaitCommitments(total int) (map[int]*qtd.Round1CommitmentMessage, error) {
	return t.waitCommitments(total, t.waitTimeout)
}

// WaitShares blocks until the total-1 open+share messages from the other
// participants have been ingested (excluding this participant's own ID), or
// until the wait timeout expires. Returns a map keyed by participant ID.
func (t *P2PDKGTransport) WaitShares(total int) (map[int]*qtd.Round1OpenMessage, error) {
	return t.waitShares(total, t.waitTimeout)
}

func (t *P2PDKGTransport) waitCommitments(total int, timeout time.Duration) (map[int]*qtd.Round1CommitmentMessage, error) {
	deadline := time.Now().Add(timeout)
	for {
		t.mu.Lock()
		others := 0
		for pid := range t.commitments {
			if pid != t.participantID {
				others++
			}
		}
		if others >= total-1 {
			out := make(map[int]*qtd.Round1CommitmentMessage, total-1)
			for pid, m := range t.commitments {
				if pid != t.participantID {
					out[pid] = m
				}
			}
			t.mu.Unlock()
			return out, nil
		}
		t.mu.Unlock()
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("p2p dkg transport: timed out waiting for %d commitments (have %d)", total-1, others)
		}
		time.Sleep(dkgWaitPollInterval)
	}
}

func (t *P2PDKGTransport) waitShares(total int, timeout time.Duration) (map[int]*qtd.Round1OpenMessage, error) {
	deadline := time.Now().Add(timeout)
	for {
		t.mu.Lock()
		others := 0
		for pid := range t.shares {
			if pid != t.participantID {
				others++
			}
		}
		if others >= total-1 {
			out := make(map[int]*qtd.Round1OpenMessage, total-1)
			for pid, m := range t.shares {
				if pid != t.participantID {
					out[pid] = m
				}
			}
			t.mu.Unlock()
			return out, nil
		}
		t.mu.Unlock()
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("p2p dkg transport: timed out waiting for %d shares (have %d)", total-1, others)
		}
		time.Sleep(dkgWaitPollInterval)
	}
}

// marshalDKGMessage serializes a DKG round payload to JSON for the wire.
func marshalDKGMessage(v any) ([]byte, error) {
	return json.Marshal(v)
}

// decodeDKGCommitmentPayload parses a qtd.Round1CommitmentMessage from a
// received p2p.MsgTypeTSSDKGCommitment payload.
func decodeDKGCommitmentPayload(payload []byte) (*qtd.Round1CommitmentMessage, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty DKG commitment payload")
	}
	var msg qtd.Round1CommitmentMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("decode DKG commitment: %w", err)
	}
	return &msg, nil
}

// decodeDKGSharePayload parses a qtd.Round1OpenMessage from a received
// p2p.MsgTypeTSSDKGAck payload.
func decodeDKGSharePayload(payload []byte) (*qtd.Round1OpenMessage, error) {
	if len(payload) == 0 {
		return nil, errors.New("empty DKG share payload")
	}
	var msg qtd.Round1OpenMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("decode DKG share: %w", err)
	}
	return &msg, nil
}

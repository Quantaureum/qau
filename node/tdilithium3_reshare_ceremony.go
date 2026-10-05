// Quantaureum Node source, version 1.0.0.
package node

// R77 ceremony: the same-key remove rotation for the Dilithium3 v1 CNF-RSS
// committee (design 2026-10-02, sections 4 and 6). When the epoch roster's
// committee equals the active share's committee minus one member, this path
// rotates the local share in place: no group rounds, only the fold deltas
// the anchor owes the other members of each target group, then the
// acknowledgement-based activation exchange. Any failure fails closed to
// the caller, which runs the ordinary fresh-key ceremony instead.

import (
	"context"
	"crypto/sha3"
	"errors"
	"fmt"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const (
	// tdilithium3ReshareRoundTimeout bounds the delta-delivery window. It is
	// a single bounded round, matching the DKG group-round timeout.
	tdilithium3ReshareRoundTimeout = 30 * time.Second
)

var (
	// errTDilithium3ReshareNotApplicable marks committee pairs that are not a
	// valid one-member remove rotation; the caller runs the ordinary
	// fresh-key ceremony instead.
	errTDilithium3ReshareNotApplicable = errors.New("Dilithium3 v1 reshare rotation not applicable")
	// errTDilithium3ReshareTimeout is returned when fold deltas do not all
	// arrive inside the delivery window.
	errTDilithium3ReshareTimeout = errors.New("Dilithium3 v1 reshare rotation timed out waiting for fold deltas")
)

// reshare-delta retention holds inbound delta envelopes that arrive while no
// ceremony inbox is installed (committee members enter the rotation at
// different block heights). The envelope's own signed session digest keys
// retention, so a stale session can never satisfy a future inbox.

// retainTDilithium3ReshareDelta stores one inbound reshare delta that no
// admissible inbox consumed, keyed by the envelope's payload digest.
func (n *Node) retainTDilithium3ReshareDelta(msg p2p.PeerMessage) {
	if n == nil {
		return
	}
	n.tdilithium3ResharePendingMu.Lock()
	defer n.tdilithium3ResharePendingMu.Unlock()
	if n.tdilithium3ResharePending == nil {
		n.tdilithium3ResharePending = make(map[[32]byte]p2p.PeerMessage)
	}
	key := sha3.Sum256(append([]byte{msg.Type}, msg.Payload...))
	if _, exists := n.tdilithium3ResharePending[key]; exists {
		return
	}
	nodeLog.Warn("Dilithium3 v1 reshare delta retained (no admissible inbox), peer=%s: %s",
		msg.From, pendingTDilithium3ReshareDeltaDiag(msg.Payload))
	if len(n.tdilithium3ResharePending) >= 256 {
		nodeLog.Warn("Dilithium3 v1 reshare delta retention full; dropping the oldest delta is not safe, refusing new delta")
		return
	}
	n.tdilithium3ResharePending[key] = p2p.PeerMessage{From: msg.From, Type: msg.Type, Payload: append([]byte(nil), msg.Payload...)}
}

// pendingTDilithium3ReshareSessions returns the retained envelope session
// digest of a raw payload, or false if the packet does not parse.
func pendingTDilithium3ReshareSession(payload []byte) ([32]byte, bool) {
	envelope, err := protocol.DecodeEnvelope(payload)
	if err != nil {
		return [32]byte{}, false
	}
	wire, err := dilithium3v1.UnmarshalReshareDeltaWire(envelope.Payload)
	if err != nil {
		return [32]byte{}, false
	}
	return wire.SessionDigest, true
}

// pendingTDilithium3ReshareDeltaDiag renders one retained envelope as a short
// diagnostic string for retention logging. Best effort: unparsable payloads
// are reported as such rather than failing the retain.
func pendingTDilithium3ReshareDeltaDiag(payload []byte) string {
	envelope, err := protocol.DecodeEnvelope(payload)
	if err != nil {
		return "unparsable envelope: " + err.Error()
	}
	wire, err := dilithium3v1.UnmarshalReshareDeltaWire(envelope.Payload)
	if err != nil {
		return "unparsable delta wire: " + err.Error()
	}
	return fmt.Sprintf("session=%x anchor=%d recipient=%d target=%06b kind=%d",
		wire.SessionDigest[:4], wire.AnchorPosition, wire.RecipientPosition,
		uint16(wire.TargetGroup), wire.Kind)
}

// replayTDilithium3ReshareDeltas feeds every retained reshare delta matching
// the session digest back through the installed inbox (identity checks and
// replay dedup run inside accept).
func (inbox *tdilithium3DKGInbox) replayTDilithium3ReshareDeltas(n *Node, sessionDigest [32]byte) {
	if inbox == nil || n == nil {
		return
	}
	n.tdilithium3ResharePendingMu.Lock()
	msgs := make([]p2p.PeerMessage, 0, len(n.tdilithium3ResharePending))
	for key, msg := range n.tdilithium3ResharePending {
		if digest, ok := pendingTDilithium3ReshareSession(msg.Payload); ok && digest == sessionDigest {
			msgs = append(msgs, msg)
			delete(n.tdilithium3ResharePending, key)
		}
	}
	n.tdilithium3ResharePendingMu.Unlock()
	if len(msgs) > 0 {
		nodeLog.Info("Dilithium3 v1 reshare rotation: replaying %d retained fold delta(s) into session %x", len(msgs), sessionDigest[:8])
	}
	for _, msg := range msgs {
		if err := inbox.accept(msg); err != nil {
			nodeLog.Debug("reshare fold delta replay rejected: %v", err)
		}
	}
}

// tdilithium3ReshareRemoveConfig carries the ceremony's explicit inputs so
// the in-process choreography tests drive exactly the production path.
type tdilithium3ReshareRemoveConfig struct {
	Session          dilithium3v1.DKGSession  // reshare-shaped; NEW committee
	Position         uint8                    // this node's position in the NEW committee
	RosterEpoch      uint64                   // roster epoch the session is anchored on
	OldShare         *dilithium3v1.LocalShare // active share of the previous committee
	Plan             *dilithium3v1.ReshareRotationPlan // address-derived plan from the probe; nil recomputes by committees
	Store            *thresholdShareStore     // candidate + activation persistence
	Password         []byte                   // share-store password
	PeerForValidator func(types.Address) (p2p.PeerID, bool)
	Sign             func(message []byte) ([]byte, error)
	Broadcast        func(messageType uint8, payload []byte) error
	SendPrivate      func(messageType uint8, recipient uint8, encoded []byte) error
}

// tdilithium3ReshareTranscriptDigest binds the old share's transcript to the
// reshare session so two different rotation artifacts never share a store row.
func tdilithium3ReshareTranscriptDigest(session dilithium3v1.DKGSession, oldTranscript [32]byte) ([32]byte, error) {
	sessionDigest, err := session.Digest()
	if err != nil {
		return [32]byte{}, err
	}
	return sha3.Sum256(append(
		[]byte("QAU-TDILITHIUM3-V1-RESHARE-TRANSCRIPT"),
		append(sessionDigest[:], oldTranscript[:]...)...,
	)), nil
}

// runTDilithium3ReshareRemoveCeremony produces the same-key rotated share
// and drives the activation exchange. The caller owns the ceremony mutex.
// Returns the (unchanged) group public key on success.
func (n *Node) runTDilithium3ReshareRemoveCeremony(
	ctx context.Context,
	config tdilithium3ReshareRemoveConfig,
) ([1952]byte, error) {
	var publicKey [1952]byte
	if n == nil || n.config == nil || !experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID) {
		return publicKey, errTDilithium3ReshareNotApplicable
	}
	if config.OldShare == nil || config.Store == nil || len(config.Password) == 0 ||
		config.Sign == nil || config.Broadcast == nil || config.SendPrivate == nil || config.PeerForValidator == nil {
		return publicKey, fmt.Errorf("%w: malformed rotation config", errTDilithium3ReshareNotApplicable)
	}
	if err := config.Session.Validate(); err != nil {
		return publicKey, err
	}
	// The caller (tryTDilithium3ReshareRemoveRotation) derives the plan by
	// address intersection of the old and new rosters and passes it through:
	// participant ids are renumbered by committee, so committee-based plan
	// reconstruction can disagree across nodes.
	plan := config.Plan
	if plan == nil {
		var planErr error
		plan, planErr = tdilithium3ReshareRotationFor(config.OldShare.Committee, config.Session.Committee)
		if planErr != nil {
			return publicKey, planErr
		}
	}
	if plan == nil || !plan.HasLeaver {
		return publicKey, fmt.Errorf("%w: committee pair is not a remove rotation", errTDilithium3ReshareNotApplicable)
	}
	if config.Position >= uint8(len(config.Session.Committee.Participants)) {
		return publicKey, fmt.Errorf("%w: position %d outside the new committee", errTDilithium3ReshareNotApplicable, config.Position)
	}
	transcriptDigest, err := tdilithium3ReshareTranscriptDigest(config.Session, config.OldShare.TranscriptDigest)
	if err != nil {
		return publicKey, err
	}
	sessionDigest, err := config.Session.Digest()
	if err != nil {
		return publicKey, err
	}
	committeeDigest, err := config.Session.Committee.CanonicalDigest()
	if err != nil {
		return publicKey, err
	}

	// The reshare flow reuses the same inbox slot as the fresh-key ceremony:
	// only one ceremony is active at a time behind the caller's mutex.
	inbox, err := n.newTDilithium3DKGInboxFromCapturedEpochRoster(
		config.Session, config.Position, config.RosterEpoch, config.PeerForValidator,
	)
	if err != nil {
		return publicKey, fmt.Errorf("Dilithium3 v1 reshare inbox: %w", err)
	}
	n.installTDilithium3DKGInbox(inbox)
	defer n.installTDilithium3DKGInbox(nil)
	inbox.replayTDilithium3ReshareDeltas(n, sessionDigest)

	runner, err := newTDilithium3ReshareRemoveRunner(plan, config.OldShare, config.Session.Committee, transcriptDigest)
	if err != nil {
		return publicKey, fmt.Errorf("Dilithium3 v1 reshare runner: %w", err)
	}

	// Publish every fold delta this member anchors. The anchor coordinate on
	// the wire is the SENDER's new-committee position (the delivery list
	// contains only this member's own anchor duties), which the inbox checks
	// against the envelope's committee position.
	sent := 0
	for _, delivery := range runner.OutgoingDeltas() {
		wire := dilithium3v1.ReshareDeltaWire{
			SessionDigest:     sessionDigest,
			CommitteeDigest:   committeeDigest,
			Kind:              dilithium3v1.ReshareDeltaKindFold,
			SourceGroup:       delivery.Delta.Source,
			TargetGroup:       delivery.Delta.Target,
			AnchorPosition:    config.Position,
			RecipientPosition: delivery.RecipientPosition,
			Component:         delivery.Delta.Component,
		}
		payload, err := wire.MarshalBinary()
		if err != nil {
			return publicKey, err
		}
		encoded, err := encodeTDilithium3DKGSignedEnvelope(config.Session, p2p.MsgTypeTDilithium3ReshareDelta,
			config.Position, 1, payload, config.Sign)
		if err != nil {
			return publicKey, err
		}
		// Broadcast rather than direct-send: the envelope's RecipientPosition
		// and the signed-anchor identity are verified at the inbox, so peers
		// not named by the delta simply discard it. The TSS broadcast path is
		// the same one the DKG randomness/commitment rounds use, which the
		// point-to-point SendTSSToPeer routing does not traverse.
		if err := config.Broadcast(p2p.MsgTypeTDilithium3ReshareDelta, encoded); err != nil {
			return publicKey, fmt.Errorf("reshare delta broadcast for position %d: %w", delivery.RecipientPosition, err)
		}
		sent++
		nodeLog.Info("reshare delta sent: anchor=%d -> recipient=%d target=%06b", config.Position, delivery.RecipientPosition, uint16(delivery.Delta.Target))
	}
	nodeLog.Info("Dilithium3 v1 reshare rotation: published %d fold delta(s), awaiting %d more (activation epoch %d, session %x, missing: %s)",
		sent, runner.Pending(), config.Session.ActivationEpoch, sessionDigest[:8], runner.PendingDetail())

	// Collect addressed deltas until the runner is complete.
	deadline := time.NewTimer(tdilithium3ReshareRoundTimeout)
	defer deadline.Stop()
	for !runner.Ready() {
		var message tdilithium3DKGVerifiedMessage
		select {
		case <-deadline.C:
			nodeLog.Warn("Dilithium3 v1 reshare rotation: delivery window elapsed, missing deltas (session %x, activation epoch %d): %s",
				sessionDigest[:8], config.Session.ActivationEpoch, runner.PendingDetail())
			return publicKey, errTDilithium3ReshareTimeout
		case <-ctx.Done():
			return publicKey, ctx.Err()
		case next, open := <-inbox.messages:
			if !open {
				return publicKey, fmt.Errorf("reshare inbox closed while deltas are outstanding")
			}
			message = next
		}
		if message.Type != p2p.MsgTypeTDilithium3ReshareDelta {
			continue
		}
		wire, err := dilithium3v1.UnmarshalReshareDeltaWire(message.Payload)
		if err != nil || wire.Kind != dilithium3v1.ReshareDeltaKindFold {
			continue
		}
		if err := runner.Receive(tdilithium3ReshareDeltaDelivery{
			RecipientPosition: wire.RecipientPosition,
			Delta: dilithium3v1.ReshareFoldDelta{
				Source:    wire.SourceGroup,
				Target:    wire.TargetGroup,
				Component: wire.Component,
			},
		}); err != nil {
			nodeLog.Debug("reshare fold delta rejected: %v", err)
		} else {
			nodeLog.Info("reshare fold delta accepted (target %06b, pending %d, session %x)",
				uint16(wire.TargetGroup), runner.Pending(), sessionDigest[:8])
		}
	}

	rotatedShare, err := runner.Assemble()
	if err != nil {
		return publicKey, err
	}
	defer rotatedShare.Zeroize()
	// Align the rotated share's identity fields with the rotation session:
	// the store's candidate/ledger invariants and the activation exchange's
	// share-vs-session check all require generation, activation epoch, and
	// committee version to equal the session's values.
	//
	// The session id (Committee canonical digest) is part of the share's
	// canonical encoding, so every aligned field is re-encoded BEFORE the
	// share is verified and stored: re-encode, re-validate, store.
	rotatedShare.Key.Generation = config.Session.KeyGeneration
	rotatedShare.ActivationEpoch = config.Session.ActivationEpoch
	rotatedShare.Committee.Version = config.Session.Committee.Version
	encodedShare, err := rotatedShare.MarshalBinary()
	if err != nil {
		return publicKey, fmt.Errorf("reshare rotation share encoding: %w", err)
	}
	canonical, err := dilithium3v1.UnmarshalLocalShare(encodedShare)
	if err != nil {
		return publicKey, fmt.Errorf("reshare rotation share decode: %w", err)
	}
	if err := canonical.Validate(); err != nil {
		return publicKey, fmt.Errorf("reshare rotation share validation: %w", err)
	}
	*rotatedShare = *canonical
	if err := config.Store.Store(rotatedShare, config.Password); err != nil {
		return publicKey, err
	}
	copy(publicKey[:], rotatedShare.Key.PublicKey)

	// Adoption short-circuit: a faster peer's exchange may have gossiped the
	// activation certificate already; the share store is the source of truth.
	if activeEpoch, activeKey, activeThreshold, activeErr := config.Store.ActiveSharePublicIdentity(config.Password); activeErr == nil && activeEpoch == config.Session.ActivationEpoch {
		nodeLog.Info("Dilithium3 v1 reshare rotation: active share already adopted for epoch %d (group key prefix %x); skipping activation exchange",
			config.Session.ActivationEpoch, activeKey[:4])
		if err := n.registerTDilithium3SigningFinalitySigner(config.Session.ActivationEpoch, activeKey, int(activeThreshold)); err != nil {
			nodeLog.Warn("Dilithium3 v1 reshare finality surface registration deferred (adopted path): %v", err)
		}
		copy(publicKey[:], activeKey)
		nodeLog.Info("Dilithium3 v1 reshare rotation completed (activation epoch %d, session digest %x, transcript %x, group key prefix %x, committee size %d)",
			config.Session.ActivationEpoch, sessionDigest[:8], transcriptDigest[:8], publicKey[:4], len(config.Session.Committee.Participants))
		return publicKey, nil
	}

	// Activation exchange identical to the fresh-key ceremony's: unanimous
	// signed acknowledgements, certificate assembly, adopt-and-gossip.
	// Rotation members start their ceremonies at staggered times (their
	// per-slot produce loops retry independently), so the exchange gets a
	// wider window than the fresh-key ceremony's single round.
	activationContext, cancelActivation := context.WithTimeout(ctx, 4*tdilithium3DKGActivationExchangeTimeout)
	exchangeErr := n.runTDilithium3ActivationExchange(
		activationContext, config.Session, rotatedShare, config.Store, config.Password,
		inbox.verifyIdentity, inbox.IdentityBindings(), config.Sign, config.Broadcast,
	)
	cancelActivation()
	if exchangeErr != nil {
		return publicKey, fmt.Errorf("Dilithium3 v1 reshare activation exchange: %w", exchangeErr)
	}
	if err := n.registerTDilithium3SigningFinalitySigner(
		config.Session.ActivationEpoch, publicKey[:], int(config.Session.Committee.Threshold),
	); err != nil {
		nodeLog.Warn("Dilithium3 v1 reshare finality surface registration deferred: %v", err)
	}
	nodeLog.Info("Dilithium3 v1 reshare rotation completed (activation epoch %d, session digest %x, transcript %x, group key prefix %x, committee size %d)",
		config.Session.ActivationEpoch, sessionDigest[:8], transcriptDigest[:8], publicKey[:4], len(config.Session.Committee.Participants))
	return publicKey, nil
}

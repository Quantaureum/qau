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

// tdilithium3ReshareRemoveConfig carries the ceremony's explicit inputs so
// the in-process choreography tests drive exactly the production path.
type tdilithium3ReshareRemoveConfig struct {
	Session          dilithium3v1.DKGSession  // reshare-shaped; NEW committee
	Position         uint8                    // this node's position in the NEW committee
	RosterEpoch      uint64                   // roster epoch the session is anchored on
	OldShare         *dilithium3v1.LocalShare // active share of the previous committee
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
	plan, err := tdilithium3ReshareRotationFor(config.OldShare.Committee, config.Session.Committee)
	if err != nil {
		return publicKey, err
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

	runner, err := newTDilithium3ReshareRemoveRunner(plan, config.OldShare, config.Session.Committee, transcriptDigest)
	if err != nil {
		return publicKey, fmt.Errorf("Dilithium3 v1 reshare runner: %w", err)
	}

	// Publish every fold delta this member anchors. The anchor coordinate on
	// the wire is the SENDER's new-committee position (the delivery list
	// contains only this member's own anchor duties), which the inbox checks
	// against the envelope's committee position.
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
		if err := config.SendPrivate(p2p.MsgTypeTDilithium3ReshareDelta, delivery.RecipientPosition, encoded); err != nil {
			return publicKey, fmt.Errorf("reshare delta to position %d: %w", delivery.RecipientPosition, err)
		}
	}

	// Collect addressed deltas until the runner is complete.
	deadline := time.NewTimer(tdilithium3ReshareRoundTimeout)
	defer deadline.Stop()
	for !runner.Ready() {
		var message tdilithium3DKGVerifiedMessage
		select {
		case <-deadline.C:
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
		}
	}

	rotatedShare, err := runner.Assemble()
	if err != nil {
		return publicKey, err
	}
	defer rotatedShare.Zeroize()
	if err := config.Store.Store(rotatedShare, config.Password); err != nil {
		return publicKey, err
	}
	copy(publicKey[:], rotatedShare.Key.PublicKey)

	// Activation exchange identical to the fresh-key ceremony's: unanimous
	// signed acknowledgements, certificate assembly, adopt-and-gossip.
	activationContext, cancelActivation := context.WithTimeout(ctx, tdilithium3DKGActivationExchangeTimeout)
	exchangeErr := n.runTDilithium3ActivationExchange(
		activationContext, config.Session, rotatedShare, config.Store, config.Password,
		inbox.verifyIdentity, config.Sign, config.Broadcast,
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

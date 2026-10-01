// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

const (
	tmldsaResharePrivateWireMagic = "QTMRPRV1"
	tmldsaResharePrivateMagic     = "QTMLDSA-RESHARE-PRIVATE-1"
)

type tmldsaResharePrivateContribution struct {
	SessionID       [32]byte                `json:"session_id"`
	Key             protocol.ThresholdKeyID `json:"key"`
	OldCommittee    protocol.CommitteeID    `json:"old_committee"`
	NewCommittee    protocol.CommitteeID    `json:"new_committee"`
	SelectedDealers []uint32                `json:"selected_dealers"`
	DealerID        uint32                  `json:"dealer_id"`
	RecipientID     uint32                  `json:"recipient_id"`
	Payload         []byte                  `json:"payload"`
}

func (message tmldsaResharePrivateContribution) validate() error {
	if message.SessionID == ([32]byte{}) || message.DealerID == 0 || message.RecipientID == 0 ||
		len(message.Payload) == 0 || len(message.Payload) > protocol.MaxThresholdEnvelopePayload {
		return fmt.Errorf("invalid TMLDSA private reshare contribution metadata")
	}
	if err := protocol.DefaultTMLDSAV1Profile().ValidateTransition(message.OldCommittee, message.NewCommittee); err != nil {
		return err
	}
	if len(message.SelectedDealers) != int(protocol.TMLDSAV1Threshold) ||
		!containsTMLDSAParticipant(message.SelectedDealers, message.DealerID) ||
		!containsTMLDSAParticipant(message.NewCommittee.Participants, message.RecipientID) {
		return fmt.Errorf("invalid TMLDSA private reshare contribution participants")
	}
	if _, err := protocolmldsa65.DecodeReshareContribution(
		message.Payload,
		message.Key,
		message.OldCommittee,
		message.NewCommittee,
		message.SelectedDealers,
		message.DealerID,
		message.RecipientID,
	); err != nil {
		return err
	}
	return nil
}

func encodeTMLDSAResharePrivateContribution(message tmldsaResharePrivateContribution) ([]byte, error) {
	if err := message.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(payload)+len(tmldsaResharePrivateMagic) > maxReshareMessageBytes {
		return nil, fmt.Errorf("TMLDSA private reshare contribution exceeds size limit")
	}
	return append([]byte(tmldsaResharePrivateMagic), payload...), nil
}

func decodeTMLDSAResharePrivateContribution(payload []byte) (tmldsaResharePrivateContribution, error) {
	if len(payload) > maxReshareMessageBytes || !bytes.HasPrefix(payload, []byte(tmldsaResharePrivateMagic)) {
		return tmldsaResharePrivateContribution{}, fmt.Errorf("invalid TMLDSA private reshare contribution encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload[len(tmldsaResharePrivateMagic):]))
	decoder.DisallowUnknownFields()
	var message tmldsaResharePrivateContribution
	if err := decoder.Decode(&message); err != nil {
		return tmldsaResharePrivateContribution{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tmldsaResharePrivateContribution{}, fmt.Errorf("invalid trailing TMLDSA private reshare contribution data")
	}
	if err := message.validate(); err != nil {
		return tmldsaResharePrivateContribution{}, err
	}
	return message, nil
}

func isTMLDSAResharePrivatePayload(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte(tmldsaResharePrivateWireMagic))
}

func (n *Node) sendTMLDSAResharePrivateContribution(message tmldsaResharePrivateContribution) error {
	plaintext, err := encodeTMLDSAResharePrivateContribution(message)
	if err != nil {
		return err
	}
	localID := n.getMyParticipantID()
	if localID > 0 && uint32(localID) == message.RecipientID {
		return n.persistTMLDSAInboundResharePayload(tmldsaInboundReshareSet{
			SessionID:           message.SessionID,
			KeyGeneration:       message.Key.Generation,
			OldCommitteeVersion: message.OldCommittee.Version,
			NewCommitteeVersion: message.NewCommittee.Version,
			RecipientID:         message.RecipientID,
		}, message.DealerID, message.Payload)
	}
	if n == nil || n.keyExchange == nil || n.p2pHost == nil || n.blockProducer == nil || n.blockProducer.qpos == nil {
		return fmt.Errorf("TMLDSA private reshare transport is unavailable")
	}
	validatorSet := n.blockProducer.qpos.GetValidatorSet()
	if validatorSet == nil {
		return fmt.Errorf("TMLDSA private reshare validator set is unavailable")
	}
	validators := validatorSet.Validators()
	if int(message.RecipientID) > len(validators) || validators[message.RecipientID-1] == nil ||
		!validators[message.RecipientID-1].Active {
		return fmt.Errorf("TMLDSA private reshare recipient is not active")
	}
	peerAddress := validators[message.RecipientID-1].Address
	peerID, found := n.p2pHost.GetPeerIDForValidator(peerAddress)
	if !found {
		return fmt.Errorf("TMLDSA private reshare recipient peer is unavailable")
	}
	sealed, err := n.keyExchange.SealForPeer(peerAddress, plaintext)
	if err != nil {
		return err
	}
	wirePayload := append([]byte(tmldsaResharePrivateWireMagic), sealed...)
	if len(wirePayload) > maxReshareMessageBytes {
		return fmt.Errorf("sealed TMLDSA private reshare contribution exceeds size limit")
	}
	return n.p2pHost.SendTSSToPeer(peerID, p2p.MsgTypeTSSDKGReshare, wirePayload)
}

func (n *Node) handleTMLDSAResharePrivateContribution(message p2p.PeerMessage) error {
	if n == nil || n.keyExchange == nil || !isTMLDSAResharePrivatePayload(message.Payload) {
		return fmt.Errorf("invalid TMLDSA private reshare transport state")
	}
	senderAddress, found := n.resolveSenderAddress(message.From)
	if !found {
		return fmt.Errorf("TMLDSA private reshare sender is unknown")
	}
	plaintext, err := n.keyExchange.OpenFromPeer(
		senderAddress,
		message.Payload[len(tmldsaResharePrivateWireMagic):],
	)
	if err != nil {
		return err
	}
	decoded, err := decodeTMLDSAResharePrivateContribution(plaintext)
	if err != nil {
		return err
	}
	if !n.validateSenderParticipantID(senderAddress, int(decoded.DealerID)) ||
		int(decoded.RecipientID) != n.getMyParticipantID() {
		return fmt.Errorf("TMLDSA private reshare participant binding mismatch")
	}
	return n.persistTMLDSAInboundResharePayload(tmldsaInboundReshareSet{
		SessionID:           decoded.SessionID,
		KeyGeneration:       decoded.Key.Generation,
		OldCommitteeVersion: decoded.OldCommittee.Version,
		NewCommitteeVersion: decoded.NewCommittee.Version,
		RecipientID:         decoded.RecipientID,
	}, decoded.DealerID, decoded.Payload)
}

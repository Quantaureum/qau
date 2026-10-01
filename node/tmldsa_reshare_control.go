// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

const (
	tmldsaReshareControlMagic    = "QTMRCTL1"
	tmldsaReshareControlProtocol = "qau-tmldsa65-v1-reshare"

	tmldsaReshareControlContributionSet = "contribution-set"
	tmldsaReshareControlAgreement       = "agreement"
	tmldsaReshareControlNonceCommitment = "nonce-commitment"
	tmldsaReshareControlNonceReveal     = "nonce-reveal"
	tmldsaReshareControlTermCommitment  = "term-commitment"
	tmldsaReshareControlTermReveal      = "term-reveal"
	tmldsaReshareControlTimeout         = "timeout"
	tmldsaReshareControlAbortEvidence   = "abort-evidence"
	tmldsaReshareControlActivationAck   = "activation-ack"
	tmldsaReshareControlActivationCert  = "activation-certificate"
)

type tmldsaReshareControlCommitment struct {
	RecipientID uint32   `json:"recipient_id"`
	Commitment  [32]byte `json:"commitment"`
}

type tmldsaReshareControlMessage struct {
	Protocol              string                                            `json:"protocol"`
	Kind                  string                                            `json:"kind"`
	SessionID             [32]byte                                          `json:"session_id"`
	Key                   protocol.ThresholdKeyID                           `json:"key,omitempty"`
	OldCommittee          protocol.CommitteeID                              `json:"old_committee,omitempty"`
	NewCommittee          protocol.CommitteeID                              `json:"new_committee,omitempty"`
	SelectedDealers       []uint32                                          `json:"selected_dealers,omitempty"`
	DealerID              uint32                                            `json:"dealer_id"`
	SenderID              uint32                                            `json:"sender_id"`
	TermSenderID          uint32                                            `json:"term_sender_id,omitempty"`
	ContributionHeads     []tmldsaReshareControlCommitment                  `json:"contribution_heads,omitempty"`
	Value                 [32]byte                                          `json:"value,omitempty"`
	Term                  int32                                             `json:"term,omitempty"`
	Salt                  [32]byte                                          `json:"salt,omitempty"`
	AbortEvidence         *protocolmldsa65.SignedReshareAbortEvidence       `json:"abort_evidence,omitempty"`
	ActivationAck         *protocolmldsa65.ReshareActivationAcknowledgement `json:"activation_ack,omitempty"`
	ActivationCertificate *protocolmldsa65.ReshareActivationCertificate     `json:"activation_certificate,omitempty"`
}

func isTMLDSAReshareControlPayload(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte(tmldsaReshareControlMagic))
}

func encodeTMLDSAReshareControlMessage(message tmldsaReshareControlMessage) ([]byte, error) {
	if err := message.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(payload)+len(tmldsaReshareControlMagic) > maxReshareMessageBytes {
		return nil, fmt.Errorf("TMLDSA reshare control message exceeds size limit")
	}
	return append([]byte(tmldsaReshareControlMagic), payload...), nil
}

func decodeTMLDSAReshareControlMessage(payload []byte) (tmldsaReshareControlMessage, error) {
	if len(payload) > maxReshareMessageBytes || !isTMLDSAReshareControlPayload(payload) {
		return tmldsaReshareControlMessage{}, fmt.Errorf("invalid TMLDSA reshare control encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload[len(tmldsaReshareControlMagic):]))
	decoder.DisallowUnknownFields()
	var message tmldsaReshareControlMessage
	if err := decoder.Decode(&message); err != nil {
		return tmldsaReshareControlMessage{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tmldsaReshareControlMessage{}, fmt.Errorf("invalid trailing TMLDSA reshare control data")
	}
	if err := message.validate(); err != nil {
		return tmldsaReshareControlMessage{}, err
	}
	return message, nil
}

func (message tmldsaReshareControlMessage) validate() error {
	if message.Protocol != tmldsaReshareControlProtocol || message.SessionID == ([32]byte{}) ||
		message.DealerID == 0 || message.SenderID == 0 {
		return fmt.Errorf("invalid TMLDSA reshare control metadata")
	}
	switch message.Kind {
	case tmldsaReshareControlContributionSet:
		if message.SenderID != message.DealerID ||
			protocol.DefaultTMLDSAV1Profile().ValidateTransition(message.OldCommittee, message.NewCommittee) != nil ||
			len(message.SelectedDealers) != int(protocol.TMLDSAV1Threshold) ||
			len(message.ContributionHeads) != int(protocol.TMLDSAV1ParticipantCount) {
			return fmt.Errorf("invalid TMLDSA contribution-set control message")
		}
		seen := make(map[uint32]struct{}, len(message.ContributionHeads))
		for index, entry := range message.ContributionHeads {
			if entry.Commitment == ([32]byte{}) || index >= len(message.NewCommittee.Participants) ||
				entry.RecipientID != message.NewCommittee.Participants[index] {
				return fmt.Errorf("invalid TMLDSA contribution commitment order")
			}
			if _, duplicate := seen[entry.RecipientID]; duplicate {
				return fmt.Errorf("duplicate TMLDSA contribution recipient")
			}
			seen[entry.RecipientID] = struct{}{}
		}
	case tmldsaReshareControlAgreement,
		tmldsaReshareControlNonceCommitment,
		tmldsaReshareControlNonceReveal:
		if message.Value == ([32]byte{}) {
			return fmt.Errorf("missing TMLDSA reshare control value")
		}
	case tmldsaReshareControlTermCommitment:
		if message.Value == ([32]byte{}) || !message.validTermSender() {
			return fmt.Errorf("invalid TMLDSA term commitment sender")
		}
	case tmldsaReshareControlTermReveal:
		if message.Salt == ([32]byte{}) || !message.validTermSender() {
			return fmt.Errorf("invalid TMLDSA term reveal sender")
		}
	case tmldsaReshareControlTimeout:
		if message.SenderID != message.DealerID || message.Value == ([32]byte{}) {
			return fmt.Errorf("invalid TMLDSA timeout evidence")
		}
	case tmldsaReshareControlAbortEvidence:
		if message.AbortEvidence == nil || message.SenderID != message.AbortEvidence.ReporterID ||
			message.SessionID != message.AbortEvidence.SessionID || message.DealerID != message.AbortEvidence.DealerID ||
			len(message.AbortEvidence.IdentitySignature) == 0 {
			return fmt.Errorf("invalid signed TMLDSA abort evidence")
		}
		if _, err := message.AbortEvidence.SigningBytes(); err != nil {
			return err
		}
	case tmldsaReshareControlActivationAck:
		if message.ActivationAck == nil || message.SenderID != message.ActivationAck.ParticipantID ||
			message.SessionID != message.ActivationAck.SessionID ||
			len(message.ActivationAck.IdentitySignature) == 0 {
			return fmt.Errorf("invalid signed TMLDSA activation acknowledgement")
		}
		if _, err := message.ActivationAck.SigningBytes(); err != nil {
			return err
		}
	case tmldsaReshareControlActivationCert:
		if message.ActivationCertificate == nil ||
			len(message.ActivationCertificate.Acknowledgements) == 0 ||
			message.SessionID != message.ActivationCertificate.Acknowledgements[0].SessionID ||
			!containsTMLDSAParticipant(
				message.ActivationCertificate.Acknowledgements[0].NewCommittee.Participants,
				message.SenderID,
			) {
			return fmt.Errorf("invalid TMLDSA activation certificate control message")
		}
		if _, err := message.ActivationCertificate.CanonicalDigest(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown TMLDSA reshare control kind")
	}
	if message.Kind != tmldsaReshareControlTermCommitment &&
		message.Kind != tmldsaReshareControlTermReveal &&
		message.TermSenderID != 0 {
		return fmt.Errorf("unexpected TMLDSA logical term sender")
	}
	if message.Kind != tmldsaReshareControlAbortEvidence && message.AbortEvidence != nil {
		return fmt.Errorf("unexpected signed TMLDSA abort evidence")
	}
	if message.Kind != tmldsaReshareControlActivationAck && message.ActivationAck != nil {
		return fmt.Errorf("unexpected TMLDSA activation acknowledgement")
	}
	if message.Kind != tmldsaReshareControlActivationCert && message.ActivationCertificate != nil {
		return fmt.Errorf("unexpected TMLDSA activation certificate")
	}
	return nil
}

func containsTMLDSAParticipant(participants []uint32, participantID uint32) bool {
	for _, candidateID := range participants {
		if candidateID == participantID {
			return true
		}
	}
	return false
}

func (message tmldsaReshareControlMessage) validTermSender() bool {
	if message.TermSenderID == message.SenderID {
		return true
	}
	return message.SenderID == message.DealerID &&
		message.TermSenderID == protocolmldsa65.ReshareDealerWitnessID(message.DealerID)
}

func (n *Node) applyTMLDSAReshareControlMessage(message tmldsaReshareControlMessage) error {
	if !experimentalTMLDSAV1Enabled() {
		return fmt.Errorf("experimental TMLDSA v1 is disabled")
	}
	if err := message.validate(); err != nil {
		return err
	}
	if message.Kind == tmldsaReshareControlContributionSet {
		commitments := make(map[uint32][32]byte, len(message.ContributionHeads))
		for _, entry := range message.ContributionHeads {
			commitments[entry.RecipientID] = entry.Commitment
		}
		coordinator, err := protocolmldsa65.NewReshareConsistencyCoordinator(
			message.SessionID,
			message.Key,
			message.OldCommittee,
			message.NewCommittee,
			message.SelectedDealers,
			message.DealerID,
			commitments,
		)
		if err != nil {
			return err
		}
		if existing, found, err := n.loadTMLDSAReshareConsistencyState(message.SessionID, message.DealerID); err != nil {
			return err
		} else if found {
			if existing.ContributionSetDigest() != coordinator.ContributionSetDigest() {
				return protocolmldsa65.ErrReshareEquivocation
			}
			return nil
		}
		return n.persistTMLDSAReshareConsistencyState(coordinator)
	}
	if message.Kind == tmldsaReshareControlAbortEvidence {
		return n.persistTMLDSAReshareAbortEvidence(
			*message.AbortEvidence,
			n.verifyTMLDSAReshareIdentity,
		)
	}
	if message.Kind == tmldsaReshareControlActivationAck {
		_, err := n.persistTMLDSAReshareActivationAcknowledgement(
			*message.ActivationAck,
			n.verifyTMLDSAReshareIdentity,
		)
		return err
	}
	if message.Kind == tmldsaReshareControlActivationCert {
		return n.persistTMLDSAReshareActivationCertificate(
			*message.ActivationCertificate,
			n.verifyTMLDSAReshareIdentity,
		)
	}

	current, found, err := n.loadTMLDSAReshareConsistencyState(message.SessionID, message.DealerID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("TMLDSA reshare control state is not initialized")
	}
	encoded, err := current.MarshalBinary()
	if err != nil {
		return err
	}
	updated, err := protocolmldsa65.UnmarshalReshareConsistencyCoordinator(encoded)
	if err != nil {
		return err
	}
	beforeCount := updated.EventCount()
	beforeDigest := updated.TranscriptDigest()
	applyErr := applyTMLDSAReshareControlTransition(updated, message)
	if updated.EventCount() != beforeCount || updated.TranscriptDigest() != beforeDigest {
		if err := n.persistTMLDSAReshareConsistencyState(updated); err != nil {
			return err
		}
	}
	return applyErr
}

func applyTMLDSAReshareControlTransition(
	coordinator *protocolmldsa65.ReshareConsistencyCoordinator,
	message tmldsaReshareControlMessage,
) error {
	if coordinator == nil {
		return fmt.Errorf("TMLDSA reshare control state is nil")
	}
	switch message.Kind {
	case tmldsaReshareControlAgreement:
		return coordinator.RecordContributionAgreement(message.SenderID, message.Value)
	case tmldsaReshareControlNonceCommitment:
		return coordinator.RecordNonceCommitment(message.SenderID, message.Value)
	case tmldsaReshareControlNonceReveal:
		return coordinator.RecordNonceReveal(message.SenderID, message.Value)
	case tmldsaReshareControlTermCommitment:
		return coordinator.RecordMaskedTermCommitment(message.TermSenderID, message.Value)
	case tmldsaReshareControlTermReveal:
		return coordinator.RecordMaskedTermReveal(protocolmldsa65.ReshareMaskedTermReveal{
			SenderID: message.TermSenderID,
			Term:     message.Term,
			Salt:     message.Salt,
		})
	case tmldsaReshareControlTimeout:
		return coordinator.AbortTimeout(message.Value)
	default:
		return fmt.Errorf("unsupported TMLDSA reshare control transition")
	}
}

func (n *Node) verifyTMLDSAReshareIdentity(participantID uint32, message, signature []byte) bool {
	if n == nil || n.blockProducer == nil || n.blockProducer.qpos == nil || participantID == 0 {
		return false
	}
	validatorSet := n.blockProducer.qpos.GetValidatorSet()
	if validatorSet == nil {
		return false
	}
	validators := validatorSet.Validators()
	if int(participantID) > len(validators) || validators[participantID-1] == nil ||
		!validators[participantID-1].Active {
		return false
	}
	publicKey, err := qcrypto.PublicKeyFromBytes(validators[participantID-1].PublicKeyBytes)
	return err == nil && qcrypto.Verify(publicKey, message, signature)
}

func (n *Node) broadcastTMLDSAReshareControl(message tmldsaReshareControlMessage) error {
	if n == nil || n.p2pHost == nil {
		return fmt.Errorf("TMLDSA reshare control transport is unavailable")
	}
	payload, err := encodeTMLDSAReshareControlMessage(message)
	if err != nil {
		return err
	}
	return n.p2pHost.BroadcastTSS(p2p.MsgTypeTSSDKGReshare, payload)
}

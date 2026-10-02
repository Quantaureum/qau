// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/sha3"
	"fmt"
	"slices"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func encodeTDilithium3DKGActivationEnvelope(
	session dilithium3v1.DKGSession,
	share *dilithium3v1.LocalShare,
	sign func([]byte) ([]byte, error),
) ([]byte, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if share == nil || sign == nil || share.Validate() != nil ||
		share.Key.Generation != session.KeyGeneration || share.ActivationEpoch != session.ActivationEpoch ||
		share.Committee.Version != session.Committee.Version ||
		share.Committee.Threshold != session.Committee.Threshold ||
		!slices.Equal(share.Committee.Participants, session.Committee.Participants) {
		return nil, fmt.Errorf("Dilithium3 DKG activation share and session differ")
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		return nil, err
	}
	encodedShare, err := share.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer tss.SecureZero(encodedShare)
	acknowledgement := dilithium3v1.DKGActivationAcknowledgement{
		SessionDigest:    sessionDigest,
		ActivationEpoch:  session.ActivationEpoch,
		Key:              share.Key.Clone(),
		Committee:        session.Committee.Clone(),
		TranscriptDigest: share.TranscriptDigest,
		ParticipantID:    share.ParticipantID,
		CandidateDigest:  sha3.Sum256(encodedShare),
	}
	message, err := acknowledgement.SigningBytes()
	if err != nil {
		return nil, err
	}
	signature, err := sign(message)
	if err != nil {
		return nil, err
	}
	if len(signature) != protocol.Dilithium3V1Profile().Algorithm.SignatureSize() {
		return nil, fmt.Errorf("invalid Dilithium3 DKG activation identity signature size")
	}
	payload := make([]byte, 0, 64)
	payload = append(payload, acknowledgement.TranscriptDigest[:]...)
	payload = append(payload, acknowledgement.CandidateDigest[:]...)
	return protocol.EncodeEnvelope(protocol.ThresholdEnvelope{
		ProtocolVersion:   protocol.ThresholdProtocolVersionV1,
		Protocol:          session.Protocol,
		Algorithm:         protocol.Dilithium3V1Profile().Algorithm,
		MessageType:       uint16(p2p.MsgTypeTDilithium3DKGActivation),
		KeyGeneration:     session.KeyGeneration,
		CommitteeVersion:  session.Committee.Version,
		SessionID:         sessionDigest,
		SenderID:          share.ParticipantID,
		Sequence:          1,
		Payload:           payload,
		IdentitySignature: signature,
	})
}

func assembleTDilithium3DKGActivationCertificate(
	session dilithium3v1.DKGSession,
	publicKey [1952]byte,
	transcriptDigest [32]byte,
	packets [][]byte,
	verifier dilithium3v1.DKGIdentityVerifier,
) (dilithium3v1.DKGActivationCertificate, error) {
	var empty dilithium3v1.DKGActivationCertificate
	if err := session.Validate(); err != nil {
		return empty, err
	}
	if len(packets) != len(session.Committee.Participants) || transcriptDigest == ([32]byte{}) || verifier == nil {
		return empty, fmt.Errorf("Dilithium3 DKG activation requires a receipt from every committee member")
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		return empty, err
	}
	key := protocolThresholdKey(publicKey, session.KeyGeneration)
	if err := key.Validate(); err != nil {
		return empty, err
	}
	acknowledgements := make([]dilithium3v1.DKGActivationAcknowledgement, len(packets))
	seen := make([]bool, len(packets))
	for _, packet := range packets {
		envelope, err := validateTDilithium3DKGStructure(p2p.MsgTypeTDilithium3DKGActivation, packet, session, nil)
		if err != nil {
			return empty, err
		}
		position, ok := tdilithium3DKGCommitteePosition(session.Committee, envelope.SenderID)
		if !ok || seen[position] || len(envelope.IdentitySignature) != key.Algorithm.SignatureSize() {
			return empty, fmt.Errorf("duplicate or invalid Dilithium3 DKG activation signer")
		}
		var receiptTranscript [32]byte
		var candidateDigest [32]byte
		copy(receiptTranscript[:], envelope.Payload[:32])
		copy(candidateDigest[:], envelope.Payload[32:])
		if receiptTranscript != transcriptDigest {
			return empty, fmt.Errorf("Dilithium3 DKG activation transcript mismatch")
		}
		acknowledgement := dilithium3v1.DKGActivationAcknowledgement{
			SessionDigest:     sessionDigest,
			ActivationEpoch:   session.ActivationEpoch,
			Key:               key.Clone(),
			Committee:         session.Committee.Clone(),
			TranscriptDigest:  receiptTranscript,
			ParticipantID:     envelope.SenderID,
			CandidateDigest:   candidateDigest,
			IdentitySignature: envelope.IdentitySignature,
		}
		if err := acknowledgement.Verify(verifier); err != nil {
			return empty, err
		}
		acknowledgements[position] = acknowledgement
		seen[position] = true
	}
	certificate := dilithium3v1.DKGActivationCertificate{Acknowledgements: acknowledgements}
	if err := certificate.Verify(verifier); err != nil {
		return empty, err
	}
	return certificate, nil
}

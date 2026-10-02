// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func encodeTDilithium3DKGSignedEnvelope(
	session dilithium3v1.DKGSession,
	messageType uint8,
	senderPosition uint8,
	sequence uint32,
	payload []byte,
	sign func([]byte) ([]byte, error),
) ([]byte, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if messageType == p2p.MsgTypeTDilithium3DKGActivation || senderPosition >= uint8(len(session.Committee.Participants)) || sequence == 0 || sign == nil {
		return nil, fmt.Errorf("invalid Dilithium3 DKG outbound context")
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		return nil, err
	}
	envelope := protocol.ThresholdEnvelope{
		ProtocolVersion:   protocol.ThresholdProtocolVersionV1,
		Protocol:          session.Protocol,
		Algorithm:         protocol.Dilithium3V1Profile().Algorithm,
		MessageType:       uint16(messageType),
		KeyGeneration:     session.KeyGeneration,
		CommitteeVersion:  session.Committee.Version,
		SessionID:         sessionDigest,
		SenderID:          session.Committee.Participants[senderPosition],
		Sequence:          sequence,
		Payload:           append([]byte(nil), payload...),
		IdentitySignature: make([]byte, protocol.Dilithium3V1Profile().Algorithm.SignatureSize()),
	}
	var recipientPosition *uint8
	if messageType == p2p.MsgTypeTDilithium3DKGGroupSeed {
		seedMessage, err := dilithium3v1.UnmarshalGroupSeedMessage(envelope.Payload)
		if err != nil {
			return nil, err
		}
		recipientPosition = &seedMessage.RecipientPosition
	}
	if messageType == p2p.MsgTypeTDilithium3ReshareDelta {
		deltaMessage, err := dilithium3v1.UnmarshalReshareDeltaWire(envelope.Payload)
		if err != nil {
			return nil, err
		}
		recipientPosition = &deltaMessage.RecipientPosition
	}
	unsigned, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if _, err := validateTDilithium3DKGStructure(messageType, unsigned, session, recipientPosition); err != nil {
		return nil, err
	}
	signingBytes, err := envelope.IdentitySigningBytes()
	if err != nil {
		return nil, err
	}
	signature, err := sign(signingBytes)
	if err != nil {
		return nil, err
	}
	if len(signature) != protocol.Dilithium3V1Profile().Algorithm.SignatureSize() {
		return nil, fmt.Errorf("invalid Dilithium3 DKG outbound identity signature size")
	}
	envelope.IdentitySignature = signature
	return protocol.EncodeEnvelope(envelope)
}

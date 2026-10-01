// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	qcrypto "github.com/quantaureum/qau/crypto"
)

const (
	ThresholdProtocolVersionV1      uint16 = 1
	MaxThresholdEnvelopePayload            = 1 << 20
	MaxThresholdIdentitySignature          = 16 << 10
	thresholdEnvelopeMagic                 = "QTM1"
	thresholdEnvelopeIdentityDomain        = "QAU-THRESHOLD-ENVELOPE-IDENTITY-V1"
	thresholdEnvelopeFixedSize             = 76
)

var ErrInvalidThresholdEnvelope = errors.New("invalid threshold envelope")

// ThresholdEnvelope is the authenticated versioned transport container used by
// threshold signing, DKG, and reshare messages.
type ThresholdEnvelope struct {
	ProtocolVersion   uint16
	Protocol          ThresholdProtocol
	Algorithm         qcrypto.SignatureAlgorithm
	MessageType       uint16
	KeyGeneration     uint64
	CommitteeVersion  uint64
	SessionID         [32]byte
	SenderID          uint32
	Sequence          uint32
	Payload           []byte
	IdentitySignature []byte
}

func (envelope ThresholdEnvelope) IdentitySigningBytes() ([]byte, error) {
	unsigned := envelope
	unsigned.IdentitySignature = []byte{1}
	encoded, err := EncodeEnvelope(unsigned)
	if err != nil {
		return nil, err
	}
	signedLength := len(encoded) - 4 - len(unsigned.IdentitySignature)
	signed := make([]byte, 0, len(thresholdEnvelopeIdentityDomain)+signedLength)
	signed = append(signed, thresholdEnvelopeIdentityDomain...)
	return append(signed, encoded[:signedLength]...), nil
}

func (envelope ThresholdEnvelope) Validate() error {
	if envelope.ProtocolVersion != ThresholdProtocolVersionV1 {
		return fmt.Errorf("%w: unsupported protocol version", ErrInvalidThresholdEnvelope)
	}
	if err := envelope.Protocol.ValidateAlgorithm(envelope.Algorithm); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidThresholdEnvelope, err)
	}
	if envelope.MessageType == 0 {
		return fmt.Errorf("%w: zero message type", ErrInvalidThresholdEnvelope)
	}
	if envelope.KeyGeneration == 0 {
		return fmt.Errorf("%w: zero key generation", ErrInvalidThresholdEnvelope)
	}
	if envelope.CommitteeVersion == 0 {
		return fmt.Errorf("%w: zero committee version", ErrInvalidThresholdEnvelope)
	}
	var zeroSession [32]byte
	if subtle.ConstantTimeCompare(envelope.SessionID[:], zeroSession[:]) == 1 {
		return fmt.Errorf("%w: zero session ID", ErrInvalidThresholdEnvelope)
	}
	if envelope.SenderID == 0 {
		return fmt.Errorf("%w: zero sender ID", ErrInvalidThresholdEnvelope)
	}
	if envelope.Sequence == 0 {
		return fmt.Errorf("%w: zero sequence", ErrInvalidThresholdEnvelope)
	}
	if len(envelope.Payload) > MaxThresholdEnvelopePayload {
		return fmt.Errorf("%w: payload exceeds limit", ErrInvalidThresholdEnvelope)
	}
	if len(envelope.IdentitySignature) == 0 || len(envelope.IdentitySignature) > MaxThresholdIdentitySignature {
		return fmt.Errorf("%w: identity signature length", ErrInvalidThresholdEnvelope)
	}
	return nil
}

// EncodeEnvelope returns the unique canonical binary encoding of an envelope.
func EncodeEnvelope(envelope ThresholdEnvelope) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, thresholdEnvelopeFixedSize+len(envelope.Payload)+len(envelope.IdentitySignature))
	encoded = append(encoded, []byte(thresholdEnvelopeMagic)...)
	encoded = binary.BigEndian.AppendUint16(encoded, envelope.ProtocolVersion)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(envelope.Protocol))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(envelope.Algorithm))
	encoded = binary.BigEndian.AppendUint16(encoded, envelope.MessageType)
	encoded = binary.BigEndian.AppendUint64(encoded, envelope.KeyGeneration)
	encoded = binary.BigEndian.AppendUint64(encoded, envelope.CommitteeVersion)
	encoded = append(encoded, envelope.SessionID[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, envelope.SenderID)
	encoded = binary.BigEndian.AppendUint32(encoded, envelope.Sequence)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(envelope.Payload)))
	encoded = append(encoded, envelope.Payload...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(envelope.IdentitySignature)))
	encoded = append(encoded, envelope.IdentitySignature...)
	return encoded, nil
}

// DecodeEnvelope decodes one canonical envelope without allocating unbounded
// attacker-controlled field lengths.
func DecodeEnvelope(encoded []byte) (ThresholdEnvelope, error) {
	if len(encoded) < thresholdEnvelopeFixedSize {
		return ThresholdEnvelope{}, fmt.Errorf("%w: truncated header", ErrInvalidThresholdEnvelope)
	}
	if !bytes.Equal(encoded[:4], []byte(thresholdEnvelopeMagic)) {
		return ThresholdEnvelope{}, fmt.Errorf("%w: magic mismatch", ErrInvalidThresholdEnvelope)
	}
	offset := 4
	envelope := ThresholdEnvelope{}
	envelope.ProtocolVersion = binary.BigEndian.Uint16(encoded[offset : offset+2])
	offset += 2
	envelope.Protocol = ThresholdProtocol(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	envelope.Algorithm = qcrypto.SignatureAlgorithm(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	envelope.MessageType = binary.BigEndian.Uint16(encoded[offset : offset+2])
	offset += 2
	envelope.KeyGeneration = binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	envelope.CommitteeVersion = binary.BigEndian.Uint64(encoded[offset : offset+8])
	offset += 8
	copy(envelope.SessionID[:], encoded[offset:offset+32])
	offset += 32
	envelope.SenderID = binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	envelope.Sequence = binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	payloadLength := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if payloadLength > MaxThresholdEnvelopePayload || payloadLength > len(encoded)-offset-4 {
		return ThresholdEnvelope{}, fmt.Errorf("%w: payload length", ErrInvalidThresholdEnvelope)
	}
	envelope.Payload = append([]byte(nil), encoded[offset:offset+payloadLength]...)
	offset += payloadLength
	if len(encoded)-offset < 4 {
		return ThresholdEnvelope{}, fmt.Errorf("%w: missing identity signature length", ErrInvalidThresholdEnvelope)
	}
	signatureLength := int(binary.BigEndian.Uint32(encoded[offset : offset+4]))
	offset += 4
	if signatureLength == 0 || signatureLength > MaxThresholdIdentitySignature || signatureLength != len(encoded)-offset {
		return ThresholdEnvelope{}, fmt.Errorf("%w: identity signature length", ErrInvalidThresholdEnvelope)
	}
	envelope.IdentitySignature = append([]byte(nil), encoded[offset:]...)
	if err := envelope.Validate(); err != nil {
		return ThresholdEnvelope{}, err
	}
	return envelope, nil
}

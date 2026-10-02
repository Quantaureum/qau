// Quantaureum Node source, version 1.0.0.
package node

// Node-side wire layer of the Dilithium3 v1 signing executor (design note,
// Slice 4). The four public round messages travel inside the shared threshold
// envelope on the p2p kinds 97..100 reserved by R64; this file owns the
// outbound signing and the inbound structural verification of those envelopes,
// and it never decides whether a slot is accepted: acceptance, rejection, and
// burn are the executor's own concern, and the envelope layer carries no key
// material beyond the caller-supplied signing callback.
//
// The wire binding is the one the p2p validator pins: protocol, algorithm,
// message type, key generation, committee version, session, sender, sequence,
// and the canonical round payload. The slot index lives inside the payload, so
// an envelope cannot disagree with its own encoding.

import (
	"fmt"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// tdilithium3SigningContext is the immutable binding of one signing execution
// as the network sees it: the signing session identifier, the key generation
// and committee version every envelope must match, and the four active signer
// identities in canonical ascending order.
type tdilithium3SigningContext struct {
	SessionID        [32]byte
	KeyGeneration    uint64
	CommitteeVersion uint64
	Signers          []uint32
}

// tdilithium3SigningIdentityVerifier verifies one sender's identity signature
// over the envelope signing bytes. It is the node layer's validator-key lookup;
// the envelope layer itself never sees a key.
type tdilithium3SigningIdentityVerifier func(senderID uint32, signingBytes, signature []byte) bool

// Validate rejects a context that does not describe exactly four strictly
// ascending, non-zero signer identities bound to a non-zero session,
// generation, and committee.
func (context tdilithium3SigningContext) Validate() error {
	if context.SessionID == ([32]byte{}) {
		return fmt.Errorf("Dilithium3 v1 signing context has a zero session")
	}
	if context.KeyGeneration == 0 {
		return fmt.Errorf("Dilithium3 v1 signing context has a zero key generation")
	}
	if context.CommitteeVersion == 0 {
		return fmt.Errorf("Dilithium3 v1 signing context has a zero committee version")
	}
	for index, signer := range context.Signers {
		if signer == 0 {
			return fmt.Errorf("Dilithium3 v1 signing context has a zero signer at position %d", index)
		}
		if index > 0 && context.Signers[index-1] >= signer {
			return fmt.Errorf("Dilithium3 v1 signing context signers are not strictly ascending")
		}
	}
	return nil
}

// activeSigner reports whether the identity is one of the four signers.
func (context tdilithium3SigningContext) activeSigner(senderID uint32) bool {
	for _, signer := range context.Signers {
		if signer == senderID {
			return true
		}
	}
	return false
}

// encodeTDilithium3SigningEnvelope builds, structurally validates, and signs
// one outbound round message of the executor.
func encodeTDilithium3SigningEnvelope(
	context tdilithium3SigningContext,
	messageType uint8,
	senderID uint32,
	sequence uint32,
	payload []byte,
	sign func([]byte) ([]byte, error),
) ([]byte, error) {
	if err := context.Validate(); err != nil {
		return nil, err
	}
	if !context.activeSigner(senderID) {
		return nil, fmt.Errorf("Dilithium3 v1 signing sender %d is not an active signer", senderID)
	}
	if sequence == 0 || sign == nil {
		return nil, fmt.Errorf("invalid Dilithium3 v1 signing outbound context")
	}
	envelope := protocol.ThresholdEnvelope{
		ProtocolVersion:   protocol.ThresholdProtocolVersionV1,
		Protocol:          protocol.ThresholdProtocolDilithium3V1,
		Algorithm:         protocol.Dilithium3V1Profile().Algorithm,
		MessageType:       uint16(messageType),
		KeyGeneration:     context.KeyGeneration,
		CommitteeVersion:  context.CommitteeVersion,
		SessionID:         context.SessionID,
		SenderID:          senderID,
		Sequence:          sequence,
		Payload:           append([]byte(nil), payload...),
		IdentitySignature: make([]byte, protocol.Dilithium3V1Profile().Algorithm.SignatureSize()),
	}
	unsigned, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if _, err := validateTDilithium3SigningStructure(messageType, unsigned, context); err != nil {
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
		return nil, fmt.Errorf("invalid Dilithium3 v1 signing identity signature size")
	}
	envelope.IdentitySignature = signature
	return protocol.EncodeEnvelope(envelope)
}

// validateTDilithium3SigningInbound verifies one inbound round message against
// the context and the sender's identity key, and returns its canonical payload.
// The identity signature is checked before the payload is handed to the
// executor, so no unauthorized sender reaches a slot.
func validateTDilithium3SigningInbound(
	messageType uint8,
	encoded []byte,
	context tdilithium3SigningContext,
	verifier tdilithium3SigningIdentityVerifier,
) ([]byte, error) {
	envelope, err := verifyTDilithium3SigningInbound(messageType, encoded, context, verifier)
	if err != nil {
		return nil, err
	}
	return envelope.Payload, nil
}

// tdilithium3SigningEnvelopeSession peeks the session id of one inbound signing
// envelope without verifying it, so the router can hand the message to the
// matching session's inbox. The inbox still runs the full authentication; this
// only chooses which inbox. A malformed envelope returns ok=false and is
// dropped by the caller.
func tdilithium3SigningEnvelopeSession(encoded []byte) ([32]byte, bool) {
	envelope, err := protocol.DecodeEnvelope(encoded)
	if err != nil {
		return [32]byte{}, false
	}
	return envelope.SessionID, true
}

// verifyTDilithium3SigningInbound is the envelope-returning form of the inbound
// check: the caller that also needs the sender and the sequence (the executor
// inbox) reads them from the envelope it verified, never from a second decode.
func verifyTDilithium3SigningInbound(
	messageType uint8,
	encoded []byte,
	context tdilithium3SigningContext,
	verifier tdilithium3SigningIdentityVerifier,
) (protocol.ThresholdEnvelope, error) {
	if verifier == nil {
		return protocol.ThresholdEnvelope{}, fmt.Errorf("Dilithium3 v1 signing inbound requires an identity verifier")
	}
	envelope, err := validateTDilithium3SigningStructure(messageType, encoded, context)
	if err != nil {
		return protocol.ThresholdEnvelope{}, err
	}
	signingBytes, err := envelope.IdentitySigningBytes()
	if err != nil || !verifier(envelope.SenderID, signingBytes, envelope.IdentitySignature) {
		return protocol.ThresholdEnvelope{}, fmt.Errorf("Dilithium3 v1 signing sender identity verification failed")
	}
	return envelope, nil
}

// validateTDilithium3SigningStructure checks one envelope against the p2p
// validator and the signing context, without touching the identity signature.
func validateTDilithium3SigningStructure(
	messageType uint8,
	encoded []byte,
	context tdilithium3SigningContext,
) (protocol.ThresholdEnvelope, error) {
	if err := context.Validate(); err != nil {
		return protocol.ThresholdEnvelope{}, err
	}
	if err := p2p.ValidateTDilithium3SigningEnvelope(messageType, encoded); err != nil {
		return protocol.ThresholdEnvelope{}, err
	}
	envelope, err := protocol.DecodeEnvelope(encoded)
	if err != nil {
		return protocol.ThresholdEnvelope{}, err
	}
	if envelope.SessionID != context.SessionID || envelope.KeyGeneration != context.KeyGeneration ||
		envelope.CommitteeVersion != context.CommitteeVersion {
		return protocol.ThresholdEnvelope{}, fmt.Errorf("Dilithium3 v1 signing envelope belongs to another session")
	}
	if !context.activeSigner(envelope.SenderID) {
		return protocol.ThresholdEnvelope{}, fmt.Errorf("Dilithium3 v1 signing sender is not an active signer")
	}
	return envelope, nil
}

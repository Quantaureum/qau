// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"crypto/sha3"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGMessageKindsValidateAndRoute(t *testing.T) {
	host := &Host{protocolRegistry: NewProtocolRegistry(), tssCh: make(chan PeerMessage, 6)}
	host.registerProtocols()
	for _, messageType := range []uint8{
		MsgTypeTDilithium3DKGRandomnessCommitment,
		MsgTypeTDilithium3DKGRandomness,
		MsgTypeTDilithium3DKGGroupSeed,
		MsgTypeTDilithium3DKGAcknowledgement,
		MsgTypeTDilithium3DKGComplaint,
		MsgTypeTDilithium3DKGContribution,
		MsgTypeTDilithium3DKGActivation,
	} {
		payload := testTDilithium3Envelope(t, messageType, testTDilithium3Payload(t, messageType))
		message := &Message{Type: messageType, From: PeerID("validator-101"), Payload: payload}
		if err := ValidateMessage(message); err != nil {
			t.Fatalf("message type %d rejected: %v", messageType, err)
		}
		if err := host.protocolRegistry.RouteMessage(message); err != nil {
			t.Fatalf("message type %d has no TSS route: %v", messageType, err)
		}
	}
}

func TestTDilithium3DKGMessageValidatorRejectsWrongProtocolAndMalformedPrivateSeed(t *testing.T) {
	validSeed := testTDilithium3Payload(t, MsgTypeTDilithium3DKGGroupSeed)
	envelope := protocol.ThresholdEnvelope{
		ProtocolVersion:   protocol.ThresholdProtocolVersionV1,
		Protocol:          protocol.ThresholdProtocolMLDSA65ExperimentalV1,
		Algorithm:         qcrypto.SignatureAlgorithmMLDSA65,
		MessageType:       uint16(MsgTypeTDilithium3DKGGroupSeed),
		KeyGeneration:     1,
		CommitteeVersion:  1,
		SessionID:         [32]byte{1},
		SenderID:          101,
		Sequence:          1,
		Payload:           validSeed,
		IdentitySignature: []byte{1},
	}
	encoded, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTDilithium3DKGEnvelope(MsgTypeTDilithium3DKGGroupSeed, encoded); err == nil {
		t.Fatal("wrong threshold protocol accepted")
	}

	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	badSeed := dilithium3v1.GroupSeedMessage{
		SessionDigest: [32]byte{1}, CommitteeDigest: [32]byte{2}, GroupMask: group,
		LeaderPosition: leader, RecipientPosition: leader, Attempt: 0, Seed: [32]byte{3},
	}
	badEnvelope := testTDilithium3Envelope(t, MsgTypeTDilithium3DKGGroupSeed, marshalUncheckedTDilithium3Seed(badSeed))
	if err := ValidateTDilithium3DKGEnvelope(MsgTypeTDilithium3DKGGroupSeed, badEnvelope); err == nil {
		t.Fatal("private group seed addressed to its leader accepted")
	}
}

func TestTDilithium3DKGMessageValidatorBoundsPayloads(t *testing.T) {
	for _, size := range []int{0, protocol.MaxThresholdEnvelopePayload + 1} {
		if err := ValidateTDilithium3DKGEnvelope(MsgTypeTDilithium3DKGRandomness, make([]byte, size)); err == nil {
			t.Fatalf("invalid envelope size %d accepted", size)
		}
	}
}

func TestTDilithium3DKGRandomnessMessagesRequireCanonicalSequence(t *testing.T) {
	for _, messageType := range []uint8{MsgTypeTDilithium3DKGRandomnessCommitment, MsgTypeTDilithium3DKGRandomness} {
		encoded := testTDilithium3Envelope(t, messageType, testTDilithium3Payload(t, messageType))
		if err := ValidateTDilithium3DKGEnvelope(messageType, encoded); err != nil {
			t.Fatal(err)
		}
		envelope, err := protocol.DecodeEnvelope(encoded)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Sequence = 2
		encoded, err = protocol.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateTDilithium3DKGEnvelope(messageType, encoded); err == nil {
			t.Fatalf("alternate randomness sequence accepted for %d", messageType)
		}
	}
}

func TestTDilithium3DKGActivationRejectsShortIdentitySignature(t *testing.T) {
	encoded := testTDilithium3Envelope(t, MsgTypeTDilithium3DKGActivation, testTDilithium3Payload(t, MsgTypeTDilithium3DKGActivation))
	envelope, err := protocol.DecodeEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	envelope.IdentitySignature = []byte{1}
	short, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTDilithium3DKGEnvelope(MsgTypeTDilithium3DKGActivation, short); err == nil {
		t.Fatal("short activation identity signature accepted")
	}
}

func TestTDilithium3DKGContributionRejectsShortIdentitySignature(t *testing.T) {
	encoded := testTDilithium3Envelope(t, MsgTypeTDilithium3DKGContribution, testTDilithium3Payload(t, MsgTypeTDilithium3DKGContribution))
	envelope, err := protocol.DecodeEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	envelope.IdentitySignature = []byte{1}
	short, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTDilithium3DKGEnvelope(MsgTypeTDilithium3DKGContribution, short); err == nil {
		t.Fatal("short DKG identity signature accepted")
	}
}

func testTDilithium3Envelope(t *testing.T, messageType uint8, payload []byte) []byte {
	t.Helper()
	identitySignature := make([]byte, protocol.Dilithium3V1Profile().Algorithm.SignatureSize())
	identitySignature[0] = 1
	envelope := protocol.ThresholdEnvelope{
		ProtocolVersion:   protocol.ThresholdProtocolVersionV1,
		Protocol:          protocol.ThresholdProtocolDilithium3V1,
		Algorithm:         qcrypto.SignatureAlgorithmDilithium3Legacy,
		MessageType:       uint16(messageType),
		KeyGeneration:     1,
		CommitteeVersion:  1,
		SessionID:         [32]byte{1},
		SenderID:          101,
		Sequence:          1,
		Payload:           payload,
		IdentitySignature: identitySignature,
	}
	encoded, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testTDilithium3Payload(t *testing.T, messageType uint8) []byte {
	t.Helper()
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	switch messageType {
	case MsgTypeTDilithium3DKGRandomnessCommitment:
		return append([]byte{1}, make([]byte, 31)...)
	case MsgTypeTDilithium3DKGRandomness:
		return append([]byte{1}, make([]byte, 31)...)
	case MsgTypeTDilithium3DKGGroupSeed:
		message := dilithium3v1.GroupSeedMessage{SessionDigest: [32]byte{1}, CommitteeDigest: [32]byte{2}, GroupMask: group, LeaderPosition: leader, RecipientPosition: 1, Seed: [32]byte{3}}
		encoded, err := message.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	case MsgTypeTDilithium3DKGAcknowledgement:
		message := dilithium3v1.GroupSeedMessage{SessionDigest: [32]byte{1}, CommitteeDigest: [32]byte{2}, GroupMask: group, LeaderPosition: leader, RecipientPosition: 1, Seed: [32]byte{3}}
		seedCommitment, _ := message.SeedCommitmentDigest()
		seedMessage, _ := message.Digest()
		ack := dilithium3v1.ContributionAcknowledgement{SessionDigest: [32]byte{1}, CommitteeDigest: [32]byte{2}, GroupMask: group, LeaderPosition: leader, ParticipantPosition: 1, SeedCommitmentDigest: seedCommitment, SeedMessageDigest: seedMessage, ContributionDigest: [32]byte{4}}
		encoded, err := ack.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	case MsgTypeTDilithium3DKGComplaint:
		complaint := dilithium3v1.Complaint{
			SessionDigest: [32]byte{1}, CommitteeDigest: [32]byte{2}, GroupMask: group,
			LeaderPosition: leader, ComplainantPosition: 1, Reason: dilithium3v1.ComplaintReasonMissingSeed,
			Evidence: dilithium3v1.ComplaintEvidence{SessionDigest: [32]byte{1}, CommitteeDigest: [32]byte{2}, GroupMask: group, LeaderPosition: leader, MessageDigest: [32]byte{5}},
		}
		encoded, err := complaint.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	case MsgTypeTDilithium3DKGContribution:
		contribution := dilithium3v1.PublicContribution{SessionDigest: [32]byte{1}, GroupMask: group, DealerPosition: leader}
		encoded, err := contribution.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	case MsgTypeTDilithium3DKGActivation:
		return append(append([]byte{1}, make([]byte, 31)...), append([]byte{2}, make([]byte, 31)...)...)
	default:
		t.Fatalf("unknown test message type %d", messageType)
		return nil
	}
}

func marshalUncheckedTDilithium3Seed(message dilithium3v1.GroupSeedMessage) []byte {
	valid := message
	valid.RecipientPosition = 1
	encoded, _ := valid.MarshalBinary()
	// Wire layout: magic(8) + version(2) + sessionDigest(32) +
	// committeeDigest(32) + groupMask(2) + leader(1) + recipient(1) + ...
	// The RECIPIENT field sits at offset 77 (76 is the leader field).
	encoded[77] = message.RecipientPosition
	digest := sha3.Sum256(encoded[:len(encoded)-32])
	copy(encoded[len(encoded)-32:], digest[:])
	return encoded
}

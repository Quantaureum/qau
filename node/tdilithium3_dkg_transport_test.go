// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGInboundBindsSenderLeaderAndRecipient(t *testing.T) {
	session := testTDilithium3DKGSession()
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	message := dilithium3v1.GroupSeedMessage{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
		LeaderPosition: leader, RecipientPosition: 1, Seed: [32]byte{3},
	}
	payload, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	encoded := testTDilithium3DKGNodeEnvelope(t, session, p2p.MsgTypeTDilithium3DKGGroupSeed, session.Committee.Participants[leader], payload)
	recipient := uint8(1)
	if _, err := validateTDilithium3DKGStructure(p2p.MsgTypeTDilithium3DKGGroupSeed, encoded, session, &recipient); err != nil {
		t.Fatal(err)
	}

	wrongSender := testTDilithium3DKGNodeEnvelope(t, session, p2p.MsgTypeTDilithium3DKGGroupSeed, session.Committee.Participants[2], payload)
	if _, err := validateTDilithium3DKGStructure(p2p.MsgTypeTDilithium3DKGGroupSeed, wrongSender, session, &recipient); err == nil {
		t.Fatal("group seed from a non-leader sender accepted")
	}
	wrongRecipient := uint8(2)
	if _, err := validateTDilithium3DKGStructure(p2p.MsgTypeTDilithium3DKGGroupSeed, encoded, session, &wrongRecipient); err == nil {
		t.Fatal("private group seed for another recipient accepted")
	}
	if _, err := validateTDilithium3DKGStructure(p2p.MsgTypeTDilithium3DKGGroupSeed, encoded, session, nil); err == nil {
		t.Fatal("private group seed accepted without point-to-point recipient context")
	}
}

func TestTDilithium3DKGInboundRequiresVerifiedIdentity(t *testing.T) {
	session := testTDilithium3DKGSession()
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	message := dilithium3v1.GroupSeedMessage{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
		LeaderPosition: leader, RecipientPosition: 1, Seed: [32]byte{3},
	}
	payload, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	encoded := testTDilithium3DKGNodeEnvelope(t, session, p2p.MsgTypeTDilithium3DKGGroupSeed, session.Committee.Participants[leader], payload)
	position := uint8(1)
	var seed [mode3.SeedSize]byte
	copy(seed[:], []byte("DEVNET ONLY identity fixture 1"))
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	verifier := dilithium3v1.DKGIdentityVerifier(func(participantID uint32, message, signature []byte) bool {
		return participantID == session.Committee.Participants[leader] && mode3.Verify(publicKey, message, signature)
	})
	if _, err := validateTDilithium3DKGInbound(p2p.MsgTypeTDilithium3DKGGroupSeed, encoded, session, &position, verifier); err == nil {
		t.Fatal("unsigned group seed accepted")
	}
	envelope, err := protocol.DecodeEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	signingBytes, err := envelope.IdentitySigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	envelope.IdentitySignature = make([]byte, mode3.SignatureSize)
	mode3.SignTo(privateKey, signingBytes, envelope.IdentitySignature)
	encoded, err = protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTDilithium3DKGInbound(p2p.MsgTypeTDilithium3DKGGroupSeed, encoded, session, &position, verifier); err != nil {
		t.Fatal(err)
	}
	otherChain := session.Clone()
	otherChain.ChainID++
	if _, err := validateTDilithium3DKGInbound(p2p.MsgTypeTDilithium3DKGGroupSeed, encoded, otherChain, &position, verifier); err == nil {
		t.Fatal("cross-chain DKG message accepted")
	}
	if _, err := validateTDilithium3DKGInbound(p2p.MsgTypeTDilithium3DKGGroupSeed, encoded, session, &position, nil); err == nil {
		t.Fatal("missing verifier accepted")
	}
	envelope.Sequence++
	tampered, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTDilithium3DKGInbound(p2p.MsgTypeTDilithium3DKGGroupSeed, tampered, session, &position, verifier); err == nil {
		t.Fatal("tampered sequence accepted")
	}
	envelope.Sequence--
	envelope.IdentitySignature[0] ^= 1
	tampered, err = protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateTDilithium3DKGInbound(p2p.MsgTypeTDilithium3DKGGroupSeed, tampered, session, &position, verifier); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestTDilithium3DKGSignedOutboundMatchesInbound(t *testing.T) {
	session := testTDilithium3DKGSession()
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	message := dilithium3v1.GroupSeedMessage{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
		LeaderPosition: leader, RecipientPosition: 1, Seed: [32]byte{3},
	}
	payload, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var seed [mode3.SeedSize]byte
	copy(seed[:], []byte("DEVNET ONLY identity fixture 2"))
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	sign := func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(privateKey, message, signature)
		return signature, nil
	}
	packet, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, leader, 1, payload, sign)
	if err != nil {
		t.Fatal(err)
	}
	verifier := dilithium3v1.DKGIdentityVerifier(func(participantID uint32, message, signature []byte) bool {
		return participantID == session.Committee.Participants[leader] && mode3.Verify(publicKey, message, signature)
	})
	recipient := uint8(1)
	if _, err := validateTDilithium3DKGInbound(p2p.MsgTypeTDilithium3DKGGroupSeed, packet, session, &recipient, verifier); err != nil {
		t.Fatal(err)
	}
	if _, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, leader, 1, payload, nil); err == nil {
		t.Fatal("unsigned outbound accepted")
	}
	if _, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, 2, 1, payload, sign); err == nil {
		t.Fatal("non-leader signed private seed")
	}
	if _, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGActivation, leader, 1, payload, sign); err == nil {
		t.Fatal("activation used wrong signing domain")
	}
	if _, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, leader, 0, payload, sign); err == nil {
		t.Fatal("zero sequence accepted")
	}
}

func TestTDilithium3DKGSignedPublicMessageKinds(t *testing.T) {
	session := testTDilithium3DKGSession()
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	seedMessage := dilithium3v1.GroupSeedMessage{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
		LeaderPosition: leader, RecipientPosition: 1, Seed: [32]byte{3},
	}
	seedCommitment, err := seedMessage.SeedCommitmentDigest()
	if err != nil {
		t.Fatal(err)
	}
	seedDigest, err := seedMessage.Digest()
	if err != nil {
		t.Fatal(err)
	}
	acknowledgement := dilithium3v1.ContributionAcknowledgement{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
		LeaderPosition: leader, ParticipantPosition: 1, SeedCommitmentDigest: seedCommitment,
		SeedMessageDigest: seedDigest, ContributionDigest: [32]byte{4},
	}
	ackPayload, err := acknowledgement.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	complaint := dilithium3v1.Complaint{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
		LeaderPosition: leader, ComplainantPosition: 1, Reason: dilithium3v1.ComplaintReasonMissingSeed,
		Evidence: dilithium3v1.ComplaintEvidence{
			SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
			LeaderPosition: leader, MessageDigest: [32]byte{5},
		},
	}
	complaintPayload, err := complaint.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	contribution := dilithium3v1.PublicContribution{SessionDigest: sessionDigest, GroupMask: group, DealerPosition: leader}
	contributionPayload, err := contribution.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var seed [mode3.SeedSize]byte
	copy(seed[:], []byte("DEVNET ONLY identity fixture 3"))
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	sign := func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(privateKey, message, signature)
		return signature, nil
	}
	verifier := dilithium3v1.DKGIdentityVerifier(func(participantID uint32, message, signature []byte) bool {
		return mode3.Verify(publicKey, message, signature)
	})
	for _, test := range []struct {
		name     string
		kind     uint8
		position uint8
		payload  []byte
	}{
		{"randomness commitment", p2p.MsgTypeTDilithium3DKGRandomnessCommitment, 2, append([]byte{1}, make([]byte, 31)...)},
		{"randomness", p2p.MsgTypeTDilithium3DKGRandomness, 2, append([]byte{1}, make([]byte, 31)...)},
		{"acknowledgement", p2p.MsgTypeTDilithium3DKGAcknowledgement, 1, ackPayload},
		{"complaint", p2p.MsgTypeTDilithium3DKGComplaint, 1, complaintPayload},
		{"contribution", p2p.MsgTypeTDilithium3DKGContribution, leader, contributionPayload},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := encodeTDilithium3DKGSignedEnvelope(session, test.kind, test.position, 1, test.payload, sign)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateTDilithium3DKGInbound(test.kind, encoded, session, nil, verifier); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTDilithium3DKGInboundRejectsForeignSessionAndContributionSender(t *testing.T) {
	session := testTDilithium3DKGSession()
	sessionDigest, _ := session.Digest()
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, _ := group.Leader(0)
	contribution := dilithium3v1.PublicContribution{SessionDigest: sessionDigest, GroupMask: group, DealerPosition: leader}
	payload, err := contribution.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	encoded := testTDilithium3DKGNodeEnvelope(t, session, p2p.MsgTypeTDilithium3DKGContribution, session.Committee.Participants[leader], payload)
	if _, err := validateTDilithium3DKGStructure(p2p.MsgTypeTDilithium3DKGContribution, encoded, session, nil); err != nil {
		t.Fatal(err)
	}
	wrongSender := testTDilithium3DKGNodeEnvelope(t, session, p2p.MsgTypeTDilithium3DKGContribution, session.Committee.Participants[3], payload)
	if _, err := validateTDilithium3DKGStructure(p2p.MsgTypeTDilithium3DKGContribution, wrongSender, session, nil); err == nil {
		t.Fatal("public contribution from a non-dealer sender accepted")
	}
	foreign := session.Clone()
	foreign.Nonce[0] ^= 1
	if _, err := validateTDilithium3DKGStructure(p2p.MsgTypeTDilithium3DKGContribution, encoded, foreign, nil); err == nil {
		t.Fatal("foreign DKG session accepted")
	}
}

func testTDilithium3DKGSession() dilithium3v1.DKGSession {
	return dilithium3v1.DKGSession{
		Protocol:             protocol.ThresholdProtocolDilithium3V1,
		ChainID:              1669,
		KeyGeneration:        1,
		Committee:            protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{101, 102, 103, 104, 105, 106}},
		ActivationEpoch:      7,
		Nonce:                [32]byte{1, 2, 3},
		IdentityRosterDigest: [32]byte{1},
	}
}

func testTDilithium3DKGNodeEnvelope(t *testing.T, session dilithium3v1.DKGSession, messageType uint8, senderID uint32, payload []byte) []byte {
	t.Helper()
	sessionDigest, _ := session.Digest()
	envelope := protocol.ThresholdEnvelope{
		ProtocolVersion:   protocol.ThresholdProtocolVersionV1,
		Protocol:          session.Protocol,
		Algorithm:         protocol.Dilithium3V1Profile().Algorithm,
		MessageType:       uint16(messageType),
		KeyGeneration:     session.KeyGeneration,
		CommitteeVersion:  session.Committee.Version,
		SessionID:         sessionDigest,
		SenderID:          senderID,
		Sequence:          1,
		Payload:           payload,
		IdentitySignature: bytes.Repeat([]byte{1}, protocol.Dilithium3V1Profile().Algorithm.SignatureSize()),
	}
	encoded, err := protocol.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

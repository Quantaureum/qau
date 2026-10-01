// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGGroupReplaySeparatedByGroup(t *testing.T) {
	session := testTDilithium3DKGSession()
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY group replay identity")
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	senderID := session.Committee.Participants[0]
	inbox, err := newTDilithium3DKGInbox(session, 1,
		func(id uint32, message, signature []byte) bool {
			return id == senderID && mode3.Verify(publicKey, message, signature)
		},
		func(peer p2p.PeerID) (uint32, bool) { return senderID, peer == "peer-0" })
	if err != nil {
		t.Fatal(err)
	}
	sign := func(message []byte) ([]byte, error) {
		signature := make([]byte, mode3.SignatureSize)
		mode3.SignTo(privateKey, message, signature)
		return signature, nil
	}
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	var packets []p2p.PeerMessage
	var firstGroup dilithium3v1.RSSGroupMask
	for _, group := range dilithium3v1.CanonicalRSSGroups() {
		leader, _ := group.Leader(0)
		if leader != 0 || !group.Contains(1) {
			continue
		}
		message := dilithium3v1.GroupSeedMessage{
			SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
			LeaderPosition: 0, RecipientPosition: 1, Seed: [32]byte{1},
		}
		payload, err := message.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, 0, 1, payload, sign)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p2p.PeerMessage{From: "peer-0", Type: p2p.MsgTypeTDilithium3DKGGroupSeed, Payload: encoded})
		if len(packets) == 1 {
			firstGroup = group
		}
		if len(packets) == 2 {
			break
		}
	}
	if len(packets) != 2 {
		t.Fatal("test requires two groups with the same leader and recipient")
	}
	for _, packet := range packets {
		if err := inbox.accept(packet); err != nil {
			t.Fatalf("distinct group with canonical sequence rejected: %v", err)
		}
	}
	if err := inbox.accept(packets[0]); err != nil || len(inbox.messages) != 2 {
		t.Fatalf("identical group retransmission not deduplicated: %v", err)
	}
	conflicting := dilithium3v1.GroupSeedMessage{
		SessionDigest: sessionDigest, CommitteeDigest: committeeDigest,
		GroupMask: firstGroup, LeaderPosition: 0,
		RecipientPosition: 1, Seed: [32]byte{2},
	}
	payload, err := conflicting.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	packet, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGGroupSeed, 0, 1, payload, sign)
	if err != nil {
		t.Fatal(err)
	}
	if err := inbox.accept(p2p.PeerMessage{From: "peer-0", Type: p2p.MsgTypeTDilithium3DKGGroupSeed, Payload: packet}); err == nil {
		t.Fatal("conflicting seed within one group and sequence accepted")
	}
}

func TestTDilithium3DKGPublicGroupReplaySeparatedByGroup(t *testing.T) {
	session := testTDilithium3DKGSession()
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	var groups []dilithium3v1.RSSGroupMask
	for _, group := range dilithium3v1.CanonicalRSSGroups() {
		leader, _ := group.Leader(0)
		if leader == 0 && group.Contains(1) {
			groups = append(groups, group)
		}
		if len(groups) == 2 {
			break
		}
	}
	if len(groups) != 2 {
		t.Fatal("test requires two groups with the same leader and participant")
	}
	for _, test := range []struct {
		name     string
		kind     uint8
		sender   uint8
		payloads func(dilithium3v1.RSSGroupMask) ([]byte, error)
	}{
		{"acknowledgement", p2p.MsgTypeTDilithium3DKGAcknowledgement, 1, func(group dilithium3v1.RSSGroupMask) ([]byte, error) {
			return (dilithium3v1.ContributionAcknowledgement{
				SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
				LeaderPosition: 0, ParticipantPosition: 1, SeedCommitmentDigest: [32]byte{1},
				SeedMessageDigest: [32]byte{2}, ContributionDigest: [32]byte{3},
			}).MarshalBinary()
		}},
		{"complaint", p2p.MsgTypeTDilithium3DKGComplaint, 1, func(group dilithium3v1.RSSGroupMask) ([]byte, error) {
			return (dilithium3v1.Complaint{
				SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
				LeaderPosition: 0, ComplainantPosition: 1, Reason: dilithium3v1.ComplaintReasonMissingSeed,
				Evidence: dilithium3v1.ComplaintEvidence{
					SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
					LeaderPosition: 0, MessageDigest: [32]byte{4},
				},
			}).MarshalBinary()
		}},
		{"contribution", p2p.MsgTypeTDilithium3DKGContribution, 0, func(group dilithium3v1.RSSGroupMask) ([]byte, error) {
			return (dilithium3v1.PublicContribution{
				SessionDigest: sessionDigest, GroupMask: group, DealerPosition: 0,
			}).MarshalBinary()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var seed [mode3.SeedSize]byte
			copy(seed[:], "DEVNET ONLY public group replay identity")
			publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
			senderID := session.Committee.Participants[test.sender]
			inbox, err := newTDilithium3DKGInbox(session, 1,
				func(id uint32, message, signature []byte) bool {
					return id == senderID && mode3.Verify(publicKey, message, signature)
				},
				func(peer p2p.PeerID) (uint32, bool) { return senderID, peer == "peer-sender" })
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range groups {
				payload, err := test.payloads(group)
				if err != nil {
					t.Fatal(err)
				}
				packet, err := encodeTDilithium3DKGSignedEnvelope(session, test.kind, test.sender, 1, payload,
					func(message []byte) ([]byte, error) {
						signature := make([]byte, mode3.SignatureSize)
						mode3.SignTo(privateKey, message, signature)
						return signature, nil
					})
				if err != nil {
					t.Fatal(err)
				}
				message := p2p.PeerMessage{From: "peer-sender", Type: test.kind, Payload: packet}
				if err := inbox.accept(message); err != nil {
					t.Fatalf("valid group %d rejected: %v", group, err)
				}
				if err := inbox.accept(message); err != nil {
					t.Fatalf("group retransmission rejected: %v", err)
				}
			}
			if len(inbox.messages) != 2 {
				t.Fatalf("expected two unique group messages, got %d", len(inbox.messages))
			}
		})
	}
}

func TestTDilithium3DKGAcknowledgementReplaySeparatedByAttempt(t *testing.T) {
	session := testTDilithium3DKGSession()
	sessionDigest, _ := session.Digest()
	committeeDigest, _ := session.Committee.CanonicalDigest()
	var group dilithium3v1.RSSGroupMask
	for _, candidate := range dilithium3v1.CanonicalRSSGroups() {
		if candidate.Contains(0) && candidate.Contains(1) && candidate.Contains(2) {
			group = candidate
			break
		}
	}
	if err := group.Validate(); err != nil {
		t.Fatal("test requires a group containing positions 0, 1 and 2")
	}
	var seed [mode3.SeedSize]byte
	copy(seed[:], "DEVNET ONLY acknowledgement attempts")
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	senderID := session.Committee.Participants[2]
	inbox, err := newTDilithium3DKGInbox(session, 2,
		func(id uint32, message, signature []byte) bool {
			return id == senderID && mode3.Verify(publicKey, message, signature)
		},
		func(peer p2p.PeerID) (uint32, bool) { return senderID, peer == "peer-2" })
	if err != nil {
		t.Fatal(err)
	}
	for attempt := uint8(0); attempt < 2; attempt++ {
		leader, err := group.Leader(attempt)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := (dilithium3v1.ContributionAcknowledgement{
			SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group,
			LeaderPosition: leader, ParticipantPosition: 2, Attempt: attempt,
			SeedCommitmentDigest: [32]byte{1}, SeedMessageDigest: [32]byte{2}, ContributionDigest: [32]byte{3},
		}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeTDilithium3DKGSignedEnvelope(session, p2p.MsgTypeTDilithium3DKGAcknowledgement, 2, 1, payload,
			func(message []byte) ([]byte, error) {
				signature := make([]byte, mode3.SignatureSize)
				mode3.SignTo(privateKey, message, signature)
				return signature, nil
			})
		if err != nil {
			t.Fatal(err)
		}
		packet := p2p.PeerMessage{From: "peer-2", Type: p2p.MsgTypeTDilithium3DKGAcknowledgement, Payload: encoded}
		if err := inbox.accept(packet); err != nil {
			t.Fatalf("attempt %d rejected: %v", attempt, err)
		}
		if err := inbox.accept(packet); err != nil {
			t.Fatalf("duplicate attempt %d rejected: %v", attempt, err)
		}
	}
	if len(inbox.messages) != 2 {
		t.Fatalf("expected one message per attempt, got %d", len(inbox.messages))
	}
}

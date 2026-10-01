// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGInboundRejectsForeignPayloadSession(t *testing.T) {
	session := testTDilithium3DKGSession()
	foreignDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	foreignDigest[0] ^= 1
	committeeDigest, err := session.Committee.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	group := dilithium3v1.CanonicalRSSGroups()[0]
	leader, err := group.Leader(0)
	if err != nil {
		t.Fatal(err)
	}
	recipient := uint8(1)
	for _, test := range []struct {
		name      string
		kind      uint8
		sender    uint8
		recipient *uint8
		payload   func() ([]byte, error)
	}{
		{"seed", p2p.MsgTypeTDilithium3DKGGroupSeed, leader, &recipient, func() ([]byte, error) {
			return (dilithium3v1.GroupSeedMessage{
				SessionDigest: foreignDigest, CommitteeDigest: committeeDigest, GroupMask: group,
				LeaderPosition: leader, RecipientPosition: recipient, Seed: [32]byte{1},
			}).MarshalBinary()
		}},
		{"acknowledgement", p2p.MsgTypeTDilithium3DKGAcknowledgement, recipient, nil, func() ([]byte, error) {
			return (dilithium3v1.ContributionAcknowledgement{
				SessionDigest: foreignDigest, CommitteeDigest: committeeDigest, GroupMask: group,
				LeaderPosition: leader, ParticipantPosition: recipient, SeedCommitmentDigest: [32]byte{1},
				SeedMessageDigest: [32]byte{2}, ContributionDigest: [32]byte{3},
			}).MarshalBinary()
		}},
		{"complaint", p2p.MsgTypeTDilithium3DKGComplaint, recipient, nil, func() ([]byte, error) {
			return (dilithium3v1.Complaint{
				SessionDigest: foreignDigest, CommitteeDigest: committeeDigest, GroupMask: group,
				LeaderPosition: leader, ComplainantPosition: recipient, Reason: dilithium3v1.ComplaintReasonMissingSeed,
				Evidence: dilithium3v1.ComplaintEvidence{
					SessionDigest: foreignDigest, CommitteeDigest: committeeDigest, GroupMask: group,
					LeaderPosition: leader, MessageDigest: [32]byte{4},
				},
			}).MarshalBinary()
		}},
		{"contribution", p2p.MsgTypeTDilithium3DKGContribution, leader, nil, func() ([]byte, error) {
			return (dilithium3v1.PublicContribution{
				SessionDigest: foreignDigest, GroupMask: group, DealerPosition: leader,
			}).MarshalBinary()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload, err := test.payload()
			if err != nil {
				t.Fatal(err)
			}
			encoded := testTDilithium3DKGNodeEnvelope(t, session, test.kind, session.Committee.Participants[test.sender], payload)
			if _, err := validateTDilithium3DKGStructure(test.kind, encoded, session, test.recipient); err == nil {
				t.Fatal("foreign inner session digest accepted with current envelope session")
			}
		})
	}
}

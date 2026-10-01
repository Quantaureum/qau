// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestLocalShareValidation(t *testing.T) {
	valid := testLocalShare(t)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid share rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*LocalShare)
	}{
		{name: "wrong protocol", mutate: func(share *LocalShare) { share.Protocol = protocol.ThresholdProtocolMLDSA65ExperimentalV1 }},
		{name: "wrong algorithm", mutate: func(share *LocalShare) { share.Key.Algorithm = qcrypto.SignatureAlgorithmMLDSA65 }},
		{name: "zero generation", mutate: func(share *LocalShare) { share.Key.Generation = 0 }},
		{name: "zero public key", mutate: func(share *LocalShare) { clear(share.Key.PublicKey) }},
		{name: "wrong threshold", mutate: func(share *LocalShare) { share.Committee.Threshold = 3 }},
		{name: "wrong participant count", mutate: func(share *LocalShare) { share.Committee.Participants = share.Committee.Participants[:5] }},
		{name: "zero participant", mutate: func(share *LocalShare) { share.ParticipantID = 0 }},
		{name: "non-member participant", mutate: func(share *LocalShare) { share.ParticipantID = 9 }},
		{name: "wrong participant position", mutate: func(share *LocalShare) { share.ParticipantPosition = 3 }},
		{name: "zero activation epoch", mutate: func(share *LocalShare) { share.ActivationEpoch = 0 }},
		{name: "zero transcript", mutate: func(share *LocalShare) { share.TranscriptDigest = [32]byte{} }},
		{name: "duplicate component", mutate: func(share *LocalShare) { share.Components[1] = share.Components[0] }},
		{name: "missing component", mutate: func(share *LocalShare) { share.Components[1] = RSSComponent{} }},
		{name: "foreign component", mutate: func(share *LocalShare) { share.Components[0].GroupMask = RSSGroupMask(0b001011) }},
		{name: "unsorted components", mutate: func(share *LocalShare) {
			share.Components[0], share.Components[1] = share.Components[1], share.Components[0]
		}},
		{name: "zero contribution digest", mutate: func(share *LocalShare) { share.Components[0].ContributionDigest = [32]byte{} }},
		{name: "dealer outside group", mutate: func(share *LocalShare) { share.Components[0].DealerPosition = 5 }},
		{name: "non-canonical s1", mutate: func(share *LocalShare) { share.Components[0].S1[0][0] = Q }},
		{name: "non-canonical s2", mutate: func(share *LocalShare) { share.Components[0].S2[0][0] = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			share := valid.Clone()
			test.mutate(share)
			if !errors.Is(share.Validate(), ErrInvalidLocalShare) {
				t.Fatalf("invalid share error = %v", share.Validate())
			}
		})
	}
}

func TestLocalShareEncodingRoundTripAndTamperRejection(t *testing.T) {
	share := testLocalShare(t)
	encoded, err := share.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(): %v", err)
	}
	if string(encoded[:8]) != "QTD3SH02" {
		t.Fatalf("magic = %q", encoded[:8])
	}
	restored, err := UnmarshalLocalShare(encoded)
	if err != nil {
		t.Fatalf("UnmarshalLocalShare(): %v", err)
	}
	if err := restored.Validate(); err != nil {
		t.Fatalf("restored share: %v", err)
	}
	if restored.Protocol != share.Protocol || restored.ParticipantID != share.ParticipantID || restored.ParticipantPosition != share.ParticipantPosition || restored.TranscriptDigest != share.TranscriptDigest {
		t.Fatal("restored metadata mismatch")
	}
	if restored.Components != share.Components {
		t.Fatal("restored RSS components mismatch")
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-33] ^= 1
	if _, err := UnmarshalLocalShare(tampered); !errors.Is(err, ErrShareDigestMismatch) {
		t.Fatalf("tamper error = %v", err)
	}
	if _, err := UnmarshalLocalShare(append(encoded, 0)); !errors.Is(err, ErrInvalidLocalShareEncoding) {
		t.Fatalf("trailing byte error = %v", err)
	}
	wrongMagic := append([]byte(nil), encoded...)
	wrongMagic[0] = 'X'
	if _, err := UnmarshalLocalShare(wrongMagic); !errors.Is(err, ErrInvalidLocalShareEncoding) {
		t.Fatalf("magic error = %v", err)
	}
}

func TestLocalShareRejectsVersionOneEncoding(t *testing.T) {
	legacy := make([]byte, 10)
	copy(legacy, "QTD3SH01")
	binary.BigEndian.PutUint16(legacy[8:], 1)
	if _, err := UnmarshalLocalShare(legacy); !errors.Is(err, ErrUnsupportedLocalShareVersion) {
		t.Fatalf("legacy encoding error = %v", err)
	}
}

func TestLocalShareCloneAndZeroize(t *testing.T) {
	share := testLocalShare(t)
	clone := share.Clone()
	clone.Key.PublicKey[0] ^= 1
	clone.Committee.Participants[0] = 99
	clone.Components[0].S1[0][0] = 99
	if share.Key.PublicKey[0] == clone.Key.PublicKey[0] || share.Committee.Participants[0] == clone.Committee.Participants[0] || share.Components[0].S1[0][0] == clone.Components[0].S1[0][0] {
		t.Fatal("clone aliases original share")
	}
	share.Zeroize()
	if !share.IsZeroized() {
		t.Fatal("share did not report zeroized")
	}
	for index, component := range share.Components {
		if component.S1 != (VectorL{}) || component.S2 != (VectorK{}) {
			t.Fatalf("component %d secret vectors were not cleared", index)
		}
	}
	if !errors.Is(share.Validate(), ErrLocalShareZeroized) {
		t.Fatalf("zeroized validation error = %v", share.Validate())
	}
	if _, err := share.MarshalBinary(); !errors.Is(err, ErrLocalShareZeroized) {
		t.Fatalf("zeroized marshal error = %v", err)
	}
}

func testLocalShare(t *testing.T) *LocalShare {
	t.Helper()
	var seed [mode3.SeedSize]byte
	seed[0] = 7
	publicKey, _ := mode3.NewKeyFromSeed(&seed)
	share := &LocalShare{
		Protocol:            protocol.ThresholdProtocolDilithium3V1,
		Key:                 protocol.ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: 11, PublicKey: publicKey.Bytes()},
		Committee:           protocol.CommitteeID{Version: 5, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}},
		ParticipantID:       3,
		ParticipantPosition: 2,
		ActivationEpoch:     21,
		TranscriptDigest:    [32]byte{1, 2, 3},
		Rho:                 [32]byte{4, 5, 6},
	}
	groups, err := GroupsForPosition(share.ParticipantPosition)
	if err != nil {
		t.Fatal(err)
	}
	for index, group := range groups {
		dealer, err := group.Leader(uint8(index % 3))
		if err != nil {
			t.Fatal(err)
		}
		share.Components[index] = RSSComponent{
			GroupMask:          group,
			DealerPosition:     dealer,
			ContributionDigest: [32]byte{byte(index + 1), byte(group)},
		}
		share.Components[index].S1[0][0] = Coefficient(index + 1)
		share.Components[index].S2[0][0] = Q - Coefficient(index+1)
	}
	return share
}

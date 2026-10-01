// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestDKGSessionValidation(t *testing.T) {
	valid := testDKGSession()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid session rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*DKGSession)
	}{
		{name: "wrong protocol and algorithm profile", mutate: func(session *DKGSession) { session.Protocol = protocol.ThresholdProtocolMLDSA65ExperimentalV1 }},
		{name: "zero generation", mutate: func(session *DKGSession) { session.KeyGeneration = 0 }},
		{name: "zero chain ID", mutate: func(session *DKGSession) { session.ChainID = 0 }},
		{name: "zero committee version", mutate: func(session *DKGSession) { session.Committee.Version = 0 }},
		{name: "wrong threshold", mutate: func(session *DKGSession) { session.Committee.Threshold = 3 }},
		{name: "wrong participant count", mutate: func(session *DKGSession) { session.Committee.Participants = session.Committee.Participants[:5] }},
		{name: "reordered committee", mutate: func(session *DKGSession) {
			session.Committee.Participants[1], session.Committee.Participants[2] = session.Committee.Participants[2], session.Committee.Participants[1]
		}},
		{name: "zero activation epoch", mutate: func(session *DKGSession) { session.ActivationEpoch = 0 }},
		{name: "zero nonce", mutate: func(session *DKGSession) { session.Nonce = [32]byte{} }},
		{name: "zero identity roster", mutate: func(session *DKGSession) { session.IdentityRosterDigest = [32]byte{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := valid.Clone()
			test.mutate(&session)
			if !errors.Is(session.Validate(), ErrInvalidDKGSession) {
				t.Fatalf("invalid session error = %v", session.Validate())
			}
		})
	}
}

func TestDKGSessionDigestIsCanonical(t *testing.T) {
	session := testDKGSession()
	digest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest == ([32]byte{}) || digest != repeated {
		t.Fatal("session digest is zero or non-deterministic")
	}
	mutated := session.Clone()
	mutated.Nonce[0] ^= 1
	changed, err := mutated.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if changed == digest {
		t.Fatal("session nonce was not bound into digest")
	}
	mutated = session.Clone()
	mutated.IdentityRosterDigest[0] ^= 1
	changed, err = mutated.Digest()
	if err != nil || changed == digest {
		t.Fatal("identity roster was not bound into session digest")
	}
	mutated = session.Clone()
	mutated.ChainID++
	changed, err = mutated.Digest()
	if err != nil || changed == digest {
		t.Fatal("session chain ID was not bound into digest")
	}
	mutated = session.Clone()
	mutated.Committee.Participants[0] = 13
	if _, err := mutated.Digest(); !errors.Is(err, ErrInvalidDKGSession) {
		t.Fatalf("non-canonical committee digest error = %v", err)
	}
}

func testDKGSession() DKGSession {
	return DKGSession{
		Protocol:             protocol.ThresholdProtocolDilithium3V1,
		ChainID:              1669,
		KeyGeneration:        7,
		Committee:            protocol.CommitteeID{Version: 9, Threshold: 4, Participants: []uint32{11, 12, 13, 14, 15, 16}},
		ActivationEpoch:      21,
		Nonce:                [32]byte{1, 2, 3, 4},
		IdentityRosterDigest: [32]byte{7},
	}
}

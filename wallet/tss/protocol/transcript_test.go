// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"bytes"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

func validSignRequest() SignRequest {
	request := SignRequest{
		Protocol: ThresholdProtocolMLDSA65ExperimentalV1,
		Key: ThresholdKeyID{
			Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
			Generation: 3,
			PublicKey:  bytes.Repeat([]byte{0x61}, qcrypto.SignatureAlgorithmMLDSA65.PublicKeySize()),
		},
		Committee: CommitteeID{Version: 9, Threshold: 4, Participants: []uint32{1, 2, 5, 8, 11, 13}},
		ChainID:   1669,
		Epoch:     12,
		Slot:      385,
		Domain:    SigningDomainFinality,
		Message:   []byte("canonical-finality-message"),
		Context:   []byte("qau-finality-v1"),
	}
	request.AttemptNonce[0] = 0x7a
	return request
}

func TestSigningSessionIDBindsEveryField(t *testing.T) {
	request := validSignRequest()
	want, err := SigningSessionID(request)
	if err != nil {
		t.Fatalf("SigningSessionID(valid): %v", err)
	}
	again, err := SigningSessionID(request.Clone())
	if err != nil {
		t.Fatalf("SigningSessionID(clone): %v", err)
	}
	if want != again {
		t.Fatal("identical requests must produce identical session IDs")
	}

	mutations := []struct {
		name   string
		mutate func(*SignRequest)
	}{
		{name: "protocol", mutate: func(value *SignRequest) {
			value.Protocol = ThresholdProtocolDilithium3V1
			value.Key.Algorithm = qcrypto.SignatureAlgorithmDilithium3Legacy
			value.Key.PublicKey = bytes.Repeat([]byte{0x61}, qcrypto.SignatureAlgorithmDilithium3Legacy.PublicKeySize())
			value.Context = nil
		}},
		{name: "generation", mutate: func(value *SignRequest) { value.Key.Generation++ }},
		{name: "public key", mutate: func(value *SignRequest) { value.Key.PublicKey[0] ^= 1 }},
		{name: "committee version", mutate: func(value *SignRequest) { value.Committee.Version++ }},
		{name: "participants", mutate: func(value *SignRequest) { value.Committee.Participants[2]++ }},
		{name: "chain", mutate: func(value *SignRequest) { value.ChainID++ }},
		{name: "epoch", mutate: func(value *SignRequest) { value.Epoch++ }},
		{name: "slot", mutate: func(value *SignRequest) { value.Slot++ }},
		{name: "domain", mutate: func(value *SignRequest) { value.Domain = SigningDomainVote }},
		{name: "message", mutate: func(value *SignRequest) { value.Message[0] ^= 1 }},
		{name: "context", mutate: func(value *SignRequest) { value.Context[0] ^= 1 }},
		{name: "attempt nonce", mutate: func(value *SignRequest) { value.AttemptNonce[1] = 1 }},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := request.Clone()
			mutation.mutate(&changed)
			got, err := SigningSessionID(changed)
			if err != nil {
				t.Fatalf("SigningSessionID(changed): %v", err)
			}
			if got == want {
				t.Fatal("changed request produced the original session ID")
			}
		})
	}
}

func TestSigningSessionIDRejectsInvalidRequest(t *testing.T) {
	request := validSignRequest()
	request.Committee.Participants = []uint32{5, 2, 8}
	if _, err := SigningSessionID(request); err == nil {
		t.Fatal("unsorted participant list must fail")
	}

	request = validSignRequest()
	request.Key.Algorithm = qcrypto.SignatureAlgorithmDilithium3Legacy
	request.Key.PublicKey = bytes.Repeat([]byte{0x61}, qcrypto.SignatureAlgorithmDilithium3Legacy.PublicKeySize())
	request.Context = nil
	if _, err := SigningSessionID(request); err == nil {
		t.Fatal("protocol and algorithm mismatch must fail")
	}

	request = validSignRequest()
	request.Committee.Threshold = 5
	if _, err := SigningSessionID(request); err == nil {
		t.Fatal("non-profile threshold must fail")
	}
}

// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"bytes"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

func TestThresholdKeyIDValidate(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x42}, qcrypto.SignatureAlgorithmMLDSA65.PublicKeySize())
	tests := []struct {
		name    string
		key     ThresholdKeyID
		wantErr bool
	}{
		{
			name: "valid",
			key: ThresholdKeyID{
				Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
				Generation: 1,
				PublicKey:  validKey,
			},
		},
		{
			name:    "unknown algorithm",
			key:     ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmUnknown, Generation: 1, PublicKey: validKey},
			wantErr: true,
		},
		{
			name:    "zero generation",
			key:     ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmMLDSA65, PublicKey: validKey},
			wantErr: true,
		},
		{
			name:    "wrong key length",
			key:     ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmMLDSA65, Generation: 1, PublicKey: validKey[:len(validKey)-1]},
			wantErr: true,
		},
		{
			name:    "zero key",
			key:     ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmMLDSA65, Generation: 1, PublicKey: make([]byte, len(validKey))},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.key.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestCommitteeIDValidate(t *testing.T) {
	tests := []struct {
		name      string
		committee CommitteeID
		wantErr   bool
	}{
		{name: "valid", committee: CommitteeID{Version: 1, Threshold: 2, Participants: []uint32{1, 2, 7}}},
		{name: "zero version", committee: CommitteeID{Threshold: 2, Participants: []uint32{1, 2}}, wantErr: true},
		{name: "threshold below two", committee: CommitteeID{Version: 1, Threshold: 1, Participants: []uint32{1, 2}}, wantErr: true},
		{name: "threshold above participants", committee: CommitteeID{Version: 1, Threshold: 3, Participants: []uint32{1, 2}}, wantErr: true},
		{name: "duplicate participant", committee: CommitteeID{Version: 1, Threshold: 2, Participants: []uint32{1, 1}}, wantErr: true},
		{name: "unsorted participants", committee: CommitteeID{Version: 1, Threshold: 2, Participants: []uint32{2, 1}}, wantErr: true},
		{name: "zero participant", committee: CommitteeID{Version: 1, Threshold: 2, Participants: []uint32{0, 1}}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.committee.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestThresholdIdentitiesCloneSlices(t *testing.T) {
	key := ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
		Generation: 1,
		PublicKey:  bytes.Repeat([]byte{0x24}, qcrypto.SignatureAlgorithmMLDSA65.PublicKeySize()),
	}
	committee := CommitteeID{Version: 1, Threshold: 2, Participants: []uint32{1, 2}}

	keyClone := key.Clone()
	committeeClone := committee.Clone()
	keyClone.PublicKey[0] ^= 0xff
	committeeClone.Participants[0] = 9

	if bytes.Equal(key.PublicKey, keyClone.PublicKey) {
		t.Fatal("key clone must not alias public key bytes")
	}
	if committee.Participants[0] == committeeClone.Participants[0] {
		t.Fatal("committee clone must not alias participant slice")
	}
}

func TestSignRequestValidateAndClone(t *testing.T) {
	request := SignRequest{
		Protocol: ThresholdProtocolMLDSA65ExperimentalV1,
		Key: ThresholdKeyID{
			Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
			Generation: 1,
			PublicKey:  bytes.Repeat([]byte{0x31}, qcrypto.SignatureAlgorithmMLDSA65.PublicKeySize()),
		},
		Committee: CommitteeID{Version: 2, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}},
		ChainID:   1669,
		Epoch:     7,
		Slot:      225,
		Domain:    SigningDomainFinality,
		Message:   []byte("finality-message"),
		Context:   []byte("qau-finality-v1"),
	}
	request.AttemptNonce[0] = 1
	if err := request.Validate(); err != nil {
		t.Fatalf("valid sign request rejected: %v", err)
	}

	clone := request.Clone()
	clone.Key.PublicKey[0] ^= 0xff
	clone.Committee.Participants[0] = 9
	clone.Message[0] ^= 0xff
	clone.Context[0] ^= 0xff
	if bytes.Equal(request.Key.PublicKey, clone.Key.PublicKey) {
		t.Fatal("request clone aliases key bytes")
	}
	if request.Committee.Participants[0] == clone.Committee.Participants[0] {
		t.Fatal("request clone aliases committee participants")
	}
	if bytes.Equal(request.Message, clone.Message) {
		t.Fatal("request clone aliases message bytes")
	}
	if bytes.Equal(request.Context, clone.Context) {
		t.Fatal("request clone aliases context bytes")
	}

	invalid := request
	invalid.Protocol = ThresholdProtocolDilithium3V1
	if err := invalid.Validate(); err == nil {
		t.Fatal("protocol and algorithm mismatch must fail")
	}
	invalid = request
	invalid.ChainID = 0
	if err := invalid.Validate(); err == nil {
		t.Fatal("zero chain ID must fail")
	}
	invalid = request
	invalid.Slot = 0
	if err := invalid.Validate(); err == nil {
		t.Fatal("zero slot must fail")
	}
	invalid = request
	invalid.Domain = SigningDomainUnknown
	if err := invalid.Validate(); err == nil {
		t.Fatal("unknown signing domain must fail")
	}
	invalid = request
	invalid.Message = nil
	if err := invalid.Validate(); err == nil {
		t.Fatal("empty message must fail")
	}
	invalid = request
	invalid.AttemptNonce = [32]byte{}
	if err := invalid.Validate(); err == nil {
		t.Fatal("zero attempt nonce must fail")
	}
	invalid = request
	invalid.Context = make([]byte, 256)
	if err := invalid.Validate(); err == nil {
		t.Fatal("ML-DSA context longer than 255 bytes must fail")
	}
}

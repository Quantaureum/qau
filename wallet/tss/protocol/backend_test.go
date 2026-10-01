// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"bytes"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

func testV1Committee(version uint64, firstParticipant uint32) CommitteeID {
	return CommitteeID{
		Version:      version,
		Threshold:    4,
		Participants: []uint32{firstParticipant, firstParticipant + 1, firstParticipant + 2, firstParticipant + 3, firstParticipant + 4, firstParticipant + 5},
	}
}

func TestDKGRequestValidateProtocolBinding(t *testing.T) {
	request := DKGRequest{
		Protocol:   ThresholdProtocolMLDSA65ExperimentalV1,
		Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
		Generation: 1,
		Committee:  testV1Committee(1, 1),
		ChainID:    1669,
		Epoch:      3,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid DKG request rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*DKGRequest)
	}{
		{name: "unknown protocol", mutate: func(value *DKGRequest) { value.Protocol = ThresholdProtocolUnknown }},
		{name: "algorithm mismatch", mutate: func(value *DKGRequest) { value.Protocol = ThresholdProtocolDilithium3V1 }},
		{name: "zero generation", mutate: func(value *DKGRequest) { value.Generation = 0 }},
		{name: "wrong threshold", mutate: func(value *DKGRequest) { value.Committee.Threshold = 3 }},
		{name: "zero chain", mutate: func(value *DKGRequest) { value.ChainID = 0 }},
		{name: "zero epoch", mutate: func(value *DKGRequest) { value.Epoch = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := request
			invalid.Committee = request.Committee.Clone()
			test.mutate(&invalid)
			if err := invalid.Validate(); err == nil {
				t.Fatal("invalid DKG request accepted")
			}
		})
	}
}

func TestReshareRequestValidateProtocolBinding(t *testing.T) {
	request := ReshareRequest{
		Protocol: ThresholdProtocolMLDSA65ExperimentalV1,
		Key: ThresholdKeyID{
			Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
			Generation: 7,
			PublicKey:  bytes.Repeat([]byte{0x4a}, qcrypto.SignatureAlgorithmMLDSA65.PublicKeySize()),
		},
		OldCommittee: testV1Committee(11, 1),
		NewCommittee: testV1Committee(12, 7),
		ChainID:      1669,
		Epoch:        19,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid reshare request rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ReshareRequest)
	}{
		{name: "algorithm mismatch", mutate: func(value *ReshareRequest) { value.Protocol = ThresholdProtocolDilithium3V1 }},
		{name: "same committee version", mutate: func(value *ReshareRequest) { value.NewCommittee.Version = value.OldCommittee.Version }},
		{name: "wrong new threshold", mutate: func(value *ReshareRequest) { value.NewCommittee.Threshold = 3 }},
		{name: "zero chain", mutate: func(value *ReshareRequest) { value.ChainID = 0 }},
		{name: "zero epoch", mutate: func(value *ReshareRequest) { value.Epoch = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := request
			invalid.Key = request.Key.Clone()
			invalid.OldCommittee = request.OldCommittee.Clone()
			invalid.NewCommittee = request.NewCommittee.Clone()
			test.mutate(&invalid)
			if err := invalid.Validate(); err == nil {
				t.Fatal("invalid reshare request accepted")
			}
		})
	}
}

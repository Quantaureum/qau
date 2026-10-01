// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"bytes"
	"reflect"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

func validThresholdEnvelope() ThresholdEnvelope {
	var sessionID [32]byte
	sessionID[0] = 0x44
	return ThresholdEnvelope{
		ProtocolVersion:   ThresholdProtocolVersionV1,
		Protocol:          ThresholdProtocolMLDSA65ExperimentalV1,
		Algorithm:         qcrypto.SignatureAlgorithmMLDSA65,
		MessageType:       1,
		KeyGeneration:     3,
		CommitteeVersion:  9,
		SessionID:         sessionID,
		SenderID:          2,
		Sequence:          1,
		Payload:           []byte("threshold-envelope-payload"),
		IdentitySignature: bytes.Repeat([]byte{0x55}, 96),
	}
}

func TestThresholdEnvelopeRoundTrip(t *testing.T) {
	want := validThresholdEnvelope()
	encoded, err := EncodeEnvelope(want)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	got, err := DecodeEnvelope(encoded)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch\n got: %#v\nwant: %#v", got, want)
	}

	got.Payload[0] ^= 0xff
	got.IdentitySignature[0] ^= 0xff
	if bytes.Equal(got.Payload, want.Payload) || bytes.Equal(got.IdentitySignature, want.IdentitySignature) {
		t.Fatal("decoded slices must not alias input values")
	}
}

func TestThresholdEnvelopeRejectsInvalidMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ThresholdEnvelope)
	}{
		{name: "unknown version", mutate: func(value *ThresholdEnvelope) { value.ProtocolVersion++ }},
		{name: "unknown protocol", mutate: func(value *ThresholdEnvelope) { value.Protocol = ThresholdProtocolUnknown }},
		{name: "protocol algorithm mismatch", mutate: func(value *ThresholdEnvelope) { value.Protocol = ThresholdProtocolDilithium3V1 }},
		{name: "unknown algorithm", mutate: func(value *ThresholdEnvelope) { value.Algorithm = qcrypto.SignatureAlgorithmUnknown }},
		{name: "zero message type", mutate: func(value *ThresholdEnvelope) { value.MessageType = 0 }},
		{name: "zero key generation", mutate: func(value *ThresholdEnvelope) { value.KeyGeneration = 0 }},
		{name: "zero committee version", mutate: func(value *ThresholdEnvelope) { value.CommitteeVersion = 0 }},
		{name: "zero session", mutate: func(value *ThresholdEnvelope) { value.SessionID = [32]byte{} }},
		{name: "zero sender", mutate: func(value *ThresholdEnvelope) { value.SenderID = 0 }},
		{name: "zero sequence", mutate: func(value *ThresholdEnvelope) { value.Sequence = 0 }},
		{name: "empty identity signature", mutate: func(value *ThresholdEnvelope) { value.IdentitySignature = nil }},
		{name: "oversized payload", mutate: func(value *ThresholdEnvelope) { value.Payload = make([]byte, MaxThresholdEnvelopePayload+1) }},
		{name: "oversized identity signature", mutate: func(value *ThresholdEnvelope) {
			value.IdentitySignature = make([]byte, MaxThresholdIdentitySignature+1)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validThresholdEnvelope()
			test.mutate(&value)
			if _, err := EncodeEnvelope(value); err == nil {
				t.Fatal("invalid envelope encoded successfully")
			}
		})
	}
}

func TestThresholdEnvelopeRejectsTrailingAndTruncatedData(t *testing.T) {
	encoded, err := EncodeEnvelope(validThresholdEnvelope())
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	if _, err := DecodeEnvelope(append(encoded, 0)); err == nil {
		t.Fatal("trailing bytes must fail")
	}
	if _, err := DecodeEnvelope(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("truncated bytes must fail")
	}
}

func TestThresholdEnvelopeIdentitySigningBytesBindEveryField(t *testing.T) {
	original := validThresholdEnvelope()
	want, err := original.IdentitySigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := original
	unsigned.IdentitySignature = nil
	got, err := unsigned.IdentitySigningBytes()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("unsigned envelope signing bytes: %v", err)
	}
	mutations := []struct {
		name   string
		change func(*ThresholdEnvelope)
	}{
		{"protocol", func(value *ThresholdEnvelope) {
			value.Protocol = ThresholdProtocolDilithium3V1
			value.Algorithm = qcrypto.SignatureAlgorithmDilithium3Legacy
		}},
		{"type", func(value *ThresholdEnvelope) { value.MessageType++ }},
		{"generation", func(value *ThresholdEnvelope) { value.KeyGeneration++ }},
		{"committee", func(value *ThresholdEnvelope) { value.CommitteeVersion++ }},
		{"session", func(value *ThresholdEnvelope) { value.SessionID[0]++ }},
		{"sender", func(value *ThresholdEnvelope) { value.SenderID++ }},
		{"sequence", func(value *ThresholdEnvelope) { value.Sequence++ }},
		{"payload", func(value *ThresholdEnvelope) { value.Payload = []byte("other") }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := original
			mutation.change(&changed)
			actual, err := changed.IdentitySigningBytes()
			if err != nil || bytes.Equal(actual, want) {
				t.Fatalf("changed field not signed: %v", err)
			}
		})
	}
	original.SenderID = 0
	if _, err := original.IdentitySigningBytes(); err == nil {
		t.Fatal("invalid sender accepted")
	}
}

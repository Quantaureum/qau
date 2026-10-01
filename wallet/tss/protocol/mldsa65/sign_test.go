// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"errors"
	"testing"

	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestStandardSignaturePartsRoundTrip(t *testing.T) {
	publicKey, message, context, signature := testStandardSignature(t)
	parts, err := ParseStandardSignature(signature)
	if err != nil {
		t.Fatalf("ParseStandardSignature(): %v", err)
	}
	assembled, err := AssembleStandardSignature(parts)
	if err != nil {
		t.Fatalf("AssembleStandardSignature(): %v", err)
	}
	if !bytes.Equal(assembled, signature) {
		t.Fatal("assembled signature differs from standard signature")
	}

	key := protocol.ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
		Generation: 1,
		PublicKey:  publicKey,
	}
	verified, err := AssembleVerifiedSignature(key, message, context, parts)
	if err != nil {
		t.Fatalf("AssembleVerifiedSignature(): %v", err)
	}
	if !bytes.Equal(verified, signature) {
		t.Fatal("verified assembly differs from standard signature")
	}
}

func TestAssembleVerifiedSignatureRejectsInvalidParts(t *testing.T) {
	publicKey, message, context, signature := testStandardSignature(t)
	parts, err := ParseStandardSignature(signature)
	if err != nil {
		t.Fatalf("ParseStandardSignature(): %v", err)
	}
	parts.CTilde[0] ^= 1
	key := protocol.ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
		Generation: 1,
		PublicKey:  publicKey,
	}
	if _, err := AssembleVerifiedSignature(key, message, context, parts); !errors.Is(err, ErrAssembledSignatureInvalid) {
		t.Fatalf("invalid assembly error = %v, want %v", err, ErrAssembledSignatureInvalid)
	}
}

func testStandardSignature(t *testing.T) ([]byte, []byte, []byte, []byte) {
	t.Helper()
	var seed [circlmldsa65.SeedSize]byte
	seed[0] = 91
	publicKey, privateKey := circlmldsa65.NewKeyFromSeed(&seed)
	message := []byte("QAU standard signature assembly")
	context := []byte("qau-finality-v1")
	signature := make([]byte, circlmldsa65.SignatureSize)
	if err := circlmldsa65.SignTo(privateKey, message, context, false, signature); err != nil {
		t.Fatalf("SignTo(): %v", err)
	}
	return publicKey.Bytes(), message, context, signature
}

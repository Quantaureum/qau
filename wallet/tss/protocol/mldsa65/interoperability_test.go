// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"testing"

	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qcrypto "github.com/quantaureum/qau/crypto"
)

func TestCIRCLDeterministicInteroperability(t *testing.T) {
	var seed [circlmldsa65.SeedSize]byte
	for index := range seed {
		seed[index] = byte(index)
	}
	message := []byte("QAU Threshold ML-DSA v1 interoperability")
	context := []byte("qau-finality-v1")

	publicKey1, privateKey1 := circlmldsa65.NewKeyFromSeed(&seed)
	signature1 := make([]byte, circlmldsa65.SignatureSize)
	if err := circlmldsa65.SignTo(privateKey1, message, context, false, signature1); err != nil {
		t.Fatalf("first deterministic signature: %v", err)
	}

	publicKey2, privateKey2 := circlmldsa65.NewKeyFromSeed(&seed)
	signature2 := make([]byte, circlmldsa65.SignatureSize)
	if err := circlmldsa65.SignTo(privateKey2, message, context, false, signature2); err != nil {
		t.Fatalf("second deterministic signature: %v", err)
	}

	if !bytes.Equal(publicKey1.Bytes(), publicKey2.Bytes()) {
		t.Fatal("same seed produced different public keys")
	}
	if !bytes.Equal(signature1, signature2) {
		t.Fatal("deterministic signing produced different signatures")
	}
	if err := ValidatePublicKeyEncoding(publicKey1.Bytes()); err != nil {
		t.Fatalf("public key encoding rejected: %v", err)
	}
	if err := ValidateSignatureEncoding(signature1); err != nil {
		t.Fatalf("signature encoding rejected: %v", err)
	}
	if err := qcrypto.VerifySignatureForAlgorithm(
		qcrypto.SignatureAlgorithmMLDSA65,
		publicKey1.Bytes(),
		message,
		context,
		signature1,
	); err != nil {
		t.Fatalf("standard signature rejected by QAU verifier: %v", err)
	}
	if err := qcrypto.VerifySignatureForAlgorithm(
		qcrypto.SignatureAlgorithmMLDSA65,
		publicKey1.Bytes(),
		message,
		[]byte("wrong-context"),
		signature1,
	); err == nil {
		t.Fatal("signature verified under a different context")
	}

	mutated := append([]byte(nil), signature1...)
	mutated[len(mutated)-1] ^= 1
	if err := qcrypto.VerifySignatureForAlgorithm(
		qcrypto.SignatureAlgorithmMLDSA65,
		publicKey1.Bytes(),
		message,
		context,
		mutated,
	); err == nil {
		t.Fatal("mutated signature verified")
	}
}

func TestStandardSignatureEncodingRoundTrip(t *testing.T) {
	var seed [circlmldsa65.SeedSize]byte
	for index := range seed {
		seed[index] = byte(255 - index)
	}
	_, privateKey := circlmldsa65.NewKeyFromSeed(&seed)
	signature := make([]byte, circlmldsa65.SignatureSize)
	if err := circlmldsa65.SignTo(
		privateKey,
		[]byte("standard encoding round trip"),
		[]byte("qau-finality-v1"),
		false,
		signature,
	); err != nil {
		t.Fatalf("SignTo(): %v", err)
	}

	const challengeSize = 48
	const zPolynomialSize = 640
	for polynomialIndex := 0; polynomialIndex < 5; polynomialIndex++ {
		start := challengeSize + polynomialIndex*zPolynomialSize
		end := start + zPolynomialSize
		decoded, err := DecodeZ(signature[start:end])
		if err != nil {
			t.Fatalf("DecodeZ(%d): %v", polynomialIndex, err)
		}
		reencoded, err := EncodeZ(decoded)
		if err != nil {
			t.Fatalf("EncodeZ(%d): %v", polynomialIndex, err)
		}
		if !bytes.Equal(reencoded[:], signature[start:end]) {
			t.Fatalf("z polynomial %d did not round trip", polynomialIndex)
		}
	}

	hintStart := challengeSize + 5*zPolynomialSize
	decodedHints, err := DecodeHints(signature[hintStart:])
	if err != nil {
		t.Fatalf("DecodeHints(): %v", err)
	}
	reencodedHints, err := EncodeHints(decodedHints)
	if err != nil {
		t.Fatalf("EncodeHints(): %v", err)
	}
	if !bytes.Equal(reencodedHints[:], signature[hintStart:]) {
		t.Fatal("hint vector did not round trip")
	}
}

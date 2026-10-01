// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
)

func TestEncodingCanonicalPolyRoundTrip(t *testing.T) {
	polynomial := Poly{0, 1, Q - 1, 255, 65535}
	encoded, err := EncodePoly(polynomial)
	if err != nil {
		t.Fatalf("EncodePoly(): %v", err)
	}
	if len(encoded) != PolyEncodedSize {
		t.Fatalf("encoded size = %d, want %d", len(encoded), PolyEncodedSize)
	}
	decoded, err := DecodePoly(encoded[:])
	if err != nil {
		t.Fatalf("DecodePoly(): %v", err)
	}
	if decoded != polynomial {
		t.Fatal("canonical polynomial did not round trip")
	}

	polynomial[0] = Q
	if _, err := EncodePoly(polynomial); !errors.Is(err, ErrNonCanonicalCoefficient) {
		t.Fatalf("EncodePoly() error = %v", err)
	}
	if _, err := DecodePoly(encoded[:len(encoded)-1]); !errors.Is(err, ErrInvalidEncodingSize) {
		t.Fatalf("truncated DecodePoly() error = %v", err)
	}
	encoded[0] = byte(Q & 0xff)
	encoded[1] = byte((Q >> 8) & 0xff)
	encoded[2] = byte((Q >> 16) & 0xff)
	if _, err := DecodePoly(encoded[:]); !errors.Is(err, ErrNonCanonicalCoefficient) {
		t.Fatalf("non-canonical DecodePoly() error = %v", err)
	}
}

func TestEncodingHighBitsRoundTrip(t *testing.T) {
	var polynomial HighBitsPoly
	for index := range polynomial {
		polynomial[index] = uint8(index % 16)
	}
	encoded, err := EncodeHighBits(polynomial)
	if err != nil {
		t.Fatalf("EncodeHighBits(): %v", err)
	}
	decoded, err := DecodeHighBits(encoded[:])
	if err != nil {
		t.Fatalf("DecodeHighBits(): %v", err)
	}
	if decoded != polynomial {
		t.Fatal("high bits did not round trip")
	}
	polynomial[0] = 16
	if _, err := EncodeHighBits(polynomial); !errors.Is(err, ErrInvalidHighBits) {
		t.Fatalf("EncodeHighBits() error = %v", err)
	}
}

func TestEncodingZRoundTripAndBounds(t *testing.T) {
	polynomial := SignedPoly{-Gamma1 + 1, -1, 0, 1, Gamma1}
	encoded, err := EncodeZ(polynomial)
	if err != nil {
		t.Fatalf("EncodeZ(): %v", err)
	}
	decoded, err := DecodeZ(encoded[:])
	if err != nil {
		t.Fatalf("DecodeZ(): %v", err)
	}
	if decoded != polynomial {
		t.Fatal("z polynomial did not round trip")
	}
	polynomial[0] = -Gamma1
	if _, err := EncodeZ(polynomial); !errors.Is(err, ErrInvalidZCoefficient) {
		t.Fatalf("EncodeZ(-Gamma1) error = %v", err)
	}
	polynomial[0] = Gamma1 + 1
	if _, err := EncodeZ(polynomial); !errors.Is(err, ErrInvalidZCoefficient) {
		t.Fatalf("EncodeZ(Gamma1+1) error = %v", err)
	}
}

func TestEncodingHintsRejectsNonCanonicalForms(t *testing.T) {
	var hints HintVector
	hints[0][2] = 1
	hints[0][9] = 1
	hints[2][7] = 1
	encoded, err := EncodeHints(hints)
	if err != nil {
		t.Fatalf("EncodeHints(): %v", err)
	}
	decoded, err := DecodeHints(encoded[:])
	if err != nil {
		t.Fatalf("DecodeHints(): %v", err)
	}
	if decoded != hints {
		t.Fatal("hints did not round trip")
	}

	for index := 0; index <= Omega; index++ {
		hints[0][index] = 1
	}
	if _, err := EncodeHints(hints); !errors.Is(err, ErrTooManyHints) {
		t.Fatalf("EncodeHints() error = %v", err)
	}

	malformed := make([]byte, HintEncodedSize)
	malformed[0], malformed[1], malformed[Omega] = 9, 9, 2
	for index := Omega + 1; index < len(malformed); index++ {
		malformed[index] = 2
	}
	if _, err := DecodeHints(malformed); !errors.Is(err, ErrInvalidHintVector) {
		t.Fatalf("duplicate hint index error = %v", err)
	}
	if _, err := DecodeHints(append(malformed, 0)); !errors.Is(err, ErrInvalidEncodingSize) {
		t.Fatalf("trailing hint byte error = %v", err)
	}
}

func TestMode3InteropDeterministicSignatureRoundTrip(t *testing.T) {
	var seed [mode3.SeedSize]byte
	for index := range seed {
		seed[index] = byte(index)
	}
	message := []byte("QAU Threshold Dilithium3 v1 interoperability")
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privateKey, message, signature)

	if err := ValidatePublicKeyEncoding(publicKey.Bytes()); err != nil {
		t.Fatalf("public key encoding rejected: %v", err)
	}
	if err := ValidatePrivateKeyEncoding(privateKey.Bytes()); err != nil {
		t.Fatalf("private key encoding rejected: %v", err)
	}
	if err := ValidateSignatureEncoding(signature); err != nil {
		t.Fatalf("signature encoding rejected: %v", err)
	}
	if err := qcrypto.VerifySignatureForAlgorithm(qcrypto.SignatureAlgorithmDilithium3Legacy, publicKey.Bytes(), message, nil, signature); err != nil {
		t.Fatalf("mode3 signature rejected by QAU verifier: %v", err)
	}

	offset := CTildeSize
	for polynomialIndex := 0; polynomialIndex < L; polynomialIndex++ {
		decoded, err := DecodeZ(signature[offset : offset+ZEncodedSize])
		if err != nil {
			t.Fatalf("DecodeZ(%d): %v", polynomialIndex, err)
		}
		reencoded, err := EncodeZ(decoded)
		if err != nil {
			t.Fatalf("EncodeZ(%d): %v", polynomialIndex, err)
		}
		if !bytes.Equal(reencoded[:], signature[offset:offset+ZEncodedSize]) {
			t.Fatalf("z polynomial %d did not round trip", polynomialIndex)
		}
		offset += ZEncodedSize
	}
	decodedHints, err := DecodeHints(signature[offset:])
	if err != nil {
		t.Fatalf("DecodeHints(): %v", err)
	}
	reencodedHints, err := EncodeHints(decodedHints)
	if err != nil {
		t.Fatalf("EncodeHints(): %v", err)
	}
	if !bytes.Equal(reencodedHints[:], signature[offset:]) {
		t.Fatal("signature hints did not round trip")
	}

	mutated := append([]byte(nil), signature...)
	mutated[len(mutated)-1] ^= 1
	if err := qcrypto.VerifySignatureForAlgorithm(qcrypto.SignatureAlgorithmDilithium3Legacy, publicKey.Bytes(), message, nil, mutated); err == nil {
		t.Fatal("mutated mode3 signature verified")
	}
}

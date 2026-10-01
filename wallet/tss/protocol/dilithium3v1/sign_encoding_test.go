// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestMode3SignaturePartsInterop(t *testing.T) {
	publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("QAU threshold Dilithium3 v1 signature-parts interoperability")
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privateKey, message, signature)
	parts, err := ParseMode3Signature(signature)
	if err != nil {
		t.Fatalf("parse CIRCL mode3 signature: %v", err)
	}
	reassembled, err := AssembleMode3Signature(parts)
	if err != nil || !bytes.Equal(reassembled, signature) {
		t.Fatalf("reassemble CIRCL mode3 signature: %v", err)
	}
	key := protocol.ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: 1, PublicKey: publicKey.Bytes()}
	verified, err := AssembleVerifiedMode3Signature(key, message, parts)
	if err != nil || !bytes.Equal(verified, signature) {
		t.Fatalf("native mode3 verifier rejected the signature: %v", err)
	}
	if len(verified) != 3293 {
		t.Fatalf("signature length = %d, want 3293", len(verified))
	}
	if _, err := ParseMode3Signature(signature[:len(signature)-1]); !errors.Is(err, ErrInvalidEncodingSize) {
		t.Fatalf("short signature error = %v", err)
	}
	if _, err := ParseMode3Signature(append(signature, 0)); !errors.Is(err, ErrInvalidEncodingSize) {
		t.Fatalf("long signature error = %v", err)
	}
	malformedHints := append([]byte(nil), signature...)
	malformedHints[len(malformedHints)-1] = Omega + 1
	if _, err := ParseMode3Signature(malformedHints); !errors.Is(err, ErrInvalidHintVector) {
		t.Fatalf("non-canonical hints error = %v", err)
	}
	parts.Z[0][0] = Gamma1 + 1
	if _, err := AssembleMode3Signature(parts); !errors.Is(err, ErrInvalidZCoefficient) {
		t.Fatalf("out-of-range z error = %v", err)
	}
}

func TestMode3SignatureAssemblerRejectsUnverifiedParts(t *testing.T) {
	publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("QAU threshold Dilithium3 v1 native verification")
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privateKey, message, signature)
	parts, err := ParseMode3Signature(signature)
	if err != nil {
		t.Fatal(err)
	}
	key := protocol.ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: 1, PublicKey: publicKey.Bytes()}
	if _, err := AssembleVerifiedMode3Signature(key, []byte("different message"), parts); err == nil {
		t.Fatal("signature accepted for a different message")
	}
	parts.Challenge[0] ^= 1
	if _, err := AssembleVerifiedMode3Signature(key, message, parts); err == nil {
		t.Fatal("mutated challenge was accepted")
	}
	parts, err = ParseMode3Signature(signature)
	if err != nil {
		t.Fatal(err)
	}
	key.Algorithm = qcrypto.SignatureAlgorithmMLDSA65
	if _, err := AssembleVerifiedMode3Signature(key, message, parts); !errors.Is(err, ErrInvalidMode3Signature) {
		t.Fatalf("wrong signing algorithm error = %v", err)
	}
}

// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestSignatureAlgorithmSizes(t *testing.T) {
	if got := SignatureAlgorithmDilithium3Legacy.PublicKeySize(); got != 1952 {
		t.Fatalf("legacy public key size = %d, want 1952", got)
	}
	if got := SignatureAlgorithmDilithium3Legacy.SignatureSize(); got != 3293 {
		t.Fatalf("legacy signature size = %d, want 3293", got)
	}
	if got := SignatureAlgorithmMLDSA65.PublicKeySize(); got != 1952 {
		t.Fatalf("ML-DSA-65 public key size = %d, want 1952", got)
	}
	if got := SignatureAlgorithmMLDSA65.SignatureSize(); got != 3309 {
		t.Fatalf("ML-DSA-65 signature size = %d, want 3309", got)
	}
	if SignatureAlgorithmUnknown.Supported() {
		t.Fatal("unknown signature algorithm must be unsupported")
	}
	if !SignatureAlgorithmDilithium3Legacy.Supported() {
		t.Fatal("legacy signature algorithm must be supported")
	}
	if !SignatureAlgorithmMLDSA65.Supported() {
		t.Fatal("ML-DSA-65 signature algorithm must be supported")
	}
}

func TestVerifySignatureForAlgorithm(t *testing.T) {
	message := []byte("qau threshold signature algorithm binding")
	context := []byte("qau-finality-v1")

	legacyPublicKey, legacyPrivateKey, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate legacy key: %v", err)
	}
	legacySignature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(legacyPrivateKey, message, legacySignature)

	mlPublicKey, mlPrivateKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ML-DSA-65 key: %v", err)
	}
	mlSignature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(mlPrivateKey, message, context, false, mlSignature); err != nil {
		t.Fatalf("sign ML-DSA-65 message: %v", err)
	}

	if err := VerifySignatureForAlgorithm(SignatureAlgorithmDilithium3Legacy, legacyPublicKey.Bytes(), message, nil, legacySignature); err != nil {
		t.Fatalf("verify legacy signature: %v", err)
	}
	if err := VerifySignatureForAlgorithm(SignatureAlgorithmMLDSA65, mlPublicKey.Bytes(), message, context, mlSignature); err != nil {
		t.Fatalf("verify ML-DSA-65 signature: %v", err)
	}

	if err := VerifySignatureForAlgorithm(SignatureAlgorithmMLDSA65, legacyPublicKey.Bytes(), message, context, legacySignature); err == nil {
		t.Fatal("cross-algorithm verification must fail")
	}
	if err := VerifySignatureForAlgorithm(SignatureAlgorithmMLDSA65, mlPublicKey.Bytes(), append([]byte(nil), message...), []byte("wrong-context"), mlSignature); err == nil {
		t.Fatal("context mismatch must fail")
	}
	changedMessage := append([]byte(nil), message...)
	changedMessage[0] ^= 0x01
	if err := VerifySignatureForAlgorithm(SignatureAlgorithmMLDSA65, mlPublicKey.Bytes(), changedMessage, context, mlSignature); err == nil {
		t.Fatal("changed message must fail")
	}
	if err := VerifySignatureForAlgorithm(SignatureAlgorithmMLDSA65, make([]byte, mldsa65.PublicKeySize), message, context, mlSignature); err == nil {
		t.Fatal("all-zero public key must fail")
	}
	if err := VerifySignatureForAlgorithm(SignatureAlgorithmMLDSA65, mlPublicKey.Bytes(), message, context, mlSignature[:len(mlSignature)-1]); err == nil {
		t.Fatal("wrong signature length must fail")
	}
	if err := VerifySignatureForAlgorithm(SignatureAlgorithmUnknown, mlPublicKey.Bytes(), message, context, mlSignature); err == nil {
		t.Fatal("unknown algorithm must fail")
	}
}

func TestSigningVerifierVerifyMessageSignatureForAlgorithm(t *testing.T) {
	message := []byte("versioned verifier entry point")
	context := []byte("qau-finality-v1")
	publicKey, privateKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ML-DSA-65 key: %v", err)
	}
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(privateKey, message, context, false, signature); err != nil {
		t.Fatalf("sign ML-DSA-65 message: %v", err)
	}

	verifier := NewSigningVerifier()
	defer verifier.Close()
	if err := verifier.VerifyMessageSignatureForAlgorithm(
		SignatureAlgorithmMLDSA65,
		publicKey.Bytes(),
		message,
		context,
		signature,
	); err != nil {
		t.Fatalf("versioned verifier rejected valid signature: %v", err)
	}
}

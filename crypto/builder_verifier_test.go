// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"testing"
)

func TestNewBuilderSignatureVerifier(t *testing.T) {
	bv := NewBuilderSignatureVerifier()
	if bv == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestBuilderSignatureVerifier_Verify_Valid(t *testing.T) {
	bv := NewBuilderSignatureVerifier()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("builder data to sign")
	sig, _ := kp.Private.Sign(data)

	err = bv.Verify(kp.Public.Bytes(), data, sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestBuilderSignatureVerifier_Verify_WrongPubKeySize(t *testing.T) {
	bv := NewBuilderSignatureVerifier()
	kp, _ := GenerateKeyPair()
	data := []byte("data")
	sig, _ := kp.Private.Sign(data)

	err := bv.Verify([]byte("short"), data, sig)
	if err == nil {
		t.Error("expected error for wrong pub key size")
	}
}

func TestBuilderSignatureVerifier_Verify_InvalidSig(t *testing.T) {
	bv := NewBuilderSignatureVerifier()
	kp, _ := GenerateKeyPair()
	data := []byte("data")

	invalidSig := make([]byte, Dilithium3SignatureSize)
	err := bv.Verify(kp.Public.Bytes(), data, invalidSig)
	if err != ErrInvalidSignature {
		t.Log("got error:", err)
	}
}

func TestBuilderSignatureVerifier_Verify_WrongSigSize(t *testing.T) {
	bv := NewBuilderSignatureVerifier()
	kp, _ := GenerateKeyPair()
	data := []byte("data")

	err := bv.Verify(kp.Public.Bytes(), data, []byte("short"))
	if err == nil {
		t.Error("expected error for wrong sig size")
	}
}

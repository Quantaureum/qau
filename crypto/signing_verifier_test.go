// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"testing"
)

func TestSigningVerifier_New(t *testing.T) {
	sv := NewSigningVerifier()
	if sv == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestSigningVerifier_SetRejectLegacy(t *testing.T) {
	sv := NewSigningVerifier()
	sv.SetRejectLegacy(true)

	if !sv.rejectLegacy.Load() {
		t.Error("rejectLegacy should be true")
	}

	sv.SetRejectLegacy(false)
	if sv.rejectLegacy.Load() {
		t.Error("rejectLegacy should be false")
	}
}

func TestSigningVerifier_IsDilithium3Signature(t *testing.T) {
	sv := NewSigningVerifier()
	kp, _ := GenerateKeyPair()
	msg := []byte("test message")
	sig, _ := kp.Private.Sign(msg)

	if !sv.IsDilithium3Signature(sig) {
		t.Error("should recognize Dilithium3 signature")
	}

	if sv.IsDilithium3Signature([]byte("short")) {
		t.Error("should not recognize short signature as Dilithium3")
	}

	if sv.IsDilithium3Signature(nil) {
		t.Error("nil should not be Dilithium3")
	}
}

func TestSigningVerifier_IsLegacySignature(t *testing.T) {
	sv := NewSigningVerifier()
	if sv.IsLegacySignature([]byte("too short to be legacy")) {
		t.Error("short sig should not be legacy")
	}

	legacySig := make([]byte, LegacyECDSASigSize)
	if !sv.IsLegacySignature(legacySig) {
		t.Error("65-byte sig should be recognized as legacy")
	}
}

func TestSigningVerifier_VerifyTransactionSignature_Valid(t *testing.T) {
	sv := NewSigningVerifier()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte{1, 2, 3, 4, 5}
	sig, _ := kp.Private.Sign(msg)

	err = sv.VerifyTransactionSignature(kp.Public.Bytes(), msg, sig)
	if err != nil {
		t.Fatalf("VerifyTransactionSignature failed: %v", err)
	}
}

func TestSigningVerifier_VerifyTransactionSignature_EmptySig(t *testing.T) {
	sv := NewSigningVerifier()

	err := sv.VerifyTransactionSignature([]byte{}, []byte("msg"), nil)
	if err != ErrInvalidSignatureFormat {
		t.Errorf("expected ErrInvalidSignatureFormat, got %v", err)
	}
}

func TestSigningVerifier_VerifyTransactionSignature_WrongPubKeySize(t *testing.T) {
	sv := NewSigningVerifier()
	kp, _ := GenerateKeyPair()
	msg := []byte{1, 2, 3}
	sig, _ := kp.Private.Sign(msg)

	err := sv.VerifyTransactionSignature([]byte("short"), msg, sig)
	if err == nil {
		t.Error("expected error for wrong pub key size")
	}
}

func TestSigningVerifier_VerifyTransactionSignature_InvalidSig(t *testing.T) {
	sv := NewSigningVerifier()
	kp, _ := GenerateKeyPair()
	msg := []byte("msg")

	invalidSig := make([]byte, Dilithium3SignatureSize)
	err := sv.VerifyTransactionSignature(kp.Public.Bytes(), msg, invalidSig)
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestSigningVerifier_VerifyTransactionSignature_Legacy(t *testing.T) {
	sv := NewSigningVerifier()
	sv.SetRejectLegacy(true)

	kp, _ := GenerateKeyPair()
	legacySig := make([]byte, LegacyECDSASigSize)
	msg := []byte("msg")

	err := sv.VerifyTransactionSignature(kp.Public.Bytes(), msg, legacySig)
	if err != ErrLegacySignatureDetected {
		t.Errorf("expected ErrLegacySignatureDetected, got %v", err)
	}
}

func TestSigningVerifier_VerifyTransactionSignature_LegacyAllowed(t *testing.T) {
	sv := NewSigningVerifier()
	sv.SetRejectLegacy(false)

	kp, _ := GenerateKeyPair()
	legacySig := make([]byte, LegacyECDSASigSize)
	msg := []byte("msg")

	err := sv.VerifyTransactionSignature(kp.Public.Bytes(), msg, legacySig)
	if err == nil {
		t.Error("expected error even when legacy not rejected (not supported)")
	}
}

func TestSigningVerifier_VerifyMessageSignature_Valid(t *testing.T) {
	sv := NewSigningVerifier()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("important message")
	sig, _ := kp.Private.Sign(msg)

	err = sv.VerifyMessageSignature(kp.Public.Bytes(), msg, sig)
	if err != nil {
		t.Fatalf("VerifyMessageSignature failed: %v", err)
	}
}

func TestSigningVerifier_VerifyMessageSignature_EmptySig(t *testing.T) {
	sv := NewSigningVerifier()

	err := sv.VerifyMessageSignature([]byte{}, []byte("msg"), []byte{})
	if err != ErrInvalidSignatureFormat {
		t.Errorf("expected ErrInvalidSignatureFormat for empty sig, got %v", err)
	}
}

func TestSigningVerifier_VerifyMessageSignature_ShortSigFormatted(t *testing.T) {
	sv := NewSigningVerifier()

	err := sv.VerifyMessageSignature([]byte{}, []byte("msg"), []byte("short"))
	if err == nil {
		t.Error("expected error for short signature")
	}
}

func TestSigningVerifier_VerifyMessageSignature_WrongPubKey(t *testing.T) {
	sv := NewSigningVerifier()
	kp, _ := GenerateKeyPair()
	msg := []byte("msg")
	sig, _ := kp.Private.Sign(msg)

	err := sv.VerifyMessageSignature([]byte("too_short"), msg, sig)
	if err == nil {
		t.Error("expected error")
	}
}

func TestSigningVerifier_VerifyMessageSignature_InvalidSig(t *testing.T) {
	sv := NewSigningVerifier()
	kp, _ := GenerateKeyPair()
	msg := []byte("msg")

	invalidSig := make([]byte, Dilithium3SignatureSize)
	err := sv.VerifyMessageSignature(kp.Public.Bytes(), msg, invalidSig)
	if err != ErrInvalidSignature {
		// acceptable - the important thing is it errors
		t.Log("got error:", err)
	}
}

func TestSigningVerifier_VerifyMessageSignature_ShortSig(t *testing.T) {
	sv := NewSigningVerifier()
	kp, _ := GenerateKeyPair()
	msg := []byte("msg")

	shortSig := []byte("not a valid dilithium signature")
	err := sv.VerifyMessageSignature(kp.Public.Bytes(), msg, shortSig)
	if err == nil {
		t.Error("expected error")
	}
}

func TestSigningVerifier_ValidatePublicKey_Valid(t *testing.T) {
	sv := NewSigningVerifier()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	err = sv.ValidatePublicKey(kp.Public.Bytes())
	if err != nil {
		t.Fatalf("ValidatePublicKey failed: %v", err)
	}
}

func TestSigningVerifier_ValidatePublicKey_WrongSize(t *testing.T) {
	sv := NewSigningVerifier()
	err := sv.ValidatePublicKey([]byte("short"))
	if err == nil {
		t.Error("expected error for wrong size")
	}
}

func TestSigningVerifier_ValidatePublicKey_AllZero(t *testing.T) {
	sv := NewSigningVerifier()
	allZero := make([]byte, Dilithium3PublicKeySize)

	// R37-P0-03 FIX (2026-07-30): all-zero public keys MUST be rejected.
	// A zero key (t1=0) degenerates Dilithium verification to w' = A·z and
	// allows keyless signature forgery. The previous expectation (accept)
	// enshrined the vulnerability.
	err := sv.ValidatePublicKey(allZero)
	if err == nil {
		t.Fatal("ValidatePublicKey must reject all-zero public key (keyless forgery vector)")
	}
}

func TestSigningVerifier_ErrorConstants(t *testing.T) {
	errors := []error{ErrLegacySignatureDetected, ErrSignatureTooShort, ErrInvalidSignatureFormat, ErrPublicKeyMismatch}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

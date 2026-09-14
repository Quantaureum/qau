// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// R37-P0-03 (2026-07-30): All-zero Dilithium3 public keys have t1=0, which
// degenerates the verification equation w' = A·z − c·t1·2^d to w' = A·z.
// mode3.Verify then accepts keyless forged signatures (z=0, h=0) for ANY
// message. These tests pin the rejection at every entry point.

func TestIsZeroPublicKeyBytes(t *testing.T) {
	zero := make([]byte, Dilithium3PublicKeySize)
	if !IsZeroPublicKeyBytes(zero) {
		t.Error("all-zero 1952-byte key must be detected")
	}
	nonZero := make([]byte, Dilithium3PublicKeySize)
	nonZero[Dilithium3PublicKeySize-1] = 0x01
	if IsZeroPublicKeyBytes(nonZero) {
		t.Error("non-zero key must not be flagged")
	}
	if IsZeroPublicKeyBytes(nil) {
		t.Error("nil input must return false (handled by length checks)")
	}
	if IsZeroPublicKeyBytes(make([]byte, 10)) {
		t.Error("wrong-length input must return false (handled by length checks)")
	}
}

func TestPublicKeyFromBytes_RejectsZeroKey_R37P003(t *testing.T) {
	zero := make([]byte, Dilithium3PublicKeySize)
	pk, err := PublicKeyFromBytes(zero)
	if err == nil || pk != nil {
		t.Fatal("PublicKeyFromBytes must reject all-zero public key")
	}
}

func TestVerify_RejectsZeroPublicKey_R37P003(t *testing.T) {
	// Construct a PublicKey with a zero internal key, bypassing
	// PublicKeyFromBytes, to prove the defense-in-depth gate in Verify.
	var zeroKey mode3.PublicKey
	zeroKey.Unpack(&[mode3.PublicKeySize]byte{})
	pk := &PublicKey{key: &zeroKey}

	msg := []byte("r37-p0-03 zero key forgery test")
	sig := make([]byte, Dilithium3SignatureSize)
	if Verify(pk, msg, sig) {
		t.Fatal("Verify must reject all-zero public key (keyless forgery vector)")
	}
}

func TestVerify_AcceptsRealKeyPair_R37P003(t *testing.T) {
	// Guard against over-blocking: a legitimate key pair must still verify.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	msg := []byte("legitimate message")
	sig, err := kp.Private.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(kp.Public, msg, sig) {
		t.Fatal("Verify must still accept a legitimate signature")
	}
	// And the exported bytes must round-trip through PublicKeyFromBytes.
	pkBytes := kp.Public.Bytes()
	pk2, err := PublicKeyFromBytes(pkBytes)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes(real key): %v", err)
	}
	if !Verify(pk2, msg, sig) {
		t.Fatal("Verify must accept round-tripped real public key")
	}
}

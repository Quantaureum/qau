// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"crypto/rand"
	"testing"
)

// F-06: a degenerate Dilithium3 public key has t1=0 but may carry a random
// rho seed. IsDegeneratePublicKeyBytes must catch it even though the key is
// not entirely all-zero, and the parser must refuse to build a PublicKey
// from it.
func TestDegeneratePublicKeyWithRandomRho(t *testing.T) {
	key := make([]byte, Dilithium3PublicKeySize)
	if _, err := rand.Read(key[:Dilithium3PublicKeyT1Offset]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if key[0] == 0 && key[1] == 0 {
		t.Fatal("random rho unexpectedly zero")
	}

	if !IsDegeneratePublicKeyBytes(key) {
		t.Fatal("random-rho t1=0 key not detected as degenerate")
	}
	if _, err := PublicKeyFromBytes(key); err == nil {
		t.Fatal("PublicKeyFromBytes accepted a t1=0 key")
	}
}

func TestDegeneratePublicKeyRejectsAllZeroAndShort(t *testing.T) {
	if !IsDegeneratePublicKeyBytes(make([]byte, Dilithium3PublicKeySize)) {
		t.Fatal("all-zero key not detected as degenerate")
	}
	if IsDegeneratePublicKeyBytes(make([]byte, Dilithium3PublicKeySize-1)) {
		t.Fatal("short input reported as degenerate")
	}
	if IsDegeneratePublicKeyBytes(nil) {
		t.Fatal("nil input reported as degenerate")
	}
}

func TestGeneratedPublicKeyIsNotDegenerate(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if IsDegeneratePublicKeyBytes(kp.Public.Bytes()) {
		t.Fatal("freshly generated public key reported as degenerate")
	}
}

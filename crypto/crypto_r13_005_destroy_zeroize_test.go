// Quantaureum Node source, version 1.0.0.
// Package crypto — CRYPTO-R13-005 regression tests for PrivateKey.Destroy/Zeroize.
package crypto

import (
	"testing"
)

// TestCRYPTO_R13_005_Destroy_NormalPathReturnsNil (CRYPTO-R13-005) verifies
// that Destroy() returns nil on the normal zeroization path. Previously
// the function always returned nil regardless of what happened inside —
// making the error return misleading. After the fix, the error return
// carries signal: nil means zeroization completed successfully (including
// the deterministic 0xAA fallback when rand.Read fails — that fallback is
// itself secure, so callers can treat it as success), non-nil means a
// panic occurred during circl's internal state manipulation.
func TestCRYPTO_R13_005_Destroy_NormalPathReturnsNil(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if err := kp.Private.Destroy(); err != nil {
		t.Fatalf("Destroy on normal path should return nil, got: %v", err)
	}
}

// TestCRYPTO_R13_005_Zeroize_NormalPathReturnsNil (CRYPTO-R13-005) verifies
// that Zeroize() returns nil on the normal zeroization path.
func TestCRYPTO_R13_005_Zeroize_NormalPathReturnsNil(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if err := kp.Private.Zeroize(); err != nil {
		t.Fatalf("Zeroize on normal path should return nil, got: %v", err)
	}
}

// TestCRYPTO_R13_005_Destroy_NilSafeReturnsNil (CRYPTO-R13-005) verifies
// that Destroy() on a nil PrivateKey or nil key field returns nil without
// panicking. This is the early-return path that does NOT go through the
// panic-recovery wrapper.
func TestCRYPTO_R13_005_Destroy_NilSafeReturnsNil(t *testing.T) {
	var nilKey *PrivateKey
	if err := nilKey.Destroy(); err != nil {
		t.Errorf("Destroy on nil *PrivateKey should return nil, got: %v", err)
	}
	// PrivateKey with nil key field
	pk := &PrivateKey{key: nil}
	if err := pk.Destroy(); err != nil {
		t.Errorf("Destroy on nil key field should return nil, got: %v", err)
	}
}

// TestCRYPTO_R13_005_Zeroize_NilSafeReturnsNil (CRYPTO-R13-005) verifies
// that Zeroize() on a nil PrivateKey or nil key field returns nil without
// panicking.
func TestCRYPTO_R13_005_Zeroize_NilSafeReturnsNil(t *testing.T) {
	var nilKey *PrivateKey
	if err := nilKey.Zeroize(); err != nil {
		t.Errorf("Zeroize on nil *PrivateKey should return nil, got: %v", err)
	}
	// PrivateKey with nil key field
	pk := &PrivateKey{key: nil}
	if err := pk.Zeroize(); err != nil {
		t.Errorf("Zeroize on nil key field should return nil, got: %v", err)
	}
}

// TestCRYPTO_R13_005_Destroy_IdempotentReturnsNil (CRYPTO-R13-005) verifies
// that calling Destroy() twice returns nil both times. The second call
// takes the early-return nil-key path, which must not error.
func TestCRYPTO_R13_005_Destroy_IdempotentReturnsNil(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if err := kp.Private.Destroy(); err != nil {
		t.Fatalf("first Destroy failed: %v", err)
	}
	// Second call: key field is nil after first Destroy
	if err := kp.Private.Destroy(); err != nil {
		t.Errorf("second Destroy should return nil (idempotent), got: %v", err)
	}
}

// TestCRYPTO_R13_005_Zeroize_IdempotentReturnsNil (CRYPTO-R13-005) verifies
// that calling Zeroize() twice returns nil both times.
func TestCRYPTO_R13_005_Zeroize_IdempotentReturnsNil(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if err := kp.Private.Zeroize(); err != nil {
		t.Fatalf("first Zeroize failed: %v", err)
	}
	if err := kp.Private.Zeroize(); err != nil {
		t.Errorf("second Zeroize should return nil (idempotent), got: %v", err)
	}
}

// TestCRYPTO_R13_005_Destroy_KeyIsNiledAfterCall (CRYPTO-R13-005) verifies
// that after Destroy() returns (whether nil or error), the internal key
// field is nil — preventing further use of the destroyed key. This is a
// defensive check: if a future change accidentally early-returns without
// nil-ing the key, this test catches it.
func TestCRYPTO_R13_005_Destroy_KeyIsNiledAfterCall(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if err := kp.Private.Destroy(); err != nil {
		t.Fatalf("Destroy failed: %v", err)
	}
	if kp.Private.key != nil {
		t.Error("CRYPTO-R13-005 regression: key field should be nil after Destroy")
	}
}

// TestCRYPTO_R13_005_Zeroize_KeyIsNiledAfterCall (CRYPTO-R13-005) verifies
// that after Zeroize() returns, the internal key field is nil.
func TestCRYPTO_R13_005_Zeroize_KeyIsNiledAfterCall(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if err := kp.Private.Zeroize(); err != nil {
		t.Fatalf("Zeroize failed: %v", err)
	}
	if kp.Private.key != nil {
		t.Error("CRYPTO-R13-005 regression: key field should be nil after Zeroize")
	}
}

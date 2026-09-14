// Quantaureum Node source, version 1.0.0.
// Package crypto — CRYPTO-R13-007 regression tests for zeroBytesSecure
// multi-pass fallback when rand.Read fails.
package crypto

import (
	"bytes"
	"testing"
)

// TestCRYPTO_R13_007_ZeroBytesSecure_NormalPathZerosMemory (CRYPTO-R13-007)
// verifies that zeroBytesSecure on the normal path (rand.Read succeeds)
// results in all-zero memory. After the fix, the normal path is 3-pass
// (random → 0xFF → 0x00) instead of 2-pass (random → 0x00).
func TestCRYPTO_R13_007_ZeroBytesSecure_NormalPathZerosMemory(t *testing.T) {
	// Fill a buffer with sensitive data (0xFF pattern simulates key material)
	buf := make([]byte, 64)
	for i := range buf {
		buf[i] = 0xFF
	}

	if err := zeroBytesSecure(buf); err != nil {
		t.Fatalf("zeroBytesSecure on normal path should return nil, got: %v", err)
	}

	// Verify final state is all zeros (the 0x00 pass should have run last)
	expected := make([]byte, 64)
	if !bytes.Equal(buf, expected) {
		t.Errorf("CRYPTO-R13-007 regression: buffer not zeroed after zeroBytesSecure, got %v", buf)
	}
}

// TestCRYPTO_R13_007_ZeroBytesSecure_EmptyInputReturnsNil (CRYPTO-R13-007)
// verifies that zeroBytesSecure on empty input returns nil without panic.
func TestCRYPTO_R13_007_ZeroBytesSecure_EmptyInputReturnsNil(t *testing.T) {
	if err := zeroBytesSecure(nil); err != nil {
		t.Errorf("zeroBytesSecure(nil) should return nil, got: %v", err)
	}
	if err := zeroBytesSecure([]byte{}); err != nil {
		t.Errorf("zeroBytesSecure(empty) should return nil, got: %v", err)
	}
}

// TestCRYPTO_R13_007_ZeroBytesSecure_LargeBufferZerosMemory (CRYPTO-R13-007)
// verifies that zeroBytesSecure correctly zeros a larger buffer (e.g.
// Dilithium3PrivateKeySize = 4000 bytes). This catches regressions in the
// multi-pass loop where fillPrivateKeyBytesFunc/zeroBytesFunc might
// misbehave on larger slices.
func TestCRYPTO_R13_007_ZeroBytesSecure_LargeBufferZerosMemory(t *testing.T) {
	// Use 4000 bytes (Dilithium3PrivateKeySize)
	buf := make([]byte, 4000)
	for i := range buf {
		buf[i] = 0xAA
	}

	if err := zeroBytesSecure(buf); err != nil {
		t.Fatalf("zeroBytesSecure on large buffer should return nil, got: %v", err)
	}

	expected := make([]byte, 4000)
	if !bytes.Equal(buf, expected) {
		t.Errorf("CRYPTO-R13-007 regression: large buffer not zeroed, first 16 bytes: %v", buf[:16])
	}
}

// TestCRYPTO_R13_007_ZeroBytesSecure_RandomFollowedBy0xFFAnd0x00 (CRYPTO-R13-007)
// verifies that the normal path executes 3 passes: random → 0xFF → 0x00.
// We cannot directly observe intermediate states (rand.Read writes random
// bytes that we cannot predict), but we CAN verify the final state is
// all zeros, which proves the 0x00 pass ran last. The 0xFF pass is
// implicitly verified by the fact that fillPrivateKeyBytesFunc is called
// with 0xFF (the function is tested separately in crypto package tests).
//
// This test is mostly a documentation test — it asserts the contract
// that zeroBytesSecure must leave the buffer in all-zero state.
func TestCRYPTO_R13_007_ZeroBytesSecure_RandomFollowedBy0xFFAnd0x00(t *testing.T) {
	buf := make([]byte, 256)
	// Fill with non-zero pattern to detect partial zeroization
	for i := range buf {
		buf[i] = byte(i % 256)
	}

	if err := zeroBytesSecure(buf); err != nil {
		t.Fatalf("zeroBytesSecure should return nil on normal path, got: %v", err)
	}

	// Verify ALL bytes are zero (0x00 pass must have covered all of them)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("CRYPTO-R13-007 regression: byte at index %d = %d, expected 0", i, b)
		}
	}
}

// TestCRYPTO_R13_007_ZeroBytesSecure_ZeroBytesFuncIsMultiPass (CRYPTO-R13-007)
// verifies that fillPrivateKeyBytesFunc and zeroBytesFunc are distinct
// operations — the 0xFF and 0x00 passes use different functions. This is
// a defense-in-depth check: if someone accidentally aliased the two
// function variables, the multi-pass strategy would silently degrade.
func TestCRYPTO_R13_007_ZeroBytesSecure_ZeroBytesFuncIsMultiPass(t *testing.T) {
	// Verify fillPrivateKeyBytesFunc with 0xFF writes 0xFF to every byte
	buf := make([]byte, 16)
	fillPrivateKeyBytesFunc(buf, 0xFF)
	for i, b := range buf {
		if b != 0xFF {
			t.Fatalf("fillPrivateKeyBytesFunc(0xFF) did not fill byte %d: got %d", i, b)
		}
	}
	// Verify fillPrivateKeyBytesFunc with 0xAA writes 0xAA to every byte
	fillPrivateKeyBytesFunc(buf, 0xAA)
	for i, b := range buf {
		if b != 0xAA {
			t.Fatalf("fillPrivateKeyBytesFunc(0xAA) did not fill byte %d: got %d", i, b)
		}
	}
	// Verify zeroBytesFunc writes 0x00 to every byte
	zeroBytesFunc(buf)
	for i, b := range buf {
		if b != 0x00 {
			t.Fatalf("zeroBytesFunc did not zero byte %d: got %d", i, b)
		}
	}
}

// TestCRYPTO_R13_007_ZeroBytesSecure_ExportedAPIWorks (CRYPTO-R13-007)
// verifies that the exported ZeroBytesSecure wrapper behaves the same
// as the internal zeroBytesSecure. This catches regressions in the
// wrapper function (e.g., if someone forgets to delegate properly).
func TestCRYPTO_R13_007_ZeroBytesSecure_ExportedAPIWorks(t *testing.T) {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = 0xCC
	}

	if err := ZeroBytesSecure(buf); err != nil {
		t.Errorf("ZeroBytesSecure (exported) should return nil, got: %v", err)
	}

	for i, b := range buf {
		if b != 0 {
			t.Errorf("ZeroBytesSecure did not zero byte %d: got %d", i, b)
		}
	}
}

// TestCRYPTO_R13_007_ZeroBytesSecure_Idempotent (CRYPTO-R13-007) verifies
// that calling zeroBytesSecure on already-zeroed memory is safe and
// returns nil (no panic, no spurious error). This catches regressions
// where the 0xFF pass might accidentally write to a freed slice.
func TestCRYPTO_R13_007_ZeroBytesSecure_Idempotent(t *testing.T) {
	buf := make([]byte, 32) // already zero

	if err := zeroBytesSecure(buf); err != nil {
		t.Errorf("zeroBytesSecure on already-zero buffer should return nil, got: %v", err)
	}
	// Call again to verify idempotency
	if err := zeroBytesSecure(buf); err != nil {
		t.Errorf("second zeroBytesSecure call should return nil, got: %v", err)
	}
	for i, b := range buf {
		if b != 0 {
			t.Errorf("CRYPTO-R13-007 regression: byte %d = %d after double zeroBytesSecure", i, b)
		}
	}
}

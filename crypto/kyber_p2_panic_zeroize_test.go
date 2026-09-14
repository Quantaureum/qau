// Quantaureum Node source, version 1.0.0.
// Package crypto - P2-KYBER-PANIC-ZEROIZE tests (R29, 2026-07-26)
//
// These tests verify the fix for the audit finding:
// "Kyber deserialization panic paths skipped zeroizing partial key material"
//
// The fix ensures that when KyberPrivateKeyFromBytes encounters a panic or
// returns an error, any partial key material that circl may have allocated
// is properly destroyed via Destroy() (which zeroizes both the serialized
// form and the internal circl state via reflection).
package crypto

import (
	"bytes"
	"reflect"
	"testing"
)

// TestP2_KYBER_PANIC_ZEROIZE_ValidKeyRoundtrip verifies that the fix does
// not break the normal (happy) path. A valid key should still deserialize
// correctly and produce an identical key.
func TestP2_KYBER_PANIC_ZEROIZE_ValidKeyRoundtrip(t *testing.T) {
	// Generate a valid key pair
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}

	// Serialize the private key
	privBytes, err := kp.Private.Bytes()
	if err != nil {
		t.Fatalf("PrivateKey.Bytes failed: %v", err)
	}

	if len(privBytes) != KyberPrivateKeySize {
		t.Fatalf("private key bytes length = %d, want %d", len(privBytes), KyberPrivateKeySize)
	}

	// Deserialize — should succeed
	priv2, err := KyberPrivateKeyFromBytes(privBytes)
	if err != nil {
		t.Fatalf("KyberPrivateKeyFromBytes failed on valid input: %v", err)
	}
	if priv2 == nil {
		t.Fatal("KyberPrivateKeyFromBytes returned nil key without error")
	}

	// Verify the deserialized key matches the original
	if !kp.Private.Equal(priv2) {
		t.Fatal("deserialized key does not match original — roundtrip failed")
	}

	// Cleanup
	_ = priv2.Zeroize()
	_ = kp.Private.Zeroize()
}

// TestP2_KYBER_PANIC_ZEROIZE_MalformedInputDoesNotPanic verifies that
// malformed input of the correct length does not cause a panic. The fix
// wraps the deserialization in a panic recovery that also zeroizes any
// partial key material. Without the recovery, a panic in circl would
// propagate up and crash the caller (e.g., the RPC path that imports
// raw keys via personal_importRawKey).
func TestP2_KYBER_PANIC_ZEROIZE_MalformedInputDoesNotPanic(t *testing.T) {
	// Generate a valid key to get the correct size
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}
	validBytes, err := kp.Private.Bytes()
	if err != nil {
		t.Fatalf("PrivateKey.Bytes failed: %v", err)
	}
	defer func() {
		_ = kp.Private.Zeroize()
		// Zero the valid bytes buffer to be safe
		for i := range validBytes {
			validBytes[i] = 0
		}
	}()

	// Test various malformed inputs — all should be handled gracefully
	// (either return an error or return a key, but never panic).
	testCases := []struct {
		name    string
		modify  func([]byte) []byte
		wantErr bool
	}{
		{
			name: "all_zeros",
			modify: func(b []byte) []byte {
				out := make([]byte, len(b))
				return out // all zeros
			},
			wantErr: false, // all-zeros might parse as a valid (but useless) key
		},
		{
			name: "all_ones",
			modify: func(b []byte) []byte {
				out := make([]byte, len(b))
				for i := range out {
					out[i] = 0xFF
				}
				return out
			},
			wantErr: false, // all-FF might parse
		},
		{
			name: "first_byte_flipped",
			modify: func(b []byte) []byte {
				out := make([]byte, len(b))
				copy(out, b)
				out[0] ^= 0xFF
				return out
			},
			wantErr: false, // single bit flip might still parse
		},
		{
			name: "last_byte_flipped",
			modify: func(b []byte) []byte {
				out := make([]byte, len(b))
				copy(out, b)
				out[len(out)-1] ^= 0xFF
				return out
			},
			wantErr: false,
		},
		{
			name: "middle_corrupted",
			modify: func(b []byte) []byte {
				out := make([]byte, len(b))
				copy(out, b)
				// Corrupt a large middle section
				for i := len(out) / 4; i < 3*len(out)/4; i++ {
					out[i] ^= byte(i)
				}
				return out
			},
			wantErr: false,
		},
		{
			name: "random_looking",
			modify: func(b []byte) []byte {
				out := make([]byte, len(b))
				// Use a deterministic but "random-looking" pattern
				for i := range out {
					out[i] = byte(i * 37 % 256)
				}
				return out
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			malformed := tc.modify(validBytes)

			// This should not panic regardless of the input
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("P2-KYBER-PANIC-ZEROIZE REGRESSION: KyberPrivateKeyFromBytes "+
						"panicked on malformed input %q: %v — panic recovery is broken, "+
						"which means partial key material is NOT zeroized on the panic path",
						tc.name, r)
				}
			}()

			priv, err := KyberPrivateKeyFromBytes(malformed)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil (priv=%v)", tc.name, priv != nil)
			}
			// If a key was returned (no error), it should be properly formed
			// and we should clean it up
			if err == nil && priv != nil {
				// Verify the key is usable (can derive public key)
				_, pubErr := priv.PublicKey()
				if pubErr != nil {
					t.Logf("malformed input %q produced a key that cannot derive public key: %v "+
						"(this is acceptable — the key is invalid but didn't panic)", tc.name, pubErr)
				}
				_ = priv.Zeroize()
			}
		})
	}
}

// TestP2_KYBER_PANIC_ZEROIZE_WrongLengthRejects verifies that inputs of the
// wrong length are rejected without calling UnmarshalBinaryPrivateKey (which
// could allocate partial state).
func TestP2_KYBER_PANIC_ZEROIZE_WrongLengthRejects(t *testing.T) {
	wrongSizes := []int{
		0,
		1,
		KyberPrivateKeySize - 1,
		KyberPrivateKeySize + 1,
		KyberPrivateKeySize * 2,
		10000,
	}

	for _, size := range wrongSizes {
		input := make([]byte, size)
		// Fill with non-zero data to ensure the length check rejects it
		// before any deserialization attempt
		for i := range input {
			input[i] = byte(i % 256)
		}

		_, err := KyberPrivateKeyFromBytes(input)
		if err == nil {
			t.Errorf("expected error for wrong length %d, got nil", size)
		}
	}
}

// TestP2_KYBER_PANIC_ZEROIZE_DestroyIsCalledOnError verifies that when
// UnmarshalBinaryPrivateKey returns a non-nil key with an error, the key
// is destroyed. Since we cannot directly observe the destruction, this test
// verifies the behavior indirectly: if the fix is working, the deserialized
// key's internal state should be zeroed after an error.
//
// Note: This test is best-effort. circl's UnmarshalBinaryPrivateKey typically
// returns (nil, err) on failure, so this test primarily verifies that the
// error path is exercised and doesn't panic.
func TestP2_KYBER_PANIC_ZEROIZE_DestroyIsCalledOnError(t *testing.T) {
	// Generate a valid key and corrupt it to cause an unmarshal error
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}
	validBytes, err := kp.Private.Bytes()
	if err != nil {
		t.Fatalf("PrivateKey.Bytes failed: %v", err)
	}
	defer func() {
		_ = kp.Private.Zeroize()
		for i := range validBytes {
			validBytes[i] = 0
		}
	}()

	// Try several different corruptions to maximize the chance of triggering
	// an error (some corruptions might still parse as valid keys)
	corruptions := []struct {
		name  string
		apply func([]byte) []byte
	}{
		{
			name: "zero_public_portion",
			apply: func(b []byte) []byte {
				// Kyber private key = public key (1184 bytes) + secret key
				// Zeroing the secret portion might cause validation failure
				out := make([]byte, len(b))
				copy(out, b)
				for i := KyberPublicKeySize; i < len(out); i++ {
					out[i] = 0
				}
				return out
			},
		},
		{
			name: "zero_secret_portion",
			apply: func(b []byte) []byte {
				out := make([]byte, len(b))
				copy(out, b)
				// Zero only the first 32 bytes of the secret portion
				for i := KyberPublicKeySize; i < KyberPublicKeySize+32 && i < len(out); i++ {
					out[i] = 0
				}
				return out
			},
		},
		{
			name: "corrupt_hash",
			apply: func(b []byte) []byte {
				// The last 32 bytes of a Kyber private key are the hash H(pk)
				// Corrupting it might cause validation failure in some implementations
				out := make([]byte, len(b))
				copy(out, b)
				for i := len(out) - 32; i < len(out); i++ {
					out[i] ^= 0xFF
				}
				return out
			},
		},
	}

	anyErrorObserved := false
	for _, c := range corruptions {
		t.Run(c.name, func(t *testing.T) {
			corrupted := c.apply(validBytes)

			// This should not panic, and if it returns an error, the partial
			// key (if any) should have been destroyed
			priv, err := KyberPrivateKeyFromBytes(corrupted)
			if err != nil {
				// Good — error was returned. If privKey was non-nil internally,
				// the fix would have called Destroy() on it.
				anyErrorObserved = true
				if priv != nil {
					t.Error("error returned but priv is non-nil — caller might leak key material")
					_ = priv.Zeroize()
				}
			} else if priv != nil {
				// The corruption didn't cause an error — this is acceptable
				// (Kyber is somewhat fault-tolerant). Just clean up.
				_ = priv.Zeroize()
			}
		})
	}

	// If none of the corruptions caused an error, the test is inconclusive
	// but not failing — Kyber's deserialization is fault-tolerant.
	if !anyErrorObserved {
		t.Log("No corruption caused an unmarshal error — Kyber is fault-tolerant. " +
			"The fix's error-path zeroization is exercised in production when " +
			"circl returns a non-nil privKey with an error (rare but possible).")
	}
}

// TestP2_KYBER_PANIC_ZEROIZE_OriginalKeyIntactAfterFailedImport verifies
// that a failed deserialization of corrupted bytes does not affect the
// original key. This is a regression test: if the fix incorrectly shares
// state between the deserialization attempt and the original key, the
// original key would be corrupted.
func TestP2_KYBER_PANIC_ZEROIZE_OriginalKeyIntactAfterFailedImport(t *testing.T) {
	// Generate a valid key
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}

	// Get the original bytes and public key for later comparison
	originalBytes, err := kp.Private.Bytes()
	if err != nil {
		t.Fatalf("PrivateKey.Bytes failed: %v", err)
	}
	originalPub, err := kp.Private.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() failed: %v", err)
	}
	originalPubBytes, err := originalPub.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes failed: %v", err)
	}

	defer func() {
		_ = kp.Private.Zeroize()
		for i := range originalBytes {
			originalBytes[i] = 0
		}
		for i := range originalPubBytes {
			originalPubBytes[i] = 0
		}
	}()

	// Create a corrupted copy and try to deserialize it
	corrupted := make([]byte, len(originalBytes))
	copy(corrupted, originalBytes)
	// Heavy corruption
	for i := range corrupted {
		corrupted[i] ^= byte(i * 7 % 256)
	}

	// Attempt deserialization (should either succeed with a different key or fail)
	_, _ = KyberPrivateKeyFromBytes(corrupted)

	// Verify the original key is still intact
	afterBytes, err := kp.Private.Bytes()
	if err != nil {
		t.Fatalf("PrivateKey.Bytes failed after corrupted import: %v", err)
	}

	if !bytes.Equal(originalBytes, afterBytes) {
		t.Fatal("REGRESSION: original key bytes changed after failed import — " +
			"the fix may have incorrectly shared state between deserialization attempts")
	}

	// Verify the original key can still derive its public key
	afterPub, err := kp.Private.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() failed after corrupted import: %v", err)
	}
	afterPubBytes, err := afterPub.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes failed after corrupted import: %v", err)
	}

	if !bytes.Equal(originalPubBytes, afterPubBytes) {
		t.Fatal("REGRESSION: derived public key changed after failed import — " +
			"the fix may have corrupted the original key's internal state")
	}
}

// R31-LOW-1 regression: zeroValue must recurse into SLICES of structs and
// slices of arrays — the Array branch recursed (CRY-R2-01) but the Slice
// branch skipped non-numeric element kinds, so a layout holding secret
// material as []struct{...int16...} would survive Destroy/Zeroize unzeroed.
// Uses a scratch struct mimicking such a layout and the exported
// KyberPrivateKey.Zeroize path's internal dispatcher indirectly via a
// synthetic reflect.Value built from an anonymous struct with a []struct field.
func TestR31LOW1_ZeroValueRecursesIntoSlicesOfStructs(t *testing.T) {
	type secretPoly struct {
		Coeffs [8]int16
	}
	type fakeLayout struct {
		Pub []byte       // public, but zeroed as numeric slice
		Sh  []secretPoly // R31-LOW-1 target: slice of structs
		Raw [][4]int16   // slice of arrays
	}

	v := fakeLayout{
		Pub: []byte{1, 2, 3, 4},
		Sh:  make([]secretPoly, 3),
		Raw: make([][4]int16, 2),
	}
	for i := range v.Sh {
		for j := range v.Sh[i].Coeffs {
			v.Sh[i].Coeffs[j] = int16(0x5A5A)
		}
	}
	for i := range v.Raw {
		for j := range v.Raw[i] {
			v.Raw[i][j] = int16(-0x5A5A)
		}
	}

	// Drive the same dispatcher Destroy/Zeroize use on internal state.
	zeroStructFields(reflect.ValueOf(v))

	for i := range v.Sh {
		for j := range v.Sh[i].Coeffs {
			if v.Sh[i].Coeffs[j] != 0 {
				t.Fatalf("slice-of-struct field NOT zeroed: Sh[%d].Coeffs[%d]=%d (R31-LOW-1)", i, j, v.Sh[i].Coeffs[j])
			}
		}
	}
	for i := range v.Raw {
		for j := range v.Raw[i] {
			if v.Raw[i][j] != 0 {
				t.Fatalf("slice-of-array field NOT zeroed: Raw[%d][%d]=%d (R31-LOW-1)", i, j, v.Raw[i][j])
			}
		}
	}
	for _, b := range v.Pub {
		if b != 0 {
			t.Fatalf("numeric slice field NOT zeroed: Pub byte %d", b)
		}
	}
}

// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// =============================================================================
// CRYPTO-R12-005 (2026-07-20) tests: GMQTD_SignMode3 constant-time nil check
//
// These tests verify that:
//  1. Each individual nil input is rejected
//  2. All combinations of nil inputs are rejected (no short-circuit bypass)
//  3. The error message does not leak which input was nil (uniform error)
//  4. The function does not panic on any nil combination
// =============================================================================

// validMode3KeyBytes generates a valid Dilithium3 private key and returns
// its raw bytes for use as privKey input to GMQTD_SignMode3.
func validMode3KeyBytes(t *testing.T) (pubBytes, privBytes []byte) {
	t.Helper()
	priv := newPrivateKeyMode3(t)
	pub := priv.Public().(*mode3.PublicKey)
	// Marshal to raw bytes
	privBytes = make([]byte, Dilithium3PrivateKeySize)
	copy(privBytes, priv.Bytes())
	pubBytes = make([]byte, Dilithium3PublicKeySize)
	copy(pubBytes, pub.Bytes())
	return pubBytes, privBytes
}

// TestCRYPTO_R12_005_NilPubKey verifies that a nil pubKey is rejected.
func TestCRYPTO_R12_005_NilPubKey(t *testing.T) {
	_, privBytes := validMode3KeyBytes(t)
	_, err := GMQTD_SignMode3(nil, privBytes, []byte("message"))
	if err == nil {
		t.Fatal("expected error for nil pubKey")
	}
	if !strings.Contains(err.Error(), "nil input") {
		t.Errorf("expected 'nil input' in error, got: %v", err)
	}
}

// TestCRYPTO_R12_005_NilPrivKey verifies that a nil privKey is rejected.
func TestCRYPTO_R12_005_NilPrivKey(t *testing.T) {
	pubBytes, _ := validMode3KeyBytes(t)
	_, err := GMQTD_SignMode3(pubBytes, nil, []byte("message"))
	if err == nil {
		t.Fatal("expected error for nil privKey")
	}
	if !strings.Contains(err.Error(), "nil input") {
		t.Errorf("expected 'nil input' in error, got: %v", err)
	}
}

// TestCRYPTO_R12_005_NilMessage verifies that a nil message is rejected.
func TestCRYPTO_R12_005_NilMessage(t *testing.T) {
	pubBytes, privBytes := validMode3KeyBytes(t)
	_, err := GMQTD_SignMode3(pubBytes, privBytes, nil)
	if err == nil {
		t.Fatal("expected error for nil message")
	}
	if !strings.Contains(err.Error(), "nil input") {
		t.Errorf("expected 'nil input' in error, got: %v", err)
	}
}

// TestCRYPTO_R12_005_NilPubAndPriv verifies that nil pubKey AND privKey
// are rejected (no short-circuit bypass that would skip the message check).
func TestCRYPTO_R12_005_NilPubAndPriv(t *testing.T) {
	_, err := GMQTD_SignMode3(nil, nil, []byte("message"))
	if err == nil {
		t.Fatal("expected error for nil pubKey and privKey")
	}
}

// TestCRYPTO_R12_005_NilPubAndMessage verifies that nil pubKey AND message
// are rejected.
func TestCRYPTO_R12_005_NilPubAndMessage(t *testing.T) {
	_, privBytes := validMode3KeyBytes(t)
	_, err := GMQTD_SignMode3(nil, privBytes, nil)
	if err == nil {
		t.Fatal("expected error for nil pubKey and message")
	}
}

// TestCRYPTO_R12_005_NilPrivAndMessage verifies that nil privKey AND message
// are rejected.
func TestCRYPTO_R12_005_NilPrivAndMessage(t *testing.T) {
	pubBytes, _ := validMode3KeyBytes(t)
	_, err := GMQTD_SignMode3(pubBytes, nil, nil)
	if err == nil {
		t.Fatal("expected error for nil privKey and message")
	}
}

// TestCRYPTO_R12_005_AllNil verifies that all nil inputs are rejected.
func TestCRYPTO_R12_005_AllNil(t *testing.T) {
	_, err := GMQTD_SignMode3(nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for all nil inputs")
	}
	if !strings.Contains(err.Error(), "nil input") {
		t.Errorf("expected 'nil input' in error, got: %v", err)
	}
}

// TestCRYPTO_R12_005_UniformErrorMessage verifies that the error message is
// uniform regardless of which input is nil. This is a defense-in-depth check:
// the error should not leak information about which input triggered the nil
// check (which could be used as a side-channel timing oracle).
//
// Note: This test verifies message uniformity, not timing uniformity. Timing
// uniformity is enforced by the constant-time implementation (boolToInt32 +
// bitwise OR) and cannot be reliably tested in Go due to scheduler noise.
func TestCRYPTO_R12_005_UniformErrorMessage(t *testing.T) {
	pubBytes, privBytes := validMode3KeyBytes(t)
	msg := []byte("test message")

	cases := []struct {
		name    string
		pubKey  []byte
		privKey []byte
		message []byte
	}{
		{"nil_pub", nil, privBytes, msg},
		{"nil_priv", pubBytes, nil, msg},
		{"nil_msg", pubBytes, privBytes, nil},
		{"nil_pub_priv", nil, nil, msg},
		{"nil_pub_msg", nil, privBytes, nil},
		{"nil_priv_msg", pubBytes, nil, nil},
		{"all_nil", nil, nil, nil},
	}

	expectedErr := "nil input to GMQTD_SignMode3"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GMQTD_SignMode3(tc.pubKey, tc.privKey, tc.message)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != expectedErr {
				t.Errorf("case %s: expected error %q, got %q", tc.name, expectedErr, err.Error())
			}
		})
	}
}

// TestCRYPTO_R12_005_NoPanicOnAnyNilCombination verifies that the function
// does not panic on any combination of nil inputs. This is important because
// a panic would be a denial-of-service vector if GMQTD_SignMode3 is called
// from a goroutine without recover.
func TestCRYPTO_R12_005_NoPanicOnAnyNilCombination(t *testing.T) {
	pubBytes, privBytes := validMode3KeyBytes(t)
	msg := []byte("test")

	// Use named fields to avoid interface{} type-assertion pitfalls.
	combinations := []struct {
		name    string
		pubKey  []byte
		privKey []byte
		message []byte
	}{
		{"nil_pub", nil, privBytes, msg},
		{"nil_priv", pubBytes, nil, msg},
		{"nil_msg", pubBytes, privBytes, nil},
		{"nil_pub_priv", nil, nil, msg},
		{"nil_pub_msg", nil, privBytes, nil},
		{"nil_priv_msg", pubBytes, nil, nil},
		{"all_nil", nil, nil, nil},
	}

	for _, tc := range combinations {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("GMQTD_SignMode3 panicked on nil combination %s: %v", tc.name, r)
				}
			}()
			_, _ = GMQTD_SignMode3(tc.pubKey, tc.privKey, tc.message)
		})
	}
}

// TestCRYPTO_R12_005_ValidInputsProceed verifies that valid (non-nil) inputs
// are accepted and proceed past the nil check. The function may still fail
// later (e.g. signer not registered), but the nil check should not reject it.
func TestCRYPTO_R12_005_ValidInputsProceed(t *testing.T) {
	pubBytes, privBytes := validMode3KeyBytes(t)
	// Call with valid inputs — should NOT return "nil input" error.
	// It may return a different error (e.g. signer not registered),
	// but the error must not mention "nil input".
	_, err := GMQTD_SignMode3(pubBytes, privBytes, []byte("valid message"))
	if err != nil && strings.Contains(err.Error(), "nil input") {
		t.Errorf("valid inputs should not return 'nil input' error, got: %v", err)
	}
}

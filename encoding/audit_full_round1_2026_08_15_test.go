// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"errors"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// TestAuditFull_R1_P0_01_VerifySingleSigBinding covers the canonical
// single-source signature authorization primitive introduced for
// AUDIT-FULL-ROUND1-2026-08-15 P0-01 — closes the drift gap between
// rollup/sequencer.go (L2 tx) and encoding.VerifyTransactionAuthorization
// (L1 tx). Both callers are required to delegate to this helper; this
// test pins the helper's behaviour so future regressions in either
// caller are caught here first.
func TestAuditFull_R1_P0_01_VerifySingleSigBinding(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv := kp.Private
	pub, err := priv.PublicKeySafe()
	if err != nil {
		t.Fatalf("PublicKeySafe: %v", err)
	}
	from := pub.Address()
	pubBytes := pub.Bytes()

	t.Run("happy path", func(t *testing.T) {
		msg := []byte("canonical-boundary-test-happy")
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := VerifySingleSigBinding(from, pubBytes, msg, sig); err != nil {
			t.Fatalf("VerifySingleSigBinding happy: want nil, got %v", err)
		}
	})

	t.Run("bad signature rejected", func(t *testing.T) {
		msg := []byte("canonical-boundary-test-bad-sig")
		badSig := make([]byte, crypto.Dilithium3SignatureSize)
		for i := range badSig {
			badSig[i] = 0xff
		}
		if err := VerifySingleSigBinding(from, pubBytes, msg, badSig); !errors.Is(err, ErrAuthInvalidSignature) {
			t.Fatalf("bad sig: want ErrAuthInvalidSignature, got %v", err)
		}
	})

	t.Run("wrong from (pubkey derives elsewhere) rejected", func(t *testing.T) {
		msg := []byte("canonical-boundary-test-wrong-from")
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		otherFrom := types.Address{0xde, 0xad, 0xbe, 0xef}
		if err := VerifySingleSigBinding(otherFrom, pubBytes, msg, sig); !errors.Is(err, ErrAuthPubKeyAddrMismatch) {
			t.Fatalf("wrong from: want ErrAuthPubKeyAddrMismatch, got %v", err)
		}
	})

	t.Run("empty pubkey rejected", func(t *testing.T) {
		if err := VerifySingleSigBinding(from, nil, []byte("x"), []byte("y")); !errors.Is(err, ErrAuthNoPublicKey) {
			t.Fatalf("nil pubkey: want ErrAuthNoPublicKey, got %v", err)
		}
	})

	t.Run("empty signature rejected", func(t *testing.T) {
		if err := VerifySingleSigBinding(from, pubBytes, []byte("x"), nil); !errors.Is(err, ErrAuthNoSignature) {
			t.Fatalf("nil sig: want ErrAuthNoSignature, got %v", err)
		}
	})

	t.Run("bad pubkey length rejected", func(t *testing.T) {
		shortPub := make([]byte, 10) // wrong length
		sig := make([]byte, crypto.Dilithium3SignatureSize)
		if err := VerifySingleSigBinding(from, shortPub, []byte("x"), sig); err == nil {
			t.Fatalf("short pubkey: want error, got nil")
		}
	})

	t.Run("bad sig length rejected", func(t *testing.T) {
		shortSig := make([]byte, 10) // wrong length
		if err := VerifySingleSigBinding(from, pubBytes, []byte("x"), shortSig); err == nil {
			t.Fatalf("short sig: want error, got nil")
		}
	})

	t.Run("msg bytes used as-is (no re-hash inside helper)", func(t *testing.T) {
		// The helper must verify the signature over the exact bytes the
		// caller passed in — NOT re-hash them. If a future refactor adds
		// an inner hash, this test catches the semantic drift because the
		// outer caller already chose to sign over a length-N msg.
		msg := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := VerifySingleSigBinding(from, pubBytes, msg, sig); err != nil {
			t.Fatalf("raw msg path: want nil, got %v", err)
		}
	})

	t.Run("returns identical bytes on no foreign allocation", func(t *testing.T) {
		// Defensive: helper must not mutate caller's slices.
		msg := []byte{0x10, 0x20}
		sig := make([]byte, crypto.Dilithium3SignatureSize)
		sigBackup := append([]byte(nil), sig...)
		pubBackup := append([]byte(nil), pubBytes...)
		fromBackup := from
		_ = VerifySingleSigBinding(from, pubBytes, msg, sig) // expect error (sig is zero), ignore
		if !bytes.Equal(sig, sigBackup) {
			t.Fatalf("helper mutated sig slice")
		}
		if !bytes.Equal(pubBytes, pubBackup) {
			t.Fatalf("helper mutated pub slice")
		}
		if fromBackup != from {
			t.Fatalf("helper mutated from address")
		}
	})
}

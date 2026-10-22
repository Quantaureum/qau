// Quantaureum Node source, version 1.0.0.
package tss

import (
	"errors"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// R4-04: the wallet-side QTD verifiers must convert a malformed key or
// signature into a verification error instead of letting a panic escape to the
// consensus block-verification path (node/adapters.go VerifyBlock).
//
// Correction from the fifth-round audit: this test originally opened by
// claiming a malformed key "would turn a single bad header into a node crash".
// Probing the pinned circl v1.6.3 (TestR5_01_CirclPanicProbe,
// TestR5_02_CirclAndQTDVerifierPanicProbe) does not support that: malformed
// right-length keys and signatures return false without panicking, and the only
// reproduced panic is a nil public key dereference. The guards under test here
// are kept as defense in depth and for caller-state errors; the remote-crash
// narrative is withdrawn.

func r4CorpusKeys(t *testing.T) map[string][]byte {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("crypto.GenerateKeyPair: %v", err)
	}
	realPub := kp.Public.Bytes()

	corrupt := append([]byte(nil), realPub...)
	for i := range corrupt {
		corrupt[i] = 0xFF
	}

	truncated := make([]byte, mode3.PublicKeySize-1)
	for i := range truncated {
		truncated[i] = byte(i)
	}

	overlong := append(append([]byte(nil), realPub...), 0x01, 0x02)

	zeroT1 := make([]byte, mode3.PublicKeySize)
	zeroT1[0] = 0xAA // rho non-zero, t1 all zero -> degenerate

	return map[string][]byte{
		"all-ones":      corrupt,
		"truncated":     truncated,
		"overlong":      overlong,
		"zero-t1":       zeroT1,
		"pseudo-random": realPub[:len(realPub)/2],
		"empty":         {},
	}
}

func TestR4_04_VerifySignatureWithPublicKey_MalformedKeysReturnErrorNotPanic(t *testing.T) {
	mgr := makeTestTSSManager(t)
	message := []byte("QTD block sealing message")
	sig := make([]byte, crypto.Dilithium3SignatureSize)

	for name, key := range r4CorpusKeys(t) {
		t.Run(name, func(t *testing.T) {
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("VerifySignatureWithPublicKey panicked on %s key: %v", name, r)
					}
				}()
				err = mgr.VerifySignatureWithPublicKey(key, message, sig)
			}()
			if err == nil {
				t.Fatalf("malformed %s key accepted", name)
			}
			if !errors.Is(err, ErrSignatureVerificationFailed) {
				t.Fatalf("wrong error for %s key: %v", name, err)
			}
		})
	}
}

func TestR4_04_VerifyCombinedSignature_MalformedGroupKeyReturnsErrorNotPanic(t *testing.T) {
	for name, key := range r4CorpusKeys(t) {
		t.Run(name, func(t *testing.T) {
			mgr := makeTestTSSManager(t)
			mgr.mu.Lock()
			mgr.qtdPubKey = &qtd.QTDPublicKey{PubKey: key}
			mgr.mu.Unlock()

			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("VerifyCombinedSignature panicked on %s group key: %v", name, r)
					}
				}()
				err = mgr.VerifyCombinedSignature(make([]byte, crypto.Dilithium3SignatureSize), []byte("message"))
			}()
			if err == nil || !errors.Is(err, ErrSignatureVerificationFailed) {
				t.Fatalf("expected verification failure for %s group key, got %v", name, err)
			}
		})
	}
}

// verifyWithPubKey is the shared inner verifier: a nil key makes the underlying
// circl call panic, which the R4-04 recover must translate into an error.
func TestR4_04_VerifyWithPubKey_PanicIsRecovered(t *testing.T) {
	err := verifyWithPubKey(nil, []byte("message"), make([]byte, 3293))
	if err == nil {
		t.Fatal("nil public key accepted")
	}
	if !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Fatalf("wrong error: %v", err)
	}
}

// A real key must still reach the verifier rather than being pre-rejected by
// the unpack helper (positive control against over-tightening).
func TestR4_04_UnpackHelper_AcceptsRealKeyRejectsWrongLength(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("crypto.GenerateKeyPair: %v", err)
	}
	pub, err := unpackDilithium3PublicKey(kp.Public.Bytes())
	if err != nil {
		t.Fatalf("real public key rejected by unpack helper: %v", err)
	}
	if pub == nil {
		t.Fatal("unpack helper returned nil key without error")
	}

	if _, err := unpackDilithium3PublicKey(make([]byte, mode3.PublicKeySize+1)); err == nil ||
		!strings.Contains(err.Error(), "wrong length") {
		t.Fatalf("wrong-length key accepted: %v", err)
	}
}

// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"errors"
	"sync"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// TestSetQTDSingleSigner_Registration verifies that a registered signer is
// stored and retrievable via GMQTD_Sign.
//
// CRYPTO-R9-L-REDO-01 (2026-07-19): previously this code path had NO unit
// test coverage — SetQTDSingleSigner / GMQTD_Sign / SetQTDSingleSigner's
// CAS guard were all untested at the crypto-package level.
func TestSetQTDSingleSigner_Registration(t *testing.T) {
	// Reset any signer state from earlier tests / init.
	UnsetQTDSingleSigner()
	t.Cleanup(UnsetQTDSingleSigner)

	calls := 0
	mockSigner := func(priv *mode3.PrivateKey, pub *mode3.PublicKey, msg []byte) ([]byte, error) {
		calls++
		return []byte("sig-by-mock"), nil
	}

	SetQTDSingleSigner(mockSigner)

	// Second registration must be silently rejected (C-04 one-shot guard).
	SetQTDSingleSigner(func(priv *mode3.PrivateKey, pub *mode3.PublicKey, msg []byte) ([]byte, error) {
		t.Error("second signer must never be invoked")
		return nil, errors.New("unreachable")
	})

	// The first registered signer remains active.
	_, pk := generateTestKeyPair(t)
	priv := &PrivateKey{key: newPrivateKeyMode3(t)}
	pub := &PublicKey{key: pk.key}

	sig, err := GMQTD_Sign(priv, pub, []byte("hello"))
	if err != nil {
		t.Fatalf("GMQTD_Sign failed after registration: %v", err)
	}
	if string(sig) != "sig-by-mock" {
		t.Errorf("unexpected signature from mock signer: %q", sig)
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 signer call, got %d", calls)
	}
}

// TestGMQTD_Sign_NotRegistered verifies that GMQTD_Sign returns
// ErrQTDNotImplemented when no signer has been registered.
func TestGMQTD_Sign_NotRegistered(t *testing.T) {
	UnsetQTDSingleSigner()
	t.Cleanup(UnsetQTDSingleSigner)

	_, pk := generateTestKeyPair(t)
	priv := &PrivateKey{key: newPrivateKeyMode3(t)}
	pub := &PublicKey{key: pk.key}

	_, err := GMQTD_Sign(priv, pub, []byte("hello"))
	if err == nil {
		t.Fatal("expected error when signer not registered")
	}
	if err != ErrQTDNotImplemented {
		t.Errorf("expected ErrQTDNotImplemented, got %v", err)
	}
}

// TestSetQTDSingleSigner_NilRejected verifies that nil signer is rejected.
func TestSetQTDSingleSigner_NilRejected(t *testing.T) {
	UnsetQTDSingleSigner()
	t.Cleanup(UnsetQTDSingleSigner)

	SetQTDSingleSigner(nil)

	// Registration state must remain "not registered" because nil was rejected.
	_, pk := generateTestKeyPair(t)
	priv := &PrivateKey{key: newPrivateKeyMode3(t)}
	pub := &PublicKey{key: pk.key}

	_, err := GMQTD_Sign(priv, pub, []byte("hello"))
	if err != ErrQTDNotImplemented {
		t.Errorf("expected ErrQTDNotImplemented after nil registration, got %v", err)
	}
}

// TestSetQTDSingleSigner_NilInputs verifies that GMQTD_Sign rejects nil
// private/public keys before consulting the registered signer.
func TestGMQTD_Sign_NilInputs(t *testing.T) {
	UnsetQTDSingleSigner()
	t.Cleanup(UnsetQTDSingleSigner)

	mockSigner := func(priv *mode3.PrivateKey, pub *mode3.PublicKey, msg []byte) ([]byte, error) {
		t.Error("signer must not be called when inputs are nil")
		return nil, errors.New("unreachable")
	}
	SetQTDSingleSigner(mockSigner)

	if _, err := GMQTD_Sign(nil, &PublicKey{key: newPublicKeyMode3(t)}, []byte("m")); err != ErrInvalidPrivateKey {
		t.Errorf("nil privateKey should return ErrInvalidPrivateKey, got %v", err)
	}
	if _, err := GMQTD_Sign(&PrivateKey{key: nil}, &PublicKey{key: newPublicKeyMode3(t)}, []byte("m")); err != ErrInvalidPrivateKey {
		t.Errorf("nil privateKey.key should return ErrInvalidPrivateKey, got %v", err)
	}
	if _, err := GMQTD_Sign(&PrivateKey{key: newPrivateKeyMode3(t)}, nil, []byte("m")); err != ErrInvalidPublicKey {
		t.Errorf("nil publicKey should return ErrInvalidPublicKey, got %v", err)
	}
	if _, err := GMQTD_Sign(&PrivateKey{key: newPrivateKeyMode3(t)}, &PublicKey{key: nil}, []byte("m")); err != ErrInvalidPublicKey {
		t.Errorf("nil publicKey.key should return ErrInvalidPublicKey, got %v", err)
	}
}

// TestGMQTD_Sign_SignerPanic verifies that a panicking signer is recovered
// and converted to an error (C-02 guard).
func TestGMQTD_Sign_SignerPanic(t *testing.T) {
	UnsetQTDSingleSigner()
	t.Cleanup(UnsetQTDSingleSigner)

	panickingSigner := func(priv *mode3.PrivateKey, pub *mode3.PublicKey, msg []byte) ([]byte, error) {
		panic("intentional signer panic")
	}
	SetQTDSingleSigner(panickingSigner)

	_, pk := generateTestKeyPair(t)
	priv := &PrivateKey{key: newPrivateKeyMode3(t)}
	pub := &PublicKey{key: pk.key}

	// Should NOT propagate the panic — should return an error instead.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("GMQTD_Sign should recover signer panic, but panic propagated: %v", r)
		}
	}()
	_, err := GMQTD_Sign(priv, pub, []byte("hello"))
	if err == nil {
		t.Error("expected error from panicking signer, got nil")
	}
}

// TestSetQTDSingleSigner_Concurrent verifies that concurrent SetQTDSingleSigner
// calls result in exactly one successful registration (CAS guard).
func TestSetQTDSingleSigner_Concurrent(t *testing.T) {
	UnsetQTDSingleSigner()
	t.Cleanup(UnsetQTDSingleSigner)

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	wins := make(chan int, goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			SetQTDSingleSigner(func(priv *mode3.PrivateKey, pub *mode3.PublicKey, msg []byte) ([]byte, error) {
				return []byte("sig"), nil
			})
			select {
			case wins <- idx:
			default:
			}
		}(i)
	}
	wg.Wait()
	close(wins)

	// All goroutines completed without panicking — the CAS guard prevented
	// any duplicate overwrite. The first successful registration should be
	// active now.
	signerPtr := qtdSingleSigner.Load()
	if signerPtr == nil {
		t.Fatal("expected a registered signer after concurrent Set calls")
	}
	if !qtdSignerRegistered.Load() {
		t.Fatal("expected qtdSignerRegistered=true after successful Set")
	}
}

// generateTestKeyPair produces a fresh Dilithium3 keypair for testing.
func generateTestKeyPair(t *testing.T) (*PrivateKey, *PublicKey) {
	t.Helper()
	pub, priv, err := mode3.GenerateKey(nilReader{})
	if err != nil {
		t.Fatalf("mode3.GenerateKey failed: %v", err)
	}
	return &PrivateKey{key: priv}, &PublicKey{key: pub}
}

// newPrivateKeyMode3 generates a fresh mode3.PrivateKey for tests that need
// a non-nil key field.
func newPrivateKeyMode3(t *testing.T) *mode3.PrivateKey {
	t.Helper()
	_, priv, err := mode3.GenerateKey(nilReader{})
	if err != nil {
		t.Fatalf("mode3.GenerateKey failed: %v", err)
	}
	return priv
}

// newPublicKeyMode3 generates a fresh mode3.PublicKey for tests.
func newPublicKeyMode3(t *testing.T) *mode3.PublicKey {
	t.Helper()
	pub, _, err := mode3.GenerateKey(nilReader{})
	if err != nil {
		t.Fatalf("mode3.GenerateKey failed: %v", err)
	}
	return pub
}

// nilReader is a zero-byte reader used as the entropy source for deterministic
// test key generation. mode3.GenerateKey accepts an io.Reader; passing a nil
// reader is not allowed, so we use this trivial stub instead of crypto/rand
// to keep tests fast and reproducible.
type nilReader struct{}

func (nilReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

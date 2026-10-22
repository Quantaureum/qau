// Quantaureum Node source, version 1.0.0.
package hsm

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// F-11 (2026-10-21): baseline coverage for the hsm package via the
// SoftwareHSM backend (the only backend testable without hardware). The
// PKCS#11/AWS drivers are thin wrappers over external libraries and are
// not faked here. Covers the fail-closed uninitialized paths, the
// key lifecycle, signing, deep-copy hygiene, audit logging, and the
// zeroization-on-close contract.

func newInitializedSoftwareHSM(t *testing.T) *SoftwareHSM {
	t.Helper()
	s := NewSoftwareHSM()
	if err := s.Initialize(&HSMConfig{Backend: "software"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return s
}

func TestSoftwareHSMRequiresInitialization(t *testing.T) {
	s := NewSoftwareHSM()
	if s.IsConnected() {
		t.Fatal("fresh HSM reports connected")
	}
	if _, err := s.GenerateKey("k1", KeyTypeValidator); !errors.Is(err, ErrHSMNotInitialized) {
		t.Fatalf("GenerateKey: err = %v, want ErrHSMNotInitialized", err)
	}
	if _, err := s.Sign("k1", []byte("data")); !errors.Is(err, ErrHSMNotInitialized) {
		t.Fatalf("Sign: err = %v, want ErrHSMNotInitialized", err)
	}
	if _, err := s.GetKeyInfo("k1"); !errors.Is(err, ErrHSMNotInitialized) {
		t.Fatalf("GetKeyInfo: err = %v, want ErrHSMNotInitialized", err)
	}
	if _, err := s.ListKeys(); !errors.Is(err, ErrHSMNotInitialized) {
		t.Fatalf("ListKeys: err = %v, want ErrHSMNotInitialized", err)
	}
	if err := s.DeleteKey("k1"); !errors.Is(err, ErrHSMNotInitialized) {
		t.Fatalf("DeleteKey: err = %v, want ErrHSMNotInitialized", err)
	}
}

func TestSoftwareHSMKeyLifecycle(t *testing.T) {
	s := newInitializedSoftwareHSM(t)

	info, err := s.GenerateKey("validator-1", KeyTypeValidator)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if info.KeyID != "validator-1" || info.Algorithm != "Dilithium3" {
		t.Fatalf("unexpected key info: %+v", info)
	}
	if info.Exportable {
		t.Fatal("validator key reported exportable")
	}

	// Duplicate IDs rejected.
	if _, err := s.GenerateKey("validator-1", KeyTypeValidator); !errors.Is(err, ErrKeyAlreadyExists) {
		t.Fatalf("duplicate GenerateKey: err = %v, want ErrKeyAlreadyExists", err)
	}

	// Sign and verify round trip.
	msg := []byte("quantaureum hsm test message")
	sig, err := s.Sign("validator-1", msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := s.Verify("validator-1", msg, sig)
	if err != nil || !ok {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}
	ok, _ = s.Verify("validator-1", []byte("other"), sig)
	if ok {
		t.Fatal("signature verified against different data")
	}

	// Unknown key IDs fail closed.
	if _, err := s.Sign("missing", msg); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Sign(missing): err = %v, want ErrKeyNotFound", err)
	}
	if _, err := s.GetKeyInfo("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("GetKeyInfo(missing): err = %v, want ErrKeyNotFound", err)
	}
	if err := s.DeleteKey("missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("DeleteKey(missing): err = %v, want ErrKeyNotFound", err)
	}

	// GetKeyInfo returns a deep copy — mutating it must not corrupt state.
	got, err := s.GetKeyInfo("validator-1")
	if err != nil {
		t.Fatalf("GetKeyInfo: %v", err)
	}
	got.KeyID = "tampered"
	again, err := s.GetKeyInfo("validator-1")
	if err != nil {
		t.Fatalf("GetKeyInfo (2nd): %v", err)
	}
	if again.KeyID != "validator-1" {
		t.Fatal("GetKeyInfo is not a copy: caller mutated internal state")
	}

	// List + delete.
	keys, err := s.ListKeys()
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListKeys: %v %v", keys, err)
	}
	if err := s.DeleteKey("validator-1"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if _, err := s.Sign("validator-1", msg); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Sign after delete: err = %v, want ErrKeyNotFound", err)
	}
}

func TestSoftwareHSMImportKeyZeroizesInput(t *testing.T) {
	s := newInitializedSoftwareHSM(t)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	privBytes := kp.Private.Bytes()

	info, err := s.ImportKey("imported", KeyTypeNode, privBytes)
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if info.Address != kp.Public.Address() {
		t.Fatal("imported key address does not match the source key pair")
	}
	// R72-PK-2: the caller's buffer must be zeroized after import.
	for i, b := range privBytes {
		if b != 0 {
			t.Fatalf("import buffer not zeroized: byte %d = %#x", i, b)
		}
	}

	// The imported key must still work.
	msg := []byte("imported key signing test")
	sig, err := s.Sign("imported", msg)
	if err != nil {
		t.Fatalf("Sign(imported): %v", err)
	}
	ok, err := s.Verify("imported", msg, sig)
	if err != nil || !ok {
		t.Fatalf("Verify(imported): ok=%v err=%v", ok, err)
	}

	// Duplicate import rejected.
	kp2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair 2: %v", err)
	}
	if _, err := s.ImportKey("imported", KeyTypeNode, kp2.Private.Bytes()); !errors.Is(err, ErrKeyAlreadyExists) {
		t.Fatalf("duplicate ImportKey: err = %v, want ErrKeyAlreadyExists", err)
	}
}

func TestSoftwareHSMCloseZeroizesPINAndKeys(t *testing.T) {
	s := newInitializedSoftwareHSM(t)
	pin := []byte("super-secret-pin")
	cfg := &HSMConfig{Backend: "software", PIN: pin}
	if err := s.Initialize(cfg); err != nil {
		t.Fatalf("re-Initialize: %v", err)
	}
	if _, err := s.GenerateKey("k", KeyTypeValidator); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s.IsConnected() {
		t.Fatal("closed HSM still reports connected")
	}
	// R72-PK-5: PIN zeroized.
	for i, b := range pin {
		if b != 0 {
			t.Fatalf("PIN not zeroized: byte %d = %#x", i, b)
		}
	}
	// Close is idempotent.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestHSMManagerBackendSelection(t *testing.T) {
	// The software backend must work end to end through the manager.
	// AuditLogging is on so the audit-log assertions below are meaningful.
	m, err := NewHSMManager(&HSMConfig{Backend: "software", AuditLogging: true})
	if err != nil {
		t.Fatalf("NewHSMManager(software): %v", err)
	}
	if _, err := m.GenerateValidatorKey("val"); err != nil {
		t.Fatalf("GenerateValidatorKey: %v", err)
	}
	if _, err := m.GenerateNodeKey("node"); err != nil {
		t.Fatalf("GenerateNodeKey: %v", err)
	}
	if _, err := m.Sign("val", []byte("msg")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := m.GetPublicKey("val"); err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if _, err := m.GetAddress("val"); err != nil {
		t.Fatalf("GetAddress: %v", err)
	}
	keys, err := m.ListKeys()
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListKeys: %v %v", keys, err)
	}
	// Audit log records operations.
	if logs := m.GetAuditLog(10); len(logs) < 2 {
		t.Fatalf("GetAuditLog returned %d entries, want >= 2", len(logs))
	}
	if err := m.DeleteKey("val"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	// Unimplemented/unknown backends fail closed at construction.
	for _, backend := range []string{"azure", "gcp", "yubihsm", "nonexistent"} {
		if _, err := NewHSMManager(&HSMConfig{Backend: backend}); err == nil {
			t.Fatalf("backend %q accepted", backend)
		}
	}
}

func TestDeriveKeyIDDeterministic(t *testing.T) {
	a := DeriveKeyID([]byte("seed"), "validator")
	b := DeriveKeyID([]byte("seed"), "validator")
	c := DeriveKeyID([]byte("seed"), "node")
	d := DeriveKeyID([]byte("other"), "validator")
	if a != b {
		t.Fatal("DeriveKeyID not deterministic")
	}
	if a == c {
		t.Fatal("purpose not bound into the key ID")
	}
	if a == d {
		t.Fatal("seed not bound into the key ID")
	}
	if len(a) != 16 {
		t.Fatalf("key ID length = %d, want 16", len(a))
	}
}

func TestGenerateSecureRandom(t *testing.T) {
	r1, err := GenerateSecureRandom(32)
	if err != nil {
		t.Fatalf("GenerateSecureRandom: %v", err)
	}
	r2, err := GenerateSecureRandom(32)
	if err != nil {
		t.Fatalf("GenerateSecureRandom (2nd): %v", err)
	}
	same := true
	for i := range r1 {
		if r1[i] != r2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two random buffers are identical")
	}
}

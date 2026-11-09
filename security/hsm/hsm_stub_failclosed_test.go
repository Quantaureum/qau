// Quantaureum Node source, version 1.0.0.
package hsm

import (
	"errors"
	"strings"
	"testing"
)

// Regression tests for audit run-13 finding B7
// (qau.hsm/cloud-pkcs11-software-stub-failopen, HIGH).
//
// Before the fix, the "pkcs11" and "aws" factory entries handed back
// complete software simulations that report full HSM capability: a
// validator operator configuring an HSM silently received in-process
// plaintext key equivalents with no hardware protection and no error. The
// fix makes both stubs fail closed at the factory AND at direct
// Initialize, while the explicitly-unprotected "software" backend keeps
// working for dev/test.

// TestHSMStubBackendsRefuseConstruction verifies the factory refuses the
// pkcs11 and aws backends with an error naming the software-stub status,
// and produces no manager (and therefore no keys).
func TestHSMStubBackendsRefuseConstruction(t *testing.T) {
	for _, backend := range []string{"pkcs11", "aws"} {
		t.Run(backend, func(t *testing.T) {
			m, err := NewHSMManager(&HSMConfig{
				Backend:           backend,
				ConnectionString:  "stub-test",
				ConnectionTimeout: 1_000_000_000,
				OperationTimeout:  1_000_000_000,
			})
			if err == nil {
				t.Fatalf("B7 REGRESSION: backend %q must be refused at construction", backend)
			}
			if m != nil {
				t.Fatalf("B7 REGRESSION: backend %q must not return a manager", backend)
			}
			if !strings.Contains(err.Error(), "software stub") {
				t.Fatalf("error must name the software-stub status, got: %v", err)
			}
		})
	}
}

// TestHSMStubInitializeRefused verifies that even direct construction of the
// stub types cannot be initialized: Initialize always errors, IsConnected
// stays false, and no key operation can ever succeed — so no KeyPair can be
// produced through these types.
func TestHSMStubInitializeRefused(t *testing.T) {
	t.Run("pkcs11", func(t *testing.T) {
		p := NewPKCS11HSM()
		if err := p.Initialize(&HSMConfig{Backend: "pkcs11", ConnectionString: "stub"}); err == nil {
			t.Fatal("B7 REGRESSION: PKCS11HSM.Initialize must refuse (software stub)")
		}
		if p.IsConnected() {
			t.Fatal("B7 REGRESSION: PKCS11HSM must not report connected")
		}
		if _, err := p.GenerateKey("validator-1", KeyTypeValidator); !errors.Is(err, ErrHSMNotInitialized) {
			t.Fatalf("B7 REGRESSION: GenerateKey must fail with ErrHSMNotInitialized, got: %v", err)
		}
		if _, err := p.ImportKey("validator-1", KeyTypeValidator, []byte("key")); !errors.Is(err, ErrHSMNotInitialized) {
			t.Fatalf("B7 REGRESSION: ImportKey must fail with ErrHSMNotInitialized, got: %v", err)
		}
		keys, err := p.ListKeys()
		if !errors.Is(err, ErrHSMNotInitialized) {
			t.Fatalf("B7 REGRESSION: ListKeys must fail closed with ErrHSMNotInitialized, got: %v %v", keys, err)
		}
		if len(keys) != 0 {
			t.Fatalf("B7 REGRESSION: no keys may exist in the stub, got: %v", keys)
		}
	})

	t.Run("aws", func(t *testing.T) {
		a := NewAWSCloudHSM()
		if err := a.Initialize(&HSMConfig{Backend: "aws", ConnectionString: "stub"}); err == nil {
			t.Fatal("B7 REGRESSION: AWSCloudHSM.Initialize must refuse (software stub)")
		}
		if a.IsConnected() {
			t.Fatal("B7 REGRESSION: AWSCloudHSM must not report connected")
		}
		if _, err := a.GenerateKey("validator-1", KeyTypeValidator); !errors.Is(err, ErrHSMNotInitialized) {
			t.Fatalf("B7 REGRESSION: GenerateKey must fail with ErrHSMNotInitialized, got: %v", err)
		}
		if _, err := a.ImportKey("validator-1", KeyTypeValidator, []byte("key")); !errors.Is(err, ErrHSMNotInitialized) {
			t.Fatalf("B7 REGRESSION: ImportKey must fail with ErrHSMNotInitialized, got: %v", err)
		}
		keys, err := a.ListKeys()
		if !errors.Is(err, ErrHSMNotInitialized) {
			t.Fatalf("B7 REGRESSION: ListKeys must fail closed with ErrHSMNotInitialized, got: %v %v", keys, err)
		}
		if len(keys) != 0 {
			t.Fatalf("B7 REGRESSION: no keys may exist in the stub, got: %v", keys)
		}
	})
}

// TestSoftwareBackendStillWorks verifies the explicitly-unprotected software
// backend remains constructible and functional, so dev/test workflows are
// unaffected by the B7 fail-closed change.
func TestSoftwareBackendStillWorks(t *testing.T) {
	m, err := NewHSMManager(&HSMConfig{Backend: "software"})
	if err != nil {
		t.Fatalf("software backend must still construct: %v", err)
	}
	info, err := m.GenerateValidatorKey("b7-validator")
	if err != nil {
		t.Fatalf("software backend must still generate keys: %v", err)
	}
	if info.KeyID != "b7-validator" {
		t.Fatalf("unexpected key info: %+v", info)
	}
}

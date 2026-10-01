// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"testing"
)

func TestReshareMaskedTermCommitReveal(t *testing.T) {
	var sessionID [32]byte
	sessionID[0] = 0x6c
	var salt [32]byte
	salt[0] = 0x7d
	commitment, err := CommitReshareMaskedTerm(sessionID, 2, 3, 1, 9, 123456, salt)
	if err != nil {
		t.Fatalf("CommitReshareMaskedTerm(): %v", err)
	}
	if err := VerifyReshareMaskedTerm(commitment, sessionID, 2, 3, 1, 9, 123456, salt); err != nil {
		t.Fatalf("VerifyReshareMaskedTerm(): %v", err)
	}
}

func TestReshareMaskedTermRejectsTampering(t *testing.T) {
	var sessionID [32]byte
	sessionID[0] = 0x8e
	var salt [32]byte
	salt[0] = 0x9f
	commitment, err := CommitReshareMaskedTerm(sessionID, 4, 5, 2, 10, 654321, salt)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReshareMaskedTerm(commitment, sessionID, 4, 5, 2, 10, 654322, salt); !errors.Is(err, ErrInvalidReshareMaskedTerm) {
		t.Fatalf("tampered term error = %v, want %v", err, ErrInvalidReshareMaskedTerm)
	}
	tamperedSalt := salt
	tamperedSalt[1] = 1
	if err := VerifyReshareMaskedTerm(commitment, sessionID, 4, 5, 2, 10, 654321, tamperedSalt); !errors.Is(err, ErrInvalidReshareMaskedTerm) {
		t.Fatalf("tampered salt error = %v, want %v", err, ErrInvalidReshareMaskedTerm)
	}
}

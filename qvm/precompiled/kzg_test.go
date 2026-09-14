// Quantaureum Node source, version 1.0.0.
package precompiled

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestKZGPointEvaluation_Address(t *testing.T) {
	c := newKZGPointEvaluation()
	expected := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A}
	if c.Address() != expected {
		t.Errorf("address mismatch: got %x, want %x", c.Address(), expected)
	}
}

func TestKZGPointEvaluation_RequiredGas(t *testing.T) {
	c := newKZGPointEvaluation()
	input := make([]byte, 192)
	gas := c.RequiredGas(input)
	if gas != 50000 {
		t.Errorf("gas mismatch: got %d, want 50000", gas)
	}
}

func TestKZGPointEvaluation_ValidInput(t *testing.T) {
	c := newKZGPointEvaluation()
	input := make([]byte, 192)
	// Fill with non-zero data to verify we don't depend on content
	for i := range input {
		input[i] = byte(i)
	}

	// FIX: KZG verification is fail-closed until full implementation.
	// The previous test expected success, but returning success for unverified
	// KZG proofs is a security vulnerability. Now the contract correctly
	// rejects all inputs until a real KZG implementation is available.
	output, err := c.Run(input)
	if err == nil {
		t.Fatalf("expected error (fail-closed), got output: %x", output)
	}
}

func TestKZGPointEvaluation_InvalidInputLength(t *testing.T) {
	c := newKZGPointEvaluation()

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", make([]byte, 0)},
		{"too short", make([]byte, 191)},
		{"too long", make([]byte, 193)},
		{"partial", make([]byte, 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Run(tt.input)
			if err == nil {
				t.Error("expected error for invalid input length, got nil")
			}
		})
	}
}

func TestKZGPointEvaluation_RegistryAddress(t *testing.T) {
	r := NewRegistry()
	addr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A}
	c := r.Get(addr)
	if c == nil {
		t.Fatal("KZG contract not found at address 0x0A")
	}
	gas := c.RequiredGas(make([]byte, 192))
	if gas != 50000 {
		t.Errorf("gas mismatch from registry: got %d, want 50000", gas)
	}
}

func TestKZGPointEvaluation_RegistryRun(t *testing.T) {
	r := NewRegistry()
	addr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A}
	input := make([]byte, 192)

	// FIX: KZG verification is fail-closed until full implementation.
	output, gasUsed, err := r.Run(addr, input, 100000)
	if err == nil {
		t.Fatalf("expected error (fail-closed), got output: %x, gasUsed: %d", output, gasUsed)
	}
}

func TestKZGPointEvaluation_RegistryOutOfGas(t *testing.T) {
	r := NewRegistry()
	addr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A}
	input := make([]byte, 192)

	_, _, err := r.Run(addr, input, 49999)
	if err != ErrOutOfGas {
		t.Errorf("expected ErrOutOfGas, got: %v", err)
	}
}

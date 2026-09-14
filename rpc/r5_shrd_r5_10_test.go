// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR5_SHRD_R5_10_ParseHexAddressRejectsOverlong verifies that
// parseHexAddress rejects an overlong input (21 bytes instead of 20).
// Previously, the overlong input was silently truncated, which could
// cause address confusion.
func TestR5_SHRD_R5_10_ParseHexAddressRejectsOverlong(t *testing.T) {
	overlong := make([]byte, 21) // 21 bytes, should be 20
	for i := range overlong {
		overlong[i] = byte(i + 1)
	}
	_, err := parseHexAddress(hex.EncodeToString(overlong))
	if err == nil {
		t.Fatal("SHRD-R5-10: expected error for overlong address (21 bytes)")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Errorf("SHRD-R5-10: error should mention length, got: %v", err)
	}
}

// TestR5_SHRD_R5_10_ParseHexAddressRejectsShort verifies that
// parseHexAddress rejects a short input (19 bytes instead of 20).
// Previously, the short input was zero-padded, which could cause
// address confusion or misleading success responses.
func TestR5_SHRD_R5_10_ParseHexAddressRejectsShort(t *testing.T) {
	short := make([]byte, 19) // 19 bytes, should be 20
	for i := range short {
		short[i] = byte(i + 1)
	}
	_, err := parseHexAddress(hex.EncodeToString(short))
	if err == nil {
		t.Fatal("SHRD-R5-10: expected error for short address (19 bytes)")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Errorf("SHRD-R5-10: error should mention length, got: %v", err)
	}
}

// TestR5_SHRD_R5_10_ParseHexAddressAcceptsExact20Bytes verifies that a
// valid 20-byte address is accepted. This is the happy path.
func TestR5_SHRD_R5_10_ParseHexAddressAcceptsExact20Bytes(t *testing.T) {
	expected := types.Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14}
	got, err := parseHexAddress("0x" + hex.EncodeToString(expected[:]))
	if err != nil {
		t.Fatalf("SHRD-R5-10: valid 20-byte address should be accepted, got: %v", err)
	}
	if got != expected {
		t.Errorf("SHRD-R5-10: address mismatch: expected %x, got %x", expected, got)
	}
}

// TestR5_SHRD_R5_10_ParseHexHashRejectsOverlong verifies that parseHexHash
// rejects an overlong input (33 bytes instead of 32).
func TestR5_SHRD_R5_10_ParseHexHashRejectsOverlong(t *testing.T) {
	overlong := make([]byte, 33) // 33 bytes, should be 32
	for i := range overlong {
		overlong[i] = byte(i + 1)
	}
	_, err := parseHexHash(hex.EncodeToString(overlong))
	if err == nil {
		t.Fatal("SHRD-R5-10: expected error for overlong hash (33 bytes)")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Errorf("SHRD-R5-10: error should mention length, got: %v", err)
	}
}

// TestR5_SHRD_R5_10_ParseHexHashRejectsShort verifies that parseHexHash
// rejects a short input (31 bytes instead of 32).
func TestR5_SHRD_R5_10_ParseHexHashRejectsShort(t *testing.T) {
	short := make([]byte, 31) // 31 bytes, should be 32
	for i := range short {
		short[i] = byte(i + 1)
	}
	_, err := parseHexHash(hex.EncodeToString(short))
	if err == nil {
		t.Fatal("SHRD-R5-10: expected error for short hash (31 bytes)")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Errorf("SHRD-R5-10: error should mention length, got: %v", err)
	}
}

// TestR5_SHRD_R5_10_ParseHexHashAcceptsExact32Bytes verifies that a valid
// 32-byte hash is accepted. This is the happy path.
func TestR5_SHRD_R5_10_ParseHexHashAcceptsExact32Bytes(t *testing.T) {
	expected := types.Hash{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	got, err := parseHexHash("0x" + hex.EncodeToString(expected[:]))
	if err != nil {
		t.Fatalf("SHRD-R5-10: valid 32-byte hash should be accepted, got: %v", err)
	}
	if got != expected {
		t.Errorf("SHRD-R5-10: hash mismatch: expected %x, got %x", expected, got)
	}
}

// TestR5_SHRD_R5_10_ParseHexAddressRejectsEmpty verifies that an empty
// input is rejected (0 bytes, should be 20).
func TestR5_SHRD_R5_10_ParseHexAddressRejectsEmpty(t *testing.T) {
	_, err := parseHexAddress("")
	if err == nil {
		t.Fatal("SHRD-R5-10: expected error for empty address")
	}
}

// TestR5_SHRD_R5_10_ParseHexHashRejectsEmpty verifies that an empty
// input is rejected (0 bytes, should be 32).
func TestR5_SHRD_R5_10_ParseHexHashRejectsEmpty(t *testing.T) {
	_, err := parseHexHash("")
	if err == nil {
		t.Fatal("SHRD-R5-10: expected error for empty hash")
	}
}

// TestR5_SHRD_R5_10_ParseHexAddressRejectsEmptyWith0x verifies that "0x"
// (empty after prefix) is rejected.
func TestR5_SHRD_R5_10_ParseHexAddressRejectsEmptyWith0x(t *testing.T) {
	_, err := parseHexAddress("0x")
	if err == nil {
		t.Fatal("SHRD-R5-10: expected error for '0x' (empty address)")
	}
}

// Quantaureum Node source, version 1.0.0.
// RLP-R12-001 (2026-07-20): Regression tests for RLP integer decoding.
//
// Two issues were fixed in this round:
//  1. BigInt() did not enforce the same 1-byte canonical check that Uint()
//     has, allowing non-canonical String-kind encodings (0x81 + byte) of
//     small integers to be accepted — creating malleability where the same
//     value has two valid encodings depending on which decoder the caller
//     uses.
//  2. decodeValue for int8/16/32/uint8/16/32 silently truncated values
//     exceeding the target type's width (e.g., decoding 200 into int8
//     wrapped to -56).
//
// These tests pin both fixes so a future refactor cannot regress them.
package rlp

import (
	"errors"
	"math"
	"math/big"
	"testing"
)

// --- BigInt canonical check (Issue 1) --------------------------------------

// TestRLP_R12001_BigInt_RejectsNonCanonical1ByteStringKind verifies that the
// non-canonical encoding `0x81 0x42` (String kind, 1 byte, value 0x42) is
// rejected. The canonical form is the single byte `0x42` (Byte kind).
//
// Before the fix, BigInt() accepted this encoding while Uint() rejected it,
// creating a malleability vector where the same logical value had two valid
// encodings depending on which decoder the caller used.
func TestRLP_R12001_BigInt_RejectsNonCanonical1ByteStringKind(t *testing.T) {
	var v big.Int
	err := DecodeBytes([]byte{0x81, 0x42}, &v)
	if err == nil {
		t.Fatalf("BigInt accepted non-canonical 0x81 0x42 (String kind for value < 0x80); expected rejection")
	}
	// Accept either ErrCanonicalSize (from Bytes()) or ErrCanonicalInt
	// (from a future strengthening). Either way, the input must be rejected.
	if !errors.Is(err, ErrCanonicalSize) && !errors.Is(err, ErrCanonicalInt) {
		t.Errorf("expected canonical-form error, got %v", err)
	}
}

// TestRLP_R12001_BigInt_AcceptsCanonicalByteKind verifies that the canonical
// encoding `0x42` (Byte kind) is accepted by BigInt(). This is the security
// guard's complement: we must not regress legitimate small-integer decoding
// while rejecting the non-canonical form.
func TestRLP_R12001_BigInt_AcceptsCanonicalByteKind(t *testing.T) {
	var v big.Int
	if err := DecodeBytes([]byte{0x42}, &v); err != nil {
		t.Fatalf("BigInt rejected canonical Byte kind 0x42: %v", err)
	}
	if v.Int64() != 0x42 {
		t.Errorf("expected 0x42, got %v", &v)
	}
}

// TestRLP_R12001_BigInt_AcceptsCanonicalMultiByteString verifies that
// canonical multi-byte String-kind encodings (where the first byte is
// >= 0x80, making the String kind mandatory) still decode correctly.
func TestRLP_R12001_BigInt_AcceptsCanonicalMultiByteString(t *testing.T) {
	// 0x82 0x01 0x02 → 258. First byte 0x01 is non-zero, so canonical.
	var v big.Int
	if err := DecodeBytes([]byte{0x82, 0x01, 0x02}, &v); err != nil {
		t.Fatalf("BigInt rejected canonical 2-byte string: %v", err)
	}
	if v.Int64() != 258 {
		t.Errorf("expected 258, got %v", &v)
	}
}

// TestRLP_R12001_BigInt_ConsistentWithUint verifies that for the
// non-canonical 1-byte String-kind case, both BigInt() and Uint() reject
// the input (consistency property — the original malleability bug was that
// they disagreed).
func TestRLP_R12001_BigInt_ConsistentWithUint(t *testing.T) {
	nonCanonical := []byte{0x81, 0x42}

	var bi big.Int
	bigErr := DecodeBytes(nonCanonical, &bi)
	if bigErr == nil {
		t.Fatal("BigInt accepted non-canonical encoding; expected rejection")
	}

	var u uint64
	uintErr := DecodeBytes(nonCanonical, &u)
	if uintErr == nil {
		t.Fatal("Uint accepted non-canonical encoding; expected rejection")
	}

	// Both must reject — that's the consistency property. We do NOT require
	// the same error type because BigInt() routes through Bytes() (which
	// returns ErrCanonicalSize) while Uint() returns ErrCanonicalInt.
}

// --- Per-type range checks (Issue 2) ---------------------------------------
//
// RLP integers are canonically unsigned. The encoder rejects negative
// inputs, so any "negative" result from overflow is always wrong. These
// tests pin the per-type upper-bound check added in decodeValue.

// runDecodeErr executes DecodeBytes(input, &target) and returns the error.
// Using a generic helper keeps the per-type test bodies short and uniform.
func runDecodeErr(input []byte, target any) error {
	return DecodeBytes(input, target)
}

// int8 cases ----------------------------------------------------------------

func TestRLP_R12001_Int8_RejectsOverflow(t *testing.T) {
	// 200 = 0xC8. MaxInt8 = 127. Encoding: 0x81 0xC8 (canonical String kind,
	// since 0xC8 >= 0x80).
	var v int8
	err := runDecodeErr([]byte{0x81, 0xC8}, &v)
	if err == nil {
		t.Fatalf("int8 accepted 200 (overflows MaxInt8=127); got %d", v)
	}
	if !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestRLP_R12001_Int8_AcceptsMax(t *testing.T) {
	// MaxInt8 = 127 = 0x7F. Canonical encoding: 0x7F (Byte kind, since < 0x80).
	var v int8
	if err := runDecodeErr([]byte{0x7F}, &v); err != nil {
		t.Fatalf("int8 rejected MaxInt8 (127): %v", err)
	}
	if v != math.MaxInt8 {
		t.Errorf("expected %d, got %d", math.MaxInt8, v)
	}
}

// int16 cases ---------------------------------------------------------------

func TestRLP_R12001_Int16_RejectsOverflow(t *testing.T) {
	// 40000 > MaxInt16 (32767). 40000 = 0x9C40.
	// Encoding: 0x82 0x9C 0x40 (canonical String kind, first byte 0x9C >= 0x80).
	var v int16
	err := runDecodeErr([]byte{0x82, 0x9C, 0x40}, &v)
	if err == nil {
		t.Fatalf("int16 accepted 40000 (overflows MaxInt16=32767); got %d", v)
	}
	if !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestRLP_R12001_Int16_AcceptsMax(t *testing.T) {
	// MaxInt16 = 32767 = 0x7FFF. Encoding: 0x82 0x7F 0xFF (canonical).
	var v int16
	if err := runDecodeErr([]byte{0x82, 0x7F, 0xFF}, &v); err != nil {
		t.Fatalf("int16 rejected MaxInt16 (32767): %v", err)
	}
	if v != math.MaxInt16 {
		t.Errorf("expected %d, got %d", math.MaxInt16, v)
	}
}

// int32 cases ---------------------------------------------------------------

func TestRLP_R12001_Int32_RejectsOverflow(t *testing.T) {
	// MaxInt32 + 1 = 0x80000000. Encoding: 0x84 0x80 0x00 0x00 0x00
	// (canonical, first byte 0x80 != 0x00 so no leading-zero rule violation).
	var v int32
	err := runDecodeErr([]byte{0x84, 0x80, 0x00, 0x00, 0x00}, &v)
	if err == nil {
		t.Fatalf("int32 accepted 0x80000000 (overflows MaxInt32); got %d", v)
	}
	if !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestRLP_R12001_Int32_AcceptsMax(t *testing.T) {
	// MaxInt32 = 0x7FFFFFFF. Encoding: 0x84 0x7F 0xFF 0xFF 0xFF (canonical).
	var v int32
	if err := runDecodeErr([]byte{0x84, 0x7F, 0xFF, 0xFF, 0xFF}, &v); err != nil {
		t.Fatalf("int32 rejected MaxInt32: %v", err)
	}
	if v != math.MaxInt32 {
		t.Errorf("expected %d, got %d", math.MaxInt32, v)
	}
}

// uint8 cases ---------------------------------------------------------------

func TestRLP_R12001_Uint8_RejectsOverflow(t *testing.T) {
	// 300 > MaxUint8 (255). 300 = 0x012C. Encoding: 0x82 0x01 0x2C (canonical).
	var v uint8
	err := runDecodeErr([]byte{0x82, 0x01, 0x2C}, &v)
	if err == nil {
		t.Fatalf("uint8 accepted 300 (overflows MaxUint8=255); got %d", v)
	}
	if !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestRLP_R12001_Uint8_AcceptsMax(t *testing.T) {
	// MaxUint8 = 255 = 0xFF. Encoding: 0x81 0xFF (canonical String kind,
	// since 0xFF >= 0x80).
	var v uint8
	if err := runDecodeErr([]byte{0x81, 0xFF}, &v); err != nil {
		t.Fatalf("uint8 rejected MaxUint8 (255): %v", err)
	}
	if v != math.MaxUint8 {
		t.Errorf("expected %d, got %d", math.MaxUint8, v)
	}
}

// uint16 cases --------------------------------------------------------------

func TestRLP_R12001_Uint16_RejectsOverflow(t *testing.T) {
	// 70000 > MaxUint16 (65535). 70000 = 0x11170.
	// Encoding: 0x83 0x01 0x11 0x70 (canonical, first byte 0x01 != 0x00).
	var v uint16
	err := runDecodeErr([]byte{0x83, 0x01, 0x11, 0x70}, &v)
	if err == nil {
		t.Fatalf("uint16 accepted 70000 (overflows MaxUint16=65535); got %d", v)
	}
	if !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestRLP_R12001_Uint16_AcceptsMax(t *testing.T) {
	// MaxUint16 = 65535 = 0xFFFF. Encoding: 0x82 0xFF 0xFF (canonical).
	var v uint16
	if err := runDecodeErr([]byte{0x82, 0xFF, 0xFF}, &v); err != nil {
		t.Fatalf("uint16 rejected MaxUint16 (65535): %v", err)
	}
	if v != math.MaxUint16 {
		t.Errorf("expected %d, got %d", math.MaxUint16, v)
	}
}

// uint32 cases --------------------------------------------------------------

func TestRLP_R12001_Uint32_RejectsOverflow(t *testing.T) {
	// MaxUint32 + 1 = 0x100000000. Encoding: 0x85 0x01 0x00 0x00 0x00 0x00
	// (canonical, first byte 0x01 != 0x00).
	var v uint32
	err := runDecodeErr([]byte{0x85, 0x01, 0x00, 0x00, 0x00, 0x00}, &v)
	if err == nil {
		t.Fatalf("uint32 accepted 0x100000000 (overflows MaxUint32); got %d", v)
	}
	if !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestRLP_R12001_Uint32_AcceptsMax(t *testing.T) {
	// MaxUint32 = 0xFFFFFFFF. Encoding: 0x84 0xFF 0xFF 0xFF 0xFF (canonical).
	var v uint32
	if err := runDecodeErr([]byte{0x84, 0xFF, 0xFF, 0xFF, 0xFF}, &v); err != nil {
		t.Fatalf("uint32 rejected MaxUint32: %v", err)
	}
	if v != math.MaxUint32 {
		t.Errorf("expected %d, got %d", math.MaxUint32, v)
	}
}

// int64/uint64 boundary check (already covered by existing tests, but we
// add explicit guards to pin the per-type path going through decodeValue).

func TestRLP_R12001_Int64_AcceptsMax(t *testing.T) {
	// MaxInt64 = 0x7FFFFFFFFFFFFFFF.
	// Encoding: 0x88 0x7F 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF (canonical).
	var v int64
	if err := runDecodeErr([]byte{0x88, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, &v); err != nil {
		t.Fatalf("int64 rejected MaxInt64: %v", err)
	}
	if v != math.MaxInt64 {
		t.Errorf("expected %d, got %d", math.MaxInt64, v)
	}
}

func TestRLP_R12001_Uint64_AcceptsMax(t *testing.T) {
	// MaxUint64 = 0xFFFFFFFFFFFFFFFF.
	// Encoding: 0x88 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF (canonical).
	var v uint64
	if err := runDecodeErr([]byte{0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, &v); err != nil {
		t.Fatalf("uint64 rejected MaxUint64: %v", err)
	}
	if v != math.MaxUint64 {
		// Use uint64 formatting to avoid int overflow on 32-bit platforms.
		t.Errorf("expected %d, got %d", uint64(math.MaxUint64), v)
	}
}

// TestRLP_R12001_ErrorMessageIncludesKind verifies that the error message
// for overflow includes the target kind, so callers can debug which field
// overflowed when decoding composite types.
func TestRLP_R12001_ErrorMessageIncludesKind(t *testing.T) {
	var v int8
	err := DecodeBytes([]byte{0x81, 0xC8}, &v)
	if err == nil {
		t.Fatal("expected error")
	}
	// The error message should mention int8 so the caller knows which
	// field failed range validation.
	if !containsInt8(err.Error()) {
		t.Errorf("error message should mention int8 kind, got: %v", err)
	}
}

// containsInt8 returns true if s contains the substring "int8".
// Using a small helper avoids importing strings just for this one test.
func containsInt8(s string) bool {
	const target = "int8"
	if len(s) < len(target) {
		return false
	}
	for i := 0; i <= len(s)-len(target); i++ {
		if s[i:i+len(target)] == target {
			return true
		}
	}
	return false
}

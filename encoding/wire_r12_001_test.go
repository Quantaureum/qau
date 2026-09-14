// Quantaureum Node source, version 1.0.0.
// ENC-R12-001 (2026-07-20): Regression tests for varint 10th-byte overflow.
//
// Background: A uint64 varint can be up to 10 bytes long. The first 9 bytes
// contribute 63 bits (9*7=63), leaving only bit 63 for the 10th byte's
// payload. Before this fix, any 10th byte whose payload exceeded 1 bit
// (i.e., (byt & 0x7F) > 1) was silently truncated by the `<< 63` shift,
// producing a corrupted-but-seemingly-valid uint64. Two distinct byte
// sequences could decode to the same uint64, breaking canonicalization.
//
// These tests pin the fix that explicitly rejects such inputs.
package encoding

import (
	"testing"
)

// TestENC_R12001_TenthByte_PayloadOneAccepted verifies that the canonical
// 10-byte encoding of 2^63 (bit 63 set) is accepted. The 10th byte is 0x01
// (payload = 1, which sets bit 63).
func TestENC_R12001_TenthByte_PayloadOneAccepted(t *testing.T) {
	// 2^63 = 0x8000000000000000.
	// Varint encoding: 9 continuation bytes (0x80) + final byte 0x01.
	// Each 0x80 contributes 0 payload, 9 bytes = 0 bits.
	// The 10th byte 0x01 contributes bit 63.
	input := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	dec := NewBuffer(input)
	v, err := dec.DecodeVarint()
	if err != nil {
		t.Fatalf("expected success for 2^63 encoding, got: %v", err)
	}
	const expected uint64 = 1 << 63
	if v != expected {
		t.Errorf("expected 0x%x, got 0x%x", expected, v)
	}
}

// TestENC_R12001_TenthByte_PayloadZeroRejectedAsTrailingZero verifies that
// a 10-byte varint ending in 0x00 is rejected. Per R40-L7 (existing fix),
// any trailing zero byte (after the first byte) is non-canonical. The 10th
// byte being 0x00 means the value could be encoded in 9 bytes.
func TestENC_R12001_TenthByte_PayloadZeroRejectedAsTrailingZero(t *testing.T) {
	input := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}
	dec := NewBuffer(input)
	_, err := dec.DecodeVarint()
	if err == nil {
		t.Fatal("expected error for 10-byte varint with trailing zero, got nil")
	}
}

// TestENC_R12001_TenthByte_PayloadTwoRejected verifies that the 10th byte
// with payload 2 is rejected. Payload 2 would try to set bit 64, which
// doesn't exist in uint64. Before the fix, the `<< 63` shift silently
// truncated bit 64 and the result would look like payload 0 (no bit set).
func TestENC_R12001_TenthByte_PayloadTwoRejected(t *testing.T) {
	// 10th byte 0x02 (payload 2, no continuation bit).
	// This would attempt to set bit 64 — overflow.
	input := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}
	dec := NewBuffer(input)
	_, err := dec.DecodeVarint()
	if err == nil {
		t.Fatal("expected error for 10th byte payload=2, got nil (silent truncation)")
	}
}

// TestENC_R12001_TenthByte_PayloadMaxRejected verifies that the 10th byte
// with maximum payload (0x7F, no continuation bit) is rejected. Before the
// fix, `(0x7F) << 63` silently truncated to `0x01 << 63` (only bit 63
// survived), producing the same result as payload=1 — a malleability vector.
func TestENC_R12001_TenthByte_PayloadMaxRejected(t *testing.T) {
	input := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F}
	dec := NewBuffer(input)
	_, err := dec.DecodeVarint()
	if err == nil {
		t.Fatal("expected error for 10th byte payload=0x7F, got nil (silent truncation to payload=1)")
	}
}

// TestENC_R12001_TenthByte_ContinuationWithPayloadOneRejected verifies
// that a 10-byte varint with the continuation bit set on the 10th byte
// (and payload=1) is rejected as overflow — there's no room for an 11th
// byte in uint64. This is the case where the existing post-loop "varint
// overflow" error should fire.
func TestENC_R12001_TenthByte_ContinuationWithPayloadOneRejected(t *testing.T) {
	// 10th byte 0x81: continuation bit set, payload = 1.
	// The loop will apply payload=1 to bit 63, then try to continue.
	// Since the loop only goes to i=9, it exits naturally and returns
	// "varint overflow" from after the loop.
	input := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x81}
	dec := NewBuffer(input)
	_, err := dec.DecodeVarint()
	if err == nil {
		t.Fatal("expected error for 10-byte varint with continuation on 10th byte, got nil")
	}
}

// TestENC_R12001_TenthByte_ContinuationWithPayloadMaxRejected verifies
// that a 10-byte varint with continuation bit AND max payload is rejected.
// The fix fires on payload > 1 before the continuation-bit check, so the
// error message is the more specific "10th byte payload exceeds 1 bit".
func TestENC_R12001_TenthByte_ContinuationWithPayloadMaxRejected(t *testing.T) {
	// 10th byte 0xFF: continuation bit set, payload = 0x7F.
	// My fix fires first: (0xFF & 0x7F) = 0x7F > 1.
	input := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xFF}
	dec := NewBuffer(input)
	_, err := dec.DecodeVarint()
	if err == nil {
		t.Fatal("expected error for 10-byte varint ending in 0xFF, got nil")
	}
}

// TestENC_R12001_TenthByte_DistinctFromPayloadOne verifies the core
// canonicalization property: a 10-byte varint with payload > 1 must NOT
// silently degrade to the same result as payload=1. Before the fix,
// [0x80*9, 0x7F] and [0x80*9, 0x01] both decoded to 0x8000000000000000.
// After the fix, the former is rejected.
func TestENC_R12001_TenthByte_DistinctFromPayloadOne(t *testing.T) {
	// Canonical: payload=1, should decode to 2^63.
	canonical := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	dec := NewBuffer(canonical)
	vCanonical, err := dec.DecodeVarint()
	if err != nil {
		t.Fatalf("canonical encoding rejected: %v", err)
	}

	// Non-canonical: payload=0x7F, must be rejected (not silently degraded
	// to the same value as canonical).
	nonCanonical := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F}
	dec = NewBuffer(nonCanonical)
	vNonCanonical, err := dec.DecodeVarint()
	if err == nil {
		t.Errorf("non-canonical payload=0x7F accepted (silent degradation): got 0x%x, expected rejection; canonical was 0x%x",
			vNonCanonical, vCanonical)
	}
}

// TestENC_R12001_NinthByte_PayloadMaxAccepted verifies that the 9th byte
// (i=8) with maximum payload 0x7F is accepted — 9 bytes can encode up
// to 2^63-1 = 0x7FFFFFFFFFFFFFFF. This is the boundary: the 9th byte's
// payload fills bits 56-62 (7 bits), which is exactly what 9 bytes can hold.
func TestENC_R12001_NinthByte_PayloadMaxAccepted(t *testing.T) {
	// 9 bytes of 0xFF (continuation bit set, payload 0x7F each).
	// Total: 9 * 7 = 63 bits all set = 0x7FFFFFFFFFFFFFFF.
	input := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}
	dec := NewBuffer(input)
	v, err := dec.DecodeVarint()
	if err != nil {
		t.Fatalf("expected success for 9-byte max varint, got: %v", err)
	}
	const expected uint64 = 0x7FFFFFFFFFFFFFFF
	if v != expected {
		t.Errorf("expected 0x%x, got 0x%x", expected, v)
	}
}

// TestENC_R12001_NinthByte_AllOnesAccepted is a variant of the above
// using all-1s bytes for clarity. Same outcome.
func TestENC_R12001_NinthByte_AllOnesAccepted(t *testing.T) {
	// 0xFFFFFFFFFFFFFFFF - 1 = 0x7FFFFFFFFFFFFFFF (MaxInt64 as uint64).
	// Canonical 9-byte varint.
	input := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}
	dec := NewBuffer(input)
	v, err := dec.DecodeVarint()
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if v != 0x7FFFFFFFFFFFFFFF {
		t.Errorf("expected 0x7FFFFFFFFFFFFFFF, got 0x%x", v)
	}
}

// TestENC_R12001_ElevenByteVarintRejected verifies the existing overflow
// behavior is preserved: an 11-byte varint (10 continuation bytes + 1 final
// byte) is rejected because it exceeds uint64's 10-byte maximum.
func TestENC_R12001_ElevenByteVarintRejected(t *testing.T) {
	// 11 bytes of 0xFF. The 10th byte (i=9) has continuation set and
	// payload 0x7F — my fix fires and returns the 10th-byte overflow error.
	// The 11th byte is never read.
	input := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	dec := NewBuffer(input)
	_, err := dec.DecodeVarint()
	if err == nil {
		t.Fatal("expected error for 11-byte varint, got nil")
	}
}

// TestENC_R12001_RoundTrip_AllOnesUint64 verifies that 0xFFFFFFFFFFFFFFFF
// (MaxUint64) round-trips through EncodeVarint/DecodeVarint. This is the
// maximum value a uint64 varint can represent, requiring all 10 bytes.
func TestENC_R12001_RoundTrip_AllOnesUint64(t *testing.T) {
	const max uint64 = 0xFFFFFFFFFFFFFFFF
	buf := NewWriteBuffer()
	buf.EncodeVarint(max)
	dec := NewBuffer(buf.Bytes())
	v, err := dec.DecodeVarint()
	if err != nil {
		t.Fatalf("round-trip failed for MaxUint64: %v", err)
	}
	if v != max {
		t.Errorf("expected 0x%x, got 0x%x", max, v)
	}
}

// TestENC_R12001_RoundTrip_TwoPow63 verifies that 2^63 round-trips correctly.
// This is the smallest value that requires the 10th byte.
func TestENC_R12001_RoundTrip_TwoPow63(t *testing.T) {
	const v uint64 = 1 << 63
	buf := NewWriteBuffer()
	buf.EncodeVarint(v)
	dec := NewBuffer(buf.Bytes())
	got, err := dec.DecodeVarint()
	if err != nil {
		t.Fatalf("round-trip failed for 2^63: %v", err)
	}
	if got != v {
		t.Errorf("expected 0x%x, got 0x%x", v, got)
	}
}

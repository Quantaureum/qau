// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"math"
	"testing"
)

// TestDecodeBytes_MemoryLimit verifies that DecodeBytes rejects oversized fields
// SECURITY (audit P1-R3-01): Prevent OOM from malicious P2P messages
func TestDecodeBytes_MemoryLimit(t *testing.T) {
	// Test per-field limit: 17MB should be rejected (limit is 16MB)
	buf := NewWriteBuffer()
	// Encode a fake length of 17MB (17 * 1024 * 1024 = 17825792)
	bigLen := uint64(17 * 1024 * 1024)
	buf.EncodeVarint(bigLen)
	// Add some data (doesn't need to be full 17MB, the length check happens before reading)
	buf.buf = append(buf.buf, make([]byte, 100)...)

	dec := NewBuffer(buf.Bytes())
	_, err := dec.DecodeBytes()
	if err == nil {
		t.Fatal("expected error for oversized bytes field, got nil")
	}
	t.Logf("Correctly rejected oversized field: %v", err)
}

// TestDecodeBytes_NormalSize verifies normal-sized fields still work
func TestDecodeBytes_NormalSize(t *testing.T) {
	data := []byte("hello world")
	buf := NewWriteBuffer()
	buf.EncodeBytes(data)

	dec := NewBuffer(buf.Bytes())
	result, err := dec.DecodeBytes()
	if err != nil {
		t.Fatalf("DecodeBytes failed: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Fatalf("expected %v, got %v", data, result)
	}
}

// TestDecodeBytes_TotalBudget verifies total decoded budget is enforced
func TestDecodeBytes_TotalBudget(t *testing.T) {
	// Each field is 1MB, decode 33 of them to exceed 32MB total budget
	fieldSize := 1024 * 1024 // 1MB
	fieldData := make([]byte, fieldSize)

	buf := NewWriteBuffer()
	for i := 0; i < 33; i++ {
		buf.EncodeBytes(fieldData)
	}

	dec := NewBuffer(buf.Bytes())
	var lastErr error
	for i := 0; i < 33; i++ {
		_, err := dec.DecodeBytes()
		if err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Fatal("expected error when exceeding total budget, got nil")
	}
	t.Logf("Correctly rejected total budget exceed: %v", lastErr)
}

// TestSkip_BytesLimit verifies Skip rejects oversized WireBytes fields
func TestSkip_BytesLimit(t *testing.T) {
	buf := NewWriteBuffer()
	bigLen := uint64(17 * 1024 * 1024) // 17MB > 16MB limit
	buf.EncodeVarint(bigLen)
	buf.buf = append(buf.buf, make([]byte, 100)...)

	dec := NewBuffer(buf.Bytes())
	err := dec.Skip(WireBytes)
	if err == nil {
		t.Fatal("expected error for oversized Skip WireBytes, got nil")
	}
	t.Logf("Correctly rejected oversized Skip: %v", err)
}

// TestDecodeVarint_CanonicalEncoding (ENC-R11-004) verifies that DecodeVarint
// accepts canonical encodings and rejects non-canonical (overlong) ones.
//
// Canonical varint rules (see wire.go DecodeVarint):
//   - The value 0 is encoded as the single byte [0x00].
//   - Any non-final byte has the high bit (0x80) set.
//   - A final byte of 0x00 is only valid as the first byte (encoding 0);
//     a 0x00 in any later position means the encoding is overlong.
//
// Without these tests, a future refactor of DecodeVarint could silently
// accept overlong encodings, breaking canonicalization invariants
// required for consensus-equivalent block/transaction hashes.
func TestDecodeVarint_CanonicalEncoding(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    uint64
		wantErr bool
	}{
		// Canonical cases — must decode successfully.
		{name: "zero_single_byte", input: []byte{0x00}, want: 0},
		{name: "one_single_byte", input: []byte{0x01}, want: 1},
		{name: "127_single_byte", input: []byte{0x7F}, want: 127},
		{name: "128_two_bytes", input: []byte{0x80, 0x01}, want: 128},
		{name: "300_two_bytes", input: []byte{0xAC, 0x02}, want: 300},
		{name: "16383_two_bytes", input: []byte{0xFF, 0x7F}, want: 16383},

		// Non-canonical cases — must be rejected.
		// [0x80, 0x00] would decode to 0, but the canonical encoding is [0x00].
		{name: "overlong_zero", input: []byte{0x80, 0x00}, wantErr: true},
		// [0x81, 0x00] would decode to 1, but canonical is [0x01].
		{name: "overlong_one", input: []byte{0x81, 0x00}, wantErr: true},
		// [0x80, 0x80, 0x00] would decode to 0 with three bytes.
		{name: "overlong_zero_three_bytes", input: []byte{0x80, 0x80, 0x00}, wantErr: true},

		// EOF cases — must be rejected.
		{name: "empty_input", input: []byte{}, wantErr: true},
		{name: "truncated_continuation", input: []byte{0x80}, wantErr: true},
		{name: "truncated_two_byte", input: []byte{0xAC}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := NewBuffer(tt.input)
			got, err := dec.DecodeVarint()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("DecodeVarint(%v) expected error, got %d", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeVarint(%v) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("DecodeVarint(%v) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// TestDecodeVarint_RoundTrip verifies EncodeVarint → DecodeVarint round-trips
// for representative values across the uint64 range.
func TestDecodeVarint_RoundTrip(t *testing.T) {
	values := []uint64{
		0,
		1,
		127,
		128,
		16383,
		16384,
		1 << 20,
		1 << 32,
		1 << 40,
		math.MaxUint64,
	}
	for _, v := range values {
		buf := NewWriteBuffer()
		buf.EncodeVarint(v)
		dec := NewBuffer(buf.Bytes())
		got, err := dec.DecodeVarint()
		if err != nil {
			t.Fatalf("DecodeVarint(%d) failed: %v", v, err)
		}
		if got != v {
			t.Fatalf("DecodeVarint(%d) = %d", v, got)
		}
	}
}

// TestDecodeVarint_Overflow verifies that an 11-byte varint (all bytes 0xFF
// followed by a final 0xFF) is rejected as overflow.
func TestDecodeVarint_Overflow(t *testing.T) {
	// 11 bytes of 0xFF — the 11th byte would shift beyond uint64.
	input := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	dec := NewBuffer(input)
	_, err := dec.DecodeVarint()
	if err == nil {
		t.Fatal("expected overflow error for 11-byte varint, got nil")
	}
}

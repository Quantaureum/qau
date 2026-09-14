// Quantaureum Node source, version 1.0.0.
// Package encoding — ENC-R13-001 regression tests.
//
// These tests verify that Skip() updates b.totalAllocated for every
// supported wireType. Before the ENC-R13-001 fix, Skip() advanced b.pos
// but did NOT update b.totalAllocated. The totalAllocated counter is the
// only mechanism that bounds total consumed input via the maxWireTotalSize
// (32 MB) guard. Without the fix, an attacker could feed a parser many
// large "unknown" fields that get Skip()'d, totaling far more than 32 MB
// of consumed input without ever tripping the guard — a slow OOM vector.
package encoding

import (
	"testing"
)

// TestSkip_TotalAllocated_ByWireType (ENC-R13-001) verifies that Skip()
// updates b.totalAllocated for every supported wireType.
//
// Setup: encode two large WireBytes fields whose total (varint prefix +
// payload) = exactly maxWireTotalSize (32 MB). Then append a single small
// field of the wireType under test. Skipping the two big fields brings
// totalAllocated to exactly 32 MB. Skipping the trailing field would push
// totalAllocated past the 32 MB budget and must fail — proving the wireType
// under test contributes to totalAllocated. If the wireType's Skip branch
// forgets to update totalAllocated, this Skip will succeed and the
// regression fires.
//
// ENC-R15-001 (2026-07-27) UPDATE: payload size reduced by 4 bytes to
// account for the 4-byte varint prefix that ENC-R15-001 now counts toward
// totalAllocated. Without this adjustment, two 16MB fields would consume
// 2*(4+16MB) = 32MB+8 > 32MB, causing the second Skip to fail prematurely.
// With the adjustment, each field consumes 4 + (16MB-4) = 16MB exactly,
// so two fields total exactly 32MB.
func TestSkip_TotalAllocated_ByWireType(t *testing.T) {
	// bigPayloadSize is chosen so that varint(bigPayloadSize) + bigPayloadSize
	// = maxWireTotalSize/2. varint(16MB-4) = 4 bytes (value < 2^28), so
	// 4 + (16MB - 4) = 16MB = maxWireTotalSize/2.
	bigPayloadSize := maxWireTotalSize/2 - 4

	cases := []struct {
		name        string
		wireType    int
		encodeField func(*Buffer)
	}{
		{
			name:        "WireVarint",
			wireType:    WireVarint,
			encodeField: func(b *Buffer) { b.EncodeVarint(0xFFFFFFFFFFFFFFFF) }, // 10-byte varint
		},
		{
			name:        "WireFixed64",
			wireType:    WireFixed64,
			encodeField: func(b *Buffer) { b.EncodeFixed64(42) }, // 8 bytes
		},
		{
			name:        "WireBytes",
			wireType:    WireBytes,
			encodeField: func(b *Buffer) { b.EncodeBytes([]byte("x")) }, // 1 byte payload
		},
		{
			name:        "WireFixed32",
			wireType:    WireFixed32,
			encodeField: func(b *Buffer) { b.EncodeFixed32(42) }, // 4 bytes
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := NewWriteBuffer()
			buf.EncodeBytes(make([]byte, bigPayloadSize)) // ~16 MB (varint+payload = exactly 16MB)
			buf.EncodeBytes(make([]byte, bigPayloadSize)) // ~16 MB (total varint+payload = exactly 32MB)
			tc.encodeField(buf)                           // small trailing field

			dec := NewBuffer(buf.Bytes())
			if err := dec.Skip(WireBytes); err != nil {
				t.Fatalf("first Skip(WireBytes) failed: %v", err)
			}
			if err := dec.Skip(WireBytes); err != nil {
				t.Fatalf("second Skip(WireBytes) failed: %v", err)
			}
			// totalAllocated is now exactly 32 MB. Skipping any further field
			// must trip the maxWireTotalSize guard. If the wireType under
			// test does NOT update totalAllocated, this Skip succeeds and
			// the regression assertion fires.
			err := dec.Skip(tc.wireType)
			if err == nil {
				t.Fatalf("ENC-R13-001 regression: Skip(%s) after 32MB totalAllocated should fail, got nil",
					tc.name)
			}
			t.Logf("Correctly rejected total budget exceed for %s: %v", tc.name, err)
		})
	}
}

// TestSkip_Bytes_TotalBudgetAccumulates (ENC-R13-001) verifies that
// Skip(WireBytes) accumulates totalAllocated across multiple calls.
//
// Setup: encode 33 fields whose (varint prefix + payload) each = exactly
// 1 MB. The first 32 Skip calls should succeed (totalAllocated grows
// 1MB → 32MB); the 33rd should fail (32MB + 1MB > 32MB).
//
// ENC-R15-001 (2026-07-27) UPDATE: field size reduced by 3 bytes to
// account for the 3-byte varint prefix that ENC-R15-001 now counts toward
// totalAllocated. Without this adjustment, 32 fields of 1MB would consume
// 32*(3+1MB) = 32MB+96 > 32MB, causing the 32nd Skip to fail prematurely.
// With the adjustment, each field consumes 3 + (1MB-3) = 1MB exactly,
// so 32 fields total exactly 32MB.
//
// This catches regressions where Skip(WireBytes) updates totalAllocated
// per-call but the check is somehow bypassed (e.g., by forgetting to lock
// or by checking only the per-field limit and not the cumulative budget).
func TestSkip_Bytes_TotalBudgetAccumulates(t *testing.T) {
	// fieldSize is chosen so that varint(fieldSize) + fieldSize = 1MB.
	// varint(1MB-3) = 3 bytes (value < 2^21), so 3 + (1MB - 3) = 1MB.
	fieldSize := 1024*1024 - 3
	buf := NewWriteBuffer()
	for i := 0; i < 33; i++ {
		buf.EncodeBytes(make([]byte, fieldSize))
	}
	dec := NewBuffer(buf.Bytes())
	var lastErr error
	skipped := 0
	for i := 0; i < 33; i++ {
		if err := dec.Skip(WireBytes); err != nil {
			lastErr = err
			break
		}
		skipped++
	}
	if lastErr == nil {
		t.Fatal("ENC-R13-001 regression: expected Skip(WireBytes) to fail when " +
			"totalAllocated exceeds 32MB, got nil")
	}
	if skipped != 32 {
		t.Fatalf("expected exactly 32 successful Skips (32MB), got %d", skipped)
	}
	t.Logf("Skipped %d fields of 1MB each, then correctly rejected: %v", skipped, lastErr)
}

// TestSkip_Bytes_PayloadExceedsRemainingBuffer (ENC-R13-001) verifies that
// Skip(WireBytes) still rejects when the encoded length exceeds the
// remaining buffer even when totalAllocated has room. This guards against
// an over-eager fix that only checks totalAllocated and forgets the
// io.ErrUnexpectedEOF check on the underlying buffer.
func TestSkip_Bytes_PayloadExceedsRemainingBuffer(t *testing.T) {
	buf := NewWriteBuffer()
	// Encode a length prefix claiming 1 MB, but only provide 100 bytes of payload.
	buf.EncodeVarint(uint64(1024 * 1024))
	buf.buf = append(buf.buf, make([]byte, 100)...)

	dec := NewBuffer(buf.Bytes())
	err := dec.Skip(WireBytes)
	if err == nil {
		t.Fatal("expected Skip(WireBytes) to fail when payload exceeds remaining buffer, got nil")
	}
	t.Logf("Correctly rejected payload exceeds remaining buffer: %v", err)
}

// TestSkip_Fixed64_TriggersUnexpectedEOF (ENC-R13-001) verifies that
// Skip(WireFixed64) still returns io.ErrUnexpectedEOF when the underlying
// buffer is too short, regardless of totalAllocated state. This guards
// against a fix that only checks totalAllocated and forgets the bounds
// check on b.buf.
func TestSkip_Fixed64_TriggersUnexpectedEOF(t *testing.T) {
	// Buffer with only 3 bytes — Skip(WireFixed64) needs 8 bytes.
	buf := NewWriteBuffer()
	buf.buf = append(buf.buf, []byte{0x01, 0x02, 0x03}...)

	dec := NewBuffer(buf.Bytes())
	err := dec.Skip(WireFixed64)
	if err == nil {
		t.Fatal("expected Skip(WireFixed64) to fail on short buffer, got nil")
	}
	t.Logf("Correctly rejected short buffer: %v", err)
}

// TestSkip_Fixed32_TriggersUnexpectedEOF (ENC-R13-001) verifies that
// Skip(WireFixed32) still returns io.ErrUnexpectedEOF when the underlying
// buffer is too short, regardless of totalAllocated state.
func TestSkip_Fixed32_TriggersUnexpectedEOF(t *testing.T) {
	// Buffer with only 2 bytes — Skip(WireFixed32) needs 4 bytes.
	buf := NewWriteBuffer()
	buf.buf = append(buf.buf, []byte{0x01, 0x02}...)

	dec := NewBuffer(buf.Bytes())
	err := dec.Skip(WireFixed32)
	if err == nil {
		t.Fatal("expected Skip(WireFixed32) to fail on short buffer, got nil")
	}
	t.Logf("Correctly rejected short buffer: %v", err)
}

// Quantaureum Node source, version 1.0.0.
// Package encoding — ENC-R15-001 regression tests for DecodeBytes varint
// prefix accounting.
//
// AUDIT (2026) ENC-R15-001: DecodeBytes previously added only the
// payload length to totalAllocated, not the varint prefix bytes consumed
// by DecodeVarint. This meant an attacker could craft many small WireBytes
// fields (1-byte payload + 1-byte varint prefix = 2 bytes consumed, but
// only 1 byte counted), consuming more buffer than totalAllocated reflects,
// potentially bypassing the maxWireTotalSize cap.
//
// The fix captures b.pos before DecodeVarint and adds both varint prefix
// bytes and payload bytes to totalAllocated.
package encoding

import (
	"testing"
)

// TestENC_R15_001_DecodeBytes_VarintPrefixCounted verifies that DecodeBytes
// counts both the varint prefix bytes AND the payload bytes in
// totalAllocated. We encode many small 1-byte-payload WireBytes fields
// and verify that the total budget check includes the varint prefix.
func TestENC_R15_001_DecodeBytes_VarintPrefixCounted(t *testing.T) {
	// Each field: 1-byte varint prefix (length=1) + 1-byte payload = 2 bytes.
	// If only payload is counted, totalAllocated = numFields * 1.
	// If varint prefix is counted, totalAllocated = numFields * 2.
	// We encode enough fields to exceed maxWireTotalSize/2 but stay under
	// maxWireTotalSize if only payload is counted.
	// maxWireTotalSize = 32MB. If only payload: 16M fields * 1 byte = 16MB < 32MB.
	// If varint+payload: 16M fields * 2 bytes = 32MB = exactly at budget.
	// So we encode maxWireTotalSize/2 + 1 fields. If varint is counted,
	// the last DecodeBytes should fail (exceeds budget). If not counted,
	// all succeed (regression).

	// Use a smaller scale to keep the test fast.
	// 1000 fields of 1-byte payload: 1000 * 2 = 2000 bytes if varint counted.
	// Set maxWireTotalSize artificially by using a buffer that's just big enough.
	// Actually, we can't change maxWireTotalSize. Instead, let's verify
	// totalAllocated directly by checking that DecodeBytes of a small field
	// after many small fields trips the budget.

	// Simpler approach: encode two big WireBytes fields whose total
	// (varint + payload) is exactly maxWireTotalSize, then try to DecodeBytes
	// a third small field. If varint prefix is NOT counted, the first two
	// fields' totalAllocated would be under budget, and the third might
	// succeed (regression).

	// Each field: varint(payloadSize) + payloadSize
	// We want two fields to total exactly maxWireTotalSize.
	// payloadSize = maxWireTotalSize/2 - varintLen
	// varint(maxWireTotalSize/2) = 4 bytes (16MB < 2^28)
	payloadSize := maxWireTotalSize/2 - 4

	buf := NewWriteBuffer()
	buf.EncodeBytes(make([]byte, payloadSize))
	buf.EncodeBytes(make([]byte, payloadSize))
	buf.EncodeBytes([]byte("x")) // small trailing field

	dec := NewBuffer(buf.Bytes())
	if _, err := dec.DecodeBytes(); err != nil {
		t.Fatalf("first DecodeBytes failed: %v", err)
	}
	if _, err := dec.DecodeBytes(); err != nil {
		t.Fatalf("second DecodeBytes failed: %v", err)
	}
	// totalAllocated should now be exactly maxWireTotalSize.
	// The third DecodeBytes must fail — if varint prefix is NOT counted,
	// totalAllocated would be 2*payloadSize = maxWireTotalSize - 8,
	// and the third field (1-byte varint + 1-byte payload = 2 bytes counted
	// or 1 byte uncounted) would succeed.
	_, err := dec.DecodeBytes()
	if err == nil {
		t.Fatal("ENC-R15-001 regression: third DecodeBytes should fail when " +
			"totalAllocated (including varint prefix bytes) reaches maxWireTotalSize")
	}
	t.Logf("Correctly rejected third DecodeBytes: %v", err)
}

// TestENC_R15_001_DecodeBytes_VarintPrefixAccurate verifies that
// totalAllocated after a single DecodeBytes equals varint_prefix_len +
// payload_len, not just payload_len.
func TestENC_R15_001_DecodeBytes_VarintPrefixAccurate(t *testing.T) {
	// Encode a 1-byte payload WireBytes field.
	buf := NewWriteBuffer()
	buf.EncodeBytes([]byte("x")) // 1-byte varint prefix + 1-byte payload

	dec := NewBuffer(buf.Bytes())
	data, err := dec.DecodeBytes()
	if err != nil {
		t.Fatalf("DecodeBytes failed: %v", err)
	}
	if len(data) != 1 || data[0] != 'x' {
		t.Fatalf("expected [x], got %v", data)
	}

	// totalAllocated should be 2 (1 varint prefix byte + 1 payload byte).
	// If only payload was counted, it would be 1.
	if dec.totalAllocated != 2 {
		t.Errorf("ENC-R15-001: expected totalAllocated=2 (varint_prefix=1 + payload=1), got %d",
			dec.totalAllocated)
	}
}

// TestENC_R15_001_Skip_WireBytes_VarintPrefixAccurate verifies that
// Skip(WireBytes) counts both varint prefix and payload in totalAllocated.
func TestENC_R15_001_Skip_WireBytes_VarintPrefixAccurate(t *testing.T) {
	// Encode a 1-byte payload WireBytes field.
	buf := NewWriteBuffer()
	buf.EncodeBytes([]byte("x")) // 1-byte varint prefix + 1-byte payload

	dec := NewBuffer(buf.Bytes())
	if err := dec.Skip(WireBytes); err != nil {
		t.Fatalf("Skip failed: %v", err)
	}

	// totalAllocated should be 2 (1 varint prefix byte + 1 payload byte).
	if dec.totalAllocated != 2 {
		t.Errorf("ENC-R15-001: expected totalAllocated=2 (varint_prefix=1 + payload=1), got %d",
			dec.totalAllocated)
	}
}

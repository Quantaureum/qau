// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"bytes"
	"testing"
	"time"
)

func TestNewOptimizedCodec(t *testing.T) {
	oc := NewOptimizedCodec()
	if oc == nil {
		t.Error("NewOptimizedCodec should not return nil")
	}
}

func TestOptimizedCodecEncodeDecodeMessage(t *testing.T) {
	oc := NewOptimizedCodec()

	encoded, err := oc.EncodeOptimizedMessage(MsgTypeBlock, []byte("block-data"), time.Now())
	if err != nil {
		t.Fatalf("EncodeOptimizedMessage failed: %v", err)
	}

	decoded, err := oc.DecodeOptimizedMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeOptimizedMessage failed: %v", err)
	}

	if decoded.Type != MsgTypeBlock {
		t.Errorf("Type = %d, want %d", decoded.Type, MsgTypeBlock)
	}
	if string(decoded.Payload) != "block-data" {
		t.Errorf("Payload = %q, want %q", string(decoded.Payload), "block-data")
	}
}

func TestOptimizedCodecEncodeTooLarge(t *testing.T) {
	oc := NewOptimizedCodec()

	largePayload := make([]byte, MaxMsgSize+1)
	_, err := oc.EncodeOptimizedMessage(MsgTypeBlock, largePayload, time.Now())
	if err != ErrMsgTooLarge {
		t.Errorf("expected ErrMsgTooLarge, got %v", err)
	}
}

func TestOptimizedCodecDecodeTooShort(t *testing.T) {
	oc := NewOptimizedCodec()

	_, err := oc.DecodeOptimizedMessage([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestOptimizedCodecDecodeInvalidChecksum(t *testing.T) {
	oc := NewOptimizedCodec()

	encoded, _ := oc.EncodeOptimizedMessage(MsgTypeBlock, []byte("data"), time.Now())
	// Corrupt checksum
	encoded[len(encoded)-1] ^= 0xFF

	_, err := oc.DecodeOptimizedMessage(encoded)
	if err != ErrInvalidChecksum {
		t.Errorf("expected ErrInvalidChecksum, got %v", err)
	}
}

func TestOptimizedCodecEncodeDecodeEmptyPayload(t *testing.T) {
	oc := NewOptimizedCodec()

	encoded, err := oc.EncodeOptimizedMessage(MsgTypePing, []byte{}, time.Now())
	if err != nil {
		t.Fatalf("EncodeOptimizedMessage failed: %v", err)
	}

	decoded, err := oc.DecodeOptimizedMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeOptimizedMessage failed: %v", err)
	}

	if decoded.Type != MsgTypePing {
		t.Errorf("Type = %d, want %d", decoded.Type, MsgTypePing)
	}
}

func TestOptimizedCodecEncodeDecodeBatchMessage(t *testing.T) {
	oc := NewOptimizedCodec()

	messages := []*Message{
		{Type: MsgTypeBlock, Payload: []byte("block-data")},
		{Type: MsgTypeTransaction, Payload: []byte("tx-data")},
	}

	encoded, err := oc.EncodeOptimizedBatchMessage(messages)
	if err != nil {
		t.Fatalf("EncodeOptimizedBatchMessage failed: %v", err)
	}

	decoded, err := oc.DecodeOptimizedBatchMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeOptimizedBatchMessage failed: %v", err)
	}

	if len(decoded) != 2 {
		t.Fatalf("len(decoded) = %d, want 2", len(decoded))
	}
	if decoded[0].Type != MsgTypeBlock {
		t.Errorf("decoded[0].Type = %d, want %d", decoded[0].Type, MsgTypeBlock)
	}
	if decoded[1].Type != MsgTypeTransaction {
		t.Errorf("decoded[1].Type = %d, want %d", decoded[1].Type, MsgTypeTransaction)
	}
}

func TestOptimizedCodecEncodeBatchEmpty(t *testing.T) {
	oc := NewOptimizedCodec()

	_, err := oc.EncodeOptimizedBatchMessage([]*Message{})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage for empty batch, got %v", err)
	}
}

func TestOptimizedCodecDecodeBatchTooShort(t *testing.T) {
	oc := NewOptimizedCodec()

	_, err := oc.DecodeOptimizedBatchMessage([]byte{1})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestOptimizedCodecDecodeBatchZeroCount(t *testing.T) {
	oc := NewOptimizedCodec()

	_, err := oc.DecodeOptimizedBatchMessage([]byte{0, 0})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage for zero count, got %v", err)
	}
}

// TestR33_P2P_03_BatchCRC32Corruption verifies that the batch CRC32 checksum
// detects data corruption. R33 P2P-03 FIX.
func TestR33_P2P_03_BatchCRC32Corruption(t *testing.T) {
	oc := NewOptimizedCodec()

	messages := []*Message{
		{Type: MsgTypeBlock, Payload: []byte("block-data")},
		{Type: MsgTypeTransaction, Payload: []byte("tx-data")},
	}

	encoded, err := oc.EncodeOptimizedBatchMessage(messages)
	if err != nil {
		t.Fatalf("EncodeOptimizedBatchMessage failed: %v", err)
	}

	// Corrupt a byte in the payload area (not in the count or CRC32).
	// The payload starts at offset 6 (count(2) + timestamp(4)) + 4 (len+type+flags) = 10.
	corrupted := make([]byte, len(encoded))
	copy(corrupted, encoded)
	corrupted[10] ^= 0xFF // Flip bits in the first payload byte

	_, err = oc.DecodeOptimizedBatchMessage(corrupted)
	if err != ErrInvalidChecksum {
		t.Errorf("R33 P2P-03: expected ErrInvalidChecksum for corrupted batch, got %v", err)
	}
}

// TestR33_P2P_03_BatchTimestampPropagated verifies that the batch timestamp
// is propagated to decoded messages instead of using time.Now(). R33 P2P-03 FIX.
func TestR33_P2P_03_BatchTimestampPropagated(t *testing.T) {
	oc := NewOptimizedCodec()

	messages := []*Message{
		{Type: MsgTypeBlock, Payload: []byte("block-data")},
	}

	encoded, err := oc.EncodeOptimizedBatchMessage(messages)
	if err != nil {
		t.Fatalf("EncodeOptimizedBatchMessage failed: %v", err)
	}

	// Read the batch timestamp from the encoded data (bytes 2-5).
	encodedTS := uint32(encoded[2])<<24 | uint32(encoded[3])<<16 | uint32(encoded[4])<<8 | uint32(encoded[5])

	decoded, err := oc.DecodeOptimizedBatchMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeOptimizedBatchMessage failed: %v", err)
	}

	if len(decoded) != 1 {
		t.Fatalf("expected 1 message, got %d", len(decoded))
	}

	decodedTS := uint32(decoded[0].Timestamp.Unix())
	if decodedTS != encodedTS {
		t.Errorf("R33 P2P-03: timestamp not propagated: decoded=%d, encoded=%d", decodedTS, encodedTS)
	}
}

// TestR33_P3_01_BatchCompressionFlagRoundTrip verifies that the per-message
// compression flag is correctly encoded and decoded in batch messages.
// R33 P3-01 FIX: previously the batch format had no compression flag, making
// decompression impossible. The P2P-03 fix added a per-message flags byte
// (including MsgFlagCompressed). This test ensures the round-trip works for
// both compressible (large, repetitive) and incompressible (small) payloads.
func TestR33_P3_01_BatchCompressionFlagRoundTrip(t *testing.T) {
	oc := NewOptimizedCodec()

	// Build a mix of messages: a large compressible payload (forces compression)
	// and a small incompressible payload (no compression).
	largePayload := make([]byte, 2048)
	for i := range largePayload {
		largePayload[i] = 'A' // highly compressible
	}
	messages := []*Message{
		{Type: MsgTypeBlock, Payload: largePayload},
		{Type: MsgTypeTransaction, Payload: []byte("short-tx")},
	}

	encoded, err := oc.EncodeOptimizedBatchMessage(messages)
	if err != nil {
		t.Fatalf("EncodeOptimizedBatchMessage failed: %v", err)
	}

	// The compressed payload should be smaller than the original, proving
	// compression was applied. Verify the per-message flags byte is set for
	// the first message but not necessarily for the second.
	// Layout: count(2) + timestamp(4) + [msg1_len(2) + msg1_type(1) + msg1_flags(1) + msg1_payload] + ...
	// First message flags byte is at offset 6 + 2 + 1 = 9.
	msg1Flags := encoded[9]
	if msg1Flags&MsgFlagCompressed == 0 {
		t.Errorf("R33 P3-01: expected first message (large compressible payload) to have MsgFlagCompressed set, got flags=0x%02x", msg1Flags)
	}

	decoded, err := oc.DecodeOptimizedBatchMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeOptimizedBatchMessage failed: %v", err)
	}

	if len(decoded) != 2 {
		t.Fatalf("expected 2 decoded messages, got %d", len(decoded))
	}

	// Verify the payloads round-trip exactly (decompression must undo compression).
	if !bytes.Equal(decoded[0].Payload, largePayload) {
		t.Errorf("R33 P3-01: large payload round-trip mismatch: got %d bytes, want %d bytes", len(decoded[0].Payload), len(largePayload))
	}
	if !bytes.Equal(decoded[1].Payload, []byte("short-tx")) {
		t.Errorf("R33 P3-01: small payload round-trip mismatch: got %q, want %q", string(decoded[1].Payload), "short-tx")
	}
}

func TestOptimizedCodecEncodeDecodeStatusMessage(t *testing.T) {
	oc := NewOptimizedCodec()

	status := &StatusMessage{
		Version:    1,
		NetworkID:  1668,
		BestHeight: 100,
	}
	copy(status.BestHash[:], []byte("best_hash_0001_0001_0001_0001_0001"))
	copy(status.GenesisHash[:], []byte("genesis_hash_0001_0001_0001_0001_01"))

	encoded := oc.EncodeOptimizedStatusMessage(status)
	decoded, err := oc.DecodeOptimizedStatusMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeOptimizedStatusMessage failed: %v", err)
	}

	if decoded.Version != status.Version {
		t.Errorf("Version = %d, want %d", decoded.Version, status.Version)
	}
	if decoded.NetworkID != status.NetworkID {
		t.Errorf("NetworkID = %d, want %d", decoded.NetworkID, status.NetworkID)
	}
	if decoded.BestHeight != status.BestHeight {
		t.Errorf("BestHeight = %d, want %d", decoded.BestHeight, status.BestHeight)
	}
}

func TestOptimizedCodecDecodeStatusTooShort(t *testing.T) {
	oc := NewOptimizedCodec()

	_, err := oc.DecodeOptimizedStatusMessage([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestOptimizedCodecMultipleMessages(t *testing.T) {
	oc := NewOptimizedCodec()

	for i := 0; i < 10; i++ {
		encoded, err := oc.EncodeOptimizedMessage(MsgTypeBlock, []byte("data"), time.Now())
		if err != nil {
			t.Fatalf("EncodeOptimizedMessage(%d) failed: %v", i, err)
		}

		decoded, err := oc.DecodeOptimizedMessage(encoded)
		if err != nil {
			t.Fatalf("DecodeOptimizedMessage(%d) failed: %v", i, err)
		}

		if decoded.Type != MsgTypeBlock {
			t.Errorf("Decode(%d) Type mismatch", i)
		}
	}
}

func TestOptimizedCodecConcurrent(t *testing.T) {
	oc := NewOptimizedCodec()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			encoded, err := oc.EncodeOptimizedMessage(MsgTypeBlock, []byte("concurrent-data"), time.Now())
			if err != nil {
				t.Errorf("Encode failed: %v", err)
				done <- false
				return
			}
			decoded, err := oc.DecodeOptimizedMessage(encoded)
			if err != nil {
				t.Errorf("Decode failed: %v", err)
				done <- false
				return
			}
			if decoded.Type != MsgTypeBlock {
				t.Error("Type mismatch")
				done <- false
				return
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		if !<-done {
			t.Error("concurrent test failed")
		}
	}
}

// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"bytes"
	"testing"
)

func TestSnappyCompressorCompressDecompress(t *testing.T) {
	c := NewSnappyCompressor()

	data := []byte("hello world, this is a test of compression and decompression in the p2p package")

	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}

	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Errorf("decompressed = %q, want %q", string(decompressed), string(data))
	}
}

func TestSnappyCompressorEmptyData(t *testing.T) {
	c := NewSnappyCompressor()

	_, err := c.Compress([]byte{})
	if err != ErrEmptyData {
		t.Errorf("expected ErrEmptyData, got %v", err)
	}
}

func TestSnappyCompressorDecompressEmptyData(t *testing.T) {
	c := NewSnappyCompressor()

	_, err := c.Decompress([]byte{})
	if err != ErrEmptyData {
		t.Errorf("expected ErrEmptyData, got %v", err)
	}
}

func TestSnappyCompressorTooLarge(t *testing.T) {
	c := NewSnappyCompressor()

	largeData := make([]byte, MaxCompressSize+1)
	_, err := c.Compress(largeData)
	if err != ErrDataTooLarge {
		t.Errorf("expected ErrDataTooLarge, got %v", err)
	}
}

func TestSnappyCompressorInvalidData(t *testing.T) {
	c := NewSnappyCompressor()

	_, err := c.Decompress([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if err != ErrDecompressionFailed {
		t.Errorf("expected ErrDecompressionFailed, got %v", err)
	}
}

func TestSnappyCompressorLargeData(t *testing.T) {
	c := NewSnappyCompressor()

	data := make([]byte, 1024*100) // 100KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	compressed, err := c.Compress(data)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}

	decompressed, err := c.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Error("large data decompress mismatch")
	}
}

func TestSnappyCompressorConcurrent(t *testing.T) {
	c := NewSnappyCompressor()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			data := []byte("concurrent test data")
			compressed, err := c.Compress(data)
			if err != nil {
				t.Errorf("Compress failed: %v", err)
				done <- false
				return
			}
			decompressed, err := c.Decompress(compressed)
			if err != nil {
				t.Errorf("Decompress failed: %v", err)
				done <- false
				return
			}
			if !bytes.Equal(decompressed, data) {
				t.Error("decompress mismatch")
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

func TestCompressMessage(t *testing.T) {
	data := []byte("test message for compression")

	compressed, err := CompressMessage(data)
	if err != nil {
		t.Fatalf("CompressMessage failed: %v", err)
	}

	decompressed, err := DecompressMessage(compressed)
	if err != nil {
		t.Fatalf("DecompressMessage failed: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Errorf("decompressed = %q, want %q", string(decompressed), string(data))
	}
}

func TestCompressMessageEmpty(t *testing.T) {
	_, err := CompressMessage([]byte{})
	if err != ErrEmptyData {
		t.Errorf("expected ErrEmptyData, got %v", err)
	}
}

func TestCompressMessageTooLarge(t *testing.T) {
	largeData := make([]byte, MaxCompressSize+1)
	_, err := CompressMessage(largeData)
	if err != ErrDataTooLarge {
		t.Errorf("expected ErrDataTooLarge, got %v", err)
	}
}

func TestDecompressMessageEmpty(t *testing.T) {
	_, err := DecompressMessage([]byte{})
	if err != ErrEmptyData {
		t.Errorf("expected ErrEmptyData, got %v", err)
	}
}

func TestDecompressMessageInvalid(t *testing.T) {
	_, err := DecompressMessage([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if err != ErrDecompressionFailed {
		t.Errorf("expected ErrDecompressionFailed, got %v", err)
	}
}

func TestCompressionRatio(t *testing.T) {
	original := make([]byte, 10000)
	for i := range original {
		original[i] = 'A'
	}

	compressed, _ := CompressMessage(original)
	ratio := CompressionRatio(original, compressed)

	if ratio <= 0 || ratio > 1 {
		t.Errorf("CompressionRatio = %f, should be between 0 and 1", ratio)
	}

	// Highly compressible data should have small ratio
	if ratio > 0.1 {
		t.Errorf("CompressionRatio = %f, should be very small for repetitive data", ratio)
	}
}

func TestCompressionRatioZeroOriginal(t *testing.T) {
	ratio := CompressionRatio([]byte{}, []byte{})
	if ratio != 0 {
		t.Errorf("CompressionRatio with empty original = %f, want 0", ratio)
	}
}

func TestShouldCompress(t *testing.T) {
	// Small data should not be compressed
	if ShouldCompress([]byte("hi")) {
		t.Error("small data should not be compressed")
	}

	// Large data should be compressed
	largeData := make([]byte, 128)
	if !ShouldCompress(largeData) {
		t.Error("data >= 128 bytes should be compressed")
	}

	// Just below threshold
	if ShouldCompress(make([]byte, 127)) {
		t.Error("data < 128 bytes should not be compressed")
	}
}

func TestMessageCompressor(t *testing.T) {
	mc := NewMessageCompressor(128, true)

	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i % 10)
	}

	compressed, wasCompressed, err := mc.CompressIfNeeded(data)
	if err != nil {
		t.Fatalf("CompressIfNeeded failed: %v", err)
	}

	if !wasCompressed {
		t.Error("data >= minSize should be compressed")
	}

	decompressed, err := mc.DecompressIfNeeded(compressed, wasCompressed)
	if err != nil {
		t.Fatalf("DecompressIfNeeded failed: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Error("decompressed data mismatch")
	}
}

func TestMessageCompressorBelowMinSize(t *testing.T) {
	mc := NewMessageCompressor(128, true)

	data := []byte("small data")

	compressed, wasCompressed, err := mc.CompressIfNeeded(data)
	if err != nil {
		t.Fatalf("CompressIfNeeded failed: %v", err)
	}

	if wasCompressed {
		t.Error("data below minSize should not be compressed")
	}

	if !bytes.Equal(compressed, data) {
		t.Error("uncompressed data should be returned as-is")
	}
}

func TestMessageCompressorDisabled(t *testing.T) {
	mc := NewMessageCompressor(128, false)

	data := make([]byte, 256)

	_, wasCompressed, err := mc.CompressIfNeeded(data)
	if err != nil {
		t.Fatalf("CompressIfNeeded failed: %v", err)
	}

	if wasCompressed {
		t.Error("disabled compressor should not compress")
	}
}

func TestMessageCompressorSetEnabled(t *testing.T) {
	mc := NewMessageCompressor(128, false)

	if mc.IsEnabled() {
		t.Error("should be disabled initially")
	}

	mc.SetEnabled(true)
	if !mc.IsEnabled() {
		t.Error("should be enabled after SetEnabled(true)")
	}
}

func TestMessageCompressorDecompressUncompressed(t *testing.T) {
	mc := NewMessageCompressor(128, true)

	data := []byte("uncompressed data")
	decompressed, err := mc.DecompressIfNeeded(data, false)
	if err != nil {
		t.Fatalf("DecompressIfNeeded failed: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Error("uncompressed data should be returned as-is")
	}
}

func TestCompressDecompressMessage(t *testing.T) {
	msg := &Message{Type: MsgTypeBlock, Payload: make([]byte, 500)}
	for i := range msg.Payload {
		msg.Payload[i] = byte(i % 256)
	}

	encoded, err := EncodeMessage(msg.Type, msg.Payload)
	if err != nil {
		t.Fatalf("EncodeMessage failed: %v", err)
	}

	compressed, err := CompressMessage(encoded)
	if err != nil {
		t.Fatalf("CompressMessage failed: %v", err)
	}

	decompressed, err := DecompressMessage(compressed)
	if err != nil {
		t.Fatalf("DecompressMessage failed: %v", err)
	}

	decoded, err := DecodeMessage(decompressed)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if decoded.Type != msg.Type {
		t.Errorf("Type = %d, want %d", decoded.Type, msg.Type)
	}
}

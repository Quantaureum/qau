// Quantaureum Node source, version 1.0.0.
// Package p2p provides peer-to-peer networking functionality for QAU blockchain.
package p2p

import (
	"errors"
	"sync"

	"github.com/golang/snappy"
)

// Compression errors
var (
	ErrCompressionFailed   = errors.New("compression failed")
	ErrDecompressionFailed = errors.New("decompression failed")
	ErrDataTooLarge        = errors.New("data too large for compression")
	ErrEmptyData           = errors.New("empty data")
)

// MaxCompressSize is the maximum size of data that can be compressed (100 MB)
const MaxCompressSize = 100 * 1024 * 1024

// R40-M4 FIX: maxDecompressedSize limits the maximum allowed decompressed message
// size to 16 MB. A small compressed payload can expand to a very large buffer,
// exhausting memory (decompression bomb). Snappy encodes the uncompressed length
// in the header, so we check via snappy.DecodedLen() before allocating.
const maxDecompressedSize = 16 * 1024 * 1024

// Compressor defines the interface for message compression
type Compressor interface {
	// Compress compresses the input data
	Compress(data []byte) ([]byte, error)
	// Decompress decompresses the input data
	Decompress(data []byte) ([]byte, error)
}

// SnappyCompressor implements Compressor using Snappy compression algorithm.
// Snappy is optimized for speed rather than compression ratio, making it
// ideal for P2P message compression where latency is critical.
type SnappyCompressor struct {
	mu sync.Mutex
	// encodeBuffer is reused for encoding to reduce allocations
	encodeBuffer []byte
	// decodeBuffer is reused for decoding to reduce allocations
	decodeBuffer []byte
}

// NewSnappyCompressor creates a new SnappyCompressor instance
func NewSnappyCompressor() *SnappyCompressor {
	return &SnappyCompressor{
		encodeBuffer: make([]byte, 0, 64*1024), // 64KB initial capacity
		decodeBuffer: make([]byte, 0, 64*1024), // 64KB initial capacity
	}
}

// Compress compresses the input data using Snappy algorithm.
// Returns the compressed data or an error if compression fails.
// Thread-safe: protected by internal mutex.
func (c *SnappyCompressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	if len(data) > MaxCompressSize {
		return nil, ErrDataTooLarge
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Calculate the maximum encoded length
	maxLen := snappy.MaxEncodedLen(len(data))

	// Ensure buffer has sufficient capacity
	if cap(c.encodeBuffer) < maxLen {
		c.encodeBuffer = make([]byte, maxLen)
	} else {
		c.encodeBuffer = c.encodeBuffer[:maxLen]
	}

	// Compress the data
	compressed := snappy.Encode(c.encodeBuffer, data)

	// Return a copy to avoid buffer reuse issues
	result := make([]byte, len(compressed))
	copy(result, compressed)

	return result, nil
}

// Decompress decompresses the input data using Snappy algorithm.
// Returns the decompressed data or an error if decompression fails.
// Thread-safe: protected by internal mutex.
func (c *SnappyCompressor) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	// R40-M4 FIX: Check decoded length against maxDecompressedSize (16 MB) before
	// allocating to prevent decompression bombs. A small compressed payload could
	// claim a very large uncompressed size, exhausting memory.
	decodedLen, err := snappy.DecodedLen(data)
	if err != nil {
		return nil, ErrDecompressionFailed
	}

	if decodedLen > maxDecompressedSize {
		return nil, ErrDataTooLarge
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Ensure buffer has sufficient capacity
	if cap(c.decodeBuffer) < decodedLen {
		c.decodeBuffer = make([]byte, decodedLen)
	} else {
		c.decodeBuffer = c.decodeBuffer[:decodedLen]
	}

	// Decompress the data
	decompressed, err := snappy.Decode(c.decodeBuffer, data)
	if err != nil {
		return nil, ErrDecompressionFailed
	}

	// Return a copy to avoid buffer reuse issues
	result := make([]byte, len(decompressed))
	copy(result, decompressed)

	return result, nil
}

// CompressMessage compresses a P2P message payload.
// This is a convenience function that creates a temporary compressor.
func CompressMessage(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	if len(data) > MaxCompressSize {
		return nil, ErrDataTooLarge
	}

	return snappy.Encode(nil, data), nil
}

// DecompressMessage decompresses a P2P message payload.
// This is a convenience function that creates a temporary compressor.
// #nosec audit-remediation R12-3: check decoded length BEFORE allocating to prevent decompression bombs
func DecompressMessage(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	// R40-M4 FIX: Check decoded length against maxDecompressedSize (16 MB) before
	// allocating to prevent decompression bombs. Snappy encodes uncompressed length
	// in the header, allowing pre-allocation check without decompressing.
	decodedLen, err := snappy.DecodedLen(data)
	if err != nil {
		return nil, ErrDecompressionFailed
	}
	if decodedLen > maxDecompressedSize {
		return nil, ErrDataTooLarge
	}

	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, ErrDecompressionFailed
	}

	return decompressed, nil
}

// CompressionRatio calculates the compression ratio for given data.
// Returns the ratio as compressed_size / original_size.
// A ratio < 1.0 indicates compression was effective.
func CompressionRatio(original, compressed []byte) float64 {
	if len(original) == 0 {
		return 0
	}
	return float64(len(compressed)) / float64(len(original))
}

// ShouldCompress determines if data should be compressed based on size.
// Small messages (< 128 bytes) typically don't benefit from compression.
func ShouldCompress(data []byte) bool {
	return len(data) >= 128
}

// MessageCompressor wraps compression functionality for P2P messages
// with automatic decision making about when to compress.
type MessageCompressor struct {
	compressor *SnappyCompressor
	minSize    int  // Minimum size to compress
	enabled    bool // Whether compression is enabled
}

// NewMessageCompressor creates a new MessageCompressor
func NewMessageCompressor(minSize int, enabled bool) *MessageCompressor {
	return &MessageCompressor{
		compressor: NewSnappyCompressor(),
		minSize:    minSize,
		enabled:    enabled,
	}
}

// CompressIfNeeded compresses data if it meets the size threshold.
// Returns (compressed_data, was_compressed, error)
func (mc *MessageCompressor) CompressIfNeeded(data []byte) ([]byte, bool, error) {
	if !mc.enabled || len(data) < mc.minSize {
		return data, false, nil
	}

	compressed, err := mc.compressor.Compress(data)
	if err != nil {
		return nil, false, err
	}

	// Only use compressed version if it's actually smaller
	if len(compressed) >= len(data) {
		return data, false, nil
	}

	return compressed, true, nil
}

// DecompressIfNeeded decompresses data if it was compressed.
// The wasCompressed flag indicates whether the data needs decompression.
func (mc *MessageCompressor) DecompressIfNeeded(data []byte, wasCompressed bool) ([]byte, error) {
	if !wasCompressed {
		return data, nil
	}

	return mc.compressor.Decompress(data)
}

// SetEnabled enables or disables compression
func (mc *MessageCompressor) SetEnabled(enabled bool) {
	mc.enabled = enabled
}

// IsEnabled returns whether compression is enabled
func (mc *MessageCompressor) IsEnabled() bool {
	return mc.enabled
}

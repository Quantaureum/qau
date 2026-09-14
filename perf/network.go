// Quantaureum Node source, version 1.0.0.
package perf

import (
	"bytes"
	"compress/zlib"
	"io"
	"sync"
	"time"
)

type CompressionLevel int

const (
	CompressionNone    CompressionLevel = 0
	CompressionFast    CompressionLevel = 1
	CompressionDefault CompressionLevel = 6
	CompressionBest    CompressionLevel = 9
)

// maxDecompressedBytes caps the output of Decompress (G110 / decompression
// bomb defense). It is an internal ceiling for this package; callers
// (p2p.MessageCompressor) apply their own MaxMessageSize validation on the
// decompressed result before use.
const maxDecompressedBytes = 10 * 1024 * 1024 // 10MB

type NetworkOptimizer struct {
	mu               sync.RWMutex
	compressionLevel CompressionLevel
	compressStats    CompressStats
	bufferPool       sync.Pool
}

type CompressStats struct {
	TotalCompressed   uint64
	TotalDecompressed uint64
	BytesSaved        uint64
	TotalBytes        uint64
}

func NewNetworkOptimizer(level CompressionLevel) *NetworkOptimizer {
	return &NetworkOptimizer{
		compressionLevel: level,
		bufferPool: sync.Pool{
			New: func() any {
				return new(bytes.Buffer)
			},
		},
	}
}

func (no *NetworkOptimizer) Compress(data []byte) ([]byte, error) {
	if no.compressionLevel == CompressionNone {
		return data, nil
	}

	buf := no.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer no.bufferPool.Put(buf)

	w, err := zlib.NewWriterLevel(buf, int(no.compressionLevel))
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(data); err != nil {
		w.Close()
		return nil, err
	}
	w.Close()

	compressed := make([]byte, buf.Len())
	copy(compressed, buf.Bytes())

	no.mu.Lock()
	no.compressStats.TotalCompressed++
	no.compressStats.TotalBytes += uint64(len(data))
	no.compressStats.BytesSaved += uint64(len(data) - len(compressed))
	no.mu.Unlock()

	return compressed, nil
}

func (no *NetworkOptimizer) Decompress(data []byte) ([]byte, error) {
	if no.compressionLevel == CompressionNone {
		return data, nil
	}

	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	buf := no.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer no.bufferPool.Put(buf)

	// G110 fix (2026-08-20): cap decompressed output at MaxMessageSize to
	// prevent a decompression bomb (a tiny compressed input expanding to
	// gigabytes and exhausting memory). LimitReader stops the copy once the
	// cap is reached; if the bomb exceeds it, the truncated buffer fails the
	// caller's length validation downstream.
	limited := io.LimitReader(r, maxDecompressedBytes)
	if _, err := io.Copy(buf, limited); err != nil {
		return nil, err
	}

	decompressed := make([]byte, buf.Len())
	copy(decompressed, buf.Bytes())

	no.mu.Lock()
	no.compressStats.TotalDecompressed++
	no.mu.Unlock()

	return decompressed, nil
}

func (no *NetworkOptimizer) GetStats() CompressStats {
	no.mu.RLock()
	defer no.mu.RUnlock()
	return no.compressStats
}

func (no *NetworkOptimizer) CompressionRatio() float64 {
	no.mu.RLock()
	defer no.mu.RUnlock()

	if no.compressStats.TotalBytes == 0 {
		return 0
	}
	return float64(no.compressStats.BytesSaved) / float64(no.compressStats.TotalBytes)
}

type MessageBatcher struct {
	mu          sync.Mutex
	buffer      [][]byte
	maxSize     int
	maxWait     time.Duration
	lastFlush   time.Time
	flushSignal chan struct{}
}

func NewMessageBatcher(maxSize int, maxWait time.Duration) *MessageBatcher {
	return &MessageBatcher{
		buffer:      make([][]byte, 0, maxSize),
		maxSize:     maxSize,
		maxWait:     maxWait,
		lastFlush:   time.Now(),
		flushSignal: make(chan struct{}, 1),
	}
}

func (mb *MessageBatcher) Add(msg []byte) [][]byte {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.buffer = append(mb.buffer, msg)

	if len(mb.buffer) >= mb.maxSize || time.Since(mb.lastFlush) >= mb.maxWait {
		return mb.flush()
	}

	return nil
}

func (mb *MessageBatcher) flush() [][]byte {
	if len(mb.buffer) == 0 {
		return nil
	}

	batch := make([][]byte, len(mb.buffer))
	copy(batch, mb.buffer)
	mb.buffer = mb.buffer[:0]
	mb.lastFlush = time.Now()

	return batch
}

func (mb *MessageBatcher) ForceFlush() [][]byte {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	return mb.flush()
}

func (mb *MessageBatcher) Size() int {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	return len(mb.buffer)
}

type AdaptiveThrottle struct {
	mu           sync.Mutex
	currentRate  float64
	minRate      float64
	maxRate      float64
	windowSize   time.Duration
	requestCount int
	windowStart  time.Time
	lastAdjust   time.Time
}

func NewAdaptiveThrottle(minRate, maxRate float64) *AdaptiveThrottle {
	return &AdaptiveThrottle{
		currentRate: maxRate,
		minRate:     minRate,
		maxRate:     maxRate,
		windowSize:  time.Second,
		windowStart: time.Now(),
		lastAdjust:  time.Now(),
	}
}

func (at *AdaptiveThrottle) Allow() bool {
	at.mu.Lock()
	defer at.mu.Unlock()

	now := time.Now()
	if now.Sub(at.windowStart) >= at.windowSize {
		at.requestCount = 0
		at.windowStart = now
	}

	expected := int(at.currentRate * at.windowSize.Seconds())
	if at.requestCount >= expected {
		return false
	}

	at.requestCount++
	return true
}

func (at *AdaptiveThrottle) AdjustRate(successRate float64) {
	at.mu.Lock()
	defer at.mu.Unlock()

	if successRate > 0.95 {
		at.currentRate *= 1.1
	} else if successRate < 0.8 {
		at.currentRate *= 0.9
	}

	if at.currentRate > at.maxRate {
		at.currentRate = at.maxRate
	}
	if at.currentRate < at.minRate {
		at.currentRate = at.minRate
	}

	at.lastAdjust = time.Now()
}

func (at *AdaptiveThrottle) GetCurrentRate() float64 {
	at.mu.Lock()
	defer at.mu.Unlock()
	return at.currentRate
}

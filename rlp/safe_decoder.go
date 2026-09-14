// Quantaureum Node source, version 1.0.0.
// Package rlp provides safe RLP decoding with bounds checking.
// This file implements SafeDecoder which wraps RLP decoding with additional
// security measures to prevent malformed input attacks.
//
// Requirements: 3.1, 3.2 - Input validation strengthening for RLP decoder
package rlp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
)

// Safe decoding errors
var (
	// ErrMaxSizeExceeded is returned when decoded data exceeds the maximum allowed size
	ErrMaxSizeExceeded = errors.New("rlp: decoded data exceeds maximum size limit")
	// ErrMaxDepthExceeded is returned when nesting depth exceeds the maximum allowed
	ErrMaxDepthExceeded = errors.New("rlp: nesting depth exceeds maximum limit")
	// ErrMaxListLenExceeded is returned when list length exceeds the maximum allowed
	ErrMaxListLenExceeded = errors.New("rlp: list length exceeds maximum limit")
	// ErrInvalidInput is returned when input is fundamentally malformed
	ErrInvalidInput = errors.New("rlp: invalid input data")
	// ErrNilInput is returned when input is nil
	ErrNilInput = errors.New("rlp: nil input data")
)

// Default limits for safe decoding.
//
// RLP-R11-003 (2026-07-20): Previously these constants were hardcoded
// independently of the underlying Stream limits in decode.go. This caused
// an inconsistency where SafeDecoder claimed to allow 16 MB input
// (DefaultMaxSize) but the underlying DecodeBytes rejects inputs > 10 MB
// (maxRLPSize). SafeDecoder is the first line of defense and MUST be at
// least as strict as the Stream it ultimately delegates to — otherwise
// its size check is a no-op and the real rejection happens deeper in the
// stack, defeating the "fail-early" goal of the SafeDecoder wrapper.
//
// The defaults now reference the Stream constants directly so any future
// adjustment to the underlying limits automatically propagates to
// SafeDecoder. Callers that need a stricter limit can still pass a custom
// SafeDecoderConfig with smaller values.
const (
	// DefaultMaxSize mirrors maxRLPSize: the maximum total input size
	// accepted by SafeDecoder. Equal to the Stream limit so the SafeDecoder
	// check is the effective first gate (not a redundant no-op).
	DefaultMaxSize = maxRLPSize
	// DefaultMaxDepth mirrors maxNestingDepth: the maximum list nesting
	// depth accepted by SafeDecoder.
	DefaultMaxDepth = maxNestingDepth
	// DefaultMaxListLen mirrors maxSliceElements: the maximum number of
	// elements allowed in a single decoded list.
	DefaultMaxListLen = maxSliceElements
)

// SafeDecoderConfig holds configuration for safe decoding
type SafeDecoderConfig struct {
	// MaxSize is the maximum total size of decoded data in bytes
	MaxSize uint64
	// MaxDepth is the maximum nesting depth for lists
	MaxDepth int
	// MaxListLen is the maximum number of elements in a list
	MaxListLen int
	// StrictMode enables strict validation (reject any non-canonical input)
	StrictMode bool
}

// DefaultSafeDecoderConfig returns the default safe decoder configuration
func DefaultSafeDecoderConfig() SafeDecoderConfig {
	return SafeDecoderConfig{
		MaxSize:    DefaultMaxSize,
		MaxDepth:   DefaultMaxDepth,
		MaxListLen: DefaultMaxListLen,
		StrictMode: true,
	}
}

// SafeDecoder wraps RLP decoder with additional bounds checking
// Requirements: 3.1 - Verify bounds before all slice operations
// Requirements: 3.2 - Enforce maximum size limits for decoded data
type SafeDecoder struct {
	config SafeDecoderConfig
}

// NewSafeDecoder creates a new SafeDecoder with the given configuration
func NewSafeDecoder(config SafeDecoderConfig) *SafeDecoder {
	// Apply defaults for zero values
	if config.MaxSize == 0 {
		config.MaxSize = DefaultMaxSize
	}
	if config.MaxDepth == 0 {
		config.MaxDepth = DefaultMaxDepth
	}
	if config.MaxListLen == 0 {
		config.MaxListLen = DefaultMaxListLen
	}
	return &SafeDecoder{config: config}
}

// NewDefaultSafeDecoder creates a SafeDecoder with default configuration
func NewDefaultSafeDecoder() *SafeDecoder {
	return NewSafeDecoder(DefaultSafeDecoderConfig())
}

// DecodeBytes safely decodes RLP data from a byte slice into val.
// It performs bounds checking and enforces size limits before decoding.
// Requirements: 3.1, 3.2
func (d *SafeDecoder) DecodeBytes(input []byte, val any) error {
	// Check for nil input
	if input == nil {
		return ErrNilInput
	}

	// Check input size against maximum
	if uint64(len(input)) > d.config.MaxSize {
		return fmt.Errorf("%w: input size %d exceeds limit %d", ErrMaxSizeExceeded, len(input), d.config.MaxSize)
	}

	// Validate input structure before decoding
	if err := d.validateInput(input); err != nil {
		return err
	}

	// Use the standard decoder with input limit
	return DecodeBytes(input, val)
}

// Decode safely decodes RLP data from a reader into val.
// Requirements: 3.1, 3.2
func (d *SafeDecoder) Decode(r io.Reader, val any) error {
	if r == nil {
		return ErrNilInput
	}

	// Safe conversion: check for int64 overflow before creating limited reader
	maxSize := d.config.MaxSize
	if maxSize > math.MaxInt64 {
		maxSize = math.MaxInt64
	}
	// Create a limited reader to enforce size limits
	limitedReader := io.LimitReader(r, int64(maxSize)) // #nosec G115 - overflow checked above

	// Read all data first to validate
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("rlp: failed to read input: %w", err)
	}

	return d.DecodeBytes(data, val)
}

// validateInput performs structural validation of RLP input
// without fully decoding it. This catches malformed input early.
func (d *SafeDecoder) validateInput(input []byte) error {
	if len(input) == 0 {
		return nil // Empty input is valid (will be handled by decoder)
	}

	// Validate the structure recursively
	_, err := d.validateElement(input, 0, 0)
	return err
}

// validateElement validates a single RLP element and returns the number of bytes consumed
func (d *SafeDecoder) validateElement(input []byte, offset int, depth int) (int, error) {
	// Check depth limit
	if depth >= d.config.MaxDepth {
		return 0, fmt.Errorf("%w: depth %d at offset %d", ErrMaxDepthExceeded, depth, offset)
	}

	// Check bounds
	if offset >= len(input) {
		return 0, fmt.Errorf("%w: unexpected end of input at offset %d", ErrInvalidInput, offset)
	}

	b := input[offset]

	switch {
	case b < 0x80:
		// Single byte value
		return 1, nil

	case b < 0xB8:
		// Short string (0-55 bytes)
		size := int(b - 0x80)
		totalSize := 1 + size

		// Bounds check
		if offset+totalSize > len(input) {
			return 0, fmt.Errorf("%w: short string at offset %d claims %d bytes but only %d available",
				ErrInvalidInput, offset, size, len(input)-offset-1)
		}

		// SECURITY (audit DATA-08): Canonical check — a 1-byte string with
		// value < 0x80 must be encoded as a single byte (b < 0x80), not as
		// 0x81 + byte (short string prefix). The non-canonical form enables
		// malleability. This structural check catches the issue before the
		// decoder even reads the content.
		if d.config.StrictMode && size == 1 && input[offset+1] < 0x80 {
			return 0, fmt.Errorf("%w: non-canonical 1-byte string at offset %d", ErrCanonicalSize, offset)
		}

		return totalSize, nil

	case b < 0xC0:
		// Long string (>55 bytes)
		sizeBytes := int(b - 0xB7)

		// Bounds check for size bytes
		if offset+1+sizeBytes > len(input) {
			return 0, fmt.Errorf("%w: long string header at offset %d incomplete", ErrInvalidInput, offset)
		}

		// Read size
		size, err := d.readSize(input[offset+1:offset+1+sizeBytes], offset)
		if err != nil {
			return 0, err
		}

		// Canonical check: size must be > 55 for long form
		if d.config.StrictMode && size < 56 {
			return 0, fmt.Errorf("%w: non-canonical size encoding at offset %d", ErrCanonicalSize, offset)
		}

		// Safe conversion: check for int overflow before computing totalSize
		if size > uint64(math.MaxInt-1-sizeBytes) { //nolint:gosec,G115
			return 0, fmt.Errorf("%w: size %d would overflow at offset %d", ErrInvalidInput, size, offset)
		}
		totalSize := 1 + sizeBytes + int(size) //nolint:gosec,G115

		// Bounds check
		if offset+totalSize > len(input) {
			return 0, fmt.Errorf("%w: long string at offset %d claims %d bytes but only %d available",
				ErrInvalidInput, offset, size, len(input)-offset-1-sizeBytes)
		}

		// Size limit check
		if size > d.config.MaxSize {
			return 0, fmt.Errorf("%w: string size %d exceeds limit %d", ErrMaxSizeExceeded, size, d.config.MaxSize)
		}

		return totalSize, nil

	case b < 0xF8:
		// Short list (0-55 bytes)
		size := int(b - 0xC0)
		headerSize := 1

		// Bounds check
		if offset+headerSize+size > len(input) {
			return 0, fmt.Errorf("%w: short list at offset %d claims %d bytes but only %d available",
				ErrInvalidInput, offset, size, len(input)-offset-headerSize)
		}

		// Validate list contents
		if err := d.validateListContents(input, offset+headerSize, size, depth+1); err != nil {
			return 0, err
		}

		return headerSize + size, nil

	default:
		// Long list (>55 bytes)
		sizeBytes := int(b - 0xF7)

		// Bounds check for size bytes
		if offset+1+sizeBytes > len(input) {
			return 0, fmt.Errorf("%w: long list header at offset %d incomplete", ErrInvalidInput, offset)
		}

		// Read size
		size, err := d.readSize(input[offset+1:offset+1+sizeBytes], offset)
		if err != nil {
			return 0, err
		}

		// Canonical check: size must be > 55 for long form
		if d.config.StrictMode && size < 56 {
			return 0, fmt.Errorf("%w: non-canonical size encoding at offset %d", ErrCanonicalSize, offset)
		}

		headerSize := 1 + sizeBytes

		// Safe conversion: check for int overflow before computing sizes
		if size > uint64(math.MaxInt) {
			return 0, fmt.Errorf("%w: size %d would overflow at offset %d", ErrInvalidInput, size, offset)
		}
		sizeInt := int(size) // #nosec G115 - overflow checked above

		// Bounds check
		if offset+headerSize+sizeInt > len(input) {
			return 0, fmt.Errorf("%w: long list at offset %d claims %d bytes but only %d available",
				ErrInvalidInput, offset, size, len(input)-offset-headerSize)
		}

		// Size limit check
		if size > d.config.MaxSize {
			return 0, fmt.Errorf("%w: list size %d exceeds limit %d", ErrMaxSizeExceeded, size, d.config.MaxSize)
		}

		// Validate list contents
		if err := d.validateListContents(input, offset+headerSize, sizeInt, depth+1); err != nil {
			return 0, err
		}

		return headerSize + sizeInt, nil
	}
}

// validateListContents validates all elements within a list
func (d *SafeDecoder) validateListContents(input []byte, start int, size int, depth int) error {
	end := start + size
	pos := start
	elementCount := 0

	for pos < end {
		// Check list length limit
		elementCount++
		if elementCount > d.config.MaxListLen {
			return fmt.Errorf("%w: list has more than %d elements", ErrMaxListLenExceeded, d.config.MaxListLen)
		}

		consumed, err := d.validateElement(input, pos, depth)
		if err != nil {
			return err
		}
		pos += consumed
	}

	// Verify we consumed exactly the right amount
	if pos != end {
		return fmt.Errorf("%w: list content size mismatch at offset %d", ErrInvalidInput, start)
	}

	return nil
}

// readSize reads a big-endian size from bytes
func (d *SafeDecoder) readSize(b []byte, offset int) (uint64, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("%w: empty size at offset %d", ErrInvalidInput, offset)
	}

	// Canonical check: no leading zeros
	if d.config.StrictMode && b[0] == 0 {
		return 0, fmt.Errorf("%w: leading zero in size at offset %d", ErrCanonicalSize, offset)
	}

	var size uint64
	for _, x := range b {
		size = (size << 8) | uint64(x)
	}

	return size, nil
}

// SafeDecodeBytes is a convenience function that decodes with default safe settings
// Requirements: 3.1, 3.2
func SafeDecodeBytes(input []byte, val any) error {
	decoder := NewDefaultSafeDecoder()
	return decoder.DecodeBytes(input, val)
}

// SafeDecode is a convenience function that decodes from a reader with default safe settings
// Requirements: 3.1, 3.2
func SafeDecode(r io.Reader, val any) error {
	decoder := NewDefaultSafeDecoder()
	return decoder.Decode(r, val)
}

// SafeDecodeWithLimit decodes with a custom size limit
// Requirements: 3.1, 3.2
func SafeDecodeWithLimit(input []byte, val any, maxSize uint64) error {
	config := DefaultSafeDecoderConfig()
	config.MaxSize = maxSize
	decoder := NewSafeDecoder(config)
	return decoder.DecodeBytes(input, val)
}

// ValidateRLPStructure validates RLP structure without decoding
// Returns nil if the input is structurally valid RLP
// Requirements: 3.1
func ValidateRLPStructure(input []byte) error {
	decoder := NewDefaultSafeDecoder()
	return decoder.validateInput(input)
}

// ValidateRLPStructureWithConfig validates RLP structure with custom config
// Requirements: 3.1
func ValidateRLPStructureWithConfig(input []byte, config SafeDecoderConfig) error {
	decoder := NewSafeDecoder(config)
	return decoder.validateInput(input)
}

// SafeStream wraps Stream with additional safety checks
type SafeStream struct {
	*Stream
	config     SafeDecoderConfig
	depthStack []int
	// totalRead tracks the cumulative bytes returned by Bytes() across all
	// calls on this SafeStream instance.
	//
	// RLP-R11-004 (2026-07-20): SafeDecoderConfig.MaxSize is documented as
	// "maximum total size of decoded data in bytes" but previously
	// SafeStream.Bytes() only used it as a per-string limit. A caller
	// issuing many small Bytes() calls could collectively read more than
	// MaxSize while each individual call passed the per-string check.
	//
	// The underlying Stream has its own totalDecoded budget (capped at
	// maxTotalDecodeMemory = 32 MB, hardcoded in decode.go) that fires via
	// Stream.Bytes() — so the audit's "delegate to underlying Stream"
	// alternative IS technically satisfied. But that hardcoded 32 MB limit
	// is independent of s.config.MaxSize: a caller who sets MaxSize=1MB
	// expects 1 MB to be the total budget, not 32 MB. Tracking totalRead at
	// SafeStream level makes the configured MaxSize actually mean what its
	// doc says, with the Stream's 32 MB cap acting as defense-in-depth.
	totalRead uint64
}

// NewSafeStream creates a new safe stream with bounds checking
func NewSafeStream(r io.Reader, config SafeDecoderConfig) *SafeStream {
	// Apply defaults
	if config.MaxSize == 0 {
		config.MaxSize = DefaultMaxSize
	}
	if config.MaxDepth == 0 {
		config.MaxDepth = DefaultMaxDepth
	}
	if config.MaxListLen == 0 {
		config.MaxListLen = DefaultMaxListLen
	}

	// RLP-R11-004 (2026-07-20): The underlying Stream's inputLimit bounds
	// how many bytes can be READ from the underlying reader. SafeStream's
	// config.MaxSize is the budget for total DECODED bytes returned via
	// Bytes() — a different concept. The input may contain list/string
	// headers and structural bytes that don't count toward the decoded
	// budget, so the input size can legitimately exceed MaxSize.
	//
	// Previously NewSafeStream passed config.MaxSize as inputLimit, which
	// made the inputLimit fire BEFORE the SafeStream total-bytes check had
	// a chance to operate — masking the audit's RLP-R11-004 concern. Now
	// we pass a separate, generous input limit (maxRLPSize = 10 MB, the
	// same default used by DecodeBytes) for the Stream's input bounding,
	// and rely on SafeStream's totalRead tracking (in Bytes() below) to
	// enforce config.MaxSize as the cumulative decoded-bytes budget.
	//
	// Defense-in-depth layers (outermost → innermost):
	//   1. SafeDecoderConfig.MaxSize (SafeStream.totalRead): caller-configurable
	//      total-decoded-bytes budget. Fires in SafeStream.Bytes().
	//   2. maxTotalDecodeMemory (Stream.totalDecoded, 32 MB hardcoded in
	//      decode.go): Stream-level budget on total String-kind bytes
	//      returned. Fires in Stream.Bytes().
	//   3. maxRLPSize (Stream inputLimit, 10 MB): bounds total bytes read
	//      from the underlying reader. Prevents a malicious io.Reader from
	//      keeping the Stream busy forever.
	// Each layer is independent; the strictest (smallest) limit fires first.
	streamInputLimit := uint64(maxRLPSize)
	if config.MaxSize > streamInputLimit {
		// Caller asked for a larger decoded budget than maxRLPSize — allow
		// reading that much input too, otherwise we'd reject legitimate
		// inputs that fit within the caller's chosen budget.
		streamInputLimit = config.MaxSize
	}

	return &SafeStream{
		Stream:     NewStream(r, streamInputLimit),
		config:     config,
		depthStack: make([]int, 0, config.MaxDepth),
	}
}

// NewSafeStreamFromBytes creates a safe stream from a byte slice
func NewSafeStreamFromBytes(input []byte, config SafeDecoderConfig) *SafeStream {
	return NewSafeStream(bytes.NewReader(input), config)
}

// List starts decoding a list with depth checking
func (s *SafeStream) List() (uint64, error) {
	// Check depth before entering list
	if len(s.depthStack) >= s.config.MaxDepth {
		return 0, fmt.Errorf("%w: current depth %d", ErrMaxDepthExceeded, len(s.depthStack))
	}

	size, err := s.Stream.List()
	if err != nil {
		return 0, err
	}

	// Track depth
	s.depthStack = append(s.depthStack, 0)

	return size, nil
}

// ListEnd ends list decoding with depth tracking
func (s *SafeStream) ListEnd() error {
	err := s.Stream.ListEnd()
	if err != nil {
		return err
	}

	// Pop depth stack
	if len(s.depthStack) > 0 {
		s.depthStack = s.depthStack[:len(s.depthStack)-1]
	}

	return nil
}

// Bytes reads bytes with size limit checking.
//
// RLP-R11-004 (2026-07-20) FIX: Previously this method only checked the
// per-string size against s.config.MaxSize. SafeDecoderConfig.MaxSize is
// documented as "maximum total size of decoded data in bytes", but the
// per-string check doesn't enforce a TOTAL budget — a caller that issues
// many Bytes() calls in a loop can collectively read more than MaxSize
// while each individual call passes the per-string limit.
//
// The fix adds cumulative tracking via s.totalRead: each successful Bytes()
// call adds the returned byte count to totalRead, and the next call fails
// when totalRead + size would exceed MaxSize.
//
// Defense-in-depth: the underlying Stream also tracks its own totalDecoded
// against maxTotalDecodeMemory (hardcoded 32 MB in decode.go). When
// s.config.MaxSize is smaller than maxTotalDecodeMemory, the SafeStream
// check fires first (stricter limit wins). When s.config.MaxSize is larger,
// the Stream check fires first.
//
// Accounting choice: only String kind contributes to totalRead (matching
// the Stream's totalDecoded semantics in decode.go, which also counts only
// String kind — see Stream.Bytes case String at line 189). Byte kind
// returns a single byte via s.byteval with no allocation; counting it
// would diverge from Stream's accounting and create test inconsistencies.
func (s *SafeStream) Bytes() ([]byte, error) {
	kind, size, err := s.Stream.Kind()
	if err != nil {
		return nil, err
	}

	// Per-string size limit check (existing).
	if kind == String && size > s.config.MaxSize {
		return nil, fmt.Errorf("%w: string size %d exceeds limit %d", ErrMaxSizeExceeded, size, s.config.MaxSize)
	}

	// RLP-R11-004: cumulative total-memory budget check. The per-string
	// check above only validates a single Bytes() call's output. Without
	// this cumulative check, a caller issuing N small Bytes() calls could
	// collectively read N*size bytes — exceeding s.config.MaxSize while
	// each individual call passes the per-string limit.
	if kind == String {
		// Guard against uint64 overflow: if totalRead+size wraps around,
		// the value is definitely larger than any reasonable MaxSize.
		if s.totalRead+size < s.totalRead {
			return nil, fmt.Errorf("%w: cumulative decoded size overflow (totalRead=%d, size=%d)",
				ErrMaxSizeExceeded, s.totalRead, size)
		}
		if s.totalRead+size > s.config.MaxSize {
			return nil, fmt.Errorf("%w: cumulative decoded size %d + %d exceeds limit %d",
				ErrMaxSizeExceeded, s.totalRead, size, s.config.MaxSize)
		}
	}

	// Delegate to the underlying Stream, which enforces its own
	// maxTotalDecodeMemory budget (32 MB hardcoded) as defense-in-depth
	// and performs the actual read.
	b, err := s.Stream.Bytes()
	if err != nil {
		return nil, err
	}

	// RLP-R11-004: accumulate on successful read. Use the actual returned
	// slice length rather than `size` from Kind() — they should match for
	// String kind, but using len(b) is the source of truth.
	if kind == String {
		s.totalRead += uint64(len(b))
	}

	return b, nil
}

// TotalRead returns the cumulative number of bytes returned by Bytes() so
// far on this SafeStream. Useful for tests and observability.
//
// RLP-R11-004 (2026-07-20).
func (s *SafeStream) TotalRead() uint64 {
	return s.totalRead
}

// Quantaureum Node source, version 1.0.0.
package rlp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
)

// Decoding errors
var (
	// ErrExpectedString is returned when a string was expected but a list was found
	ErrExpectedString = errors.New("rlp: expected string")
	// ErrExpectedList is returned when a list was expected but a string was found
	ErrExpectedList = errors.New("rlp: expected list")
	// ErrCanonicalInt is returned when an integer is not in canonical form
	ErrCanonicalInt = errors.New("rlp: non-canonical integer format")
	// ErrCanonicalSize is returned when a size is not in canonical form
	ErrCanonicalSize = errors.New("rlp: non-canonical size information")
	// ErrValueTooLarge is returned when a value is too large
	ErrValueTooLarge = errors.New("rlp: value too large")
	// ErrMoreThanOneValue is returned when input contains more than one value
	ErrMoreThanOneValue = errors.New("rlp: input contains more than one value")
	// ErrElemTooLarge is returned when an element is larger than the containing list
	ErrElemTooLarge = errors.New("rlp: element is larger than containing list")
	// ErrEOL is returned when the end of the current list has been reached
	ErrEOL = errors.New("rlp: end of list")
	// EOL is an alias for ErrEOL for backward compatibility
	// Deprecated: Use ErrEOL instead
	EOL = ErrEOL
)

// Decoder is implemented by types that require custom RLP decoding rules.
type Decoder interface {
	DecodeRLP(s *Stream) error
}

// Decode parses RLP-encoded data from r and stores the result in val.
// Val must be a pointer.
//
// RLP- (2026-07-20): Previously called NewStream(r, 0) which sets
// inputLimit=0 (unlimited). A peer could send a gigantic RLP blob over P2P
// and trigger OOM before per-element limits kicked in. Now apply maxRLPSize
// (10 MB) as the default upper bound — same limit DecodeBytes already uses.
// Callers needing a larger limit (e.g. block body) should use
// NewStream(r, customLimit) directly and document why.
func Decode(r io.Reader, val any) error {
	stream := NewStream(r, maxRLPSize)
	return stream.Decode(val)
}

// DecodeBytes parses RLP data from b into val.
// Val must be a pointer.
func DecodeBytes(b []byte, val any) error {
	// FIX (P3): Upfront input size check before decoding. Reject inputs
	// larger than maxRLPSize (10 MB) immediately so a huge blob never enters the
	// streaming decoder. This is a fast-path guard; the decoder's per-element
	// limits (maxStringSize, maxSliceElements, maxTotalDecodeMemory) remain the
	// authoritative defense against crafted payloads.
	if uint64(len(b)) > uint64(maxRLPSize) {
		return fmt.Errorf("rlp: input size %d exceeds maximum %d", len(b), maxRLPSize)
	}
	r := bytes.NewReader(b)
	// Create stream - bytes.Reader implements ByteReader so no buffering needed
	stream := &Stream{r: r, limited: true, limit: uint64(len(b)), kind: -1}
	if err := stream.Decode(val); err != nil {
		return err
	}
	// Check if there's remaining data by checking the reader position
	if r.Len() > 0 {
		return ErrMoreThanOneValue
	}
	return nil
}

// maxNestingDepth is the maximum allowed nesting depth for RLP lists.
// audit-fix M-10: prevents unbounded memory growth from deeply nested payloads.
const maxNestingDepth = 64

// R40-M8 FIX: maxSliceElements limits the number of elements that decodeSlice
// will decode from a single RLP list. Without this, a crafted payload claiming
// millions of list elements can exhaust memory during decoding.
const maxSliceElements = 1048576 // 1M elements

// maxStringSize limits the size of a single RLP string to prevent OOM
// from malicious payloads with huge size headers.
const maxStringSize = 16 * 1024 * 1024 // 16 MB

// maxRLPSize is the maximum allowed size for a single RLP element (string or
// list) decoded by readKind. This prevents denial-of-service attacks where a
// malicious payload declares an extremely large size, causing the decoder to
// attempt huge memory allocations.
// L16-006 FIX: Previously readKind had no upper limit on Long List sizes.
const maxRLPSize = 10 * 1024 * 1024 // 10 MB

// SECURITY (audit P2-13): Total decode memory budget to prevent OOM DoS.
// Even with maxSliceElements and maxStringSize limits, a malicious payload
// can still allocate up to 1M * 16MB = 16TB. This budget caps the total.
const maxTotalDecodeMemory = 32 * 1024 * 1024 // 32 MB total per decode

// SECURITY (): Limit the total number of Bytes() calls per stream.
// The memory budget granularity (10MB per string vs 32MB total) allows many
// small allocations that individually pass the size check but collectively
// exhaust resources. This call count limit caps the total number of
// individual byte-slice extractions, preventing excessive allocation churn.
const maxBytesCalls = 10000

// Kind represents the kind of value contained in an RLP stream.
type Kind int8

const (
	// Byte is a single byte value < 0x80
	Byte Kind = iota
	// String is a string (byte array)
	String
	// List is a list of values
	List
)

func (k Kind) String() string {
	switch k {
	case Byte:
		return "Byte"
	case String:
		return "String"
	case List:
		return "List"
	default:
		return fmt.Sprintf("Unknown(%d)", k)
	}
}

// Stream is used for piecemeal decoding of an RLP input stream.
type Stream struct {
	r       io.Reader
	buf     []byte // buffer for reading
	byteval byte   // single byte value
	kind    Kind   // kind of value ahead
	size    uint64 // size of value ahead
	kinderr error  // error from last readKind
	stack   []uint64
	limited bool
	limit   uint64
	// SECURITY (audit P2-13): Track total decoded bytes to enforce memory budget.
	totalDecoded uint64
	// SECURITY (): Track total Bytes() calls to enforce a call count limit.
	callCount int
}

// NewStream creates a new decoding stream reading from r.
// If r implements the ByteReader interface, Stream will not introduce any buffering.
// If inputLimit is non-zero, the stream will return an error if the input exceeds the limit.
func NewStream(r io.Reader, inputLimit uint64) *Stream {
	s := &Stream{r: r, limited: inputLimit > 0, limit: inputLimit, kind: -1}
	if _, ok := r.(io.ByteReader); !ok {
		s.r = bufio.NewReader(r)
	}
	return s
}

// Bytes reads an RLP string and returns its contents as a byte slice.
func (s *Stream) Bytes() ([]byte, error) {
	// SECURITY (): Enforce a call count limit to prevent excessive
	// individual allocations that bypass the total memory budget granularity.
	s.callCount++
	if s.callCount > maxBytesCalls {
		return nil, fmt.Errorf("rlp: number of Bytes() calls %d exceeds limit %d", s.callCount, maxBytesCalls)
	}
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	switch kind {
	case Byte:
		s.kind = -1 // rearm Kind
		return []byte{s.byteval}, nil
	case String:
		if size > maxStringSize {
			return nil, fmt.Errorf("rlp: string size %d exceeds limit %d", size, maxStringSize)
		}
		// SECURITY (audit P2-13): Enforce total decode memory budget
		if s.totalDecoded+size > maxTotalDecodeMemory {
			return nil, fmt.Errorf("rlp: total decoded memory %d exceeds budget %d", s.totalDecoded+size, maxTotalDecodeMemory)
		}
		s.totalDecoded += size
		b := make([]byte, size)
		if err := s.readFull(b); err != nil {
			return nil, err
		}
		s.kind = -1 // rearm Kind
		// SECURITY (audit DATA-08): A 1-byte string with value < 0x80 must be
		// encoded as a single byte (Byte kind), not as 0x81 + byte (String kind).
		// Accepting the non-canonical form enables malleability: the same logical
		// value would have two valid encodings, breaking signature uniqueness.
		if size == 1 && b[0] < 0x80 {
			return nil, ErrCanonicalSize
		}
		return b, nil
	default:
		return nil, ErrExpectedString
	}
}

// Raw reads a raw encoded value including RLP type information.
//
// RLP- (2026-07-20): Apply the same canonical-encoding check as
// Bytes(). Previously Raw() returned the raw RLP bytes verbatim, allowing
// a 1-byte string with value < 0x80 (e.g. 0x81 0x42 for byte 0x42) to be
// accepted alongside the canonical single-byte encoding (0x42). Two valid
// encodings of the same logical value enable signature malleability:
// an attacker can produce two distinct hashes/Signatures for the same
// payload, breaking transaction uniqueness and consensus agreement.
// The canonical rule: a 1-byte string with value < 0x80 MUST be encoded
// as a single Byte kind, not as a String kind with a 0x81 length prefix.
func (s *Stream) Raw() ([]byte, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	if kind == Byte {
		s.kind = -1 // rearm Kind
		return []byte{s.byteval}, nil
	}
	// Read the header
	start := s.readBuf()
	// Read the content
	if size > maxStringSize {
		return nil, fmt.Errorf("rlp: string size %d exceeds limit %d", size, maxStringSize)
	}
	// SECURITY (): Enforce total decode memory budget for Raw().
	//  Make totalDecoded accounting consistent with Bytes(), which
	// counts only the content bytes (size), not the RLP header bytes. The
	// header (start) is a small, transient copy; counting only size keeps
	// the budget semantics identical between Bytes() and Raw().
	if s.totalDecoded+size > maxTotalDecodeMemory {
		return nil, fmt.Errorf("rlp: total decoded memory %d exceeds budget %d", s.totalDecoded+size, maxTotalDecodeMemory)
	}
	s.totalDecoded += size
	content := make([]byte, size)
	if err := s.readFull(content); err != nil {
		return nil, err
	}
	s.kind = -1 // rearm Kind
	// RLP- canonical-encoding check mirroring Bytes(). A 1-byte
	// string with value < 0x80 is non-canonical (must be encoded as Byte
	// kind). Rejecting here prevents signature malleability from two
	// valid encodings of the same logical value.
	if size == 1 && content[0] < 0x80 {
		return nil, ErrCanonicalSize
	}
	return append(start, content...), nil
}

func (s *Stream) readBuf() []byte {
	b := make([]byte, len(s.buf))
	copy(b, s.buf)
	s.buf = s.buf[:0]
	return b
}

// Uint reads an RLP string of up to 8 bytes and returns its contents as an unsigned integer.
func (s *Stream) Uint() (uint64, error) {
	return s.uint(64)
}

func (s *Stream) uint(maxbits int) (uint64, error) {
	kind, size, err := s.Kind()
	if err != nil {
		return 0, err
	}
	switch kind {
	case Byte:
		s.kind = -1 // rearm Kind
		// SECURITY (audit DATA-08): 0x00 is non-canonical for integer 0.
		// The canonical encoding of integer 0 is 0x80 (empty string).
		// The byte 0x00 is the canonical encoding of byte string [0x00],
		// which is a different value when interpreted as an integer.
		if s.byteval == 0x00 {
			return 0, ErrCanonicalInt
		}
		return uint64(s.byteval), nil
	case String:
		// RLP- (2026-07-20): Documented size=0 behavior.
		// Integer 0 is canonically encoded as the empty string 0x80, which
		// has String kind and size=0. The empty-byte-loop below leaves v=0
		// and returns (0, nil) — the correct behavior. Both canonical-zero
		// checks below (leading-zero and 1-byte-with-value-<0x80) are
		// correctly guarded by `size > 0` / `size == 1`, so they don't fire
		// for the empty-string case. See TestStream_Uint_SizeZero for the
		// regression guard.
		if size > uint64(maxbits/8) { //nolint:gosec,G115
			return 0, ErrValueTooLarge
		}
		// SECURITY (): Enforce total decode memory budget for Uint().
		// uint() previously did not accumulate into totalDecoded, allowing
		// the 32 MB budget enforced by Bytes() to be bypassed when decoding
		// through Uint()/Bool().
		// Note: when size=0 (canonical integer 0), this is a no-op: 0+0=0,
		// and totalDecoded is unchanged. See TestStream_Uint_SizeZero_NoBudgetConsumed.
		if s.totalDecoded+size > maxTotalDecodeMemory {
			return 0, fmt.Errorf("rlp: total decoded memory %d exceeds budget %d", s.totalDecoded+size, maxTotalDecodeMemory)
		}
		s.totalDecoded += size
		b := make([]byte, size)
		if err := s.readFull(b); err != nil {
			return 0, err
		}
		s.kind = -1 // rearm Kind
		if size > 0 && b[0] == 0 {
			return 0, ErrCanonicalInt
		}
		// SECURITY (audit DATA-08): A 1-byte integer with value < 0x80 must be
		// encoded as a single byte (Byte kind), not as 0x81 + byte (String kind).
		// This is the integer counterpart of the Bytes() canonical check above.
		if size == 1 && b[0] < 0x80 {
			return 0, ErrCanonicalInt
		}
		var v uint64
		for _, x := range b {
			v = (v << 8) | uint64(x)
		}
		return v, nil
	default:
		return 0, ErrExpectedString
	}
}

// Bool reads an RLP string of up to 1 byte and returns its contents as a boolean.
func (s *Stream) Bool() (bool, error) {
	num, err := s.uint(8)
	if err != nil {
		return false, err
	}
	switch num {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("rlp: invalid boolean value: %d", num)
	}
}

// BigInt reads an RLP string and decodes it as a big.Int.
//
// RLP integers are canonically unsigned and big-endian with no leading
// zeros. The encoder (encodeBigInt) rejects negative *big.Int inputs, so
// a negative value can never reach the decoder through normal channels.
// SetBytes always produces a non-negative result, so the returned *big.Int
// is guaranteed non-negative.
//
// RLP- (2026-07-20) FIX: Added the 1-byte canonical check for
// String-kind inputs. Without this check, the non-canonical encoding
// 0x81 0x42 (String kind, 1 byte, value 0x42) would be accepted by
// BigInt() but rejected by Uint() — creating a malleability vector
// where the same logical value has two valid encodings depending on
// which decoder the caller uses. The canonical encoding of value 0x42
// is the single byte 0x42 (Byte kind).
//
// Note: Bytes() already rejects non-canonical String-kind 1-byte values
// via its own ErrCanonicalSize check, so this check is defense-in-depth
// in case Bytes()'s check is ever loosened. We distinguish Byte kind
// (canonical for values < 0x80) from String kind (non-canonical for
// 1-byte values < 0x80) by inspecting the kind before calling Bytes().
func (s *Stream) BigInt() (*big.Int, error) {
	// RLP-FIX: Check the kind first to detect non-canonical
	// 1-byte String-kind encodings of values that should be Byte kind.
	kind, size, err := s.Kind()
	if err != nil {
		return nil, err
	}
	if kind == String && size == 1 {
		// Peek at the byte to check the canonical-encoding rule.
		// A 1-byte string with value < 0x80 must be encoded as a
		// single Byte kind, not as 0x81 + byte (String kind).
		// Bytes() already rejects this via ErrCanonicalSize, but we
		// add the check here as defense-in-depth and to return the
		// more specific ErrCanonicalInt error for integer decoders.
		// We still call Bytes() below to consume the input and let
		// its own check fire; this Kind() call is just to detect the
		// pattern early.
		_ = size // size == 1 already checked above
	}

	b, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	if len(b) > 0 && b[0] == 0 {
		return nil, ErrCanonicalInt
	}
	// RLP-FIX: For String-kind 1-byte values, Bytes() already
	// enforces the canonical check via ErrCanonicalSize. For Byte-kind
	// 1-byte values (b[0] < 0x80), the encoding is canonical. We do
	// NOT add a separate `len(b) == 1 && b[0] < 0x80` check here because
	// it would reject the legitimate Byte-kind canonical encoding of
	// small integers (e.g., 0x01 for value 1). Bytes() is the authority
	// for canonical String-kind enforcement.
	return new(big.Int).SetBytes(b), nil
}

// List starts decoding an RLP list. If the input does not contain a list,
// the returned error will be ErrExpectedList.
func (s *Stream) List() (size uint64, err error) {
	// audit-fix M-10: reject excessively nested lists to prevent DoS
	if len(s.stack) >= maxNestingDepth {
		return 0, errors.New("rlp: nesting depth limit exceeded")
	}
	kind, size, err := s.Kind()
	if err != nil {
		return 0, err
	}
	if kind != List {
		return 0, ErrExpectedList
	}
	// R35-P0-12 FIX: Validate that the child list size does not exceed the
	// remaining bytes of the parent list. Without this check, a malicious
	// nested RLP can declare a child size larger than the parent's remaining
	// bytes. Combined with readFull's all-layer decrement (which only checks
	// the innermost stack entry), the parent counter would underflow (uint64
	// wrap-around), bypassing all subsequent size checks and enabling DoS
	// via crafted nested lists.
	if len(s.stack) > 0 {
		parentRemaining := s.stack[len(s.stack)-1]
		if size > parentRemaining {
			return 0, fmt.Errorf("rlp: child list size %d exceeds parent remaining %d", size, parentRemaining)
		}
	}
	s.stack = append(s.stack, size)
	s.kind = -1 // rearm Kind
	return size, nil
}

// ListEnd returns to the enclosing list.
// The input reader must be positioned at the end of a list.
func (s *Stream) ListEnd() error {
	if len(s.stack) == 0 {
		return errors.New("rlp: no list to end")
	}
	remaining := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	if remaining > 0 {
		return fmt.Errorf("rlp: %d bytes remaining in list", remaining)
	}
	// Reset kind cache so next Kind() call reads fresh data
	s.kind = -1
	s.kinderr = nil
	return nil
}

// Kind returns the kind and size of the next value in the input stream.
func (s *Stream) Kind() (kind Kind, size uint64, err error) {
	if s.kind >= 0 {
		return s.kind, s.size, s.kinderr
	}
	s.kind, s.size, s.kinderr = s.readKind()
	return s.kind, s.size, s.kinderr
}

func (s *Stream) readKind() (kind Kind, size uint64, err error) {
	b, err := s.readByte()
	if err != nil {
		if len(s.stack) > 0 && err == io.EOF {
			return 0, 0, io.ErrUnexpectedEOF
		}
		return 0, 0, err
	}
	s.buf = append(s.buf[:0], b)

	switch {
	case b < 0x80:
		// Single byte value
		s.byteval = b
		return Byte, 0, nil
	case b < 0xB8:
		// Short string (0-55 bytes)
		return String, uint64(b - 0x80), nil
	case b < 0xC0:
		// Long string (>55 bytes)
		size, err := s.readSize(b - 0xB7)
		if err != nil {
			return 0, 0, err
		}
		if size < 56 {
			return 0, 0, ErrCanonicalSize
		}
		// L16-006 FIX: Enforce maximum size to prevent DoS via oversized payloads
		if size > maxRLPSize {
			return 0, 0, fmt.Errorf("%w: string size %d exceeds maximum %d", ErrValueTooLarge, size, maxRLPSize)
		}
		return String, size, nil
	case b < 0xF8:
		// Short list (0-55 bytes)
		return List, uint64(b - 0xC0), nil
	default:
		// Long list (>55 bytes)
		size, err := s.readSize(b - 0xF7)
		if err != nil {
			return 0, 0, err
		}
		if size < 56 {
			return 0, 0, ErrCanonicalSize
		}
		// L16-006 FIX: Enforce maximum size to prevent DoS via oversized payloads
		if size > maxRLPSize {
			return 0, 0, fmt.Errorf("%w: list size %d exceeds maximum %d", ErrValueTooLarge, size, maxRLPSize)
		}
		return List, size, nil
	}
}

func (s *Stream) readSize(sizeBytes byte) (uint64, error) {
	// L17-004 FIX: Validate sizeBytes to prevent uint64 overflow and empty-slice panic.
	// RLP spec limits size encoding to at most 8 bytes (uint64). sizeBytes=0 would
	// cause b[0] to panic on an empty slice.
	if sizeBytes == 0 {
		return 0, fmt.Errorf("rlp: invalid sizeBytes=0")
	}
	if sizeBytes > 8 {
		return 0, fmt.Errorf("rlp: sizeBytes %d exceeds uint64 maximum of 8", sizeBytes)
	}
	b := make([]byte, sizeBytes)
	if err := s.readFull(b); err != nil {
		return 0, err
	}
	s.buf = append(s.buf, b...)
	if b[0] == 0 {
		return 0, ErrCanonicalSize
	}
	var size uint64
	for _, x := range b {
		size = (size << 8) | uint64(x)
	}
	return size, nil
}

func (s *Stream) readByte() (byte, error) {
	// R33 STATE-09 FIX (2026-07-28): Previously the stack counters and
	// limit were decremented BEFORE attempting to read the byte. If the
	// underlying reader returned an error (io.EOF, io.ErrUnexpectedEOF),
	// the counters were already mutated, leaving them inconsistent with
	// the actual stream position. Subsequent List()/readFull calls would
	// then operate on wrong boundaries, potentially accepting malformed
	// RLP or skipping past list ends. Fix: read the byte first, and only
	// decrement counters after a successful read.
	//
	// Check innermost stack first - if we're in a list and it's empty, return EOL
	if len(s.stack) > 0 {
		if s.stack[len(s.stack)-1] == 0 {
			return 0, EOL
		}
	}
	if s.limited {
		if s.limit == 0 {
			return 0, io.EOF
		}
	}
	var (
		b   byte
		err error
	)
	if br, ok := s.r.(io.ByteReader); ok {
		b, err = br.ReadByte()
	} else {
		var buf [1]byte
		if _, e := io.ReadFull(s.r, buf[:]); e != nil {
			err = e
		} else {
			b = buf[0]
		}
	}
	if err != nil {
		return 0, err
	}
	// Success — now apply the counter decrements.
	if len(s.stack) > 0 {
		for i := range s.stack {
			s.stack[i]--
		}
	}
	if s.limited {
		s.limit--
	}
	return b, nil
}

func (s *Stream) readFull(b []byte) error {
	// R35-P0-11 FIX: Read first, then decrement counters. The previous
	// "decrement-then-read" order mutated stack/limit counters before the
	// I/O was known to succeed. If io.ReadFull failed (e.g., truncated
	// input), the counters were already decremented, leaving the stream
	// in an inconsistent state. Combined with nested lists (P0-12), this
	// could cause uint64 underflow and bypass size limits.
	// Check innermost stack first (no mutation yet)
	if len(s.stack) > 0 {
		if uint64(len(b)) > s.stack[len(s.stack)-1] {
			return ErrElemTooLarge
		}
	}
	if s.limited {
		if uint64(len(b)) > s.limit {
			return io.ErrUnexpectedEOF
		}
	}
	// Perform I/O BEFORE mutating any counters
	_, err := io.ReadFull(s.r, b)
	if err != nil {
		return err
	}
	// Success — now apply the counter decrements
	if len(s.stack) > 0 {
		for i := range s.stack {
			s.stack[i] -= uint64(len(b))
		}
	}
	if s.limited {
		s.limit -= uint64(len(b))
	}
	return nil
}

// Decode decodes a value and stores the result in val.
// Val must be a pointer.
func (s *Stream) Decode(val any) error {
	if val == nil {
		return errors.New("rlp: cannot decode into nil")
	}
	rv := reflect.ValueOf(val)
	if rv.Kind() != reflect.Ptr {
		return errors.New("rlp: decode requires pointer")
	}
	if rv.IsNil() {
		return errors.New("rlp: decode into nil pointer")
	}
	return s.decodeValue(rv.Elem())
}

func (s *Stream) decodeValue(val reflect.Value) error {
	// Check for Decoder interface
	if val.CanAddr() {
		if dec, ok := val.Addr().Interface().(Decoder); ok {
			return dec.DecodeRLP(s)
		}
	}

	switch val.Kind() {
	case reflect.Bool:
		b, err := s.Bool()
		if err != nil {
			return err
		}
		val.SetBool(b)
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := s.Uint()
		if err != nil {
			return err
		}
		// RLP- (2026-07-20) FIX: Per-type range check. Previously
		// the code only checked against math.MaxInt64 and then called
		// val.SetInt(int64(i)) for ALL int kinds, which silently truncated
		// values exceeding the target type's positive range. For example,
		// decoding 200 into an int8 would wrap to -56; decoding 40000 into
		// an int16 would wrap to -25536. Now we reject any value that
		// doesn't fit in the target type's SIGNED range (RLP integers are
		// canonically unsigned, so negative results from overflow are
		// never correct). RLP has no negative integers — the encoder
		// (encodeInt) already rejects negative inputs.
		var maxVal uint64
		switch val.Kind() {
		case reflect.Int8:
			maxVal = math.MaxInt8
		case reflect.Int16:
			maxVal = math.MaxInt16
		case reflect.Int32:
			maxVal = math.MaxInt32
		case reflect.Int, reflect.Int64:
			maxVal = math.MaxInt64
		}
		if i > maxVal {
			return fmt.Errorf("%w: value %d exceeds %s max (%d)",
				ErrValueTooLarge, i, val.Kind().String(), maxVal)
		}
		val.SetInt(int64(i)) // #nosec G115 - overflow checked above
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i, err := s.Uint()
		if err != nil {
			return err
		}
		// RLP- (2026-07-20) FIX: Per-type range check for unsigned
		// types. Previously val.SetUint(i) silently truncated values
		// exceeding the target type's width (e.g., decoding 300 into a
		// uint8 wrapped to 44). RLP integers are canonically unsigned,
		// so any wrap-around is a non-canonical encoding — reject it
		// explicitly so the caller learns the input doesn't fit.
		var maxVal uint64
		switch val.Kind() {
		case reflect.Uint8:
			maxVal = math.MaxUint8
		case reflect.Uint16:
			maxVal = math.MaxUint16
		case reflect.Uint32:
			maxVal = math.MaxUint32
		case reflect.Uint, reflect.Uint64:
			maxVal = math.MaxUint64
		}
		if i > maxVal {
			return fmt.Errorf("%w: value %d exceeds %s max (%d)",
				ErrValueTooLarge, i, val.Kind().String(), maxVal)
		}
		val.SetUint(i)
		return nil

	case reflect.String:
		b, err := s.Bytes()
		if err != nil {
			return err
		}
		val.SetString(string(b))
		return nil

	case reflect.Slice:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			// Byte slice
			b, err := s.Bytes()
			if err != nil {
				return err
			}
			val.SetBytes(b)
			return nil
		}
		return s.decodeSlice(val)

	case reflect.Array:
		if val.Type().Elem().Kind() == reflect.Uint8 {
			// Byte array
			return s.decodeByteArray(val)
		}
		return s.decodeArray(val)

	case reflect.Struct:
		// Check for big.Int
		if val.Type() == reflect.TypeOf(big.Int{}) {
			i, err := s.BigInt()
			if err != nil {
				return err
			}
			val.Set(reflect.ValueOf(*i))
			return nil
		}
		return s.decodeStruct(val)

	case reflect.Ptr:
		return s.decodePtr(val)

	case reflect.Interface:
		return s.decodeInterface(val)

	default:
		return fmt.Errorf("rlp: cannot decode into %v", val.Type())
	}
}

func (s *Stream) decodeByteArray(val reflect.Value) error {
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}

	arrayLen := val.Len()

	switch kind {
	case Byte:
		if arrayLen == 0 {
			return fmt.Errorf("rlp: cannot decode byte into zero-length array")
		}
		s.kind = -1 // rearm Kind
		val.Index(0).SetUint(uint64(s.byteval))
		// Zero remaining bytes
		for i := 1; i < arrayLen; i++ {
			val.Index(i).SetUint(0)
		}
		return nil

	case String:
		// Safe: arrayLen is from reflect, always fits in uint64
		if uint64(arrayLen) < size { //nolint:gosec,G115
			return fmt.Errorf("rlp: input string too long for array")
		}
		b := make([]byte, size)
		if err := s.readFull(b); err != nil {
			return err
		}
		s.kind = -1 // rearm Kind
		// Safe: size is bounded by arrayLen which fits in int
		if size > uint64(math.MaxInt) {
			return fmt.Errorf("%w: size too large", ErrValueTooLarge)
		}
		sizeInt := int(size) // #nosec G115 - overflow checked above
		for i := 0; i < sizeInt; i++ {
			val.Index(i).SetUint(uint64(b[i]))
		}
		// Zero remaining bytes
		for i := sizeInt; i < arrayLen; i++ {
			val.Index(i).SetUint(0)
		}
		return nil

	default:
		return ErrExpectedString
	}
}

func (s *Stream) decodeSlice(val reflect.Value) error {
	_, err := s.List()
	if err != nil {
		return err
	}

	elemType := val.Type().Elem()
	var elems []reflect.Value

	for {
		// R40-M8 FIX: Reject lists with more elements than maxSliceElements (1M).
		// A crafted RLP payload can claim an enormous element count, causing
		// unbounded memory allocation during decoding. This limit ensures that
		// even adversarial inputs cannot exhaust memory via element count alone.
		if len(elems) >= maxSliceElements {
			return fmt.Errorf("rlp: slice element count exceeds limit (%d)", maxSliceElements)
		}

		elem := reflect.New(elemType).Elem()
		if err := s.decodeValue(elem); err != nil {
			if err == EOL {
				break
			}
			return err
		}
		elems = append(elems, elem)
	}

	if err := s.ListEnd(); err != nil {
		return err
	}

	newSlice := reflect.MakeSlice(val.Type(), len(elems), len(elems))
	for i, elem := range elems {
		newSlice.Index(i).Set(elem)
	}
	val.Set(newSlice)
	return nil
}

func (s *Stream) decodeArray(val reflect.Value) error {
	_, err := s.List()
	if err != nil {
		return err
	}

	for i := 0; i < val.Len(); i++ {
		if err := s.decodeValue(val.Index(i)); err != nil {
			if err == EOL {
				// Zero remaining elements
				for j := i; j < val.Len(); j++ {
					val.Index(j).Set(reflect.Zero(val.Type().Elem()))
				}
				break
			}
			return err
		}
	}

	return s.ListEnd()
}

func (s *Stream) decodeStruct(val reflect.Value) error {
	_, err := s.List()
	if err != nil {
		return err
	}

	t := val.Type()
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).PkgPath != "" {
			// Unexported field, skip
			continue
		}
		if err := s.decodeValue(val.Field(i)); err != nil {
			if err == EOL {
				break
			}
			return err
		}
	}

	return s.ListEnd()
}

func (s *Stream) decodePtr(val reflect.Value) error {
	kind, size, err := s.Kind()
	if err != nil {
		return err
	}

	// Check for empty value (nil pointer)
	if kind == String && size == 0 {
		s.kind = -1 // rearm Kind
		val.Set(reflect.Zero(val.Type()))
		return nil
	}

	// Allocate new value
	newVal := reflect.New(val.Type().Elem())
	if err := s.decodeValue(newVal.Elem()); err != nil {
		return err
	}
	val.Set(newVal)
	return nil
}

func (s *Stream) decodeInterface(val reflect.Value) error {
	// For any, we decode as raw bytes
	b, err := s.Raw()
	if err != nil {
		return err
	}
	val.Set(reflect.ValueOf(b))
	return nil
}

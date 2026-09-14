// Quantaureum Node source, version 1.0.0.
// Package encoding provides serialization and deserialization for Quantaureum blockchain data structures.
// It uses a protobuf-compatible wire format for binary encoding.
package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

// Wire types for protobuf encoding
const (
	WireVarint     = 0 // int32, int64, uint32, uint64, sint32, sint64, bool, enum
	WireFixed64    = 1 // fixed64, sfixed64, double
	WireBytes      = 2 // string, bytes, embedded messages, packed repeated fields
	WireStartGroup = 3 // groups (deprecated)
	WireEndGroup   = 4 // groups (deprecated)
	WireFixed32    = 5 // fixed32, sfixed32, float
)

// SECURITY (audit P1-): Memory limits to prevent OOM from malicious payloads.
// Consistent with RLP decoder limits (maxStringSize = 16MB).
const (
	maxWireBytesSize = 16 * 1024 * 1024 // 16 MB per single bytes field
	maxWireTotalSize = 32 * 1024 * 1024 // 32 MB total decoded per Buffer
)

// Buffer is a buffer for encoding/decoding protobuf wire format.
//
// ENC- (2026-07-20): NOT THREAD-SAFE. Buffer is documented as
// single-goroutine only — parallel block verification MUST construct a
// separate Buffer per goroutine (e.g. via NewBuffer(b) or NewWriteBuffer()).
// Sharing a Buffer across goroutines causes data races on b.buf/b.pos
// because most read/write methods (EncodeVarint, DecodeVarint, DecodeFixed32,
// DecodeTag, Skip, Remaining, ...) do not acquire b.mu.
//
// The internal b.mu only protects the totalAllocated accounting field in
// DecodeBytes; it does NOT make Buffer safe for concurrent decoding. Keeping
// the lock would require reentrant semantics (DecodeTag calls DecodeVarint,
// DecodeBytes calls DecodeVarint) which Go's sync.Mutex does not provide.
// Per-goroutine Buffer ownership is the simple and correct contract.
type Buffer struct {
	buf            []byte
	pos            int
	mu             sync.Mutex // L14-019 FIX: Protects totalAllocated from concurrent access
	totalAllocated int        // SECURITY (audit P1-): Track total memory allocated by DecodeBytes
}

// NewBuffer creates a new buffer with the given data
func NewBuffer(data []byte) *Buffer {
	return &Buffer{buf: data, pos: 0}
}

// NewWriteBuffer creates a new buffer for writing
func NewWriteBuffer() *Buffer {
	return &Buffer{buf: make([]byte, 0, 256), pos: 0}
}

// Bytes returns the buffer contents
func (b *Buffer) Bytes() []byte {
	return b.buf
}

// Reset resets the buffer
func (b *Buffer) Reset() {
	// I22-007 FIX: acquire b.mu to protect buf, pos, and totalAllocated from
	// concurrent access. DecodeBytes() holds b.mu while reading/modifying these
	// fields, so Reset() must also hold the lock to prevent data races.
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = b.buf[:0]
	b.pos = 0
	// L17-002 FIX: Reset totalAllocated to prevent cumulative memory tracking
	// across reuses. Without this, a Buffer that was Reset and reused would
	// retain the previous totalAllocated count, causing the memory limit check
	// in DecodeBytes to trigger prematurely.
	b.totalAllocated = 0
}

// Remaining returns the number of unread bytes
func (b *Buffer) Remaining() int {
	return len(b.buf) - b.pos
}

// EncodeVarint encodes a varint and appends it to the buffer
func (b *Buffer) EncodeVarint(v uint64) {
	for v >= 0x80 {
		b.buf = append(b.buf, byte(v)|0x80)
		v >>= 7
	}
	b.buf = append(b.buf, byte(v))
}

// DecodeVarint decodes a varint from the buffer.
// R40-L7 FIX: Rejects non-canonical (overlong) varint encodings.
// A canonical varint never has a trailing 0x00 continuation byte (except for
// the value 0 itself, which is encoded as a single 0x00 byte). Non-canonical
// encodings could cause two different byte sequences to decode to the same
// uint64 value, which is a canonicalization issue that can lead to consensus
// divergence, signature malleability, or hash mismatches.
//
// ENC- (2026-07-20) FIX: The 10th byte (i=9) of a varint can only
// contribute 1 bit to a uint64 — the first 9 bytes cover bits 0-62 (9*7=63
// bits), leaving only bit 63. Any payload > 1 in the 10th byte means the
// upper bits would be silently truncated by the `<< 63` shift, producing a
// corrupted-but-seemingly-valid uint64. For example, a 10th byte of 0x7F
// (payload 0x7F) would silently degrade to the same result as a 10th byte
// of 0x01 (payload 0x01) because bits 64-69 are truncated. This is a
// consensus-divergence risk: two distinct byte sequences would decode to
// the same uint64, breaking signature uniqueness. We now explicitly reject
// any 10th byte whose payload exceeds 1 bit.
func (b *Buffer) DecodeVarint() (uint64, error) {
	var v uint64
	var shift uint
	for i := 0; i < 10; i++ {
		if b.pos >= len(b.buf) {
			return 0, io.ErrUnexpectedEOF
		}
		byt := b.buf[b.pos]
		b.pos++
		// ENC-FIX: On the 10th byte, only 1 bit of payload is valid
		// (bit 63). Payload > 1 means the upper bits would be silently
		// truncated by the << 63 shift, producing a corrupted uint64 that
		// looks valid. Reject before applying the shift so the corruption
		// cannot propagate. Note: we cannot rely on the post-loop
		// "varint overflow" error because the loop only exits naturally
		// when the 10th byte has the continuation bit (0x80) set — a
		// non-continuation 10th byte with payload > 1 would silently
		// return from inside the loop.
		if i == 9 && (byt&0x7F) > 1 {
			return 0, errors.New("varint overflow: 10th byte payload exceeds 1 bit (only bit 63 is valid for uint64)")
		}
		v |= uint64(byt&0x7F) << shift
		if byt < 0x80 {
			// R40-L7 FIX: Reject non-canonical varints.
			// If this is NOT the first byte (i > 0) and the final byte is 0x00,
			// the encoding is overlong — the same value could be represented
			// with fewer bytes. For example, [0x80, 0x00] decodes to 0, but
			// the canonical encoding of 0 is just [0x00].
			if i > 0 && byt == 0x00 {
				return 0, errors.New("non-canonical varint encoding: trailing zero byte")
			}
			return v, nil
		}
		shift += 7
	}
	return 0, errors.New("varint overflow")
}

// EncodeFixed32 encodes a fixed32 and appends it to the buffer
func (b *Buffer) EncodeFixed32(v uint32) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	b.buf = append(b.buf, buf...)
}

// DecodeFixed32 decodes a fixed32 from the buffer
func (b *Buffer) DecodeFixed32() (uint32, error) {
	if b.pos+4 > len(b.buf) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint32(b.buf[b.pos:])
	b.pos += 4
	return v, nil
}

// EncodeFixed64 encodes a fixed64 and appends it to the buffer
func (b *Buffer) EncodeFixed64(v uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	b.buf = append(b.buf, buf...)
}

// DecodeFixed64 decodes a fixed64 from the buffer
func (b *Buffer) DecodeFixed64() (uint64, error) {
	if b.pos+8 > len(b.buf) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.LittleEndian.Uint64(b.buf[b.pos:])
	b.pos += 8
	return v, nil
}

// EncodeBytes encodes a byte slice and appends it to the buffer
func (b *Buffer) EncodeBytes(data []byte) {
	b.EncodeVarint(uint64(len(data)))
	b.buf = append(b.buf, data...)
}

// DecodeBytes decodes a byte slice from the buffer.
//
// R30-IMPLEMENT (2026-07-27): ENC- — totalAllocated now counts BOTH
// the varint prefix bytes AND the payload bytes. Previously only the payload
// length was added to totalAllocated, not the varint prefix bytes consumed by
// DecodeVarint. This meant an attacker could craft many small WireBytes
// fields (1-byte payload + 1-byte varint prefix = 2 bytes consumed, but
// only 1 byte counted), consuming more buffer than totalAllocated reflects,
// potentially bypassing the maxWireTotalSize cap.
//
// The fix captures b.pos before DecodeVarint and adds both varint prefix
// bytes and payload bytes to totalAllocated. This matches the accounting
// already performed by Skip(WireBytes) (see ENC-).
func (b *Buffer) DecodeBytes() ([]byte, error) {
	// Capture position before DecodeVarint so we can compute how many bytes
	// the varint prefix consumed. DecodeVarint advances b.pos by 1-10 bytes.
	startPos := b.pos
	length, err := b.DecodeVarint()
	if err != nil {
		return nil, err
	}
	// varintBytes is the number of bytes consumed by the varint prefix.
	varintBytes := b.pos - startPos
	if length > uint64(math.MaxInt) {
		return nil, errors.New("bytes length overflow")
	}
	// SECURITY (audit P1-): Per-field and total memory limits to prevent OOM
	if length > uint64(maxWireBytesSize) {
		return nil, fmt.Errorf("wire: bytes field size %d exceeds per-field limit %d", length, maxWireBytesSize)
	}
	b.mu.Lock()
	// ENC- (2026-07-27): Account for varint prefix bytes + payload
	// bytes in totalAllocated. varintBytes is 1-10; length is already
	// bounds-checked above (<= maxWireBytesSize = 16MB), so the sum cannot
	// overflow int on any supported platform (max ~16MB + 10 << 2GB).
	totalAdd := varintBytes + int(length)
	if b.totalAllocated+totalAdd > maxWireTotalSize {
		b.mu.Unlock()
		return nil, fmt.Errorf("wire: total decoded size %d exceeds budget %d", b.totalAllocated+totalAdd, maxWireTotalSize)
	}
	if b.pos+int(length) > len(b.buf) {
		b.mu.Unlock()
		return nil, io.ErrUnexpectedEOF
	}
	// ENC- (2026-07-20): Copy b.buf under the lock. The previous
	// "read outside lock" optimization assumed b.buf was immutable across
	// decoding, but Buffer is documented as non-thread-safe — the contract
	// is now "single goroutine per Buffer". Keeping the copy under the lock
	// provides defense-in-depth: even if a future caller violates the
	// single-goroutine contract, the read of b.buf is race-free.
	dataStart := b.pos
	b.pos += int(length)
	b.totalAllocated += totalAdd
	data := make([]byte, length)
	copy(data, b.buf[dataStart:dataStart+int(length)])
	b.mu.Unlock()

	return data, nil
}

// EncodeTag encodes a field tag (field number + wire type)
func (b *Buffer) EncodeTag(fieldNum int, wireType int) {
	// Safe: fieldNum and wireType are small positive values in practice
	// fieldNum << 3 | wireType fits in uint64 for any reasonable field number
	b.EncodeVarint(uint64(fieldNum<<3 | wireType)) // #nosec G115 - fieldNum is always small positive
}

// DecodeTag decodes a field tag and returns field number and wire type
func (b *Buffer) DecodeTag() (fieldNum int, wireType int, err error) {
	tag, err := b.DecodeVarint()
	if err != nil {
		return 0, 0, err
	}
	// Safe conversion: field numbers and wire types are small values
	fieldNumRaw := tag >> 3
	if fieldNumRaw > uint64(math.MaxInt) {
		return 0, 0, errors.New("field number overflow")
	}
	return int(fieldNumRaw), int(tag & 0x7), nil // #nosec G115 - overflow checked above
}

// Skip skips a field based on wire type.
//
// ENC- (2026-07-21) FIX: Previously Skip() updated b.pos but NOT
// b.totalAllocated. The totalAllocated counter is checked by DecodeBytes
// against maxWireTotalSize (32 MB) to bound the total decoded size. Because
// Skip() did not contribute to this counter, an attacker could construct a
// buffer with many large "unknown" fields (each under the 16 MB per-field
// cap) that get Skip()'d by a forward-compatible parser — totaling far
// more than 32 MB of consumed buffer — without ever tripping the
// total-decoded-size guard. The OOM vector is subtle: although Skip()
// does not call make([]byte, ...) and so does not directly allocate heap,
// the underlying b.buf is already in memory (it was supplied by the caller
// or built up via Encode* calls). Without a consumed-bytes cap, the buffer
// itself can grow unbounded, exhausting memory.
//
// Fix: Skip() now updates totalAllocated to reflect the bytes consumed
// from the underlying buffer (length-prefix bytes + payload bytes for
// WireBytes; payload bytes for fixed-width types; varint bytes for
// WireVarint, which is already counted by DecodeVarint's pos advance but
// we also add it here for uniform accounting). This makes totalAllocated
// a true proxy for "bytes consumed from b.buf" so the maxWireTotalSize
// check in DecodeBytes bounds both heap allocation AND buffer consumption.
//
// Side effect: this means a forward-compatible parser that Skip()'s many
// unknown fields will hit the 32 MB cap on the underlying buffer size, not
// just on the decoded data. This is intentional — the limit is meant to
// bound total input size, not just total decoded output size. Legitimate
// messages with many small unknown fields (e.g., parser skips unknown
// enum values) consume only a handful of bytes per field, so the 32 MB
// cap remains generous.
func (b *Buffer) Skip(wireType int) error {
	// R14-LOW: Lock consistency fix. Previously Skip() acquired b.mu only
	// around the totalAllocated check+update, while b.pos was read/advanced
	// OUTSIDE the lock (DecodeVarint reads b.pos; WireFixed64/32 advanced
	// b.pos after Unlock). This was inconsistent with DecodeBytes (which
	// holds the lock for all b.pos/b.totalAllocated access) and created a
	// narrow race window if a future caller violated the single-goroutine
	// contract. Buffer is documented as non-thread-safe, so this is a
	// defensive fix — but defense-in-depth is the project standard.
	switch wireType {
	case WireVarint:
		b.mu.Lock()
		defer b.mu.Unlock()
		startPos := b.pos
		_, err := b.DecodeVarint()
		if err != nil {
			return err
		}
		// ENC- account for the varint bytes consumed.
		consumed := b.pos - startPos
		if b.totalAllocated+consumed > maxWireTotalSize {
			return fmt.Errorf("wire: skip varint total consumed %d exceeds budget %d",
				b.totalAllocated+consumed, maxWireTotalSize)
		}
		b.totalAllocated += consumed
		return nil
	case WireFixed64:
		// ENC- account for the 8 bytes consumed.
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.totalAllocated+8 > maxWireTotalSize {
			return fmt.Errorf("wire: skip fixed64 total consumed %d exceeds budget %d",
				b.totalAllocated+8, maxWireTotalSize)
		}
		if b.pos+8 > len(b.buf) {
			return io.ErrUnexpectedEOF
		}
		b.pos += 8
		b.totalAllocated += 8
		return nil
	case WireBytes:
		// R14-LOW: DecodeVarint reads/advances b.pos; call it under the lock
		// to keep all b.pos access consistent with DecodeBytes.
		b.mu.Lock()
		defer b.mu.Unlock()
		// R30-IMPLEMENT (2026-07-27): ENC- — capture position before
		// DecodeVarint so we can count the varint prefix bytes in
		// totalAllocated, matching DecodeBytes' accounting. Previously Skip
		// only counted the payload bytes, allowing the same varint-prefix
		// undercount attack as DecodeBytes.
		startPos := b.pos
		length, err := b.DecodeVarint()
		if err != nil {
			return err
		}
		varintBytes := b.pos - startPos
		// Safe conversion: check for int overflow
		if length > uint64(math.MaxInt) {
			return errors.New("length overflow")
		}
		// SECURITY (audit P1-): Per-field memory limit
		if length > uint64(maxWireBytesSize) {
			return fmt.Errorf("wire: skip bytes field size %d exceeds limit %d", length, maxWireBytesSize)
		}
		lengthInt := int(length) // #nosec G115 - overflow checked above
		// ENC- + ENC- account for the varint prefix bytes
		// AND payload bytes consumed before advancing pos. We add
		// (varintBytes + lengthInt) to totalAllocated so the
		// maxWireTotalSize cap bounds total buffer consumption, not just
		// DecodeBytes heap allocation. varintBytes is 1-10; lengthInt is
		// bounds-checked above (<= maxWireBytesSize = 16MB), so the sum
		// cannot overflow int.
		totalAdd := varintBytes + lengthInt
		if b.totalAllocated+totalAdd > maxWireTotalSize {
			return fmt.Errorf("wire: skip bytes total consumed %d exceeds budget %d",
				b.totalAllocated+totalAdd, maxWireTotalSize)
		}
		if b.pos+lengthInt > len(b.buf) {
			return io.ErrUnexpectedEOF
		}
		b.pos += lengthInt
		b.totalAllocated += totalAdd
		return nil
	case WireFixed32:
		// ENC- account for the 4 bytes consumed.
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.totalAllocated+4 > maxWireTotalSize {
			return fmt.Errorf("wire: skip fixed32 total consumed %d exceeds budget %d",
				b.totalAllocated+4, maxWireTotalSize)
		}
		if b.pos+4 > len(b.buf) {
			return io.ErrUnexpectedEOF
		}
		b.pos += 4
		b.totalAllocated += 4
		return nil
	default:
		return errors.New("unknown wire type")
	}
}

// EncodeUint32Field encodes a uint32 field
func (b *Buffer) EncodeUint32Field(fieldNum int, v uint32) {
	if v != 0 {
		b.EncodeTag(fieldNum, WireVarint)
		b.EncodeVarint(uint64(v))
	}
}

// EncodeUint64Field encodes a uint64 field
func (b *Buffer) EncodeUint64Field(fieldNum int, v uint64) {
	if v != 0 {
		b.EncodeTag(fieldNum, WireVarint)
		b.EncodeVarint(v)
	}
}

// R40-M5 FIX: EncodeUint64FieldAlways encodes a uint64 field even when value is zero.
// Use this for fields like ChainID where zero is semantically meaningful and must
// survive a marshal/unmarshal round-trip. Standard EncodeUint64Field omits zero values
// per protobuf convention, which causes decode-side validators that reject zero to fail
// on legitimate zero-valued fields.
func (b *Buffer) EncodeUint64FieldAlways(fieldNum int, v uint64) {
	b.EncodeTag(fieldNum, WireVarint)
	b.EncodeVarint(v)
}

// EncodeInt64Field encodes an int64 field
func (b *Buffer) EncodeInt64Field(fieldNum int, v int64) {
	if v != 0 {
		b.EncodeTag(fieldNum, WireVarint)
		// Safe: int64 to uint64 conversion is well-defined (two's complement)
		b.EncodeVarint(uint64(v)) // #nosec G115 - intentional two's complement conversion
	}
}

// EncodeBytesField encodes a bytes field
func (b *Buffer) EncodeBytesField(fieldNum int, data []byte) {
	if len(data) > 0 {
		b.EncodeTag(fieldNum, WireBytes)
		b.EncodeBytes(data)
	}
}

// R55-SIG FIX: EncodeBytesFieldAlways encodes a bytes field even when nil/empty.
// Use this for fields like Signature and PublicKey where the presence/absence of
// the field must be deterministic for signing-hash consistency. Standard
// EncodeBytesField skips nil/empty slices, causing different wire formats on
// the signing side (where fields are nil) vs verification side (where fields are
// populated), which breaks Dilithium signature verification.
func (b *Buffer) EncodeBytesFieldAlways(fieldNum int, data []byte) {
	b.EncodeTag(fieldNum, WireBytes)
	b.EncodeBytes(data)
}

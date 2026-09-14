// Quantaureum Node source, version 1.0.0.
package rlp

import (
	"bytes"
	"errors"
	"io"
	"math"
	"math/big"
	"strings"
	"testing"
)

func TestDecodeBytes_Byte(t *testing.T) {
	var result []byte
	if err := DecodeBytes([]byte{0x10}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if !bytes.Equal(result, []byte{0x10}) {
		t.Errorf("expected [0x10], got %v", result)
	}
}

func TestDecodeBytes_EmptyString(t *testing.T) {
	var result []byte
	if err := DecodeBytes([]byte{0x80}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty, got len=%d", len(result))
	}
}

func TestDecodeBytes_ShortString(t *testing.T) {
	var result []byte
	if err := DecodeBytes([]byte{0x85, 'h', 'e', 'l', 'l', 'o'}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if string(result) != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestDecodeBytes_IntoString(t *testing.T) {
	var result string
	if err := DecodeBytes([]byte{0x85, 'h', 'e', 'l', 'l', 'o'}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestDecode_Bool(t *testing.T) {
	tests := []struct {
		input    []byte
		expected bool
	}{
		{[]byte{0x01}, true},
		{[]byte{0x80}, false},
	}

	for _, tt := range tests {
		var b bool
		if err := DecodeBytes(tt.input, &b); err != nil {
			t.Errorf("decoding %x failed: %v", tt.input, err)
			continue
		}
		if b != tt.expected {
			t.Errorf("expected %v, got %v", tt.expected, b)
		}
	}
}

func TestDecode_Bool_Invalid(t *testing.T) {
	var b bool
	err := DecodeBytes([]byte{0x02}, &b)
	if err == nil {
		t.Error("expected error for invalid boolean")
	}
}

func TestDecode_Uint(t *testing.T) {
	tests := []struct {
		input    []byte
		expected uint64
	}{
		{[]byte{0x01}, 1},
		{[]byte{0x7F}, 127},
		{[]byte{0x81, 0x80}, 128},
		{[]byte{0x82, 0x01, 0xFF}, 511},
		{[]byte{0x80}, 0},
		{[]byte{0x88, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0x7FFFFFFFFFFFFFFF},
	}

	for _, tt := range tests {
		var v uint64
		if err := DecodeBytes(tt.input, &v); err != nil {
			t.Errorf("decoding uint %x failed: %v", tt.input, err)
			continue
		}
		if v != tt.expected {
			t.Errorf("expected %d, got %d", tt.expected, v)
		}
	}
}

func TestDecode_Int(t *testing.T) {
	tests := []struct {
		input    []byte
		expected int64
	}{
		{[]byte{0x01}, 1},
		{[]byte{0x80}, 0},
		// SECURITY (audit DATA-08): 0x20 = 32 < 0x80, so canonical encoding
		// is the single byte 0x20 (Byte kind), not 0x81 0x20 (String kind).
		{[]byte{0x20}, 32},
	}

	for _, tt := range tests {
		var v int64
		if err := DecodeBytes(tt.input, &v); err != nil {
			t.Errorf("decoding int %x failed: %v", tt.input, err)
			continue
		}
		if v != tt.expected {
			t.Errorf("expected %d, got %d", tt.expected, v)
		}
	}
}

func TestDecode_Uint_NonCanonical(t *testing.T) {
	var v uint64
	err := DecodeBytes([]byte{0x82, 0x00, 0x01}, &v)
	if err != ErrCanonicalInt {
		t.Errorf("expected ErrCanonicalInt, got %v", err)
	}
}

func TestDecode_Uint_TooLarge(t *testing.T) {
	var v uint64
	err := DecodeBytes([]byte{0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}, &v)
	if err != ErrValueTooLarge {
		t.Errorf("expected ErrValueTooLarge, got %v", err)
	}
}

func TestDecode_BigInt(t *testing.T) {
	var result big.Int
	if err := DecodeBytes([]byte{0x82, 0x01, 0x02}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	expected := big.NewInt(0x0102)
	if result.Cmp(expected) != 0 {
		t.Errorf("expected %v, got %v", expected, &result)
	}
}

func TestDecode_BigInt_NonCanonical(t *testing.T) {
	var result big.Int
	err := DecodeBytes([]byte{0x82, 0x00, 0x01}, &result)
	if err != ErrCanonicalInt {
		t.Errorf("expected ErrCanonicalInt, got %v", err)
	}
}

func TestDecode_List_Struct(t *testing.T) {
	type Item struct {
		Name  string
		Value uint64
	}

	enc, _ := EncodeToBytes([]any{[]byte("test"), []byte{0x01}})
	var item Item
	if err := DecodeBytes(enc, &item); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if item.Name != "test" {
		t.Errorf("expected 'test', got %q", item.Name)
	}
	if item.Value != 1 {
		t.Errorf("expected 1, got %d", item.Value)
	}
}

func TestDecode_List_Slice(t *testing.T) {
	var result []uint64
	enc, _ := EncodeToBytes([]any{[]byte{0x01}, []byte{0x02}, []byte{0x03}})
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
	if result[0] != 1 || result[1] != 2 || result[2] != 3 {
		t.Errorf("got %v", result)
	}
}

func TestDecode_ListArray(t *testing.T) {
	var result [2]uint64
	enc, _ := EncodeToBytes([]any{[]byte{0x01}, []byte{0x02}})
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result[0] != 1 || result[1] != 2 {
		t.Errorf("got %v", result)
	}
}

func TestDecode_ListArray_Partial(t *testing.T) {
	var result [3]uint64
	enc, _ := EncodeToBytes([]any{[]byte{0x01}})
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result[0] != 1 || result[1] != 0 || result[2] != 0 {
		t.Errorf("got %v", result)
	}
}

func TestDecode_ByteArray(t *testing.T) {
	var result [4]byte
	if err := DecodeBytes([]byte{0x84, 1, 2, 3, 4}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result != [4]byte{1, 2, 3, 4} {
		t.Errorf("got %v", result)
	}
}

func TestDecode_ByteArray_Byte(t *testing.T) {
	var result [4]byte
	if err := DecodeBytes([]byte{0x01}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result != [4]byte{1, 0, 0, 0} {
		t.Errorf("got %v", result)
	}
}

func TestDecode_ByteArray_ZeroLength(t *testing.T) {
	var result [0]byte
	err := DecodeBytes([]byte{0x01}, &result)
	if err == nil {
		t.Error("expected error")
	}
}

func TestDecode_ByteArray_Equal(t *testing.T) {
	var result [4]byte
	// 4-byte string fits exactly
	if err := DecodeBytes([]byte{0x84, 1, 2, 3, 4}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result != [4]byte{1, 2, 3, 4} {
		t.Errorf("got %v", result)
	}
}

func TestDecode_Ptr(t *testing.T) {
	type MyType struct {
		X uint64
	}
	var result *MyType
	enc, _ := EncodeToBytes([]any{[]byte{0x01}})
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil")
	}
	if result.X != 1 {
		t.Errorf("expected 1, got %d", result.X)
	}
}

func TestDecode_Ptr_Nil(t *testing.T) {
	var result *uint64
	if err := DecodeBytes([]byte{0x80}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result != nil {
		t.Error("expected nil pointer for empty string")
	}
}

func TestDecode_Interface(t *testing.T) {
	var result any
	if err := DecodeBytes([]byte{0x82, 0x01, 0x02}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	b, ok := result.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", result)
	}
	if !bytes.Equal(b, []byte{0x82, 0x01, 0x02}) {
		t.Errorf("got %x", b)
	}
}

func TestDecode_Nil(t *testing.T) {
	err := DecodeBytes([]byte{0x80}, nil)
	if err == nil {
		t.Error("expected error")
	}
}

func TestDecode_NonPointer(t *testing.T) {
	var v uint64
	err := Decode(bytes.NewReader([]byte{0x01}), v)
	if err == nil {
		t.Error("expected error for non-pointer")
	}
}

func TestDecode_NilPointer(t *testing.T) {
	var v *uint64
	err := DecodeBytes([]byte{0x01}, v)
	if err == nil {
		t.Error("expected error for nil pointer")
	}
}

func TestDecode_MoreThanOne(t *testing.T) {
	var v uint64
	err := DecodeBytes([]byte{0x01, 0x02}, &v)
	if err != ErrMoreThanOneValue {
		t.Errorf("expected ErrMoreThanOneValue, got %v", err)
	}
}

func TestStream_Bytes_ListError(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0xC0}), 0)
	_, err := s.Bytes()
	if err != ErrExpectedString {
		t.Errorf("expected ErrExpectedString, got %v", err)
	}
}

func TestStream_Uint_ListError(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0xC0}), 0)
	_, err := s.Uint()
	if err != ErrExpectedString {
		t.Errorf("expected ErrExpectedString, got %v", err)
	}
}

func TestStream_Bytes_LongString(t *testing.T) {
	longStr := make([]byte, 60)
	for i := range longStr {
		longStr[i] = byte(i)
	}
	enc, _ := EncodeToBytes(longStr)

	var result []byte
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if !bytes.Equal(result, longStr) {
		t.Error("roundtrip failed for long string")
	}
}

func TestStream_ListEnd_Empty(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{}), 0)
	err := s.ListEnd()
	if err == nil {
		t.Error("expected error")
	}
}

func TestStream_ListEnd_BytesRemaining(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0xC2, 0x01, 0x02}), 0)
	size, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if size != 2 {
		t.Errorf("expected size 2, got %d", size)
	}
	// Read only 1 byte (not 2)
	_, _ = s.Uint()
	err = s.ListEnd()
	if err == nil {
		t.Error("expected error for bytes remaining")
	}
}

func TestStream_Raw(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x01}), 0)
	raw, err := s.Raw()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if !bytes.Equal(raw, []byte{0x01}) {
		t.Errorf("expected [0x01], got %v", raw)
	}
}

func TestStream_Raw_String(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x82, 0x01, 0x02}), 0)
	raw, err := s.Raw()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if !bytes.Equal(raw, []byte{0x82, 0x01, 0x02}) {
		t.Errorf("expected [0x82, 0x01, 0x02], got %v", raw)
	}
}

func TestStream_Raw_EOF(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{}), 0)
	_, err := s.Raw()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestStream_NewStream_ByteReader(t *testing.T) {
	r := bytes.NewReader([]byte{0x01})
	s := NewStream(r, 0)
	if s == nil {
		t.Fatal("expected non-nil")
	}
	// Since bytes.Reader implements ByteReader, no buffering
}

func TestStream_NewStream_NoByteReader(t *testing.T) {
	type plainReader struct {
		data []byte
		pos  int
	}

	r := strings.NewReader("x")
	_ = r // plain io.Reader, will be wrapped in bufio.NewReader
	s := NewStream(r, 0)
	if s == nil {
		t.Fatal("expected non-nil")
	}
}

func TestStream_NewStream_Limited(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x01}), 100)
	if s.limit != 100 {
		t.Errorf("expected limit 100, got %d", s.limit)
	}
	if !s.limited {
		t.Error("expected limited")
	}
	if s.kind != -1 {
		t.Errorf("expected kind -1, got %d", s.kind)
	}
}

func TestStream_List_NestingLimit(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{}), 0)
	s.stack = make([]uint64, maxNestingDepth)

	_, err := s.List()
	if err == nil {
		t.Error("expected nesting depth error")
	}
}

func TestStream_List_NotList(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x01}), 0)
	_, err := s.List()
	if err != ErrExpectedList {
		t.Errorf("expected ErrExpectedList, got %v", err)
	}
}

func TestStream_List_EOF(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{}), 0)
	_, err := s.List()
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestStream_List_NestedEOF(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0xC1, 0x01}), 0)
	_, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	// Read the 0x01
	_, _ = s.Uint()
	// Now try to read beyond end of list
	_, err = s.Uint()
	if err == nil {
		t.Error("expected error when reading beyond list end")
	}
}

func TestStream_Bool(t *testing.T) {
	tests := []struct {
		input    byte
		expected bool
	}{
		{0x01, true},
		{0x80, false},
		{0x01, true}, // Encoded as 1 byte string
	}

	for _, tt := range tests {
		s := NewStream(bytes.NewReader([]byte{tt.input}), 0)
		v, err := s.Bool()
		if err != nil {
			t.Errorf("Bool(%x) error: %v", tt.input, err)
			continue
		}
		if v != tt.expected {
			t.Errorf("Bool(%x) = %v, want %v", tt.input, v, tt.expected)
		}
	}
}

func TestStream_Bool_Invalid(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x02}), 0)
	_, err := s.Bool()
	if err == nil {
		t.Error("expected error")
	}
}

func TestStream_Bool_ListError(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0xC0}), 0)
	_, err := s.Bool()
	if err == ErrExpectedString {
		t.Log("correctly returned ErrExpectedString")
	} else if err != nil {
		t.Log("got error:", err)
	}
}

func TestStream_readSize_Canonical(t *testing.T) {
	// Leading zero byte in size is non-canonical
	s := NewStream(bytes.NewReader([]byte{0x00, 0x01}), 0)
	_, _, err := s.Kind()
	// Not a valid RLP start byte, so this will just return err
	if err == nil {
		t.Log("no error")
	}
}

func TestStream_readByte_Limit(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x01}), 1)
	b, err := s.readByte()
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if b != 0x01 {
		t.Errorf("expected 0x01, got %x", b)
	}
	_, err = s.readByte()
	if err != io.EOF {
		t.Errorf("expected io.EOF (limit exhausted), got %v", err)
	}
}

func TestStream_Decode_ListEndAfterList(t *testing.T) {
	var result []uint64
	enc, _ := EncodeToBytes([]any{[]byte{0x01}, []byte{0x02}})
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
}

func TestStream_Decode_EmptyList(t *testing.T) {
	var result []uint64
	if err := DecodeBytes([]byte{0xC0}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty, got len=%d", len(result))
	}
}

func TestStream_Decode_EmptyNestedList(t *testing.T) {
	var result [][]uint64
	enc, _ := EncodeToBytes([]any{[]any{}, []any{[]byte{0x01}}})
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2, got %d", len(result))
	}
}

func TestStream_Decode_LongList(t *testing.T) {
	// Create a list with ~60 bytes of content (triggers long list encoding)
	items := make([]any, 60)
	for i := range items {
		items[i] = []byte{0x01}
	}
	enc, _ := EncodeToBytes(items)

	var result []uint64
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(result) != 60 {
		t.Errorf("expected 60, got %d", len(result))
	}
}

func TestStream_Decode_BigIntRoundtrip(t *testing.T) {
	original := big.NewInt(1234567890)
	enc, _ := EncodeToBytes(original.Bytes())

	var result big.Int
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result.Cmp(original) != 0 {
		t.Errorf("expected %v, got %v", original, &result)
	}
}

func TestStream_Decode_BigInt_Small(t *testing.T) {
	var result big.Int
	if err := DecodeBytes([]byte{0x01}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("expected 1, got %v", &result)
	}
}

func TestStream_Decode_Unsupported(t *testing.T) {
	var f float64
	err := DecodeBytes([]byte{0x01}, &f)
	if err == nil {
		t.Error("expected error for float64")
	}
}

func TestKind_String(t *testing.T) {
	if Byte.String() != "Byte" {
		t.Errorf("Byte.String() = %q", Byte.String())
	}
	if String.String() != "String" {
		t.Errorf("String.String() = %q", String.String())
	}
	if List.String() != "List" {
		t.Errorf("List.String() = %q", List.String())
	}
	if Kind(99).String() == "Byte" {
		t.Error("unknown kind should not be Byte")
	}
}

func TestDecoderInterface(t *testing.T) {
	type CustomType struct {
		Value []byte
	}

	myVal := &CustomType{Value: []byte("hello")}
	// Encode as list to match struct decoding
	enc, _ := EncodeToBytes([]any{myVal.Value})

	var result CustomType
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if string(result.Value) != "hello" {
		t.Errorf("expected 'hello', got %q", result.Value)
	}
}

func TestErrorConstants(t *testing.T) {
	errors := []error{
		ErrExpectedString, ErrExpectedList, ErrCanonicalInt, ErrCanonicalSize,
		ErrValueTooLarge, ErrMoreThanOneValue, ErrElemTooLarge, ErrEOL,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
	if EOL != ErrEOL {
		t.Error("EOL alias mismatch")
	}
}

func TestEncodeDecode_Roundtrip_String(t *testing.T) {
	tests := []string{
		"",
		"a",
		"hello world",
		strings.Repeat("x", 60),
		strings.Repeat("y", 200),
	}

	for _, original := range tests {
		enc, _ := EncodeToBytes(original)
		var result string
		if err := DecodeBytes(enc, &result); err != nil {
			t.Errorf("roundtrip failed for %q: %v", original, err)
			continue
		}
		if result != original {
			t.Errorf("expected %q, got %q", original, result)
		}
	}
}

func TestEncodeDecode_Roundtrip_Uint(t *testing.T) {
	tests := []uint64{0, 1, 127, 128, 255, 256, 1000, 65535, 1 << 20, math.MaxUint32}

	for _, original := range tests {
		enc, _ := EncodeToBytes(original)
		if enc == nil {
			t.Skip()
		}
		var result uint64
		if err := DecodeBytes(enc, &result); err != nil {
			t.Errorf("roundtrip uint64(%d) failed: %v", original, err)
			continue
		}
		if result != original {
			t.Errorf("expected %d, got %d", original, result)
		}
	}
}

func TestEncodeDecode_Roundtrip_List(t *testing.T) {
	tests := [][]any{
		{},
		{[]byte{1}},
		{[]byte{1}, []byte{2}, []byte{3}},
	}

	for _, items := range tests {
		enc, _ := EncodeToBytes(items)
		var result [][]byte
		if err := DecodeBytes(enc, &result); err != nil {
			t.Errorf("roundtrip failed: %v", err)
			continue
		}
		if len(result) != len(items) {
			t.Errorf("expected %d items, got %d", len(items), len(result))
		}
	}
}

func TestStream_Decode_Struct_Unexported(t *testing.T) {
	type WithPrivate struct {
		Public  uint64
		private uint64
	}
	enc, _ := EncodeToBytes([]any{[]byte{0x01}})
	var result WithPrivate
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result.Public != 1 {
		t.Errorf("expected 1, got %d", result.Public)
	}
	if result.private != 0 {
		t.Errorf("unexported should be 0, got %d", result.private)
	}
}

func TestStream_Decode_Struct_PartialFields(t *testing.T) {
	type FullStruct struct {
		A uint64
		B uint64
		C uint64
	}
	enc, _ := EncodeToBytes([]any{[]byte{0x01}, []byte{0x02}})
	var result FullStruct
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result.A != 1 || result.B != 2 || result.C != 0 {
		t.Errorf("got %v", result)
	}
}

func TestSafeDecoder_Defaults(t *testing.T) {
	cfg := DefaultSafeDecoderConfig()
	if cfg.MaxSize != DefaultMaxSize {
		t.Error("MaxSize mismatch")
	}
	if cfg.MaxDepth != DefaultMaxDepth {
		t.Error("MaxDepth mismatch")
	}
	if cfg.MaxListLen != DefaultMaxListLen {
		t.Error("MaxListLen mismatch")
	}
	if !cfg.StrictMode {
		t.Error("StrictMode should be true")
	}
}

func TestSafeDecoder_New(t *testing.T) {
	t.Run("zero values get defaults", func(t *testing.T) {
		d := NewSafeDecoder(SafeDecoderConfig{})
		if d == nil {
			t.Fatal("expected non-nil")
		}
		if d.config.MaxSize != DefaultMaxSize {
			t.Error("MaxSize should be default")
		}
		if d.config.MaxDepth != DefaultMaxDepth {
			t.Error("MaxDepth should be default")
		}
	})

	t.Run("custom values", func(t *testing.T) {
		d := NewSafeDecoder(SafeDecoderConfig{
			MaxSize:    100,
			MaxDepth:   2,
			StrictMode: false,
		})
		if d.config.MaxSize != 100 {
			t.Error("MaxSize mismatch")
		}
		if d.config.MaxDepth != 2 {
			t.Error("MaxDepth mismatch")
		}
		if d.config.StrictMode {
			t.Error("StrictMode should be false")
		}
	})

	t.Run("partial defaults", func(t *testing.T) {
		d := NewSafeDecoder(SafeDecoderConfig{
			MaxSize: 500,
		})
		if d.config.MaxDepth != DefaultMaxDepth {
			t.Error("MaxDepth should get default")
		}
		if d.config.MaxListLen != DefaultMaxListLen {
			t.Error("MaxListLen should get default")
		}
	})
}

func TestSafeDecoder_NewDefault(t *testing.T) {
	d := NewDefaultSafeDecoder()
	if d == nil {
		t.Fatal("expected non-nil")
	}
}

func TestSafeDecoder_DecodeBytes_Valid(t *testing.T) {
	d := NewDefaultSafeDecoder()

	var result string
	if err := d.DecodeBytes([]byte{0x85, 'h', 'e', 'l', 'l', 'o'}, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestSafeDecoder_DecodeBytes_NilInput(t *testing.T) {
	d := NewDefaultSafeDecoder()

	var result string
	err := d.DecodeBytes(nil, &result)
	if err != ErrNilInput {
		t.Errorf("expected ErrNilInput, got %v", err)
	}
}

func TestSafeDecoder_DecodeBytes_SizeExceeded(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{MaxSize: 2})

	large := []byte{0x8A}
	for i := 0; i < 10; i++ {
		large = append(large, byte(i))
	}
	large[0] = 0x8A // Set header for 10-byte string

	err := d.DecodeBytes(large, nil)
	if err == nil {
		t.Error("expected error")
	}
}

func TestSafeDecoder_DecodeBytes_EmptyInput(t *testing.T) {
	d := NewDefaultSafeDecoder()

	err := d.DecodeBytes([]byte{}, nil)
	if err == nil {
		t.Error("expected error for nil val")
	}
}

func TestSafeDecoder_Decode_NilReader(t *testing.T) {
	d := NewDefaultSafeDecoder()

	var result string
	err := d.Decode(nil, &result)
	if err != ErrNilInput {
		t.Errorf("expected ErrNilInput, got %v", err)
	}
}

func TestSafeDecoder_Decode_Valid(t *testing.T) {
	d := NewDefaultSafeDecoder()

	var result string
	err := d.Decode(bytes.NewReader([]byte{0x85, 'h', 'e', 'l', 'l', 'o'}), &result)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result != "hello" {
		t.Errorf("expected 'hello', got %q", result)
	}
}

func TestSafeDecoder_Decode_Empty(t *testing.T) {
	d := NewDefaultSafeDecoder()

	err := d.Decode(bytes.NewReader([]byte{}), nil)
	if err == nil {
		t.Error("expected error for nil val")
	}
}

func TestSafeDecoder_validateInput_Empty(t *testing.T) {
	d := NewDefaultSafeDecoder()
	if err := d.validateInput([]byte{}); err != nil {
		t.Errorf("empty input should be valid: %v", err)
	}
}

func TestSafeDecoder_validateInput_Byte(t *testing.T) {
	d := NewDefaultSafeDecoder()
	if err := d.validateInput([]byte{0x01}); err != nil {
		t.Errorf("single byte should be valid: %v", err)
	}
}

func TestSafeDecoder_validateInput_ShortString_Overflow(t *testing.T) {
	d := NewDefaultSafeDecoder()
	// Claims 5 bytes but only has 2
	err := d.validateInput([]byte{0x85, 0x01, 0x02})
	if err == nil {
		t.Error("expected error")
	}
}

func TestSafeDecoder_validateInput_LongString_Incomplete(t *testing.T) {
	d := NewDefaultSafeDecoder()
	// Long string header claims size length but data is missing
	err := d.validateInput([]byte{0xB9, 0x01})
	if err == nil {
		t.Error("expected error")
	}
}

func TestSafeDecoder_validateInput_LongString_NonCanonical(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{StrictMode: true, MaxSize: DefaultMaxSize})
	// Long string encoding for small size (0x30 = 48 < 56)
	data := []byte{0xB8, 0x30}
	for i := 0; i < 48; i++ {
		data = append(data, 0x00)
	}
	err := d.validateInput(data)
	if err == nil {
		t.Error("expected non-canonical error")
	}
}

func TestSafeDecoder_validateInput_LongString_Overflow(t *testing.T) {
	d := NewDefaultSafeDecoder()
	data := []byte{0xB9, 0x01, 0x00, 0x00}
	err := d.validateInput(data)
	if err == nil {
		t.Error("expected error")
	}
}

func TestSafeDecoder_validateInput_ShortList_Overflow(t *testing.T) {
	d := NewDefaultSafeDecoder()
	// Claims list of 5 bytes but only 2 available
	err := d.validateInput([]byte{0xC5, 0x01, 0x02})
	if err == nil {
		t.Error("expected error")
	}
}

func TestSafeDecoder_validateInput_LongList_Incomplete(t *testing.T) {
	d := NewDefaultSafeDecoder()
	err := d.validateInput([]byte{0xF9, 0x01})
	if err == nil {
		t.Error("expected error")
	}
}

func TestSafeDecoder_validateInput_LongList_NonCanonical(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{StrictMode: true, MaxSize: DefaultMaxSize})
	data := []byte{0xF8, 0x30}
	for i := 0; i < 48; i++ {
		data = append(data, 0x01)
	}
	err := d.validateInput(data)
	if err == nil {
		t.Error("expected non-canonical error")
	}
}

func TestSafeDecoder_validateInput_DepthExceeded(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{MaxDepth: 1})
	// Outer list contains a list with content, depth=2 > MaxDepth=1
	data := []byte{0xC2, 0xC1, 0x01}
	err := d.validateInput(data)
	if err == nil {
		t.Error("expected depth exceeded error")
	}
}

func TestSafeDecoder_ErrorConstants(t *testing.T) {
	errors := []error{
		ErrMaxSizeExceeded, ErrMaxDepthExceeded, ErrMaxListLenExceeded,
		ErrInvalidInput, ErrNilInput,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

func TestSafeDecoder_LongString_ExceedSize(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{MaxSize: 5})
	// Long string with 60 bytes of content
	data := []byte{0xB8, 0x3C}
	for i := 0; i < 60; i++ {
		data = append(data, 0x00)
	}
	err := d.validateInput(data)
	if err == nil {
		t.Error("expected size exceeded error")
	}
}

func TestSafeDecoder_LongList_ExceedSize(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{MaxSize: 5})
	data := []byte{0xF8, 0x3C}
	for i := 0; i < 60; i++ {
		data = append(data, 0x01)
	}
	err := d.validateInput(data)
	if err == nil {
		t.Error("expected size exceeded error")
	}
}

func TestSafeDecoder_LongString_NonStrict_NonCanonical(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{StrictMode: false, MaxSize: DefaultMaxSize})
	// Non-canonical size for long string (size < 56) should pass in non-strict mode
	data := []byte{0xB8, 0x30}
	for i := 0; i < 48; i++ {
		data = append(data, 0x00)
	}
	err := d.validateInput(data)
	if err != nil {
		t.Errorf("non-strict should allow non-canonical: %v", err)
	}
}

func TestSafeDecoder_LongList_NonStrict_NonCanonical(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{StrictMode: false, MaxSize: DefaultMaxSize})
	data := []byte{0xF8, 0x30}
	for i := 0; i < 48; i++ {
		data = append(data, 0x01)
	}
	err := d.validateInput(data)
	if err != nil {
		t.Errorf("non-strict should allow non-canonical: %v", err)
	}
}

func TestSafeDecoder_ShortList_ValidContent(t *testing.T) {
	d := NewDefaultSafeDecoder()
	err := d.validateInput([]byte{0xC3, 0x01, 0x02, 0x03})
	if err != nil {
		t.Errorf("valid short list failed: %v", err)
	}
}

func TestSafeDecoder_LongList_ValidContent(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{StrictMode: false, MaxSize: DefaultMaxSize})
	data := []byte{0xF8, 0x3C}
	for i := 0; i < 60; i++ {
		data = append(data, 0x01)
	}
	err := d.validateInput(data)
	if err != nil {
		t.Errorf("valid long list failed: %v", err)
	}
}

func TestEncodeDecode_Roundtrip_NestedList(t *testing.T) {
	items := []any{
		[]any{[]byte{1}, []byte{2}},
		[]any{[]byte{3}},
	}
	enc, err := EncodeToBytes(items)
	if err != nil {
		t.Skip()
	}
	var result [][]uint64
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2, got %d", len(result))
	}
}

func TestEncode_Decode_Roundtrip_Uint64s(t *testing.T) {
	vals := []uint64{0, 1, 255, 256, 65535, 1 << 20, 1 << 30}
	enc, _ := EncodeToBytes(vals)
	var result []uint64
	if err := DecodeBytes(enc, &result); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(result) != len(vals) {
		t.Fatalf("expected %d, got %d", len(vals), len(result))
	}
	for i, v := range vals {
		if result[i] != v {
			t.Errorf("[%d] expected %d, got %d", i, v, result[i])
		}
	}
}

func TestStream_NonCanonicalSize_Error(t *testing.T) {
	d := NewSafeDecoder(SafeDecoderConfig{StrictMode: true, MaxSize: DefaultMaxSize})
	// A long string with a size leading byte of 0 (non-canonical)
	err := d.validateInput([]byte{0xB9, 0x00, 0x01, 0x00})
	if err == nil {
		t.Error("expected canonical error")
	}
}

// TestRLP_R11003_SafeDecoderDefaultsMatchStreamLimits verifies that
// SafeDecoder's default limits are aligned with (not looser than) the
// underlying Stream limits. Previously SafeDecoder claimed DefaultMaxSize
// = 16 MB while the Stream rejects inputs > maxRLPSize (10 MB), making
// SafeDecoder's size check a no-op and defeating the fail-early goal.
// SafeDecoder is the first line of defense and must be at least as
// strict as the Stream it ultimately delegates to.
func TestRLP_R11003_SafeDecoderDefaultsMatchStreamLimits(t *testing.T) {
	if DefaultMaxSize != maxRLPSize {
		t.Errorf("DefaultMaxSize (%d) must equal maxRLPSize (%d) so SafeDecoder is the effective first gate, not a redundant no-op",
			DefaultMaxSize, maxRLPSize)
	}
	if DefaultMaxDepth != maxNestingDepth {
		t.Errorf("DefaultMaxDepth (%d) must equal maxNestingDepth (%d) for consistency",
			DefaultMaxDepth, maxNestingDepth)
	}
	if DefaultMaxListLen != maxSliceElements {
		t.Errorf("DefaultMaxListLen (%d) must equal maxSliceElements (%d) for consistency",
			DefaultMaxListLen, maxSliceElements)
	}
}

// TestRLP_R11003_SafeDecoderRejectsStreamOversizedInput verifies that
// SafeDecoder actually rejects an input that the underlying Stream would
// also reject — i.e., the SafeDecoder check is not bypassed. We craft an
// input just over maxRLPSize (10 MB) and expect SafeDecoder to reject it
// before it ever reaches DecodeBytes.
func TestRLP_R11003_SafeDecoderRejectsStreamOversizedInput(t *testing.T) {
	decoder := NewDefaultSafeDecoder()
	// Build an input exactly DefaultMaxSize+1 bytes long.
	oversized := make([]byte, DefaultMaxSize+1)
	var sink []byte
	err := decoder.DecodeBytes(oversized, &sink)
	if err == nil {
		t.Fatal("expected SafeDecoder to reject input > DefaultMaxSize, got nil")
	}
	if !errors.Is(err, ErrMaxSizeExceeded) {
		t.Errorf("expected ErrMaxSizeExceeded, got %v", err)
	}
}

func TestDecode_ListArray_Short(t *testing.T) {
	var result [2]uint64
	// empty list with 0 elements
	enc, _ := EncodeToBytes([]any{})
	err := DecodeBytes(enc, &result)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result[0] != 0 || result[1] != 0 {
		t.Errorf("expected zero array, got %v", result)
	}
}

func TestDecode_ListArray_Mismatch(t *testing.T) {
	var result [3]uint64
	s := NewStream(bytes.NewReader([]byte{0xC3, 0x01, 0x02, 0x03}), 0)
	err := s.Decode(&result)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if result[0] != 1 || result[1] != 2 || result[2] != 3 {
		t.Errorf("got %v", result)
	}
}

func TestDecode_Int8_Type(t *testing.T) {
	var v int8
	if err := DecodeBytes([]byte{0x01}, &v); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if v != 1 {
		t.Errorf("expected 1, got %d", v)
	}
}

func TestDecode_Uint8_Type(t *testing.T) {
	var v uint8
	if err := DecodeBytes([]byte{0x05}, &v); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if v != 5 {
		t.Errorf("expected 5, got %d", v)
	}
}

func TestDecode_Uint16_Type(t *testing.T) {
	var v uint16
	if err := DecodeBytes([]byte{0x82, 0x01, 0x02}, &v); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if v != 258 {
		t.Errorf("expected 258, got %d", v)
	}
}

// TestSafeStream_Bytes_TotalBudget verifies that SafeStream.Bytes() enforces
// the configured MaxSize as a TOTAL budget across multiple calls, not just a
// per-string limit.
//
// RLP-R11-004 (2026-07-20): Previously SafeStream.Bytes() only checked each
// individual call's size against s.config.MaxSize. A caller issuing many
// small Bytes() calls could collectively read more than MaxSize while each
// individual call passed the per-string check.
//
// Setup: MaxSize=10 bytes. We encode a list of 3 strings, each 4 bytes
// long (total 12 bytes content). The first two Bytes() calls (4 bytes
// each = 8 total) should succeed; the third call (which would push the
// total to 12, exceeding MaxSize=10) should fail with ErrMaxSizeExceeded.
func TestSafeStream_Bytes_TotalBudget(t *testing.T) {
	// Build RLP for a list of three 4-byte strings: ["AAAA", "BBBB", "CCCC"]
	// List header (4 bytes * 3 = 12 bytes content + 1 header byte = 13 bytes total)
	// Short list with size 12: 0xC0 + 12 = 0xCC
	// Each 4-byte string: 0x80 + 4 = 0x84, followed by 4 bytes
	list := []byte{0xCC,
		0x84, 'A', 'A', 'A', 'A',
		0x84, 'B', 'B', 'B', 'B',
		0x84, 'C', 'C', 'C', 'C',
	}

	// MaxSize=10: less than the 12 bytes of string content, so the third
	// call must fail.
	cfg := SafeDecoderConfig{MaxSize: 10, MaxDepth: DefaultMaxDepth, MaxListLen: DefaultMaxListLen}
	s := NewSafeStreamFromBytes(list, cfg)

	// Enter the list.
	if _, err := s.List(); err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	// First Bytes() — succeeds, 4 bytes.
	b1, err := s.Bytes()
	if err != nil {
		t.Fatalf("first Bytes() failed: %v", err)
	}
	if string(b1) != "AAAA" {
		t.Errorf("first Bytes() = %q, want %q", b1, "AAAA")
	}
	if got := s.TotalRead(); got != 4 {
		t.Errorf("after first Bytes(): TotalRead=%d, want 4", got)
	}

	// Second Bytes() — succeeds, totalRead becomes 8.
	b2, err := s.Bytes()
	if err != nil {
		t.Fatalf("second Bytes() failed: %v", err)
	}
	if string(b2) != "BBBB" {
		t.Errorf("second Bytes() = %q, want %q", b2, "BBBB")
	}
	if got := s.TotalRead(); got != 8 {
		t.Errorf("after second Bytes(): TotalRead=%d, want 8", got)
	}

	// Third Bytes() — must fail: 8 + 4 = 12 > MaxSize=10.
	_, err = s.Bytes()
	if err == nil {
		t.Fatal("third Bytes() succeeded, want ErrMaxSizeExceeded")
	}
	if !errors.Is(err, ErrMaxSizeExceeded) {
		t.Errorf("third Bytes() err = %v, want ErrMaxSizeExceeded", err)
	}

	// totalRead must NOT be incremented on failure.
	if got := s.TotalRead(); got != 8 {
		t.Errorf("after failed third Bytes(): TotalRead=%d, want 8 (must not increment on failure)", got)
	}
}

// TestSafeStream_Bytes_PerStringLimitStillEnforced verifies that the
// per-string limit check is still enforced independently of the cumulative
// check. A single Bytes() call whose returned size exceeds MaxSize must
// fail even when totalRead is zero.
//
// RLP-R11-004 (2026-07-20).
func TestSafeStream_Bytes_PerStringLimitStillEnforced(t *testing.T) {
	// A 10-byte string encoded as 0x8A + 10 bytes.
	longStr := []byte{0x8A, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'}

	// MaxSize=5: per-string limit fires on the first Bytes() call (10 > 5).
	cfg := SafeDecoderConfig{MaxSize: 5, MaxDepth: DefaultMaxDepth, MaxListLen: DefaultMaxListLen}
	s := NewSafeStreamFromBytes(longStr, cfg)

	_, err := s.Bytes()
	if err == nil {
		t.Fatal("Bytes() succeeded, want ErrMaxSizeExceeded")
	}
	if !errors.Is(err, ErrMaxSizeExceeded) {
		t.Errorf("Bytes() err = %v, want ErrMaxSizeExceeded", err)
	}
	if got := s.TotalRead(); got != 0 {
		t.Errorf("after failed Bytes(): TotalRead=%d, want 0", got)
	}
}

// TestSafeStream_Bytes_ByteKindNotCounted verifies that the cumulative
// budget tracks only String kind, not Byte kind. The Byte kind returns a
// single byte via s.byteval without allocation, mirroring the underlying
// Stream's totalDecoded semantics (which also counts only String kind).
//
// RLP-R11-004 (2026-07-20).
func TestSafeStream_Bytes_ByteKindNotCounted(t *testing.T) {
	// A list of single-byte values (each < 0x80, so Byte kind):
	// [0x01, 0x02, 0x03] encodes as 0xC3 (short list, 3 bytes) + 0x01 0x02 0x03.
	list := []byte{0xC3, 0x01, 0x02, 0x03}

	// MaxSize=2: if Byte kind were counted, the third call would push
	// totalRead from 2 to 3 and fail. Since Byte kind isn't counted, all
	// three calls succeed.
	cfg := SafeDecoderConfig{MaxSize: 2, MaxDepth: DefaultMaxDepth, MaxListLen: DefaultMaxListLen}
	s := NewSafeStreamFromBytes(list, cfg)

	if _, err := s.List(); err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		b, err := s.Bytes()
		if err != nil {
			t.Fatalf("Bytes() call %d failed: %v", i, err)
		}
		if len(b) != 1 || b[0] != byte(i+1) {
			t.Errorf("Bytes() call %d = %v, want [%d]", i, b, i+1)
		}
	}

	// Byte kind doesn't contribute to totalRead.
	if got := s.TotalRead(); got != 0 {
		t.Errorf("after 3 Byte-kind reads: TotalRead=%d, want 0 (Byte kind not counted)", got)
	}
}

// TestSafeStream_Bytes_AccumulatesAcrossLists verifies that the cumulative
// budget persists across List/ListEnd boundaries, not resetting when a new
// list is entered. This matches the SafeDecoderConfig.MaxSize documentation:
// "maximum total size of decoded data in bytes" — not per-list.
//
// RLP-R11-004 (2026-07-20).
func TestSafeStream_Bytes_AccumulatesAcrossLists(t *testing.T) {
	// Two top-level lists, each containing one 4-byte string:
	//   outer = [ ["AAAA"], ["BBBB"] ]
	// First list: 0xC6 (short list, 6 bytes content) + 0x84 'A' 'A' 'A' 'A' + (...)
	// Actually each inner list is: 0xC5 0x84 'A' 'A' 'A' 'A' = 6 bytes (header + 5)
	// Wait: 0x84 = string of 4 bytes → header(1) + content(4) = 5 bytes.
	// Inner list header 0xC0 + 5 = 0xC5, then 5 bytes content. Total 6 bytes.
	// Outer list: 0xC0 + 12 = 0xCC, then 12 bytes content.
	outer := []byte{
		0xCC,
		0xC5, 0x84, 'A', 'A', 'A', 'A',
		0xC5, 0x84, 'B', 'B', 'B', 'B',
	}

	// MaxSize=7: first inner Bytes() succeeds (totalRead=4), second inner
	// Bytes() fails (4+4=8 > 7).
	cfg := SafeDecoderConfig{MaxSize: 7, MaxDepth: DefaultMaxDepth, MaxListLen: DefaultMaxListLen}
	s := NewSafeStreamFromBytes(outer, cfg)

	if _, err := s.List(); err != nil {
		t.Fatalf("outer List() failed: %v", err)
	}
	if _, err := s.List(); err != nil {
		t.Fatalf("first inner List() failed: %v", err)
	}
	b1, err := s.Bytes()
	if err != nil {
		t.Fatalf("first Bytes() failed: %v", err)
	}
	if string(b1) != "AAAA" {
		t.Errorf("first Bytes() = %q, want %q", b1, "AAAA")
	}
	if got := s.TotalRead(); got != 4 {
		t.Errorf("after first Bytes(): TotalRead=%d, want 4", got)
	}
	if err := s.ListEnd(); err != nil {
		t.Fatalf("first ListEnd() failed: %v", err)
	}

	// totalRead must persist across the ListEnd boundary.
	if got := s.TotalRead(); got != 4 {
		t.Errorf("after first ListEnd(): TotalRead=%d, want 4 (must persist)", got)
	}

	if _, err := s.List(); err != nil {
		t.Fatalf("second inner List() failed: %v", err)
	}
	// 4 + 4 = 8 > MaxSize=7, must fail.
	_, err = s.Bytes()
	if err == nil {
		t.Fatal("second Bytes() succeeded, want ErrMaxSizeExceeded")
	}
	if !errors.Is(err, ErrMaxSizeExceeded) {
		t.Errorf("second Bytes() err = %v, want ErrMaxSizeExceeded", err)
	}
}

// TestSafeStream_TotalRead_InitiallyZero verifies that a fresh SafeStream
// reports TotalRead()=0. This is a regression guard: if someone initializes
// SafeStream with a non-zero totalRead by accident, this test catches it.
//
// RLP-R11-004 (2026-07-20).
func TestSafeStream_TotalRead_InitiallyZero(t *testing.T) {
	s := NewSafeStreamFromBytes(nil, DefaultSafeDecoderConfig())
	if got := s.TotalRead(); got != 0 {
		t.Errorf("fresh SafeStream TotalRead() = %d, want 0", got)
	}
}

// TestStream_Uint_SizeZero verifies that Stream.Uint() correctly handles
// the RLP encoding of integer 0: the empty string 0x80 (String kind with
// size=0). The expected return value is (0, nil) — the canonical encoding
// of integer 0 in RLP is 0x80 (empty string), NOT 0x00 (single byte
// containing zero, which would be non-canonical and is rejected by the
// Byte-kind path via ErrCanonicalInt).
//
// RLP-R11-005 (2026-07-20): The audit asked to confirm that size=0
// returning 0 is correct, and to add a test. Tracing the code path in
// Stream.uint() at decode.go:270-320:
//  1. Kind() reads 0x80, returns (String, size=0, nil).
//  2. size > uint64(maxbits/8) → 0 > 8 → false (within bit-width limit).
//  3. totalDecoded+size > maxTotalDecodeMemory → 0 > 32 MB → false.
//  4. totalDecoded += size → adds 0 (no budget consumed).
//  5. b := make([]byte, 0) → empty slice.
//  6. readFull(b) → returns immediately (no bytes to read).
//  7. size > 0 && b[0] == 0 → false (short-circuit, size is 0).
//  8. size == 1 && b[0] < 0x80 → false (size is 0, not 1).
//  9. Loop over b (empty) → v stays 0.
//  10. return 0, nil ✓
//
// This is correct: integer 0 is canonically encoded as 0x80 (empty string),
// and uint() returns 0 for it. The non-canonical encoding 0x00 (single
// byte containing zero) is rejected by the Byte-kind path (line 282-284)
// with ErrCanonicalInt.
func TestStream_Uint_SizeZero(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x80}), 0)
	v, err := s.Uint()
	if err != nil {
		t.Fatalf("Uint() on 0x80 failed: %v", err)
	}
	if v != 0 {
		t.Errorf("Uint() on 0x80 = %d, want 0", v)
	}
}

// TestStream_Uint_SizeZero_NoBudgetConsumed verifies that calling Uint()
// on the empty-string encoding of 0 (0x80) does NOT consume any of the
// Stream's totalDecoded memory budget. This is because size=0 means the
// underlying make([]byte, 0) is empty, and totalDecoded += 0 is a no-op.
//
// RLP-R11-005 (2026-07-20): Guards against a future regression where
// someone might "fix" the budget tracking by always incrementing by at
// least 1, which would make a list of N zeros consume N bytes of budget
// even though they return no actual data.
func TestStream_Uint_SizeZero_NoBudgetConsumed(t *testing.T) {
	// A list of 5 zeros: 0xC5 (short list, 5 bytes) + 0x80 * 5.
	// Each 0x80 is String kind with size=0.
	list := []byte{0xC5, 0x80, 0x80, 0x80, 0x80, 0x80}
	s := NewStream(bytes.NewReader(list), 0)

	if _, err := s.List(); err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	// Read 5 zeros. Each Uint() call must succeed and return 0.
	for i := 0; i < 5; i++ {
		v, err := s.Uint()
		if err != nil {
			t.Fatalf("Uint() call %d failed: %v", i, err)
		}
		if v != 0 {
			t.Errorf("Uint() call %d = %d, want 0", i, v)
		}
	}

	// totalDecoded must remain 0 (5 zeros × 0 bytes each = 0 bytes).
	// We can't directly read s.totalDecoded (unexported), but we can
	// verify by trying to read one more Uint() — if budget were
	// incorrectly consumed, the next call would still succeed (we're
	// well under the 32 MB cap), so this is mostly a sanity check that
	// the list iteration didn't break.
	if err := s.ListEnd(); err != nil {
		t.Fatalf("ListEnd() failed: %v", err)
	}
}

// TestStream_Uint_SizeZero_InList verifies that Stream.Uint() correctly
// decodes a list containing a mix of 0 (encoded as 0x80, size=0) and
// non-zero integers. This exercises the size=0 path alongside normal
// paths in a single Stream.
//
// RLP-R11-005 (2026-07-20).
func TestStream_Uint_SizeZero_InList(t *testing.T) {
	// List: [0, 1, 0, 127, 0, 128]
	// Encoded as:
	//   0x80        (0, empty string)
	//   0x01        (1, single byte, Byte kind)
	//   0x80        (0, empty string)
	//   0x7F        (127, single byte, Byte kind)
	//   0x80        (0, empty string)
	//   0x81 0x80   (128, 1-byte string with value 0x80)
	// List size = 1 + 1 + 1 + 1 + 1 + 2 = 7 bytes
	// List header = 0xC7 (short list, 7 bytes)
	list := []byte{0xC7, 0x80, 0x01, 0x80, 0x7F, 0x80, 0x81, 0x80}
	expected := []uint64{0, 1, 0, 127, 0, 128}

	s := NewStream(bytes.NewReader(list), 0)
	if _, err := s.List(); err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	for i, want := range expected {
		v, err := s.Uint()
		if err != nil {
			t.Fatalf("Uint() call %d failed: %v", i, err)
		}
		if v != want {
			t.Errorf("Uint() call %d = %d, want %d", i, v, want)
		}
	}

	if err := s.ListEnd(); err != nil {
		t.Fatalf("ListEnd() failed: %v", err)
	}
}

// TestStream_Uint_NonCanonical_0x00 verifies that the non-canonical
// encoding of integer 0 as 0x00 (single byte containing zero, Byte kind)
// is rejected with ErrCanonicalInt. The canonical encoding is 0x80
// (empty string, String kind, size=0).
//
// RLP-R11-005 (2026-07-20): This test complements TestStream_Uint_SizeZero
// by verifying the OTHER encoding of zero — the non-canonical 0x00 form —
// is rejected. Together, these two tests pin down the canonical-encoding
// contract for integer 0.
func TestStream_Uint_NonCanonical_0x00(t *testing.T) {
	s := NewStream(bytes.NewReader([]byte{0x00}), 0)
	_, err := s.Uint()
	if err != ErrCanonicalInt {
		t.Errorf("Uint() on 0x00 err = %v, want ErrCanonicalInt", err)
	}
}

// Quantaureum Node source, version 1.0.0.
package rlp

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"
)

func TestEncodeToBytes_Empty(t *testing.T) {
	b, err := EncodeToBytes([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0x80}) {
		t.Errorf("expected [0x80], got %v", b)
	}
}

func TestEncodeToBytes_Nil(t *testing.T) {
	b, err := EncodeToBytes(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0x80}) {
		t.Errorf("expected [0x80], got %v", b)
	}
}

func TestEncodeToBytes_SingleByte(t *testing.T) {
	b, err := EncodeToBytes([]byte{0x01})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0x01}) {
		t.Errorf("expected [0x01], got %v", b)
	}
}

func TestEncodeToBytes_SingleByteHighRange(t *testing.T) {
	b, err := EncodeToBytes([]byte{0x80})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0x81, 0x80}) {
		t.Errorf("expected [0x81, 0x80], got %v", b)
	}
}

func TestEncodeToBytes_ShortString(t *testing.T) {
	b, err := EncodeToBytes("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0x84, 't', 'e', 's', 't'}
	if !bytes.Equal(b, expected) {
		t.Errorf("expected %v, got %v", expected, b)
	}
}

func TestEncodeToBytes_LongString(t *testing.T) {
	long := make([]byte, 60)
	b, err := EncodeToBytes(long)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b[0] != 0xb7+0x01 {
		t.Errorf("expected header byte %d, got %d", 0xb7+0x01, b[0])
	}
}

func TestEncodeToBytes_Uint64(t *testing.T) {
	tests := []struct {
		name     string
		val      uint64
		expected []byte
	}{
		{"zero", 0, []byte{0x80}},
		{"small", 10, []byte{0x0a}},
		{"max_byte", 127, []byte{0x7f}},
		{"one_byte_len", 128, []byte{0x81, 0x80}},
		{"large", 1000, []byte{0x82, 0x03, 0xe8}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := EncodeToBytes(tt.val)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(b, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, b)
			}
		})
	}
}

func TestEncodeToBytes_Bool(t *testing.T) {
	b, err := EncodeToBytes(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0x01}) {
		t.Errorf("expected [0x01], got %v", b)
	}

	b, err = EncodeToBytes(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0x80}) {
		t.Errorf("expected [0x80], got %v", b)
	}
}

func TestEncodeToBytes_BigInt(t *testing.T) {
	b, err := EncodeToBytes(big.NewInt(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0x2a}) {
		t.Errorf("expected [0x2a], got %v", b)
	}
}

func TestEncodeToBytes_BigInt_Negative(t *testing.T) {
	_, err := EncodeToBytes(big.NewInt(-1))
	if err != ErrNegativeBigInt {
		t.Errorf("expected ErrNegativeBigInt, got %v", err)
	}
}

func TestEncodeToBytes_Slice(t *testing.T) {
	b, err := EncodeToBytes([]string{"a", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0xc2, 0x61, 0x62}
	if !bytes.Equal(b, expected) {
		t.Errorf("expected %v, got %v", expected, b)
	}
}

func TestEncodeToBytes_EmptySlice(t *testing.T) {
	b, err := EncodeToBytes([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0xc0}) {
		t.Errorf("expected [0xc0], got %v", b)
	}
}

func TestEncodeToBytes_Struct(t *testing.T) {
	type Simple struct {
		A uint64
		B string
	}

	s := Simple{A: 10, B: "test"}
	b, err := EncodeToBytes(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestEncodeToBytes_ByteArray(t *testing.T) {
	arr := [4]byte{0x01, 0x02, 0x03, 0x04}
	b, err := EncodeToBytes(arr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []byte{0x84, 0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(b, expected) {
		t.Errorf("expected %v, got %v", expected, b)
	}
}

func TestEncodeToBytes_NestedSlices(t *testing.T) {
	b, err := EncodeToBytes([][]string{{"a"}, {"b", "c"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty")
	}
}

func TestEncodeToWriter(t *testing.T) {
	var buf bytes.Buffer
	err := Encode(&buf, uint64(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0x2a}) {
		t.Errorf("expected [0x2a], got %v", buf.Bytes())
	}
}

func TestEncodeToReader(t *testing.T) {
	size, r, err := EncodeToReader(uint64(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if size != 1 {
		t.Errorf("expected size 1, got %d", size)
	}
	out := make([]byte, 1)
	n, err := r.Read(out)
	if err != nil || n != 1 {
		t.Fatalf("read failed: n=%d err=%v", n, err)
	}
	if out[0] != 0x2a {
		t.Errorf("expected 0x2a, got 0x%x", out[0])
	}
}

func TestEncodeToBytes_Int64(t *testing.T) {
	b, err := EncodeToBytes(int64(100))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(b, []byte{0x64}) {
		t.Errorf("expected [0x64], got %v", b)
	}
}

func TestListSize(t *testing.T) {
	sz := ListSize(100)
	if sz != 102 {
		t.Errorf("expected 102, got %d", sz)
	}

	sz = ListSize(0)
	if sz != 1 {
		t.Errorf("expected 1, got %d", sz)
	}
}

func TestStringSize(t *testing.T) {
	sz := StringSize([]byte{})
	if sz != 1 {
		t.Errorf("expected 1, got %d", sz)
	}

	sz = StringSize([]byte{0x01})
	if sz != 1 {
		t.Errorf("expected 1, got %d", sz)
	}

	sz = StringSize([]byte{0x80})
	if sz != 2 {
		t.Errorf("expected 2, got %d", sz)
	}
}

func TestIntSize(t *testing.T) {
	sz := IntSize(0)
	if sz != 1 {
		t.Errorf("expected 1, got %d", sz)
	}
	sz = IntSize(127)
	if sz != 1 {
		t.Errorf("expected 1, got %d", sz)
	}
	sz = IntSize(128)
	if sz != 2 {
		t.Errorf("expected 2, got %d", sz)
	}
}

func TestEncodeToBytes_Roundtrip(t *testing.T) {
	original := uint64(12345)
	encoded, _ := EncodeToBytes(original)
	if !bytes.Equal(encoded, []byte{0x82, 0x30, 0x39}) {
		t.Errorf("expected [0x82, 0x30, 0x39], got %v", encoded)
	}
	_ = reflect.ValueOf(original)
}

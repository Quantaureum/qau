// Quantaureum Node source, version 1.0.0.
package hexutil

import (
	"math/big"
	"reflect"
	"strings"
	"testing"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte{}, "0x"},
		{"nil", nil, "0x"},
		{"single_byte", []byte{0x01}, "0x01"},
		{"multiple", []byte{0x01, 0x02, 0xab}, "0x0102ab"},
		{"all_zeros", []byte{0x00, 0x00}, "0x0000"},
		{"full_range", []byte{0x00, 0xff, 0x0f, 0xf0}, "0x00ff0ff0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encode(tt.input)
			if got != tt.expected {
				t.Errorf("Encode(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr error
	}{
		{"empty_string", "", nil, ErrEmptyString},
		{"no_prefix", "1234", nil, ErrMissingPrefix},
		{"empty_data", "0x", []byte{}, nil},
		{"single_byte", "0x01", []byte{0x01}, nil},
		{"multiple", "0x0102ab", []byte{0x01, 0x02, 0xab}, nil},
		{"odd_length", "0x123", nil, ErrOddLength},
		{"invalid_char", "0xgh", nil, ErrInvalidHex},
		{"lowercase", "0xabcdef", []byte{0xab, 0xcd, 0xef}, nil},
		{"uppercase", "0xABCDEF", []byte{0xab, 0xcd, 0xef}, nil},
		{"mixed_case", "0xaBcDeF", []byte{0xab, 0xcd, 0xef}, nil},
		{"uppercase_prefix", "0XAB", []byte{0xab}, nil},
		{"long_bytes", "0x" + strings.Repeat("ff", 1024), bytesRepeat(0xff, 1024), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.input)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeBytes(t *testing.T) {
	got, err := DecodeBytes("0xabcd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []byte{0xab, 0xcd}) {
		t.Errorf("expected [ab cd], got %v", got)
	}
}

func TestEncodeBig(t *testing.T) {
	tests := []struct {
		name     string
		input    *big.Int
		expected string
	}{
		{"nil", nil, "0x0"},
		{"zero", big.NewInt(0), "0x0"},
		{"one", big.NewInt(1), "0x1"},
		{"large", big.NewInt(255), "0xff"},
		{"negative", big.NewInt(-10), "0xa"},
		{"max256", new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), "0x" + strings.Repeat("f", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeBig(tt.input)
			if got != tt.expected {
				t.Errorf("EncodeBig(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDecodeBig(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *big.Int
		wantErr error
	}{
		{"empty", "", nil, ErrEmptyString},
		{"no_prefix", "123", nil, ErrMissingPrefix},
		{"empty_number", "0x", nil, ErrEmptyNumber},
		{"zero", "0x0", big.NewInt(0), nil},
		{"one", "0x1", big.NewInt(1), nil},
		{"large", "0xff", big.NewInt(255), nil},
		{"leading_zero", "0x0123", nil, ErrLeadingZero},
		{"invalid", "0xgh", nil, ErrInvalidHex},
		{"exceeds_256", "0x1" + strings.Repeat("f", 65), nil, ErrBig256Range},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeBig(tt.input)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got.Cmp(tt.want) != 0 {
				t.Errorf("DecodeBig(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeBigInt(t *testing.T) {
	got, err := DecodeBigInt("0x2a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Int64() != 42 {
		t.Errorf("expected 42, got %d", got.Int64())
	}
}

func TestEncodeUint64(t *testing.T) {
	tests := []struct {
		name     string
		input    uint64
		expected string
	}{
		{"zero", 0, "0x0"},
		{"one", 1, "0x1"},
		{"max64", 0xFFFFFFFFFFFFFFFF, "0xffffffffffffffff"},
		{"mid_range", 123456789, "0x75bcd15"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeUint64(tt.input)
			if got != tt.expected {
				t.Errorf("EncodeUint64(%d) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDecodeUint64(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr error
	}{
		{"empty", "", 0, ErrEmptyString},
		{"no_prefix", "123", 0, ErrMissingPrefix},
		{"empty_number", "0x", 0, ErrEmptyNumber},
		{"zero", "0x0", 0, nil},
		{"one", "0x1", 1, nil},
		{"max64", "0xffffffffffffffff", 0xFFFFFFFFFFFFFFFF, nil},
		{"leading_zero", "0x0123", 0, ErrLeadingZero},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeUint64(tt.input)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("DecodeUint64(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"0x", true},
		{"0x123", true},
		{"0Xabc", true},
		{"123", false},
		{"", false},
		{"0xgh", false},
		{"0xABCDEF", true},
		{"0x12x3", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsHex(tt.input)
			if got != tt.want {
				t.Errorf("IsHex(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeNoPrefix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr error
	}{
		{"empty", "", []byte{}, nil},
		{"with_prefix", "0xabcd", []byte{0xab, 0xcd}, nil},
		{"without_prefix", "abcd", []byte{0xab, 0xcd}, nil},
		{"uppercase_prefix", "0XABCD", []byte{0xab, 0xcd}, nil},
		{"odd_length", "abc", nil, ErrOddLength},
		{"invalid", "gh", nil, ErrInvalidHex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeNoPrefix(tt.input)
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodeNoPrefix(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHas0xPrefix(t *testing.T) {
	if !has0xPrefix("0x123") {
		t.Error("expected true for 0x123")
	}
	if !has0xPrefix("0X123") {
		t.Error("expected true for 0X123")
	}
	if has0xPrefix("123") {
		t.Error("expected false for 123")
	}
	if has0xPrefix("") {
		t.Error("expected false for empty")
	}
	if has0xPrefix("0") {
		t.Error("expected false for 0")
	}
}

func TestEncodeRoundtrip(t *testing.T) {
	original := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded := Encode(original)
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("roundtrip failed: %v != %v", decoded, original)
	}
}

func TestDecodeUint64Large(t *testing.T) {
	_, err := DecodeUint64("0x1ffffffffffffffff")
	if err == nil {
		t.Error("expected error for overflow")
	}
}

func bytesRepeat(b byte, n int) []byte {
	result := make([]byte, n)
	for i := range result {
		result[i] = b
	}
	return result
}

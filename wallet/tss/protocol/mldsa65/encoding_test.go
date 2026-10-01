// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"testing"
)

func TestEncodeHighBits(t *testing.T) {
	var high HighBitsPoly
	high[0] = 1
	high[1] = 15
	high[2] = 2
	encoded, err := EncodeHighBits(high)
	if err != nil {
		t.Fatalf("EncodeHighBits(): %v", err)
	}
	if len(encoded) != 128 || encoded[0] != 0xf1 || encoded[1] != 0x02 {
		t.Fatalf("encoded prefix = %x", encoded[:2])
	}
	high[7] = 16
	if _, err := EncodeHighBits(high); !errors.Is(err, ErrInvalidHighBits) {
		t.Fatalf("EncodeHighBits() error = %v, want %v", err, ErrInvalidHighBits)
	}
}

func TestEncodeZ(t *testing.T) {
	var z SignedPoly
	z[0] = -524287
	z[1] = 524288
	encoded, err := EncodeZ(z)
	if err != nil {
		t.Fatalf("EncodeZ(): %v", err)
	}
	if len(encoded) != 640 {
		t.Fatalf("encoded z length = %d", len(encoded))
	}
	z[3] = -524288
	if _, err := EncodeZ(z); !errors.Is(err, ErrInvalidZCoefficient) {
		t.Fatalf("EncodeZ() error = %v, want %v", err, ErrInvalidZCoefficient)
	}
}

func TestEncodeHints(t *testing.T) {
	var hints HintVector
	hints[0][2] = 1
	hints[0][9] = 1
	hints[2][7] = 1
	encoded, err := EncodeHints(hints)
	if err != nil {
		t.Fatalf("EncodeHints(): %v", err)
	}
	if len(encoded) != 61 {
		t.Fatalf("encoded hint length = %d", len(encoded))
	}
	if encoded[0] != 2 || encoded[1] != 9 || encoded[2] != 7 {
		t.Fatalf("hint indices = %v", encoded[:3])
	}
	if encoded[55] != 2 || encoded[56] != 2 || encoded[57] != 3 {
		t.Fatalf("hint offsets = %v", encoded[55:61])
	}

	for index := 0; index < 56; index++ {
		hints[0][index] = 1
	}
	if _, err := EncodeHints(hints); !errors.Is(err, ErrTooManyHints) {
		t.Fatalf("EncodeHints() error = %v, want %v", err, ErrTooManyHints)
	}
}

func TestDecodeRejectsNonCanonicalHints(t *testing.T) {
	encoded := make([]byte, 61)
	encoded[0] = 9
	encoded[1] = 9
	encoded[55] = 2
	for index := 56; index < len(encoded); index++ {
		encoded[index] = 2
	}
	if _, err := DecodeHints(encoded); !errors.Is(err, ErrInvalidHintVector) {
		t.Fatalf("duplicate hint index error = %v, want %v", err, ErrInvalidHintVector)
	}

	encoded = make([]byte, 61)
	encoded[0] = 7
	encoded[55] = 1
	for index := 56; index < len(encoded); index++ {
		encoded[index] = 1
	}
	encoded[3] = 1
	if _, err := DecodeHints(encoded); !errors.Is(err, ErrInvalidHintVector) {
		t.Fatalf("non-zero padding error = %v, want %v", err, ErrInvalidHintVector)
	}
}

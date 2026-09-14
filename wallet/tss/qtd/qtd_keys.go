// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

const (
	// polyLeqEtaSize: byte size of each packed low-entropy polynomial in mode3
	polyLeqEtaSize = 128

	rhoOffset = 0
	keyOffset = 32
	trOffset  = 64
	s1Offset  = 96
	// audit-fix L7-001: Use Dilithium3 constants instead of magic numbers.
	s2Offset = 96 + Dilithium3L*polyLeqEtaSize
	t0Offset = 96 + (Dilithium3L+Dilithium3K)*polyLeqEtaSize
)

// L6-002 FIX: Validate hardcoded private key offsets against the circl mode3
// packed layout at init time.
func init() {
	const (
		seedFieldSize = 32 // rho, key, tr are each 32 bytes
		polyT0Size    = 416
	)
	// rho -> key -> tr -> s1 must be contiguous 32-byte fields starting at 0.
	if rhoOffset != 0 ||
		keyOffset != rhoOffset+seedFieldSize ||
		trOffset != keyOffset+seedFieldSize ||
		s1Offset != trOffset+seedFieldSize {
		panic("qtd: rho/key/tr/s1 offsets are not contiguous 32-byte fields")
	}
	// s1 and s2 spans must be positive multiples of polyLeqEtaSize (128).
	s1Span := s2Offset - s1Offset
	s2Span := t0Offset - s2Offset
	if s1Span <= 0 || s1Span%polyLeqEtaSize != 0 ||
		s2Span <= 0 || s2Span%polyLeqEtaSize != 0 {
		panic("qtd: s1/s2 span is not a positive multiple of polyLeqEtaSize")
	}
	// t0 span must fill the remainder of PrivateKeySize with polyT0Size multiples.
	t0Span := mode3.PrivateKeySize - t0Offset
	if t0Span <= 0 || t0Span%polyT0Size != 0 {
		panic("qtd: t0 span does not fill mode3.PrivateKeySize with polyT0Size multiples")
	}
}

func s1PolyLeqEtaDecode(dst *Poly, src []byte) error {
	// L18-021 FIX: Validate input length before decoding to prevent
	// out-of-bounds reads from truncated or corrupted key material.
	// N20-005 FIX: Return error instead of panic to prevent crash from
	// malformed key material supplied by external callers.
	if len(src) < polyLeqEtaSize {
		return fmt.Errorf("qtd: s1PolyLeqEtaDecode: src too short")
	}
	j := 0
	for i := 0; i < 128; i++ {
		dst[j] = int32(Q) + Dilithium3EtaPoly - int32(src[i]&15)
		dst[j+1] = int32(Q) + Dilithium3EtaPoly - int32(src[i]>>4)
		j += 2
	}
	return nil
}

func parseT0Poly(dst *Poly, src []byte) error {
	const D = 13
	// L18-021 FIX: Validate input length before decoding to prevent
	// out-of-bounds reads from truncated or corrupted key material.
	if len(src) < 416 {
		// N20-005 FIX: Return error instead of panic to prevent crash from
		// malformed key material supplied by external callers.
		return fmt.Errorf("qtd: parseT0Poly: src too short")
	}
	j := 0
	for i := 0; i < 416; i += 13 {
		dst[j] = int32(Q) + (1 << (D - 1)) - int32((uint32(src[i])|
			(uint32(src[i+1])<<8))&0x1fff)
		dst[j+1] = int32(Q) + (1 << (D - 1)) - int32(((uint32(src[i+1])>>5)|
			(uint32(src[i+2])<<3)|
			(uint32(src[i+3])<<11))&0x1fff)
		dst[j+2] = int32(Q) + (1 << (D - 1)) - int32(((uint32(src[i+3])>>2)|
			(uint32(src[i+4])<<6))&0x1fff)
		dst[j+3] = int32(Q) + (1 << (D - 1)) - int32(((uint32(src[i+4])>>7)|
			(uint32(src[i+5])<<1)|
			(uint32(src[i+6])<<9))&0x1fff)
		dst[j+4] = int32(Q) + (1 << (D - 1)) - int32(((uint32(src[i+6])>>4)|
			(uint32(src[i+7])<<4)|
			(uint32(src[i+8])<<12))&0x1fff)
		dst[j+5] = int32(Q) + (1 << (D - 1)) - int32(((uint32(src[i+8])>>1)|
			(uint32(src[i+9])<<7))&0x1fff)
		dst[j+6] = int32(Q) + (1 << (D - 1)) - int32(((uint32(src[i+9])>>6)|
			(uint32(src[i+10])<<2)|
			(uint32(src[i+11])<<10))&0x1fff)
		dst[j+7] = int32(Q) + (1 << (D - 1)) - int32((uint32(src[i+11])>>3)|
			(uint32(src[i+12])<<5))
		j += 8
	}
	return nil
}

func parseT0PolyVec(dst PolyVec, src []byte, k int) error {
	for i := 0; i < k; i++ {
		dst[i] = Poly{}
		off := i * 416
		if err := parseT0Poly(&dst[i], src[off:off+416]); err != nil {
			return err
		}
	}
	return nil
}

func FullKeyShareFromMode3(sk *mode3.PrivateKey, pk *mode3.PublicKey) (*QTDShare, error) {
	var skBuf [mode3.PrivateKeySize]byte
	sk.Pack(&skBuf)

	rho := make([]byte, 32)
	copy(rho, skBuf[rhoOffset:keyOffset])

	s1 := make(PolyVec, Dilithium3L)
	for i := 0; i < Dilithium3L; i++ {
		s1[i] = Poly{}
		off := s1Offset + i*128
		if err := s1PolyLeqEtaDecode(&s1[i], skBuf[off:off+128]); err != nil {
			return nil, fmt.Errorf("failed to decode s1 polynomial %d: %w", i, err)
		}
	}

	var pkBuf [mode3.PublicKeySize]byte
	pk.Pack(&pkBuf)
	t1 := make([]byte, mode3.PublicKeySize-32)
	copy(t1, pkBuf[32:])

	// L7-009 FIX: Zero sensitive intermediate key material before returning.
	// skBuf holds the full packed private key (including the s2/t0 vectors
	// that are NOT extracted into the share), s1 is the secret-key polynomial
	// vector (serialized separately into the returned s1Bytes), and pkBuf is
	// the packed public key. Poly is a value-type [N]int32 array, so the
	// byte-oriented SecurelyZeroMemory is used for the byte buffers while the
	// PolyVec is zeroed via Zero(). The returned rho/t1/s1Bytes are NOT touched.
	defer func() {
		for i := range s1 {
			s1[i].Zero()
		}
		SecurelyZeroMemory(skBuf[:])
		SecurelyZeroMemory(pkBuf[:])
	}()
	// L8-009 CONFIRMED FIXED: skBuf is zeroed via the L7-009 defer block above
	// (SecurelyZeroMemory). The zeroing happens on function exit, after s1Bytes
	// has been derived from s1, so skBuf contents are wiped before returning.

	s1Bytes := VecToBytes(s1)
	expectedS1Len := Dilithium3L * N * 3
	if len(s1Bytes) != expectedS1Len {
		return nil, fmt.Errorf("invalid S1 share length: got %d, expected %d", len(s1Bytes), expectedS1Len)
	}

	return &QTDShare{
		ParticipantID: 0,
		Rho:           rho,
		S1ShareBytes:  s1Bytes,
		T1Bytes:       t1,
	}, nil
}

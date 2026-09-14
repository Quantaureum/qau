// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// L8-010 CONFIRMED FIXED: Pack/Unpack consistency analysis:
//   - sigPackZ / sigUnpackZ: symmetric inverse pair (640 bytes per Z poly).
//     Pack encodes 2 coeffs per 5 bytes; Unpack reads the same layout.
//   - PackGMQTDSignature: produces standard 3293-byte Dilithium3 signature
//     (ctilde[32] + z[5*640] + hint[61]). Verified by standard Dilithium3
//     verification, no separate unpack needed.
//   - PackGMQTDFullSignature / CheckGMQTDFullSignature: paired pack/verify
//     for the 4064-byte full-signature format (ctilde + z bitmap + hint
//     bitmap). CheckGMQTDFullSignature reads the packed format directly,
//     so no standalone Unpack function is required.

func sigUnpackZ(p *Poly, buf []byte) error {
	// L10-026 FIX: Validate buffer size to prevent out-of-bounds reads.
	// Q21-021 FIX: Return error instead of silently returning with zeroed data.
	if len(buf) < 640 {
		return fmt.Errorf("sigUnpackZ: buffer too small: %d < 640", len(buf))
	}
	j := 0
	for i := 0; i < 640; i += 5 {
		p0 := uint32(buf[i]) | uint32(buf[i+1])<<8 | (uint32(buf[i+2])&0x0F)<<16
		p1 := uint32(buf[i+2])>>4 | uint32(buf[i+3])<<4 | uint32(buf[i+4])<<12

		p[j] = int32(Dilithium3Gamma1 - int64(p0))
		p[j+1] = int32(Dilithium3Gamma1 - int64(p1))
		j += 2
	}
	// FIX: Validate that unpacked Gamma1 values are within the
	// valid range [-Gamma1, Gamma1]. Each 20-bit packed value is in
	// [0, 2*Gamma1-1], so the unpacked coefficient is in
	// [-(Gamma1-1), Gamma1]. Reject any coefficient outside [-Gamma1, Gamma1]
	// as a defense-in-depth measure against malformed signature data.
	gamma1Bound := int32(Dilithium3Gamma1)
	for k := 0; k < j; k++ {
		if p[k] < -gamma1Bound || p[k] > gamma1Bound {
			return fmt.Errorf("sigUnpackZ: coefficient %d out of range [-%d, %d]: %d",
				k, Dilithium3Gamma1, Dilithium3Gamma1, p[k])
		}
	}
	return nil
}

func sigPackZ(p Poly, buf []byte) error {
	// L10-026 FIX: Validate buffer size to prevent out-of-bounds writes.
	// Q21-021 FIX: Return error instead of silently returning.
	if len(buf) < 640 {
		return fmt.Errorf("sigPackZ: buffer too small: %d < 640", len(buf))
	}
	j := 0
	for i := 0; i < 640; i += 5 {
		p0 := Dilithium3Gamma1 - p[j]
		p0 += (p0 >> 31) & Q
		p1 := Dilithium3Gamma1 - p[j+1]
		p1 += (p1 >> 31) & Q

		buf[i+0] = byte(p0)
		buf[i+1] = byte(p0 >> 8)
		buf[i+2] = byte(p0>>16) | byte(p1<<4)
		buf[i+3] = byte(p1 >> 4)
		buf[i+4] = byte(p1 >> 12)
		j += 2
	}
	return nil
}

func sigPackHint(hint PolyVec, buf []byte) error {
	K := len(hint)
	omega := Dilithium3Omega
	// L10-026 FIX: Validate buffer size to prevent out-of-bounds writes.
	if len(buf) < omega+K {
		return fmt.Errorf("sigPackHint: buffer too small: %d < %d", len(buf), omega+K)
	}
	off := 0
	for i := 0; i < K; i++ {
		for j := 0; j < N; j++ {
			if hint[i][j] != 0 {
				if off < omega {
					buf[off] = byte(j)
				}
				off++
			}
		}
		buf[omega+i] = byte(off) // #nosec G602 -- len(buf)>=omega+K checked above, i<K
	}
	for ; off < omega; off++ {
		buf[off] = 0
	}
	for i := omega + K; i < len(buf); i++ {
		buf[i] = 0
	}
	return nil
}

func PackGMQTDSignature(z PolyVec, hint PolyVec, ctilde [32]byte) []byte {
	// L10-026 FIX: Validate input sizes to prevent buffer overflow.
	if len(z) != Dilithium3L || len(hint) != Dilithium3K {
		return nil
	}
	sig := make([]byte, 3293)

	copy(sig[:32], ctilde[:])

	off := 32
	for i := 0; i < len(z); i++ {
		if err := sigPackZ(z[i], sig[off:off+640]); err != nil {
			return nil // Q21-021: Return nil signature on pack error
		}
		off += 640
	}

	hintBuf := make([]byte, 61)
	if err := sigPackHint(hint, hintBuf); err != nil {
		return nil //  return nil signature on pack error
	}
	copy(sig[off:off+61], hintBuf)

	return sig
}

func PackGMQTDFullSignature(z PolyVec, hint PolyVec, ctilde [32]byte) []byte {
	// L10-026 FIX: Validate input sizes to prevent buffer overflow.
	if len(z) != Dilithium3L || len(hint) != Dilithium3K {
		return nil
	}
	const fullSigSize = 4064
	sig := make([]byte, fullSigSize)

	copy(sig[:32], ctilde[:])

	off := 32
	for i := 0; i < len(z); i++ {
		zBytes := z[i].ToBytes()
		copy(sig[off:off+len(zBytes)], zBytes)
		off += len(zBytes)
	}

	for i := 0; i < len(hint); i++ {
		for j := 0; j < N; j++ {
			if hint[i][j] != 0 {
				byteIdx := (i*N + j) / 8
				bitIdx := (i*N + j) % 8
				sig[off+byteIdx] |= 1 << bitIdx
			}
		}
	}

	return sig
}

func CheckGMQTDFullSignature(pk *mode3.PublicKey, message, sig []byte) bool {
	if len(sig) != 4064 {
		return false
	}

	ctilde := sig[:32]
	zPacked := sig[32:3872]
	hintBitmap := sig[3872:4064]

	pkBytes := pk.Bytes()
	// FIX: Use mode3.PublicKeySize constant instead of hardcoded 1952.
	if len(pkBytes) < mode3.PublicKeySize {
		return false
	}
	rho := pkBytes[:32]
	t1Packed := pkBytes[32:mode3.PublicKeySize]

	// tr = SHAKE-256(pk) = CRH(rho || t1)
	hTr := sha3.NewShake256()
	hTr.Write(pkBytes[:mode3.PublicKeySize])
	var tr [32]byte
	hTr.Read(tr[:])

	t1, err := UnpackT1(t1Packed, Dilithium3K)
	if err != nil {
		return false
	}

	z, err := VecFromBytes(zPacked, Dilithium3L)
	if err != nil {
		return false
	}

	A, err := ComputeA(rho, Dilithium3K, Dilithium3L)
	if err != nil {
		return false
	}

	var c Poly
	if err := c.SampleInBall(ctilde, int(Dilithium3Tau)); err != nil {
		return false
	}

	az := ComputeAz(A, z)

	const twoToD = 1 << Dilithium3D
	for i := 0; i < Dilithium3K; i++ {
		var ct Poly
		ct.PolyMul(&c, &t1[i])
		for j := 0; j < N; j++ {
			ct[j] = int32((int64(ct[j]) * twoToD) % Q)
		}
		az[i].Sub(&az[i], &ct)
	}

	// Convert hintBitmap to PolyVec for UseHint
	hint := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			byteIdx := (i*N + j) / 8
			bitIdx := (i*N + j) % 8
			if (hintBitmap[byteIdx]>>bitIdx)&1 == 1 {
				hint[i][j] = 1
			}
		}
	}

	w1 := UseHint(hint, az, int(Dilithium3Gamma2))

	// Pack w1 using circl-compatible PackLe16 (4-bit per coefficient)
	w1Packed := PackW1(w1)

	// mu = SHAKE-256(tr || msg)
	hMu := sha3.NewShake256()
	hMu.Write(tr[:])
	hMu.Write(message)
	var mu [64]byte
	hMu.Read(mu[:])

	// ctilde' = SHAKE-256(mu || w1Packed)
	hC := sha3.NewShake256()
	hC.Write(mu[:])
	hC.Write(w1Packed)
	var ctildePrime [32]byte
	hC.Read(ctildePrime[:])

	// L18-003 FIX: Use crypto/subtle.ConstantTimeCompare instead of manual XOR
	// accumulation. While the manual loop was technically constant-time, using
	// the standard library function is more maintainable and auditable.
	return subtle.ConstantTimeCompare(ctilde[:], ctildePrime[:]) == 1
}

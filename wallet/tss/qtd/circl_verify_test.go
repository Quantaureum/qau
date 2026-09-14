// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/sha256"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/sha3"
)

// TestCirclSigQtdVerify generates a signature with circl, then verifies it
// using QTD's matrix A, nttMul, UseHint, and PackW1. If this fails, QTD's
// matrix A computation (or verification math) is wrong. If it passes, the
// bug is in the signing flow.
func TestCirclSigQtdVerify(t *testing.T) {
	seedArr := sha256.Sum256([]byte("circl-qtd-verify-test"))
	pk, sk := mode3.NewKeyFromSeed(&seedArr)

	message := []byte("test message for circl-qtd verification")
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(sk, message, sig)

	if !mode3.Verify(pk, message, sig) {
		t.Fatal("circl signature failed circl verification (sanity check)")
	}
	t.Log("circl signature passes circl verification (sanity OK)")

	ctilde := sig[:32]
	zPacked := sig[32 : 32+3200]
	hintPacked := sig[32+3200:]

	pkBytes := pk.Bytes()
	rho := pkBytes[:32]
	t1Packed := pkBytes[32:1952]

	hTr := sha3.NewShake256()
	hTr.Write(pkBytes[:1952])
	var tr [32]byte
	hTr.Read(tr[:])

	hMu := sha3.NewShake256()
	hMu.Write(tr[:])
	hMu.Write(message)
	var mu [64]byte
	hMu.Read(mu[:])

	zVec := make(PolyVec, Dilithium3L)
	for i := 0; i < Dilithium3L; i++ {
		offset := i * 640
		buf := zPacked[offset : offset+640]
		j := 0
		for k := 0; k < 640; k += 5 {
			p0 := uint32(buf[k]) | uint32(buf[k+1])<<8 | (uint32(buf[k+2])&0x0F)<<16
			p1 := uint32(buf[k+2]>>4) | uint32(buf[k+3])<<4 | uint32(buf[k+4])<<12

			val0 := int32(Dilithium3Gamma1) - int32(p0)
			if val0 < 0 {
				val0 += int32(Q)
			}
			val1 := int32(Dilithium3Gamma1) - int32(p1)
			if val1 < 0 {
				val1 += int32(Q)
			}
			zVec[i][j] = val0
			zVec[i][j+1] = val1
			j += 2
		}
	}

	hint := make(PolyVec, Dilithium3K)
	omega := Dilithium3Omega
	prevSOP := byte(0)
	hintCount := 0
	for i := 0; i < Dilithium3K; i++ {
		sop := hintPacked[omega+i]
		if sop < prevSOP || sop > byte(omega) {
			t.Fatalf("Invalid hint: SOP=%d, prevSOP=%d", sop, prevSOP)
		}
		for j := prevSOP; j < sop; j++ {
			if j > prevSOP && hintPacked[j] <= hintPacked[j-1] {
				t.Fatalf("Invalid hint: non-increasing indices")
			}
			hint[i][hintPacked[j]] = 1
			hintCount++
		}
		prevSOP = sop
	}
	t.Logf("hint count: %d (max %d)", hintCount, omega)

	var c Poly
	if err := c.SampleInBall(ctilde, int(Dilithium3Tau)); err != nil {
		t.Fatalf("SampleInBall: %v", err)
	}
	nonZero := 0
	for i := 0; i < 256; i++ {
		if c[i] != 0 {
			nonZero++
		}
	}
	t.Logf("c non-zero coefficients: %d (want %d)", nonZero, Dilithium3Tau)

	A, err := ComputeA(rho, Dilithium3K, Dilithium3L)
	if err != nil {
		t.Fatalf("ComputeA: %v", err)
	}

	az := ComputeAz(A, zVec)

	t1, err := UnpackT1(t1Packed, Dilithium3K)
	if err != nil {
		t.Fatalf("UnpackT1: %v", err)
	}

	const twoToD = 1 << Dilithium3D
	wApprox := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		var ct Poly
		ct.PolyMul(&c, &t1[i])
		for j := 0; j < 256; j++ {
			ct[j] = int32((int64(ct[j]) * twoToD) % Q)
		}
		wApprox[i].Sub(&az[i], &ct)
		wApprox[i].Reduce()
	}

	w1Reconstructed := UseHint(hint, wApprox, int(Dilithium3Gamma2))

	w1Packed := PackW1(w1Reconstructed)

	hC := sha3.NewShake256()
	hC.Write(mu[:])
	hC.Write(w1Packed)
	var ctildePrime [32]byte
	hC.Read(ctildePrime[:])

	match := true
	for i := 0; i < 32; i++ {
		if ctilde[i] != ctildePrime[i] {
			match = false
			break
		}
	}

	if match {
		t.Log("SUCCESS: QTD verification of circl signature PASSES!")
		t.Log("QTD matrix A, nttMul, UseHint, PackW1 are all correct.")
		t.Log("The bug is in the QTD SIGNING flow, not verification.")
	} else {
		t.Error("FAILURE: QTD verification of circl signature FAILS!")
		t.Logf("ctilde:  %x", ctilde[:8])
		t.Logf("ctilde': %x", ctildePrime[:8])

		var a, b Poly
		for i := 0; i < 256; i++ {
			a[i] = int32((i*7 + 3) % Q)
			b[i] = int32((i*11 + 5) % Q)
		}
		var result1 Poly
		result1.PolyMul(&a, &b)
		aNTT := a
		aNTT.NTT()
		bNTT := b
		bNTT.NTT()
		var resultNTT Poly
		for i := 0; i < 256; i++ {
			resultNTT[i] = int32((int64(aNTT[i]) * int64(bNTT[i])) % Q)
		}
		resultNTT.InvNTT()

		nttMulMatch := true
		for i := 0; i < 256; i++ {
			if result1[i] != resultNTT[i] {
				nttMulMatch = false
				t.Logf("nttMul vs NTT mismatch at %d: schoolbook=%d, ntt=%d", i, result1[i], resultNTT[i])
				if i > 5 {
					break
				}
			}
		}
		if nttMulMatch {
			t.Log("nttMul vs NTT-based multiplication: MATCH")
		} else {
			t.Error("nttMul vs NTT-based multiplication: MISMATCH!")
			t.Log("QTD NTT is incompatible. Fix: use NTT-domain pointwise multiplication.")
		}
	}
}

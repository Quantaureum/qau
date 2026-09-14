// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"testing"
	"time"
)

func BenchmarkPolyAdd(b *testing.B) {
	var a, c Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i * 1000 % Q)
		c[i] = int32(i * 500 % Q)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var r Poly
		r.Add(&a, &c)
	}
}

func BenchmarkPolyMul(b *testing.B) {
	var a, c Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i * 1000 % Q)
		c[i] = int32(i * 500 % Q)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var r Poly
		r.PolyMul(&a, &c)
	}
}

func BenchmarkPolyNTT(b *testing.B) {
	var a Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i * 1000 % Q)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := a
		p.NTT()
		a = p
	}
}

func BenchmarkPolyInvNTT(b *testing.B) {
	var a Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i * 1000 % Q)
	}
	a.NTT()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := a
		p.InvNTT()
		a = p
	}
}

func BenchmarkSampleUniform(b *testing.B) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var p Poly
		_ = p.SampleUniform(seed)
	}
}

func BenchmarkMatVecMul2x2(b *testing.B) {
	mat := make([][]Poly, 2)
	for i := 0; i < 2; i++ {
		mat[i] = make([]Poly, 2)
		for j := 0; j < 2; j++ {
			for k := 0; k < N; k++ {
				mat[i][j][k] = int32((i*N + j + k) % Q)
			}
		}
	}
	vec := make(PolyVec, 2)
	for i := 0; i < 2; i++ {
		for k := 0; k < N; k++ {
			vec[i][k] = int32((i*N + k) % Q)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MatVecMul(mat, vec)
	}
}

func BenchmarkLagrangeCoeff(b *testing.B) {
	parts := []int{1, 2, 3, 4, 5}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lagrangeCoeff(1, parts)
	}
}

func BenchmarkZKProofGeneration(b *testing.B) {
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, 100),
	}
	message := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateZKProof(share, message)
	}
}

func BenchmarkShamirSplit(b *testing.B) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = shamirSplitAll(data, 3, 5)
	}
}

func BenchmarkCommitment(b *testing.B) {
	v := NewPedersenVerifier()
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, 50),
	}
	v.AddVerificationVector(share.ParticipantID, [][]byte{make([]byte, 32)})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.VerifyShare(share)
	}
}

func BenchmarkQTDManagerCreateSession(b *testing.B) {
	m, _ := NewQTDManager(3, 5)
	for i := 1; i <= 5; i++ {
		m.AddShare(&QTDShare{
			ParticipantID: i,
			Rho:           make([]byte, 32),
			S1ShareBytes:  make([]byte, 100),
			S2ShareBytes:  make([]byte, 100),
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.CreateSigningSession([]byte("test"), []int{1, 2, 3})
	}
}

func BenchmarkSecurityAudit(b *testing.B) {
	audit := NewSecurityAudit()
	shares := make([]*QTDShare, 5)
	for i := 0; i < 5; i++ {
		shares[i] = &QTDShare{
			ParticipantID: i + 1,
			Rho:           make([]byte, 32),
			S1ShareBytes:  make([]byte, 100),
			S2ShareBytes:  make([]byte, 100),
			VVector:       [][]byte{make([]byte, 32)},
		}
	}
	session, _ := NewQTDSession([]byte("test"), []int{1, 2, 3}, 3, map[int]*QTDShare{
		1: shares[0], 2: shares[1], 3: shares[2],
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = audit.AuditSession(session, shares[:3])
	}
}

func BenchmarkConstantTimeCompare(b *testing.B) {
	prot := &TimingAttackProtection{}
	a := make([]byte, 3293)
	b2 := make([]byte, 3293)
	for i := range a {
		a[i] = byte(i)
		b2[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = prot.ConstantTimeCompare(a, b2)
	}
}

func BenchmarkEncodeShare(b *testing.B) {
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, 100),
		S2ShareBytes:  make([]byte, 100),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncodeShareForTransmission(share)
	}
}

func BenchmarkDecodeShare(b *testing.B) {
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, 100),
		S2ShareBytes:  make([]byte, 100),
	}
	encoded, _ := EncodeShareForTransmission(share)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeShareFromTransmission(encoded)
	}
}

// PerformanceMeasurement captures actual timing data for the paper.
func TestPerformanceMeasurement(t *testing.T) {
	// PolyMul performance
	var a, c Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i * 1000 % Q)
		c[i] = int32(i * 500 % Q)
	}
	start := time.Now()
	for i := 0; i < 100; i++ {
		var r Poly
		r.PolyMul(&a, &c)
	}
	polyMulTime := time.Since(start) / 100

	// MatVecMul 6x5 performance (Dilithium3 dimensions)
	mat := make([][]Poly, 6)
	for i := 0; i < 6; i++ {
		mat[i] = make([]Poly, 5)
		for j := 0; j < 5; j++ {
			for k := 0; k < N; k++ {
				mat[i][j][k] = int32((i*100 + j*10 + k) % Q)
			}
		}
	}
	vec := make(PolyVec, 5)
	for i := 0; i < 5; i++ {
		for k := 0; k < N; k++ {
			vec[i][k] = int32((i*100 + k) % Q)
		}
	}
	start = time.Now()
	for i := 0; i < 10; i++ {
		_ = MatVecMul(mat, vec)
	}
	matVecTime := time.Since(start) / 10

	// SampleUniform performance
	seed := make([]byte, 32)
	start = time.Now()
	for i := 0; i < 100; i++ {
		var p Poly
		_ = p.SampleUniform(seed)
	}
	sampleTime := time.Since(start) / 100

	// Lagrange interpolation performance
	parts := []int{1, 2, 3}
	start = time.Now()
	for i := 0; i < 10000; i++ {
		_ = lagrangeCoeff(1, parts)
	}
	lagrangeTime := time.Since(start) / 10000

	// ZK proof generation performance
	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, Dilithium3L*N),
	}
	message := []byte("performance test message")
	start = time.Now()
	for i := 0; i < 100; i++ {
		_, _ = GenerateZKProof(share, message)
	}
	zkTime := time.Since(start) / 100

	t.Logf("=== QTD Performance Measurements ===")
	t.Logf("PolyMul (schoolbook, N=256):    %v", polyMulTime)
	t.Logf("MatVecMul (6x5, Dilithium3):     %v", matVecTime)
	t.Logf("SampleUniform (SHA-256 stream):  %v", sampleTime)
	t.Logf("Lagrange Coefficient:            %v", lagrangeTime)
	t.Logf("ZK Proof Generation:             %v", zkTime)

	// Verify correctness alongside performance
	var result Poly
	result.PolyMul(&a, &c)
	if result.NormInf() <= 0 {
		t.Error("PolyMul produced zero result")
	}
}

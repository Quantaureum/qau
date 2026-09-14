// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"testing"
)

func TestNttMulCorrectness(t *testing.T) {
	var a, b, prod Poly

	a[0] = 1
	a[255] = 1
	b[1] = 1

	nttMul(&prod, &a, &b)

	if prod[0] != int32(Q-1) || prod[1] != 1 {
		t.Errorf("(X^255+1)*X: coeff[0]=%d (want %d), coeff[1]=%d (want 1)",
			prod[0], Q-1, prod[1])
	} else {
		t.Log("nttMul basic test OK")
	}

	var c Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i + 1)
		b[i] = int32((i * 7) % (Q - 1))
	}

	var prodS, prodNTT, temp Poly

	nttMul(&prodS, &a, &b)

	temp.Copy(&a)
	temp.NTT()
	c.Copy(&b)
	c.NTT()
	for i := 0; i < N; i++ {
		prodNTT[i] = int32((int64(temp[i]) * int64(c[i])) % Q)
	}
	prodNTT.InvNTT()

	mismatch := 0
	for i := 0; i < N; i++ {
		s := (int64(prodS[i])%Q + Q) % Q
		n := (int64(prodNTT[i])%Q + Q) % Q
		if s != n {
			mismatch++
			if mismatch <= 3 {
				t.Errorf("nttMul vs NTT mismatch at %d: schoolbook=%d ntt=%d", i, s, n)
			}
		}
	}
	if mismatch > 0 {
		t.Errorf("nttMul vs NTT: %d mismatches", mismatch)
	} else {
		t.Log("nttMul vs NTT match OK")
	}
}

func TestMatVecMulSmall(t *testing.T) {
	mat := make([][]Poly, 2)
	for i := 0; i < 2; i++ {
		mat[i] = make([]Poly, 3)
		for j := 0; j < 3; j++ {
			for k := 0; k < N; k++ {
				mat[i][j][k] = int32((i*3 + j + k*7) % Q)
			}
		}
	}

	vec := make(PolyVec, 3)
	for i := 0; i < 3; i++ {
		for k := 0; k < N; k++ {
			vec[i][k] = int32((i*5 + k*3) % Q)
		}
	}

	result := MatVecMul(mat, vec)

	for i := 0; i < 2; i++ {
		for k := 0; k < N; k++ {
			if result[i][k] < 0 || result[i][k] >= Q {
				t.Errorf("result[%d][%d]=%d out of range", i, k, result[i][k])
			}
		}
	}
	t.Log("MatVecMul produces valid range output OK")
}

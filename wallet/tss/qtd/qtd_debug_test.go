// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"reflect"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func TestCirclSignVerify(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i + 1)
	}

	pubKey, privKey := mode3.NewKeyFromSeed(&seed)

	msg := []byte("hello world")
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privKey, msg, sig)

	if !mode3.Verify(pubKey, msg, sig) {
		t.Fatal("circl self-verification failed")
	}
	t.Log("circl sign+verify OK")
}

func getCirclAMatrix(pk *mode3.PublicKey) [][][256]uint32 {
	pkVal := reflect.ValueOf(pk).Elem()
	aField := pkVal.FieldByName("A")
	if !aField.IsValid() {
		return nil
	}
	aPtr := aField.Elem()
	mat := make([][][256]uint32, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		mat[i] = make([][256]uint32, Dilithium3L)
		row := aPtr.Index(i)
		for j := 0; j < Dilithium3L; j++ {
			poly := row.Index(j)
			for k := 0; k < N; k++ {
				mat[i][j][k] = uint32(poly.Index(k).Uint())
			}
		}
	}
	return mat
}

func TestAMatrixComparison(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i + 1)
	}

	pubKey, _ := mode3.NewKeyFromSeed(&seed)
	rho := pubKey.Bytes()[:32]

	circlA := getCirclAMatrix(pubKey)
	if circlA == nil {
		t.Fatal("cannot access circl A matrix via reflect")
	}

	ourA, err := computeARaw(rho, Dilithium3K, Dilithium3L)
	if err != nil {
		t.Fatal(err)
	}

	mismatch := 0
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < Dilithium3L; j++ {
			for k := 0; k < N; k++ {
				if circlA[i][j][k] != uint32(ourA[i][j][k]) {
					mismatch++
					if mismatch <= 5 {
						t.Logf("A[%d][%d][%d]: circl=%d our=%d", i, j, k, circlA[i][j][k], ourA[i][j][k])
					}
				}
			}
		}
	}
	if mismatch > 0 {
		t.Errorf("A matrix: %d/%d mismatch", mismatch, Dilithium3K*Dilithium3L*N)
	} else {
		t.Log("A matrix exact match")
	}
}

func TestTraceOneCoefficient(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i + 1)
	}

	pubKey, privKey := mode3.NewKeyFromSeed(&seed)

	skBytes := privKey.Bytes()
	pkBytes := pubKey.Bytes()
	rho := pkBytes[:32]

	s1Off := mode3.SeedSize * 3
	s1Packed := skBytes[s1Off : s1Off+Dilithium3L*128]
	s1Vec, err := UnpackEtaVec(s1Packed, Dilithium3L, Dilithium3EtaPoly)
	if err != nil {
		t.Fatal(err)
	}

	s2Off := s1Off + Dilithium3L*128
	s2Packed := skBytes[s2Off : s2Off+Dilithium3K*128]
	s2Vec, err := UnpackEtaVec(s2Packed, Dilithium3K, Dilithium3EtaPoly)
	if err != nil {
		t.Fatal(err)
	}

	t0Off := s2Off + Dilithium3K*128
	t0Packed := skBytes[t0Off : t0Off+Dilithium3K*416]
	t0VecInternal := make(PolyVec, Dilithium3K)
	if err := parseT0PolyVec(t0VecInternal, t0Packed, Dilithium3K); err != nil {
		t.Fatalf("failed to parse t0: %v", err)
	}

	t0VecStd := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			t0VecStd[i][j] = int32((int64(t0VecInternal[i][j])%Q + Q) % Q)
		}
	}

	t1Packed := pkBytes[32:]
	t1Vec, err := UnpackT1(t1Packed, Dilithium3K)
	if err != nil {
		t.Fatal(err)
	}

	aMat, err := ComputeA(rho, Dilithium3K, Dilithium3L)
	if err != nil {
		t.Fatal(err)
	}

	as1 := ComputeAz(aMat, s1Vec)

	as1s2 := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		as1s2[i].Add(&as1[i], &s2Vec[i])
	}

	t1Full := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			t1Full[i][j] = int32((int64(t1Vec[i][j]) * (1 << Dilithium3D)) % Q)
		}
		t1Full[i].Add(&t1Full[i], &t0VecStd[i])
	}

	diffCount := 0
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			a := (int64(as1s2[i][j])%Q + Q) % Q
			b := (int64(t1Full[i][j])%Q + Q) % Q
			if a != b {
				diffCount++
				if diffCount <= 5 {
					t.Logf("mismatch[%d][%d]: as1s2=%d t1Full=%d diff=%d",
						i, j, a, b, (a-b+Q)%Q)
				}
			}
		}
	}

	t.Logf("mismatch=%d/%d", diffCount, Dilithium3K*N)

	a00Nibbles := make([]int, N)
	for k := 0; k < N; k++ {
		a00Nibbles[k] = int(aMat[0][0][k] & 0xF)
	}
	t.Logf("A[0][0] low nibbles: %v...%v", a00Nibbles[:4], a00Nibbles[N-4:])
}

func TestInvNttRoundtripOnCirclA(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i + 1)
	}

	pubKey, _ := mode3.NewKeyFromSeed(&seed)
	rho := pubKey.Bytes()[:32]

	ourA, err := computeARaw(rho, Dilithium3K, Dilithium3L)
	if err != nil {
		t.Fatal(err)
	}

	circlA := getCirclAMatrix(pubKey)
	if circlA == nil {
		t.Fatal("cannot access circl A matrix via reflect")
	}

	mismatchInvNtt := 0
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < Dilithium3L; j++ {
			temp := ourA[i][j]
			temp.InvNTT()
			temp.NTT()

			for k := 0; k < N; k++ {
				orig := int64(circlA[i][j][k])
				back := (int64(temp[k])%Q + Q) % Q
				if orig != back {
					mismatchInvNtt++
					if mismatchInvNtt <= 5 {
						t.Logf("InvNTT→NTT fail A[%d][%d][%d]: orig=%d back=%d",
							i, j, k, orig, back)
					}
				}
			}
		}
	}

	if mismatchInvNtt > 0 {
		t.Errorf("InvNTT roundtrip: %d/%d mismatch", mismatchInvNtt, Dilithium3K*Dilithium3L*N)
	} else {
		t.Log("InvNTT→NTT roundtrip on circl A values OK")
	}
}

func TestNttInvNttRoundtrip(t *testing.T) {
	var orig, temp Poly
	for i := 0; i < N; i++ {
		orig[i] = int32((i*12345 + 6789) % Q)
	}

	temp.Copy(&orig)
	temp.NTT()
	temp.InvNTT()

	mismatch := 0
	for i := 0; i < N; i++ {
		if (int64(orig[i])%Q+Q)%Q != (int64(temp[i])%Q+Q)%Q {
			mismatch++
			if mismatch <= 5 {
				t.Errorf("NTT→InvNTT roundtrip fail at %d: orig=%d back=%d",
					i, orig[i], temp[i])
			}
		}
	}
	if mismatch > 0 {
		t.Errorf("NTT→InvNTT roundtrip: %d/%d mismatch", mismatch, N)
	} else {
		t.Log("NTT→InvNTT roundtrip OK")
	}
}

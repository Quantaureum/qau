// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"io"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func TestMode3ChallengeSamplerVector(t *testing.T) {
	var seed [CTildeSize]byte
	for index := range seed {
		seed[index] = byte(index)
	}
	challenge, err := DeriveMode3Challenge(seed)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[int]Coefficient{
		3: Q - 1, 7: 1, 9: 1, 19: Q - 1, 30: Q - 1,
		36: 1, 44: Q - 1, 53: Q - 1, 57: Q - 1, 61: Q - 1,
		66: 1, 69: 1, 77: Q - 1, 78: 1, 90: 1,
		91: 1, 99: 1, 112: Q - 1, 113: 1, 114: 1,
		115: 1, 122: 1, 136: 1, 145: 1, 152: 1,
		154: Q - 1, 155: 1, 156: 1, 167: Q - 1, 178: 1,
		179: 1, 188: 1, 196: 1, 201: 1, 202: 1,
		204: 1, 205: Q - 1, 209: Q - 1, 210: Q - 1, 211: Q - 1,
		212: 1, 218: 1, 224: Q - 1, 225: 1, 230: Q - 1,
		233: Q - 1, 234: Q - 1, 239: Q - 1, 243: Q - 1,
	}
	if len(expected) != Tau {
		t.Fatalf("vector has %d entries, want %d", len(expected), Tau)
	}
	for index, coefficient := range challenge {
		if coefficient != expected[index] {
			t.Fatalf("challenge[%d] = %d, want %d", index, coefficient, expected[index])
		}
	}
}

func TestMode3ChallengeRecomputesNativeSignature(t *testing.T) {
	var seed [mode3.SeedSize]byte
	for index := range seed {
		seed[index] = byte(index + 7)
	}
	message := []byte("DEVNET ONLY mode3 challenge signing interoperability")
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(privateKey, message, signature)
	parts, err := ParseMode3Signature(signature)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBytes := publicKey.Bytes()
	var rho [32]byte
	copy(rho[:], publicKeyBytes[:32])
	t1 := testUnpackMode3PublicT1(t, publicKeyBytes)
	var normalizedZ VectorL
	for polynomialIndex, polynomial := range parts.Z {
		for coefficientIndex, coefficient := range polynomial {
			normalizedZ[polynomialIndex][coefficientIndex] = Normalize(coefficient)
		}
	}
	az, err := ComputePublicVector(rho, normalizedZ, VectorK{})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := DeriveMode3Challenge(parts.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	var packedW1 [K * HighBitsEncodedSize]byte
	for polynomialIndex, polynomial := range az {
		t1Scaled := ScalarMul(t1[polynomialIndex], 1<<D)
		verificationInput := Sub(polynomial, MultiplyPolynomials(challenge, t1Scaled))
		w1, err := UseHint(verificationInput, parts.Hints[polynomialIndex])
		if err != nil {
			t.Fatal(err)
		}
		var highBits HighBitsPoly
		for coefficientIndex, coefficient := range w1 {
			highBits[coefficientIndex] = uint8(coefficient)
		}
		encoded, err := EncodeHighBits(highBits)
		if err != nil {
			t.Fatal(err)
		}
		copy(packedW1[polynomialIndex*HighBitsEncodedSize:], encoded[:])
	}
	var tr [TRSize]byte
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write(publicKeyBytes)
	if _, err := io.ReadFull(shake, tr[:]); err != nil {
		t.Fatal(err)
	}
	shake.Reset()
	_, _ = shake.Write(tr[:])
	_, _ = shake.Write(message)
	var mu [64]byte
	if _, err := io.ReadFull(shake, mu[:]); err != nil {
		t.Fatal(err)
	}
	shake.Reset()
	_, _ = shake.Write(mu[:])
	_, _ = shake.Write(packedW1[:])
	var recomputed [CTildeSize]byte
	if _, err := io.ReadFull(shake, recomputed[:]); err != nil {
		t.Fatal(err)
	}
	if recomputed != parts.Challenge {
		t.Fatal("mode3 verification equation yielded another challenge")
	}
}

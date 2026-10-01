// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"testing"

	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestLocalShareIdentityAndCommitment(t *testing.T) {
	key, committee := testShareIdentity(t)
	material := ShareMaterial{}
	material.S1[0][0] = 17
	material.S2[1][2] = 29
	material.T0[5][255] = 41

	share, err := NewLocalShare(key, committee, 3, material)
	if err != nil {
		t.Fatalf("NewLocalShare(): %v", err)
	}
	if err := share.ValidateIdentity(key, committee, 3); err != nil {
		t.Fatalf("ValidateIdentity(): %v", err)
	}
	commitment := share.Commitment()
	if err := share.VerifyCommitment(commitment); err != nil {
		t.Fatalf("VerifyCommitment(): %v", err)
	}

	commitment[0] ^= 1
	if err := share.VerifyCommitment(commitment); !errors.Is(err, ErrShareCommitmentMismatch) {
		t.Fatalf("VerifyCommitment() error = %v, want %v", err, ErrShareCommitmentMismatch)
	}

	wrongKey := key.Clone()
	wrongKey.Generation++
	if err := share.ValidateIdentity(wrongKey, committee, 3); !errors.Is(err, ErrShareIdentityMismatch) {
		t.Fatalf("generation mismatch error = %v, want %v", err, ErrShareIdentityMismatch)
	}

	wrongCommittee := committee.Clone()
	wrongCommittee.Version++
	if err := share.ValidateIdentity(key, wrongCommittee, 3); !errors.Is(err, ErrShareIdentityMismatch) {
		t.Fatalf("committee mismatch error = %v, want %v", err, ErrShareIdentityMismatch)
	}

	if _, err := NewLocalShare(key, committee, 9, material); !errors.Is(err, ErrInvalidLocalShare) {
		t.Fatalf("non-member error = %v, want %v", err, ErrInvalidLocalShare)
	}
}

func TestLocalShareZeroize(t *testing.T) {
	key, committee := testShareIdentity(t)
	material := ShareMaterial{}
	for index := 0; index < Degree; index++ {
		material.S1[0][index] = int32(index + 1)
	}
	share, err := NewLocalShare(key, committee, 1, material)
	if err != nil {
		t.Fatalf("NewLocalShare(): %v", err)
	}
	share.Zeroize()
	if !share.IsZeroized() {
		t.Fatal("share did not report zeroized state")
	}
	if err := share.VerifyCommitment(share.Commitment()); !errors.Is(err, ErrLocalShareZeroized) {
		t.Fatalf("zeroized share error = %v, want %v", err, ErrLocalShareZeroized)
	}
}

func TestLocalShareIdentityReturnsClonedPublicMetadata(t *testing.T) {
	key, committee := testShareIdentity(t)
	share, err := NewLocalShare(key, committee, 2, ShareMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	gotKey, gotCommittee, participantID, err := share.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if participantID != 2 || gotKey.Generation != key.Generation || gotCommittee.Version != committee.Version {
		t.Fatal("share identity mismatch")
	}
	gotKey.PublicKey[0] ^= 1
	gotCommittee.Participants[0]++
	if err := share.ValidateIdentity(key, committee, 2); err != nil {
		t.Fatal("identity result aliases share metadata")
	}
}

func TestFourSharesReconstructAndThreeRemainUnderdetermined(t *testing.T) {
	secret := int32(1234)
	base := func(x int32) int32 {
		return NormalizeCoefficient(int64(secret) + 2*int64(x) + 3*int64(x*x) + 4*int64(x*x*x))
	}
	alternative := func(x int32) int32 {
		delta := int64(x-1) * int64(x-2) * int64(x-3)
		return NormalizeCoefficient(int64(base(x)) + 9*delta)
	}

	for participant := int32(1); participant <= 3; participant++ {
		if base(participant) != alternative(participant) {
			t.Fatalf("alternative polynomial changed share %d", participant)
		}
	}
	if base(0) == alternative(0) {
		t.Fatal("three shares unexpectedly fixed the secret")
	}

	points := map[int32]int32{1: base(1), 2: base(2), 3: base(3), 4: base(4)}
	if got := interpolateAtZeroForTest(t, points); got != secret {
		t.Fatalf("four-share reconstruction = %d, want %d", got, secret)
	}
}

func TestLocalShareEncodingRoundTripAndTamperRejection(t *testing.T) {
	key, committee := testShareIdentity(t)
	material := evaluateTestShareMaterial(ShareMaterial{}, 23)
	share, err := NewLocalShare(key, committee, 3, material)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := share.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(): %v", err)
	}
	restored, err := UnmarshalLocalShare(encoded)
	if err != nil {
		t.Fatalf("UnmarshalLocalShare(): %v", err)
	}
	if restored.Commitment() != share.Commitment() {
		t.Fatal("restored local share commitment mismatch")
	}
	if err := restored.ValidateIdentity(key, committee, 3); err != nil {
		t.Fatalf("restored identity: %v", err)
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-33] ^= 0x01
	if _, err := UnmarshalLocalShare(tampered); err == nil {
		t.Fatal("tampered local share must fail")
	}

	share.Zeroize()
	if _, err := share.MarshalBinary(); !errors.Is(err, ErrLocalShareZeroized) {
		t.Fatalf("zeroized marshal error = %v, want %v", err, ErrLocalShareZeroized)
	}
}

func testShareIdentity(t *testing.T) (protocol.ThresholdKeyID, protocol.CommitteeID) {
	t.Helper()
	var seed [circlmldsa65.SeedSize]byte
	seed[0] = 7
	publicKey, _ := circlmldsa65.NewKeyFromSeed(&seed)
	return protocol.ThresholdKeyID{
			Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
			Generation: 11,
			PublicKey:  publicKey.Bytes(),
		}, protocol.CommitteeID{
			Version:      5,
			Threshold:    4,
			Participants: []uint32{1, 2, 3, 4, 5, 6},
		}
}

func interpolateAtZeroForTest(t *testing.T, points map[int32]int32) int32 {
	t.Helper()
	var result int64
	for x, y := range points {
		numerator := int64(1)
		denominator := int64(1)
		for otherX := range points {
			if otherX == x {
				continue
			}
			numerator = modForTest(numerator * -int64(otherX))
			denominator = modForTest(denominator * int64(x-otherX))
		}
		inverse := inverseForTest(t, denominator)
		result = modForTest(result + int64(y)*numerator%Modulus*inverse)
	}
	return int32(result)
}

func inverseForTest(t *testing.T, value int64) int64 {
	t.Helper()
	base := modForTest(value)
	exponent := int64(Modulus - 2)
	result := int64(1)
	for exponent > 0 {
		if exponent&1 == 1 {
			result = result * base % Modulus
		}
		base = base * base % Modulus
		exponent >>= 1
	}
	if result == 0 {
		t.Fatal("non-invertible denominator")
	}
	return result
}

func modForTest(value int64) int64 {
	value %= Modulus
	if value < 0 {
		value += Modulus
	}
	return value
}

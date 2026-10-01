// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func TestPublicContributionMatchesCIRCLMode3KeyGeneration(t *testing.T) {
	var seed [mode3.SeedSize]byte
	for index := range seed {
		seed[index] = byte(0x40 + index)
	}
	publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
	rho, s1, s2 := testUnpackMode3PrivateKey(t, privateKey.Bytes())
	got, err := ComputePublicVector(rho, s1, s2)
	if err != nil {
		t.Fatal(err)
	}
	wantT1 := testUnpackMode3PublicT1(t, publicKey.Bytes())
	for index := range got {
		high, _ := Power2Round(got[index])
		if high != wantT1[index] {
			t.Fatalf("public vector %d does not match CIRCL t1", index)
		}
	}
}

func TestPublicContributionEncodingAndDigest(t *testing.T) {
	sessionDigest := [32]byte{1, 2, 3}
	group := RSSGroupMask(0b001011)
	dealer := uint8(1)
	var rho [32]byte
	rho[0] = 9
	s1, s2, err := DeriveRSSComponent(sessionDigest, group, dealer, [64]byte{7}, [32]byte{8})
	if err != nil {
		t.Fatal(err)
	}
	contribution, err := NewPublicContribution(sessionDigest, group, dealer, rho, s1, s2)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contribution.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest == ([32]byte{}) {
		t.Fatal("zero contribution digest")
	}
	encoded, err := contribution.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalPublicContribution(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if restored != contribution {
		t.Fatal("public contribution round trip mismatch")
	}
	restoredDigest, err := restored.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if restoredDigest != digest {
		t.Fatal("public contribution digest changed after round trip")
	}
	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-33] ^= 1
	if _, err := UnmarshalPublicContribution(tampered); !errors.Is(err, ErrPublicContributionDigestMismatch) {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestPublicContributionRejectsInvalidState(t *testing.T) {
	valid := PublicContribution{
		SessionDigest:  [32]byte{1},
		GroupMask:      RSSGroupMask(0b001011),
		DealerPosition: 1,
	}
	tests := []struct {
		name   string
		mutate func(*PublicContribution)
	}{
		{name: "zero session", mutate: func(contribution *PublicContribution) { contribution.SessionDigest = [32]byte{} }},
		{name: "invalid group", mutate: func(contribution *PublicContribution) { contribution.GroupMask = 3 }},
		{name: "dealer outside group", mutate: func(contribution *PublicContribution) { contribution.DealerPosition = 5 }},
		{name: "non-canonical t", mutate: func(contribution *PublicContribution) { contribution.T[0][0] = Q }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contribution := valid
			test.mutate(&contribution)
			if !errors.Is(contribution.Validate(), ErrInvalidPublicContribution) {
				t.Fatalf("invalid contribution error = %v", contribution.Validate())
			}
		})
	}
}

func TestVerifyPublicContributionForComponent(t *testing.T) {
	sessionDigest := [32]byte{4, 5, 6}
	group := RSSGroupMask(0b001011)
	dealer := uint8(1)
	var rho [32]byte
	rho[0] = 11
	s1, s2, err := DeriveRSSComponent(sessionDigest, group, dealer, [64]byte{7}, [32]byte{8})
	if err != nil {
		t.Fatal(err)
	}
	published, err := NewPublicContribution(sessionDigest, group, dealer, rho, s1, s2)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicContributionForComponent(published, sessionDigest, group, dealer, rho, s1, s2); err != nil {
		t.Fatalf("locally derived contribution rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PublicContribution)
		want   error
	}{
		{name: "altered coefficient", mutate: func(contribution *PublicContribution) {
			contribution.T[0][0] = Normalize(contribution.T[0][0] + 2)
		}, want: ErrPublicContributionDigestMismatch},
		{name: "altered last coefficient", mutate: func(contribution *PublicContribution) {
			contribution.T[K-1][N-1] = Normalize(contribution.T[K-1][N-1] + 1)
		}, want: ErrPublicContributionDigestMismatch},
		{name: "foreign session", mutate: func(contribution *PublicContribution) {
			contribution.SessionDigest = [32]byte{9}
		}, want: ErrPublicContributionDigestMismatch},
		{name: "foreign group", mutate: func(contribution *PublicContribution) {
			contribution.GroupMask = RSSGroupMask(0b000111)
		}, want: ErrPublicContributionDigestMismatch},
		{name: "foreign dealer", mutate: func(contribution *PublicContribution) {
			contribution.DealerPosition = 0
		}, want: ErrPublicContributionDigestMismatch},
		{name: "non-canonical", mutate: func(contribution *PublicContribution) {
			contribution.T[0][0] = Q
		}, want: ErrInvalidPublicContribution},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contribution := published
			test.mutate(&contribution)
			if err := VerifyPublicContributionForComponent(contribution, sessionDigest, group, dealer, rho, s1, s2); !errors.Is(err, test.want) {
				t.Fatalf("verification error = %v, want %v", err, test.want)
			}
		})
	}

	var otherRho [32]byte
	otherRho[0] = 12
	if err := VerifyPublicContributionForComponent(published, sessionDigest, group, dealer, otherRho, s1, s2); !errors.Is(err, ErrPublicContributionDigestMismatch) {
		t.Fatalf("foreign matrix seed error = %v", err)
	}
}

func testUnpackMode3PrivateKey(t *testing.T, encoded []byte) (rho [32]byte, s1 VectorL, s2 VectorK) {
	t.Helper()
	if len(encoded) != mode3.PrivateKeySize {
		t.Fatalf("private key size = %d", len(encoded))
	}
	copy(rho[:], encoded[:32])
	offset := 64 + TRSize
	decodePolynomial := func(polynomial *Poly) {
		for byteIndex := 0; byteIndex < N/2; byteIndex++ {
			value := encoded[offset+byteIndex]
			polynomial[2*byteIndex] = Normalize(Coefficient(Eta - int(value&0x0f)))
			polynomial[2*byteIndex+1] = Normalize(Coefficient(Eta - int(value>>4)))
		}
		offset += N / 2
	}
	for index := range s1 {
		decodePolynomial(&s1[index])
	}
	for index := range s2 {
		decodePolynomial(&s2[index])
	}
	return rho, s1, s2
}

func testUnpackMode3PublicT1(t *testing.T, encoded []byte) VectorK {
	t.Helper()
	if len(encoded) != mode3.PublicKeySize {
		t.Fatalf("public key size = %d", len(encoded))
	}
	var vector VectorK
	offset := 32
	for polynomialIndex := range vector {
		polynomial := &vector[polynomialIndex]
		for coefficientIndex := 0; coefficientIndex < N; coefficientIndex += 4 {
			first := uint32(encoded[offset])
			second := uint32(encoded[offset+1])
			third := uint32(encoded[offset+2])
			fourth := uint32(encoded[offset+3])
			fifth := uint32(encoded[offset+4])
			polynomial[coefficientIndex] = Coefficient((first | second<<8) & 0x3ff)
			polynomial[coefficientIndex+1] = Coefficient((second>>2 | third<<6) & 0x3ff)
			polynomial[coefficientIndex+2] = Coefficient((third>>4 | fourth<<4) & 0x3ff)
			polynomial[coefficientIndex+3] = Coefficient((fourth>>6 | fifth<<2) & 0x3ff)
			offset += 5
		}
	}
	return vector
}

// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

type mode3PublicKeyFixture struct {
	Rho                     string `json:"rho"`
	SessionDigest           string `json:"session_digest"`
	ContributionsGzipBase64 string `json:"contributions_gzip_base64"`
	ExpectedPublicKey       string `json:"expected_public_key"`
}

func TestAssembleMode3PublicKeyRequiresCanonicalTwentyContributions(t *testing.T) {
	rho := [32]byte{1, 2, 3}
	contributions := testPublicKeyContributions()
	publicKey, transcriptDigest, err := AssembleMode3PublicKey(rho, contributions)
	if err != nil {
		t.Fatal(err)
	}
	if publicKey == ([1952]byte{}) || transcriptDigest == ([32]byte{}) {
		t.Fatal("assembly returned zero public material")
	}

	reversed := contributions
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	reorderedKey, reorderedTranscript, err := AssembleMode3PublicKey(rho, reversed)
	if err != nil {
		t.Fatal(err)
	}
	if reorderedKey != publicKey || reorderedTranscript != transcriptDigest {
		t.Fatal("input ordering changed canonical assembly")
	}
	changedDealer := contributions
	changedDealer[0].DealerPosition, _ = changedDealer[0].GroupMask.Leader(1)
	dealerKey, dealerTranscript, err := AssembleMode3PublicKey(rho, changedDealer)
	if err != nil {
		t.Fatal(err)
	}
	if dealerKey != publicKey || dealerTranscript == transcriptDigest {
		t.Fatal("dealer identity was not isolated to the transcript")
	}

	tests := []struct {
		name   string
		mutate func(*[20]PublicContribution)
	}{
		{name: "missing", mutate: func(values *[20]PublicContribution) { values[4] = PublicContribution{} }},
		{name: "duplicate", mutate: func(values *[20]PublicContribution) { values[4] = values[3] }},
		{name: "foreign session", mutate: func(values *[20]PublicContribution) { values[4].SessionDigest[0] ^= 1 }},
		{name: "wrong group", mutate: func(values *[20]PublicContribution) { values[4].GroupMask = RSSGroupMask(3) }},
		{name: "malformed contribution", mutate: func(values *[20]PublicContribution) { values[4].T[0][0] = Q }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := contributions
			test.mutate(&mutated)
			if _, _, err := AssembleMode3PublicKey(rho, mutated); !errors.Is(err, ErrInvalidPublicKeyAssembly) {
				t.Fatalf("invalid assembly error = %v", err)
			}
		})
	}
}

func TestAssembleMode3PublicKeyMatchesOfflineCIRCLVector(t *testing.T) {
	fixture := loadMode3PublicKeyFixture(t)
	rho := decodeFixtureArray32(t, fixture.Rho)
	expectedPublicKeyBytes, err := hex.DecodeString(fixture.ExpectedPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(expectedPublicKeyBytes) != 1952 {
		t.Fatalf("public key length = %d", len(expectedPublicKeyBytes))
	}
	var expectedPublicKey [1952]byte
	copy(expectedPublicKey[:], expectedPublicKeyBytes)
	contributions := decodeFixtureContributions(t, fixture.ContributionsGzipBase64)
	expectedSessionDigest := decodeFixtureArray32(t, fixture.SessionDigest)
	for index, contribution := range contributions {
		if contribution.SessionDigest != expectedSessionDigest {
			t.Fatalf("contribution %d has foreign fixture session", index)
		}
	}
	publicKey, transcriptDigest, err := AssembleMode3PublicKey(rho, contributions)
	if err != nil {
		t.Fatal(err)
	}
	if publicKey != expectedPublicKey {
		t.Fatal("assembled public key differs from offline CIRCL vector")
	}
	if transcriptDigest == ([32]byte{}) {
		t.Fatal("zero public-key transcript digest")
	}
}

func testPublicKeyContributions() [20]PublicContribution {
	groups := CanonicalRSSGroups()
	var contributions [20]PublicContribution
	for index, group := range groups {
		leader, _ := group.Leader(0)
		contributions[index] = PublicContribution{
			SessionDigest:  [32]byte{7, 8, 9},
			GroupMask:      group,
			DealerPosition: leader,
		}
		contributions[index].T[index%K][index%N] = Coefficient(index + 1)
	}
	return contributions
}

func loadMode3PublicKeyFixture(t *testing.T) mode3PublicKeyFixture {
	t.Helper()
	encoded, err := os.ReadFile("testdata/mode3_public_key_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture mode3PublicKeyFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func decodeFixtureContributions(t *testing.T, encoded string) [20]PublicContribution {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if len(decoded)%20 != 0 {
		t.Fatalf("contribution fixture length %d is not divisible by 20", len(decoded))
	}
	entrySize := len(decoded) / 20
	var contributions [20]PublicContribution
	for index := range contributions {
		contribution, err := UnmarshalPublicContribution(decoded[index*entrySize : (index+1)*entrySize])
		if err != nil {
			t.Fatalf("contribution %d: %v", index, err)
		}
		contributions[index] = contribution
	}
	return contributions
}

func decodeFixtureArray32(t *testing.T, encoded string) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded length = %d, want 32", len(decoded))
	}
	var result [32]byte
	copy(result[:], decoded)
	return result
}

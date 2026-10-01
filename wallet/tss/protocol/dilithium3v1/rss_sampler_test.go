// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type rssSamplingVector struct {
	SessionDigest    string `json:"session_digest"`
	GroupMask        uint8  `json:"group_mask"`
	LeaderPosition   uint8  `json:"leader_position"`
	GlobalRandomness string `json:"global_randomness"`
	GroupSeed        string `json:"group_seed"`
	ComponentDigest  string `json:"component_digest"`
}

func TestRSSComponentSamplingVector(t *testing.T) {
	vector := loadRSSSamplingVector(t)
	sessionDigest := decodeRSSVector32(t, vector.SessionDigest)
	globalRandomness := decodeRSSVector64(t, vector.GlobalRandomness)
	groupSeed := decodeRSSVector32(t, vector.GroupSeed)
	s1, s2, err := DeriveRSSComponent(sessionDigest, RSSGroupMask(vector.GroupMask), vector.LeaderPosition, globalRandomness, groupSeed)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := appendVectorL(nil, s1)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = appendVectorK(encoded, s2)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha3.Sum256(encoded)
	if got := hex.EncodeToString(digest[:]); got != vector.ComponentDigest {
		t.Fatalf("component digest = %s, want %s", got, vector.ComponentDigest)
	}
	assertRSSVectorBounds(t, s1, s2)
}

func TestRSSComponentSamplingSeparatesEveryInput(t *testing.T) {
	vector := loadRSSSamplingVector(t)
	sessionDigest := decodeRSSVector32(t, vector.SessionDigest)
	globalRandomness := decodeRSSVector64(t, vector.GlobalRandomness)
	groupSeed := decodeRSSVector32(t, vector.GroupSeed)
	group := RSSGroupMask(vector.GroupMask)
	baselineS1, baselineS2, err := DeriveRSSComponent(sessionDigest, group, vector.LeaderPosition, globalRandomness, groupSeed)
	if err != nil {
		t.Fatal(err)
	}
	assertChanged := func(name string, mutatedS1 VectorL, mutatedS2 VectorK, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s mutation: %v", name, err)
		}
		if mutatedS1 == baselineS1 && mutatedS2 == baselineS2 {
			t.Fatalf("%s was not domain-separated", name)
		}
	}
	mutatedSession := sessionDigest
	mutatedSession[0] ^= 1
	s1, s2, err := DeriveRSSComponent(mutatedSession, group, vector.LeaderPosition, globalRandomness, groupSeed)
	assertChanged("session digest", s1, s2, err)
	s1, s2, err = DeriveRSSComponent(sessionDigest, RSSGroupMask(0b001101), vector.LeaderPosition, globalRandomness, groupSeed)
	assertChanged("group mask", s1, s2, err)
	s1, s2, err = DeriveRSSComponent(sessionDigest, group, 1, globalRandomness, groupSeed)
	assertChanged("leader position", s1, s2, err)
	mutatedRandomness := globalRandomness
	mutatedRandomness[0] ^= 1
	s1, s2, err = DeriveRSSComponent(sessionDigest, group, vector.LeaderPosition, mutatedRandomness, groupSeed)
	assertChanged("global randomness", s1, s2, err)
	mutatedSeed := groupSeed
	mutatedSeed[0] ^= 1
	s1, s2, err = DeriveRSSComponent(sessionDigest, group, vector.LeaderPosition, globalRandomness, mutatedSeed)
	assertChanged("group seed", s1, s2, err)
}

func TestRSSComponentSamplingRejectsInvalidInputs(t *testing.T) {
	vector := loadRSSSamplingVector(t)
	sessionDigest := decodeRSSVector32(t, vector.SessionDigest)
	globalRandomness := decodeRSSVector64(t, vector.GlobalRandomness)
	groupSeed := decodeRSSVector32(t, vector.GroupSeed)
	group := RSSGroupMask(vector.GroupMask)
	tests := []struct {
		name       string
		session    [32]byte
		group      RSSGroupMask
		leader     uint8
		randomness [64]byte
		seed       [32]byte
	}{
		{name: "zero session", group: group, leader: vector.LeaderPosition, randomness: globalRandomness, seed: groupSeed},
		{name: "invalid group", session: sessionDigest, group: RSSGroupMask(3), leader: vector.LeaderPosition, randomness: globalRandomness, seed: groupSeed},
		{name: "leader outside group", session: sessionDigest, group: group, leader: 5, randomness: globalRandomness, seed: groupSeed},
		{name: "zero randomness", session: sessionDigest, group: group, leader: vector.LeaderPosition, seed: groupSeed},
		{name: "zero seed", session: sessionDigest, group: group, leader: vector.LeaderPosition, randomness: globalRandomness},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := DeriveRSSComponent(test.session, test.group, test.leader, test.randomness, test.seed); !errors.Is(err, ErrInvalidRSSComponentSampling) {
				t.Fatalf("invalid input error = %v", err)
			}
		})
	}
}

func loadRSSSamplingVector(t *testing.T) rssSamplingVector {
	t.Helper()
	encoded, err := os.ReadFile("testdata/rss_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector rssSamplingVector
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func decodeRSSVector32(t *testing.T, value string) [32]byte {
	t.Helper()
	var result [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(result) {
		t.Fatalf("decoded length = %d, want %d", len(decoded), len(result))
	}
	copy(result[:], decoded)
	return result
}

func decodeRSSVector64(t *testing.T, value string) [64]byte {
	t.Helper()
	var result [64]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(result) {
		t.Fatalf("decoded length = %d, want %d", len(decoded), len(result))
	}
	copy(result[:], decoded)
	return result
}

func assertRSSVectorBounds(t *testing.T, s1 VectorL, s2 VectorK) {
	t.Helper()
	check := func(name string, polynomialIndex int, polynomial Poly) {
		for coefficientIndex, coefficient := range polynomial {
			if coefficient > RSSComponentEta && coefficient < Q-RSSComponentEta {
				t.Fatalf("%s[%d][%d] = %d exceeds centered component bound", name, polynomialIndex, coefficientIndex, coefficient)
			}
		}
	}
	for index, polynomial := range s1 {
		check("s1", index, polynomial)
	}
	for index, polynomial := range s2 {
		check("s2", index, polynomial)
	}
}

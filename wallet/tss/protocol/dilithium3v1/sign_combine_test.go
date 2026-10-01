// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"fmt"
	"io"
	"math/bits"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestMode3FourHolderPublicResponseCombination(t *testing.T) {
	shares, key, rho := testMode3RSSShares(t)
	for mask := uint8(0); mask < 64; mask++ {
		if bits.OnesCount8(mask) != 4 {
			continue
		}
		t.Run(fmt.Sprintf("mask-%06b", mask), func(t *testing.T) {
			testMode3PublicResponseCombinationForMask(t, shares, key, rho, mask)
		})
	}
}

func testMode3PublicResponseCombinationForMask(t *testing.T, shares [6]*LocalShare, key protocol.ThresholdKeyID, rho [32]byte, activeMask uint8) {
	message := []byte("DEVNET ONLY distributed response correctness, not a secure signing protocol")
	allocation, err := AllocateRSSGroups(activeMask)
	if err != nil {
		t.Fatal(err)
	}
	groups := CanonicalRSSGroups()
	for attempt := 0; attempt < 48; attempt++ {
		var commitments [6]VectorK
		var randomness [6]VectorL
		var aggregateCommitment VectorK
		for position := range randomness {
			if activeMask&(1<<position) == 0 {
				continue
			}
			shake := sha3.NewSHAKE256()
			_, _ = shake.Write([]byte("DEVNET ONLY algebra-only nonce"))
			_, _ = shake.Write([]byte{byte(attempt), byte(position)})
			var byteValue [1]byte
			for polynomialIndex := range randomness[position] {
				for coefficientIndex := range randomness[position][polynomialIndex] {
					if _, err := io.ReadFull(shake, byteValue[:]); err != nil {
						t.Fatal(err)
					}
					randomness[position][polynomialIndex][coefficientIndex] = Normalize(Coefficient(int(byteValue[0]) - 128))
				}
			}
			commitments[position], err = ComputePublicVector(rho, randomness[position], VectorK{})
			if err != nil {
				t.Fatal(err)
			}
			for polynomialIndex := range aggregateCommitment {
				aggregateCommitment[polynomialIndex] = Add(aggregateCommitment[polynomialIndex], commitments[position][polynomialIndex])
			}
		}
		challenge, err := mode3CommitmentChallenge(key, message, aggregateCommitment)
		if err != nil {
			t.Fatal(err)
		}
		challengePolynomial, err := DeriveMode3Challenge(challenge)
		if err != nil {
			t.Fatal(err)
		}
		var aggregateResponses VectorL
		for position := range randomness {
			if activeMask&(1<<position) == 0 {
				continue
			}
			share := shares[position]
			var assignedS1 VectorL
			assignedCount := 0
			for _, component := range share.Components {
				for groupIndex, group := range groups {
					if group != component.GroupMask || allocation[groupIndex] != uint8(position) {
						continue
					}
					assignedCount++
					for polynomialIndex := range assignedS1 {
						assignedS1[polynomialIndex] = Add(assignedS1[polynomialIndex], component.S1[polynomialIndex])
					}
				}
			}
			if assignedCount != 5 {
				t.Fatalf("signer %d has %d components", position, assignedCount)
			}
			for polynomialIndex := range aggregateResponses {
				partial := Add(randomness[position][polynomialIndex], MultiplyPolynomials(challengePolynomial, assignedS1[polynomialIndex]))
				aggregateResponses[polynomialIndex] = Add(aggregateResponses[polynomialIndex], partial)
			}
		}
		var centered [L]SignedPoly
		for polynomialIndex, polynomial := range aggregateResponses {
			for coefficientIndex, coefficient := range polynomial {
				centeredValue := int32(coefficient)
				if centeredValue > Q/2 {
					centeredValue -= Q
				}
				centered[polynomialIndex][coefficientIndex] = Coefficient(centeredValue)
			}
		}
		signature, err := combineMode3PublicResponses(key, message, challenge, aggregateCommitment, centered)
		if err != nil {
			continue
		}
		if len(signature) != key.Algorithm.SignatureSize() {
			t.Fatalf("signature size = %d", len(signature))
		}
		if err := qcrypto.VerifySignatureForAlgorithm(key.Algorithm, key.PublicKey, message, nil, signature); err != nil {
			t.Fatal(err)
		}
		if _, err := combineMode3PublicResponses(key, append(append([]byte(nil), message...), 0), challenge, aggregateCommitment, centered); err == nil {
			t.FailNow()
		}
		changed := aggregateCommitment
		changed[0][0] = Normalize(changed[0][0] + 2*Gamma2)
		if _, err := combineMode3PublicResponses(key, message, challenge, changed, centered); err == nil {
			t.Fatal("modified public commitment accepted")
		}
		centered[0][0] = Gamma1 - Beta
		if _, err := combineMode3PublicResponses(key, message, challenge, aggregateCommitment, centered); err == nil {
			t.Fatal("out-of-bound response accepted")
		}
		changed = aggregateCommitment
		changed[0][0] = Q
		if _, err := mode3CommitmentChallenge(key, message, changed); err == nil {
			t.FailNow()
		}
		return
	}
	t.Fatal("no algebraic response combination produced a native mode3 signature")
}

func testMode3RSSShares(t *testing.T) ([6]*LocalShare, protocol.ThresholdKeyID, [32]byte) {
	t.Helper()
	sessionDigest := [32]byte{1}
	rho := [32]byte{2}
	groups := CanonicalRSSGroups()
	var components [20]RSSComponent
	var contributions [20]PublicContribution
	for groupIndex, group := range groups {
		leader, err := group.Leader(0)
		if err != nil {
			t.Fatal(err)
		}
		s1, s2, err := DeriveRSSComponent(sessionDigest, group, leader, [64]byte{3}, [32]byte{byte(groupIndex + 1)})
		if err != nil {
			t.Fatal(err)
		}
		contribution, err := NewPublicContribution(sessionDigest, group, leader, rho, s1, s2)
		if err != nil {
			t.Fatal(err)
		}
		contributions[groupIndex] = contribution
		digest, err := contribution.Digest()
		if err != nil {
			t.Fatal(err)
		}
		components[groupIndex] = RSSComponent{GroupMask: group, DealerPosition: leader, ContributionDigest: digest, S1: s1, S2: s2}
	}
	publicKey, transcriptDigest, err := AssembleMode3PublicKey(rho, contributions)
	if err != nil {
		t.Fatal(err)
	}
	key := protocol.ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: 1, PublicKey: publicKey[:]}
	committee := protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}}
	var shares [6]*LocalShare
	for position := range shares {
		share := &LocalShare{Protocol: protocol.ThresholdProtocolDilithium3V1, Key: key.Clone(), Committee: committee.Clone(), ParticipantID: uint32(position + 1), ParticipantPosition: uint8(position), ActivationEpoch: 1, TranscriptDigest: transcriptDigest, Rho: rho}
		owned, err := GroupsForPosition(uint8(position))
		if err != nil {
			t.Fatal(err)
		}
		for componentIndex, group := range owned {
			for groupIndex, candidate := range groups {
				if candidate == group {
					share.Components[componentIndex] = components[groupIndex]
					break
				}
			}
		}
		if err := share.Validate(); err != nil {
			t.Fatal(fmt.Errorf("share %d: %w", position, err))
		}
		shares[position] = share
	}
	return shares, key, rho
}

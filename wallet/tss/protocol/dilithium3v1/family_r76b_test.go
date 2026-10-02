// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// R76b positive coverage: the signing MPC accepts the second pinned committee
// row (C = 7, t = 5) end to end, on shares of the generalized RSS family, and
// the reference driver and the in-process executor agree byte for byte on it
// exactly as they do on the C = 6 row.

import (
	"bytes"
	"math/rand"
	"path/filepath"
	"strconv"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// signingTestSharesFor builds the synthetic CNF-RSS shares of one pinned
// committee size, exactly the way testMode3RSSShares builds the C=6 fixture.
func signingTestSharesFor(t *testing.T, participants, threshold int) ([]*LocalShare, protocol.ThresholdKeyID) {
	t.Helper()
	sessionDigest := [32]byte{1}
	rho := [32]byte{2}
	groups, err := CanonicalRSSGroupsFor(participants)
	if err != nil {
		t.Fatal(err)
	}
	components := make([]RSSComponent, len(groups))
	contributions := make([]PublicContribution, len(groups))
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
		components[groupIndex] = RSSComponent{GroupMask: group, DealerPosition: leader, ContributionDigest: digest, Multiplicity: 1, S1: s1, S2: s2}
	}
	publicKey, transcriptDigest, err := AssembleMode3PublicKey(rho, contributions, participants)
	if err != nil {
		t.Fatal(err)
	}
	key := protocol.ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: 1, PublicKey: publicKey[:]}
	participantIDs := make([]uint32, participants)
	for index := range participantIDs {
		participantIDs[index] = uint32(index + 1)
	}
	committee := protocol.CommitteeID{Version: 1, Threshold: uint32(threshold), Participants: participantIDs}
	shares := make([]*LocalShare, participants)
	for position := range shares {
		share := &LocalShare{
			Protocol: protocol.ThresholdProtocolDilithium3V1, Key: key.Clone(), Committee: committee.Clone(),
			ParticipantID: uint32(position + 1), ParticipantPosition: uint8(position),
			ActivationEpoch: 1, TranscriptDigest: transcriptDigest, Rho: rho,
		}
		owned, err := GroupsForPositionN(uint8(position), participants)
		if err != nil {
			t.Fatal(err)
		}
		share.Components = make([]RSSComponent, len(owned))
		for componentIndex, group := range owned {
			share.Components[componentIndex] = components[rssGroupIndex(groups, group)]
		}
		if err := share.Validate(); err != nil {
			t.Fatalf("share %d: %v", position, err)
		}
		shares[position] = share
	}
	return shares, key
}

// rssGroupIndex returns the position of a mask inside a canonical list.
func rssGroupIndex(groups []RSSGroupMask, want RSSGroupMask) int {
	for index, group := range groups {
		if group == want {
			return index
		}
	}
	return -1
}

// signingExecutorTestJournalsFor opens one journal per signer position.
func signingExecutorTestJournalsFor(t *testing.T, signers int, label string) []*SigningJournal {
	t.Helper()
	journals := make([]*SigningJournal, signers)
	for index := range journals {
		journals[index] = signingTestJournalAt(t, filepath.Join(t.TempDir(), label+"-"+strconv.Itoa(index)))
	}
	return journals
}

// TestSigningExecutorC7FamilyRow drives the C=7 row end to end: the pinned
// parameters accept a five-signer slot on both the reference driver and the
// in-process executor, they emit identical signatures, and the schedule pass
// stays within the row's own pinned slot budget.
func TestSigningExecutorC7FamilyRow(t *testing.T) {
	params, err := SigningParametersForParticipants(7)
	if err != nil {
		t.Fatal(err)
	}
	if params.Threshold != 5 || params.ParallelSlots != 43 {
		t.Fatalf("C=7 row = threshold %d slots %d, want 5 and 43", params.Threshold, params.ParallelSlots)
	}
	shares, key := signingTestSharesFor(t, 7, params.Threshold)
	active := append([]*LocalShare(nil), shares[:params.Threshold]...)
	request := protocol.SignRequest{
		Protocol: protocol.ThresholdProtocolDilithium3V1, Key: key.Clone(),
		Committee: active[0].Committee.Clone(), ChainID: 1669, Epoch: 1, Slot: 64,
		Domain: protocol.SigningDomainFinality, Message: []byte("R76b C=7 family row"),
		AttemptNonce: [32]byte{0xA1, 0x02, 0x03},
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("request rejected for the C=7 row: %v", err)
	}
	// Draw fresh slots until the reference accepts one; the C=7 per-slot
	// acceptance is about a half, so the pinned budget covers it many times
	// over.
	source := rand.New(rand.NewSource(0xC7))
	journal := signingTestJournal(t)
	var (
		chosenAttempt    *signingAttempt
		chosenRandomness []*signingRandomness
		chosenSlot       uint16
	)
	for slot := uint16(1); slot <= uint16(params.ParallelSlots); slot++ {
		randomness := make([]*signingRandomness, params.Threshold)
		for index := range randomness {
			point, drawErr := sampleSigningRandomness(source, params)
			if drawErr != nil {
				t.Fatalf("slot %d: sampleSigningRandomness(): %v", slot, drawErr)
			}
			randomness[index] = point
		}
		attempt, attemptErr := newSigningAttempt(
			journal, signingTestAttemptRecord(t, int(slot)), signingExecutorSlotRequest(request, slot),
			active, signingTestCoordinator, randomness,
		)
		if attemptErr != nil {
			t.Fatalf("slot %d: newSigningAttempt(): %v", slot, attemptErr)
		}
		if err := attempt.prepare(); err != nil {
			t.Fatalf("slot %d: prepare(): %v", slot, err)
		}
		if _, err := attempt.commit(); err != nil {
			t.Fatalf("slot %d: commit(): %v", slot, err)
		}
		if _, err := attempt.challenge(); err != nil {
			t.Fatalf("slot %d: challenge(): %v", slot, err)
		}
		finish := func() error {
			if _, err := attempt.respond(); err != nil {
				return err
			}
			_, err := attempt.finalize()
			return err
		}
		if err := finish(); err != nil {
			continue
		}
		chosenAttempt, chosenRandomness, chosenSlot = attempt, randomness, slot
		break
	}
	if chosenAttempt == nil {
		t.Fatal("no C=7 slot accepted within the pinned slot budget")
	}
	// The executor session agrees on the same slot, byte for byte.
	journals := signingExecutorTestJournalsFor(t, params.Threshold, "c7-session")
	session, err := newSigningExecutorSession(
		signingExecutorSlotRequest(request, chosenSlot), active, chosenSlot,
		signingExecutorTestMaterial(t, int(chosenSlot), chosenRandomness, journals),
	)
	if err != nil {
		t.Fatalf("newSigningExecutorSession(): %v", err)
	}
	if err := session.start(); err != nil {
		t.Fatalf("session start: %v", err)
	}
	run := signingExecutorTestDrive(t, session, signingExecutorTestCleanRoute(session))
	for _, deliveryErr := range run.errors {
		t.Fatalf("session delivery: %v", deliveryErr)
	}
	signature, err := session.finish()
	if err != nil {
		t.Fatalf("session finish: %v", err)
	}
	if !bytes.Equal(signature, chosenAttempt.signature) {
		t.Fatal("executor signature differs from the reference driver on the C=7 row")
	}
	if len(session.signers) != params.Threshold {
		t.Fatalf("executor ran %d signers, want %d", len(session.signers), params.Threshold)
	}
}

// TestSigningExecutorC7PartyParity drives the exported party surface on the
// C=7 row over the same slot material and requires every finishing party to
// agree on one signature (or on the shared filter outcome).
func TestSigningExecutorC7PartyParity(t *testing.T) {
	params, err := SigningParametersForParticipants(7)
	if err != nil {
		t.Fatal(err)
	}
	shares, key := signingTestSharesFor(t, 7, params.Threshold)
	active := append([]*LocalShare(nil), shares[:params.Threshold]...)
	request := protocol.SignRequest{
		Protocol: protocol.ThresholdProtocolDilithium3V1, Key: key.Clone(),
		Committee: active[0].Committee.Clone(), ChainID: 1669, Epoch: 1, Slot: 64,
		Domain: protocol.SigningDomainFinality, Message: []byte("R76b C=7 party parity"),
		AttemptNonce: [32]byte{0xA1, 0x02, 0x03},
	}
	slot := uint16(1)
	source := rand.New(rand.NewSource(0xC77))
	randomness := make([]*signingRandomness, params.Threshold)
	for index := range randomness {
		point, drawErr := sampleSigningRandomness(source, params)
		if drawErr != nil {
			t.Fatalf("sampleSigningRandomness(): %v", drawErr)
		}
		randomness[index] = point
	}
	journals := signingExecutorTestJournalsFor(t, params.Threshold, "c7-party")
	identities := make([]uint32, params.Threshold)
	for index := range identities {
		identities[index] = active[index].ParticipantID
	}
	parties := make([]*SigningExecutorParty, params.Threshold)
	for index := range parties {
		party, partyErr := newSigningExecutorParty(
			SigningExecutorPartyConfig{
				Request: request, Share: active[index], Signers: identities, Slot: slot,
				Journal: journals[index], Record: mpcTestRecord(t, byte(0x40+index)),
			}, params, randomness[index],
		)
		if partyErr != nil {
			t.Fatalf("signer %d: newSigningExecutorParty(): %v", index, partyErr)
		}
		parties[index] = party
	}
	for index, party := range parties {
		if err := party.Start(); err != nil {
			t.Fatalf("signer %d: Start(): %v", index, err)
		}
	}
	stopped := make([]bool, len(parties))
	for {
		quiet := true
		for index, party := range parties {
			batch := party.Drain()
			if len(batch) == 0 {
				continue
			}
			quiet = false
			for _, message := range batch {
				for target := range parties {
					if target == index || stopped[target] {
						continue
					}
					if err := parties[target].Deliver(identities[index], message.Kind, message.Payload); err != nil {
						if outcome, ok := SigningExecutorOutcomeOf(err); !ok || outcome.Fatal {
							stopped[target] = true
						}
					}
				}
			}
		}
		if quiet {
			break
		}
	}
	var firstSignature []byte
	accepted := 0
	for index, party := range parties {
		signature, err := party.Finish()
		if err != nil {
			continue
		}
		accepted++
		if firstSignature == nil {
			firstSignature = signature
		} else if !bytes.Equal(signature, firstSignature) {
			t.Fatalf("signer %d signature differs from signer 0", index)
		}
	}
	if accepted != 0 && accepted != params.Threshold {
		t.Fatalf("%d parties accepted, want all or none", accepted)
	}
}

// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"crypto/sha3"
	"errors"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestReshareConsistencyCoordinatorEnforcesOrderedCompleteTranscript(t *testing.T) {
	coordinator := testReshareConsistencyCoordinator(t)
	participants := []uint32{7, 8, 9, 10, 11, 12}

	if coordinator.Phase() != ReshareConsistencyPhaseContributionAgreement {
		t.Fatalf("initial phase = %v", coordinator.Phase())
	}
	if err := coordinator.RecordNonceCommitment(7, [32]byte{1}); !errors.Is(err, ErrReshareStateTransition) {
		t.Fatalf("early nonce commitment error = %v, want %v", err, ErrReshareStateTransition)
	}

	agreement := coordinator.ContributionSetDigest()
	for _, participantID := range participants {
		if err := coordinator.RecordContributionAgreement(participantID, agreement); err != nil {
			t.Fatalf("RecordContributionAgreement(%d): %v", participantID, err)
		}
	}
	if coordinator.Phase() != ReshareConsistencyPhaseNonceCommitment {
		t.Fatalf("phase after agreements = %v", coordinator.Phase())
	}

	nonces := make(map[uint32][32]byte, len(participants))
	for _, participantID := range participants {
		nonce := sha3.Sum256([]byte{byte(participantID), 0x91})
		nonces[participantID] = nonce
		commitment := CommitReshareConsistencyNonce([32]byte{0x44}, 1, participantID, nonce)
		if err := coordinator.RecordNonceCommitment(participantID, commitment); err != nil {
			t.Fatalf("RecordNonceCommitment(%d): %v", participantID, err)
		}
	}
	if coordinator.Phase() != ReshareConsistencyPhaseNonceReveal {
		t.Fatalf("phase after nonce commitments = %v", coordinator.Phase())
	}
	for _, participantID := range participants {
		if err := coordinator.RecordNonceReveal(participantID, nonces[participantID]); err != nil {
			t.Fatalf("RecordNonceReveal(%d): %v", participantID, err)
		}
	}
	if coordinator.Phase() != ReshareConsistencyPhaseTermCommitment {
		t.Fatalf("phase after nonce reveals = %v", coordinator.Phase())
	}

	for round := uint32(0); round < ReshareConsistencyRounds; round++ {
		for checkID := uint32(0); checkID < ReshareConsistencyChecksPerRound; checkID++ {
			gotRound, gotCheck := coordinator.CurrentCheck()
			if gotRound != round || gotCheck != checkID {
				t.Fatalf("current check = (%d,%d), want (%d,%d)", gotRound, gotCheck, round, checkID)
			}
			senders := testReshareConsistencyTermSenders(participants, 1, checkID)
			reveals := make(map[uint32]ReshareMaskedTermReveal, len(senders))
			for _, participantID := range senders {
				salt := sha3.Sum256([]byte{byte(round), byte(checkID), byte(participantID), 0xa3})
				commitment, err := CommitReshareMaskedTerm([32]byte{0x44}, 1, round, checkID, participantID, 0, salt)
				if err != nil {
					t.Fatal(err)
				}
				reveals[participantID] = ReshareMaskedTermReveal{SenderID: participantID, Term: 0, Salt: salt}
				if err := coordinator.RecordMaskedTermCommitment(participantID, commitment); err != nil {
					t.Fatalf("RecordMaskedTermCommitment(%d): %v", participantID, err)
				}
			}
			if coordinator.Phase() != ReshareConsistencyPhaseTermReveal {
				t.Fatalf("phase before term reveals = %v", coordinator.Phase())
			}
			for _, participantID := range senders {
				if err := coordinator.RecordMaskedTermReveal(reveals[participantID]); err != nil {
					t.Fatalf("RecordMaskedTermReveal(%d): %v", participantID, err)
				}
			}
		}
	}
	if coordinator.Phase() != ReshareConsistencyPhaseVerified {
		t.Fatalf("final phase = %v", coordinator.Phase())
	}
	if coordinator.TranscriptDigest() == ([32]byte{}) {
		t.Fatal("verified transcript has zero digest")
	}

	encoded, err := coordinator.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary(): %v", err)
	}
	restored, err := UnmarshalReshareConsistencyCoordinator(encoded)
	if err != nil {
		t.Fatalf("UnmarshalReshareConsistencyCoordinator(): %v", err)
	}
	if restored.Phase() != ReshareConsistencyPhaseVerified ||
		restored.TranscriptDigest() != coordinator.TranscriptDigest() ||
		restored.EventCount() != coordinator.EventCount() {
		t.Fatal("restored coordinator does not match verified transcript")
	}
}

func TestReshareConsistencyConstantLinkRequiresDealerWitness(t *testing.T) {
	coordinator := testReshareConsistencyCoordinatorAtTerms(t)
	participants := []uint32{7, 8, 9, 10, 11, 12}
	completeZeroReshareCheck(t, coordinator, participants, 1, 0, 0)
	completeZeroReshareCheck(t, coordinator, participants, 1, 0, 1)
	for _, participantID := range participants {
		salt := sha3.Sum256([]byte{byte(participantID), 0xb1})
		commitment, err := CommitReshareMaskedTerm([32]byte{0x44}, 1, 0, 2, participantID, 0, salt)
		if err != nil {
			t.Fatal(err)
		}
		if err := coordinator.RecordMaskedTermCommitment(participantID, commitment); err != nil {
			t.Fatal(err)
		}
	}
	if coordinator.Phase() != ReshareConsistencyPhaseTermCommitment {
		t.Fatal("constant-link check advanced without the dealer witness")
	}
	witnessID := ReshareDealerWitnessID(1)
	salt := sha3.Sum256([]byte{0xfe, 0xb1})
	commitment, err := CommitReshareMaskedTerm([32]byte{0x44}, 1, 0, 2, witnessID, 0, salt)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RecordMaskedTermCommitment(witnessID, commitment); err != nil {
		t.Fatal(err)
	}
	if coordinator.Phase() != ReshareConsistencyPhaseTermReveal {
		t.Fatal("constant-link check did not advance after the dealer witness")
	}
}

func TestReshareConsistencyCoordinatorValidatesFullIdentity(t *testing.T) {
	coordinator := testReshareConsistencyCoordinator(t)
	key, oldCommittee := testShareIdentity(t)
	newCommittee := protocol.CommitteeID{
		Version:      6,
		Threshold:    4,
		Participants: []uint32{7, 8, 9, 10, 11, 12},
	}
	if err := coordinator.ValidateIdentity(
		[32]byte{0x44},
		key,
		oldCommittee,
		newCommittee,
		[]uint32{1, 2, 3, 4},
		1,
	); err != nil {
		t.Fatalf("ValidateIdentity(): %v", err)
	}
	newCommittee.Version++
	if err := coordinator.ValidateIdentity(
		[32]byte{0x44},
		key,
		oldCommittee,
		newCommittee,
		[]uint32{1, 2, 3, 4},
		1,
	); err == nil {
		t.Fatal("mismatched committee identity accepted")
	}
}

func TestReshareConsistencyCoordinatorAbortsOnEquivocation(t *testing.T) {
	coordinator := testReshareConsistencyCoordinator(t)
	agreement := coordinator.ContributionSetDigest()
	if err := coordinator.RecordContributionAgreement(7, agreement); err != nil {
		t.Fatal(err)
	}
	agreement[0] ^= 0xff
	if err := coordinator.RecordContributionAgreement(7, agreement); !errors.Is(err, ErrReshareEquivocation) {
		t.Fatalf("equivocation error = %v, want %v", err, ErrReshareEquivocation)
	}
	if coordinator.Phase() != ReshareConsistencyPhaseAborted {
		t.Fatalf("phase = %v, want aborted", coordinator.Phase())
	}
	evidence, ok := coordinator.AbortEvidence()
	if !ok || evidence.OffenderID != 7 || evidence.Reason != ReshareAbortReasonEquivocation {
		t.Fatalf("abort evidence = %+v, found=%v", evidence, ok)
	}
}

func TestReshareConsistencyCoordinatorAbortsOnNonZeroSyndrome(t *testing.T) {
	coordinator := testReshareConsistencyCoordinatorAtTerms(t)
	participants := []uint32{7, 8, 9, 10, 11, 12}
	for _, participantID := range participants {
		term := int32(0)
		if participantID == 12 {
			term = 1
		}
		salt := sha3.Sum256([]byte{byte(participantID), 0x55})
		commitment, err := CommitReshareMaskedTerm([32]byte{0x44}, 1, 0, 0, participantID, term, salt)
		if err != nil {
			t.Fatal(err)
		}
		if err := coordinator.RecordMaskedTermCommitment(participantID, commitment); err != nil {
			t.Fatal(err)
		}
	}
	for _, participantID := range participants {
		term := int32(0)
		if participantID == 12 {
			term = 1
		}
		salt := sha3.Sum256([]byte{byte(participantID), 0x55})
		err := coordinator.RecordMaskedTermReveal(ReshareMaskedTermReveal{SenderID: participantID, Term: term, Salt: salt})
		if participantID != 12 && err != nil {
			t.Fatal(err)
		}
		if participantID == 12 && !errors.Is(err, ErrReshareNonZeroSyndrome) {
			t.Fatalf("final reveal error = %v, want %v", err, ErrReshareNonZeroSyndrome)
		}
	}
	if coordinator.Phase() != ReshareConsistencyPhaseAborted {
		t.Fatalf("phase = %v, want aborted", coordinator.Phase())
	}
}

func TestReshareConsistencyCoordinatorValidatesDurableExtension(t *testing.T) {
	coordinator := testReshareConsistencyCoordinator(t)
	encoded, err := coordinator.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	previous, err := UnmarshalReshareConsistencyCoordinator(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RecordContributionAgreement(7, coordinator.ContributionSetDigest()); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.ValidateExtension(previous); err != nil {
		t.Fatalf("valid extension rejected: %v", err)
	}
	prefixDigest, err := coordinator.TranscriptDigestAt(previous.EventCount())
	if err != nil {
		t.Fatal(err)
	}
	if prefixDigest != previous.TranscriptDigest() {
		t.Fatal("extension does not preserve the previous transcript head")
	}
	if err := previous.ValidateExtension(coordinator); !errors.Is(err, ErrReshareStateRollback) {
		t.Fatalf("rollback error = %v, want %v", err, ErrReshareStateRollback)
	}

	conflict := testReshareConsistencyCoordinator(t)
	wrong := conflict.ContributionSetDigest()
	wrong[0] ^= 0xff
	if err := conflict.RecordContributionAgreement(7, wrong); err == nil {
		t.Fatal("mismatched transcript must abort")
	}
	if err := conflict.ValidateExtension(coordinator); !errors.Is(err, ErrReshareStateRollback) {
		t.Fatalf("fork replacement error = %v, want %v", err, ErrReshareStateRollback)
	}
}

func TestReshareConsistencyCoordinatorBindsInstalledContribution(t *testing.T) {
	coordinator := testReshareConsistencyCoordinator(t)
	commitment := sha3.Sum256([]byte{7, 0x73})
	if err := coordinator.ValidateContributionCommitment(7, commitment); err != nil {
		t.Fatalf("valid contribution commitment rejected: %v", err)
	}
	commitment[0] ^= 0xff
	if err := coordinator.ValidateContributionCommitment(7, commitment); !errors.Is(err, ErrInvalidReshareState) {
		t.Fatalf("mismatched contribution error = %v, want %v", err, ErrInvalidReshareState)
	}
}

func testReshareConsistencyCoordinator(t *testing.T) *ReshareConsistencyCoordinator {
	t.Helper()
	key, oldCommittee := testShareIdentity(t)
	newCommittee := protocol.CommitteeID{
		Version:      oldCommittee.Version + 1,
		Threshold:    4,
		Participants: []uint32{7, 8, 9, 10, 11, 12},
	}
	commitments := make(map[uint32][32]byte, len(newCommittee.Participants))
	for _, participantID := range newCommittee.Participants {
		commitments[participantID] = sha3.Sum256([]byte{byte(participantID), 0x73})
	}
	coordinator, err := NewReshareConsistencyCoordinator(
		[32]byte{0x44},
		key,
		oldCommittee,
		newCommittee,
		[]uint32{1, 2, 3, 4},
		1,
		commitments,
	)
	if err != nil {
		t.Fatalf("NewReshareConsistencyCoordinator(): %v", err)
	}
	return coordinator
}

func testReshareConsistencyCoordinatorAtTerms(t *testing.T) *ReshareConsistencyCoordinator {
	t.Helper()
	coordinator := testReshareConsistencyCoordinator(t)
	participants := []uint32{7, 8, 9, 10, 11, 12}
	agreement := coordinator.ContributionSetDigest()
	for _, participantID := range participants {
		if err := coordinator.RecordContributionAgreement(participantID, agreement); err != nil {
			t.Fatal(err)
		}
	}
	nonces := make(map[uint32][32]byte, len(participants))
	for _, participantID := range participants {
		nonce := sha3.Sum256([]byte{byte(participantID), 0x91})
		nonces[participantID] = nonce
		if err := coordinator.RecordNonceCommitment(
			participantID,
			CommitReshareConsistencyNonce([32]byte{0x44}, 1, participantID, nonce),
		); err != nil {
			t.Fatal(err)
		}
	}
	for _, participantID := range participants {
		if err := coordinator.RecordNonceReveal(participantID, nonces[participantID]); err != nil {
			t.Fatal(err)
		}
	}
	return coordinator
}

func testReshareConsistencyTermSenders(participants []uint32, dealerID, checkID uint32) []uint32 {
	senders := append([]uint32(nil), participants...)
	if checkID == ReshareConsistencyChecksPerRound-1 {
		senders = append(senders, ReshareDealerWitnessID(dealerID))
	}
	return senders
}

func completeZeroReshareCheck(
	t *testing.T,
	coordinator *ReshareConsistencyCoordinator,
	participants []uint32,
	dealerID uint32,
	round uint32,
	checkID uint32,
) {
	t.Helper()
	senders := testReshareConsistencyTermSenders(participants, dealerID, checkID)
	reveals := make(map[uint32]ReshareMaskedTermReveal, len(senders))
	for _, senderID := range senders {
		salt := sha3.Sum256([]byte{byte(round), byte(checkID), byte(senderID), 0xc2})
		commitment, err := CommitReshareMaskedTerm([32]byte{0x44}, dealerID, round, checkID, senderID, 0, salt)
		if err != nil {
			t.Fatal(err)
		}
		reveals[senderID] = ReshareMaskedTermReveal{SenderID: senderID, Salt: salt}
		if err := coordinator.RecordMaskedTermCommitment(senderID, commitment); err != nil {
			t.Fatal(err)
		}
	}
	for _, senderID := range senders {
		if err := coordinator.RecordMaskedTermReveal(reveals[senderID]); err != nil {
			t.Fatal(err)
		}
	}
}

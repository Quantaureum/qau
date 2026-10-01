// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"testing"
)

func TestReshareConsistencyNonceCommitReveal(t *testing.T) {
	var sessionID [32]byte
	sessionID[0] = 0x17
	dealerID := uint32(3)
	participants := []uint32{7, 8, 9, 10, 11, 12}
	commitments := make(map[uint32][32]byte, len(participants))
	reveals := make(map[uint32][32]byte, len(participants))
	var expected [32]byte
	for _, participantID := range participants {
		var share [32]byte
		share[0] = byte(participantID)
		share[31] = byte(participantID * 3)
		reveals[participantID] = share
		commitments[participantID] = CommitReshareConsistencyNonce(sessionID, dealerID, participantID, share)
		for index := range expected {
			expected[index] ^= share[index]
		}
	}

	got, err := RevealReshareConsistencyNonce(sessionID, dealerID, participants, commitments, reveals)
	if err != nil {
		t.Fatalf("RevealReshareConsistencyNonce(): %v", err)
	}
	if got != expected {
		t.Fatalf("combined nonce = %x, want %x", got, expected)
	}
}

func TestReshareConsistencyNonceRejectsMissingAndTamperedReveal(t *testing.T) {
	var sessionID [32]byte
	sessionID[0] = 0x28
	dealerID := uint32(4)
	participants := []uint32{7, 8, 9, 10, 11, 12}
	commitments := make(map[uint32][32]byte, len(participants))
	reveals := make(map[uint32][32]byte, len(participants))
	for _, participantID := range participants {
		var share [32]byte
		share[0] = byte(participantID + 1)
		reveals[participantID] = share
		commitments[participantID] = CommitReshareConsistencyNonce(sessionID, dealerID, participantID, share)
	}

	missing := cloneNonceReveals(reveals)
	delete(missing, 12)
	if _, err := RevealReshareConsistencyNonce(sessionID, dealerID, participants, commitments, missing); !errors.Is(err, ErrInvalidReshareConsistencyNonce) {
		t.Fatalf("missing reveal error = %v, want %v", err, ErrInvalidReshareConsistencyNonce)
	}

	tampered := cloneNonceReveals(reveals)
	share := tampered[11]
	share[0] ^= 1
	tampered[11] = share
	if _, err := RevealReshareConsistencyNonce(sessionID, dealerID, participants, commitments, tampered); !errors.Is(err, ErrInvalidReshareConsistencyNonce) {
		t.Fatalf("tampered reveal error = %v, want %v", err, ErrInvalidReshareConsistencyNonce)
	}
}

func cloneNonceReveals(values map[uint32][32]byte) map[uint32][32]byte {
	clone := make(map[uint32][32]byte, len(values))
	for participantID, value := range values {
		clone[participantID] = value
	}
	return clone
}

// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"errors"
	"testing"
)

func TestVerifyAndAggregateReshareMaskedTerms(t *testing.T) {
	var sessionID [32]byte
	sessionID[0] = 0xa1
	senders := []uint32{7, 8, 9, 10, 11, 12}
	terms := []int32{100, 200, 300, 400, 500, NormalizeCoefficient(-1500)}
	commitments := make(map[uint32][32]byte, len(senders))
	reveals := make(map[uint32]ReshareMaskedTermReveal, len(senders))
	for index, senderID := range senders {
		var salt [32]byte
		salt[0] = byte(senderID)
		commitment, err := CommitReshareMaskedTerm(sessionID, 2, 4, 1, senderID, terms[index], salt)
		if err != nil {
			t.Fatal(err)
		}
		commitments[senderID] = commitment
		reveals[senderID] = ReshareMaskedTermReveal{SenderID: senderID, Term: terms[index], Salt: salt}
	}

	syndrome, err := VerifyAndAggregateReshareMaskedTerms(sessionID, 2, 4, 1, senders, commitments, reveals)
	if err != nil {
		t.Fatalf("VerifyAndAggregateReshareMaskedTerms(): %v", err)
	}
	if syndrome != 0 {
		t.Fatalf("syndrome = %d, want 0", syndrome)
	}
}

func TestVerifyAndAggregateReshareMaskedTermsRejectsIncompleteReveal(t *testing.T) {
	var sessionID [32]byte
	sessionID[0] = 0xb2
	senders := []uint32{7, 8, 9, 10, 11, 12}
	commitments := make(map[uint32][32]byte, len(senders))
	reveals := make(map[uint32]ReshareMaskedTermReveal, len(senders))
	for _, senderID := range senders {
		var salt [32]byte
		salt[0] = byte(senderID + 1)
		commitment, err := CommitReshareMaskedTerm(sessionID, 3, 5, 2, senderID, 17, salt)
		if err != nil {
			t.Fatal(err)
		}
		commitments[senderID] = commitment
		reveals[senderID] = ReshareMaskedTermReveal{SenderID: senderID, Term: 17, Salt: salt}
	}
	delete(reveals, 12)
	if _, err := VerifyAndAggregateReshareMaskedTerms(sessionID, 3, 5, 2, senders, commitments, reveals); !errors.Is(err, ErrInvalidReshareMaskedTerm) {
		t.Fatalf("incomplete reveal error = %v, want %v", err, ErrInvalidReshareMaskedTerm)
	}
}

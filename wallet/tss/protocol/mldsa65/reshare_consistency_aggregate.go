// Quantaureum Node source, version 1.0.0.
package mldsa65

// ReshareMaskedTermReveal is the public reveal after all term commitments exist.
type ReshareMaskedTermReveal struct {
	SenderID uint32
	Term     int32
	Salt     [32]byte
}

// VerifyAndAggregateReshareMaskedTerms validates a complete reveal set and
// returns only the aggregate syndrome.
func VerifyAndAggregateReshareMaskedTerms(
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	senders []uint32,
	commitments map[uint32][32]byte,
	reveals map[uint32]ReshareMaskedTermReveal,
) (int32, error) {
	if sessionID == ([32]byte{}) || dealerID == 0 ||
		!validReshareTermSenders(senders) ||
		len(commitments) != len(senders) || len(reveals) != len(senders) {
		return 0, ErrInvalidReshareMaskedTerm
	}
	terms := make([]int32, 0, len(senders))
	for _, senderID := range senders {
		commitment, hasCommitment := commitments[senderID]
		reveal, hasReveal := reveals[senderID]
		if !hasCommitment || !hasReveal || reveal.SenderID != senderID {
			return 0, ErrInvalidReshareMaskedTerm
		}
		if err := VerifyReshareMaskedTerm(
			commitment,
			sessionID,
			dealerID,
			round,
			checkID,
			senderID,
			reveal.Term,
			reveal.Salt,
		); err != nil {
			return 0, err
		}
		terms = append(terms, reveal.Term)
	}
	return AggregateLinearTerms(terms), nil
}

func validReshareTermSenders(senders []uint32) bool {
	if len(senders) == 0 {
		return false
	}
	seen := make(map[uint32]struct{}, len(senders))
	for _, senderID := range senders {
		if senderID == 0 {
			return false
		}
		if _, duplicate := seen[senderID]; duplicate {
			return false
		}
		seen[senderID] = struct{}{}
	}
	return true
}

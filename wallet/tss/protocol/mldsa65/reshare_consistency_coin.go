// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var ErrInvalidReshareConsistencyNonce = errors.New("invalid TMLDSA v1 reshare consistency nonce")

// CommitReshareConsistencyNonce binds one participant's nonce share before reveal.
func CommitReshareConsistencyNonce(
	sessionID [32]byte,
	dealerID uint32,
	participantID uint32,
	nonceShare [32]byte,
) [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-NONCE-COMMIT"))
	_, _ = digest.Write(sessionID[:])
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], dealerID)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], participantID)
	_, _ = digest.Write(encoded[:])
	_, _ = digest.Write(nonceShare[:])
	var commitment [32]byte
	copy(commitment[:], digest.Sum(nil))
	return commitment
}

// RevealReshareConsistencyNonce validates all six reveals and combines them.
func RevealReshareConsistencyNonce(
	sessionID [32]byte,
	dealerID uint32,
	participants []uint32,
	commitments map[uint32][32]byte,
	reveals map[uint32][32]byte,
) ([32]byte, error) {
	if sessionID == ([32]byte{}) || dealerID == 0 ||
		validateEvaluationPoints(participants) != nil ||
		len(commitments) != len(participants) || len(reveals) != len(participants) {
		return [32]byte{}, ErrInvalidReshareConsistencyNonce
	}
	var combined [32]byte
	for _, participantID := range participants {
		commitment, hasCommitment := commitments[participantID]
		reveal, hasReveal := reveals[participantID]
		if !hasCommitment || !hasReveal || reveal == ([32]byte{}) {
			return [32]byte{}, ErrInvalidReshareConsistencyNonce
		}
		want := CommitReshareConsistencyNonce(sessionID, dealerID, participantID, reveal)
		if subtle.ConstantTimeCompare(want[:], commitment[:]) != 1 {
			return [32]byte{}, ErrInvalidReshareConsistencyNonce
		}
		for index := range combined {
			combined[index] ^= reveal[index]
		}
	}
	if combined == ([32]byte{}) {
		return [32]byte{}, ErrInvalidReshareConsistencyNonce
	}
	return combined, nil
}

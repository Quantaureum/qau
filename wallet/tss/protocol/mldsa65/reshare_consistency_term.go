// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var ErrInvalidReshareMaskedTerm = errors.New("invalid TMLDSA v1 reshare masked term")

// CommitReshareMaskedTerm hides one masked term until every sender commits.
func CommitReshareMaskedTerm(
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	senderID uint32,
	term int32,
	salt [32]byte,
) ([32]byte, error) {
	if sessionID == ([32]byte{}) || dealerID == 0 || senderID == 0 ||
		!isCanonicalCoefficient(term) || salt == ([32]byte{}) {
		return [32]byte{}, ErrInvalidReshareMaskedTerm
	}
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-MASKED-TERM"))
	_, _ = digest.Write(sessionID[:])
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], dealerID)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], round)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], checkID)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], senderID)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], uint32(term))
	_, _ = digest.Write(encoded[:])
	_, _ = digest.Write(salt[:])
	var commitment [32]byte
	copy(commitment[:], digest.Sum(nil))
	return commitment, nil
}

// VerifyReshareMaskedTerm validates one committed term reveal.
func VerifyReshareMaskedTerm(
	commitment [32]byte,
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	senderID uint32,
	term int32,
	salt [32]byte,
) error {
	want, err := CommitReshareMaskedTerm(sessionID, dealerID, round, checkID, senderID, term, salt)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(want[:], commitment[:]) != 1 {
		return ErrInvalidReshareMaskedTerm
	}
	return nil
}

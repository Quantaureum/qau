// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
)

var ErrInvalidResharePairwiseMask = errors.New("invalid TMLDSA v1 reshare pairwise mask")

// DeriveResharePairwiseMask returns opposite masks for the two participants.
// The shared secret must come from a direct authenticated post-quantum channel.
func DeriveResharePairwiseMask(
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	localID uint32,
	peerID uint32,
	sharedSecret [32]byte,
) (int32, error) {
	if sessionID == ([32]byte{}) || dealerID == 0 || localID == 0 || peerID == 0 ||
		localID == peerID || sharedSecret == ([32]byte{}) {
		return 0, ErrInvalidResharePairwiseMask
	}
	leftID := localID
	rightID := peerID
	if leftID > rightID {
		leftID, rightID = rightID, leftID
	}
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write([]byte("QAU-TMLDSA65-V1-RESHARE-PAIRWISE-MASK"))
	_, _ = shake.Write(sessionID[:])
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], dealerID)
	_, _ = shake.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], round)
	_, _ = shake.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], checkID)
	_, _ = shake.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], leftID)
	_, _ = shake.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], rightID)
	_, _ = shake.Write(encoded[:])
	_, _ = shake.Write(sharedSecret[:])

	var magnitude int32
	for magnitude == 0 {
		candidate, err := sampleUniformCoefficient(shake)
		if err != nil {
			return 0, err
		}
		magnitude = candidate
	}
	if localID == leftID {
		return magnitude, nil
	}
	return -magnitude, nil
}

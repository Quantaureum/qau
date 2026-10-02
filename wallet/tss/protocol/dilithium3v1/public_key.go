// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
)

const publicKeyTranscriptDomain = "QAU-TDILITHIUM3-V1-PUBLIC-KEY-TRANSCRIPT"

var ErrInvalidPublicKeyAssembly = errors.New("invalid Dilithium3 v1 public-key assembly")

// AssembleMode3PublicKey aggregates the binomial(C, floor(C/3)+1) public
// contributions of one session's committee into one mode3 key (R76a family;
// C = participants must be within the committee family).
func AssembleMode3PublicKey(
	rho [32]byte,
	contributions []PublicContribution,
	participants int,
) (publicKey [1952]byte, transcriptDigest [32]byte, err error) {
	groups, err := CanonicalRSSGroupsFor(participants)
	if err != nil {
		return [1952]byte{}, [32]byte{}, err
	}
	if len(contributions) != len(groups) {
		return [1952]byte{}, [32]byte{}, fmt.Errorf("%w: contribution count %d, want %d for a %d-member committee",
			ErrInvalidPublicKeyAssembly, len(contributions), len(groups), participants)
	}
	ordered := append([]PublicContribution(nil), contributions...)
	for index := range ordered {
		if err := ordered[index].Validate(); err != nil {
			return [1952]byte{}, [32]byte{}, fmt.Errorf("%w: contribution %d: %v", ErrInvalidPublicKeyAssembly, index, err)
		}
	}
	for index := 1; index < len(ordered); index++ {
		current := ordered[index]
		position := index
		for position > 0 && ordered[position-1].GroupMask > current.GroupMask {
			ordered[position] = ordered[position-1]
			position--
		}
		ordered[position] = current
	}
	sessionDigest := ordered[0].SessionDigest
	var aggregate VectorK
	contributionDigests := make([][32]byte, len(ordered))
	for index, contribution := range ordered {
		if contribution.GroupMask != groups[index] {
			return [1952]byte{}, [32]byte{}, fmt.Errorf("%w: group %d is %06b, want %06b", ErrInvalidPublicKeyAssembly, index, contribution.GroupMask, groups[index])
		}
		if contribution.SessionDigest != sessionDigest {
			return [1952]byte{}, [32]byte{}, fmt.Errorf("%w: foreign session at group %06b", ErrInvalidPublicKeyAssembly, contribution.GroupMask)
		}
		digest, err := contribution.Digest()
		if err != nil {
			return [1952]byte{}, [32]byte{}, fmt.Errorf("%w: contribution digest: %v", ErrInvalidPublicKeyAssembly, err)
		}
		contributionDigests[index] = digest
		for polynomialIndex := 0; polynomialIndex < K; polynomialIndex++ {
			aggregate[polynomialIndex] = Add(aggregate[polynomialIndex], contribution.T[polynomialIndex])
		}
	}

	var t1 VectorK
	var t0 VectorK
	for polynomialIndex := range aggregate {
		t1[polynomialIndex], t0[polynomialIndex] = Power2Round(aggregate[polynomialIndex])
	}
	copy(publicKey[:32], rho[:])
	offset := 32
	for polynomialIndex := range t1 {
		encoded, err := encodeMode3T1(t1[polynomialIndex])
		if err != nil {
			t0 = VectorK{}
			return [1952]byte{}, [32]byte{}, err
		}
		copy(publicKey[offset:offset+len(encoded)], encoded[:])
		offset += len(encoded)
	}
	t0 = VectorK{}

	transcript := make([]byte, 0, len(publicKeyTranscriptDomain)+32+32+len(publicKey)+20*(1+1+32))
	transcript = append(transcript, publicKeyTranscriptDomain...)
	transcript = append(transcript, sessionDigest[:]...)
	transcript = append(transcript, rho[:]...)
	transcript = append(transcript, publicKey[:]...)
	for index, contribution := range ordered {
		transcript = binary.BigEndian.AppendUint16(transcript, uint16(contribution.GroupMask))
		transcript = append(transcript, contribution.DealerPosition)
		transcript = append(transcript, contributionDigests[index][:]...)
	}
	return publicKey, sha3.Sum256(transcript), nil
}

// decodeMode3T1 expands the public-key t1 packing: four ten-bit coefficients in
// five bytes per group, six rows after the 32-byte rho. It is the inverse of
// encodeMode3T1 and is used by signing to rebuild the public verification
// equation.
func decodeMode3T1(encoded []byte) (VectorK, error) {
	const rowEncodedSize = N / 4 * 5
	if len(encoded) != K*rowEncodedSize {
		return VectorK{}, fmt.Errorf(
			"%w: t1 length %d, want %d", ErrInvalidPublicKeyAssembly, len(encoded), K*rowEncodedSize,
		)
	}
	var vector VectorK
	for row := 0; row < K; row++ {
		for coefficientIndex := 0; coefficientIndex < N; coefficientIndex += 4 {
			offset := row*rowEncodedSize + coefficientIndex/4*5
			first := uint32(encoded[offset]) | uint32(encoded[offset+1])<<8
			second := uint32(encoded[offset+1])>>2 | uint32(encoded[offset+2])<<6
			third := uint32(encoded[offset+2])>>4 | uint32(encoded[offset+3])<<4
			fourth := uint32(encoded[offset+3])>>6 | uint32(encoded[offset+4])<<2
			vector[row][coefficientIndex] = Coefficient(first & 0x3ff)
			vector[row][coefficientIndex+1] = Coefficient(second & 0x3ff)
			vector[row][coefficientIndex+2] = Coefficient(third & 0x3ff)
			vector[row][coefficientIndex+3] = Coefficient(fourth & 0x3ff)
		}
	}
	return vector, nil
}

func encodeMode3T1(polynomial Poly) ([320]byte, error) {
	var encoded [320]byte
	for coefficientIndex, byteIndex := 0, 0; coefficientIndex < N; coefficientIndex, byteIndex = coefficientIndex+4, byteIndex+5 {
		first := polynomial[coefficientIndex]
		second := polynomial[coefficientIndex+1]
		third := polynomial[coefficientIndex+2]
		fourth := polynomial[coefficientIndex+3]
		if first < 0 || first >= 1<<10 || second < 0 || second >= 1<<10 || third < 0 || third >= 1<<10 || fourth < 0 || fourth >= 1<<10 {
			return [320]byte{}, fmt.Errorf("%w: t1 coefficient outside ten-bit range", ErrInvalidPublicKeyAssembly)
		}
		encoded[byteIndex] = byte(first)
		encoded[byteIndex+1] = byte(first>>8) | byte(second<<2)
		encoded[byteIndex+2] = byte(second>>6) | byte(third<<4)
		encoded[byteIndex+3] = byte(third>>4) | byte(fourth<<6)
		encoded[byteIndex+4] = byte(fourth >> 2)
	}
	return encoded, nil
}

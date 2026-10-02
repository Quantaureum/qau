// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bufio"
	"crypto/sha3"
	"errors"
	"fmt"
)

const (
	rssComponentDomain      = "QAU-TDILITHIUM3-V1-RSS-COMPONENT"
	rssComponentSampleRange = 2*RSSComponentEta + 1
	rssComponentByteLimit   = 256 - 256%rssComponentSampleRange
)

var ErrInvalidRSSComponentSampling = errors.New("invalid Dilithium3 v1 RSS component sampling input")

// DeriveRSSComponent expands one private group seed into bounded RSS vectors.
func DeriveRSSComponent(
	sessionDigest [32]byte,
	group RSSGroupMask,
	leaderPosition uint8,
	globalRandomness [64]byte,
	groupSeed [32]byte,
) (s1 VectorL, s2 VectorK, err error) {
	if sessionDigest == ([32]byte{}) {
		return VectorL{}, VectorK{}, fmt.Errorf("%w: zero session digest", ErrInvalidRSSComponentSampling)
	}
	if err := group.Validate(); err != nil {
		return VectorL{}, VectorK{}, fmt.Errorf("%w: group: %v", ErrInvalidRSSComponentSampling, err)
	}
	if leaderPosition >= 12 || !group.Contains(leaderPosition) {
		return VectorL{}, VectorK{}, fmt.Errorf("%w: leader %d is outside group", ErrInvalidRSSComponentSampling, leaderPosition)
	}
	if globalRandomness == ([64]byte{}) {
		return VectorL{}, VectorK{}, fmt.Errorf("%w: zero global randomness", ErrInvalidRSSComponentSampling)
	}
	if groupSeed == ([32]byte{}) {
		return VectorL{}, VectorK{}, fmt.Errorf("%w: zero group seed", ErrInvalidRSSComponentSampling)
	}

	shake := sha3.NewSHAKE256()
	_, _ = shake.Write([]byte(rssComponentDomain))
	_, _ = shake.Write(sessionDigest[:])
	_, _ = shake.Write([]byte{byte(uint16(group) >> 8), byte(uint16(group)), leaderPosition})
	_, _ = shake.Write(globalRandomness[:])
	_, _ = shake.Write(groupSeed[:])
	reader := bufio.NewReaderSize(shake, 512)
	for vectorIndex := range s1 {
		if err := sampleRSSPolynomial(reader, &s1[vectorIndex]); err != nil {
			return VectorL{}, VectorK{}, err
		}
	}
	for vectorIndex := range s2 {
		if err := sampleRSSPolynomial(reader, &s2[vectorIndex]); err != nil {
			return VectorL{}, VectorK{}, err
		}
	}
	return s1, s2, nil
}

func sampleRSSPolynomial(reader *bufio.Reader, polynomial *Poly) error {
	for coefficientIndex := range polynomial {
		for {
			sample, err := reader.ReadByte()
			if err != nil {
				return fmt.Errorf("%w: SHAKE read: %v", ErrInvalidRSSComponentSampling, err)
			}
			if int(sample) >= rssComponentByteLimit {
				continue
			}
			centered := int32(sample%rssComponentSampleRange) - RSSComponentEta
			polynomial[coefficientIndex] = Normalize(Coefficient(centered))
			break
		}
	}
	return nil
}

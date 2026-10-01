// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Wallet-side message layer of the signing executor: the four canonical,
// fixed-width payloads of the revised construction's rounds, plus the round-1
// commitment digest. Every decoder rejects every non-canonical form. These
// kinds are the wallet-side view that maps onto protocol.SigningMessage; the
// p2p kind numbers are reserved by the node-wiring slice (design note, Slices 1
// and 4).

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrInvalidSigningExecutorMessage reports a malformed, mis-sized, or
// non-canonical signing-executor payload.
var ErrInvalidSigningExecutorMessage = errors.New("invalid Dilithium3 v1 signing executor message")

const (
	// SigningExecutorKindCommit carries the round-1 commitment digest.
	SigningExecutorKindCommit uint16 = 1

	// SigningExecutorKindReveal carries the round-2 commitment share w_i.
	SigningExecutorKindReveal uint16 = 2

	// SigningExecutorKindAcceptance carries the round-3 acceptance bit.
	SigningExecutorKindAcceptance uint16 = 3

	// SigningExecutorKindResponse carries one signer's round-3 response part
	// z_i^(1). It is only ever sent for a slot every signer accepted.
	SigningExecutorKindResponse uint16 = 4

	signingExecutorCommitMagic     = "QTD3SC01"
	signingExecutorRevealMagic     = "QTD3SW01"
	signingExecutorAcceptanceMagic = "QTD3SA01"
	signingExecutorResponseMagic   = "QTD3SZ01"

	// signingExecutorCommitDomain binds the round-1 commitment digest.
	signingExecutorCommitDomain = "QAU-TDILITHIUM3-V1-SIGNING-EXECUTOR-COMMIT"

	// signingExecutorSlotSize is the encoded slot index width. Slots are
	// one-based, and a zero slot is malformed.
	signingExecutorSlotSize = 2

	signingExecutorCommitEncodedSize     = len(signingExecutorCommitMagic) + signingExecutorSlotSize + 32
	signingExecutorRevealEncodedSize     = len(signingExecutorRevealMagic) + signingExecutorSlotSize + K*PolyEncodedSize
	signingExecutorAcceptanceEncodedSize = len(signingExecutorAcceptanceMagic) + signingExecutorSlotSize + 1
	signingExecutorResponseEncodedSize   = len(signingExecutorResponseMagic) + signingExecutorSlotSize + L*ZEncodedSize
)

// signingCommitmentDigest is the round-1 commitment to one signer's next
// reveal: it binds the session, the signer, the slot, and every coefficient of
// the commitment share w_i.
func signingCommitmentDigest(
	sessionID [32]byte,
	senderID uint32,
	slot uint16,
	contribution VectorK,
) ([32]byte, error) {
	if slot == 0 {
		return [32]byte{}, fmt.Errorf("%w: zero slot", ErrInvalidSigningExecutorMessage)
	}
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write([]byte(signingExecutorCommitDomain))
	_, _ = shake.Write(sessionID[:])
	var identity [4]byte
	binary.BigEndian.PutUint32(identity[:], senderID)
	_, _ = shake.Write(identity[:])
	var slotBytes [signingExecutorSlotSize]byte
	binary.BigEndian.PutUint16(slotBytes[:], slot)
	_, _ = shake.Write(slotBytes[:])
	for row := range contribution {
		encoded, err := EncodePoly(contribution[row])
		if err != nil {
			return [32]byte{}, fmt.Errorf("%w: %v", ErrInvalidSigningExecutorMessage, err)
		}
		_, _ = shake.Write(encoded[:])
	}
	var digest [32]byte
	if _, err := io.ReadFull(shake, digest[:]); err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrInvalidSigningExecutorMessage, err)
	}
	return digest, nil
}

// signingExecutorPayloadHead builds the magic and slot prefix of one payload.
func signingExecutorPayloadHead(magic string, slot uint16) []byte {
	payload := make([]byte, 0, len(magic)+signingExecutorSlotSize)
	payload = append(payload, magic...)
	payload = append(payload, byte(slot>>8), byte(slot))
	return payload
}

// signingExecutorPayloadBody validates one payload's magic, exact length, and
// non-zero slot, and returns the slot with the body.
func signingExecutorPayloadBody(payload []byte, magic string, want int) (uint16, []byte, error) {
	if len(payload) != want || !bytes.Equal(payload[:len(magic)], []byte(magic)) {
		return 0, nil, fmt.Errorf(
			"%w: kind %s length %d, want %d", ErrInvalidSigningExecutorMessage, magic, len(payload), want,
		)
	}
	slot := binary.BigEndian.Uint16(payload[len(magic):])
	if slot == 0 {
		return 0, nil, fmt.Errorf("%w: zero slot", ErrInvalidSigningExecutorMessage)
	}
	return slot, payload[len(magic)+signingExecutorSlotSize:], nil
}

// EncodeSigningExecutorCommit encodes the round-1 commitment payload.
func EncodeSigningExecutorCommit(slot uint16, digest [32]byte) ([]byte, error) {
	if slot == 0 {
		return nil, fmt.Errorf("%w: zero slot", ErrInvalidSigningExecutorMessage)
	}
	payload := signingExecutorPayloadHead(signingExecutorCommitMagic, slot)
	payload = append(payload, digest[:]...)
	return payload, nil
}

// DecodeSigningExecutorCommit decodes the round-1 commitment payload.
func DecodeSigningExecutorCommit(payload []byte) (uint16, [32]byte, error) {
	slot, body, err := signingExecutorPayloadBody(payload, signingExecutorCommitMagic, signingExecutorCommitEncodedSize)
	if err != nil {
		return 0, [32]byte{}, err
	}
	var digest [32]byte
	copy(digest[:], body)
	return slot, digest, nil
}

// EncodeSigningExecutorReveal encodes one signer's round-2 commitment share.
func EncodeSigningExecutorReveal(slot uint16, contribution VectorK) ([]byte, error) {
	if slot == 0 {
		return nil, fmt.Errorf("%w: zero slot", ErrInvalidSigningExecutorMessage)
	}
	payload := signingExecutorPayloadHead(signingExecutorRevealMagic, slot)
	for row := range contribution {
		encoded, err := EncodePoly(contribution[row])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSigningExecutorMessage, err)
		}
		payload = append(payload, encoded[:]...)
	}
	return payload, nil
}

// DecodeSigningExecutorReveal decodes one signer's round-2 commitment share.
func DecodeSigningExecutorReveal(payload []byte) (uint16, VectorK, error) {
	slot, body, err := signingExecutorPayloadBody(payload, signingExecutorRevealMagic, signingExecutorRevealEncodedSize)
	if err != nil {
		return 0, VectorK{}, err
	}
	var contribution VectorK
	for row := 0; row < K; row++ {
		decoded, err := DecodePoly(body[row*PolyEncodedSize : (row+1)*PolyEncodedSize])
		if err != nil {
			return 0, VectorK{}, fmt.Errorf("%w: %v", ErrInvalidSigningExecutorMessage, err)
		}
		contribution[row] = decoded
	}
	return slot, contribution, nil
}

// EncodeSigningExecutorAcceptance encodes one signer's round-3 acceptance bit.
func EncodeSigningExecutorAcceptance(slot uint16, accepted bool) ([]byte, error) {
	if slot == 0 {
		return nil, fmt.Errorf("%w: zero slot", ErrInvalidSigningExecutorMessage)
	}
	payload := signingExecutorPayloadHead(signingExecutorAcceptanceMagic, slot)
	if accepted {
		payload = append(payload, 1)
	} else {
		payload = append(payload, 0)
	}
	return payload, nil
}

// DecodeSigningExecutorAcceptance decodes one signer's round-3 acceptance bit.
func DecodeSigningExecutorAcceptance(payload []byte) (uint16, bool, error) {
	slot, body, err := signingExecutorPayloadBody(payload, signingExecutorAcceptanceMagic, signingExecutorAcceptanceEncodedSize)
	if err != nil {
		return 0, false, err
	}
	switch body[0] {
	case 0:
		return slot, false, nil
	case 1:
		return slot, true, nil
	default:
		return 0, false, fmt.Errorf("%w: acceptance byte %d", ErrInvalidSigningExecutorMessage, body[0])
	}
}

// EncodeSigningExecutorResponse encodes one signer's round-3 response part.
func EncodeSigningExecutorResponse(slot uint16, part [L]SignedPoly) ([]byte, error) {
	if slot == 0 {
		return nil, fmt.Errorf("%w: zero slot", ErrInvalidSigningExecutorMessage)
	}
	payload := signingExecutorPayloadHead(signingExecutorResponseMagic, slot)
	for row := range part {
		encoded, err := EncodeZ(part[row])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSigningExecutorMessage, err)
		}
		payload = append(payload, encoded[:]...)
	}
	return payload, nil
}

// DecodeSigningExecutorResponse decodes one signer's round-3 response part.
func DecodeSigningExecutorResponse(payload []byte) (uint16, [L]SignedPoly, error) {
	slot, body, err := signingExecutorPayloadBody(payload, signingExecutorResponseMagic, signingExecutorResponseEncodedSize)
	if err != nil {
		return 0, [L]SignedPoly{}, err
	}
	var part [L]SignedPoly
	for row := 0; row < L; row++ {
		decoded, err := DecodeZ(body[row*ZEncodedSize : (row+1)*ZEncodedSize])
		if err != nil {
			return 0, [L]SignedPoly{}, fmt.Errorf("%w: %v", ErrInvalidSigningExecutorMessage, err)
		}
		part[row] = decoded
	}
	return slot, part, nil
}

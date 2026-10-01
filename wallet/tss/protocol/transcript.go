// Quantaureum Node source, version 1.0.0.
package protocol

import (
	"crypto/sha3"
	"encoding/binary"
)

const signingTranscriptDomain = "QAU-THRESHOLD-SIGN-V1"

// SigningSessionID derives the canonical identifier for one signing attempt.
func SigningSessionID(request SignRequest) ([32]byte, error) {
	if err := request.Validate(); err != nil {
		return [32]byte{}, err
	}
	keyDigest, err := request.Key.CanonicalDigest()
	if err != nil {
		return [32]byte{}, err
	}
	committeeDigest, err := request.Committee.CanonicalDigest()
	if err != nil {
		return [32]byte{}, err
	}
	messageDigest := sha3.Sum256(request.Message)

	encoded := make([]byte, 0, 160+len(request.Context))
	encoded = appendLengthPrefixed(encoded, []byte(signingTranscriptDomain))
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(request.Protocol))
	encoded = append(encoded, keyDigest[:]...)
	encoded = append(encoded, committeeDigest[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, request.ChainID)
	encoded = binary.BigEndian.AppendUint64(encoded, request.Epoch)
	encoded = binary.BigEndian.AppendUint64(encoded, request.Slot)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(request.Domain))
	encoded = appendLengthPrefixed(encoded, request.Context)
	encoded = append(encoded, messageDigest[:]...)
	encoded = append(encoded, request.AttemptNonce[:]...)
	return sha3.Sum256(encoded), nil
}

func appendLengthPrefixed(destination []byte, value []byte) []byte {
	destination = binary.BigEndian.AppendUint32(destination, uint32(len(value)))
	return append(destination, value...)
}

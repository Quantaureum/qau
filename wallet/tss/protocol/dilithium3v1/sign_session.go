// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const dilithium3SigningSetDomain = "QAU-TDILITHIUM3-V1-SIGNING-SET"

// dilithium3SigningRequestNonceDomain separates the derived attempt nonce of a
// signing request from every other hash input of the protocol.
const dilithium3SigningRequestNonceDomain = "QAU-TDILITHIUM3-V1-SIGNING-REQUEST-NONCE"

var ErrInvalidDilithium3SigningSession = errors.New("invalid Dilithium3 v1 signing session")

func Dilithium3SigningSessionID(request protocol.SignRequest, signerIDs []uint32) ([32]byte, error) {
	if request.Protocol != protocol.ThresholdProtocolDilithium3V1 {
		return [32]byte{}, ErrInvalidDilithium3SigningSession
	}
	baseID, err := protocol.SigningSessionID(request)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrInvalidDilithium3SigningSession, err)
	}
	if len(signerIDs) != int(protocol.ThresholdV1Threshold) {
		return [32]byte{}, ErrInvalidDilithium3SigningSession
	}
	for index, signerID := range signerIDs {
		if !slices.Contains(request.Committee.Participants, signerID) ||
			(index > 0 && signerIDs[index-1] >= signerID) {
			return [32]byte{}, ErrInvalidDilithium3SigningSession
		}
	}
	encoded := make([]byte, 0, len(dilithium3SigningSetDomain)+32+len(signerIDs)*4)
	encoded = append(encoded, dilithium3SigningSetDomain...)
	encoded = append(encoded, baseID[:]...)
	for _, signerID := range signerIDs {
		encoded = binary.BigEndian.AppendUint32(encoded, signerID)
	}
	return sha3.Sum256(encoded), nil
}

func Dilithium3SigningSessionForShare(request protocol.SignRequest, share *LocalShare, signerIDs []uint32) ([32]byte, error) {
	if share == nil || share.Validate() != nil || request.Epoch < share.ActivationEpoch ||
		!slices.Contains(signerIDs, share.ParticipantID) ||
		request.Key.Algorithm != share.Key.Algorithm ||
		request.Key.Generation != share.Key.Generation ||
		!bytes.Equal(request.Key.PublicKey, share.Key.PublicKey) {
		return [32]byte{}, ErrInvalidDilithium3SigningSession
	}
	requestCommitteeDigest, err := request.Committee.CanonicalDigest()
	if err != nil {
		return [32]byte{}, ErrInvalidDilithium3SigningSession
	}
	shareCommitteeDigest, err := share.Committee.CanonicalDigest()
	if err != nil || requestCommitteeDigest != shareCommitteeDigest {
		return [32]byte{}, ErrInvalidDilithium3SigningSession
	}
	return Dilithium3SigningSessionID(request, signerIDs)
}

// SigningRequestAttemptNonce derives one attempt's nonce from the request's
// public binding: the chain, the epoch, the seal slot, the signing domain, the
// message, and the attempt ordinal. Every active signer of one attempt derives
// the same nonce with no extra round, so a networked four-party session forms
// from public inputs alone; a retry announces a higher ordinal and therefore a
// fresh session, and a restarted signer recomputes the same value for the
// attempt it was already in. Nothing here is random: the freshness a random
// nonce would provide comes from the seal tuple, the same chain-anchored-inputs
// convention the DKG session derivation follows.
func SigningRequestAttemptNonce(
	chainID, epoch, slot uint64,
	domain protocol.SigningDomain,
	message []byte,
	attempt uint64,
) ([32]byte, error) {
	if chainID == 0 {
		return [32]byte{}, fmt.Errorf("%w: zero chain ID", ErrInvalidDilithium3SigningSession)
	}
	if slot == 0 {
		return [32]byte{}, fmt.Errorf("%w: zero slot", ErrInvalidDilithium3SigningSession)
	}
	switch domain {
	case protocol.SigningDomainBlock, protocol.SigningDomainVote, protocol.SigningDomainFinality:
	default:
		return [32]byte{}, fmt.Errorf("%w: unknown signing domain", ErrInvalidDilithium3SigningSession)
	}
	if len(message) == 0 {
		return [32]byte{}, fmt.Errorf("%w: empty message", ErrInvalidDilithium3SigningSession)
	}
	messageDigest := sha3.Sum256(message)
	encoded := make([]byte, 0, len(dilithium3SigningRequestNonceDomain)+8*4+2+32)
	encoded = append(encoded, dilithium3SigningRequestNonceDomain...)
	encoded = binary.BigEndian.AppendUint64(encoded, chainID)
	encoded = binary.BigEndian.AppendUint64(encoded, epoch)
	encoded = binary.BigEndian.AppendUint64(encoded, slot)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(domain))
	encoded = binary.BigEndian.AppendUint64(encoded, attempt)
	encoded = append(encoded, messageDigest[:]...)
	return sha3.Sum256(encoded), nil
}

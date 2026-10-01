// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"encoding/binary"
	"fmt"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const dkgIdentityRosterDomain = "QAU-TDILITHIUM3-V1-IDENTITY-ROSTER"

type DKGIdentityBinding struct {
	ParticipantID    uint32
	ValidatorAddress [20]byte
	PublicKey        []byte
}

func DKGIdentityRosterDigest(committee protocol.CommitteeID, bindings []DKGIdentityBinding) ([32]byte, error) {
	if err := protocol.Dilithium3V1Profile().ValidateCommittee(committee); err != nil || len(bindings) != len(committee.Participants) {
		return [32]byte{}, fmt.Errorf("%w: invalid identity roster committee", ErrInvalidDKGSession)
	}
	committeeDigest, err := committee.CanonicalDigest()
	if err != nil {
		return [32]byte{}, err
	}
	encoded := make([]byte, 0, len(dkgIdentityRosterDomain)+32+len(bindings)*(4+20+qcrypto.Dilithium3PublicKeySize))
	encoded = append(encoded, dkgIdentityRosterDomain...)
	encoded = append(encoded, committeeDigest[:]...)
	addresses := make(map[[20]byte]bool, len(bindings))
	keys := make(map[[32]byte]bool, len(bindings))
	for position, binding := range bindings {
		if binding.ParticipantID != committee.Participants[position] || binding.ValidatorAddress == ([20]byte{}) || addresses[binding.ValidatorAddress] {
			return [32]byte{}, fmt.Errorf("%w: invalid roster address or order", ErrInvalidDKGSession)
		}
		if _, err := qcrypto.PublicKeyFromBytes(binding.PublicKey); err != nil {
			return [32]byte{}, fmt.Errorf("%w: invalid roster identity key: %v", ErrInvalidDKGSession, err)
		}
		keyHash := sha3.Sum256(binding.PublicKey)
		if keys[keyHash] {
			return [32]byte{}, fmt.Errorf("%w: duplicate roster identity key", ErrInvalidDKGSession)
		}
		addresses[binding.ValidatorAddress] = true
		keys[keyHash] = true
		encoded = binary.BigEndian.AppendUint32(encoded, binding.ParticipantID)
		encoded = append(encoded, binding.ValidatorAddress[:]...)
		encoded = append(encoded, binding.PublicKey...)
	}
	return sha3.Sum256(encoded), nil
}

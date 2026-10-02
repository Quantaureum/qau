// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	dkgRandomnessDomain           = "QAU-TDILITHIUM3-V1-DKG-RANDOMNESS"
	dkgMatrixSeedDomain           = "QAU-TDILITHIUM3-V1-MATRIX-SEED"
	dkgRandomnessCommitmentDomain = "QAU-TDILITHIUM3-V1-RANDOMNESS-COMMITMENT"
)

var ErrInvalidDKGRandomness = errors.New("invalid Dilithium3 v1 DKG randomness")

// DKGRandomnessCommitment binds a contribution to a session and committee position.
func DKGRandomnessCommitment(session DKGSession, position uint8, contribution [32]byte) ([32]byte, error) {
	if position >= uint8(len(session.Committee.Participants)) || contribution == ([32]byte{}) {
		return [32]byte{}, ErrInvalidDKGRandomness
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		return [32]byte{}, err
	}
	preimage := make([]byte, 0, len(dkgRandomnessCommitmentDomain)+32+4+32)
	preimage = append(preimage, dkgRandomnessCommitmentDomain...)
	preimage = append(preimage, sessionDigest[:]...)
	preimage = binary.BigEndian.AppendUint32(preimage, session.Committee.Participants[position])
	preimage = append(preimage, contribution[:]...)
	return sha3.Sum256(preimage), nil
}

// DeriveDKGRandomness binds the committee's ordered contributions (one per
// participant) to global randomness and rho.
func DeriveDKGRandomness(session DKGSession, contributions [][32]byte) (global [64]byte, rho [32]byte, err error) {
	if len(contributions) != len(session.Committee.Participants) {
		return [64]byte{}, [32]byte{}, fmt.Errorf("%w: %d contributions, want %d", ErrInvalidDKGRandomness, len(contributions), len(session.Committee.Participants))
	}
	sessionDigest, err := session.Digest()
	if err != nil {
		return [64]byte{}, [32]byte{}, err
	}
	committeeDigest, err := session.Committee.CanonicalDigest()
	if err != nil {
		return [64]byte{}, [32]byte{}, fmt.Errorf("%w: committee digest: %v", ErrInvalidDKGRandomness, err)
	}
	seen := make(map[[32]byte]struct{}, len(contributions))
	for position, contribution := range contributions {
		if contribution == ([32]byte{}) {
			return [64]byte{}, [32]byte{}, fmt.Errorf("%w: missing position %d", ErrInvalidDKGRandomness, position)
		}
		if _, duplicate := seen[contribution]; duplicate {
			return [64]byte{}, [32]byte{}, fmt.Errorf("%w: duplicate position %d", ErrInvalidDKGRandomness, position)
		}
		seen[contribution] = struct{}{}
	}

	randomnessXOF := sha3.NewSHAKE256()
	_, _ = randomnessXOF.Write([]byte(dkgRandomnessDomain))
	_, _ = randomnessXOF.Write(sessionDigest[:])
	_, _ = randomnessXOF.Write(committeeDigest[:])
	for _, contribution := range contributions {
		_, _ = randomnessXOF.Write(contribution[:])
	}
	if _, err := io.ReadFull(randomnessXOF, global[:]); err != nil {
		return [64]byte{}, [32]byte{}, fmt.Errorf("%w: global derivation: %v", ErrInvalidDKGRandomness, err)
	}

	matrixXOF := sha3.NewSHAKE256()
	_, _ = matrixXOF.Write([]byte(dkgMatrixSeedDomain))
	_, _ = matrixXOF.Write(sessionDigest[:])
	_, _ = matrixXOF.Write(committeeDigest[:])
	_, _ = matrixXOF.Write(global[:])
	if _, err := io.ReadFull(matrixXOF, rho[:]); err != nil {
		return [64]byte{}, [32]byte{}, fmt.Errorf("%w: matrix seed derivation: %v", ErrInvalidDKGRandomness, err)
	}
	return global, rho, nil
}

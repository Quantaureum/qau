package node

import (
	"fmt"

	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3_reshare_r77.go wires the R77 same-key rotation plan into the
// v1 session machinery. The wire choreography (fold-delta delivery and weave
// group rounds under the reshare nonce) drives the same runner the DKG
// ceremony uses; this file supplies the reshare-honest session shape and the
// plan lookup so certificates from a wrong-shape ceremony verify nowhere.

// tdilithium3ReshareSessionFor builds the reshare session for the new
// committee anchored at activationEpoch. The nonce mixes the fresh-DKG
// session inputs with the previous committee digest and the previous group
// public key, so the same-key ceremony can never collide with a same-epoch
// fresh-key ceremony nor with a ceremony for a different old key.
func tdilithium3ReshareSessionFor(
	chainID uint64,
	genesis types.Hash,
	activationEpoch uint64,
	previousCommittee protocol.CommitteeID,
	previousGroupPublicKey []byte,
	committee protocol.CommitteeID,
	identityRosterDigest [32]byte,
) (dilithium3v1.DKGSession, error) {
	keyGeneration := activationEpoch
	committeeDigest, err := committee.CanonicalDigest()
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	previousCommitteeDigest, err := previousCommittee.CanonicalDigest()
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	baseNonce := tdilithium3DKGSessionNonce(chainID, genesis, keyGeneration, activationEpoch, committeeDigest, identityRosterDigest)
	session := dilithium3v1.DKGSession{
		Protocol:             protocol.ThresholdProtocolDilithium3V1,
		ChainID:              chainID,
		KeyGeneration:        keyGeneration,
		Committee:            committee,
		ActivationEpoch:      activationEpoch,
		Nonce:                dilithium3v1.ReshareSessionNonce(chainID, genesis, previousCommitteeDigest, previousGroupPublicKey, committeeDigest, baseNonce),
		IdentityRosterDigest: identityRosterDigest,
	}
	if err := session.Validate(); err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	return session, nil
}

// tdilithium3ReshareRotationFor derives the signed-family rotation plan
// between the previous committee (the currently active share) and the epoch
// roster committee. Non-reshare-shaped transitions fall through with the
// reshare-input error so the caller can fall back to the fresh-key DKG
// ceremony path exactly as the R77 spec requires.
func tdilithium3ReshareRotationFor(
	previousCommittee, committee protocol.CommitteeID,
) (*dilithium3v1.ReshareRotationPlan, error) {
	plan, err := dilithium3v1.PlanReshareRotationForCommittees(previousCommittee, committee)
	if err != nil {
		return nil, fmt.Errorf("reshare rotation plan: %w", err)
	}
	return plan, nil
}

// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// Session derivation for the Dilithium3 v1 CNF-RSS DKG (session-derivation
// design, section 3).
//
// A session must be reproducible from chain state alone, because the DKG
// journal is keyed by the session digest
// (tdilithium3DKGRunner / newTDilithium3DKGRunner) and a restarted node only
// resumes the attempt it was already in if it rebuilds the identical session.
// Nothing here is random: the freshness that a random nonce would provide comes
// from the chain-anchored inputs (chain id, genesis, epoch, roster digest and
// the key generation derived from the epoch).

const tdilithium3DKGSessionNonceDomain = "QAU-TDILITHIUM3-V1-DKG-SESSION-NONCE"

var (
	// errTDilithium3DKGSessionUnavailable is the named fail-closed outcome of
	// session derivation: no session could be derived from the local state.
	errTDilithium3DKGSessionUnavailable = errors.New("Dilithium3 v1 DKG session is unavailable")
)

// tdilithium3DKGSessionRosterEpoch returns the epoch whose boundary roster
// anchors a session that activates for activationEpoch.
//
// The roster is read one epoch below the activation epoch: the boundary block of
// N-1 is already an ancestor of the head when epoch N begins, while epoch N's own
// boundary has just been applied and is almost never finalized yet (see the
// design, D1). Activation epochs 0 and 1 have no lower boundary to anchor on.
func tdilithium3DKGSessionRosterEpoch(activationEpoch uint64) (uint64, error) {
	if activationEpoch < 2 {
		return 0, fmt.Errorf("%w: activation epoch %d has no lower boundary to anchor on",
			errTDilithium3DKGSessionUnavailable, activationEpoch)
	}
	return activationEpoch - 1, nil
}

// tdilithium3DKGCommitteeForRoster builds the Dilithium3 v1 committee from a
// roster and returns the local node's position in it.
//
// R76a: the committee is the whole epoch roster in canonical order and
// participant IDs are position+1, with the family shape (C = roster size,
// threshold = ceil(2C/3)). Rosters smaller than the family minimum or larger
// than the family maximum fail closed; subsetting a larger set is R76b, which
// requires a consensus-anchored sampling rule to stay deterministic.
func (n *Node) tdilithium3DKGCommitteeForRoster(roster *tdilithium3DKGEpochRoster) (protocol.CommitteeID, uint8, error) {
	if roster == nil {
		return protocol.CommitteeID{}, 0, fmt.Errorf("%w: roster is missing", errTDilithium3DKGSessionUnavailable)
	}
	count := len(roster.Entries)
	threshold := protocol.Dilithium3V1ThresholdFor(uint32(count))
	if threshold == 0 {
		return protocol.CommitteeID{}, 0, fmt.Errorf("%w: epoch %d roster has %d members, outside the Dilithium3 v1 committee family [%d, %d]",
			errTDilithium3DKGSessionUnavailable, roster.Epoch, count,
			protocol.Dilithium3V1MinParticipants, protocol.Dilithium3V1MaxParticipants)
	}
	participants := make([]uint32, count)
	for position := range participants {
		participants[position] = uint32(position) + 1
	}
	committee := protocol.CommitteeID{Version: 1, Threshold: threshold, Participants: participants}
	if err := protocol.ValidateDilithium3V1Committee(committee); err != nil {
		return protocol.CommitteeID{}, 0, fmt.Errorf("%w: committee: %v", errTDilithium3DKGSessionUnavailable, err)
	}
	if n == nil || n.blockProducer == nil {
		return protocol.CommitteeID{}, 0, fmt.Errorf("%w: local validator identity is not available", errTDilithium3DKGSessionUnavailable)
	}
	address := n.blockProducer.ValidatorAddr()
	for position, entry := range roster.Entries {
		if entry.Address == address {
			return committee, uint8(position), nil
		}
	}
	return protocol.CommitteeID{}, 0, fmt.Errorf("%w: local validator %s is not in the epoch %d roster",
		errTDilithium3DKGSessionUnavailable, address.String(), roster.Epoch)
}

// tdilithium3DKGChainGenesisHash returns the genesis block hash, which anchors
// every derived session to this chain instance.
func (n *Node) tdilithium3DKGChainGenesisHash() (types.Hash, error) {
	if n == nil {
		return types.Hash{}, fmt.Errorf("%w: node is not configured", errTDilithium3DKGSessionUnavailable)
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.genesisBlock == nil || n.genesisBlock.Header == nil {
		return types.Hash{}, fmt.Errorf("%w: genesis block is not loaded", errTDilithium3DKGSessionUnavailable)
	}
	return block.ComputeBlockHash(n.genesisBlock.Header), nil
}

// tdilithium3DKGSessionNonce derives the session nonce from chain-anchored
// inputs. Every participant computes the same value with no extra round, and a
// restarted participant recomputes it (see the design, D3).
func tdilithium3DKGSessionNonce(
	chainID uint64,
	genesis types.Hash,
	keyGeneration uint64,
	activationEpoch uint64,
	committeeDigest [32]byte,
	identityRosterDigest [32]byte,
) [32]byte {
	encoded := make([]byte, 0, len(tdilithium3DKGSessionNonceDomain)+8*3+32*3)
	encoded = append(encoded, tdilithium3DKGSessionNonceDomain...)
	encoded = binary.BigEndian.AppendUint64(encoded, chainID)
	encoded = append(encoded, genesis[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, keyGeneration)
	encoded = binary.BigEndian.AppendUint64(encoded, activationEpoch)
	encoded = append(encoded, committeeDigest[:]...)
	encoded = append(encoded, identityRosterDigest[:]...)
	return sha3.Sum256(encoded)
}

// tdilithium3DKGVerifyLocalIdentity enforces decision D6: the key that signs
// every envelope must be the identity key the epoch roster publishes for this
// node's committee position. If they differ, every peer rejects this node's
// messages, so the ceremony refuses to start rather than burn a full timeout.
func (n *Node) tdilithium3DKGVerifyLocalIdentity(roster *tdilithium3DKGEpochRoster, position uint8) error {
	if n == nil || n.blockProducer == nil {
		return fmt.Errorf("%w: local validator identity is not available", errTDilithium3DKGSessionUnavailable)
	}
	if roster == nil || int(position) >= len(roster.Entries) {
		return fmt.Errorf("%w: roster position %d is out of range", errTDilithium3DKGSessionUnavailable, position)
	}
	key := n.blockProducer.ValidatorKey()
	if key == nil {
		return fmt.Errorf("%w: local validator key is not loaded", errTDilithium3DKGIdentityKeyMismatch)
	}
	if !bytes.Equal(key.PublicKeyBytes(), roster.Entries[position].PublicKey) {
		return fmt.Errorf("%w: epoch %d roster position %d", errTDilithium3DKGIdentityKeyMismatch, roster.Epoch, position)
	}
	return nil
}

// deriveTDilithium3DKGSession builds the deterministic session for an
// activation epoch: the roster captured at the boundary of activationEpoch-1,
// the fixed four-of-six committee over that roster, the derived nonce and the
// epoch-derived key generation.
//
// Depends on the experimental gates only indirectly: the roster store it reads
// is created by tdilithium3DKGEpochRosterStoreForUse, which is a no-op unless
// both gates are open.
func (n *Node) deriveTDilithium3DKGSession(activationEpoch uint64) (dilithium3v1.DKGSession, error) {
	if n == nil || n.config == nil {
		return dilithium3v1.DKGSession{}, fmt.Errorf("%w: node is not configured", errTDilithium3DKGSessionUnavailable)
	}
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	genesis, err := n.tdilithium3DKGChainGenesisHash()
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	committee, _, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	bindings, err := tdilithium3DKGRosterBindings(roster, committee)
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	rosterDigest, err := dilithium3v1.DKGIdentityRosterDigest(committee, bindings)
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	committeeDigest, err := committee.CanonicalDigest()
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	// Key generation is the activation epoch: deterministic, unique per epoch
	// and needs no consensus change. A consensus-backed counter is the follow-up
	// once reshare exists (see the design, D4).
	keyGeneration := activationEpoch
	session := dilithium3v1.DKGSession{
		Protocol:             protocol.ThresholdProtocolDilithium3V1,
		ChainID:              n.config.NetworkID,
		KeyGeneration:        keyGeneration,
		Committee:            committee,
		ActivationEpoch:      activationEpoch,
		Nonce:                tdilithium3DKGSessionNonce(n.config.NetworkID, genesis, keyGeneration, activationEpoch, committeeDigest, rosterDigest),
		IdentityRosterDigest: rosterDigest,
	}
	if err := session.Validate(); err != nil {
		return dilithium3v1.DKGSession{}, fmt.Errorf("%w: %v", errTDilithium3DKGSessionUnavailable, err)
	}
	return session, nil
}

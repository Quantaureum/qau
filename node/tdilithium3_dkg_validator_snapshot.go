// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func newTDilithium3DKGInboxFromValidatorSnapshot(
	session dilithium3v1.DKGSession,
	recipientPosition uint8,
	participantAddresses map[uint32]types.Address,
	validators []*consensus.Validator,
	peerForValidator func(types.Address) (p2p.PeerID, bool),
) (*tdilithium3DKGInbox, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if len(participantAddresses) != len(session.Committee.Participants) || len(validators) == 0 || peerForValidator == nil {
		return nil, fmt.Errorf("Dilithium3 DKG requires a complete validator and peer snapshot")
	}
	byAddress := make(map[types.Address]*consensus.Validator, len(validators))
	for _, validator := range validators {
		if validator == nil || validator.Address == (types.Address{}) {
			return nil, fmt.Errorf("Dilithium3 DKG validator snapshot contains an invalid entry")
		}
		if _, exists := byAddress[validator.Address]; exists {
			return nil, fmt.Errorf("Dilithium3 DKG validator snapshot contains a duplicate address")
		}
		byAddress[validator.Address] = validator
	}
	identities := make(map[uint32]tdilithium3DKGIdentity, len(session.Committee.Participants))
	usedAddresses := make(map[types.Address]bool, len(session.Committee.Participants))
	for _, participantID := range session.Committee.Participants {
		address, found := participantAddresses[participantID]
		validator := byAddress[address]
		if !found || usedAddresses[address] || validator == nil || !validator.Active {
			return nil, fmt.Errorf("Dilithium3 DKG committee member is missing, duplicated or inactive")
		}
		peer, mapped := peerForValidator(address)
		if !mapped || peer == "" {
			return nil, fmt.Errorf("Dilithium3 DKG committee member has no peer binding")
		}
		identities[participantID] = tdilithium3DKGIdentity{Peer: peer, ValidatorAddress: address, PublicKey: validator.PublicKeyBytes}
		usedAddresses[address] = true
	}
	return newTDilithium3DKGInboxFromIdentitySnapshot(session, recipientPosition, identities)
}

// tdilithium3DKGRosterBindings maps a roster positionally onto a committee:
// committee position i is the i-th roster entry. It is the single place where
// the roster-to-committee pairing is defined, shared by session derivation and
// by the Round 0 inbox, so both commit to exactly the same binding.
//
// A roster whose size differs from the committee is refused rather than
// subsetted, because the committee-selection rule is consensus state and is not
// reproduced in the node layer.
func tdilithium3DKGRosterBindings(roster *tdilithium3DKGEpochRoster, committee protocol.CommitteeID) ([]dilithium3v1.DKGIdentityBinding, error) {
	if roster == nil {
		return nil, fmt.Errorf("%w: roster is missing", errTDilithium3DKGEpochRosterUnavailable)
	}
	// D1: when the roster exceeds the pinned committee row, the committee is a
	// deterministic sample of it — the binding pairs committee position i with
	// the i-th selected roster entry (selection is derived from the roster
	// record itself, so recomputing it here cannot diverge).
	selection, err := tdilithium3DKGCommitteeSelection(roster)
	if err != nil {
		return nil, err
	}
	if len(selection) != len(committee.Participants) {
		return nil, fmt.Errorf("%w: epoch %d committee selection has %d members but the committee has %d",
			errTDilithium3DKGEpochRosterUnavailable, roster.Epoch, len(selection), len(committee.Participants))
	}
	bindings := make([]dilithium3v1.DKGIdentityBinding, 0, len(selection))
	for position, index := range selection {
		entry := roster.Entries[index]
		bindings = append(bindings, dilithium3v1.DKGIdentityBinding{
			ParticipantID:    committee.Participants[position],
			ValidatorAddress: [20]byte(entry.Address),
			PublicKey:        append([]byte(nil), entry.PublicKey...),
		})
	}
	return bindings, nil
}

// tdilithium3DKGEpochRosterBindings derives the ordered Round-0 identity
// bindings for a session from the roster captured at the boundary of
// rosterEpoch, and refuses any session whose committed identity roster digest is
// not exactly that roster.
//
// This is the production source of the Round 0 roster (Dilithium3 v1 CNF-RSS
// design, "Finalized-Epoch Validator Snapshot"). It replaces "take the node's
// live ValidatorSet", which is mutable state with no epoch tag and therefore
// cannot be reproduced for a past epoch.
//
// The caller supplies the roster epoch explicitly rather than relying on
// session.ActivationEpoch: a session activates for epoch N but is anchored on
// the boundary of N-1, which is already an ancestor of the head when N begins
// (see the session derivation design, D1).
func (n *Node) tdilithium3DKGEpochRosterBindings(session dilithium3v1.DKGSession, rosterEpoch uint64) ([]dilithium3v1.DKGIdentityBinding, error) {
	if err := session.Validate(); err != nil {
		return nil, err
	}
	if n == nil || n.config == nil {
		return nil, fmt.Errorf("%w: node is not configured", errTDilithium3DKGEpochRosterUnavailable)
	}
	if session.ChainID != n.config.NetworkID {
		return nil, fmt.Errorf("%w: session chain %d does not match this node's chain %d",
			errTDilithium3DKGEpochRosterUnavailable, session.ChainID, n.config.NetworkID)
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return nil, err
	}
	bindings, err := tdilithium3DKGRosterBindings(roster, session.Committee)
	if err != nil {
		return nil, err
	}
	digest, err := dilithium3v1.DKGIdentityRosterDigest(session.Committee, bindings)
	if err != nil {
		return nil, err
	}
	if digest != session.IdentityRosterDigest {
		return nil, fmt.Errorf("%w: session roster digest does not match the captured epoch %d roster",
			errTDilithium3DKGEpochRosterUnavailable, roster.Epoch)
	}
	return bindings, nil
}

// newTDilithium3DKGInboxFromCapturedEpochRoster builds the DKG inbox from the
// roster captured at the boundary of rosterEpoch instead of the node's live
// validator set, so a node that synced from a snapshot cannot silently
// substitute a different committee. Any missing, at-or-below-bootstrap, or
// mismatched roster fails closed.
func (n *Node) newTDilithium3DKGInboxFromCapturedEpochRoster(
	session dilithium3v1.DKGSession,
	recipientPosition uint8,
	rosterEpoch uint64,
	peerForValidator func(types.Address) (p2p.PeerID, bool),
) (*tdilithium3DKGInbox, error) {
	bindings, err := n.tdilithium3DKGEpochRosterBindings(session, rosterEpoch)
	if err != nil {
		return nil, err
	}
	addresses := make(map[uint32]types.Address, len(bindings))
	validators := make([]*consensus.Validator, 0, len(bindings))
	for _, binding := range bindings {
		address := types.Address(binding.ValidatorAddress)
		addresses[binding.ParticipantID] = address
		validators = append(validators, &consensus.Validator{
			Address:        address,
			Active:         true,
			PublicKeyBytes: append([]byte(nil), binding.PublicKey...),
		})
	}
	return newTDilithium3DKGInboxFromValidatorSnapshot(session, recipientPosition, addresses, validators, peerForValidator)
}

// Quantaureum Node source, version 1.0.0.
package dilithium3v1

// Offline (air-gapped) trusted-dealer generation of Dilithium3 v1 CNF-RSS
// committee shares.
//
// This entry point exists for exactly one reason: mainnet forbids any runtime
// DKG (node startup hard-block), so the genesis v1 committee key has to be
// produced on an air-gapped machine and imported per validator through the
// encrypted share store. The dealer runs the SAME deterministic mathematics
// as the distributed ceremony (DeriveRSSComponent / NewPublicContribution /
// AssembleMode3PublicKey), so the assembled group key and transcript digest
// are indistinguishable from what a runtime ceremony over the same session
// would have produced; session binding (chain ID, committee, activation
// epoch, nonce, roster digest) is preserved unchanged through DKGSession.
//
// SECURITY MODEL: this is the single place where all shares exist inside one
// process. That is acceptable only on an air-gapped ceremony machine — the
// same trust model the legacy tss_dkg_gen ceremony already operates under
// (see QAU_ALLOW_TRUSTED_DEALER_CEREMONY for the legacy family). Everything
// drawn from entropy is zeroized before return except the shares themselves.

import (
	"fmt"
	"io"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

// DealShares generates the full committee share set for one session.
//
// session must identify the real deployment (chain ID, committee, key
// generation, activation epoch, session nonce, identity roster digest) — the
// ceremony reproduces what the runtime activation path will recompute, so the
// caller derives the session with the same functions the node uses.
//
// entropy must be a cryptographic randomness source (crypto/rand.Reader on
// the ceremony machine). One 32-byte contribution is drawn per participant
// (mirroring the distributed round-3b contributions) plus one 32-byte seed
// per canonical RSS group (mirroring the per-group leader seed), so the
// dealer's draws stay inside the same domains as the interactive protocol.
//
// Returns the per-participant shares (index = participant position), the
// committee public key (generation = session.KeyGeneration), and rho (the
// public randomness, needed by callers that archive the transcript).
func DealShares(session DKGSession, entropy io.Reader) ([]*LocalShare, protocol.ThresholdKeyID, [32]byte, error) {
	if err := session.Validate(); err != nil {
		return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: %w", err)
	}
	if entropy == nil {
		return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: nil entropy source")
	}
	participants := len(session.Committee.Participants)
	groups, err := CanonicalRSSGroupsFor(participants)
	if err != nil {
		return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: committee family: %w", err)
	}

	// Deterministic session binding, identical to the runtime path.
	sessionDigest, err := session.Digest()
	if err != nil {
		return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: session digest: %w", err)
	}

	// One contribution per participant mirrors the distributed round that
	// feeds DeriveDKGRandomness, keeping the rho/global domains identical.
	contributions := make([][32]byte, participants)
	for i := range contributions {
		if err := dealNonzero(entropy, contributions[i][:]); err != nil {
			return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: contribution %d: %w", i, err)
		}
	}
	global, rho, err := DeriveDKGRandomness(session, contributions)
	if err != nil {
		return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: randomness: %w", err)
	}

	components := make([]RSSComponent, len(groups))
	contributionsPublic := make([]PublicContribution, len(groups))
	owned := make([][]RSSGroupMask, participants)
	for position := 0; position < participants; position++ {
		owned[position], err = GroupsForPositionN(uint8(position), participants)
		if err != nil {
			return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: groups for position %d: %w", position, err)
		}
	}
	for groupIndex, group := range groups {
		leader, err := group.Leader(0)
		if err != nil {
			return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: group %d leader: %w", groupIndex, err)
		}
		var seed [32]byte
		if err := dealNonzero(entropy, seed[:]); err != nil {
			return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: group %d seed: %w", groupIndex, err)
		}
		s1, s2, err := DeriveRSSComponent(sessionDigest, group, leader, global, seed)
		dealWipe(seed[:])
		if err != nil {
			return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: group %d component: %w", groupIndex, err)
		}
		contribution, err := NewPublicContribution(sessionDigest, group, leader, rho, s1, s2)
		if err != nil {
			return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: group %d contribution: %w", groupIndex, err)
		}
		contributionsPublic[groupIndex] = contribution
		digest, err := contribution.Digest()
		if err != nil {
			return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: group %d digest: %w", groupIndex, err)
		}
		components[groupIndex] = RSSComponent{
			GroupMask:          group,
			DealerPosition:     leader,
			ContributionDigest: digest,
			Multiplicity:       1,
			S1:                 s1,
			S2:                 s2,
		}
	}
	dealWipeBytes := global
	dealWipe(dealWipeBytes[:])

	publicKey, transcriptDigest, err := AssembleMode3PublicKey(rho, contributionsPublic, participants)
	if err != nil {
		return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: assemble public key: %w", err)
	}
	key := protocol.ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmDilithium3Legacy,
		Generation: session.KeyGeneration,
		PublicKey:  append([]byte(nil), publicKey[:]...),
	}

	shares := make([]*LocalShare, participants)
	for position := 0; position < participants; position++ {
		share := &LocalShare{
			Protocol:            session.Protocol,
			Key:                 key.Clone(),
			Committee:           session.Committee.Clone(),
			ParticipantID:       session.Committee.Participants[position],
			ParticipantPosition: uint8(position),
			ActivationEpoch:     session.ActivationEpoch,
			TranscriptDigest:    transcriptDigest,
			Rho:                 rho,
		}
		share.Components = make([]RSSComponent, len(owned[position]))
		for componentIndex, group := range owned[position] {
			found := false
			for groupIndex, candidate := range groups {
				if candidate == group {
					share.Components[componentIndex] = components[groupIndex]
					found = true
					break
				}
			}
			if !found {
				return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: position %d owns unknown group %x", position, uint16(group))
			}
		}
		if err := share.Validate(); err != nil {
			return nil, protocol.ThresholdKeyID{}, [32]byte{}, fmt.Errorf("dealer: share %d: %w", position, err)
		}
		shares[position] = share
	}
	return shares, key, rho, nil
}

// dealNonzero fills destination from entropy, retrying the (never expected)
// all-zero draw the same way the runtime ceremony's entropy reader does.
func dealNonzero(entropy io.Reader, destination []byte) error {
	for attempts := 0; attempts < 4; attempts++ {
		if _, err := io.ReadFull(entropy, destination); err != nil {
			return err
		}
		nonzero := false
		for _, b := range destination {
			if b != 0 {
				nonzero = true
				break
			}
		}
		if nonzero {
			return nil
		}
	}
	return fmt.Errorf("dealer: entropy returned zero repeatedly")
}

func dealWipe(buffer []byte) {
	for i := range buffer {
		buffer[i] = 0
	}
}

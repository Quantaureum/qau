// Quantaureum Node source, version 1.0.0.
package node

// Offline ceremony support for the Dilithium3 v1 committee key.
//
// Mainnet refuses any runtime DKG, so the genesis v1 committee key is
// produced on an air-gapped machine (see cmd/tdil3_ceremony) and installed
// per validator through the encrypted share store. The helpers in this file
// are the node-side halves of that flow:
//
//   - OfflineCeremonySession reproduces, byte-for-byte, the DKGSession the
//     validators will derive at the activation epoch boundary (same roster
//     epoch rule, same committee ordering, same digests, same nonce domain) —
//     the ceremony output only activates if the sessions match.
//   - InstallOfflineCeremonyShare decrypts one transported share blob and
//     stores it as the node's threshold candidate, re-encrypting under the
//     validator's own store password. The plaintext share exists only in this
//     process's memory on the machine that is trusted with the share anyway.

import (
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// OfflineCeremonyRosterEntry is one validator's identity in the roster the
// ceremony is anchored on, in the roster's canonical order. It carries only
// public information (address and identity public key, exactly what the
// on-chain roster record publishes); stake is advisory and unused for the
// at-or-below-row rosters this flow targets.
type OfflineCeremonyRosterEntry struct {
	Address   types.Address
	PublicKey []byte
	Stake     *big.Int
}

// OfflineCeremonySession derives the Dilithium3 v1 DKG session for one
// activation epoch from the roster captured at the boundary of
// activationEpoch-1. This duplicates deriveTDilithium3DKGSession's result
// without requiring a running node, so the offline ceremony machine and the
// validators compute the identical session (and therefore identical
// committee/roster digests and nonce).
func OfflineCeremonySession(
	chainID uint64,
	genesis types.Hash,
	activationEpoch uint64,
	entries []OfflineCeremonyRosterEntry,
) (dilithium3v1.DKGSession, error) {
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return dilithium3v1.DKGSession{}, err
	}
	rosterEntries := make([]tdilithium3DKGEpochRosterEntry, len(entries))
	for i, entry := range entries {
		if len(entry.PublicKey) == 0 {
			return dilithium3v1.DKGSession{}, fmt.Errorf("offline ceremony: roster entry %d has no public key", i)
		}
		rosterEntries[i] = tdilithium3DKGEpochRosterEntry{
			Address:   entry.Address,
			PublicKey: append([]byte(nil), entry.PublicKey...),
			Stake:     entry.Stake,
		}
	}
	roster := &tdilithium3DKGEpochRoster{Epoch: rosterEpoch, Entries: rosterEntries}
	selection, err := tdilithium3DKGCommitteeSelection(roster)
	if err != nil {
		return dilithium3v1.DKGSession{}, fmt.Errorf("offline ceremony: %w", err)
	}
	committee, err := tdilithium3DKGCommitteeForSelectedRoster(roster, selection)
	if err != nil {
		return dilithium3v1.DKGSession{}, fmt.Errorf("offline ceremony: %w", err)
	}
	bindings, err := tdilithium3DKGRosterBindings(roster, committee)
	if err != nil {
		return dilithium3v1.DKGSession{}, fmt.Errorf("offline ceremony: %w", err)
	}
	rosterDigest, err := dilithium3v1.DKGIdentityRosterDigest(committee, bindings)
	if err != nil {
		return dilithium3v1.DKGSession{}, fmt.Errorf("offline ceremony: roster digest: %w", err)
	}
	committeeDigest, err := committee.CanonicalDigest()
	if err != nil {
		return dilithium3v1.DKGSession{}, fmt.Errorf("offline ceremony: committee digest: %w", err)
	}
	// Key generation is the activation epoch, matching
	// deriveTDilithium3DKGSession ("deterministic, unique per epoch").
	keyGeneration := activationEpoch
	session := dilithium3v1.DKGSession{
		Protocol:             protocol.ThresholdProtocolDilithium3V1,
		ChainID:              chainID,
		KeyGeneration:        keyGeneration,
		Committee:            committee,
		ActivationEpoch:      activationEpoch,
		Nonce:                tdilithium3DKGSessionNonce(chainID, genesis, keyGeneration, activationEpoch, committeeDigest, rosterDigest),
		IdentityRosterDigest: rosterDigest,
	}
	if err := session.Validate(); err != nil {
		return dilithium3v1.DKGSession{}, fmt.Errorf("offline ceremony: %w", err)
	}
	return session, nil
}

// InstallOfflineCeremonyShare decrypts one transported share blob (the
// ceremony machine's output file) with the ceremony password and stores it as
// this node's threshold candidate, encrypted under the validator's own store
// password. Transport and store passwords may differ; the plaintext share
// exists only in this process's memory and is zeroized on all exit paths.
//
// The candidate becomes the active share only through the activation-record
// flow (threshold_activation.go), which stays unchanged: offline installation
// never bypasses activation verification.
func InstallOfflineCeremonyShare(dataDir string, encryptedShare []byte, transportPassword, storePassword []byte) (uint32, error) {
	if len(encryptedShare) == 0 || len(transportPassword) == 0 || len(storePassword) == 0 {
		return 0, fmt.Errorf("offline ceremony install: missing data dir input, share blob, or password")
	}
	plaintext, err := tss.DecryptSingleShareBlob(encryptedShare, transportPassword)
	if err != nil {
		return 0, fmt.Errorf("offline ceremony install: decrypt share: %w", err)
	}
	defer tss.SecureZero(plaintext)
	share, err := dilithium3v1.UnmarshalLocalShare(plaintext)
	if err != nil {
		return 0, fmt.Errorf("offline ceremony install: decode share: %w", err)
	}
	defer share.Zeroize()
	if err := share.Validate(); err != nil {
		return 0, fmt.Errorf("offline ceremony install: %w", err)
	}
	store := newThresholdShareStore(dataDir)
	if err := store.Store(share, storePassword); err != nil {
		return 0, fmt.Errorf("offline ceremony install: %w", err)
	}
	return share.ParticipantID, nil
}

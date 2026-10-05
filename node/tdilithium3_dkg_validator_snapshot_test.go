// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func TestTDilithium3DKGValidatorSnapshotRejectsMissingAndConflictingBindings(t *testing.T) {
	session := testTDilithium3DKGSession()
	session.IdentityRosterDigest = testTDilithium3IdentityRosterDigest(t, session, "DEVNET ONLY validator snapshot")
	addresses := make(map[uint32]types.Address, 6)
	validators := make([]*consensus.Validator, 6)
	peers := make(map[types.Address]p2p.PeerID, 6)
	for position, participantID := range session.Committee.Participants {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY validator snapshot %d", position))
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		address := types.AddressFromPublicKey(publicKey.Bytes())
		addresses[participantID] = address
		validators[position] = &consensus.Validator{Address: address, Active: true, Stake: big.NewInt(1_000_000), PublicKeyBytes: publicKey.Bytes()}
		peers[address] = p2p.PeerID(fmt.Sprintf("peer-%d", position))
	}
	resolve := func(address types.Address) (p2p.PeerID, bool) {
		peer, found := peers[address]
		return peer, found
	}
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, validators, resolve); err != nil {
		t.Fatal(err)
	}
	otherRoster := session.Clone()
	otherRoster.IdentityRosterDigest[0] ^= 1
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(otherRoster, 1, addresses, validators, resolve); err == nil {
		t.Fatal("session for another identity roster accepted")
	}
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, validators, nil); err == nil {
		t.Fatal("missing peer resolver accepted")
	}
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, append(validators, validators[0]), resolve); err == nil {
		t.Fatal("duplicate validator snapshot entry accepted")
	}
	delete(addresses, session.Committee.Participants[0])
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, validators, resolve); err == nil {
		t.Fatal("missing participant address accepted")
	}
	addresses[session.Committee.Participants[0]] = validators[0].Address
	addresses[session.Committee.Participants[1]] = validators[0].Address
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, validators, resolve); err == nil {
		t.Fatal("duplicate validator address accepted")
	}
	addresses[session.Committee.Participants[1]] = validators[1].Address
	validators[1].Active = false
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, validators, resolve); err == nil {
		t.Fatal("inactive committee member accepted")
	}
	validators[1].Active = true
	delete(peers, validators[1].Address)
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, validators, resolve); err == nil {
		t.Fatal("unmapped validator peer accepted")
	}
	peers[validators[1].Address] = peers[validators[0].Address]
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, validators, resolve); err == nil {
		t.Fatal("shared validator peer accepted")
	}
	peers[validators[1].Address] = "peer-1"
	addresses[session.Committee.Participants[1]] = types.Address{1}
	if _, err := newTDilithium3DKGInboxFromValidatorSnapshot(session, 1, addresses, validators, resolve); err == nil {
		t.Fatal("unknown validator address accepted")
	}
}

func testTDilithium3IdentityRosterDigest(t *testing.T, session dilithium3v1.DKGSession, seedPrefix string) [32]byte {
	t.Helper()
	bindings := make([]dilithium3v1.DKGIdentityBinding, len(session.Committee.Participants))
	for position, participantID := range session.Committee.Participants {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("%s %d", seedPrefix, position))
		publicKey, _ := mode3.NewKeyFromSeed(&seed)
		bindings[position] = dilithium3v1.DKGIdentityBinding{
			ParticipantID: participantID, ValidatorAddress: [20]byte(types.AddressFromPublicKey(publicKey.Bytes())), PublicKey: publicKey.Bytes(),
		}
	}
	digest, err := dilithium3v1.DKGIdentityRosterDigest(session.Committee, bindings)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

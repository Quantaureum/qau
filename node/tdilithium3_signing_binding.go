// Quantaureum Node source, version 1.0.0.
package node

// Node-side binding projections of the signing executor (design note, Slice 4).
// A signing request needs the same roster-derived inputs the DKG ceremony
// builds: the four signers' validator identities (peer, address, and Dilithium3
// key) and an identity verifier over the epoch roster, which the share store
// demands before it returns an activated share.
//
// Both projections are pure: they read the epoch roster a DKG activation was
// anchored on -- the same roster the ceremony captured (see the ceremony at
// node/tdilithium3_dkg_ceremony.go) -- and never the node's live validator set,
// which is mutable state with no epoch tag. The assembly that also touches the
// share store, the local validator key, the p2p host, and the signing journal is
// the remaining step of Slice 4.

import (
	"context"
	"crypto/sha3"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SigningIdentitiesForRoster projects the identity snapshot of the
// four active signers out of the epoch roster a DKG activation was anchored on.
// The roster-to-committee pairing is the single definition shared with the DKG
// layer (tdilithium3DKGRosterBindings), so a signing session and the DKG session
// that produced its share commit to the same binding, and every signer must have
// a peer binding or the snapshot is refused.
func tdilithium3SigningIdentitiesForRoster(
	roster *tdilithium3DKGEpochRoster,
	committee protocol.CommitteeID,
	signers []uint32,
	peerForValidator func(types.Address) (p2p.PeerID, bool),
) (map[uint32]tdilithium3SigningIdentity, error) {
	if peerForValidator == nil {
		return nil, fmt.Errorf("Dilithium3 signing identities require a peer binding")
	}
	bindings, err := tdilithium3DKGRosterBindings(roster, committee)
	if err != nil {
		return nil, err
	}
	byParticipant := make(map[uint32]dilithium3v1.DKGIdentityBinding, len(bindings))
	for _, binding := range bindings {
		byParticipant[binding.ParticipantID] = binding
	}
	identities := make(map[uint32]tdilithium3SigningIdentity, len(signers))
	for _, signer := range signers {
		binding, found := byParticipant[signer]
		if !found {
			return nil, fmt.Errorf("Dilithium3 signing signer %d is outside the epoch roster", signer)
		}
		address := types.Address(binding.ValidatorAddress)
		peer, mapped := peerForValidator(address)
		if !mapped || peer == "" {
			return nil, fmt.Errorf("Dilithium3 signing signer %s has no peer binding", address.String())
		}
		identities[signer] = tdilithium3SigningIdentity{
			Peer:             peer,
			ValidatorAddress: address,
			PublicKey:        append([]byte(nil), binding.PublicKey...),
		}
	}
	return identities, nil
}

// tdilithium3SigningShareVerifier builds the identity verifier a share-store
// load requires: it checks one committee member's Dilithium3 identity signature
// against the key the epoch roster publishes for that participant, so a share
// whose activation certificate was signed by anyone outside the captured roster
// cannot load.
func tdilithium3SigningShareVerifier(
	bindings []dilithium3v1.DKGIdentityBinding,
) (dilithium3v1.DKGIdentityVerifier, error) {
	if len(bindings) == 0 {
		return nil, fmt.Errorf("Dilithium3 signing share verifier requires roster bindings")
	}
	keys := make(map[uint32]*qcrypto.PublicKey, len(bindings))
	hashes := make(map[[32]byte]bool, len(bindings))
	for _, binding := range bindings {
		if binding.ParticipantID == 0 || len(binding.PublicKey) == 0 {
			return nil, fmt.Errorf("Dilithium3 signing share verifier requires complete roster bindings")
		}
		key, err := qcrypto.PublicKeyFromBytes(binding.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("Dilithium3 signing roster public key invalid: %w", err)
		}
		hash := sha3.Sum256(binding.PublicKey)
		if hashes[hash] {
			return nil, fmt.Errorf("Dilithium3 signing roster public key is bound to multiple participants")
		}
		hashes[hash] = true
		keys[binding.ParticipantID] = key
	}
	return func(participantID uint32, message, signature []byte) bool {
		key, found := keys[participantID]
		return found && qcrypto.Verify(key, message, signature)
	}, nil
}

// tdilithium3SigningBinding is one local signer's complete signing input for one
// activation epoch: the activated share, the four signers' identity snapshot,
// the request-long journal, and the callbacks the request schedule drives.
type tdilithium3SigningBinding struct {
	Share      *dilithium3v1.LocalShare
	Signers    []uint32
	Identities map[uint32]tdilithium3SigningIdentity
	Sign       func([]byte) ([]byte, error)
	Broadcast  func(uint8, []byte) error
	Journal    *dilithium3v1.SigningJournal
	Entropy    io.Reader

	chainID uint64
}

// close releases the binding's per-attempt state. The share stays caller-owned
// and the journal is a node-cached shared handle (closed at node shutdown, not
// here), so a concurrent session sealing another slot keeps using it.
func (binding *tdilithium3SigningBinding) close() error {
	return nil
}

// tdilithium3SigningJournalFor returns the node's shared signing journal for one
// path, opening and caching it on first use. bbolt takes an exclusive file lock
// per handle, so every concurrent seal session must share one handle; the
// SigningJournal guards its own writes with a mutex, so the shared handle is
// safe under concurrent Advance calls.
func (n *Node) tdilithium3SigningJournalFor(path string) (*dilithium3v1.SigningJournal, error) {
	if n == nil {
		return nil, fmt.Errorf("Dilithium3 signing journal cache requires a node")
	}
	n.tdilithium3SigningJournalsMu.Lock()
	defer n.tdilithium3SigningJournalsMu.Unlock()
	if journal := n.tdilithium3SigningJournals[path]; journal != nil {
		return journal, nil
	}
	journal, err := dilithium3v1.OpenSigningJournal(path)
	if err != nil {
		return nil, err
	}
	if n.tdilithium3SigningJournals == nil {
		n.tdilithium3SigningJournals = make(map[string]*dilithium3v1.SigningJournal)
	}
	n.tdilithium3SigningJournals[path] = journal
	return journal, nil
}

// closeTDilithium3SigningJournals closes every cached signing journal handle. It
// runs at node shutdown, after every seal session has stopped.
func (n *Node) closeTDilithium3SigningJournals() {
	if n == nil {
		return
	}
	n.tdilithium3SigningJournalsMu.Lock()
	defer n.tdilithium3SigningJournalsMu.Unlock()
	for path, journal := range n.tdilithium3SigningJournals {
		if journal != nil {
			_ = journal.Close()
		}
		delete(n.tdilithium3SigningJournals, path)
	}
}

// newTDilithium3SigningBinding assembles one signer's binding out of node state:
// the epoch roster the activation was anchored on, the activated share whose
// activation certificate must be signed by that roster, the local validator key
// the roster publishes (D6), the p2p host, and the signer's request-long
// journal. Every missing or mismatched piece fails closed and the loaded share
// is zeroized. The caller supplies a cryptographic entropy source
// (crypto/rand.Reader); nothing here is enabled by construction, because the
// request schedule still refuses to run outside the experimental gate and off
// the mainnet.
func (n *Node) newTDilithium3SigningBinding(
	activationEpoch uint64,
	signers []uint32,
	entropy io.Reader,
) (*tdilithium3SigningBinding, error) {
	if n == nil || n.config == nil {
		return nil, fmt.Errorf("Dilithium3 signing binding requires a configured node")
	}
	if n.config.DataDir == "" || n.config.ValidatorKeyPassword == "" {
		return nil, fmt.Errorf("Dilithium3 signing binding requires a data directory and a validator key password")
	}
	if entropy == nil {
		return nil, fmt.Errorf("Dilithium3 signing binding requires an entropy source")
	}
	if activationEpoch == 0 {
		return nil, fmt.Errorf("Dilithium3 signing binding requires a non-zero activation epoch")
	}
	if n.p2pHost == nil || n.blockProducer == nil {
		return nil, fmt.Errorf("Dilithium3 signing binding requires a p2p host and a block producer")
	}
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return nil, err
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return nil, err
	}
	committee, position, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil {
		return nil, err
	}
	bindings, err := tdilithium3DKGRosterBindings(roster, committee)
	if err != nil {
		return nil, err
	}
	verifier, err := tdilithium3SigningShareVerifier(bindings)
	if err != nil {
		return nil, err
	}
	share, err := newThresholdShareStore(n.config.DataDir).LoadActiveAtEpoch(
		activationEpoch, verifier, []byte(n.config.ValidatorKeyPassword),
	)
	if err != nil {
		return nil, fmt.Errorf("Dilithium3 signing share: %w", err)
	}
	// The share must belong to the committee generation the roster derives, at
	// the same position and activation epoch: anything else would sign with a
	// share the roster does not bind.
	committeeDigest, err := committee.CanonicalDigest()
	if err != nil {
		share.Zeroize()
		return nil, err
	}
	shareDigest, err := share.Committee.CanonicalDigest()
	if err != nil || shareDigest != committeeDigest {
		share.Zeroize()
		return nil, fmt.Errorf("Dilithium3 signing share committee does not match the epoch roster")
	}
	if share.ParticipantPosition != position || share.ActivationEpoch != activationEpoch {
		share.Zeroize()
		return nil, fmt.Errorf("Dilithium3 signing share belongs to another participant position or epoch")
	}
	if err := n.tdilithium3DKGVerifyLocalIdentity(roster, position); err != nil {
		share.Zeroize()
		return nil, err
	}
	localKey := n.blockProducer.ValidatorKey()
	if localKey == nil {
		share.Zeroize()
		return nil, fmt.Errorf("Dilithium3 signing binding requires the local validator key")
	}
	ownAddress := roster.Entries[position].Address
	ownPeer := n.p2pHost.ID()
	peerForValidator := func(address types.Address) (p2p.PeerID, bool) {
		if address == ownAddress {
			return ownPeer, ownPeer != ""
		}
		return n.p2pHost.GetPeerIDForValidator(address)
	}
	identities, err := tdilithium3SigningIdentitiesForRoster(roster, committee, signers, peerForValidator)
	if err != nil {
		share.Zeroize()
		return nil, err
	}
	if !slices.Contains(signers[:], share.ParticipantID) {
		share.Zeroize()
		return nil, fmt.Errorf(
			"Dilithium3 signing share of participant %d is not an active signer", share.ParticipantID,
		)
	}
	paths, err := newThresholdProtocolPaths(
		n.config.DataDir, share.Protocol, share.Key.Generation, share.Committee.Version, share.ParticipantID,
	)
	if err != nil {
		share.Zeroize()
		return nil, err
	}
	journal, err := n.tdilithium3SigningJournalFor(filepath.Join(paths.Root, "signing", "journal.db"))
	if err != nil {
		share.Zeroize()
		return nil, fmt.Errorf("Dilithium3 signing journal: %w", err)
	}
	return &tdilithium3SigningBinding{
		Share:      share,
		Signers:    signers,
		Identities: identities,
		Sign:       localKey.Sign,
		Broadcast:  n.p2pHost.BroadcastTSS,
		Journal:    journal,
		Entropy:    entropy,
		chainID:    n.config.NetworkID,
	}, nil
}

// request builds the base signing request of one attempt: the binding's key and
// committee, this chain, the caller's epoch, slot, and domain, the message, and
// the attempt nonce derived from that same public tuple (attempt ordinal
// included). The nonce is never drawn locally: every active signer of the
// attempt derives the same session from public inputs alone, which a networked
// four-party session requires. The party binds the slot index into the nonce
// itself.
func (binding *tdilithium3SigningBinding) request(
	epoch, slot uint64,
	domain protocol.SigningDomain,
	message []byte,
	attempt uint64,
) (protocol.SignRequest, error) {
	if binding == nil || binding.Share == nil {
		return protocol.SignRequest{}, fmt.Errorf("Dilithium3 signing binding is incomplete")
	}
	if epoch < binding.Share.ActivationEpoch {
		return protocol.SignRequest{}, fmt.Errorf(
			"Dilithium3 signing epoch %d precedes the activation epoch %d",
			epoch, binding.Share.ActivationEpoch,
		)
	}
	nonce, err := dilithium3v1.SigningRequestAttemptNonce(binding.chainID, epoch, slot, domain, message, attempt)
	if err != nil {
		return protocol.SignRequest{}, fmt.Errorf("Dilithium3 signing attempt nonce: %w", err)
	}
	request := protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          binding.Share.Key.Clone(),
		Committee:    binding.Share.Committee.Clone(),
		ChainID:      binding.chainID,
		Epoch:        epoch,
		Slot:         slot,
		Domain:       domain,
		Message:      append([]byte(nil), message...),
		AttemptNonce: nonce,
	}
	if err := request.Validate(); err != nil {
		return protocol.SignRequest{}, fmt.Errorf("Dilithium3 signing request: %w", err)
	}
	return request, nil
}

// signWithTDilithium3Signing runs one signing attempt for one message over the
// network and returns the signature with every candidate slot's outcome. It is
// the entry point the finality and sealing wiring calls behind the gates; the
// schedule itself refuses a mainnet node and a closed gate before any party
// starts. The attempt ordinal is part of the request nonce, so a retry is a
// fresh session and every active signer of the attempt derives the same one.
func (n *Node) signWithTDilithium3Signing(
	ctx context.Context,
	binding *tdilithium3SigningBinding,
	epoch, slot uint64,
	domain protocol.SigningDomain,
	message []byte,
	attempt uint64,
) ([]byte, []tdilithium3SigningRequestOutcome, error) {
	if binding == nil {
		return nil, nil, fmt.Errorf("Dilithium3 signing requires a binding")
	}
	request, err := binding.request(epoch, slot, domain, message, attempt)
	if err != nil {
		return nil, nil, err
	}
	schedule, err := newTDilithium3SigningSchedule(n, tdilithium3SigningPartyConfig{
		Request:    request,
		Share:      binding.Share,
		Signers:    binding.Signers,
		Journal:    binding.Journal,
		Identities: binding.Identities,
		Sign:       binding.Sign,
		Broadcast:  binding.Broadcast,
		Entropy:    binding.Entropy,
	})
	if err != nil {
		return nil, nil, err
	}
	return schedule.run(ctx)
}

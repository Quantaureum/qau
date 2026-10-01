// Quantaureum Node source, version 1.0.0.
package node

// Tests of the roster-derived signing binding projections: the four signers'
// identity snapshot and the share-store verifier both come from the epoch
// roster a DKG activation was anchored on, and every incomplete or foreign
// binding fails closed.

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SigningBindingTestFixture is one epoch roster of six deterministic
// DEVNET ONLY validator identities with their peer bindings.
type tdilithium3SigningBindingTestFixture struct {
	roster      *tdilithium3DKGEpochRoster
	committee   protocol.CommitteeID
	signers     [4]uint32
	peers       map[types.Address]p2p.PeerID
	privateKeys map[types.Address]*mode3.PrivateKey
}

func tdilithium3SigningBindingTestFixtureFor(t *testing.T) *tdilithium3SigningBindingTestFixture {
	t.Helper()
	committee := protocol.CommitteeID{
		Version: 3, Threshold: protocol.ThresholdV1Threshold, Participants: []uint32{1, 2, 3, 4, 5, 6},
	}
	entries := make([]tdilithium3DKGEpochRosterEntry, 0, len(committee.Participants))
	peers := make(map[types.Address]p2p.PeerID, len(committee.Participants))
	privateKeys := make(map[types.Address]*mode3.PrivateKey, len(committee.Participants))
	for index := range committee.Participants {
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY signing roster key %d", index))
		publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
		address := types.AddressFromPublicKey(publicKey.Bytes())
		entries = append(entries, tdilithium3DKGEpochRosterEntry{Address: address, PublicKey: publicKey.Bytes()})
		peers[address] = p2p.PeerID(fmt.Sprintf("peer-%d", index))
		privateKeys[address] = privateKey
	}
	return &tdilithium3SigningBindingTestFixture{
		roster: &tdilithium3DKGEpochRoster{
			Epoch: 2, BoundaryHash: types.Hash{0x51}, Entries: entries, Digest: [32]byte{0x52},
		},
		committee:   committee,
		signers:     [4]uint32{1, 2, 3, 4},
		peers:       peers,
		privateKeys: privateKeys,
	}
}

// resolver maps roster addresses to their peers, refusing one address when the
// caller asks for a missing peer binding.
func (fixture *tdilithium3SigningBindingTestFixture) resolver(
	deny types.Address,
) func(types.Address) (p2p.PeerID, bool) {
	return func(address types.Address) (p2p.PeerID, bool) {
		if address == deny {
			return "", false
		}
		peer, found := fixture.peers[address]
		return peer, found
	}
}

// TestTDilithium3SigningIdentitiesForRoster requires the projection to return
// the four signers' identities, to refuse signers outside the roster or without
// a peer, and to keep refusing a roster that does not match the committee. The
// projected snapshot must be accepted by the executor inbox constructor.
func TestTDilithium3SigningIdentitiesForRoster(t *testing.T) {
	fixture := tdilithium3SigningBindingTestFixtureFor(t)
	identities, err := tdilithium3SigningIdentitiesForRoster(
		fixture.roster, fixture.committee, fixture.signers, fixture.resolver(types.Address{}),
	)
	if err != nil {
		t.Fatalf("identities: %v", err)
	}
	if len(identities) != 4 {
		t.Fatalf("%d identities, want 4", len(identities))
	}
	for index, signer := range fixture.signers {
		entry := fixture.roster.Entries[index]
		identity, found := identities[signer]
		if !found {
			t.Fatalf("signer %d is missing", signer)
		}
		if identity.ValidatorAddress != entry.Address || identity.Peer != fixture.peers[entry.Address] ||
			string(identity.PublicKey) != string(entry.PublicKey) {
			t.Fatalf("signer %d identity %+v does not match the roster entry", signer, identity)
		}
	}
	context := tdilithium3SigningContext{
		SessionID: [32]byte{0x53}, KeyGeneration: 7, CommitteeVersion: fixture.committee.Version,
		Signers: fixture.signers,
	}
	if _, err := newTDilithium3SigningInboxFromIdentitySnapshot(context, identities); err != nil {
		t.Fatalf("projected snapshot refused by the inbox: %v", err)
	}
	if _, err := tdilithium3SigningIdentitiesForRoster(
		fixture.roster, fixture.committee, [4]uint32{1, 2, 3, 9}, fixture.resolver(types.Address{}),
	); err == nil {
		t.Fatal("signer outside the roster accepted")
	}
	denied := fixture.roster.Entries[2].Address
	if _, err := tdilithium3SigningIdentitiesForRoster(
		fixture.roster, fixture.committee, fixture.signers, fixture.resolver(denied),
	); err == nil {
		t.Fatal("signer without a peer binding accepted")
	}
	if _, err := tdilithium3SigningIdentitiesForRoster(
		nil, fixture.committee, fixture.signers, fixture.resolver(types.Address{}),
	); err == nil {
		t.Fatal("missing roster accepted")
	}
	shortRoster := *fixture.roster
	shortRoster.Entries = fixture.roster.Entries[:5]
	if _, err := tdilithium3SigningIdentitiesForRoster(
		&shortRoster, fixture.committee, fixture.signers, fixture.resolver(types.Address{}),
	); err == nil {
		t.Fatal("roster that does not match the committee accepted")
	}
	if _, err := tdilithium3SigningIdentitiesForRoster(
		fixture.roster, fixture.committee, fixture.signers, nil,
	); err == nil {
		t.Fatal("missing peer binding function accepted")
	}
}

// TestNewTDilithium3SigningBindingFailsClosed requires every missing node input
// to be refused before any roster or share is touched. The roster, quorum, and
// store path needs a p2p host, a block producer, a captured epoch roster, and a
// stored share, so the development-network integration covers it.
func TestNewTDilithium3SigningBindingFailsClosed(t *testing.T) {
	signers := [4]uint32{1, 2, 3, 4}
	var unconfigured *Node
	if _, err := unconfigured.newTDilithium3SigningBinding(1, signers, rand.Reader); err == nil {
		t.Fatal("unconfigured node accepted")
	}
	incomplete := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	if _, err := incomplete.newTDilithium3SigningBinding(1, signers, rand.Reader); err == nil {
		t.Fatal("node without a data directory accepted")
	}
	configured := &Node{config: &Config{
		NetworkID: TestnetNetworkID, DataDir: t.TempDir(), ValidatorKeyPassword: "test",
	}}
	if _, err := configured.newTDilithium3SigningBinding(1, signers, nil); err == nil {
		t.Fatal("missing entropy accepted")
	}
	if _, err := configured.newTDilithium3SigningBinding(0, signers, rand.Reader); err == nil {
		t.Fatal("zero activation epoch accepted")
	}
	if _, err := configured.newTDilithium3SigningBinding(1, signers, rand.Reader); err == nil {
		t.Fatal("node without a p2p host and a block producer accepted")
	}
}

// TestTDilithium3SigningBindingRequestFailsClosed requires the request builder
// to refuse an incomplete binding, an epoch before the activation, and a share
// that does not validate.
func TestTDilithium3SigningBindingRequestFailsClosed(t *testing.T) {
	var missing *tdilithium3SigningBinding
	if _, err := missing.request(1, 1, protocol.SigningDomainFinality, []byte("msg"), 0); err == nil {
		t.Fatal("missing binding accepted")
	}
	early := &tdilithium3SigningBinding{
		Share:   &dilithium3v1.LocalShare{ActivationEpoch: 5},
		chainID: 1669,
	}
	if _, err := early.request(4, 1, protocol.SigningDomainFinality, []byte("msg"), 0); err == nil {
		t.Fatal("epoch before the activation accepted")
	}
	invalidShare := &tdilithium3SigningBinding{
		Share:   &dilithium3v1.LocalShare{ActivationEpoch: 1},
		chainID: 1669,
	}
	if _, err := invalidShare.request(1, 1, protocol.SigningDomainFinality, []byte("msg"), 0); err == nil {
		t.Fatal("invalid share accepted")
	}
	noChain := &tdilithium3SigningBinding{
		Share:   testThresholdStoreShare(t, 1),
		chainID: 0,
	}
	if _, err := noChain.request(noChain.Share.ActivationEpoch, 1, protocol.SigningDomainFinality, []byte("msg"), 0); err == nil {
		t.Fatal("zero chain ID accepted")
	}
}

// TestTDilithium3SigningBindingRequestDerivesTheAttemptNonce requires the
// request builder to derive the attempt nonce from the seal tuple instead of
// drawing it locally: two signers of one attempt build the same request, and a
// retry at a higher ordinal builds a fresh one.
func TestTDilithium3SigningBindingRequestDerivesTheAttemptNonce(t *testing.T) {
	share := testThresholdStoreShare(t, 1)
	binding := &tdilithium3SigningBinding{Share: share, chainID: 1669}
	message := []byte("QAU-TDILITHIUM3-V1-SIGNING-BINDING-NONCE")
	epoch := share.ActivationEpoch + 1
	request, err := binding.request(epoch, 64, protocol.SigningDomainFinality, message, 0)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	want, err := dilithium3v1.SigningRequestAttemptNonce(1669, epoch, 64, protocol.SigningDomainFinality, message, 0)
	if err != nil {
		t.Fatalf("derived nonce: %v", err)
	}
	if request.AttemptNonce != want {
		t.Fatal("request nonce is not the derived attempt nonce")
	}
	again, err := binding.request(epoch, 64, protocol.SigningDomainFinality, message, 0)
	if err != nil || again.AttemptNonce != request.AttemptNonce {
		t.Fatalf("request nonce is not deterministic: %v", err)
	}
	retry, err := binding.request(epoch, 64, protocol.SigningDomainFinality, message, 1)
	if err != nil {
		t.Fatalf("retry request: %v", err)
	}
	if retry.AttemptNonce == request.AttemptNonce {
		t.Fatal("a retry reused the attempt nonce")
	}
	otherMessage, err := binding.request(epoch, 64, protocol.SigningDomainFinality, []byte("QAU-TDILITHIUM3-V1-SIGNING-BINDING-OTHER"), 0)
	if err != nil {
		t.Fatalf("other message: %v", err)
	}
	if otherMessage.AttemptNonce == request.AttemptNonce {
		t.Fatal("a different message reused the attempt nonce")
	}
}

// TestSignWithTDilithium3SigningFailsClosed requires the entry point to refuse a
// missing binding and a binding whose request cannot be built, before any slot
// or party exists.
func TestSignWithTDilithium3SigningFailsClosed(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := node.signWithTDilithium3Signing(ctx, nil, 1, 1, protocol.SigningDomainFinality, []byte("m"), 0); err == nil {
		t.Fatal("missing binding accepted")
	}
	binding := &tdilithium3SigningBinding{
		Share:   &dilithium3v1.LocalShare{ActivationEpoch: 1},
		Entropy: rand.Reader,
		chainID: 1669,
	}
	if _, _, err := node.signWithTDilithium3Signing(ctx, binding, 1, 1, protocol.SigningDomainFinality, []byte("m"), 0); err == nil {
		t.Fatal("binding with an invalid share accepted")
	}
}

// TestTDilithium3SigningShareVerifier requires the verifier to accept only the
// roster key of the claimed participant, and to refuse incomplete or ambiguous
// roster bindings.
func TestTDilithium3SigningShareVerifier(t *testing.T) {
	fixture := tdilithium3SigningBindingTestFixtureFor(t)
	bindings, err := tdilithium3DKGRosterBindings(fixture.roster, fixture.committee)
	if err != nil {
		t.Fatalf("bindings: %v", err)
	}
	verifier, err := tdilithium3SigningShareVerifier(bindings)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	message := []byte("QAU-TDILITHIUM3-V1-SIGNING-BINDING-TEST")
	signature := make([]byte, mode3.SignatureSize)
	address := fixture.roster.Entries[2].Address
	mode3.SignTo(fixture.privateKeys[address], message, signature)
	if !verifier(3, message, signature) {
		t.Fatal("roster signature rejected")
	}
	if verifier(4, message, signature) {
		t.Fatal("roster signature accepted for another participant")
	}
	if verifier(99, message, signature) {
		t.Fatal("roster signature accepted for an unknown participant")
	}
	if verifier(3, message, make([]byte, mode3.SignatureSize)) {
		t.Fatal("zero signature accepted")
	}
	if _, err := tdilithium3SigningShareVerifier(nil); err == nil {
		t.Fatal("empty bindings accepted")
	}
	if _, err := tdilithium3SigningShareVerifier([]dilithium3v1.DKGIdentityBinding{
		{ParticipantID: 1, ValidatorAddress: [20]byte{}, PublicKey: []byte{1, 2, 3}},
	}); err == nil {
		t.Fatal("malformed roster key accepted")
	}
	if _, err := tdilithium3SigningShareVerifier([]dilithium3v1.DKGIdentityBinding{
		{ParticipantID: 1, ValidatorAddress: [20]byte{0x01}, PublicKey: bindings[0].PublicKey},
		{ParticipantID: 2, ValidatorAddress: [20]byte{0x02}, PublicKey: bindings[0].PublicKey},
	}); err == nil {
		t.Fatal("duplicate roster key accepted")
	}
}

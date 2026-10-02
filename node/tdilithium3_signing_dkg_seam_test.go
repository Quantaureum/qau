// Quantaureum Node source, version 1.0.0.
package node

// Tests of the DKG-to-signing seam: the four signers hold the shares a real
// six-node DKG ceremony produced and persisted, load them back through the
// share store, and run the production request schedule over the real
// transport, the real authenticated inbox, and the real p2p routing. The
// resulting signature must verify natively against the group public key the
// ceremony assembled, which is the only assertion that ties key generation to
// signature production.
//
// Every negative case fails closed: a signer set the share is not part of, a
// share tampered with after the ceremony, a mutated signed message, and a
// response part corrupted in flight must all fail closed rather than produce a
// signature the mode3 verifier accepts under the ceremony's group key.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SeamTestChainID is the chain ID the seam tests run under: the
// testnet ID, because the admissibility gates permanently exclude mainnet and
// the seam needs every other gate open.
const tdilithium3SeamTestChainID = TestnetNetworkID

// tdilithium3SeamTestMessage is the deterministic payload the seam signs. A
// mutation of it is a mutation of the signed message, which the mode3 verifier
// must refuse.
const tdilithium3SeamTestMessage = "QAU-TDILITHIUM3-V1-DKG-SEAM"

// tdilithium3SeamSlotTimeout bounds one candidate slot, so a session that
// cannot converge is closed rather than retried forever.
const tdilithium3SeamSlotTimeout = 5 * time.Second

// tdilithium3SeamSlots is how many candidate slots one seam request runs. The
// executor rejects a candidate unless every signer accepts it, and the
// per-slot acceptance rate the sampler parameters predict is about one in
// ten, so eleven candidates accept with high probability. This mirrors the
// production schedule, which stops at the same bound, so the seam exercises the
// retry path a live node relies on rather than a single lucky slot.
const tdilithium3SeamSlots = dilithium3v1.SigningParallelSlots

// tdilithium3SeamRequests bounds the retries of a request whose candidate
// slots were all filtered. Each is an independent draw with a per-slot
// acceptance rate near 0.10, so a handful of requests converges with
// probability far above any tolerable flake.
const tdilithium3SeamRequests = 8

// tdilithium3SeamFixture is the DKG half of the seam: the six ceremony
// runners, their persisted candidate shares, the assembled group public key,
// and the identity material the signing half needs to authenticate envelopes.
type tdilithium3SeamFixture struct {
	session     dilithium3v1.DKGSession
	shares      [6]*dilithium3v1.LocalShare
	groupKey    []byte
	identities  map[uint32]tdilithium3SigningIdentity
	privateKeys map[uint32]*mode3.PrivateKey
	peers       map[uint32]p2p.PeerID
}

// tdilithium3SeamFixtureFor runs one six-node DKG ceremony to completion and
// returns the persisted shares together with the group public key. The shares
// are reloaded from the share store rather than taken from the run results, so
// the seam covers the persistence path the signing half actually reads.
func tdilithium3SeamFixtureFor(t *testing.T) *tdilithium3SeamFixture {
	t.Helper()
	runners, transport := testTDilithium3DKGRunners(t)
	results, err := runTDilithium3DKGCluster(context.Background(), runners, transport, tdilithium3DKGFaultPlan{})
	if err != nil {
		t.Fatalf("six-node DKG cluster: %v", err)
	}

	fixture := &tdilithium3SeamFixture{
		session:     runners[0].session.Clone(),
		groupKey:    append([]byte(nil), results[0].PublicKey[:]...),
		identities:  make(map[uint32]tdilithium3SigningIdentity, len(results)),
		privateKeys: make(map[uint32]*mode3.PrivateKey, len(results)),
		peers:       make(map[uint32]p2p.PeerID, len(results)),
	}
	for position, result := range results {
		loaded, err := runners[position].shareStore.LoadCandidate(
			result.Share.Key.Generation, result.Share.ParticipantID, runners[position].password,
		)
		if err != nil {
			t.Fatalf("participant %d load candidate: %v", position, err)
		}
		t.Cleanup(loaded.Zeroize)
		fixture.shares[position] = loaded

		// The signing envelope is authenticated with the participant's
		// validator key, which the DKG roster binds. The ceremony fixture
		// carries no key material, so each participant gets a deterministic
		// DEVNET ONLY one and the signing identity snapshot is built from it.
		var seed [mode3.SeedSize]byte
		copy(seed[:], fmt.Sprintf("DEVNET ONLY seam identity %d", position))
		publicKey, privateKey := mode3.NewKeyFromSeed(&seed)
		participantID := loaded.ParticipantID
		peer := p2p.PeerID(fmt.Sprintf("seam-peer-%d", participantID))
		fixture.privateKeys[participantID] = privateKey
		fixture.peers[participantID] = peer
		fixture.identities[participantID] = tdilithium3SigningIdentity{
			Peer:             peer,
			ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()),
			PublicKey:        publicKey.Bytes(),
		}
	}
	return fixture
}

// signersFor returns the fixed four-signer subset of the seal path: the first
// four committee participants in canonical order.
func (fixture *tdilithium3SeamFixture) signersFor() []uint32 {
	signers := make([]uint32, 4)
	for index := range signers {
		signers[index] = fixture.session.Committee.Participants[index]
	}
	return signers
}

// shareOf returns this participant's persisted share.
func (fixture *tdilithium3SeamFixture) shareOf(participantID uint32) (*dilithium3v1.LocalShare, error) {
	for _, share := range fixture.shares {
		if share != nil && share.ParticipantID == participantID {
			return share, nil
		}
	}
	return nil, fmt.Errorf("seam fixture has no share of participant %d", participantID)
}

// tdilithium3SeamRequest builds the base signing request of one seam request
// from the ceremony's own public inputs, using the same attempt-nonce
// derivation the seal path uses.
func tdilithium3SeamRequest(
	t *testing.T,
	share *dilithium3v1.LocalShare,
	epoch, slot uint64,
	message []byte,
) protocol.SignRequest {
	t.Helper()
	nonce, err := dilithium3v1.SigningRequestAttemptNonce(
		tdilithium3SeamTestChainID, epoch, slot, protocol.SigningDomainFinality, message, 0,
	)
	if err != nil {
		t.Fatalf("attempt nonce: %v", err)
	}
	request := protocol.SignRequest{
		Protocol:     protocol.ThresholdProtocolDilithium3V1,
		Key:          share.Key.Clone(),
		Committee:    share.Committee.Clone(),
		ChainID:      tdilithium3SeamTestChainID,
		Epoch:        epoch,
		Slot:         slot,
		Domain:       protocol.SigningDomainFinality,
		Message:      append([]byte(nil), message...),
		AttemptNonce: nonce,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("seam request: %v", err)
	}
	return request
}

// tdilithium3SeamParty is one signer of one seam request: the node that owns
// the slot driver and its authenticated inbox, and its peer identity.
type tdilithium3SeamParty struct {
	node  *Node
	peer  p2p.PeerID
	index int
}

// tdilithium3SeamNetwork routes broadcasts between the seam parties through the
// real TSS message path, so every round message is encoded, authenticated,
// decoded, and verified exactly as it is on a live network. An optional hook
// lets a test corrupt one message in flight.
type tdilithium3SeamNetwork struct {
	mu    sync.Mutex
	parts []*tdilithium3SeamParty
	// corrupt rewrites one outbound message before it reaches the receivers. It
	// receives the sender index, the p2p message type, and the payload the
	// sender encoded, and returns the replacement payload.
	corrupt func(from int, messageType uint8, payload []byte) ([]byte, bool)
}

func (network *tdilithium3SeamNetwork) broadcast(from int, messageType uint8, encoded []byte) error {
	network.mu.Lock()
	parts := append([]*tdilithium3SeamParty(nil), network.parts...)
	corrupt := network.corrupt
	network.mu.Unlock()
	if corrupt != nil {
		if replacement, changed := corrupt(from, messageType, encoded); changed {
			encoded = replacement
		}
	}
	for _, part := range parts {
		if part.index == from {
			continue
		}
		part.node.handleTSSMessage(p2p.PeerMessage{
			From: parts[from].peer, Type: messageType, Payload: append([]byte(nil), encoded...),
		})
	}
	return nil
}

// tdilithium3SeamHarness is the four-party signing network of one seam
// request. Every signer runs the production request schedule, so the candidate
// slots, the per-slot material, the per-slot transport and inbox, and the
// per-party rejection retry are the ones a live node would run.
type tdilithium3SeamHarness struct {
	fixture  *tdilithium3SeamFixture
	network  *tdilithium3SeamNetwork
	schedule []*tdilithium3SigningRequestSchedule
	request  protocol.SignRequest
}

// tdilithium3SeamHarnessFor builds the four signers' request schedules of one
// seam request over the fixture's persisted shares, each signer with its own
// node, journal, identity key, and entropy source, exactly as four signer
// processes would hold them.
func tdilithium3SeamHarnessFor(
	t *testing.T,
	fixture *tdilithium3SeamFixture,
	signers []uint32,
	request protocol.SignRequest,
	slotTimeout time.Duration,
) *tdilithium3SeamHarness {
	t.Helper()
	identities := make(map[uint32]tdilithium3SigningIdentity, len(signers))
	for _, signer := range signers {
		identity, found := fixture.identities[signer]
		if !found {
			t.Fatalf("seam fixture has no identity of signer %d", signer)
		}
		identities[signer] = identity
	}
	if slotTimeout <= 0 {
		slotTimeout = tdilithium3SeamSlotTimeout
	}

	network := &tdilithium3SeamNetwork{}
	harness := &tdilithium3SeamHarness{fixture: fixture, network: network, request: request}
	root := t.TempDir()
	for index, signer := range signers {
		signerShare, err := fixture.shareOf(signer)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := dilithium3v1.OpenSigningJournal(filepath.Join(root, fmt.Sprintf("signer-%d", signer), "journal.db"))
		if err != nil {
			t.Fatalf("signer %d journal: %v", signer, err)
		}
		t.Cleanup(func() { _ = journal.Close() })

		part := &tdilithium3SeamParty{
			node:  &Node{config: &Config{NetworkID: tdilithium3SeamTestChainID}},
			peer:  fixture.peers[signer],
			index: index,
		}
		network.parts = append(network.parts, part)

		privateKey := fixture.privateKeys[signer]
		sign := func(message []byte) ([]byte, error) {
			signature := make([]byte, mode3.SignatureSize)
			mode3.SignTo(privateKey, message, signature)
			return signature, nil
		}
		// The production schedule mints each candidate slot's own one-time
		// record and binds the wallet party, the identity snapshot, and the
		// per-slot transport and inbox to that slot's session.
		schedule, err := newTDilithium3SigningSchedule(part.node, tdilithium3SigningPartyConfig{
			Request: request, Share: signerShare, Signers: signers,
			Journal: journal, Identities: identities, Sign: sign,
			Broadcast: func(messageType uint8, encoded []byte) error {
				return network.broadcast(index, messageType, encoded)
			},
			Entropy:     rand.Reader,
			Slots:       dilithium3v1.SigningParallelSlots,
			SlotTimeout: slotTimeout,
		})
		if err != nil {
			t.Fatalf("signer %d schedule: %v", signer, err)
		}
		harness.schedule = append(harness.schedule, schedule)
	}
	return harness
}

// run drives all four signers' request schedules to completion and returns the
// signature of each plus the failures.
func (harness *tdilithium3SeamHarness) run(ctx context.Context) ([][]byte, []error) {
	signatures := make([][]byte, len(harness.schedule))
	failures := make([]error, len(harness.schedule))
	var wait sync.WaitGroup
	for index, schedule := range harness.schedule {
		wait.Add(1)
		go func(index int, schedule *tdilithium3SigningRequestSchedule) {
			defer wait.Done()
			signature, _, err := schedule.run(ctx)
			signatures[index], failures[index] = signature, err
		}(index, schedule)
	}
	wait.Wait()
	return signatures, failures
}

// signOne runs one seam request and requires every signer to return the same
// signature, which the mode3 verifier must accept under the ceremony's group
// public key. An exhausted request is reported to the caller, which retries
// with a fresh request.
func (harness *tdilithium3SeamHarness) signOne(t *testing.T) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	signatures, failures := harness.run(ctx)
	for index, failure := range failures {
		if failure != nil {
			if errors.Is(failure, errTDilithium3SigningRequestExhausted) {
				return nil
			}
			t.Fatalf("signer %d: %v", index, failure)
		}
	}
	if len(signatures) == 0 {
		t.Fatal("seam produced no signature")
	}
	signature := signatures[0]
	if len(signature) != qcrypto.Dilithium3SignatureSize {
		t.Fatalf("seam signature size = %d, want %d", len(signature), qcrypto.Dilithium3SignatureSize)
	}
	for index, other := range signatures[1:] {
		if !bytes.Equal(signature, other) {
			t.Fatalf("signer %d produced a different signature", index+1)
		}
	}
	if err := qcrypto.VerifySignatureForAlgorithm(
		qcrypto.SignatureAlgorithmDilithium3Legacy, harness.fixture.groupKey, harness.request.Message, nil, signature,
	); err != nil {
		t.Fatalf("seam signature does not verify under the DKG group key: %v", err)
	}
	return signature
}

// tdilithium3SeamSign drives the seam to a signature, retrying a request whose
// candidate slots were all filtered with a fresh request. Each retry is a new
// seal tuple, so it is a new session with its own one-time material, exactly as
// the seal path retries with a higher attempt ordinal.
func tdilithium3SeamSign(
	t *testing.T,
	fixture *tdilithium3SeamFixture,
	signers []uint32,
	share *dilithium3v1.LocalShare,
	firstSlot uint64,
) []byte {
	t.Helper()
	message := []byte(tdilithium3SeamTestMessage)
	for attempt := 0; attempt < tdilithium3SeamRequests; attempt++ {
		request := tdilithium3SeamRequest(
			t, share, fixture.session.ActivationEpoch, firstSlot+uint64(attempt), message,
		)
		harness := tdilithium3SeamHarnessFor(t, fixture, signers, request, 0)
		if signature := harness.signOne(t); signature != nil {
			return signature
		}
	}
	t.Fatalf("seam did not converge in %d requests of %d candidate slots", tdilithium3SeamRequests, tdilithium3SeamSlots)
	return nil
}

// TestTDilithium3DKGSeamSignsWithCeremonyShares requires the four signers of
// the fixed seal subset to sign with the shares the six-node ceremony produced
// and persisted, running the production request schedule over the real
// transport, inbox, and routing, and requires the resulting signature to verify
// natively against the group public key that same ceremony assembled. This is
// the seam both halves of the protocol meet at: without it a key-generation
// bug and a signing bug could each pass their own tests and still not
// interoperate.
func TestTDilithium3DKGSeamSignsWithCeremonyShares(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	signers := fixture.signersFor()
	share, err := fixture.shareOf(signers[0])
	if err != nil {
		t.Fatal(err)
	}
	request := tdilithium3SeamRequest(
		t, share, fixture.session.ActivationEpoch, 64, []byte(tdilithium3SeamTestMessage),
	)
	if signature := tdilithium3SeamHarnessFor(t, fixture, signers, request, 0).signOne(t); signature != nil {
		return
	}
	// The first request was filtered out; a fresh request is its own session.
	tdilithium3SeamSign(t, fixture, signers, share, 64)
}

// TestTDilithium3DKGSeamFailsClosed requires every seam that cannot honestly
// sign to fail closed: a signer set the share is not part of, a share tampered
// with after the ceremony, a mutated signed message, and a response part
// corrupted in flight. None of them may produce a signature the mode3 verifier
// accepts under the ceremony's group key.
func TestTDilithium3DKGSeamFailsClosed(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	signers := fixture.signersFor()
	share, err := fixture.shareOf(signers[0])
	if err != nil {
		t.Fatal(err)
	}
	epoch := fixture.session.ActivationEpoch
	message := []byte(tdilithium3SeamTestMessage)

	t.Run("signer set excludes the share holder", func(t *testing.T) {
		// A signer set the share is not part of cannot host that share's
		// party, so the session never starts.
		excluded := make([]uint32, 4)
		copy(excluded, signers[1:])
		excluded[3] = fixture.session.Committee.Participants[5]
		if excluded[0] >= excluded[1] || excluded[1] >= excluded[2] || excluded[2] >= excluded[3] {
			t.Skip("fixture committee does not yield a strictly ascending alternate set")
		}
		_, err := dilithium3v1.NewSigningExecutorParty(dilithium3v1.SigningExecutorPartyConfig{
			Request: tdilithium3SeamRequest(t, share, epoch, 65, message),
			Share:   share,
			Signers: excluded,
			Slot:    1,
			Journal: tdilithium3SeamTestJournal(t),
			Record:  tdilithium3SeamTestRecord(t, signers[0]),
			Entropy: rand.Reader,
		})
		if err == nil {
			t.Fatal("a party accepted a signer set that excludes its own share")
		}
	})

	t.Run("share tampered after the ceremony", func(t *testing.T) {
		// A share whose secret component no longer matches the key the request
		// binds cannot produce a signature the group key verifies. The party
		// either refuses the tampered share or signs under a foreign key; in
		// neither case may a signature verify under the ceremony's group key.
		// Components is a slice since R76a: copy the backing array too, so the
		// tampered variant never aliases the fixture's honest share.
		copied := *share
		copied.Components = append([]dilithium3v1.RSSComponent(nil), share.Components...)
		copied.Components[0].S1[0][0] = dilithium3v1.Add(copied.Components[0].S1[0], dilithium3v1.Poly{0x7f})[0]
		party, err := dilithium3v1.NewSigningExecutorParty(dilithium3v1.SigningExecutorPartyConfig{
			Request: tdilithium3SeamRequest(t, share, epoch, 66, message),
			Share:   &copied,
			Signers: signers,
			Slot:    1,
			Journal: tdilithium3SeamTestJournal(t),
			Record:  tdilithium3SeamTestRecord(t, signers[0]),
			Entropy: rand.Reader,
		})
		if err != nil {
			// The party refused the tampered share outright.
			return
		}
		// The party accepted it, so it must be a single slot with no peers: it
		// cannot complete, and any signature it could still produce would be
		// bound to a key the ceremony never assembled.
		if err := party.Start(); err != nil {
			return
		}
		if signature, finishErr := party.Finish(); finishErr == nil && len(signature) != 0 {
			if err := qcrypto.VerifySignatureForAlgorithm(
				qcrypto.SignatureAlgorithmDilithium3Legacy, fixture.groupKey, message, nil, signature,
			); err == nil {
				t.Fatal("a tampered share produced a signature the ceremony group key accepts")
			}
		}
	})

	t.Run("mutated signed message", func(t *testing.T) {
		// An honest seam signature must not verify a mutated message: the
		// binding the executor signs is the whole message, not a prefix of it.
		signature := tdilithium3SeamSign(t, fixture, signers, share, 67)
		mutated := append(append([]byte(nil), message...), 0)
		if err := qcrypto.VerifySignatureForAlgorithm(
			qcrypto.SignatureAlgorithmDilithium3Legacy, fixture.groupKey, mutated, nil, signature,
		); err == nil {
			t.Fatal("the seam signature verified against a mutated message")
		}
	})

	t.Run("response part corrupted in flight", func(t *testing.T) {
		// A response part that does not open its own commitment fails the
		// combine check, so no signer can publish a verifying signature.
		harness := tdilithium3SeamHarnessFor(
			t, fixture, signers, tdilithium3SeamRequest(t, share, epoch, 68, message), 0,
		)
		harness.network.mu.Lock()
		harness.network.corrupt = func(_ int, messageType uint8, payload []byte) ([]byte, bool) {
			if messageType != p2p.MsgTypeTDilithium3SigningResponse {
				return nil, false
			}
			corrupted := append([]byte(nil), payload...)
			corrupted[len(corrupted)-1] ^= 1
			return corrupted, true
		}
		harness.network.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		signatures, _ := harness.run(ctx)
		for index, signature := range signatures {
			if len(signature) == 0 {
				continue
			}
			if err := qcrypto.VerifySignatureForAlgorithm(
				qcrypto.SignatureAlgorithmDilithium3Legacy, fixture.groupKey, message, nil, signature,
			); err == nil {
				t.Fatalf("signer %d produced a verifying signature from a corrupted response part", index)
			}
		}
	})
}

// tdilithium3SeamTestJournal opens one throwaway signing journal.
func tdilithium3SeamTestJournal(t *testing.T) *dilithium3v1.SigningJournal {
	t.Helper()
	journal, err := dilithium3v1.OpenSigningJournal(filepath.Join(t.TempDir(), "journal.db"))
	if err != nil {
		t.Fatalf("open signing journal: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

// tdilithium3SeamTestRecord mints one throwaway one-time record.
func tdilithium3SeamTestRecord(t *testing.T, participantID uint32) *dilithium3v1.PreprocessingRecord {
	t.Helper()
	record, err := dilithium3v1.NewSigningExecutorRecord(participantID, rand.Reader)
	if err != nil {
		t.Fatalf("mint preprocessing record: %v", err)
	}
	return record
}

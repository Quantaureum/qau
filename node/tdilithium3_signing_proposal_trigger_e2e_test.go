// Quantaureum Node source, version 1.0.0.
package node

// Handler-level end-to-end test of the proposal trigger channel on a node
// that holds a REAL active share (TSS-R3-B-1 P2 audit follow-up, fix 2): a
// six-member identity set, a real DKG ceremony whose committee matches what
// the node's captured epoch roster derives, an activated share in the node's
// own store, and the production custody registration — so the trigger passes
// every gate for real and reaches the request schedule. The lifecycle
// assertions:
//
//   - start accepted: the session map gains the slot, the pre-registered
//     candidate inbox shells appear, and the schedule adopts them (the
//     request-build trace proves the factory ran);
//   - ordinal replacement: a higher announced attempt cancels the running
//     one and replaces the session entry;
//   - shell hygiene (fix 1): the shells are released when the attempt ends
//     (a shell the schedule adopted is the driver's own registration and is
//     cleaned by the driver), and a start refused AFTER a successful prebuild
//     (the future-slot check) drops the shells immediately;
//   - start refused: no session entry, no shells, no goroutine state.
//
// The session itself does not converge here — a single node hears no round
// messages from peers that do not exist — but every step below convergence is
// the production path; the cryptographic convergence is pinned by
// TestTDilithium3ProposalTriggerChannelConvergence.

import (
	"bytes"
	"context"
	"crypto/sha3"
	"fmt"
	"log/slog"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const (
	// triggerE2EActivationEpoch is the ceremony's activation epoch; the
	// roster the session derivation consumes is captured at epoch-1.
	triggerE2EActivationEpoch = uint64(7)

	// triggerE2EWaitTimeout bounds one lifecycle poll against the live
	// attempt (one candidate-slot window plus scheduling slack).
	triggerE2EWaitTimeout = 45 * time.Second
)

// triggerE2EIdentity is one committee member's validator identity: the
// Dilithium3 key the roster binds, its derived address, and the peer id the
// p2p host maps it to.
type triggerE2EIdentity struct {
	keyPair *qcrypto.KeyPair
	address types.Address
	peer    p2p.PeerID
}

// triggerE2ELogBuffer is a concurrency-safe slog capture (the same shape as
// the proposal test's buffer, local to this file's fixture).
type triggerE2ELogBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *triggerE2ELogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *triggerE2ELogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// triggerE2EIdentityList builds the six deterministic validator identities.
func triggerE2EIdentityList(t *testing.T) []triggerE2EIdentity {
	t.Helper()
	identities := make([]triggerE2EIdentity, 6)
	for i := range identities {
		kp, err := qcrypto.GenerateKeyPairFromSeed([]byte(fmt.Sprintf("%-32s", fmt.Sprintf("DEVNET ONLY trigger e2e id %d", i))))
		if err != nil {
			t.Fatalf("identity %d: %v", i, err)
		}
		identities[i] = triggerE2EIdentity{
			keyPair: kp,
			address: types.AddressFromPublicKey(kp.Public.Bytes()),
			peer:    p2p.PeerID(fmt.Sprintf("trigger-e2e-peer-%d", i)),
		}
	}
	return identities
}

// triggerE2EActivationCertificate builds the activation certificate of one
// persisted share with the fixture identities' keys — the shape of
// testThresholdActivationCertificate, but signed by the roster's identities
// so the node's roster-keyed loader accepts the activation.
func triggerE2EActivationCertificate(
	t *testing.T,
	share *dilithium3v1.LocalShare,
	identities []triggerE2EIdentity,
) (dilithium3v1.DKGActivationCertificate, [32]byte, dilithium3v1.DKGIdentityVerifier, []dilithium3v1.DKGIdentityBinding) {
	t.Helper()
	sessionDigest := sha3.Sum256([]byte("DEVNET ONLY trigger e2e activation session"))
	encoded, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	localDigest := sha3.Sum256(encoded)
	clear(encoded)
	signerFor := func(participantID uint32) *qcrypto.PrivateKey {
		return identities[participantID-1].keyPair.Private
	}
	certificate := dilithium3v1.DKGActivationCertificate{Acknowledgements: make([]dilithium3v1.DKGActivationAcknowledgement, len(share.Committee.Participants))}
	for index, participantID := range share.Committee.Participants {
		candidateDigest := sha3.Sum256([]byte{byte(participantID)})
		if participantID == share.ParticipantID {
			candidateDigest = localDigest
		}
		acknowledgement := dilithium3v1.DKGActivationAcknowledgement{
			SessionDigest:     sessionDigest,
			ActivationEpoch:   share.ActivationEpoch,
			Key:               share.Key.Clone(),
			Committee:         share.Committee.Clone(),
			TranscriptDigest:  share.TranscriptDigest,
			ParticipantID:     participantID,
			CandidateDigest:   candidateDigest,
			IdentitySignature: make([]byte, qcrypto.Dilithium3SignatureSize),
		}
		message, err := acknowledgement.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		signature, err := signerFor(participantID).Sign(message)
		if err != nil {
			t.Fatalf("acknowledgement %d signature: %v", participantID, err)
		}
		copy(acknowledgement.IdentitySignature, signature)
		certificate.Acknowledgements[index] = acknowledgement
	}
	verifier := func(participantID uint32, message, signature []byte) bool {
		key := identities[participantID-1].keyPair.Public
		return key != nil && qcrypto.Verify(key, message, signature)
	}
	// Participant ids are the committee's canonical 1..6, bound to the
	// roster's identities in committee order.
	bindings := make([]dilithium3v1.DKGIdentityBinding, 0, len(identities))
	for _, participantID := range share.Committee.Participants {
		bindings = append(bindings, dilithium3v1.DKGIdentityBinding{
			ParticipantID:    participantID,
			ValidatorAddress: identities[participantID-1].address,
			PublicKey:        append([]byte(nil), identities[participantID-1].keyPair.Public.Bytes()...),
		})
	}
	return certificate, sessionDigest, verifier, bindings
}

// triggerE2EFixture assembles a node that holds participant 1's share of a
// real ceremony as an ACTIVE share, with the roster, custody, peer map, and
// gates the production trigger path consumes. It returns the node, the
// ceremony group key, and the peer id of the slot's elected proposer.
func triggerE2EFixture(t *testing.T) (*Node, []byte, p2p.PeerID, types.Address, uint64) {
	t.Helper()
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL", "1")
	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_SEAL", "1")

	identities := triggerE2EIdentityList(t)
	validators := make([]*consensus.Validator, len(identities))
	for i, identity := range identities {
		validators[i] = &consensus.Validator{
			Address:        identity.address,
			Stake:          big.NewInt(100),
			Active:         true,
			PublicKeyBytes: append([]byte(nil), identity.keyPair.Public.Bytes()...),
		}
	}
	validatorSet, err := consensus.NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("validator set: %v", err)
	}
	qpos, err := consensus.NewQPOS(validatorSet)
	if err != nil {
		t.Fatalf("qpos: %v", err)
	}
	qpos.InitChambers() // the QTD finality engine the anchor custody lives in

	// The ceremony's committee is exactly what the captured roster derives
	// for a six-member set: version 1, threshold 4, participants 1..6.
	ceremonySession := dilithium3v1.DKGSession{
		Protocol:        protocol.ThresholdProtocolDilithium3V1,
		ChainID:         tdilithium3SeamTestChainID,
		KeyGeneration:   1,
		Committee:       protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}},
		ActivationEpoch: triggerE2EActivationEpoch,
		Nonce:           [32]byte{9, 8, 7},
	}
	ceremonySession.IdentityRosterDigest = testTDilithium3IdentityRosterDigest(t, ceremonySession, "trigger e2e id")

	dataDir := t.TempDir()
	node := &Node{
		config: &Config{
			NetworkID:                    tdilithium3SeamTestChainID,
			DataDir:                      dataDir,
			ValidatorKeyPassword:         "DEVNET ONLY trigger e2e password",
			TSSV1ProposalActivationEpoch: triggerE2EActivationEpoch,
		},
		blockProducer: &BlockProducer{
			qpos:          qpos,
			validatorAddr: identities[0].address,
			validatorKey:  identities[0].keyPair.Private,
		},
	}
	node.blockProducer.node = node

	// The p2p host supplies the node's own peer id and the signers' peer
	// bindings; an unstarted host's broadcast reaches no one, which is what
	// the lifecycle assertions want.
	host, err := p2p.NewHost(nil)
	if err != nil {
		t.Fatalf("p2p host: %v", err)
	}
	host.AuthorizeValidatorRegistration()
	for _, identity := range identities {
		host.RegisterValidatorPeer(identity.address, identity.peer)
	}
	node.p2pHost = host
	// The signing journal handle is node-cached and only closed at node
	// shutdown; close it before t.TempDir removes the directory (this
	// cleanup runs after the fixture built the handle and before the
	// TempDir's own cleanup, LIFO).
	t.Cleanup(func() { node.closeTDilithium3SigningJournals() })

	// Roster capture: a valid epoch-boundary block at epoch 6 (the roster
	// epoch the activation epoch 7 derives from) records the six identities.
	boundary := &encoding.BlockHeader{
		Height: consensus.SlotsPerEpoch * 6,
		Slot:   consensus.SlotsPerEpoch * 6,
		Epoch:  6,
	}
	node.captureTDilithium3DKGEpochRosterFromBlock(&encoding.Block{Header: boundary})
	if node.tdilithium3DKGEpochRosterStore == nil {
		t.Fatal("the boundary block did not create the roster sidecar")
	}

	// The real ceremony: six runners, one share each, persisted in their own
	// stores; participant 1's store IS the node's share store, so the
	// activation below is what the node's loader reads back.
	transport := newTDilithium3DKGMemoryTransport(6)
	runners, err := newTriggerE2ERunners(t, ceremonySession, dataDir)
	if err != nil {
		t.Fatalf("ceremony runners: %v", err)
	}
	results, err := runTDilithium3DKGCluster(context.Background(), runners, transport, tdilithium3DKGFaultPlan{})
	if err != nil {
		t.Fatalf("six-node DKG cluster: %v", err)
	}
	groupKey := append([]byte(nil), results[0].PublicKey[:]...)

	// Activate participant 1's persisted candidate share in the node's store,
	// with an activation certificate signed by the SAME identities the roster
	// binds — the loader re-verifies under the roster's keys.
	loaded, err := runners[0].shareStore.LoadCandidate(1, 1, []byte(node.config.ValidatorKeyPassword))
	if err != nil {
		t.Fatalf("load candidate share: %v", err)
	}
	t.Cleanup(loaded.Zeroize)
	certificate, sessionDigest, verifier, bindings := triggerE2EActivationCertificate(t, loaded, identities)
	store := newThresholdShareStore(dataDir)
	if err := store.ActivateCandidate(certificate, sessionDigest, triggerE2EActivationEpoch, verifier, bindings, []byte(node.config.ValidatorKeyPassword)); err != nil {
		t.Fatalf("activate share: %v", err)
	}

	// Production custody registration: the ceremony key re-roots the anchor
	// custody and installs the finality signer at the activation epoch, so
	// the anchor-agreement self-check finds exactly the ceremony key. The
	// canonical-anchor observation state stays EMPTY here: the fixture models
	// a node whose key is not on the chain yet, and the fresh-sync bootstrap
	// gates treat exactly that state as "keep headers individually signed".
	// Tests that model a chain-anchored key call recordTDilithium3CanonicalAnchor
	// themselves.
	if err := node.registerTDilithium3SigningFinalitySigner(triggerE2EActivationEpoch, groupKey, 4); err != nil {
		t.Fatalf("custody registration: %v", err)
	}

	// The trigger slot must elect a proposer the sender can claim, and the
	// ANNOUNCED attempt's subset must include the local participant. The
	// attempt ordinal is 1, not 0: the attempt pairs are sorted, so the pair
	// holding position 0 is always the round's first pair and attempt 0
	// always sits position 0 out; a fresh slot admits ordinals 0 and 1.
	const triggerE2EAttempt = uint64(1)
	proposerPeer := p2p.PeerID("")
	proposerAddr := types.Address{}
	slot := uint64(64)
	var firstErr error
	subsetMiss := 0
	for ; slot < 64+128; slot++ {
		proposer, propErr := qpos.GetProposerForSlot(slot)
		if propErr != nil || proposer == nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("proposer election slot %d: %w", slot, propErr)
			}
			continue
		}
		_, _, _, shareErr := node.tdilithium3ActiveShareIdentityCached()
		if shareErr != nil {
			t.Fatalf("active share identity: %v", shareErr)
		}
		_, localSigner, signerErr := node.tdilithium3SealSigningSigners(triggerE2EActivationEpoch, slot, triggerE2EAttempt)
		if signerErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("signer resolution slot %d: %w", slot, signerErr)
			}
			continue
		}
		if !localSigner {
			subsetMiss++
			continue
		}
		proposerPeer = identities[proposerFixtureIndex(t, identities, proposer.Address)].peer
		proposerAddr = identities[proposerFixtureIndex(t, identities, proposer.Address)].address
		break
	}
	if proposerPeer == "" {
		t.Fatalf("no slot with the local validator in the attempt subset (subsetMiss=%d, firstErr=%v)", subsetMiss, firstErr)
	}
	return node, groupKey, proposerPeer, proposerAddr, slot
}

// newTriggerE2ERunners builds the six ceremony runners of the fixture's
// session; participant 1's store is the node's own share store directory.
func newTriggerE2ERunners(t *testing.T, session dilithium3v1.DKGSession, localDataDir string) ([6]*tdilithium3DKGRunner, error) {
	t.Helper()
	root := t.TempDir()
	var runners [6]*tdilithium3DKGRunner
	for position := range runners {
		basePath := filepath.Join(root, "node", fmt.Sprintf("%d", position), "shares.enc")
		if position == 0 {
			// The node's own share store reads from its DataDir.
			basePath = localDataDir
		}
		entropy := bytes.NewReader(bytes.Repeat([]byte{byte(position + 1), byte(position + 17), byte(position + 33)}, 1<<16))
		runner, err := newTDilithium3DKGRunner(tdilithium3DKGRunnerConfig{
			Session:             session.Clone(),
			ParticipantPosition: uint8(position),
			BasePath:            basePath,
			Password:            []byte("DEVNET ONLY trigger e2e password"),
			Entropy:             entropy,
		})
		if err != nil {
			return runners, err
		}
		runners[position] = runner
	}
	return runners, nil
}

// proposerFixtureIndex resolves a validator address to its fixture index.
func proposerFixtureIndex(t *testing.T, identities []triggerE2EIdentity, address types.Address) int {
	t.Helper()
	for index := range identities {
		if identities[index].address == address {
			return index
		}
	}
	t.Fatalf("elected proposer %s is not one of the fixture identities", address.String())
	return 0
}

// waitFor polls a condition until it holds or the timeout elapses.
func waitFor(timeout time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return condition()
}

// registeredInboxCount is the number of signing inboxes currently registered
// on the node (candidate shells and adopted drivers share this map).
func registeredInboxCount(node *Node) int {
	node.tdilithium3SigningInboxMu.RLock()
	defer node.tdilithium3SigningInboxMu.RUnlock()
	return len(node.tdilithium3SigningInboxes)
}

// runningTriggerAttempt reads the running trigger attempt of the slot (0
// meaning none, plus the session presence).
func runningTriggerAttempt(node *Node, slot uint64) (bool, uint64) {
	node.tdilithium3ProposalSigningMu.Lock()
	defer node.tdilithium3ProposalSigningMu.Unlock()
	session := node.tdilithium3ProposalTriggerSessions[slot]
	if session == nil {
		return false, 0
	}
	return true, session.attempt
}

// TestTDilithium3ProposalTriggerHandlerEndToEnd drives the production
// handler on the real-share node: an authenticated proposer trigger passes
// every gate, starts the session, pre-registers the candidate inboxes, and
// reaches the request schedule (whose factory adopts the shells). The attempt
// ends without convergence (no peers to hear the round messages) and the
// lifecycle cleans up: session entry gone, inboxes unregistered. A higher
// announced attempt replaces a running one, and a future-slot trigger —
// refused by the start AFTER the prebuild succeeded — leaves no shells
// behind (the fix-1 hygiene on the refuse path).
func TestTDilithium3ProposalTriggerHandlerEndToEnd(t *testing.T) {
	node, groupKey, proposerPeer, proposerAddr, triggerSlot := triggerE2EFixture(t)
	// The lifecycle tests model a chain that already carries the ceremony
	// key's canonical anchor (what an armed producer's applied anchor block
	// records); without it the fresh-sync bootstrap gates would refuse every
	// start, which is the correct behavior for a key that is not on the chain.
	node.recordTDilithium3CanonicalAnchor(triggerE2EActivationEpoch, groupKey)
	capture := &triggerE2ELogBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	bound := triggerTestBound()

	// Phase A: an accepted attempt reaches the schedule and cleans up. The
	// announced ordinal is 1 (see the fixture's subset scan above).
	node.handleTDilithium3ProposalTrigger(p2p.PeerMessage{
		From: proposerPeer, Type: p2p.MsgTypeTDilithium3ProposalTrigger,
		Payload: tdilithium3ProposalTriggerPayload(triggerE2EActivationEpoch, triggerSlot, bound, 1),
	})
	if !waitFor(5*time.Second, func() bool {
		present, attempt := runningTriggerAttempt(node, triggerSlot)
		return present && attempt == 1
	}) {
		t.Fatalf("the accepted trigger did not insert the session entry; handler log: %s", capture.String())
	}
	if !waitFor(5*time.Second, func() bool { return registeredInboxCount(node) > 0 }) {
		t.Fatal("the accepted trigger registered no candidate inbox shells")
	}
	if !waitFor(triggerE2EWaitTimeout, func() bool { return registeredInboxCount(node) == 0 }) {
		t.Fatalf("the attempt's inboxes were never released (%d still registered)", registeredInboxCount(node))
	}
	if !waitFor(5*time.Second, func() bool {
		present, _ := runningTriggerAttempt(node, triggerSlot)
		return !present
	}) {
		t.Fatal("the finished attempt did not forget its session entry")
	}
	// The schedule adoption proof: the request-build trace fired, which only
	// happens when the schedule's factory constructed the candidate slots.
	if out := capture.String(); !strings.Contains(out, "request build:") {
		t.Fatalf("the attempt never reached the request schedule; log: %s", out)
	}

	// Phase B: a higher announced attempt replaces a running one.
	deliver := func(attempt uint64) {
		t.Helper()
		node.handleTDilithium3ProposalTrigger(p2p.PeerMessage{
			From: proposerPeer, Type: p2p.MsgTypeTDilithium3ProposalTrigger,
			Payload: tdilithium3ProposalTriggerPayload(triggerE2EActivationEpoch, triggerSlot, bound, attempt),
		})
	}
	// The ordinals advance: phase A's attempt-1 session consumed its journal
	// records, so replaying ordinal 1 would be refused by the journal's
	// single-use discipline (correctly — a re-run of the same session id is a
	// replay). Phase B therefore starts the next admissible ordinal (2) and
	// replaces it with 3; both subsets include the local participant.
	deliver(2)
	if !waitFor(5*time.Second, func() bool {
		present, attempt := runningTriggerAttempt(node, triggerSlot)
		return present && attempt == 2
	}) {
		t.Fatalf("phase B: the first attempt did not start; handler log: %s", capture.String())
	}
	// The replacement ordinal is 3 (one past the highest recorded); its
	// subset sits the local participant out, so this run exits quietly at the
	// not-a-signer outcome -- the replacement itself is what the assertion
	// pins. The next ordinal (4) has the local participant back in, and its
	// session runs the full attempt.
	deliver(3)
	deliver(4)
	if present, attempt := runningTriggerAttempt(node, triggerSlot); !present || attempt != 4 {
		t.Fatalf("the higher announced attempt did not replace the running one (present=%v attempt=%d)", present, attempt)
	}
	// Let the replaced attempt's run finish so Phase C's invariants are not
	// polluted by its live shells.
	if !waitFor(triggerE2EWaitTimeout, func() bool {
		present, _ := runningTriggerAttempt(node, triggerSlot)
		return !present && registeredInboxCount(node) == 0
	}) {
		t.Fatal("phase B: the replaced attempt never settled")
	}

	// Phase C (fix 1 + fix 3): a trigger for a slot that has not started is
	// refused by the start AFTER the prebuild registered its shells — and the
	// refusal drops them. The future slot's attempt subset must include the
	// local participant so the prebuild actually registers shells, and the
	// chain clock must be configured so the future-tolerance gate engages.
	consensus.EnableTestHelpers()
	consensus.ResetGenesisTimeForTesting()
	defer consensus.ResetGenesisTimeForTesting()
	futureSlot := uint64(0)
	for candidate := triggerSlot + 1; candidate < triggerSlot+256; candidate++ {
		if _, _, _, shareErr := node.tdilithium3ActiveShareIdentityCached(); shareErr != nil {
			t.Fatalf("active share identity: %v", shareErr)
		}
		// The future slot must keep the SAME proposer (the B-5 check runs
		// before the future-tolerance gate) and keep the local participant in
		// the announced attempt's subset (so the prebuild registers shells).
		proposer, propErr := node.blockProducer.QPOS().GetProposerForSlot(candidate)
		if propErr != nil || proposer == nil || proposer.Address != proposerAddr {
			continue
		}
		_, localSigner, signerErr := node.tdilithium3SealSigningSigners(triggerE2EActivationEpoch, candidate, 1)
		if signerErr == nil && localSigner {
			futureSlot = candidate
			break
		}
	}
	if futureSlot == 0 {
		t.Fatal("no future slot with the local validator in the attempt subset")
	}
	// Genesis such that the future slot starts two slots from now: outside
	// the one-slot tolerance, and far enough past the running window.
	genesis := time.Now().Add(-time.Duration(futureSlot-2) * consensus.SlotDuration)
	if err := consensus.SetGenesisTime(genesis.Unix()); err != nil {
		t.Skipf("genesis time frozen by a prior test; phase C skipped: %v", err)
	}
	node.handleTDilithium3ProposalTrigger(p2p.PeerMessage{
		From: proposerPeer, Type: p2p.MsgTypeTDilithium3ProposalTrigger,
		Payload: tdilithium3ProposalTriggerPayload(triggerE2EActivationEpoch, futureSlot, bound, 1),
	})
	if !waitFor(5*time.Second, func() bool { return registeredInboxCount(node) == 0 }) {
		t.Fatalf("the refused future-slot trigger left %d inbox shells behind", registeredInboxCount(node))
	}
	if present, _ := runningTriggerAttempt(node, futureSlot); present {
		t.Fatal("the refused future-slot trigger started a session")
	}
	if out := capture.String(); !strings.Contains(out, "has not started yet") {
		t.Fatalf("the future-slot trigger did not fail the future-tolerance gate; log: %s", out)
	}
}

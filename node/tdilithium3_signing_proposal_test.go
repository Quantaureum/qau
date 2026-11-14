// Quantaureum Node source, version 1.0.0.
package node

// Tests of the Dilithium3 v1 proposal signing executor wiring (TSS-R3-B-1 P1):
// the two independent gate layers, the entry's fail-closed refusals, the
// proposal-path's own concurrency budget, the slot-anchored window, the
// retryable-failure classification, and the session identity isolation from
// the seal executor. The full four-signer cryptographic drive over the
// canonical binding lives in the protocol package
// (wallet/tss/protocol/dilithium3v1/sign_proposal_binding_test.go); everything
// this file can reach fails closed.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"

	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// TestTDilithium3ProposalSigningEnvLayer pins the environment layer alone:
// the explicit opt-in enables non-mainnet networks, and the mainnet
// additionally requires the mainnet acknowledgement. The switch is
// independent of the seal executor's experimental gate.
func TestTDilithium3ProposalSigningEnvLayer(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "0")
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "")
	if tdilithium3ProposalSigningEnvEnabled(TestnetNetworkID) {
		t.Fatal("testnet enabled without the proposal opt-in")
	}
	if tdilithium3ProposalSigningEnvEnabled(MainnetNetworkID) {
		t.Fatal("mainnet enabled without the proposal opt-in")
	}
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	if !tdilithium3ProposalSigningEnvEnabled(TestnetNetworkID) {
		t.Fatal("testnet not enabled by the proposal opt-in")
	}
	if !tdilithium3ProposalSigningEnvEnabled(DevnetNetworkID) {
		t.Fatal("devnet not enabled by the proposal opt-in")
	}
	if tdilithium3ProposalSigningEnvEnabled(MainnetNetworkID) {
		t.Fatal("mainnet enabled without the mainnet acknowledgement")
	}
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_MAINNET", "1")
	if !tdilithium3ProposalSigningEnvEnabled(MainnetNetworkID) {
		t.Fatal("mainnet not enabled with both opt-ins")
	}
	// The seal executor's experimental gate stays untouched by this switch.
	if experimentalTDilithium3V1Enabled() {
		t.Fatal("the proposal opt-in leaked into the seal executor's gate")
	}
}

// TestTDilithium3ProposalSigningGateLayers pins the two-layer AND semantics:
// both the environment opt-in and the chain-height gate must be open; either
// layer closed keeps the legacy signature path.
func TestTDilithium3ProposalSigningGateLayers(t *testing.T) {
	if tdilithium3ProposalSigningEnabled(nil, 10) {
		t.Fatal("nil node enabled")
	}
	testnet := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	if tdilithium3ProposalSigningEnabled(testnet, 10) {
		t.Fatal("no opt-in and no activation epoch, yet enabled")
	}
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	// Environment open, chain-height gate closed (0 = never active).
	if tdilithium3ProposalSigningEnabled(testnet, 10) {
		t.Fatal("enabled without an activation epoch")
	}
	testnet.config.TSSV1ProposalActivationEpoch = 10
	if tdilithium3ProposalSigningEnabled(testnet, 9) {
		t.Fatal("enabled below the activation epoch")
	}
	if !tdilithium3ProposalSigningEnabled(testnet, 10) {
		t.Fatal("not enabled at the activation epoch")
	}
	if !tdilithium3ProposalSigningEnabled(testnet, 11) {
		t.Fatal("not enabled past the activation epoch")
	}
	// Mainnet: the second acknowledgement is required on top of both layers.
	mainnet := &Node{config: &Config{
		NetworkID:                    MainnetNetworkID,
		TSSV1ProposalActivationEpoch: 10,
	}}
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_MAINNET", "")
	if tdilithium3ProposalSigningEnabled(mainnet, 10) {
		t.Fatal("mainnet enabled without the mainnet acknowledgement")
	}
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_MAINNET", "1")
	if !tdilithium3ProposalSigningEnabled(mainnet, 10) {
		t.Fatal("mainnet not enabled with every layer open")
	}
}

// TestTDilithium3V1ProposalHeaderSignatureFailsClosed requires the entry to
// return nil -- never a signature, never a panic -- whenever a precondition is
// missing, and to touch nothing when the gate is closed (the default posture).
func TestTDilithium3V1ProposalHeaderSignatureFailsClosed(t *testing.T) {
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "")
	var unconfigured *Node
	if sig := unconfigured.tdilithium3V1ProposalHeaderSignature(&encoding.BlockHeader{}); sig != nil {
		t.Fatal("nil node produced a signature")
	}
	header := &encoding.BlockHeader{
		ChainID:      TestnetNetworkID,
		Epoch:        10,
		Slot:         100,
		ProposerAddr: types.BytesToAddress([]byte{0x42}),
	}
	// Gate closed (default): nil with no share store, no p2p, no producer.
	bare := &Node{}
	if sig := bare.tdilithium3V1ProposalHeaderSignature(header); sig != nil {
		t.Fatal("closed gate produced a signature")
	}
	// Gate open but no block producer.
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	producerLess := &Node{config: &Config{
		NetworkID:                    TestnetNetworkID,
		TSSV1ProposalActivationEpoch: 10,
	}}
	if sig := producerLess.tdilithium3V1ProposalHeaderSignature(header); sig != nil {
		t.Fatal("node without a block producer produced a signature")
	}
	// Gate open, producer present, but no active share store: the session
	// inputs are missing, so the entry must refuse.
	node := &Node{config: &Config{
		NetworkID:                    TestnetNetworkID,
		TSSV1ProposalActivationEpoch: 10,
		DataDir:                      t.TempDir(),
		ValidatorKeyPassword:         "DEVNET ONLY proposal executor refusal test",
	}}
	node.blockProducer = &BlockProducer{node: node}
	if sig := node.tdilithium3V1ProposalHeaderSignature(header); sig != nil {
		t.Fatal("node without an active share produced a signature")
	}
}

// TestTDilithium3ProposalPermitBoundsConcurrency requires the proposal path's
// own budget to cap concurrency and to be independent of the seal executor's
// permits: filling one never blocks the other.
func TestTDilithium3ProposalPermitBoundsConcurrency(t *testing.T) {
	node := &Node{}
	ctx := context.Background()
	for i := 0; i < tdilithium3ProposalSigningMaxConcurrent; i++ {
		if !node.acquireTDilithium3ProposalSigning(ctx) {
			t.Fatalf("permit %d of %d was refused", i+1, tdilithium3ProposalSigningMaxConcurrent)
		}
	}
	blocked, cancelBlocked := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelBlocked()
	if node.acquireTDilithium3ProposalSigning(blocked) {
		t.Fatal("acquire exceeded the proposal concurrency bound")
	}
	// The seal executor's budget is untouched while every proposal permit is
	// held, and the reverse holds too.
	for i := 0; i < tdilithium3SealSigningMaxConcurrentSlots; i++ {
		if !node.acquireTDilithium3SealSigning(ctx, uint64(100+i)) {
			t.Fatalf("seal permit %d was blocked by the proposal budget", i+1)
		}
	}
	blockedSeal, cancelSeal := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelSeal()
	if node.acquireTDilithium3SealSigning(blockedSeal, 999) {
		t.Fatal("seal acquire exceeded its own bound")
	}
	for i := 0; i < tdilithium3SealSigningMaxConcurrentSlots; i++ {
		node.releaseTDilithium3SealSigning()
	}
	for i := 0; i < tdilithium3ProposalSigningMaxConcurrent; i++ {
		node.releaseTDilithium3ProposalSigning()
	}
	if !node.acquireTDilithium3ProposalSigning(ctx) {
		t.Fatal("a freed proposal permit was not reusable")
	}
	node.releaseTDilithium3ProposalSigning()
	node.releaseTDilithium3ProposalSigning() // must stay quiet, not panic
}

// TestTDilithium3ProposalWindowIsSlotAnchored pins the window shape: without a
// chain clock it bounds nothing; with one, the slot's start anchors it.
func TestTDilithium3ProposalWindowIsSlotAnchored(t *testing.T) {
	consensus.EnableTestHelpers()
	consensus.ResetGenesisTimeForTesting()
	defer consensus.ResetGenesisTimeForTesting()
	if !tdilithium3ProposalWithinWindow(5, time.Now()) {
		t.Fatal("without a chain clock the window must not bound anything")
	}
	if err := consensus.SetGenesisTime(1700000000); err != nil {
		t.Fatal(err)
	}
	const slot = 40
	start := consensus.GetSlotStartTime(slot)
	if !tdilithium3ProposalWithinWindow(slot, start.Add(tdilithium3ProposalSigningWindow)) {
		t.Fatal("the window's last instant was rejected")
	}
	if tdilithium3ProposalWithinWindow(slot, start.Add(tdilithium3ProposalSigningWindow+time.Second)) {
		t.Fatal("an instant past the window was accepted")
	}
}

// TestTDilithium3ProposalAttemptRetryable pins the retry classification: a
// filtered request or an unreachable signer moves the header to the next
// attempt (whose subset may differ); the proposer's own exclusion is a
// rotation signal; anything else is structural.
func TestTDilithium3ProposalAttemptRetryable(t *testing.T) {
	exhausted := fmt.Errorf("%w: 11 candidate slots all filtered", errTDilithium3SigningRequestExhausted)
	unreachable := fmt.Errorf("Dilithium3 v1 proposal executor binding: %w",
		fmt.Errorf("%w: signer has no peer binding", errTDilithium3SigningSignerUnreachable))
	if !tdilithium3ProposalAttemptRetryable(exhausted) {
		t.Fatal("an exhausted request was not retried")
	}
	if !tdilithium3ProposalAttemptRetryable(unreachable) {
		t.Fatal("an unreachable signer was not retried")
	}
	if tdilithium3ProposalAttemptRetryable(errTDilithium3ProposalSigningNotASigner) {
		t.Fatal("the proposer's own exclusion must rotate via skip, not via the retryable class")
	}
	if tdilithium3ProposalAttemptRetryable(fmt.Errorf("binding requires a data directory")) {
		t.Fatal("a structural failure was classified as retryable")
	}
	if tdilithium3ProposalAttemptRetryable(nil) {
		t.Fatal("nil was classified as retryable")
	}
}

// TestTDilithium3ProposalSessionIsolatedFromSeal requires the proposal
// session's identity to differ from a seal session's identity for the same
// slot even when every other input coincides: the block domain and the bound
// message enter the session derivation, so the two paths' inboxes, journals,
// and one-time records cannot cross.
func TestTDilithium3ProposalSessionIsolatedFromSeal(t *testing.T) {
	fixture := tdilithium3SigningBindingTestFixtureFor(t)
	const (
		chainID = uint64(1669)
		epoch   = uint64(2)
		slot    = uint64(64)
	)
	signingData := []byte("DEVNET ONLY proposal isolation signing data")
	bound := consensus.ComputeTSSCanonicalBinding(
		chainID, epoch, slot, fixture.roster.Entries[0].Address, "block", signingData,
	)
	blockHash := types.Hash{0xAB}
	sealMessage := consensus.QTDSignedMessage(chainID, epoch, slot, blockHash)
	build := func(domain protocol.SigningDomain, message []byte, nonce [32]byte) protocol.SignRequest {
		return protocol.SignRequest{
			Protocol: protocol.ThresholdProtocolDilithium3V1,
			Key: protocol.ThresholdKeyID{
				Algorithm:  qcrypto.SignatureAlgorithmDilithium3Legacy,
				Generation: 1,
				PublicKey:  bytes.Repeat([]byte{0x31}, 1952),
			},
			Committee:    fixture.committee,
			ChainID:      chainID,
			Epoch:        epoch,
			Slot:         slot,
			Domain:       domain,
			Message:      append([]byte(nil), message...),
			AttemptNonce: nonce,
		}
	}
	proposalNonce, err := dilithium3v1.SigningRequestAttemptNonce(chainID, epoch, slot, protocol.SigningDomainBlock, bound[:], 0)
	if err != nil {
		t.Fatal(err)
	}
	sealNonce, err := dilithium3v1.SigningRequestAttemptNonce(chainID, epoch, slot, protocol.SigningDomainFinality, sealMessage, 0)
	if err != nil {
		t.Fatal(err)
	}
	proposalID, err := dilithium3v1.Dilithium3SigningSessionID(
		build(protocol.SigningDomainBlock, bound[:], proposalNonce), fixture.signers,
	)
	if err != nil {
		t.Fatal(err)
	}
	sealID, err := dilithium3v1.Dilithium3SigningSessionID(
		build(protocol.SigningDomainFinality, sealMessage, sealNonce), fixture.signers,
	)
	if err != nil {
		t.Fatal(err)
	}
	if proposalID == sealID {
		t.Fatal("a proposal session and a seal session of the same slot share a session id")
	}
	// Isolation does not lean on the nonce alone: with an IDENTICAL nonce the
	// domain and message still separate the two sessions.
	sharedNonce := [32]byte{0x5A}
	sameNonceProposal, err := dilithium3v1.Dilithium3SigningSessionID(
		build(protocol.SigningDomainBlock, bound[:], sharedNonce), fixture.signers,
	)
	if err != nil {
		t.Fatal(err)
	}
	sameNonceSeal, err := dilithium3v1.Dilithium3SigningSessionID(
		build(protocol.SigningDomainFinality, sealMessage, sharedNonce), fixture.signers,
	)
	if err != nil {
		t.Fatal(err)
	}
	if sameNonceProposal == sameNonceSeal {
		t.Fatal("identical nonces collapsed the two domains' sessions")
	}
	again, err := dilithium3v1.Dilithium3SigningSessionID(
		build(protocol.SigningDomainBlock, bound[:], proposalNonce), fixture.signers,
	)
	if err != nil || again != proposalID {
		t.Fatalf("session derivation is not deterministic (err %v)", err)
	}
}

// TestTDilithium3ProposalTraceDefaultOff pins the default log posture: the
// trace switch is closed without its environment variable, so a default node
// emits no proposal executor logs at all.
func TestTDilithium3ProposalTraceDefaultOff(t *testing.T) {
	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL", "")
	if tdilithium3ProposalSigningTrace() {
		t.Fatal("trace enabled without its environment variable")
	}
	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL", "1")
	if !tdilithium3ProposalSigningTrace() {
		t.Fatal("trace not enabled by its environment variable")
	}
}

// TestTDilithium3ProposalErrorsAreDistinct guards the error taxonomy the
// retry classification and the skip path rely on.
func TestTDilithium3ProposalErrorsAreDistinct(t *testing.T) {
	if errors.Is(errTDilithium3ProposalSigningNotASigner, errTDilithium3SealSigningNotASigner) ||
		errors.Is(errTDilithium3SealSigningNotASigner, errTDilithium3ProposalSigningNotASigner) {
		t.Fatal("the proposal and seal not-a-signer errors must stay distinct")
	}
}

// TestTDilithium3ProposalAnchorAgreesBranches pins the anchor-agreement
// self-check's three outcomes (audit R3-B-1 follow-up): the ceremony key must
// match the key the QTD anchor custody serves for the header's epoch.
//
//   - anchored equal -> agree: the validators' v1 branch verifies against the
//     same key, so the group signature is reachable network-wide;
//   - anchored different (experimental DKG rotation ahead of this node) ->
//     refuse: the network would verify against the new anchored key and
//     reject every header this node signs with the stale ceremony key;
//   - empty/unknown -> refuse. The "empty means not anchored yet, the
//     header's own QTDGroupKey self-anchors it" reading does NOT hold:
//     ObserveAnchoredGroupKey runs post-apply (block_producer.go:163 via
//     node.go:9125/10563) while ValidateSignature runs first (syncer.go:1059),
//     so an empty-custody validator rejects the group-signed header before
//     the anchor inside it can be adopted. See
//     tdilithium3ProposalAnchorAgrees for the full evidence chain.
func TestTDilithium3ProposalAnchorAgreesBranches(t *testing.T) {
	ceremonyKey := bytes.Repeat([]byte{0x5C}, crypto.Dilithium3PublicKeySize)
	rotatedKey := bytes.Repeat([]byte{0x6D}, crypto.Dilithium3PublicKeySize)

	// The custody fixture is a fresh QTD finality state whose only trust root
	// is the observer first establishment of the ceremony key (no QPOS: the
	// anchor adoption and the exact-epoch lookup never touch it).
	qfs := consensus.NewQTDFinalityState(nil)
	if !qfs.ObserveAnchoredGroupKey(10, ceremonyKey, nil) {
		t.Fatal("ceremony key first establishment refused")
	}

	// Branch 1: anchored and equal -> agree.
	if !tdilithium3ProposalEpochKeyAgrees(qfs, 10, ceremonyKey) {
		t.Fatal("anchored custody equal to the ceremony key was refused")
	}

	// Branch 2: anchored but different -> refuse (rotation ahead).
	if tdilithium3ProposalEpochKeyAgrees(qfs, 10, rotatedKey) {
		t.Fatal("anchored custody differing from the ceremony key was accepted")
	}

	// Branch 3: empty (no validated anchor for the epoch) -> refuse.
	if tdilithium3ProposalEpochKeyAgrees(qfs, 11, ceremonyKey) {
		t.Fatal("an unknown epoch's empty custody was accepted")
	}
	if tdilithium3ProposalEpochKeyAgrees(nil, 10, ceremonyKey) {
		t.Fatal("a nil QTD finality state was accepted")
	}

	// The node-level wrapper keeps its fail-closed guards: a nil node, a node
	// without a block producer, and a producer without a consensus engine all
	// refuse.
	var unconfigured *Node
	if unconfigured.tdilithium3ProposalAnchorAgrees(10, ceremonyKey) {
		t.Fatal("nil node accepted")
	}
	if (&Node{}).tdilithium3ProposalAnchorAgrees(10, ceremonyKey) {
		t.Fatal("node without a block producer accepted")
	}
	noEngine := &Node{blockProducer: &BlockProducer{node: &Node{}}}
	if noEngine.tdilithium3ProposalAnchorAgrees(10, ceremonyKey) {
		t.Fatal("producer without a consensus engine accepted")
	}
}

// proposalLogBuffer is a concurrency-safe capture buffer for the default slog
// handler during a test.
type proposalLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *proposalLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *proposalLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestTDilithium3ProposalFlagGateLogContract pins the flag-gate contract at
// the log level. With either gate layer closed the entry returns nil -- the
// caller then produces the legacy INDIVIDUAL signature on its unchanged path
// -- and no proposal executor log is emitted, even with the trace switch
// open. The positive control proves the capture works: with both gates open
// the same refusal DOES log its decision, so the silence above is the
// contract, not a broken capture; and with the trace closed the open-gate
// refusal is silent again (the default posture adds no logs).
func TestTDilithium3ProposalFlagGateLogContract(t *testing.T) {
	capture := &proposalLogBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL", "1")
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "")
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	node.blockProducer = &BlockProducer{node: node}
	header := &encoding.BlockHeader{
		ChainID:      TestnetNetworkID,
		Epoch:        10,
		Slot:         100,
		ProposerAddr: types.BytesToAddress([]byte{0x42}),
	}
	if sig := node.tdilithium3V1ProposalHeaderSignature(header); sig != nil {
		t.Fatal("a closed gate layer produced a group signature")
	}
	if out := capture.String(); strings.Contains(out, "Dilithium3 v1 proposal executor") {
		t.Fatalf("a closed gate layer produced proposal executor logs: %s", out)
	}

	// Positive control: both layers open, the decision path logs (here: the
	// missing active share refusal), proving the capture is live.
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	node.config.TSSV1ProposalActivationEpoch = 10
	node.config.DataDir = t.TempDir()
	node.config.ValidatorKeyPassword = "DEVNET ONLY flag gate log contract test"
	capture.buf.Reset()
	if sig := node.tdilithium3V1ProposalHeaderSignature(header); sig != nil {
		t.Fatal("a node without an active share produced a signature")
	}
	if out := capture.String(); !strings.Contains(out, "Dilithium3 v1 proposal executor") {
		t.Fatalf("an open-gate refusal produced no decision log; the capture may be broken: %s", out)
	}

	// With the trace switch closed, the same open-gate refusal is silent
	// again: a default node emits no new logs on this path.
	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL", "")
	capture.buf.Reset()
	if sig := node.tdilithium3V1ProposalHeaderSignature(header); sig != nil {
		t.Fatal("a node without an active share produced a signature")
	}
	if out := capture.String(); strings.Contains(out, "Dilithium3 v1 proposal executor") {
		t.Fatalf("a trace-closed refusal produced logs: %s", out)
	}
}

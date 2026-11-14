// Quantaureum Node source, version 1.0.0.
package node

// Tests of the Dilithium3 v1 proposal trigger channel (TSS-R3-B-1 P2): the
// wire payload round trip, the start path's fail-closed refusals (bare-Node
// mode, mirroring the seal executor's start tests), the ordinal admission,
// the per-peer rate limit, the B-5 sender authentication, and the handler's
// refusal ordering. The multi-node convergence drive lives in
// TestTDilithium3ProposalTriggerChannelConvergence (same file): it runs a
// real DKG ceremony, derives the four signers' request from a TRIGGER
// PAYLOAD alone, converges the four-of-six session in-process, and requires
// the block validator to accept the signature.

import (
	"encoding/binary"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// triggerTestEpoch is the epoch the trigger tests announce; the chain-height
// gate in the fixtures is armed at exactly this epoch.
const triggerTestEpoch = uint64(10)

// triggerTestSlot is the slot the trigger tests announce.
const triggerTestSlot = uint64(100)

// triggerTestBound is a distinguishable non-zero binding fixture.
func triggerTestBound() [32]byte {
	var bound [32]byte
	for i := range bound {
		bound[i] = byte(0x40 + i)
	}
	return bound
}

// triggerTestOpenNode builds a bare node whose proposal gate is OPEN (env
// opt-in + activation epoch) but which holds no share, no p2p host, and no
// consensus engine: everything downstream of the pure checks fails closed.
func triggerTestOpenNode(t *testing.T) *Node {
	t.Helper()
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL", "1")
	return &Node{config: &Config{
		NetworkID:                    TestnetNetworkID,
		TSSV1ProposalActivationEpoch: triggerTestEpoch,
	}}
}

// TestTDilithium3ProposalTriggerPayloadRoundTrip pins the wire format: the
// payload is the exact inverse of the parser, so the sender-side and the
// receiver-side session derivations consume the same bound bytes.
func TestTDilithium3ProposalTriggerPayloadRoundTrip(t *testing.T) {
	bound := triggerTestBound()
	payload := tdilithium3ProposalTriggerPayload(7, 64, bound, 2)
	if len(payload) != 56 {
		t.Fatalf("payload length %d, want 56", len(payload))
	}
	if got := binary.BigEndian.Uint64(payload[0:8]); got != 7 {
		t.Fatalf("epoch = %d, want 7", got)
	}
	if got := binary.BigEndian.Uint64(payload[8:16]); got != 64 {
		t.Fatalf("slot = %d, want 64", got)
	}
	if got := binary.BigEndian.Uint64(payload[48:56]); got != 2 {
		t.Fatalf("attempt = %d, want 2", got)
	}
	epoch, slot, parsed, attempt, ok := tdilithium3ProposalTriggerParse(payload)
	if !ok || epoch != 7 || slot != 64 || attempt != 2 || parsed != bound {
		t.Fatalf("parse round trip: ok=%v epoch=%d slot=%d attempt=%d", ok, epoch, slot, attempt)
	}
	// Extension bytes are admitted and leave the base fields intact.
	extended := append(append([]byte(nil), payload...), 0x01, 0x02)
	epoch, slot, parsed, attempt, ok = tdilithium3ProposalTriggerParse(extended)
	if !ok || epoch != 7 || slot != 64 || attempt != 2 || parsed != bound {
		t.Fatalf("extended parse: ok=%v", ok)
	}
	// Outside the bound the payload is not a trigger.
	for _, length := range []int{0, 55, 97} {
		if _, _, _, _, ok := tdilithium3ProposalTriggerParse(make([]byte, length)); ok {
			t.Fatalf("payload of length %d parsed", length)
		}
	}
}

// TestTDilithium3ProposalSigningStartFailsClosed mirrors the seal executor's
// start test: a bare node refuses every announced attempt it cannot run, and
// a refusal never leaves session state behind.
func TestTDilithium3ProposalSigningStartFailsClosed(t *testing.T) {
	var unconfigured *Node
	bound := triggerTestBound()
	if unconfigured.tdilithium3ProposalSigningStart(triggerTestEpoch, triggerTestSlot, bound, 0, nil) {
		t.Fatal("nil node started a session")
	}
	// Gate closed (the default): refuse with zero side effects.
	closed := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	if closed.tdilithium3ProposalSigningStart(triggerTestEpoch, triggerTestSlot, bound, 0, nil) {
		t.Fatal("node with a closed gate started a session")
	}
	// Gate open: the attempt bound refuses before anything expensive runs.
	node := triggerTestOpenNode(t)
	if node.tdilithium3ProposalSigningStart(triggerTestEpoch, triggerTestSlot, bound, tdilithium3ProposalSigningMaxAttempts, nil) {
		t.Fatal("an attempt beyond the bound started a session")
	}
	// Ordinal admission: a skip ahead of the attempts seen so far refuses.
	node.tdilithium3ProposalOrdinalRecord(triggerTestSlot, 1)
	if node.tdilithium3ProposalSigningStart(triggerTestEpoch, triggerTestSlot, bound, 3, nil) {
		t.Fatal("a skip-ahead attempt started a session")
	}
	// Past the slot's proposal window.
	consensus.EnableTestHelpers()
	consensus.ResetGenesisTimeForTesting()
	defer consensus.ResetGenesisTimeForTesting()
	if err := consensus.SetGenesisTime(1700000000); err != nil {
		t.Fatal(err)
	}
	if node.tdilithium3ProposalSigningStart(triggerTestEpoch, triggerTestSlot, bound, 0, nil) {
		t.Fatal("a trigger far past the slot window started a session")
	}
	// Gate open, ordinal and window fine, but no active share: the session's
	// inputs are missing, so the start refuses.
	consensus.ResetGenesisTimeForTesting()
	if node.tdilithium3ProposalSigningStart(triggerTestEpoch, triggerTestSlot, bound, 0, nil) {
		t.Fatal("node without an active share started a session")
	}
	if len(node.tdilithium3ProposalTriggerSessions) != 0 {
		t.Fatalf("refused starts left %d session entries behind", len(node.tdilithium3ProposalTriggerSessions))
	}
}

// TestTDilithium3ProposalOrdinalAdmission mirrors the seal executor's
// ordinal semantics: attempts advance one ordinal at a time, re-entry with an
// admitted ordinal is fine, skips are refused, and the history is pruned.
func TestTDilithium3ProposalOrdinalAdmission(t *testing.T) {
	node := &Node{}
	const slot = 12
	if !node.tdilithium3ProposalOrdinalAdmissible(slot, 0) || !node.tdilithium3ProposalOrdinalAdmissible(slot, 1) {
		t.Fatal("the first attempt or the retry after it was refused on a fresh slot")
	}
	if node.tdilithium3ProposalOrdinalAdmissible(slot, 2) {
		t.Fatal("a fresh slot admitted a skip to attempt 2")
	}
	node.tdilithium3ProposalOrdinalRecord(slot, 1)
	if !node.tdilithium3ProposalOrdinalAdmissible(slot, 2) {
		t.Fatal("the next attempt was refused")
	}
	if !node.tdilithium3ProposalOrdinalAdmissible(slot, 1) {
		t.Fatal("re-entry with an admitted ordinal was refused")
	}
	if node.tdilithium3ProposalOrdinalAdmissible(slot, 3) {
		t.Fatal("a skip of two ordinals was admitted")
	}
	node.tdilithium3ProposalOrdinalRecord(slot, 0)
	if node.tdilithium3ProposalOrdinalAdmissible(slot, 3) {
		t.Fatal("recording a lower ordinal lowered the slot's high-water mark")
	}
	for later := uint64(slot + 1); later < slot+1+3*tdilithium3ProposalOrdinalHistorySlots; later++ {
		node.tdilithium3ProposalOrdinalRecord(later, 0)
	}
	if len(node.tdilithium3ProposalTriggerOrdinals) > 2*tdilithium3ProposalOrdinalHistorySlots+1 {
		t.Fatalf("ordinal history holds %d slots, want it pruned", len(node.tdilithium3ProposalTriggerOrdinals))
	}
}

// TestTDilithium3ProposalTriggerRateLimit mirrors the seal request's
// NODE-R12-H01 tests: lazy init on a bare node, a bounded per-peer window,
// per-peer isolation, and a reset after the window expires.
func TestTDilithium3ProposalTriggerRateLimit(t *testing.T) {
	node := &Node{}
	if node.tdilithium3ProposalTriggerRate != nil {
		t.Fatal("bare node should start with a nil rate map")
	}
	peer := p2p.PeerID("trigger-peer-A")
	for i := 0; i < tdilithium3ProposalTriggerPerPeerMax; i++ {
		if !node.allowTDilithium3ProposalTriggerFromPeer(peer) {
			t.Fatalf("peer rejected at message %d", i+1)
		}
	}
	if node.allowTDilithium3ProposalTriggerFromPeer(peer) {
		t.Fatal("peer should be over limit")
	}
	// Per-peer isolation: another peer's quota is untouched.
	other := p2p.PeerID("trigger-peer-B")
	if !node.allowTDilithium3ProposalTriggerFromPeer(other) {
		t.Fatal("an unrelated peer was blocked by the first peer's quota")
	}
	// Window expiry resets the counter.
	node.tdilithium3ProposalTriggerRateMu.Lock()
	if info, ok := node.tdilithium3ProposalTriggerRate[peer]; ok {
		info.windowStart = time.Now().Add(-(tdilithium3ProposalTriggerPerPeerWindow + time.Second))
	}
	node.tdilithium3ProposalTriggerRateMu.Unlock()
	if !node.allowTDilithium3ProposalTriggerFromPeer(peer) {
		t.Fatal("peer should be allowed after the window reset")
	}
}

// triggerTestElectedProposer builds the consensus half of an auth fixture: a
// six-validator QPOS whose elected proposer for triggerTestSlot is returned
// alongside the node wiring. The elected proposer for a fresh deterministic
// shuffle is the validator set's first entry.
func triggerTestElectedProposer(t *testing.T) (*Node, types.Address) {
	t.Helper()
	var vals []*consensus.Validator
	for i := 0; i < 6; i++ {
		vals = append(vals, &consensus.Validator{
			Address: types.BytesToAddress([]byte{byte(0xA0 + i)}),
			Stake:   big.NewInt(100),
			Active:  true,
		})
	}
	vs, err := consensus.NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("validator set: %v", err)
	}
	qpos, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("qpos: %v", err)
	}
	proposer, err := qpos.GetProposerForSlot(triggerTestSlot)
	if err != nil || proposer == nil {
		t.Fatalf("proposer election: %v", err)
	}
	// The trigger sender's peer mapping rides a real (unstarted) host: only
	// the validator-peer map is consulted on this path.
	host, err := p2p.NewHost(nil)
	if err != nil {
		t.Fatalf("p2p host: %v", err)
	}
	host.AuthorizeValidatorRegistration()
	host.RegisterValidatorPeer(proposer.Address, p2p.PeerID("trigger-proposer-peer"))
	host.RegisterValidatorPeer(types.BytesToAddress([]byte{0xEE}), p2p.PeerID("trigger-other-peer"))

	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL", "1")
	node := &Node{
		config: &Config{
			NetworkID:                    TestnetNetworkID,
			TSSV1ProposalActivationEpoch: triggerTestEpoch,
		},
		blockProducer: &BlockProducer{qpos: qpos},
		p2pHost:       host,
	}
	return node, proposer.Address
}

// TestTDilithium3ProposalTriggerSenderAuthed pins the B-5 decision: only the
// slot's proposer may announce proposal attempts, an unresolvable sender
// refuses, and a missing consensus engine refuses.
func TestTDilithium3ProposalTriggerSenderAuthed(t *testing.T) {
	node, proposerAddr := triggerTestElectedProposer(t)
	if !node.tdilithium3ProposalTriggerSenderAuthed(triggerTestSlot, p2p.PeerID("trigger-proposer-peer")) {
		t.Fatal("the slot's proposer was refused")
	}
	if node.tdilithium3ProposalTriggerSenderAuthed(triggerTestSlot, p2p.PeerID("trigger-other-peer")) {
		t.Fatal("a non-proposer sender was admitted")
	}
	if node.tdilithium3ProposalTriggerSenderAuthed(triggerTestSlot, p2p.PeerID("trigger-unknown-peer")) {
		t.Fatal("an unresolvable sender was admitted")
	}
	var unconfigured *Node
	if unconfigured.tdilithium3ProposalTriggerSenderAuthed(triggerTestSlot, p2p.PeerID("trigger-proposer-peer")) {
		t.Fatal("nil node admitted a sender")
	}
	if (&Node{}).tdilithium3ProposalTriggerSenderAuthed(triggerTestSlot, p2p.PeerID("trigger-proposer-peer")) {
		t.Fatal("node without a consensus engine admitted a sender")
	}
	_ = proposerAddr
}

// captureLogs redirects the default slog handler into a capture buffer for
// the duration of the test, so a negative assertion about logs ("nothing was
// logged") is meaningful rather than vacuous.
func captureLogs(t *testing.T) *triggerLogBuffer {
	t.Helper()
	capture := &triggerLogBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return capture
}

type triggerLogBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *triggerLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *triggerLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestTDilithium3ProposalTriggerHandlerDefaultPosture pins the default
// posture end to end: with the gate closed, a well-formed trigger delivered
// through the real handler is a zero-side-effect, zero-log drop -- no rate
// entry, no session, no goroutine-observable state, no log line, even with
// the trace switch open. The positive control proves the capture works: with
// the gate open the same handler DOES log its refusal (the missing share),
// so the silence above is the contract, not a broken capture.
func TestTDilithium3ProposalTriggerHandlerDefaultPosture(t *testing.T) {
	capture := captureLogs(t)
	t.Setenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL", "1")
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "")
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}

	payload := tdilithium3ProposalTriggerPayload(triggerTestEpoch, triggerTestSlot, triggerTestBound(), 0)
	node.handleTDilithium3ProposalTrigger(p2p.PeerMessage{
		From: p2p.PeerID("trigger-proposer-peer"), Type: p2p.MsgTypeTDilithium3ProposalTrigger, Payload: payload,
	})
	if len(node.tdilithium3ProposalTriggerRate) != 0 {
		t.Fatal("a closed-gate trigger left rate-limit state behind")
	}
	if len(node.tdilithium3ProposalTriggerSessions) != 0 {
		t.Fatal("a closed-gate trigger left session state behind")
	}
	if out := capture.String(); strings.Contains(out, "proposal executor") {
		t.Fatalf("a closed-gate trigger produced logs: %s", out)
	}
	// Positive control: same handler, gate open -- the refusal past the gate
	// logs, proving the capture is live.
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	node.config.TSSV1ProposalActivationEpoch = triggerTestEpoch
	capture.buf.Reset()
	node.handleTDilithium3ProposalTrigger(p2p.PeerMessage{
		From: p2p.PeerID("trigger-proposer-peer"), Type: p2p.MsgTypeTDilithium3ProposalTrigger, Payload: payload,
	})
	if out := capture.String(); !strings.Contains(out, "proposal executor") {
		t.Fatalf("an open-gate refusal produced no decision log; the capture may be broken: %s", out)
	}
	if len(node.tdilithium3ProposalTriggerSessions) != 0 {
		t.Fatal("an open-gate trigger on a node without a share left session state behind")
	}
}

// TestTDilithium3ProposalTriggerHandlerRefusals walks the handler's refusal
// ordering with the gate open and the consensus wiring present: a malformed
// payload, a zero binding, a rate-limited peer, a non-proposer sender, and a
// legitimate proposer all drop -- the last because the node holds no share --
// and none of them leaves session state behind.
func TestTDilithium3ProposalTriggerHandlerRefusals(t *testing.T) {
	node, _ := triggerTestElectedProposer(t)
	bound := triggerTestBound()
	proposerPeer := p2p.PeerID("trigger-proposer-peer")
	otherPeer := p2p.PeerID("trigger-other-peer")
	deliver := func(from p2p.PeerID, payload []byte) {
		t.Helper()
		node.handleTDilithium3ProposalTrigger(p2p.PeerMessage{
			From: from, Type: p2p.MsgTypeTDilithium3ProposalTrigger, Payload: payload,
		})
	}
	assertNoSession := func(stage string) {
		t.Helper()
		if len(node.tdilithium3ProposalTriggerSessions) != 0 {
			t.Fatalf("%s left session state behind", stage)
		}
	}

	// Malformed payload (too short): dropped before even the gate.
	deliver(proposerPeer, make([]byte, 10))
	assertNoSession("malformed payload")

	// Zero binding: refused after the gate.
	deliver(proposerPeer, tdilithium3ProposalTriggerPayload(triggerTestEpoch, triggerTestSlot, [32]byte{}, 0))
	assertNoSession("zero binding")

	// Non-proposer sender: refused at the B-5 check.
	capture := captureLogs(t)
	deliver(otherPeer, tdilithium3ProposalTriggerPayload(triggerTestEpoch, triggerTestSlot, bound, 0))
	if out := capture.String(); !strings.Contains(out, "not the proposer (B-5)") {
		t.Fatalf("the non-proposer trigger did not fail the B-5 check: %s", out)
	}
	assertNoSession("non-proposer trigger")

	// A legitimate proposer on a node without a share: the auth passes and
	// the start fails closed on the missing session inputs.
	capture.buf.Reset()
	deliver(proposerPeer, tdilithium3ProposalTriggerPayload(triggerTestEpoch, triggerTestSlot, bound, 0))
	if out := capture.String(); !strings.Contains(out, "active share") {
		t.Fatalf("the proposer trigger did not reach the start's share gate: %s", out)
	}
	assertNoSession("proposer trigger without a share")

	// Rate limit: the B-5-refused sender already burned one unit; burn the
	// rest of its quota with distinct slots, then the next trigger from that
	// peer must be refused before any session work.
	for i := 1; i < tdilithium3ProposalTriggerPerPeerMax; i++ {
		deliver(otherPeer, tdilithium3ProposalTriggerPayload(triggerTestEpoch, uint64(200+i), bound, 0))
	}
	capture.buf.Reset()
	deliver(otherPeer, tdilithium3ProposalTriggerPayload(triggerTestEpoch, triggerTestSlot, bound, 0))
	if out := capture.String(); !strings.Contains(out, "rate-limited") {
		t.Fatalf("the over-quota trigger was not rate-limited: %s", out)
	}
	assertNoSession("rate-limited trigger")
}

// TestTDilithium3ProposalTriggerChannelConvergence is the channel's core
// assertion: a real six-member DKG ceremony provides the four signers'
// persisted shares, the request is derived from a TRIGGER PAYLOAD alone (the
// exact wire bytes the proposer broadcasts, parsed by the production parser),
// and the four-of-six session converges in-process over the loopback network.
// The resulting group signature must verify under the ceremony's group key
// and be accepted by the block validator's per-epoch v1 branch.
func TestTDilithium3ProposalTriggerChannelConvergence(t *testing.T) {
	// The signing inbox admissibility gate is keyed on the experimental
	// protocol env (the same gate the seal path's sessions pass), so the
	// in-process signers run with it open.
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	fixture := tdilithium3SeamFixtureFor(t)
	epoch := fixture.shares[0].ActivationEpoch
	proposerAddr := types.BytesToAddress([]byte{0x71})
	header := &encoding.BlockHeader{
		ChainID:      tdilithium3SeamTestChainID,
		Epoch:        epoch,
		Slot:         64,
		Height:       640,
		ProposerAddr: proposerAddr,
	}
	signingRoot, err := encoding.BlockHeaderSigningRoot(header)
	if err != nil {
		t.Fatalf("header signing root: %v", err)
	}
	bound := consensus.ComputeTSSCanonicalBinding(
		header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, "block", signingRoot[:],
	)
	// The proposer broadcasts the trigger; a signer parses it and derives the
	// session request from the payload alone (plus its own chain ID and
	// share), exactly as the production handler does. A request whose
	// candidate slots were all filtered is a statistical outcome, mirrored on
	// the wire by the proposer's retry announcement: the next attempt ordinal
	// is a fresh session with fresh one-time material, exactly as the seal
	// path retries.
	var signature []byte
	for attempt := uint64(0); attempt < tdilithium3ProposalSigningMaxAttempts && signature == nil; attempt++ {
		wire := tdilithium3ProposalTriggerPayload(epoch, header.Slot, bound, attempt)
		wireEpoch, wireSlot, wireBound, wireAttempt, ok := tdilithium3ProposalTriggerParse(wire)
		if !ok || wireEpoch != epoch || wireSlot != header.Slot || wireBound != bound || wireAttempt != attempt {
			t.Fatalf("trigger payload round trip broken: ok=%v", ok)
		}
		nonce, err := dilithium3v1.SigningRequestAttemptNonce(
			tdilithium3SeamTestChainID, wireEpoch, wireSlot, protocol.SigningDomainBlock, wireBound[:], wireAttempt,
		)
		if err != nil {
			t.Fatalf("attempt nonce: %v", err)
		}
		request := protocol.SignRequest{
			Protocol:     protocol.ThresholdProtocolDilithium3V1,
			Key:          fixture.shares[0].Key.Clone(),
			Committee:    fixture.shares[0].Committee.Clone(),
			ChainID:      tdilithium3SeamTestChainID,
			Epoch:        wireEpoch,
			Slot:         wireSlot,
			Domain:       protocol.SigningDomainBlock,
			Message:      append([]byte(nil), wireBound[:]...),
			AttemptNonce: nonce,
		}
		if err := request.Validate(); err != nil {
			t.Fatalf("trigger-derived request (attempt %d): %v", attempt, err)
		}
		// The four-of-six session converges over the loopback network; the
		// signature binds the trigger's bound message.
		harness := tdilithium3SeamHarnessFor(t, fixture, fixture.signersFor(), request, 0)
		signature = harness.signOne(t)
	}
	if len(signature) != 3293 {
		t.Fatalf("signature length %d, want 3293", len(signature))
	}
	// Validator acceptance: the v1 branch armed at the trigger's epoch with
	// the ceremony group key accepts the header carrying the group signature.
	validator := newTriggerConvergenceValidator(t, fixture.groupKey, epoch)
	header.Signature = append([]byte(nil), signature...)
	if err := validator.ValidateSignature(header); err != nil {
		t.Fatalf("block validator rejected the trigger-channel group signature: %v", err)
	}
	// Tampered header: the same signature must fail.
	tampered := *header
	tampered.GasUsed ^= 1
	if err := validator.ValidateSignature(&tampered); err == nil {
		t.Fatal("block validator accepted the signature for a tampered header")
	}
}

// newTriggerConvergenceValidator builds the block validator side of the
// convergence assertion: the v1 branch armed at the trigger's epoch with the
// ceremony group key as the anchor custody's answer.
func newTriggerConvergenceValidator(t *testing.T, groupKey []byte, epoch uint64) *core.BlockValidator {
	t.Helper()
	validator := core.NewBlockValidator(tdilithium3SeamTestChainID, 30_000_000)
	validator.SetTSSV1ProposalActivationEpoch(epoch)
	validator.SetTSSV1GroupKeyLookup(func(uint64) []byte {
		return append([]byte(nil), groupKey...)
	})
	return validator
}

// TestTDilithium3ProposalFutureTolerance pins the future-slot gate (audit
// follow-up, fix 3): a trigger whose slot has not started — beyond one slot
// of clock-skew tolerance — is refused, the slot's own window passes, and
// without a chain clock the gate bounds nothing.
func TestTDilithium3ProposalFutureTolerance(t *testing.T) {
	consensus.EnableTestHelpers()
	consensus.ResetGenesisTimeForTesting()
	defer consensus.ResetGenesisTimeForTesting()
	if !tdilithium3ProposalWithinFutureTolerance(5, time.Now()) {
		t.Fatal("without a chain clock the future-tolerance gate must not bound anything")
	}
	if err := consensus.SetGenesisTime(1700000000); err != nil {
		t.Fatal(err)
	}
	const slot = 40
	start := consensus.GetSlotStartTime(slot)
	// The slot's own window: inside the tolerance.
	if !tdilithium3ProposalWithinFutureTolerance(slot, start) {
		t.Fatal("the slot's own start was refused as a future slot")
	}
	// One slot of skew tolerance: a start up to one slot ahead still passes.
	if !tdilithium3ProposalWithinFutureTolerance(slot, start.Add(-consensus.SlotDuration)) {
		t.Fatal("a start within the one-slot skew tolerance was refused")
	}
	// Beyond the tolerance: refused.
	if tdilithium3ProposalWithinFutureTolerance(slot, start.Add(-consensus.SlotDuration-time.Second)) {
		t.Fatal("a slot start beyond the skew tolerance was accepted")
	}
}

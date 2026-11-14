// Quantaureum Node source, version 1.0.0.
package node

// Node-side proposal signing executor (TSS-R3-B-1 P1). When a block is
// produced, this path may replace the proposer's individual header signature
// with a Dilithium3 v1 four-signer threshold signature over the header's
// canonical TSS binding. It reuses the seal executor's session machinery
// unchanged -- the roster-derived binding (newTDilithium3SigningBinding), the
// inbox/envelope/journal transport half, the candidate-slot schedule
// (signWithTDilithium3Signing), and the attempt subset rotation
// (tdilithium3SealSigningSigners) -- and differs from the seal only in the
// signed message and the delivery of the result:
//
//   - The message is HARD-BOUND to the proposal: bound =
//     ComputeTSSCanonicalBinding(chainID, epoch, slot, proposerAddr, "block",
//     signingData). The session never signs a raw hash or an arbitrary 32
//     bytes (the R38-P1-03/B-5 failure mode). The validator side re-derives
//     the same binding, so the group signature carries the proposer's
//     accountability even though four signers produced it.
//   - The session identity is Dilithium3SigningSessionID(request, signers)
//     derived from the request itself, so a proposal session and a seal
//     session of the same slot never share a session id (different domain and
//     message): their inboxes, journals, and one-time records cannot cross.
//   - The produced signature passes TWO self-checks before it is returned:
//     the ceremony group public key verifies it over the bound (cryptographic
//     self-check), and the QTD anchor custody serves exactly that ceremony
//     key for the header's epoch (anchor-agreement self-check -- the same key
//     the validators' v1 branch verifies against; an empty custody refuses
//     too, because a like-configured validator would reject the header). A
//     header that no validator would accept never leaves the producer: the
//     caller falls back to the individual signature.
//
// The path is gated by two INDEPENDENT layers, and both must be open: the
// explicit environment opt-in (network-scoped; mainnet needs the extra
// acknowledgement) and the chain-height gate tssV1ProposalActivationEpoch.
// With either layer closed the entry returns nil before touching the share
// store, the p2p host, or any session state -- the legacy signature path runs
// byte-for-byte unchanged, and the default posture (no env, no activation
// epoch) produces no new logs. Even with both layers open, every missing
// input fails closed: the active share, the roster, the peer bindings, and
// the signer subset are all required, exactly as for the seal executor.
//
// TRIGGER CHANNEL (P2): the four signers of an attempt converge on a
// multi-node network through the proposal trigger (p2p message kind 103, see
// the trigger-channel section below). The proposer announces every attempt it
// runs; a signer that hears the announcement starts the same session, and the
// attempt's other signers need nothing else -- the announcement carries the
// full public tuple (epoch, slot, bound, attempt) the session derives from.
// This does not weaken the default posture: the gate is closed everywhere
// unless explicitly opened, an unannounced attempt still times out inside the
// bounded budget, and the legacy individual signature is produced as before.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const (
	// tdilithium3ProposalSigningMaxAttempts bounds the attempts of one header,
	// mirroring the seal executor's bound. Each attempt is its own session over
	// fresh one-time material with its own signer subset
	// (tdilithium3SealSigningSubset), so a run skips the attempts that exclude
	// the proposer and rotates onto ones that include it.
	tdilithium3ProposalSigningMaxAttempts = 6

	// tdilithium3ProposalSigningWindow bounds, from the slot's start on the
	// chain clock, when attempts of this slot's proposal may still start --
	// the same slot-anchored shape as the seal's retry window, with its own
	// constant so the two budgets stay independently tunable.
	tdilithium3ProposalSigningWindow = 4 * consensus.SlotDuration

	// tdilithium3ProposalSigningBackoff is the pause before the next attempt.
	tdilithium3ProposalSigningBackoff = time.Second

	// tdilithium3ProposalSigningBudget bounds the whole proposal signing
	// operation: the session runs synchronously inside block production, so
	// the budget caps how long a block's publication may be delayed by the
	// threshold session before the individual signature is produced instead.
	// Half a slot leaves the rest of the slot to the legacy flow; the value is
	// a devnet-tuning starting point (design open question: per-slot budget
	// under proposal+seal concurrency is measured in the P2 stage).
	tdilithium3ProposalSigningBudget = 6 * time.Second

	// tdilithium3ProposalSigningMaxConcurrent bounds how many proposal
	// sessions run at once on this node. This is the proposal path's OWN
	// budget -- it never shares or steals the seal executor's permits. Under
	// normal cadence at most one proposal session is live (the producer signs
	// one header synchronously), so this is generous headroom that the
	// acquire path never blocks on, mirroring the seal cap's structure.
	tdilithium3ProposalSigningMaxConcurrent = 8
)

// errTDilithium3ProposalSigningNotASigner reports that the local validator is
// not in the signer subset of the attempt. For the proposal path this is a
// rotation signal rather than a stop: the proposer skips to the next attempt,
// whose subset may include it again.
var errTDilithium3ProposalSigningNotASigner = errors.New("local validator is not one of the Dilithium3 v1 proposal signers")

// tdilithium3ProposalSigningEnvEnabled is the environment layer of the
// proposal gate: the explicit QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL=1 opt-in.
// The scope rule mirrors the experimental protocol gate's structure but is an
// independent switch with its own name: non-mainnet networks need only the
// proposal opt-in; mainnet additionally requires the
// QAU_ENABLE_TDILITHIUM3_V1_MAINNET=1 acknowledgement, so a mainnet binary
// cannot open the proposal path with the proposal env alone.
func tdilithium3ProposalSigningEnvEnabled(networkID uint64) bool {
	if os.Getenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL") != "1" {
		return false
	}
	if networkID != MainnetNetworkID {
		return true
	}
	return os.Getenv("QAU_ENABLE_TDILITHIUM3_V1_MAINNET") == "1"
}

// tdilithium3ProposalSigningEnabled reports whether BOTH independent gate
// layers are open for a header of the given epoch: the environment opt-in
// above, and the chain-height gate (config.TSSV1ProposalActivationEpoch, 0 =
// never active). Either layer closed keeps the legacy signature path.
func tdilithium3ProposalSigningEnabled(n *Node, epoch uint64) bool {
	if n == nil || n.config == nil {
		return false
	}
	if !tdilithium3ProposalSigningEnvEnabled(n.config.NetworkID) {
		return false
	}
	activation := n.config.TSSV1ProposalActivationEpoch
	return activation != 0 && epoch >= activation
}

// tdilithium3ProposalSigningTrace reports whether the proposal executor's
// decision log is enabled (QAU_TRACE_TDILITHIUM3_V1_PROPOSAL=1). Every gate
// here fails closed, so with the trace closed a refusal is indistinguishable
// from a path never entered -- exactly the default posture the P0 contract
// pins. The switch promotes only those decisions for devnet attribution.
func tdilithium3ProposalSigningTrace() bool {
	return os.Getenv("QAU_TRACE_TDILITHIUM3_V1_PROPOSAL") == "1"
}

// tdilithium3ProposalTrace logs one proposal executor decision when the trace
// switch is open, and does nothing otherwise.
func tdilithium3ProposalTrace(format string, args ...any) {
	if !tdilithium3ProposalSigningTrace() {
		return
	}
	nodeLog.Info("Dilithium3 v1 proposal executor: "+format, args...)
}

// tdilithium3ProposalWithinWindow reports whether now is still inside the
// slot's proposal signing window, anchored to the slot's start on the chain
// clock (the seal's window shape). Without a configured genesis time there is
// no chain clock, and the window does not bound anything.
func tdilithium3ProposalWithinWindow(slot uint64, now time.Time) bool {
	if !consensus.IsGenesisTimeConfigured() {
		return true
	}
	return now.Sub(consensus.GetSlotStartTime(slot)) <= tdilithium3ProposalSigningWindow
}

// tdilithium3ProposalWithinFutureTolerance refuses a trigger whose slot has
// not started yet: a trigger for a future slot can only be a misconfigured or
// hostile announcement (a slot's own proposer cannot have anything to sign
// before its slot begins), and starting a session for it would burn one-time
// material on a message no header will carry. One slot of tolerance absorbs
// modest clock skew between peers; without a configured genesis time there is
// no chain clock and the check bounds nothing.
func tdilithium3ProposalWithinFutureTolerance(slot uint64, now time.Time) bool {
	if !consensus.IsGenesisTimeConfigured() {
		return true
	}
	return !consensus.GetSlotStartTime(slot).After(now.Add(consensus.SlotDuration))
}

// tdilithium3ProposalAttemptRetryable reports whether a failed attempt moves
// the header on to the next ordinal: its candidate slots were all filtered (a
// statistical outcome of the per-slot rejection sampling), or one of its
// signers is unreachable from this node, in which case a later attempt's
// subset may exclude that signer. Any other failure is structural and stops.
func tdilithium3ProposalAttemptRetryable(err error) bool {
	return errors.Is(err, errTDilithium3SigningRequestExhausted) ||
		errors.Is(err, errTDilithium3SigningSignerUnreachable)
}

// tdilithium3V1ProposalHeaderSignature attempts the Dilithium3 v1 proposal
// session for the header being produced and returns the four-signer group
// signature over the header's canonical TSS binding. A closed gate, a missing
// input, or a failed session returns nil -- the caller then keeps its legacy
// signature path (the individual fallback is the steady state), so this
// function only ever ADDS a signature, never removes one.
//
// The gate check is the first statement after the nil guards: with the
// default posture (no env opt-in or no activation epoch) the function touches
// nothing -- no share store, no p2p host, no logs -- and returns immediately.
func (n *Node) tdilithium3V1ProposalHeaderSignature(header *encoding.BlockHeader) []byte {
	if n == nil || n.blockProducer == nil || header == nil {
		return nil
	}
	epoch, slot := header.Epoch, header.Slot
	if !tdilithium3ProposalSigningEnabled(n, epoch) {
		return nil
	}
	signingData := n.blockProducer.computeSigningData(header)
	if signingData == nil {
		tdilithium3ProposalTrace("epoch %d slot %d: no signing data", epoch, slot)
		return nil
	}
	// Hard message contract: the session signs the canonical TSS binding over
	// the header's own chain/epoch/slot/proposer tuple -- never the raw
	// signing hash, never an arbitrary 32 bytes. The validator side derives
	// the identical binding, so acceptance here and acceptance there are the
	// same equation.
	bound := consensus.ComputeTSSCanonicalBinding(header.ChainID, epoch, slot, header.ProposerAddr, "block", signingData)
	activationEpoch, _, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		tdilithium3ProposalTrace("epoch %d slot %d: active share: %v", epoch, slot, err)
		return nil
	}
	if epoch < activationEpoch {
		tdilithium3ProposalTrace("epoch %d slot %d: precedes the activation epoch %d", epoch, slot, activationEpoch)
		return nil
	}
	base := n.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, tdilithium3ProposalSigningBudget)
	defer cancel()
	if !n.acquireTDilithium3ProposalSigning(ctx) {
		tdilithium3ProposalTrace("epoch %d slot %d: proposal permit unavailable", epoch, slot)
		return nil
	}
	defer n.releaseTDilithium3ProposalSigning()
	for attempt := uint64(0); attempt < tdilithium3ProposalSigningMaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil
		}
		if attempt > 0 {
			if !tdilithium3ProposalWithinWindow(slot, time.Now()) {
				tdilithium3ProposalTrace("slot %d: attempt %d is past the proposal window", slot, attempt)
				return nil
			}
			if !n.tdilithium3ProposalSleep(ctx) {
				return nil
			}
		}
		// Announce the attempt BEFORE running it: the attempt's other signers
		// start their session on the trigger, and a host never receives its
		// own broadcast, so the proposer must run its own attempt locally
		// (the seal request's broadcast-plus-local-start shape).
		n.broadcastTDilithium3ProposalTrigger(epoch, slot, bound, attempt)
		signature, err := n.tdilithium3ProposalAttemptRun(ctx, activationEpoch, epoch, slot, bound, attempt)
		if err == nil {
			tdilithium3ProposalTrace("epoch %d slot %d: signed by attempt %d", epoch, slot, attempt)
			return signature
		}
		if errors.Is(err, errTDilithium3ProposalSigningNotASigner) {
			// This attempt's subset excludes the proposer; rotate on.
			tdilithium3ProposalTrace("slot %d attempt %d: local validator not in the subset", slot, attempt)
			continue
		}
		if errors.Is(err, errTDilithium3ProposalSelfCheck) {
			// A produced signature that fails the ceremony or anchor
			// self-check is structural for this slot's material: retrying
			// reproduces it, so the header falls back to the individual
			// signature instead of rotating attempts.
			tdilithium3ProposalTrace("slot %d attempt %d: self-check failed: %v", slot, attempt, err)
			return nil
		}
		tdilithium3ProposalTrace("slot %d attempt %d failed: %v", slot, attempt, err)
		if !tdilithium3ProposalAttemptRetryable(err) {
			return nil
		}
	}
	tdilithium3ProposalTrace("slot %d: attempts exhausted; falling back", slot)
	return nil
}

// errTDilithium3ProposalSelfCheck reports that a produced signature did not
// pass one of the two self-checks (the ceremony key verification or the
// anchor-custody agreement). It is structural for the slot's material: the
// caller falls back instead of rotating attempts.
var errTDilithium3ProposalSelfCheck = errors.New("Dilithium3 v1 proposal executor self-check failed")

// tdilithium3ProposalAttemptRun executes ONE attempt end to end -- signer
// resolution, binding, the four-round session, and both self-checks -- and
// returns the signature that passed them. It is the shared attempt body of
// the local producer path (which loops over attempts synchronously,
// announcing each one to the committee) and the trigger path (which runs the
// announced attempt once, asynchronously).
func (n *Node) tdilithium3ProposalAttemptRun(ctx context.Context, activationEpoch, epoch, slot uint64, bound [32]byte, attempt uint64) ([]byte, error) {
	signature, err := n.tdilithium3ProposalSigningAttempt(ctx, activationEpoch, epoch, slot, bound[:], attempt)
	if err != nil {
		return nil, err
	}
	// Self-check 1 (cryptographic): the produced signature must verify under
	// the CEREMONY group public key over the bound. A header that no
	// validator would accept must not leave the producer.
	_, groupKey, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		return nil, fmt.Errorf("%w: identity: %v", errTDilithium3ProposalSelfCheck, err)
	}
	if !tdilithium3ProposalGroupVerify(groupKey, bound[:], signature) {
		return nil, fmt.Errorf("%w: signature failed the ceremony key verification", errTDilithium3ProposalSelfCheck)
	}
	// Self-check 2 (anchor agreement): the validators' v1 branch verifies
	// against the QTD anchor custody's key for THIS epoch, so the ceremony
	// key must be exactly what that custody serves. See
	// tdilithium3ProposalAnchorAgrees for the empty-custody verdict.
	if !n.tdilithium3ProposalAnchorAgrees(epoch, groupKey) {
		return nil, fmt.Errorf("%w: anchor custody does not vouch for the ceremony key", errTDilithium3ProposalSelfCheck)
	}
	return signature, nil
}

// tdilithium3ProposalSigningAttempt runs one attempt: it resolves the
// attempt's signer subset (the seal executor's own rotation, unchanged), skips
// subsets that exclude the local validator, assembles the roster-derived
// binding, and signs the canonical binding through the shared schedule. The
// session id is derived from the request (block domain, bound message), so it
// cannot collide with a seal session of the same slot.
func (n *Node) tdilithium3ProposalSigningAttempt(
	ctx context.Context,
	activationEpoch, epoch, slot uint64,
	bound []byte,
	attempt uint64,
) ([]byte, error) {
	if n == nil || n.config == nil {
		return nil, fmt.Errorf("Dilithium3 v1 proposal executor requires a configured node")
	}
	signers, localSigner, err := n.tdilithium3SealSigningSigners(activationEpoch, slot, attempt)
	if err != nil {
		return nil, fmt.Errorf("Dilithium3 v1 proposal executor signers at activation epoch %d: %w", activationEpoch, err)
	}
	if !localSigner {
		return nil, errTDilithium3ProposalSigningNotASigner
	}
	binding, err := n.newTDilithium3SigningBinding(activationEpoch, signers, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Dilithium3 v1 proposal executor binding: %w", err)
	}
	defer binding.close()
	signature, outcomes, err := n.signWithTDilithium3Signing(
		ctx, binding, epoch, slot, protocol.SigningDomainBlock, bound, attempt,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", tdilithium3SealOutcomeSummary(outcomes), err)
	}
	if len(signature) != qcrypto.Dilithium3SignatureSize {
		return nil, fmt.Errorf("Dilithium3 v1 proposal executor produced a %d-byte signature, want %d",
			len(signature), qcrypto.Dilithium3SignatureSize)
	}
	return signature, nil
}

// tdilithium3ProposalGroupVerify is self-check 1: it verifies one produced
// signature against the CEREMONY group public key (the active share's key,
// tdilithium3ActiveShareIdentityCached) over the bound message. An unusable
// group key or a failing verification is reported as false, so the caller
// falls back. The anchor-side agreement check is
// tdilithium3ProposalAnchorAgrees (self-check 2).
func tdilithium3ProposalGroupVerify(groupKey []byte, bound, signature []byte) bool {
	if len(groupKey) == 0 || len(signature) == 0 {
		return false
	}
	key, err := qcrypto.PublicKeyFromBytes(groupKey)
	if err != nil {
		return false
	}
	return key.Verify(bound, signature)
}

// tdilithium3ProposalSleep pauses before the next attempt, and reports
// whether the pause completed rather than being canceled.
func (n *Node) tdilithium3ProposalSleep(ctx context.Context) bool {
	timer := time.NewTimer(tdilithium3ProposalSigningBackoff)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// tdilithium3ProposalAnchorAgrees is self-check 2 (anchor agreement): the
// ceremony key the session signed with must be exactly the key the QTD anchor
// custody serves for the header's epoch -- the same key the validators' v1
// branch verifies against (wired from GroupPublicKeyForEpoch in
// wireTSSVerifier).
//
// The EMPTY custody case refuses too, deliberately. The alternative reading
// -- "empty means the epoch is not anchored yet, and the header's own
// QTDGroupKey field self-anchors it" -- does not hold: the anchor adoption
// (ObserveAnchoredGroupKey, called only from onCanonicalBlockImported at
// block_producer.go:163, invoked post-apply at node.go:9125 and node.go:10563)
// runs AFTER ValidateSignature in every import path (syncer.go:1059), so an
// empty-custody validator rejects a group-signed header before the anchor
// inside it can ever be adopted. An armed validator's custody is non-empty by
// construction instead (registerTDilithium3SigningFinalitySigner re-roots and
// installs at activation, tdilithium3_signing_finality.go:157-163, refreshed
// at startup node.go:7673), so an empty lookup here means this node's
// verification side is not reachable for the epoch -- the same refusal every
// like-configured peer would produce. Refusing keeps the individual fallback
// and never broadcasts a header the network rejects as a whole.
func (n *Node) tdilithium3ProposalAnchorAgrees(epoch uint64, ceremonyKey []byte) bool {
	if n == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	qfs := n.blockProducer.QPOS().GetQTDFinality()
	if qfs == nil {
		return false
	}
	return tdilithium3ProposalEpochKeyAgrees(qfs, epoch, ceremonyKey)
}

// tdilithium3ProposalEpochKeyAgrees is the custody comparison itself, split
// out of the node method so the three outcomes (anchored equal, anchored
// different, empty/unknown) are directly testable.
func tdilithium3ProposalEpochKeyAgrees(qfs *consensus.QTDFinalityState, epoch uint64, ceremonyKey []byte) bool {
	if qfs == nil {
		return false
	}
	anchored := qfs.GroupPublicKeyForEpoch(epoch)
	if len(anchored) == 0 {
		return false
	}
	return bytes.Equal(anchored, ceremonyKey)
}

// acquireTDilithium3ProposalSigning takes one of the node's bounded
// proposal-signing permits. This is the proposal path's own budget; the seal
// executor's permits are never consumed or blocked by it.
func (n *Node) acquireTDilithium3ProposalSigning(ctx context.Context) bool {
	n.tdilithium3ProposalSigningMu.Lock()
	if n.tdilithium3ProposalSigningRunning == nil {
		n.tdilithium3ProposalSigningRunning = make(chan struct{}, tdilithium3ProposalSigningMaxConcurrent)
	}
	running := n.tdilithium3ProposalSigningRunning
	n.tdilithium3ProposalSigningMu.Unlock()
	select {
	case running <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// releaseTDilithium3ProposalSigning frees one proposal-signing permit; every
// acquire pairs with exactly one release, deferred by the entry.
func (n *Node) releaseTDilithium3ProposalSigning() {
	n.tdilithium3ProposalSigningMu.Lock()
	running := n.tdilithium3ProposalSigningRunning
	n.tdilithium3ProposalSigningMu.Unlock()
	if running == nil {
		return
	}
	select {
	case <-running:
	default:
		nodeLog.Warn("Dilithium3 v1 proposal executor: release without a matching acquire")
	}
}

// ---------------------------------------------------------------------------
// Proposal trigger channel (TSS-R3-B-1 P2). The block proposer announces each
// attempt of a proposal signing session on the p2p trigger kind (103); the
// attempt's other signers start the same session on the announcement, which
// is what makes the four-of-six threshold session converge on a multi-node
// network. The shape mirrors the seal executor's trigger flow (announcement,
// receiver-side B-5 authentication, per-peer rate limit, ordinal admission,
// session replacement) with one deliberate simplification: the trigger is
// self-sufficient (it carries the full signed-message binding, so a signer
// starts immediately and nothing waits for pending state), which removes the
// seal's deferred-latch half -- the pre-registered candidate inboxes, the
// load-bearing half that keeps a first round message from being dropped
// before a party exists, remain.
// ---------------------------------------------------------------------------

const (
	// tdilithium3ProposalTriggerPayloadLen is the base trigger payload:
	// epoch(8) | slot(8) | bound(32) | attempt(8), all big endian.
	tdilithium3ProposalTriggerPayloadLen = 56

	// tdilithium3ProposalTriggerPayloadMaxLen bounds appended future fields,
	// mirroring the seal request's 40/48 dual-length precedent.
	tdilithium3ProposalTriggerPayloadMaxLen = 96

	// tdilithium3ProposalTriggerPerPeerWindow is the sliding window for the
	// per-peer rate limit of inbound triggers (the seal request's
	// NODE-R12-H01 posture). An honest proposer announces at most a few
	// attempts per slot.
	tdilithium3ProposalTriggerPerPeerWindow = 10 * time.Second

	// tdilithium3ProposalTriggerPerPeerMax caps one peer's triggers per
	// window. An honest proposer sends at most one trigger per attempt and
	// at most tdilithium3ProposalSigningMaxAttempts attempts per slot, so 20
	// is generous for honest peers and blocks floods.
	tdilithium3ProposalTriggerPerPeerMax = 20

	// tdilithium3ProposalTriggerPeerRateMaxSize caps the peers tracked in
	// the rate map (the qtdPeerRateMaxSize rationale).
	tdilithium3ProposalTriggerPeerRateMaxSize = 1024

	// tdilithium3ProposalTriggerPeerRateTTL is the entry time-to-live (the
	// qtdPeerRateTTL rationale).
	tdilithium3ProposalTriggerPeerRateTTL = time.Hour

	// tdilithium3ProposalOrdinalHistorySlots is how many slots of admitted
	// ordinal history a node keeps (the seal executor's retention shape).
	tdilithium3ProposalOrdinalHistorySlots = 256
)

// tdilithium3ProposalTriggerRateInfo tracks one peer's trigger rate-limit
// state (the qtdPeerRateInfo layout: window start, count, last seen).
type tdilithium3ProposalTriggerRateInfo struct {
	windowStart time.Time
	count       int
	lastSeen    time.Time
}

// tdilithium3ProposalTriggerSession is the running executor attempt of one
// triggered proposal slot on a signer. A higher announced ordinal replaces
// the running one (the attempt cancel below).
type tdilithium3ProposalTriggerSession struct {
	attempt uint64
	cancel  context.CancelFunc
}

// tdilithium3ProposalTriggerParse splits one trigger payload into its public
// tuple. A payload shorter than the base layout (or beyond the extension
// bound) is not a trigger the executor can act on.
func tdilithium3ProposalTriggerParse(payload []byte) (epoch, slot uint64, bound [32]byte, attempt uint64, ok bool) {
	if len(payload) < tdilithium3ProposalTriggerPayloadLen || len(payload) > tdilithium3ProposalTriggerPayloadMaxLen {
		return 0, 0, [32]byte{}, 0, false
	}
	epoch = binary.BigEndian.Uint64(payload[0:8])
	slot = binary.BigEndian.Uint64(payload[8:16])
	copy(bound[:], payload[16:48])
	attempt = binary.BigEndian.Uint64(payload[48:56])
	return epoch, slot, bound, attempt, true
}

// broadcastTDilithium3ProposalTrigger announces one attempt of one proposal
// slot to the committee. The proposer sends this before running its own
// attempt: a host never receives its own broadcast, so the local run below is
// the proposer's own participation (the seal request's
// broadcast-plus-local-start shape, qtd_seal.go).
// tdilithium3ProposalTriggerPayload encodes one trigger's public tuple into
// the wire format (epoch | slot | bound | attempt, big endian). It is the
// exact inverse of tdilithium3ProposalTriggerParse, and the sender-side and
// receiver-side session derivations consume the same bound bytes, so both
// ends derive one session id.
func tdilithium3ProposalTriggerPayload(epoch, slot uint64, bound [32]byte, attempt uint64) []byte {
	msg := make([]byte, tdilithium3ProposalTriggerPayloadLen)
	binary.BigEndian.PutUint64(msg[0:8], epoch)
	binary.BigEndian.PutUint64(msg[8:16], slot)
	copy(msg[16:48], bound[:])
	binary.BigEndian.PutUint64(msg[48:56], attempt)
	return msg
}

func (n *Node) broadcastTDilithium3ProposalTrigger(epoch, slot uint64, bound [32]byte, attempt uint64) {
	if n == nil || n.p2pHost == nil {
		return
	}
	if err := n.p2pHost.BroadcastTDilithium3ProposalTrigger(tdilithium3ProposalTriggerPayload(epoch, slot, bound, attempt)); err != nil {
		tdilithium3ProposalTrace("slot %d attempt %d: trigger broadcast failed: %v", slot, attempt, err)
	}
}

// allowTDilithium3ProposalTriggerFromPeer is the per-peer sliding-window rate
// limit for inbound triggers (the allowQTDSealFromPeer shape): entries beyond
// the cap are cleaned first, a window older than
// tdilithium3ProposalTriggerPerPeerWindow resets, and the count is capped.
func (n *Node) allowTDilithium3ProposalTriggerFromPeer(peerID p2p.PeerID) bool {
	if n == nil {
		return false
	}
	n.tdilithium3ProposalTriggerRateMu.Lock()
	defer n.tdilithium3ProposalTriggerRateMu.Unlock()
	if n.tdilithium3ProposalTriggerRate == nil {
		n.tdilithium3ProposalTriggerRate = make(map[p2p.PeerID]*tdilithium3ProposalTriggerRateInfo)
	}
	now := time.Now()
	if len(n.tdilithium3ProposalTriggerRate) >= tdilithium3ProposalTriggerPeerRateMaxSize {
		for pid, info := range n.tdilithium3ProposalTriggerRate {
			if now.Sub(info.lastSeen) >= tdilithium3ProposalTriggerPeerRateTTL {
				delete(n.tdilithium3ProposalTriggerRate, pid)
			}
		}
	}
	info, ok := n.tdilithium3ProposalTriggerRate[peerID]
	if !ok || now.Sub(info.windowStart) >= tdilithium3ProposalTriggerPerPeerWindow {
		info = &tdilithium3ProposalTriggerRateInfo{windowStart: now, count: 0}
		n.tdilithium3ProposalTriggerRate[peerID] = info
	}
	info.count++
	info.lastSeen = now
	return info.count <= tdilithium3ProposalTriggerPerPeerMax
}

// tdilithium3ProposalOrdinalAdmissible reports whether an announced attempt
// may start here: attempts advance one ordinal at a time, so an ordinal is
// admitted only up to one past the highest this node has admitted for the
// slot (the seal executor's admission semantics). The proposer announces its
// attempts sequentially, so honest announcements always pass.
func (n *Node) tdilithium3ProposalOrdinalAdmissible(slot, ordinal uint64) bool {
	n.tdilithium3ProposalSigningMu.Lock()
	defer n.tdilithium3ProposalSigningMu.Unlock()
	highest, seen := n.tdilithium3ProposalTriggerOrdinals[slot]
	if !seen {
		return ordinal <= 1
	}
	return ordinal <= highest+1
}

// tdilithium3ProposalOrdinalRecord notes an admitted ordinal for the slot.
func (n *Node) tdilithium3ProposalOrdinalRecord(slot, ordinal uint64) {
	n.tdilithium3ProposalSigningMu.Lock()
	defer n.tdilithium3ProposalSigningMu.Unlock()
	n.tdilithium3ProposalOrdinalRecordLocked(slot, ordinal)
}

// tdilithium3ProposalOrdinalRecordLocked is tdilithium3ProposalOrdinalRecord
// for a caller holding tdilithium3ProposalSigningMu; it also prunes old slots.
func (n *Node) tdilithium3ProposalOrdinalRecordLocked(slot, ordinal uint64) {
	if n.tdilithium3ProposalTriggerOrdinals == nil {
		n.tdilithium3ProposalTriggerOrdinals = make(map[uint64]uint64)
	}
	if highest, seen := n.tdilithium3ProposalTriggerOrdinals[slot]; !seen || ordinal > highest {
		n.tdilithium3ProposalTriggerOrdinals[slot] = ordinal
	}
	if len(n.tdilithium3ProposalTriggerOrdinals) > 2*tdilithium3ProposalOrdinalHistorySlots {
		for old := range n.tdilithium3ProposalTriggerOrdinals {
			if old+tdilithium3ProposalOrdinalHistorySlots < slot {
				delete(n.tdilithium3ProposalTriggerOrdinals, old)
			}
		}
	}
}

// tdilithium3ProposalSigningStart makes this node run the announced attempt
// of one proposal slot, replacing a lower attempt that is still running. The
// caller's pre-registered inbox shells travel with the start: a refusal drops
// them immediately (they would otherwise queue messages for a session that
// never runs), and an accepted start hands them to the run, which releases
// them when the attempt ends (a shell the schedule adopted is owned by its
// slot driver from that point, so the late unregister is a safe no-op). It
// returns false, without any state change, when the gate is closed, the
// ordinal is out of bounds or out of sequence, the proposal window has
// passed, the epoch precedes the share's activation, or the anchor custody
// does not vouch for the ceremony key -- every refusal is fail-closed, and a
// refusal never leaves a goroutine or an inbox behind.
func (n *Node) tdilithium3ProposalSigningStart(epoch, slot uint64, bound [32]byte, ordinal uint64, shells []*tdilithium3SigningInbox) bool {
	if n == nil {
		return false
	}
	started := false
	defer func() {
		if !started {
			// Every refusal drops the pre-registered shells: a refused
			// attempt has no schedule that could adopt them, so the
			// registrations would leak one inbox (with its identity
			// snapshot) per candidate slot.
			n.unregisterTDilithium3ProposalShells(shells)
		}
	}()
	if !tdilithium3ProposalSigningEnabled(n, epoch) {
		// Gate closed (the default posture): zero side effects, zero logs.
		return false
	}
	if ordinal >= tdilithium3ProposalSigningMaxAttempts {
		tdilithium3ProposalTrace("slot %d: attempt %d is beyond the attempt bound", slot, ordinal)
		return false
	}
	if !tdilithium3ProposalWithinWindow(slot, time.Now()) {
		tdilithium3ProposalTrace("slot %d: attempt %d arrived after the proposal window", slot, ordinal)
		return false
	}
	if !tdilithium3ProposalWithinFutureTolerance(slot, time.Now()) {
		tdilithium3ProposalTrace("slot %d: attempt %d is from a slot that has not started yet", slot, ordinal)
		return false
	}
	if !n.tdilithium3ProposalOrdinalAdmissible(slot, ordinal) {
		tdilithium3ProposalTrace("slot %d: attempt %d skips ahead of the attempts seen so far", slot, ordinal)
		return false
	}
	activationEpoch, groupKey, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		tdilithium3ProposalTrace("slot %d attempt %d: active share: %v", slot, ordinal, err)
		return false
	}
	if epoch < activationEpoch {
		tdilithium3ProposalTrace("slot %d attempt %d: epoch %d precedes the activation epoch %d", slot, ordinal, epoch, activationEpoch)
		return false
	}
	if !n.tdilithium3ProposalAnchorAgrees(epoch, groupKey) {
		tdilithium3ProposalTrace("slot %d attempt %d: anchor custody does not vouch for the ceremony key", slot, ordinal)
		return false
	}
	n.tdilithium3ProposalSigningMu.Lock()
	if n.tdilithium3ProposalTriggerSessions == nil {
		n.tdilithium3ProposalTriggerSessions = make(map[uint64]*tdilithium3ProposalTriggerSession)
	}
	if existing := n.tdilithium3ProposalTriggerSessions[slot]; existing != nil {
		if existing.attempt >= ordinal {
			n.tdilithium3ProposalSigningMu.Unlock()
			// An idempotent retransmission or a superseded announcement: the
			// running attempt is not replaced, and its schedule owns the
			// inboxes of that session id -- the duplicate's shells (same
			// derivation, fresh registrations) are dropped here so they
			// cannot shadow the live session's registrations.
			tdilithium3ProposalTrace("slot %d: attempt %d is not newer than the running %d", slot, ordinal, existing.attempt)
			return false
		}
		existing.cancel()
	}
	n.tdilithium3ProposalOrdinalRecordLocked(slot, ordinal)
	base := n.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	session := &tdilithium3ProposalTriggerSession{attempt: ordinal, cancel: cancel}
	n.tdilithium3ProposalTriggerSessions[slot] = session
	n.tdilithium3ProposalSigningMu.Unlock()
	tdilithium3ProposalTrace("slot %d: starting triggered attempt %d for epoch %d", slot, ordinal, epoch)
	started = true
	go n.tdilithium3ProposalTriggerRun(ctx, session, activationEpoch, epoch, slot, bound, ordinal, shells)
	return true
}

// tdilithium3ProposalTriggerRun drives the ANNOUNCED attempt once, on the
// triggered signer. There is no retry loop here: the proposer drives the
// retries and announces each fresh attempt, which supersedes this one via
// the ordinal admission in the start. The converged signature is a byproduct
// on a signer -- the proposer attaches its own copy to the header -- so it
// passes the attempt body's self-checks and is dropped.
//
// The pre-registered inbox shells are released when this run ends, whatever
// the outcome. A shell the request schedule adopted is owned by its slot
// driver from that point and is unregistered by the driver itself when the
// candidate exits. The schedule returns after the FIRST candidate succeeds
// (cancelling the rest), so a cancelled candidate's driver unregisters its
// own shell asynchronously and may run after this deferred unregister; the
// interleaving is safe because every unregister goes through the same
// mutex-guarded map with a pointer-identity check, making any order an
// idempotent remove. Shells that never reached a schedule (an attempt
// refused before it was built: permit, share, roster, binding) would
// otherwise leak one inbox with its identity snapshot per candidate slot.
func (n *Node) tdilithium3ProposalTriggerRun(ctx context.Context, session *tdilithium3ProposalTriggerSession, activationEpoch, epoch, slot uint64, bound [32]byte, ordinal uint64, shells []*tdilithium3SigningInbox) {
	defer func() {
		n.unregisterTDilithium3ProposalShells(shells)
		n.tdilithium3ProposalTriggerForget(slot, session)
	}()
	if !n.acquireTDilithium3ProposalSigning(ctx) {
		tdilithium3ProposalTrace("slot %d attempt %d: proposal permit unavailable", slot, ordinal)
		return
	}
	defer n.releaseTDilithium3ProposalSigning()
	if ctx.Err() != nil {
		return
	}
	if _, err := n.tdilithium3ProposalAttemptRun(ctx, activationEpoch, epoch, slot, bound, ordinal); err != nil {
		tdilithium3ProposalTrace("slot %d attempt %d: triggered attempt failed: %v", slot, ordinal, err)
		return
	}
	tdilithium3ProposalTrace("slot %d attempt %d: trigger session converged", slot, ordinal)
}

// tdilithium3ProposalTriggerForget drops this run's session entry, never a
// newer one that replaced it.
func (n *Node) tdilithium3ProposalTriggerForget(slot uint64, session *tdilithium3ProposalTriggerSession) {
	n.tdilithium3ProposalSigningMu.Lock()
	defer n.tdilithium3ProposalSigningMu.Unlock()
	if n.tdilithium3ProposalTriggerSessions[slot] == session {
		delete(n.tdilithium3ProposalTriggerSessions, slot)
	}
}

// tdilithium3ProposalPrebuildInboxes builds and registers the candidate
// inboxes of one announced attempt WITHOUT starting any party, so a first
// round message that arrives before this node's session goroutine has built
// its party queues in the inbox instead of being dropped at routing (the
// seal executor's prebuild shape; the request schedule reuses a registered
// inbox for the same session id). Failures degrade to the old behavior:
// first messages dropped, then retransmitted by the session's own cadence.
func (n *Node) tdilithium3ProposalPrebuildInboxes(epoch, slot uint64, bound [32]byte, ordinal uint64) []*tdilithium3SigningInbox {
	var inboxes []*tdilithium3SigningInbox
	defer func() {
		if r := recover(); r != nil {
			tdilithium3ProposalTrace("slot %d attempt %d: inbox prebuild failed: %v", slot, ordinal, r)
		}
	}()
	if !tdilithium3ProposalSigningEnabled(n, epoch) {
		return nil
	}
	activationEpoch, _, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		return nil
	}
	signers, localSigner, err := n.tdilithium3SealSigningSigners(activationEpoch, slot, ordinal)
	if err != nil || !localSigner {
		return nil
	}
	binding, err := n.newTDilithium3SigningBinding(activationEpoch, signers, rand.Reader)
	if err != nil {
		return nil
	}
	defer binding.close()
	request, err := binding.request(epoch, slot, protocol.SigningDomainBlock, bound[:], ordinal)
	if err != nil {
		return nil
	}
	params, err := dilithium3v1.SigningParametersForShares([]*dilithium3v1.LocalShare{binding.Share})
	if err != nil {
		return nil
	}
	for candidate := uint16(1); candidate <= uint16(params.ParallelSlots); candidate++ {
		slotRequest := dilithium3v1.SigningExecutorSlotRequestFor(request, candidate)
		sessionID, err := dilithium3v1.Dilithium3SigningSessionForShare(slotRequest, binding.Share, signers)
		if err != nil {
			return inboxes
		}
		slotContext := tdilithium3SigningContext{
			SessionID:        sessionID,
			KeyGeneration:    request.Key.Generation,
			CommitteeVersion: request.Committee.Version,
			Signers:          signers,
		}
		inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(slotContext, binding.Identities)
		if err != nil {
			return inboxes
		}
		inboxes = append(inboxes, inbox)
	}
	for _, inbox := range inboxes {
		n.registerTDilithium3SigningInbox(inbox)
	}
	return inboxes
}

// unregisterTDilithium3ProposalShells drops pre-registered candidate inboxes
// whose session never started (the start refused after the prebuild).
func (n *Node) unregisterTDilithium3ProposalShells(inboxes []*tdilithium3SigningInbox) {
	for _, inbox := range inboxes {
		n.unregisterTDilithium3SigningInbox(inbox)
	}
}

// tdilithium3ProposalTriggerSenderAuthed is the trigger's B-5 decision: only
// the slot's proposer may announce proposal attempts -- all of them,
// including retries (the proposal's retry is proposer-driven; there is no
// delegate announcer, unlike the seal's retry delegation). An unresolvable
// sender, an unresolvable slot proposer, or a missing consensus engine all
// refuse.
func (n *Node) tdilithium3ProposalTriggerSenderAuthed(slot uint64, sender p2p.PeerID) bool {
	if n == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	proposer, err := n.blockProducer.QPOS().GetProposerForSlot(slot)
	if err != nil || proposer == nil {
		return false
	}
	addr, found := n.resolveSenderAddress(sender)
	return found && bytes.Equal(addr[:], proposer.Address[:])
}

// handleTDilithium3ProposalTrigger consumes one proposal signing trigger.
// Refusal ordering, cheapest and purest first: parse, gate (zero side
// effects and zero logs when closed -- the default posture), zero-binding
// check, per-peer rate limit, B-5 authentication, duplicate suppression,
// inbox prebuild, start. Every refusal drops the message; none starts a
// goroutine or leaves an inbox behind.
func (n *Node) handleTDilithium3ProposalTrigger(msg p2p.PeerMessage) {
	epoch, slot, bound, ordinal, ok := tdilithium3ProposalTriggerParse(msg.Payload)
	if !ok {
		return
	}
	// Gate first (a pure config read): with either gate layer closed the
	// trigger is a zero-side-effect, zero-log drop.
	if !tdilithium3ProposalSigningEnabled(n, epoch) {
		return
	}
	var zeroBound [32]byte
	if bound == zeroBound {
		tdilithium3ProposalTrace("slot %d: trigger with a zero binding dropped", slot)
		return
	}
	// Per-peer rate limit before any expensive work (the proposer resolution
	// and the roster read), the NODE-R12-H01 posture.
	if !n.allowTDilithium3ProposalTriggerFromPeer(msg.From) {
		tdilithium3ProposalTrace("trigger from peer %s rate-limited", msg.From)
		return
	}
	// B-5: only the slot's proposer may announce proposal attempts -- all of
	// them, including retries: the proposal's retry is proposer-driven and
	// has no delegate announcer. An unresolvable sender is refused too.
	if !n.tdilithium3ProposalTriggerSenderAuthed(slot, msg.From) {
		tdilithium3ProposalTrace("slot %d: trigger sender is not the proposer (B-5)", slot)
		return
	}
	// Duplicate suppression before the prebuild: an attempt that is not
	// newer than the running one is an idempotent no-op, and prebuilding
	// shells for it would replace a live session's inbox registration.
	n.tdilithium3ProposalSigningMu.Lock()
	if existing := n.tdilithium3ProposalTriggerSessions[slot]; existing != nil && existing.attempt >= ordinal {
		n.tdilithium3ProposalSigningMu.Unlock()
		return
	}
	n.tdilithium3ProposalSigningMu.Unlock()
	// Pre-register the attempt's candidate inboxes BEFORE starting: the
	// proposer begins its own attempt's round messages as soon as its local
	// run starts, and a first message that outruns this node's session
	// goroutine would otherwise be dropped at routing. The start's schedule
	// factory reuses a registered inbox for the same session id. The shells
	// travel with the start: a refusal drops them immediately, an accepted
	// start releases them when the attempt's run ends (see
	// tdilithium3ProposalTriggerRun for the ownership hand-off).
	n.tdilithium3ProposalSigningStart(epoch, slot, bound, ordinal, n.tdilithium3ProposalPrebuildInboxes(epoch, slot, bound, ordinal))
}

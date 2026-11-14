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
// KNOWN SCOPE NOTE (P1): the four signers of an attempt converge only when
// each signer's node runs the same attempt. The seal path reaches its signers
// through the per-slot seal-request broadcast; the proposal path has no
// per-slot announcement channel of its own yet (a new p2p message kind is a
// cross-layer change deliberately out of this phase's scope), so until that
// trigger lands, a multi-node deployment converges only where the peers
// independently start the same attempt. This does not weaken the default
// posture: the gate is closed everywhere unless explicitly opened, and a
// session that cannot converge times out inside the bounded budget and the
// legacy individual signature is produced as before.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/wallet/tss/protocol"
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
	activationEpoch, groupKey, _, err := n.tdilithium3ActiveShareIdentityCached()
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
		signature, err := n.tdilithium3ProposalSigningAttempt(ctx, activationEpoch, epoch, slot, bound[:], attempt)
		if err == nil {
			// Self-check 1 (cryptographic): the produced signature must
			// verify under the CEREMONY group public key over the bound. A
			// header that no validator would accept must not leave the
			// producer.
			if !tdilithium3ProposalGroupVerify(groupKey, bound[:], signature) {
				tdilithium3ProposalTrace("epoch %d slot %d: group self-check failed; falling back", epoch, slot)
				return nil
			}
			// Self-check 2 (anchor agreement, audit R3-B-1 follow-up): the
			// validators' v1 branch verifies against the QTD anchor custody's
			// key for THIS epoch, so the ceremony key must be exactly what
			// that custody serves. A disagreement (experimental DKG rotation
			// ahead of this node) or an empty custody would produce a header
			// the network rejects as a whole; fall back to the individual
			// signature instead.
			if !n.tdilithium3ProposalAnchorAgrees(epoch, groupKey) {
				tdilithium3ProposalTrace("epoch %d slot %d: anchor custody does not vouch for the ceremony key; falling back", epoch, slot)
				return nil
			}
			tdilithium3ProposalTrace("epoch %d slot %d: signed by attempt %d", epoch, slot, attempt)
			return signature
		}
		if errors.Is(err, errTDilithium3ProposalSigningNotASigner) {
			// This attempt's subset excludes the proposer; rotate on.
			tdilithium3ProposalTrace("slot %d attempt %d: local validator not in the subset", slot, attempt)
			continue
		}
		tdilithium3ProposalTrace("slot %d attempt %d failed: %v", slot, attempt, err)
		if !tdilithium3ProposalAttemptRetryable(err) {
			return nil
		}
	}
	tdilithium3ProposalTrace("slot %d: attempts exhausted; falling back", slot)
	return nil
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

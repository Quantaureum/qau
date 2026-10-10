// Quantaureum Node source, version 1.0.0.
package node

// Node-side seal executor wiring (design note, Slice 4, decision C). The seal
// flow knows the slot, the block hash, and -- through its pending seal -- the
// epoch and the chain the finality message binds, so this node seals by running
// one interactive four-round session of the four fixed signers (the first four
// committee positions) in place of the legacy per-node aggregation. The
// submission goes through qfs.SubmitCompletedSeal, which verifies the produced
// signature against the epoch's group public key, so the executor never has to
// be trusted by the finality layer.
//
// Two properties shape the code. First, the request nonce is derived from the
// seal tuple and the attempt ordinal, never drawn locally, because the four
// signers must derive one session from public inputs alone; a retry announces a
// higher ordinal, and the ordinal authority is the slot's proposer — or, when
// the proposer is not one of the four signers (it then never joins the session
// and could never retry it), the lowest signer as an authenticated delegate
// (tdilithium3SealRetryDelegateAuthed). The session binding commits the
// request, so an ordinal authority can equivocate only on the ordinal.
// Second, sessions of different slots run concurrently up to a bounded fan-out:
// the authenticated inbox is keyed by session id, so a node can drive several
// slots' sessions at once without their messages crossing. This is what keeps a
// node that is still finishing slot N from having to abandon it the instant
// slot N+1's block arrives -- the earlier serialization on a single inbox field
// forced exactly that abandonment and made peers drift onto different slots. A
// higher announced ordinal of the *same* slot still cancels that slot's running
// attempt (a retry), because only one attempt of one slot may be live at once.
//
// Nothing here is enabled by construction: the gate is the existing
// experimental switch plus the mainnet exclusion, the signer set is the fixed
// first four, and every missing input fails closed. While the gate is closed
// the legacy sealing path stays byte-for-byte unchanged.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const (
	// tdilithium3SealSigningMaxAttempts bounds the attempts one slot runs when
	// this node drives its ordinals. Every attempt is its own session run by
	// all four signers over fresh one-time material, so the bound is the
	// liveness/cost knob: at the pinned fresh row's per-attempt success rate
	// three attempts leave ~10% of slots to Casper — and that is the stop the
	// concurrency budget tolerates: a full silence run costs ~15s per attempt,
	// so a deeper bound lets failing slots outlive the parallel-session cap and
	// starve the slots behind them (measured on the 10-09 devnet: attempt
	// depth 5 saturated the 8-session cap and cascaded into follower misses).
	tdilithium3SealSigningMaxAttempts = 3

	// tdilithium3SealSigningRetryBackoff is the pause before a retry attempt
	// starts locally. The retry announcement already told the other three
	// signers to switch, so the pause only mirrors the legacy retry cadence.
	tdilithium3SealSigningRetryBackoff = time.Second

	// tdilithium3SealSigningMaxConcurrentSlots bounds how many slots' seal
	// sessions run at once on this node. Since the inbox is keyed by session id,
	// distinct slots seal concurrently; the bound only caps goroutine fan-out.
	// With a 12s slot and a session that lives at most a few attempts, at most a
	// couple of slots overlap in practice, so this is generous headroom that the
	// acquire path never blocks on under normal cadence.
	tdilithium3SealSigningMaxConcurrentSlots = 8

	// tdilithium3SealSigningRequestBaseLen is the legacy seal request payload
	// (slot + block hash); a retry appends the attempt ordinal, so a short
	// payload is attempt zero.
	tdilithium3SealSigningRequestBaseLen = 40
)

// errTDilithium3SealSigningNotASigner reports that this node's validator is not
// one of the four fixed signers of the epoch, which is a quiet outcome: the
// node announced the seal request but does not join the session.
var errTDilithium3SealSigningNotASigner = errors.New("local validator is not one of the Dilithium3 v1 seal signers")

// tdilithium3SealSigningSession is the running executor attempt of one slot.
// The attempt is the highest announced ordinal, and cancel stops the slot when
// a higher ordinal arrives.
type tdilithium3SealSigningSession struct {
	attempt uint64
	cancel  context.CancelFunc
}

// tdilithium3SealExecutorEnabled reports whether this node may replace its
// legacy sealing with executor sessions. Two independent gates open it:
//
//   - the experimental network gate (devnet/testing; mainnet additionally
//     requires the explicit QAU_ENABLE_TDILITHIUM3_V1_MAINNET env opt-in), or
//   - the offline-ceremony production path: tssV1SealingActivationEpoch is
//     configured and the chain has reached it (the active share itself is
//     still required by every downstream check, so this gate alone never
//     signs anything).
func tdilithium3SealExecutorEnabled(n *Node) bool {
	if n == nil || n.config == nil {
		return false
	}
	if experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID) {
		return true
	}
	if !n.offlineTDilithium3SealingConfigured() {
		return false
	}
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	return n.offlineTDilithium3SealingArmed(n.blockProducer.QPOS().GetCurrentEpoch())
}

// tdilithium3SealExecutorTrace reports whether the seal executor's decision
// log is enabled. Every gate of this path fails closed, so on a node running
// at info level a refusal is indistinguishable from a path that was never
// entered: the legacy branch logs its own refusal, and the executor's does not.
// This switch promotes only those decisions, so a devnet run can attribute a
// missing signature to a specific precondition without changing any default
// log level and without touching a behavior.
func tdilithium3SealExecutorTrace() bool {
	return os.Getenv("QAU_TRACE_TDILITHIUM3_V1_SEAL") == "1"
}

// tdilithium3SealSigningOrdinal reads the attempt ordinal of one seal request
// payload. A payload without the trailing ordinal is the first attempt, which
// is what the legacy 40-byte broadcast carries.
func tdilithium3SealSigningOrdinal(payload []byte) uint64 {
	if len(payload) < tdilithium3SealSigningRequestBaseLen+8 {
		return 0
	}
	return binary.BigEndian.Uint64(payload[tdilithium3SealSigningRequestBaseLen : tdilithium3SealSigningRequestBaseLen+8])
}

// tdilithium3SealSigningSignersForRoster returns the fixed signers of one
// epoch: the first t committee participants in canonical order, which are the
// first t roster positions, where t comes from the committee itself (t = 4 at
// C = 6, t = 5 at C = 7 per the pinned family). The boolean reports whether
// local is one of them. Fixing the set keeps the selection deterministic on
// every node with no extra round; a later revision may rotate the subset
// without touching the session binding.
func tdilithium3SealSigningSignersForRoster(
	roster *tdilithium3DKGEpochRoster,
	committee protocol.CommitteeID,
	local types.Address,
) ([]uint32, bool, error) {
	threshold := int(committee.Threshold)
	if roster == nil || len(committee.Participants) != len(roster.Entries) ||
		len(committee.Participants) < threshold || threshold == 0 {
		return nil, false, fmt.Errorf("Dilithium3 v1 seal signers require a roster and its committee")
	}
	selected := append([]uint32(nil), committee.Participants[:threshold]...)
	for index, signer := range selected {
		if signer == 0 || (index > 0 && selected[index-1] >= signer) {
			return nil, false, fmt.Errorf("Dilithium3 v1 seal signer set is not canonically ordered")
		}
	}
	for position, entry := range roster.Entries {
		if entry.Address != local {
			continue
		}
		return selected, position < len(selected), nil
	}
	return nil, false, fmt.Errorf("local validator is not in the epoch roster")
}

// tdilithium3SealSigningSigners resolves the fixed signer set of the epoch a
// local share activated at, and whether this node is one of the four. The
// roster is read at the activation epoch's anchor, the same roster the signing
// binding and the DKG ceremony derive from.
func (n *Node) tdilithium3SealSigningSigners(activationEpoch uint64) ([]uint32, bool, error) {
	signers, _, isSigner, err := n.tdilithium3SealSigningSignersDetailed(activationEpoch)
	return signers, isSigner, err
}

// tdilithium3SealSigningSignersDetailed additionally reports this node's
// participant id (0 when not in the roster) so the retry-authority rule can
// name the lowest signer.
func (n *Node) tdilithium3SealSigningSignersDetailed(activationEpoch uint64) ([]uint32, uint32, bool, error) {
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return nil, 0, false, err
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return nil, 0, false, err
	}
	committee, position, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil {
		return nil, 0, false, err
	}
	signers, isSigner, err := tdilithium3SealSigningSignersForRoster(roster, committee, n.blockProducer.ValidatorAddr())
	if err != nil {
		return nil, 0, false, err
	}
	return signers, uint32(position) + 1, isSigner, nil
}

// tdilithium3SealSigningStart makes this node run the announced attempt of one
// sealed slot, replacing a lower attempt that is still running. It returns
// false, without any state change, when the gate is closed, the seal is not
// pending on this node, it is already finalized, or the announced ordinal is
// not newer than the running one.
func (n *Node) tdilithium3SealSigningStart(slot uint64, blockHash types.Hash, ordinal uint64) bool {
	if n == nil {
		return false
	}
	if !tdilithium3SealExecutorEnabled(n) {
		tdilithium3SealTrace("slot %d: gate closed (experimental=%t mainnet=%t)",
			slot, experimentalTDilithium3V1Enabled(), n.config != nil && n.config.NetworkID == MainnetNetworkID)
		return false
	}
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		tdilithium3SealTrace("slot %d: no block producer", slot)
		return false
	}
	qfs := n.blockProducer.QPOS().GetQTDFinality()
	if qfs == nil {
		tdilithium3SealTrace("slot %d: no QTD finality engine", slot)
		return false
	}
	if qfs.GetFinalityRecord(slot) != nil {
		tdilithium3SealTrace("slot %d: already finalized", slot)
		return false
	}
	pending := qfs.GetPendingSeal(slot)
	if pending == nil {
		// A proposer's attempt announcement regularly outruns the local
		// approval that creates the pending seal — the two travel different
		// paths. Refusing here strands the slot's whole four-signer session
		// (the round then dies on "silence: missing commit"), so latch the
		// start and let the waiter fire it when the pending seal appears.
		tdilithium3SealTrace("slot %d: no pending seal yet (block %s) — deferring start", slot, blockHash.String())
		n.deferTDilithium3SealStart(slot, blockHash, ordinal)
		return false
	}
	if pending.BlockHash != blockHash {
		tdilithium3SealTrace("slot %d: pending seal is for block %s, not %s",
			slot, pending.BlockHash.String(), blockHash.String())
		return false
	}
	if pending.Epoch == 0 {
		tdilithium3SealTrace("slot %d: pending seal has no epoch", slot)
		return false
	}
	if pending.ChainID == 0 {
		// A legacy or decoupled pending seal (chain ID zero) has no canonical
		// message to sign, so the executor refuses it instead of guessing.
		tdilithium3SealTrace("slot %d: pending seal has no chain id", slot)
		return false
	}
	n.tdilithium3SealSigningMu.Lock()
	if n.tdilithium3SealSigningSessions == nil {
		n.tdilithium3SealSigningSessions = make(map[uint64]*tdilithium3SealSigningSession)
	}
	if existing := n.tdilithium3SealSigningSessions[slot]; existing != nil {
		if existing.attempt >= ordinal {
			n.tdilithium3SealSigningMu.Unlock()
			tdilithium3SealTrace("slot %d: attempt %d is not newer than the running %d",
				slot, ordinal, existing.attempt)
			return false
		}
		existing.cancel()
	}
	base := n.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	session := &tdilithium3SealSigningSession{attempt: ordinal, cancel: cancel}
	n.tdilithium3SealSigningSessions[slot] = session
	n.tdilithium3SealSigningMu.Unlock()
	tdilithium3SealTrace("slot %d: starting attempt %d for epoch %d chain %d",
		slot, ordinal, pending.Epoch, pending.ChainID)
	go n.tdilithium3SealSigningRun(ctx, session, slot, pending.Epoch, pending.ChainID, blockHash, ordinal)
	return true
}

// tdilithium3SealDeferredStart is one latched seal start request: the
// attempt announcement's block hash and ordinal, plus the wall-clock deadline
// after which the latch self-destructs (bounded waiter lifetime — liveness
// stays with the ordinary per-slot flow, never with a stale latch), and the
// pre-registered candidate inboxes that queue the early starters' round
// messages until the pending seal lands.
type tdilithium3SealDeferredStart struct {
	blockHash types.Hash
	ordinal   uint64
	deadline  time.Time
	inboxes   []*tdilithium3SigningInbox
}

// deferTDilithium3SealStart latches one announced attempt for a slot whose
// pending seal does not exist yet. A newer ordinal supersedes the old latch
// (same ordering rule the runner itself uses); each latch owns exactly one
// waiter goroutine.
func (n *Node) deferTDilithium3SealStart(slot uint64, blockHash types.Hash, ordinal uint64) {
	n.tdilithium3SealDeferredMu.Lock()
	if n.tdilithium3SealDeferred == nil {
		n.tdilithium3SealDeferred = make(map[uint64]tdilithium3SealDeferredStart)
	}
	if existing, found := n.tdilithium3SealDeferred[slot]; found && existing.ordinal >= ordinal {
		n.tdilithium3SealDeferredMu.Unlock()
		return
	}
	if existing, found := n.tdilithium3SealDeferred[slot]; found {
		// Superseded: drop the older ordinal's shells so their session ids
		// cannot queue messages into a dead latch.
		n.unregisterTDilithium3SealShells(existing.inboxes)
	}
	n.tdilithium3SealDeferred[slot] = tdilithium3SealDeferredStart{blockHash: blockHash, ordinal: ordinal, deadline: time.Now().Add(30 * time.Second)}
	n.tdilithium3SealDeferredMu.Unlock()
	// Pre-register the attempt's candidate inboxes so commits of peers that
	// started earlier (the proposer's pending seal always lands first locally)
	// queue instead of being dropped at routing; without the shells every
	// round only converges through the 1s retransmission cadence.
	n.tdilithium3SealPrebuildInboxes(slot, blockHash, ordinal)
	go n.runDeferredTDilithium3SealStart(slot, ordinal)
}

// tdilithium3SealPrebuildInboxes builds and registers the inboxes of one
// attempt's candidate sessions without starting any party. Everything needed
// is derivable from the public seal tuple plus the local share: the request,
// the per-candidate session ids, and the identity snapshot. When the latch
// fires, the request schedule reuses these inboxes, so nothing the peers sent
// in between is lost. Failures are logged and degrade to the old behavior
// (first messages dropped, then retransmitted).
func (n *Node) tdilithium3SealPrebuildInboxes(slot uint64, blockHash types.Hash, ordinal uint64) {
	defer func() {
		if r := recover(); r != nil {
			tdilithium3SealTrace("slot %d attempt %d: inbox prebuild failed: %v", slot, ordinal, r)
		}
	}()
	activationEpoch, _, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		return
	}
	signers, _, localSigner, err := n.tdilithium3SealSigningSignersDetailed(activationEpoch)
	if err != nil || !localSigner {
		return
	}
	binding, err := n.newTDilithium3SigningBinding(activationEpoch, signers, rand.Reader)
	if err != nil {
		return
	}
	epoch := consensus.SlotToEpoch(slot)
	message := consensus.QTDSignedMessage(n.config.NetworkID, epoch, slot, blockHash)
	request, err := binding.request(epoch, slot, protocol.SigningDomainFinality, message, ordinal)
	if err != nil {
		return
	}
	params, err := dilithium3v1.SigningParametersForShares([]*dilithium3v1.LocalShare{binding.Share})
	if err != nil {
		return
	}
	inboxes := make([]*tdilithium3SigningInbox, 0, params.ParallelSlots)
	for candidate := uint16(1); candidate <= uint16(params.ParallelSlots); candidate++ {
		slotRequest := dilithium3v1.SigningExecutorSlotRequestFor(request, candidate)
		sessionID, err := dilithium3v1.Dilithium3SigningSessionForShare(slotRequest, binding.Share, signers)
		if err != nil {
			return
		}
		slotContext := tdilithium3SigningContext{
			SessionID:        sessionID,
			KeyGeneration:    request.Key.Generation,
			CommitteeVersion: request.Committee.Version,
			Signers:          signers,
		}
		inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(slotContext, binding.Identities)
		if err != nil {
			return
		}
		inboxes = append(inboxes, inbox)
	}
	n.tdilithium3SealDeferredMu.Lock()
	entry, found := n.tdilithium3SealDeferred[slot]
	if !found || entry.ordinal != ordinal {
		n.tdilithium3SealDeferredMu.Unlock()
		return
	}
	entry.inboxes = inboxes
	n.tdilithium3SealDeferred[slot] = entry
	n.tdilithium3SealDeferredMu.Unlock()
	for _, inbox := range inboxes {
		n.registerTDilithium3SigningInbox(inbox)
	}
}

// unregisterTDilithium3SealShells drops pre-registered candidate inboxes.
func (n *Node) unregisterTDilithium3SealShells(inboxes []*tdilithium3SigningInbox) {
	for _, inbox := range inboxes {
		n.unregisterTDilithium3SigningInbox(inbox)
	}
}

// runDeferredTDilithium3SealStart is the deferred latch's waiter: poll for
// the slot's pending seal, fire the (supersede-checked) start once it exists
// with the announced block hash, and die on expiry or supersession.
func (n *Node) runDeferredTDilithium3SealStart(slot uint64, ordinal uint64) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		<-ticker.C
		n.tdilithium3SealDeferredMu.Lock()
		entry, found := n.tdilithium3SealDeferred[slot]
		if !found || entry.ordinal != ordinal {
			// Gone (fired or finalized) or superseded by a newer ordinal.
			n.tdilithium3SealDeferredMu.Unlock()
			return
		}
		expired := time.Now().After(entry.deadline)
		n.tdilithium3SealDeferredMu.Unlock()
		if expired {
			n.tdilithium3SealDeferredMu.Lock()
			if cur, ok := n.tdilithium3SealDeferred[slot]; ok && cur.ordinal == ordinal {
				delete(n.tdilithium3SealDeferred, slot)
			}
			n.tdilithium3SealDeferredMu.Unlock()
			tdilithium3SealTrace("slot %d: deferred seal start expired", slot)
			return
		}
		if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
			continue
		}
		qfs := n.blockProducer.QPOS().GetQTDFinality()
		if qfs == nil {
			continue
		}
		pending := qfs.GetPendingSeal(slot)
		if pending == nil || pending.BlockHash != entry.blockHash {
			continue
		}
		n.tdilithium3SealDeferredMu.Lock()
		delete(n.tdilithium3SealDeferred, slot)
		n.tdilithium3SealDeferredMu.Unlock()
		if !n.tdilithium3SealSigningStart(slot, entry.blockHash, ordinal) {
			tdilithium3SealTrace("slot %d: deferred seal start refused", slot)
		}
		return
	}
}

// tdilithium3ActiveShareIdentityCached is the identity-only variant of the
// share cache (activation epoch/key/threshold), same 1s TTL, same
// invalidation discipline.
func (n *Node) tdilithium3ActiveShareIdentityCached() (uint64, []byte, uint32, error) {
	n.tdilithium3ShareCacheMu.Lock()
	cached := n.tdilithium3ShareCache
	fresh := cached != nil && time.Since(n.tdilithium3ShareCacheAt) < time.Second
	if fresh {
		out := cached.Clone()
		epoch, key, threshold := n.tdilithium3ShareCacheEpoch, append([]byte(nil), out.Key.PublicKey...), out.Committee.Threshold
		n.tdilithium3ShareCacheMu.Unlock()
		out.Zeroize()
		return epoch, key, threshold, nil
	}
	n.tdilithium3ShareCacheMu.Unlock()
	return newThresholdShareStore(n.config.DataDir).ActiveSharePublicIdentity([]byte(n.config.ValidatorKeyPassword))
}

// tdilithium3SealTrace logs one seal executor decision when the trace switch is
// open, and does nothing otherwise.
func tdilithium3SealTrace(format string, args ...any) {
	if !tdilithium3SealExecutorTrace() {
		return
	}
	nodeLog.Info("Dilithium3 v1 seal executor: "+format, args...)
}

// tdilithium3SealOutcomeSummary compresses a failed attempt's candidate
// outcomes for the trace: a count per (reason, silent participant), so the
// per-slot cause reads off one log line instead of eleven.
func tdilithium3SealOutcomeSummary(outcomes []tdilithium3SigningRequestOutcome) string {
	if len(outcomes) == 0 {
		return "outcomes=0"
	}
	type key struct {
		reason      dilithium3v1.SigningExecutorReason
		participant uint32
	}
	counts := make(map[key]int, len(outcomes))
	order := make([]key, 0, len(outcomes))
	for _, outcome := range outcomes {
		k := key{reason: outcome.Reason, participant: outcome.Evidence.ParticipantID}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "outcomes=%d", len(outcomes))
	for _, k := range order {
		fmt.Fprintf(&sb, " %s", k.reason)
		if k.participant != 0 {
			fmt.Fprintf(&sb, "(signer %d)", k.participant)
		}
		fmt.Fprintf(&sb, "x%d", counts[k])
	}
	return sb.String()
}

// tdilithium3SealSigningRun drives the announced attempt and, when this node is
// the slot's ordinal authority, the announced retries after it. Only the
// authority advances the ordinal — the proposer, or the lowest signer when the
// proposer is outside the signer set (see tdilithium3SealSigningDrivesRetries);
// the remaining signers follow announcements, so the four cannot drift into
// different attempt numbers.
func (n *Node) tdilithium3SealSigningRun(
	ctx context.Context,
	session *tdilithium3SealSigningSession,
	slot, epoch, chainID uint64,
	blockHash types.Hash,
	ordinal uint64,
) {
	defer n.tdilithium3SealSigningForget(slot, session)
	if !n.acquireTDilithium3SealSigning(ctx, slot) {
		tdilithium3SealTrace("slot %d attempt %d: executor slot unavailable", slot, ordinal)
		return
	}
	defer n.releaseTDilithium3SealSigning()
	authority := n.tdilithium3SealSigningDrivesRetries(slot)
	for attempt := ordinal; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		attemptStart := time.Now()
		signature, signers, outcomes, err := n.tdilithium3SealSigningAttempt(ctx, slot, epoch, chainID, blockHash, attempt)
		if err == nil {
			n.submitTDilithium3SealSignature(slot, signers, signature)
			return
		}
		if errors.Is(err, errTDilithium3SealSigningNotASigner) {
			tdilithium3SealTrace("slot %d attempt %d skipped: local validator is not one of the four signers", slot, attempt)
			return
		}
		tdilithium3SealTrace("slot %d attempt %d failed (%s) after %s: %v",
			slot, attempt, tdilithium3SealOutcomeSummary(outcomes), time.Since(attemptStart).Round(time.Millisecond), err)
		if !errors.Is(err, errTDilithium3SigningRequestExhausted) || !authority ||
			attempt+1 >= tdilithium3SealSigningMaxAttempts {
			return
		}
		next := attempt + 1
		// Announce the fresh attempt before running it: the other signers
		// switch to the new ordinal, so they cannot wait in the exhausted one.
		n.broadcastTDilithium3SealSigningRetry(slot, blockHash, next)
		if !n.tdilithium3SealSigningAdvance(slot, session, next) {
			return
		}
		if !n.tdilithium3SealSigningSleep(ctx, tdilithium3SealSigningRetryBackoff) {
			return
		}
	}
}

// tdilithium3SealSigningAttempt runs one attempt: it resolves the local share's
// activation epoch, refuses the slot unless this node is one of the four fixed
// signers, assembles the binding, and signs the canonical seal message. The
// active share is read twice by design -- once as an epoch hint, once through
// the roster verifier in the binding -- because the roster can only be chosen
// after the epoch is known; both reads are the share store's own encrypted
// persistence path.
func (n *Node) tdilithium3SealSigningAttempt(
	ctx context.Context,
	slot, epoch, chainID uint64,
	blockHash types.Hash,
	attempt uint64,
) ([]byte, []uint32, []tdilithium3SigningRequestOutcome, error) {
	if n == nil || n.config == nil || n.config.DataDir == "" || n.config.ValidatorKeyPassword == "" {
		return nil, nil, nil, fmt.Errorf("Dilithium3 v1 seal executor requires a configured node")
	}
	activationEpoch, _, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		tdilithium3SealTrace("slot %d attempt %d: active share: %v", slot, attempt, err)
		return nil, nil, nil, fmt.Errorf("Dilithium3 v1 seal executor active share: %w", err)
	}
	signers, localSigner, err := n.tdilithium3SealSigningSigners(activationEpoch)
	if err != nil {
		tdilithium3SealTrace("slot %d attempt %d: signers at activation epoch %d: %v",
			slot, attempt, activationEpoch, err)
		return nil, nil, nil, err
	}
	if !localSigner {
		return nil, nil, nil, errTDilithium3SealSigningNotASigner
	}
	if epoch < activationEpoch {
		return nil, nil, nil, fmt.Errorf(
			"Dilithium3 v1 seal executor slot %d epoch %d precedes the activation epoch %d",
			slot, epoch, activationEpoch,
		)
	}
	binding, err := n.newTDilithium3SigningBinding(activationEpoch, signers, rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Dilithium3 v1 seal executor binding: %w", err)
	}
	defer binding.close()
	message := consensus.QTDSignedMessage(chainID, epoch, slot, blockHash)
	signature, outcomes, err := n.signWithTDilithium3Signing(
		ctx, binding, epoch, slot, protocol.SigningDomainFinality, message, attempt,
	)
	if err != nil {
		return nil, signers, outcomes, err
	}
	return signature, signers, outcomes, nil
}

// submitTDilithium3SealSignature hands the produced signature to the finality
// engine, which verifies it against the epoch's group public key before the
// slot is finalized. A slot another signer finalized first is a success: the
// finality record exists, so this node's submission has nothing left to do.
func (n *Node) submitTDilithium3SealSignature(slot uint64, signers []uint32, signature []byte) {
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return
	}
	qfs := n.blockProducer.QPOS().GetQTDFinality()
	if qfs == nil || len(signature) == 0 {
		return
	}
	sealers := make([]int, 0, len(signers))
	for _, signer := range signers {
		if signer == 0 {
			return
		}
		sealers = append(sealers, int(signer)-1)
	}
	if err := qfs.SubmitCompletedSeal(slot, signature, sealers); err != nil {
		if qfs.GetFinalityRecord(slot) != nil {
			nodeLog.Info("Dilithium3 v1 seal executor: slot %d was finalized by another signer", slot)
			return
		}
		nodeLog.Error("Dilithium3 v1 seal executor: slot %d submission failed: %v", slot, err)
		return
	}
	nodeLog.Info("Dilithium3 v1 seal executor: slot %d sealed by the four-signer session", slot)
}

// broadcastTDilithium3SealSigningRetry announces a retry attempt of one slot.
// The ordinal is appended to the legacy request payload, so a receiver that
// does not know the extension still reads the slot and the block hash. Only the
// slot's proposer announces, and the receiver's proposer check authenticates
// the announcement, so the ordinal has one authority per slot.
func (n *Node) broadcastTDilithium3SealSigningRetry(slot uint64, blockHash types.Hash, ordinal uint64) {
	if n.p2pHost == nil {
		return
	}
	msg := make([]byte, tdilithium3SealSigningRequestBaseLen+8)
	binary.BigEndian.PutUint64(msg[0:8], slot)
	copy(msg[8:tdilithium3SealSigningRequestBaseLen], blockHash[:])
	binary.BigEndian.PutUint64(msg[tdilithium3SealSigningRequestBaseLen:], ordinal)
	if err := n.p2pHost.BroadcastQTDSealRequest(msg); err != nil {
		nodeLog.Warn("Dilithium3 v1 seal executor: retry announcement for slot %d failed: %v", slot, err)
	}
}

// tdilithium3SealSigningIsProposer reports whether this node proposes the slot,
// which is the same authority the seal request receivers check.
func (n *Node) tdilithium3SealSigningIsProposer(slot uint64) bool {
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	proposer, err := n.blockProducer.QPOS().GetProposerForSlot(slot)
	if err != nil || proposer == nil {
		return false
	}
	return proposer.Address == n.blockProducer.ValidatorAddr()
}

// tdilithium3SealSigningDrivesRetries reports whether this node may advance the
// attempt ordinals of one slot. The slot's proposer is the ordinal authority;
// when the proposer is not one of the four signers it never joins the session
// and could never time an announcement to the attempt's end, so the lowest
// signer of the session drives retries instead — a delegate the receivers
// authenticate the same way (roster position), and which cannot equivocate on
// anything but the ordinal because the session binding commits the request.
func (n *Node) tdilithium3SealSigningDrivesRetries(slot uint64) bool {
	if n == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	if n.tdilithium3SealSigningIsProposer(slot) {
		return true
	}
	activationEpoch, _, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		return false
	}
	signers, local, isSigner, err := n.tdilithium3SealSigningSignersDetailed(activationEpoch)
	if err != nil || !isSigner || len(signers) == 0 {
		return false
	}
	proposer, err := n.blockProducer.QPOS().GetProposerForSlot(slot)
	if err != nil || proposer == nil {
		return false
	}
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return false
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return false
	}
	for position, entry := range roster.Entries {
		if entry.Address == proposer.Address {
			// A proposer inside the signer set drives its own retries; the
			// delegate rule never runs alongside it.
			if uint32(position) < uint32(len(signers)) { // #nosec G115 -- roster positions are small
				return false
			}
		}
	}
	return local == signers[0]
}

// tdilithium3SealRetryDelegateAuthed reports whether the sender of a seal
// request that failed the proposer check may still carry it: only a retry
// announcement (ordinal ≥ 1) and only when the slot's proposer is outside the
// four signers, in which case the lowest signer drives the ordinals
// (tdilithium3SealSigningDrivesRetries). Everything else stays rejected. With
// the executor gate closed there is no ordinal at all, so the legacy path is
// untouched.
func (n *Node) tdilithium3SealRetryDelegateAuthed(
	slot, ordinal uint64,
	proposer, sender types.Address,
) bool {
	if ordinal == 0 || !tdilithium3SealExecutorEnabled(n) ||
		n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	activationEpoch, _, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		return false
	}
	signers, _, _, err := n.tdilithium3SealSigningSignersDetailed(activationEpoch)
	if err != nil || len(signers) == 0 {
		return false
	}
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return false
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return false
	}
	threshold := len(signers)
	proposerIsSigner := false
	senderIsLowest := false
	for position, entry := range roster.Entries {
		if entry.Address == proposer && position < threshold {
			proposerIsSigner = true
		}
		if entry.Address == sender && position == 0 {
			senderIsLowest = true
		}
	}
	return !proposerIsSigner && senderIsLowest
}

// tdilithium3SealSigningAdvance moves the session entry to the retry's ordinal
// so an echoed announcement of the same ordinal cannot cancel this run.
func (n *Node) tdilithium3SealSigningAdvance(slot uint64, session *tdilithium3SealSigningSession, ordinal uint64) bool {
	n.tdilithium3SealSigningMu.Lock()
	defer n.tdilithium3SealSigningMu.Unlock()
	if n.tdilithium3SealSigningSessions[slot] != session {
		return false
	}
	session.attempt = ordinal
	return true
}

// tdilithium3SealSigningForget drops this run's session entry, never a newer
// one that replaced it.
func (n *Node) tdilithium3SealSigningForget(slot uint64, session *tdilithium3SealSigningSession) {
	n.tdilithium3SealSigningMu.Lock()
	defer n.tdilithium3SealSigningMu.Unlock()
	if n.tdilithium3SealSigningSessions[slot] == session {
		delete(n.tdilithium3SealSigningSessions, slot)
	}
}

// acquireTDilithium3SealSigning takes one of the node's bounded seal-signing
// permits. Distinct slots seal concurrently (the inbox is keyed by session id),
// so this no longer cancels other slots' sessions -- doing so was what forced a
// node to abandon slot N the instant slot N+1 arrived, drifting it away from
// peers still on N. The permit only bounds goroutine fan-out; the same-slot
// retry (a higher ordinal) is canceled where the session is created, not here.
func (n *Node) acquireTDilithium3SealSigning(ctx context.Context, slot uint64) bool {
	n.tdilithium3SealSigningMu.Lock()
	if n.tdilithium3SealSigningRunning == nil {
		n.tdilithium3SealSigningRunning = make(chan struct{}, tdilithium3SealSigningMaxConcurrentSlots)
	}
	running := n.tdilithium3SealSigningRunning
	n.tdilithium3SealSigningMu.Unlock()
	select {
	case running <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// releaseTDilithium3SealSigning frees the node's executor slot; every acquire
// pairs with exactly one release, deferred by the run.
func (n *Node) releaseTDilithium3SealSigning() {
	n.tdilithium3SealSigningMu.Lock()
	running := n.tdilithium3SealSigningRunning
	n.tdilithium3SealSigningMu.Unlock()
	if running == nil {
		return
	}
	select {
	case <-running:
	default:
		nodeLog.Warn("Dilithium3 v1 seal executor: release without a matching acquire")
	}
}

// tdilithium3SealSigningSleep pauses before a retry, and reports whether the
// pause completed rather than being canceled.
func (n *Node) tdilithium3SealSigningSleep(ctx context.Context, pause time.Duration) bool {
	timer := time.NewTimer(pause)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

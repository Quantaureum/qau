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
// higher ordinal, and the slot's proposer is the only ordinal authority (the
// existing proposer check on the seal request already authenticates it).
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
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const (
	// tdilithium3SealSigningMaxAttempts bounds the attempts one slot runs when
	// this node proposes it. Every attempt is its own session, so the bound is
	// what keeps an exhausted slot from spinning forever.
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
// legacy sealing with executor sessions: the experimental gate is open for
// this network (mainnet additionally requires the explicit
// QAU_ENABLE_TDILITHIUM3_V1_MAINNET acknowledgement).
func tdilithium3SealExecutorEnabled(n *Node) bool {
	if n == nil || n.config == nil {
		return false
	}
	return experimentalTDilithium3V1EnabledForNetwork(n.config.NetworkID)
}

// tdilithium3SealExecutorTrace reports whether the seal executor's decision
// log is enabled. Every gate of this path fails closed, so on a node running
// at info level a refusal is indistinguishable from a path that was never
// entered: the legacy branch logs its own refusal, and the executor's does not.
// This switch promotes only those decisions, so a devnet run can attribute a
// missing signature to a specific precondition without changing any default
// log level and without touching a behaviour.
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
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return nil, false, err
	}
	roster, err := n.capturedEpochValidatorRoster(rosterEpoch)
	if err != nil {
		return nil, false, err
	}
	committee, _, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil {
		return nil, false, err
	}
	return tdilithium3SealSigningSignersForRoster(roster, committee, n.blockProducer.ValidatorAddr())
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
		tdilithium3SealTrace("slot %d: no pending seal for block %s", slot, blockHash.String())
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

// tdilithium3SealTrace logs one seal executor decision when the trace switch is
// open, and does nothing otherwise.
func tdilithium3SealTrace(format string, args ...any) {
	if !tdilithium3SealExecutorTrace() {
		return
	}
	nodeLog.Info("Dilithium3 v1 seal executor: "+format, args...)
}

// tdilithium3SealSigningRun drives the announced attempt and, on a slot this
// node proposes, the announced retries after it. Only the proposer advances the
// ordinal: the other three signers follow announcements, so the four cannot
// drift into different attempt numbers.
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
	proposer := n.tdilithium3SealSigningIsProposer(slot)
	for attempt := ordinal; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		signature, signers, outcomes, err := n.tdilithium3SealSigningAttempt(ctx, slot, epoch, chainID, blockHash, attempt)
		if err == nil {
			n.submitTDilithium3SealSignature(slot, signers, signature)
			return
		}
		if errors.Is(err, errTDilithium3SealSigningNotASigner) {
			tdilithium3SealTrace("slot %d attempt %d skipped: local validator is not one of the four signers", slot, attempt)
			return
		}
		tdilithium3SealTrace("slot %d attempt %d failed (outcomes=%d): %v", slot, attempt, len(outcomes), err)
		if !errors.Is(err, errTDilithium3SigningRequestExhausted) || !proposer ||
			attempt+1 >= tdilithium3SealSigningMaxAttempts {
			return
		}
		next := attempt + 1
		// Announce the fresh attempt before running it: the other three signers
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
	store := newThresholdShareStore(n.config.DataDir)
	activationEpoch, _, _, err := store.ActiveSharePublicIdentity([]byte(n.config.ValidatorKeyPassword))
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
// retry (a higher ordinal) is cancelled where the session is created, not here.
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
// pause completed rather than being cancelled.
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

// Quantaureum Node source, version 1.0.0.
package node

// Node-side seal executor wiring (design note, Slice 4, decision C). The seal
// flow knows the slot, the block hash, and -- through its pending seal -- the
// epoch and the chain the finality message binds, so this node seals by running
// one interactive four-round session of a threshold subset of the committee in
// place of the legacy per-node aggregation. The subset rotates with the slot
// and the attempt (tdilithium3SealSigningSubset), so one offline member never
// stops sealing. The
// submission goes through qfs.SubmitCompletedSeal, which verifies the produced
// signature against the epoch's group public key, so the executor never has to
// be trusted by the finality layer.
//
// Two properties shape the code. First, the request nonce is derived from the
// seal tuple and the attempt ordinal, never drawn locally, because the four
// signers must derive one session from public inputs alone; a retry announces a
// higher ordinal. The slot's proposer may announce any attempt, and every
// signer of a failed attempt may announce the next one
// (tdilithium3SealRetryAnnouncerAllowed), so a retry never depends on one
// node. The session binding commits the request, so an announcer can
// equivocate only on the ordinal, which is bounded.
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
// experimental switch plus the mainnet exclusion, the signer subset is a pure
// function of public inputs, and every missing input fails closed. While the
// gate is closed the legacy sealing path stays byte-for-byte unchanged.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const (
	// tdilithium3SealSigningMaxAttempts bounds the attempts of one slot. Every
	// attempt is its own session over fresh one-time material, run by that
	// attempt's signer subset (tdilithium3SealSigningSubset). Six attempts walk
	// a round's three excluded pairs twice. At C = 6 every member sits out two
	// of the six attempts, so a slot with one member offline still gets two
	// attempts without it (each succeeds about half the time at the pinned
	// fresh row); at C = 7 the round's bye member sits out none, so a slot
	// whose bye is the offline member cannot seal (one slot in seven). An
	// attempt with an unreachable signer fails within milliseconds and a
	// filtered one within a few seconds; tdilithium3SealSigningRetryWindow
	// bounds the slow case where attempts time out on silence.
	tdilithium3SealSigningMaxAttempts = 6

	// tdilithium3SealSigningRetryWindow bounds, from the sealed slot's own
	// start, when any node may still start one of the slot's retry attempts.
	// The bound is anchored to the slot, not to a node's run, so it holds for
	// the whole committee: a member that joins late (it sat out the earlier
	// attempts) inherits the slot's remaining window instead of a fresh one.
	// The first attempt starts about one slot in, so retries get about three
	// slots; a run of silent attempts (15 s each) then ends after the window
	// plus one attempt, well inside the concurrent-session cap.
	tdilithium3SealSigningRetryWindow = 4 * consensus.SlotDuration

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
// in the signer subset of the attempt, which is a quiet outcome: the node does
// not join that attempt's session.
var errTDilithium3SealSigningNotASigner = errors.New("local validator is not one of the Dilithium3 v1 seal signers")

// tdilithium3SealSigningSession is the running executor attempt of one slot.
// The attempt is the highest admitted ordinal, and cancel stops the slot when
// the next ordinal is admitted (tdilithium3SealOrdinalAdmissible).
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

// tdilithium3SealSigningWeights is the stake view a seal's signers must meet:
// the stake of every committee position and the weight the finality engine
// requires of a completed seal (SubmitCompletedSeal checks the signers' stake
// against it). The zero value carries no constraint.
type tdilithium3SealSigningWeights struct {
	stakes   []*big.Int
	required *big.Int
}

// admits reports whether leaving the pair of positions out keeps the rest of
// a committee of the given size at the required weight.
func (weights tdilithium3SealSigningWeights) admits(size int, pair [2]int) bool {
	if weights.required == nil || len(weights.stakes) != size {
		return true
	}
	remaining := new(big.Int)
	for position, stake := range weights.stakes {
		if position == pair[0] || position == pair[1] || stake == nil {
			continue
		}
		remaining.Add(remaining, stake)
	}
	return remaining.Cmp(weights.required) >= 0
}

// tdilithium3SealSigningSubset returns the signer subset of one attempt of one
// slot: the committee minus one excluded pair (tdilithium3SealAttemptPairs).
// With equal stakes the pairs are the slot's round-robin round (the circle
// method; an odd committee adds a bye), so:
//
//   - the attempts of a slot walk the round's disjoint pairs, so every member
//     but the bye sits out an attempt of the slot: a single offline member is
//     skipped within one slot (unless it is the bye);
//   - over one full round every pair sits out exactly once, so any two
//     offline members still leave some slots sealable.
//
// A pair whose exclusion would leave the signers below the required stake is
// never used: the finality engine would reject the finished signature.
//
// The subset is a pure function of the committee, the threshold, the slot,
// the attempt, and the stake view, so every node derives the same one with no
// extra round. Committees whose threshold does not leave exactly two members
// out, and stake views no pair satisfies, keep the first t participants.
func tdilithium3SealSigningSubset(
	participants []uint32,
	threshold int,
	slot, attempt uint64,
	weights tdilithium3SealSigningWeights,
) ([]uint32, error) {
	size := len(participants)
	if size == 0 || threshold <= 0 || threshold > size {
		return nil, fmt.Errorf("Dilithium3 v1 seal signers require a committee and a threshold within it")
	}
	for index, participant := range participants {
		if participant == 0 || (index > 0 && participants[index-1] >= participant) {
			return nil, fmt.Errorf("Dilithium3 v1 seal signer set is not canonically ordered")
		}
	}
	if size-threshold != 2 {
		return append([]uint32(nil), participants[:threshold]...), nil
	}
	pairs := tdilithium3SealAttemptPairs(size, slot, weights)
	if len(pairs) == 0 {
		return append([]uint32(nil), participants[:threshold]...), nil
	}
	pair := pairs[attempt%uint64(len(pairs))]
	selected := make([]uint32, 0, threshold)
	for position, participant := range participants {
		if position == pair[0] || position == pair[1] {
			continue
		}
		selected = append(selected, participant)
	}
	return selected, nil
}

// tdilithium3SealAttemptPairs returns the excluded pairs a slot's attempts
// walk: the admissible pairs of the slot's round, topped up to the round's
// length with admissible pairs of the following rounds, in round order, when
// the stake view rules some out. With equal stakes this is exactly the slot's
// round. Empty when no pair at all is admissible.
func tdilithium3SealAttemptPairs(size int, slot uint64, weights tdilithium3SealSigningWeights) [][2]int {
	players := size + size%2
	rounds := uint64(players - 1)
	perRound := size / 2
	pairs := make([][2]int, 0, perRound)
	for offset := uint64(0); offset < rounds && len(pairs) < perRound; offset++ {
		for _, pair := range tdilithium3SealRoundPairs(size, slot+offset) {
			if len(pairs) == perRound {
				break
			}
			if weights.admits(size, pair) && !slices.Contains(pairs, pair) {
				pairs = append(pairs, pair)
			}
		}
	}
	return pairs
}

// tdilithium3SealRoundPairs returns the disjoint position pairs of the
// round-robin round the slot falls in, each pair ordered and the list sorted.
// For an even size the circle method fixes the last position and rotates the
// rest; an odd size plays with a bye, and the pair holding the bye leaves
// nobody out, so it is omitted.
func tdilithium3SealRoundPairs(size int, slot uint64) [][2]int {
	players := size + size%2
	rounds := players - 1
	round := int(slot % uint64(rounds))
	pairs := make([][2]int, 0, players/2)
	add := func(a, b int) {
		if a >= size || b >= size {
			return
		}
		if a > b {
			a, b = b, a
		}
		pairs = append(pairs, [2]int{a, b})
	}
	add(round, players-1)
	for offset := 1; offset < players/2; offset++ {
		add((round+offset)%rounds, (round-offset+rounds)%rounds)
	}
	slices.SortFunc(pairs, func(left, right [2]int) int {
		if left[0] != right[0] {
			return left[0] - right[0]
		}
		return left[1] - right[1]
	})
	return pairs
}

// tdilithium3SealSigningSignersForRoster returns the signer subset of one
// attempt of one slot over the epoch's committee (t = 4 at C = 6, t = 5 at
// C = 7 per the pinned family), and whether local is in it.
func tdilithium3SealSigningSignersForRoster(
	roster *tdilithium3DKGEpochRoster,
	committee protocol.CommitteeID,
	local types.Address,
	slot, attempt uint64,
	weights tdilithium3SealSigningWeights,
) ([]uint32, bool, error) {
	threshold := int(committee.Threshold)
	if roster == nil || len(committee.Participants) != len(roster.Entries) ||
		len(committee.Participants) < threshold || threshold == 0 {
		return nil, false, fmt.Errorf("Dilithium3 v1 seal signers require a roster and its committee")
	}
	selected, err := tdilithium3SealSigningSubset(committee.Participants, threshold, slot, attempt, weights)
	if err != nil {
		return nil, false, err
	}
	for position, entry := range roster.Entries {
		if entry.Address != local {
			continue
		}
		return selected, slices.Contains(selected, committee.Participants[position]), nil
	}
	return nil, false, fmt.Errorf("local validator is not in the epoch roster")
}

// tdilithium3SealSigningSigners resolves the signer subset of one attempt of
// one slot, and whether this node is in it. The roster is read at the
// activation epoch's anchor, the same roster the signing binding and the DKG
// ceremony derive from.
func (n *Node) tdilithium3SealSigningSigners(activationEpoch, slot, attempt uint64) ([]uint32, bool, error) {
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return nil, false, err
	}
	roster, err := n.capturedEpochValidatorRosterAtOrAfter(rosterEpoch)
	if err != nil {
		return nil, false, err
	}
	committee, _, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil {
		return nil, false, err
	}
	return tdilithium3SealSigningSignersForRoster(
		roster, committee, n.blockProducer.ValidatorAddr(), slot, attempt,
		n.tdilithium3SealSigningWeightsFor(slot, committee.Participants),
	)
}

// tdilithium3SealSigningWeightsFor reads the stake view a slot's seal is
// checked against: the pending seal's own snapshot when the slot has one (the
// exact values SubmitCompletedSeal compares with), otherwise the finality
// engine's current snapshot. Participant p is validator index p-1, the mapping
// submitTDilithium3SealSignature reports sealers under. An unavailable view is
// the zero value, which constrains nothing.
func (n *Node) tdilithium3SealSigningWeightsFor(slot uint64, participants []uint32) tdilithium3SealSigningWeights {
	if n == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return tdilithium3SealSigningWeights{}
	}
	qfs := n.blockProducer.QPOS().GetQTDFinality()
	if qfs == nil {
		return tdilithium3SealSigningWeights{}
	}
	var stakes map[int]*big.Int
	var required *big.Int
	if pending := qfs.GetPendingSeal(slot); pending != nil && pending.RequiredWeight != nil {
		stakes, required = pending.MemberStakes, pending.RequiredWeight
	} else {
		stakes, required = qfs.SealerStakeSnapshot()
	}
	if required == nil || stakes == nil {
		return tdilithium3SealSigningWeights{}
	}
	weights := tdilithium3SealSigningWeights{stakes: make([]*big.Int, len(participants)), required: required}
	for position, participant := range participants {
		if participant == 0 {
			return tdilithium3SealSigningWeights{}
		}
		weights.stakes[position] = stakes[int(participant)-1]
	}
	return weights
}

// tdilithium3SealRetryAnnouncerAllowed reports whether a participant may
// announce the given attempt: only a retry (ordinal >= 1) within the attempt
// bound, and only from a signer of the attempt that just failed, which is
// exactly the set of nodes that observed it fail. The rule binds the slot's
// proposer too: its authority ends at the first attempt.
func tdilithium3SealRetryAnnouncerAllowed(
	participants []uint32,
	threshold int,
	slot, ordinal uint64,
	sender uint32,
	weights tdilithium3SealSigningWeights,
) (bool, error) {
	if ordinal == 0 || ordinal >= tdilithium3SealSigningMaxAttempts {
		return false, nil
	}
	previous, err := tdilithium3SealSigningSubset(participants, threshold, slot, ordinal-1, weights)
	if err != nil {
		return false, err
	}
	return slices.Contains(previous, sender), nil
}

// tdilithium3SealSigningStart makes this node run the announced attempt of one
// sealed slot, replacing the lower attempt that is still running. It returns
// false, without any state change, when the gate is closed, the ordinal is
// out of bounds or out of sequence (tdilithium3SealOrdinalAdmissible), the
// slot's retry window has passed, the seal is not pending on this node, it is
// already finalized, or the announced ordinal is not newer than the running
// one.
func (n *Node) tdilithium3SealSigningStart(slot uint64, blockHash types.Hash, ordinal uint64) bool {
	if n == nil {
		return false
	}
	if ordinal >= tdilithium3SealSigningMaxAttempts {
		tdilithium3SealTrace("slot %d: attempt %d is beyond the attempt bound", slot, ordinal)
		return false
	}
	if ordinal > 0 && !tdilithium3SealWithinRetryWindow(slot, time.Now()) {
		tdilithium3SealTrace("slot %d: attempt %d arrived after the slot's retry window", slot, ordinal)
		return false
	}
	if !n.tdilithium3SealOrdinalAdmissible(slot, ordinal) {
		tdilithium3SealTrace("slot %d: attempt %d skips ahead of the attempts seen so far", slot, ordinal)
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
	// R24 (2026-10-29): a retained agreement over a NON-canonical block must
	// not wedge the canonical seal of that slot. Skip the session only when
	// the slot already carries an agreement that covers this block, or a
	// provably canonical one (auditor finding X03).
	if qfs.SealAlreadyCovers(slot, blockHash) {
		tdilithium3SealTrace("slot %d: already sealed for this slot", slot)
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
		n.tdilithium3SealOrdinalRecord(slot, ordinal)
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
	n.tdilithium3SealOrdinalRecordLocked(slot, ordinal)
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
	signers, localSigner, err := n.tdilithium3SealSigningSigners(activationEpoch, slot, ordinal)
	if err != nil || !localSigner {
		return
	}
	binding, err := n.newTDilithium3SigningBinding(activationEpoch, signers, rand.Reader)
	if err != nil {
		return
	}
	defer binding.close()
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
// invalidation discipline. On the offline path an active share of an earlier
// ceremony than the armed one is refused (errTDilithium3ActiveShareSuperseded),
// so nothing signs, anchors, or registers with a key being replaced.
func (n *Node) tdilithium3ActiveShareIdentityCached() (uint64, []byte, uint32, error) {
	n.tdilithium3ShareCacheMu.Lock()
	cached := n.tdilithium3ShareCache
	fresh := cached != nil && time.Since(n.tdilithium3ShareCacheAt) < time.Second
	if fresh {
		out := cached.Clone()
		epoch, key, threshold := n.tdilithium3ShareCacheEpoch, append([]byte(nil), out.Key.PublicKey...), out.Committee.Threshold
		n.tdilithium3ShareCacheMu.Unlock()
		out.Zeroize()
		if n.offlineTDilithium3ShareSuperseded(epoch) {
			return 0, nil, 0, fmt.Errorf("%w: share activates at epoch %d", errTDilithium3ActiveShareSuperseded, epoch)
		}
		return epoch, key, threshold, nil
	}
	n.tdilithium3ShareCacheMu.Unlock()
	epoch, key, threshold, err := newThresholdShareStore(n.config.DataDir).ActiveSharePublicIdentity([]byte(n.config.ValidatorKeyPassword))
	if err != nil {
		return 0, nil, 0, err
	}
	if n.offlineTDilithium3ShareSuperseded(epoch) {
		return 0, nil, 0, fmt.Errorf("%w: share activates at epoch %d", errTDilithium3ActiveShareSuperseded, epoch)
	}
	return epoch, key, threshold, nil
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

// tdilithium3SealSigningRun drives the announced attempt and the retries after
// it. A signer whose attempt was exhausted announces the next ordinal, which
// every node orders by the same rule (a higher ordinal replaces a running
// lower one), and keeps running only if it is in the next attempt's subset;
// the other signers of the next attempt start on the announcement.
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
			tdilithium3SealTrace("slot %d attempt %d skipped: local validator is not in this attempt's signers", slot, attempt)
			return
		}
		tdilithium3SealTrace("slot %d attempt %d failed (%s) after %s: %v",
			slot, attempt, tdilithium3SealOutcomeSummary(outcomes), time.Since(attemptStart).Round(time.Millisecond), err)
		if !tdilithium3SealSigningRetryAllowed(err, attempt, tdilithium3SealWithinRetryWindow(slot, time.Now())) {
			return
		}
		next := attempt + 1
		// Announce the fresh attempt before running it: the next attempt's
		// signers switch to the new ordinal, so they cannot wait in the
		// exhausted one, and the members who sat out the failed attempt start.
		n.broadcastTDilithium3SealSigningRetry(slot, blockHash, next)
		if !n.tdilithium3SealSigningAdvance(slot, session, next) {
			return
		}
		if !n.tdilithium3SealSigningSleep(ctx, tdilithium3SealSigningRetryBackoff) {
			return
		}
	}
}

// tdilithium3SealSigningRetryAllowed reports whether a slot whose attempt
// failed with err starts its next attempt: the failure must be retryable,
// another ordinal must remain, and the slot must still be inside its retry
// window.
func tdilithium3SealSigningRetryAllowed(err error, attempt uint64, withinWindow bool) bool {
	return tdilithium3SealAttemptRetryable(err) &&
		attempt+1 < tdilithium3SealSigningMaxAttempts &&
		withinWindow
}

// tdilithium3SealWithinRetryWindow reports whether now is still inside the
// slot's retry window (tdilithium3SealSigningRetryWindow), measured from the
// slot's start on the chain clock. Without a configured genesis time there is
// no chain clock, and the window does not bound anything.
func tdilithium3SealWithinRetryWindow(slot uint64, now time.Time) bool {
	if !consensus.IsGenesisTimeConfigured() {
		return true
	}
	return now.Sub(consensus.GetSlotStartTime(slot)) <= tdilithium3SealSigningRetryWindow
}

// tdilithium3SealOrdinalHistorySlots is how many slots of admitted-ordinal
// history a node keeps; a slot's attempts end within its retry window.
const tdilithium3SealOrdinalHistorySlots = 256

// tdilithium3SealOrdinalAdmissible reports whether an announced attempt may
// start here: attempts advance one ordinal at a time, so an ordinal is
// admitted only up to one past the highest this node has admitted for the
// slot (the first attempt, or the retry after it, when none was seen). A
// member that may announce the next attempt (a signer of the current one)
// therefore cannot skip the attempts that exclude it; it can only cut short
// an attempt it belongs to, which it could stall by going silent anyway.
func (n *Node) tdilithium3SealOrdinalAdmissible(slot, ordinal uint64) bool {
	n.tdilithium3SealSigningMu.Lock()
	defer n.tdilithium3SealSigningMu.Unlock()
	highest, seen := n.tdilithium3SealSigningOrdinals[slot]
	if !seen {
		return ordinal <= 1
	}
	return ordinal <= highest+1
}

// tdilithium3SealOrdinalRecord notes an admitted ordinal for the slot.
func (n *Node) tdilithium3SealOrdinalRecord(slot, ordinal uint64) {
	n.tdilithium3SealSigningMu.Lock()
	defer n.tdilithium3SealSigningMu.Unlock()
	n.tdilithium3SealOrdinalRecordLocked(slot, ordinal)
}

// tdilithium3SealOrdinalRecordLocked is tdilithium3SealOrdinalRecord for a
// caller holding tdilithium3SealSigningMu; it also prunes old slots.
func (n *Node) tdilithium3SealOrdinalRecordLocked(slot, ordinal uint64) {
	if n.tdilithium3SealSigningOrdinals == nil {
		n.tdilithium3SealSigningOrdinals = make(map[uint64]uint64)
	}
	if highest, seen := n.tdilithium3SealSigningOrdinals[slot]; !seen || ordinal > highest {
		n.tdilithium3SealSigningOrdinals[slot] = ordinal
	}
	if len(n.tdilithium3SealSigningOrdinals) > 2*tdilithium3SealOrdinalHistorySlots {
		for old := range n.tdilithium3SealSigningOrdinals {
			if old+tdilithium3SealOrdinalHistorySlots < slot {
				delete(n.tdilithium3SealSigningOrdinals, old)
			}
		}
	}
}

// tdilithium3SealAttemptRetryable reports whether a failed attempt moves the
// slot on to the next ordinal: its candidate slots were all filtered (a
// statistical outcome), or one of its signers is unreachable from this node, in
// which case a later attempt's subset may exclude that signer. Any other
// failure is structural and stops the slot.
func tdilithium3SealAttemptRetryable(err error) bool {
	return errors.Is(err, errTDilithium3SigningRequestExhausted) ||
		errors.Is(err, errTDilithium3SigningSignerUnreachable)
}

// tdilithium3SealSigningAttempt runs one attempt: it resolves the local share's
// activation epoch, refuses the attempt unless this node is in its signer
// subset, assembles the binding, and signs the canonical seal message. The
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
	signers, localSigner, err := n.tdilithium3SealSigningSigners(activationEpoch, slot, attempt)
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
// does not know the extension still reads the slot and the block hash. The
// receiver authenticates the sender as a signer of the attempt that just
// failed (tdilithium3SealRetryDelegateAuthed), whoever proposed the slot.
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

// tdilithium3SealRetryDelegateAuthed reports whether the sender may announce a
// retry attempt: only within the attempt bound, and only as a signer of the
// attempt that just failed (tdilithium3SealRetryAnnouncerAllowed); the slot's
// proposer is held to the same rule. With the executor gate closed there are
// no retries at all, so the legacy path is untouched.
func (n *Node) tdilithium3SealRetryDelegateAuthed(slot, ordinal uint64, sender types.Address) bool {
	if ordinal == 0 || !tdilithium3SealExecutorEnabled(n) ||
		n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	activationEpoch, _, _, err := n.tdilithium3ActiveShareIdentityCached()
	if err != nil {
		return false
	}
	rosterEpoch, err := tdilithium3DKGSessionRosterEpoch(activationEpoch)
	if err != nil {
		return false
	}
	roster, err := n.capturedEpochValidatorRosterAtOrAfter(rosterEpoch)
	if err != nil {
		return false
	}
	committee, _, err := n.tdilithium3DKGCommitteeForRoster(roster)
	if err != nil || len(committee.Participants) != len(roster.Entries) {
		return false
	}
	for position, entry := range roster.Entries {
		if entry.Address != sender {
			continue
		}
		allowed, err := tdilithium3SealRetryAnnouncerAllowed(
			committee.Participants, int(committee.Threshold), slot, ordinal, committee.Participants[position],
			n.tdilithium3SealSigningWeightsFor(slot, committee.Participants),
		)
		return err == nil && allowed
	}
	return false
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
	n.tdilithium3SealOrdinalRecordLocked(slot, ordinal)
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

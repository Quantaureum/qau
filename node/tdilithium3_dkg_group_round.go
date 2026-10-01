// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/sha3"
	"fmt"
	"sync"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// Dilithium3 DKG group round is the networked counterpart of the in-process
// per-group loop in runTDilithium3DKGCluster. It drives one canonical RSS group
// through the private seed, component derivation, public contribution and
// acknowledgement phases for a single participant, persisting every state
// change in the same encrypted journal the in-process runner uses.
//
// The seed stays private. Only the group leader generates it and only the other
// two members receive it, so participants outside the group can never derive
// the group component. Those participants therefore cannot recompute t_U
// locally; they accept a contribution only once the three group members signed
// acknowledgements binding one seed commitment digest and one contribution
// digest. Members always recompute t_U from the seed they received and refuse to
// acknowledge anything else, so a leader that publishes a false partial public
// key never collects three acknowledgements.
//
// Leader replacement (attempt > 0) is deliberately not implemented here. The
// journal refuses to rewrite the seed, leader, or attempt of a group that
// already persisted one, and the complaint sub-protocol cannot yet justify such
// a rewrite: ApplyComplaint validates complaint structure but not complaint
// evidence, so any single group member could burn attempts without attributable
// proof and force an abort. A group whose leader stalls therefore fails closed
// with errTDilithium3DKGGroupStalled instead of silently accepting a partial
// transcript. Wiring leader replacement into this driver requires the complaint
// wire format to carry the dealer's signed envelope plus a signature check
// against the committee roster; until then unattributable complaints are refused
// by policy, so a genuinely missing seed — which has no signed envelope to
// disclose — always fails the session closed.

const (
	// tdilithium3DKGGroupBroadcast marks a public group message.
	tdilithium3DKGGroupBroadcast uint8 = 0xff

	tdilithium3DKGGroupSeedSequence            uint32 = 1
	tdilithium3DKGGroupContributionSequence    uint32 = 1
	tdilithium3DKGGroupAcknowledgementSequence uint32 = 1
)

// tdilithium3DKGGroupOutbound is one encoded group message the driver must send.
type tdilithium3DKGGroupOutbound struct {
	MessageType uint8
	Recipient   uint8 // tdilithium3DKGGroupBroadcast for public messages.
	Payload     []byte
}

type tdilithium3DKGGroupRound struct {
	mu sync.Mutex

	runner     *tdilithium3DKGRunner
	group      dilithium3v1.RSSGroupMask
	groupIndex int
	attempt    uint8
	leader     uint8

	sessionDigest   [32]byte
	committeeDigest [32]byte

	seedPersisted    bool
	componentDerived bool
	verified         bool
	locallyVerified  bool

	seed         [32]byte
	receivedSeed *[32]byte

	component          dilithium3v1.RSSComponent
	computed           *dilithium3v1.PublicContribution
	computedDigest     [32]byte
	contribution       dilithium3v1.PublicContribution
	contributionDigest [32]byte

	acks   []dilithium3v1.ContributionAcknowledgement
	ownAck *dilithium3v1.ContributionAcknowledgement
	ackSet *dilithium3v1.GroupAcknowledgementSet
}

// newTDilithium3DKGGroupRound prepares one group round from the durable journal.
func newTDilithium3DKGGroupRound(runner *tdilithium3DKGRunner, group dilithium3v1.RSSGroupMask) (*tdilithium3DKGGroupRound, error) {
	if runner == nil || runner.journal == nil || runner.participantPosition >= 6 || runner.record.ParticipantPosition != runner.participantPosition {
		return nil, errTDilithium3DKGInvalidCluster
	}
	if runner.record.Stage < tdilithium3DKGStageRandomnessComplete || runner.record.GlobalRandomness == ([64]byte{}) || runner.record.Rho == ([32]byte{}) {
		return nil, fmt.Errorf("Dilithium3 DKG group round requires completed group randomness")
	}
	if err := runner.session.Validate(); err != nil {
		return nil, err
	}
	sessionDigest, err := runner.session.Digest()
	if err != nil || sessionDigest != runner.record.SessionDigest {
		return nil, errTDilithium3DKGJournalSession
	}
	committeeDigest, err := runner.session.Committee.CanonicalDigest()
	if err != nil {
		return nil, err
	}
	groupIndex, err := tdilithium3DKGGroupIndex(group)
	if err != nil {
		return nil, err
	}
	round := &tdilithium3DKGGroupRound{
		runner: runner, group: group, groupIndex: groupIndex,
		attempt: 0, sessionDigest: sessionDigest, committeeDigest: committeeDigest,
	}
	leader, err := group.Leader(round.attempt)
	if err != nil {
		return nil, err
	}
	round.leader = leader
	if state := runner.record.Groups[groupIndex]; state.Stage >= tdilithium3DKGGroupSeedPersisted {
		if _, err := group.Leader(state.Attempt); err != nil || state.Attempt > round.attempt {
			return nil, errTDilithium3DKGJournalTransition
		}
		round.attempt = state.Attempt
		round.leader = state.LeaderPosition
		round.seed = state.Seed
		round.seedPersisted = true
	}
	if state := runner.record.Groups[groupIndex]; state.Stage >= tdilithium3DKGGroupComponentDerived {
		round.component = state.Component
		round.componentDerived = true
	}
	if state := runner.record.Groups[groupIndex]; state.Stage >= tdilithium3DKGGroupContributionVerified {
		round.contribution = state.Contribution
		round.contributionDigest = state.ContributionDigest
		round.verified = true
	}
	return round, nil
}

func (round *tdilithium3DKGGroupRound) isMember() bool {
	return round != nil && round.runner != nil && round.group.Contains(round.runner.participantPosition)
}

func (round *tdilithium3DKGGroupRound) isLeader() bool {
	return round != nil && round.runner != nil && round.runner.participantPosition == round.leader
}

func (round *tdilithium3DKGGroupRound) complete() bool {
	round.mu.Lock()
	defer round.mu.Unlock()
	return round.verified
}

// stalledError reports that the driver ran out of time while this group still
// waited for peer progress. It is the explicit, fail-closed outcome of a group
// whose leader stalled: the journal is left exactly where it was and no partial
// transcript is recorded. The context error is wrapped so callers can still
// distinguish a stall from an ordinary cancellation.
func (round *tdilithium3DKGGroupRound) stalledError(cause error) error {
	if round == nil || round.runner == nil {
		return fmt.Errorf("%w: %w", errTDilithium3DKGGroupStalled, cause)
	}
	round.mu.Lock()
	defer round.mu.Unlock()
	return fmt.Errorf("%w: group %06b leader %d attempt %d: %w", errTDilithium3DKGGroupStalled, round.group, round.leader, round.attempt, cause)
}

// observe buffers one verified inbound message owned by this group. It returns
// whether the round state changed. Messages belonging to another group are
// ignored so a driver never aborts on a slower peer's unrelated traffic.
func (round *tdilithium3DKGGroupRound) observe(message tdilithium3DKGVerifiedMessage) (bool, error) {
	if round == nil || round.runner == nil {
		return false, errTDilithium3DKGInvalidCluster
	}
	round.mu.Lock()
	defer round.mu.Unlock()
	if round.verified {
		return false, nil
	}
	switch message.Type {
	case p2p.MsgTypeTDilithium3DKGGroupSeed:
		seed, err := dilithium3v1.UnmarshalGroupSeedMessage(message.Payload)
		if err != nil {
			return false, err
		}
		if seed.GroupMask != round.group {
			return false, nil
		}
		if err := seed.ValidateFor(round.sessionDigest, round.committeeDigest, round.group, round.runner.participantPosition); err != nil {
			return false, err
		}
		if !round.isMember() {
			return false, fmt.Errorf("%w: private seed for a foreign group", dilithium3v1.ErrInvalidGroupSeedMessage)
		}
		if seed.Attempt != round.attempt || seed.LeaderPosition != round.leader {
			return false, errTDilithium3DKGJournalTransition
		}
		if round.seedPersisted {
			if round.seed != seed.Seed {
				return false, fmt.Errorf("%w: group %06b", dilithium3v1.ErrConflictingGroupSeed, round.group)
			}
			return false, nil
		}
		if round.receivedSeed != nil && *round.receivedSeed != seed.Seed {
			return false, fmt.Errorf("%w: group %06b", dilithium3v1.ErrConflictingGroupSeed, round.group)
		}
		copied := seed.Seed
		round.receivedSeed = &copied
		return true, nil
	case p2p.MsgTypeTDilithium3DKGContribution:
		contribution, err := dilithium3v1.UnmarshalPublicContribution(message.Payload)
		if err != nil {
			return false, err
		}
		if contribution.GroupMask != round.group {
			return false, nil
		}
		if contribution.SessionDigest != round.sessionDigest || contribution.DealerPosition != round.leader {
			return false, errTDilithium3DKGJournalTransition
		}
		if round.isLeader() {
			return false, nil // Our own broadcast echoed back; the leader already holds t_U.
		}
		digest, err := contribution.Digest()
		if err != nil {
			return false, err
		}
		if round.contributionDigest != ([32]byte{}) && round.contributionDigest != digest {
			return false, fmt.Errorf("%w: group %06b", dilithium3v1.ErrConflictingPublicContribution, round.group)
		}
		round.contribution = contribution
		round.contributionDigest = digest
		return true, nil
	case p2p.MsgTypeTDilithium3DKGComplaint:
		// Complaints belong to the leader-replacement sub-protocol, which this
		// round does not implement. Acting on an unverified complaint would let
		// one member burn the attempt, so complaints are ignored and a stalled
		// leader instead fails closed with errTDilithium3DKGGroupStalled.
		return false, nil
	case p2p.MsgTypeTDilithium3DKGAcknowledgement:
		acknowledgement, err := dilithium3v1.UnmarshalContributionAcknowledgement(message.Payload)
		if err != nil {
			return false, err
		}
		if acknowledgement.GroupMask != round.group {
			return false, nil
		}
		if acknowledgement.SessionDigest != round.sessionDigest || acknowledgement.CommitteeDigest != round.committeeDigest ||
			acknowledgement.LeaderPosition != round.leader || acknowledgement.Attempt != round.attempt {
			return false, errTDilithium3DKGJournalTransition
		}
		if acknowledgement.ParticipantPosition == round.runner.participantPosition {
			return false, nil // Our own broadcast echoed back; the set already holds it.
		}
		round.acks = append(round.acks, acknowledgement)
		return true, nil
	default:
		// Randomness messages (and any other phase) are replayed traffic from a
		// neighbouring phase; they belong to no group and are dropped here.
		return false, nil
	}
}

// advance persists whatever the buffered messages allow and returns the group
// messages that must be (re)sent. It is idempotent: repeated calls without new
// input only re-emit the same outbound traffic.
func (round *tdilithium3DKGGroupRound) advance(sign func([]byte) ([]byte, error)) ([]tdilithium3DKGGroupOutbound, error) {
	if round == nil || round.runner == nil || sign == nil {
		return nil, fmt.Errorf("Dilithium3 DKG group round requires a local signer")
	}
	round.mu.Lock()
	defer round.mu.Unlock()
	if err := round.persistSeedLocked(); err != nil {
		return nil, err
	}
	if err := round.deriveComponentLocked(); err != nil {
		return nil, err
	}
	if err := round.verifyContributionLocked(); err != nil {
		return nil, err
	}
	if err := round.accumulateAcknowledgementsLocked(); err != nil {
		return nil, err
	}
	return round.outboundLocked(sign)
}

// persistSeedLocked durably binds the group seed. The leader generates it; every
// other member only ever persists the seed the leader sent over the network.
func (round *tdilithium3DKGGroupRound) persistSeedLocked() error {
	if round.seedPersisted {
		return nil
	}
	runner := round.runner
	state := runner.record.Groups[round.groupIndex]
	if state.Stage >= tdilithium3DKGGroupSeedPersisted {
		if state.Attempt != round.attempt || state.LeaderPosition != round.leader {
			return errTDilithium3DKGJournalTransition
		}
		round.seed = state.Seed
		round.seedPersisted = true
		return nil
	}
	var seed [32]byte
	var digest [32]byte
	if round.isMember() {
		if round.isLeader() {
			if state.Seed != ([32]byte{}) {
				return errTDilithium3DKGJournalTransition
			}
			if err := readTDilithium3DKGRandom(runner.entropy, seed[:]); err != nil {
				return err
			}
		} else {
			if round.receivedSeed == nil {
				return nil // Wait for the private seed; never self-generate one.
			}
			seed = *round.receivedSeed
		}
		digest = tdilithium3DKGJournalSeedDigest(seed)
	} else {
		digest = tdilithium3DKGPublicSeedDigest(round.group, round.leader, round.attempt)
	}
	updated := runner.record
	if round.isMember() {
		updated.Groups[round.groupIndex].Seed = seed
	}
	if err := updated.PersistGroupSeed(round.group, round.attempt, round.leader, digest); err != nil {
		return err
	}
	if err := runner.journal.Store(updated); err != nil {
		return err
	}
	runner.record = updated
	round.seed = seed
	round.seedPersisted = true
	return nil
}

// deriveComponentLocked expands the persisted seed into this participant's
// share material and recomputes t_U. Participants outside the group derive
// nothing: they persist an opaque placeholder digest so the journal stage
// machine stays uniform, and they never read group material.
func (round *tdilithium3DKGGroupRound) deriveComponentLocked() error {
	if round.componentDerived || !round.seedPersisted {
		return nil
	}
	runner := round.runner
	state := runner.record.Groups[round.groupIndex]
	if state.Stage >= tdilithium3DKGGroupComponentDerived {
		round.component = state.Component
		round.componentDerived = true
		if !round.isMember() {
			return nil
		}
		computed, err := dilithium3v1.NewPublicContribution(round.sessionDigest, round.group, round.leader, runner.record.Rho, state.Component.S1, state.Component.S2)
		if err != nil {
			return err
		}
		digest, err := computed.Digest()
		if err != nil {
			return err
		}
		round.computed = &computed
		round.computedDigest = digest
		if round.isLeader() {
			round.contribution = computed
			round.contributionDigest = digest
		}
		return nil
	}
	updated := runner.record
	var digest [32]byte
	if round.isMember() {
		if round.seed == ([32]byte{}) {
			return errTDilithium3DKGJournalTransition
		}
		s1, s2, err := dilithium3v1.DeriveRSSComponent(round.sessionDigest, round.group, round.leader, runner.record.GlobalRandomness, round.seed)
		if err != nil {
			return err
		}
		component := dilithium3v1.RSSComponent{GroupMask: round.group, DealerPosition: round.leader, S1: s1, S2: s2}
		computed, err := dilithium3v1.NewPublicContribution(round.sessionDigest, round.group, round.leader, runner.record.Rho, s1, s2)
		if err != nil {
			return err
		}
		contributionDigest, err := computed.Digest()
		if err != nil {
			return err
		}
		component.ContributionDigest = contributionDigest
		digest = tdilithium3DKGComponentDigest(round.group, round.leader, contributionDigest, s1, s2)
		updated.Groups[round.groupIndex].Component = component
		round.component = component
		round.computed = &computed
		round.computedDigest = contributionDigest
		if round.isLeader() {
			round.contribution = computed
			round.contributionDigest = contributionDigest
		}
	} else {
		if round.contributionDigest == ([32]byte{}) {
			return nil // Wait for the published contribution to bind the placeholder.
		}
		digest = tdilithium3DKGPublicComponentDigest(round.group, round.leader, round.contributionDigest)
	}
	if err := updated.MarkComponentDerived(round.group, digest); err != nil {
		return err
	}
	if err := runner.journal.Store(updated); err != nil {
		return err
	}
	runner.record = updated
	round.componentDerived = true
	return nil
}

// verifyContributionLocked recomputes the published partial public key from the
// locally derived component. A mismatch means the leader equivocated, so the
// round fails instead of acknowledging a false t_U.
func (round *tdilithium3DKGGroupRound) verifyContributionLocked() error {
	if round.locallyVerified || !round.isMember() || round.computed == nil || round.contributionDigest == ([32]byte{}) {
		return nil
	}
	if round.contributionDigest != round.computedDigest {
		return fmt.Errorf("%w: group %06b", dilithium3v1.ErrConflictingPublicContribution, round.group)
	}
	if err := dilithium3v1.VerifyPublicContributionForComponent(round.contribution, round.sessionDigest, round.group, round.leader, round.runner.record.Rho, round.component.S1, round.component.S2); err != nil {
		return fmt.Errorf("%w: group %06b: %v", dilithium3v1.ErrConflictingPublicContribution, round.group, err)
	}
	round.locallyVerified = true
	return nil
}

// accumulateAcknowledgementsLocked collects the three member acknowledgements
// and, once complete, durably records the verified contribution.
func (round *tdilithium3DKGGroupRound) accumulateAcknowledgementsLocked() error {
	if round.verified || round.contributionDigest == ([32]byte{}) {
		return nil
	}
	if round.isMember() && !round.locallyVerified {
		return nil
	}
	if round.ackSet == nil {
		if err := round.buildAcknowledgementSetLocked(); err != nil {
			return err
		}
		if round.ackSet == nil {
			return nil
		}
	}
	for _, acknowledgement := range round.acks {
		if err := round.addAcknowledgementLocked(acknowledgement); err != nil {
			return err
		}
	}
	round.acks = nil
	if round.isMember() {
		// A member only reaches this point after recomputing t_U locally, so its
		// own acknowledgement is part of the quorum.
		if _, err := round.buildOwnAcknowledgementLocked(); err != nil {
			return err
		}
	}
	if round.ownAck != nil {
		if err := round.addAcknowledgementLocked(*round.ownAck); err != nil {
			return err
		}
	}
	if !round.ackSet.Complete() {
		return nil
	}
	updated := round.runner.record
	if updated.Groups[round.groupIndex].Stage < tdilithium3DKGGroupComponentDerived {
		return errTDilithium3DKGJournalTransition
	}
	updated.Groups[round.groupIndex].Contribution = round.contribution
	if err := updated.MarkContributionVerified(round.group, round.contributionDigest); err != nil {
		return err
	}
	if err := round.runner.journal.Store(updated); err != nil {
		return err
	}
	round.runner.record = updated
	round.verified = true
	return nil
}

func (round *tdilithium3DKGGroupRound) buildAcknowledgementSetLocked() error {
	if round.isMember() {
		message, err := round.seedMessageLocked()
		if err != nil {
			return err
		}
		set, err := dilithium3v1.NewGroupAcknowledgementSet(message, round.contributionDigest)
		if err != nil {
			return err
		}
		round.ackSet = set
		return nil
	}
	if len(round.acks) == 0 {
		return nil // The shared seed commitment digest arrives with the acknowledgements.
	}
	first := round.acks[0]
	set, err := dilithium3v1.NewGroupAcknowledgementSetFromContext(round.sessionDigest, round.committeeDigest, round.group, round.leader, round.attempt, first.SeedCommitmentDigest, round.contributionDigest)
	if err != nil {
		return err
	}
	round.ackSet = set
	return nil
}

func (round *tdilithium3DKGGroupRound) addAcknowledgementLocked(acknowledgement dilithium3v1.ContributionAcknowledgement) error {
	err := round.ackSet.Add(acknowledgement)
	if err == nil || err == dilithium3v1.ErrDuplicateGroupAcknowledgement {
		return nil
	}
	return err
}

// seedMessageLocked rebuilds the canonical recipient-specific seed message bound
// to the persisted seed. A member rebuilds the message it received; the leader
// rebuilds the message it sent to its lowest-position peer, because the protocol
// never lets a leader address itself. The shared seed commitment digest does not
// depend on the recipient, which is what ties the three acknowledgements
// together.
func (round *tdilithium3DKGGroupRound) seedMessageLocked() (dilithium3v1.GroupSeedMessage, error) {
	if !round.isMember() || round.seed == ([32]byte{}) {
		return dilithium3v1.GroupSeedMessage{}, errTDilithium3DKGJournalTransition
	}
	recipient := round.runner.participantPosition
	if recipient == round.leader {
		recipient = 0xff
		for position := uint8(0); position < 6; position++ {
			if round.group.Contains(position) && position != round.leader {
				recipient = position
				break
			}
		}
	}
	if recipient == 0xff {
		return dilithium3v1.GroupSeedMessage{}, errTDilithium3DKGJournalTransition
	}
	return dilithium3v1.GroupSeedMessage{
		SessionDigest: round.sessionDigest, CommitteeDigest: round.committeeDigest, GroupMask: round.group,
		LeaderPosition: round.leader, RecipientPosition: recipient, Attempt: round.attempt, Seed: round.seed,
	}, nil
}

func (round *tdilithium3DKGGroupRound) outboundLocked(sign func([]byte) ([]byte, error)) ([]tdilithium3DKGGroupOutbound, error) {
	if round.verified {
		return nil, nil
	}
	var outbound []tdilithium3DKGGroupOutbound
	if round.isLeader() && round.seedPersisted {
		recipients, err := round.outboundSeedLocked(sign)
		if err != nil {
			return nil, err
		}
		outbound = append(outbound, recipients...)
	}
	if round.isLeader() && round.contributionDigest != ([32]byte{}) {
		payload, err := round.contribution.MarshalBinary()
		if err != nil {
			return nil, err
		}
		encoded, err := encodeTDilithium3DKGSignedEnvelope(round.runner.session, p2p.MsgTypeTDilithium3DKGContribution, round.leader, tdilithium3DKGGroupContributionSequence, payload, sign)
		if err != nil {
			return nil, err
		}
		outbound = append(outbound, tdilithium3DKGGroupOutbound{MessageType: p2p.MsgTypeTDilithium3DKGContribution, Recipient: tdilithium3DKGGroupBroadcast, Payload: encoded})
	}
	if round.isMember() && round.locallyVerified {
		acknowledgement, err := round.ownAcknowledgementLocked()
		if err != nil {
			return nil, err
		}
		encoded, err := encodeTDilithium3DKGSignedEnvelope(round.runner.session, p2p.MsgTypeTDilithium3DKGAcknowledgement, round.runner.participantPosition, tdilithium3DKGGroupAcknowledgementSequence, acknowledgement, sign)
		if err != nil {
			return nil, err
		}
		outbound = append(outbound, tdilithium3DKGGroupOutbound{MessageType: p2p.MsgTypeTDilithium3DKGAcknowledgement, Recipient: tdilithium3DKGGroupBroadcast, Payload: encoded})
	}
	return outbound, nil
}

func (round *tdilithium3DKGGroupRound) outboundSeedLocked(sign func([]byte) ([]byte, error)) ([]tdilithium3DKGGroupOutbound, error) {
	var outbound []tdilithium3DKGGroupOutbound
	for recipient := uint8(0); recipient < 6; recipient++ {
		if !round.group.Contains(recipient) || recipient == round.leader {
			continue
		}
		message := dilithium3v1.GroupSeedMessage{
			SessionDigest: round.sessionDigest, CommitteeDigest: round.committeeDigest, GroupMask: round.group,
			LeaderPosition: round.leader, RecipientPosition: recipient, Attempt: round.attempt, Seed: round.seed,
		}
		payload, err := message.MarshalBinary()
		if err != nil {
			return nil, err
		}
		encoded, err := encodeTDilithium3DKGSignedEnvelope(round.runner.session, p2p.MsgTypeTDilithium3DKGGroupSeed, round.leader, tdilithium3DKGGroupSeedSequence, payload, sign)
		if err != nil {
			return nil, err
		}
		outbound = append(outbound, tdilithium3DKGGroupOutbound{MessageType: p2p.MsgTypeTDilithium3DKGGroupSeed, Recipient: recipient, Payload: encoded})
	}
	return outbound, nil
}

// buildOwnAcknowledgementLocked lazily builds this member's acknowledgement of
// the verified contribution. It is cached so repeated retransmissions are
// stable.
func (round *tdilithium3DKGGroupRound) buildOwnAcknowledgementLocked() (*dilithium3v1.ContributionAcknowledgement, error) {
	if round.ownAck != nil {
		return round.ownAck, nil
	}
	message, err := round.seedMessageLocked()
	if err != nil {
		return nil, err
	}
	seedCommitmentDigest, err := message.SeedCommitmentDigest()
	if err != nil {
		return nil, err
	}
	seedMessageDigest, err := message.Digest()
	if err != nil {
		return nil, err
	}
	round.ownAck = &dilithium3v1.ContributionAcknowledgement{
		SessionDigest: round.sessionDigest, CommitteeDigest: round.committeeDigest, GroupMask: round.group,
		LeaderPosition: round.leader, ParticipantPosition: round.runner.participantPosition, Attempt: round.attempt,
		SeedCommitmentDigest: seedCommitmentDigest, SeedMessageDigest: seedMessageDigest, ContributionDigest: round.contributionDigest,
	}
	return round.ownAck, nil
}

func (round *tdilithium3DKGGroupRound) ownAcknowledgementLocked() ([]byte, error) {
	acknowledgement, err := round.buildOwnAcknowledgementLocked()
	if err != nil {
		return nil, err
	}
	return acknowledgement.MarshalBinary()
}

// tdilithium3DKGJournalSeedDigest matches the seed digest the in-process runner
// writes, so a journal produced by either path stays interchangeable.
func tdilithium3DKGJournalSeedDigest(seed [32]byte) [32]byte {
	return sha3.Sum256(append([]byte("QAU-TDILITHIUM3-V1-JOURNAL-SEED"), seed[:]...))
}

// tdilithium3DKGPublicSeedDigest and tdilithium3DKGPublicComponentDigest give
// participants outside a group deterministic, non-secret journal placeholders.
// They are never read to derive key material.
func tdilithium3DKGPublicSeedDigest(group dilithium3v1.RSSGroupMask, leader, attempt uint8) [32]byte {
	hash := sha3.New256()
	_, _ = hash.Write([]byte("QAU-TDILITHIUM3-V1-GROUP-SEED-PUBLIC"))
	_, _ = hash.Write([]byte{byte(group), leader, attempt})
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func tdilithium3DKGPublicComponentDigest(group dilithium3v1.RSSGroupMask, leader uint8, contributionDigest [32]byte) [32]byte {
	hash := sha3.New256()
	_, _ = hash.Write([]byte("QAU-TDILITHIUM3-V1-GROUP-COMPONENT-PUBLIC"))
	_, _ = hash.Write([]byte{byte(group), leader})
	_, _ = hash.Write(contributionDigest[:])
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

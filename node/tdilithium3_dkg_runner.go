// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

var (
	errTDilithium3DKGInjectedCrash  = errors.New("injected Dilithium3 DKG crash")
	errTDilithium3DKGInvalidCluster = errors.New("invalid Dilithium3 DKG cluster")
	errTDilithium3DKGPacketConflict = errors.New("conflicting Dilithium3 DKG packet")
	// errTDilithium3DKGGroupStalled is the explicit fail-closed outcome of a
	// group round whose leader stopped making progress. It wraps the context
	// error so callers can tell a stalled peer from a cancelled ceremony.
	errTDilithium3DKGGroupStalled = errors.New("Dilithium3 DKG group stalled waiting for peer progress")
)

type tdilithium3DKGBoundary string

const (
	tdilithium3DKGBoundaryPrepared        tdilithium3DKGBoundary = "prepared"
	tdilithium3DKGBoundaryCommitment      tdilithium3DKGBoundary = "commitment"
	tdilithium3DKGBoundaryRandomness      tdilithium3DKGBoundary = "randomness"
	tdilithium3DKGBoundaryGroupSeed       tdilithium3DKGBoundary = "group-seed"
	tdilithium3DKGBoundaryComponent       tdilithium3DKGBoundary = "component"
	tdilithium3DKGBoundaryContribution    tdilithium3DKGBoundary = "contribution"
	tdilithium3DKGBoundaryAllGroups       tdilithium3DKGBoundary = "all-groups"
	tdilithium3DKGBoundaryShareInstalled  tdilithium3DKGBoundary = "share-installed"
	tdilithium3DKGBoundaryAcknowledgement tdilithium3DKGBoundary = "acknowledgement"
)

type tdilithium3DKGRunnerConfig struct {
	Session             dilithium3v1.DKGSession
	ParticipantPosition uint8
	BasePath            string
	Password            []byte
	Entropy             io.Reader
}

type tdilithium3DKGRunner struct {
	session             dilithium3v1.DKGSession
	participantPosition uint8
	basePath            string
	password            []byte
	entropy             io.Reader
	shareStore          *thresholdShareStore
	journal             *tdilithium3DKGJournal
	record              tdilithium3DKGJournalRecord
}

type tdilithium3DKGResult struct {
	PublicKey        [1952]byte
	TranscriptDigest [32]byte
	Share            *dilithium3v1.LocalShare
}

type tdilithium3DKGFaultPlan struct {
	FailedLeaderAttempts    map[dilithium3v1.RSSGroupMask]uint8
	MissingContribution     *dilithium3v1.RSSGroupMask
	ConflictingContribution *dilithium3v1.RSSGroupMask
	CrashPosition           uint8
	CrashBoundary           tdilithium3DKGBoundary
	DelayedPackets          bool
	ReorderedPackets        bool
	DuplicatePackets        bool
}

type tdilithium3DKGPacket struct {
	Kind              uint8
	SessionDigest     [32]byte
	CommitteeDigest   [32]byte
	GroupMask         dilithium3v1.RSSGroupMask
	Attempt           uint8
	SenderPosition    uint8
	RecipientPosition uint8
	Payload           []byte
}

type tdilithium3DKGMemoryTransport struct {
	participants int
	packets      map[string]tdilithium3DKGPacket
	pending      []tdilithium3DKGPacket
	delayed      bool
	reordered    bool
}

func newTDilithium3DKGMemoryTransport(participants int) *tdilithium3DKGMemoryTransport {
	return &tdilithium3DKGMemoryTransport{participants: participants, packets: make(map[string]tdilithium3DKGPacket)}
}

func (transport *tdilithium3DKGMemoryTransport) deliver(packet tdilithium3DKGPacket, duplicate bool) error {
	if transport == nil || packet.SessionDigest == ([32]byte{}) || packet.CommitteeDigest == ([32]byte{}) || int(packet.SenderPosition) >= transport.participants || int(packet.RecipientPosition) >= transport.participants || len(packet.Payload) == 0 {
		return errTDilithium3DKGInvalidCluster
	}
	if transport.delayed {
		packet.Payload = append([]byte(nil), packet.Payload...)
		transport.pending = append(transport.pending, packet)
		if duplicate {
			duplicatePacket := packet
			duplicatePacket.Payload = append([]byte(nil), packet.Payload...)
			transport.pending = append(transport.pending, duplicatePacket)
		}
		return nil
	}
	if err := transport.accept(packet); err != nil {
		return err
	}
	if duplicate {
		return transport.accept(packet)
	}
	return nil
}

func (transport *tdilithium3DKGMemoryTransport) accept(packet tdilithium3DKGPacket) error {
	key := fmt.Sprintf("%d:%x:%x:%d:%d:%d:%d", packet.Kind, packet.SessionDigest, packet.CommitteeDigest, packet.GroupMask, packet.Attempt, packet.SenderPosition, packet.RecipientPosition)
	if existing, ok := transport.packets[key]; ok {
		if !slices.Equal(existing.Payload, packet.Payload) {
			return errTDilithium3DKGPacketConflict
		}
		return nil
	}
	if err := validateTDilithium3DKGMemoryPacket(packet); err != nil {
		return err
	}
	packet.Payload = append([]byte(nil), packet.Payload...)
	transport.packets[key] = packet
	return nil
}

func (transport *tdilithium3DKGMemoryTransport) flush() error {
	if transport == nil || len(transport.pending) == 0 {
		return nil
	}
	if transport.reordered {
		slices.Reverse(transport.pending)
	}
	for _, packet := range transport.pending {
		if err := transport.accept(packet); err != nil {
			return err
		}
	}
	transport.pending = transport.pending[:0]
	return nil
}

func validateTDilithium3DKGMemoryPacket(packet tdilithium3DKGPacket) error {
	switch packet.Kind {
	case 1:
		message, err := dilithium3v1.UnmarshalGroupSeedMessage(packet.Payload)
		if err != nil {
			return err
		}
		if message.SessionDigest != packet.SessionDigest || message.CommitteeDigest != packet.CommitteeDigest || message.GroupMask != packet.GroupMask || message.Attempt != packet.Attempt || message.LeaderPosition != packet.SenderPosition || message.RecipientPosition != packet.RecipientPosition {
			return errTDilithium3DKGInvalidCluster
		}
	case 2:
		contribution, err := dilithium3v1.UnmarshalPublicContribution(packet.Payload)
		if err != nil {
			return err
		}
		if contribution.SessionDigest != packet.SessionDigest || contribution.GroupMask != packet.GroupMask || contribution.DealerPosition != packet.SenderPosition {
			return errTDilithium3DKGInvalidCluster
		}
	default:
		return errTDilithium3DKGInvalidCluster
	}
	return nil
}

func newTDilithium3DKGRunner(config tdilithium3DKGRunnerConfig) (*tdilithium3DKGRunner, error) {
	if err := config.Session.Validate(); err != nil {
		return nil, err
	}
	if int(config.ParticipantPosition) >= len(config.Session.Committee.Participants) || config.BasePath == "" || len(config.Password) == 0 || config.Entropy == nil {
		return nil, errTDilithium3DKGInvalidCluster
	}
	sessionDigest, err := config.Session.Digest()
	if err != nil {
		return nil, err
	}
	committeeDigest, err := config.Session.Committee.CanonicalDigest()
	if err != nil {
		return nil, err
	}
	journalPath := filepath.Join(config.BasePath+".threshold-v1", "dilithium3-v1", "dkg", fmt.Sprintf("%x", sessionDigest), "journal.enc")
	runner := &tdilithium3DKGRunner{
		session:             config.Session.Clone(),
		participantPosition: config.ParticipantPosition,
		basePath:            config.BasePath,
		password:            append([]byte(nil), config.Password...),
		entropy:             config.Entropy,
		shareStore:          newThresholdShareStore(config.BasePath),
		journal:             newTDilithium3DKGJournal(journalPath, config.Password),
	}
	record, err := runner.journal.Load(sessionDigest)
	if err == nil {
		if record.CommitteeDigest != committeeDigest || record.ParticipantPosition != config.ParticipantPosition {
			return nil, errTDilithium3DKGJournalSession
		}
		runner.record = record
		return runner, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	record = newTDilithium3DKGJournalRecord(sessionDigest, committeeDigest, config.ParticipantPosition, len(config.Session.Committee.Participants))
	if err := readTDilithium3DKGRandom(config.Entropy, record.LocalRandomness[:]); err != nil {
		return nil, err
	}
	if err := runner.journal.Store(record); err != nil {
		return nil, err
	}
	runner.record = record
	return runner, nil
}

func runTDilithium3DKGCluster(ctx context.Context, runners [6]*tdilithium3DKGRunner, transport *tdilithium3DKGMemoryTransport, faults tdilithium3DKGFaultPlan) ([6]tdilithium3DKGResult, error) {
	var results [6]tdilithium3DKGResult
	sessionDigest, committeeDigest, err := validateTDilithium3DKGCluster(runners, transport)
	if err != nil {
		return results, err
	}
	transport.delayed = faults.DelayedPackets || faults.ReorderedPackets
	transport.reordered = faults.ReorderedPackets
	if err := checkTDilithium3DKGContext(ctx); err != nil {
		return results, err
	}
	if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryPrepared) {
		return results, errTDilithium3DKGInjectedCrash
	}

	var randomnessContributions = make([][32]byte, len(runners))
	var randomnessCommitments = make([][32]byte, len(runners))
	for position, runner := range runners {
		randomnessContributions[position] = runner.record.LocalRandomness
		commitment, err := dilithium3v1.DKGRandomnessCommitment(runner.session, uint8(position), runner.record.LocalRandomness)
		if err != nil {
			return results, err
		}
		randomnessCommitments[position] = commitment
	}
	var dirty [6]bool
	for position, runner := range runners {
		if runner.record.CommitmentsPersisted {
			if !tdilithium3DKGCommitmentsEqual(runner.record.RandomnessCommitments, randomnessCommitments) {
				return results, errTDilithium3DKGJournalSession
			}
			continue
		}
		if err := runner.record.MarkRandomnessCommitments(randomnessCommitments); err != nil {
			return results, err
		}
		dirty[position] = true
	}
	if err := storeTDilithium3DKGRecords(runners, dirty); err != nil {
		return results, err
	}
	if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryCommitment) {
		return results, errTDilithium3DKGInjectedCrash
	}
	globalRandomness, rho, err := dilithium3v1.DeriveDKGRandomness(runners[0].session, randomnessContributions)
	if err != nil {
		return results, err
	}
	dirty = [6]bool{}
	for position, runner := range runners {
		if runner.record.Stage == tdilithium3DKGStagePrepared {
			if err := runner.record.MarkRandomnessComplete(globalRandomness, rho); err != nil {
				return results, err
			}
			dirty[position] = true
		} else if runner.record.GlobalRandomness != globalRandomness || runner.record.Rho != rho {
			return results, errTDilithium3DKGJournalSession
		}
	}
	if err := storeTDilithium3DKGRecords(runners, dirty); err != nil {
		return results, err
	}
	if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryRandomness) {
		return results, errTDilithium3DKGInjectedCrash
	}

	groups := dilithium3v1.CanonicalRSSGroups()
	var contributions [20]dilithium3v1.PublicContribution
	for groupIndex, group := range groups {
		if err := checkTDilithium3DKGContext(ctx); err != nil {
			return results, err
		}
		failedAttempts := faults.FailedLeaderAttempts[group]
		if failedAttempts >= 3 {
			return results, dilithium3v1.ErrDKGSessionAbort
		}
		attempt := failedAttempts
		leader, err := group.Leader(attempt)
		if err != nil {
			return results, dilithium3v1.ErrDKGSessionAbort
		}
		seed, err := recoverOrCreateTDilithium3DKGSeed(runners, groupIndex, group, attempt, leader)
		if err != nil {
			return results, err
		}
		seedDigest := sha3.Sum256(append([]byte("QAU-TDILITHIUM3-V1-JOURNAL-SEED"), seed[:]...))
		dirty = [6]bool{}
		for position, runner := range runners {
			state := &runner.record.Groups[groupIndex]
			if state.Stage >= tdilithium3DKGGroupSeedPersisted {
				if state.Attempt != attempt || state.LeaderPosition != leader || state.SeedDigest != seedDigest {
					return results, errTDilithium3DKGJournalTransition
				}
				continue
			}
			if group.Contains(uint8(position)) {
				state.Seed = seed
			}
			if err := runner.record.PersistGroupSeed(group, attempt, leader, seedDigest); err != nil {
				return results, err
			}
			dirty[position] = true
		}
		if err := storeTDilithium3DKGRecords(runners, dirty); err != nil {
			return results, err
		}
		if err := deliverTDilithium3DKGSeedPackets(transport, sessionDigest, committeeDigest, group, attempt, leader, seed, faults.DuplicatePackets); err != nil {
			return results, err
		}
		if err := transport.flush(); err != nil {
			return results, err
		}
		if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryGroupSeed) {
			return results, errTDilithium3DKGInjectedCrash
		}

		s1, s2, err := dilithium3v1.DeriveRSSComponent(sessionDigest, group, leader, globalRandomness, seed)
		if err != nil {
			return results, err
		}
		contribution, err := dilithium3v1.NewPublicContribution(sessionDigest, group, leader, rho, s1, s2)
		if err != nil {
			return results, err
		}
		contributionDigest, err := contribution.Digest()
		if err != nil {
			return results, err
		}
		componentDigest := tdilithium3DKGComponentDigest(group, leader, contributionDigest, s1, s2)
		component := dilithium3v1.RSSComponent{GroupMask: group, DealerPosition: leader, ContributionDigest: contributionDigest, Multiplicity: 1, S1: s1, S2: s2}
		dirty = [6]bool{}
		for position, runner := range runners {
			state := &runner.record.Groups[groupIndex]
			if state.Stage < tdilithium3DKGGroupComponentDerived {
				if group.Contains(uint8(position)) {
					state.Component = component
				}
				if err := runner.record.MarkComponentDerived(group, componentDigest); err != nil {
					return results, err
				}
				dirty[position] = true
			} else if state.ComponentDigest != componentDigest {
				return results, errTDilithium3DKGJournalTransition
			}
		}
		if err := storeTDilithium3DKGRecords(runners, dirty); err != nil {
			return results, err
		}
		if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryComponent) {
			return results, errTDilithium3DKGInjectedCrash
		}

		if faults.MissingContribution != nil && *faults.MissingContribution == group {
			return results, fmt.Errorf("missing Dilithium3 DKG contribution for group %06b", group)
		}
		// A conflicting fault models a malicious leader that publishes a
		// well-formed but false t_U. It must be caught by local verification
		// below rather than being injected as a pre-baked error, so the test
		// path exercises the same check the production path relies on.
		published := contribution
		if faults.ConflictingContribution != nil && *faults.ConflictingContribution == group {
			published.T[0][0] = dilithium3v1.Normalize(published.T[0][0] + 2)
		}
		encodedContribution, err := published.MarshalBinary()
		if err != nil {
			return results, err
		}
		for position := range runners {
			if err := transport.deliver(tdilithium3DKGPacket{Kind: 2, SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group, Attempt: attempt, SenderPosition: leader, RecipientPosition: uint8(position), Payload: encodedContribution}, faults.DuplicatePackets); err != nil {
				return results, err
			}
		}
		if err := transport.flush(); err != nil {
			return results, err
		}
		// Round 4: the published partial public contribution may only enter the
		// transcript when it matches the value the group members derived from
		// their own component. Every member derives the same component, so one
		// check covers the whole group in this in-process cluster.
		if err := dilithium3v1.VerifyPublicContributionForComponent(published, sessionDigest, group, leader, rho, s1, s2); err != nil {
			return results, fmt.Errorf("%w: group %06b: %v", dilithium3v1.ErrConflictingPublicContribution, group, err)
		}
		publishedDigest, err := published.Digest()
		if err != nil {
			return results, err
		}
		dirty = [6]bool{}
		for position, runner := range runners {
			state := &runner.record.Groups[groupIndex]
			if state.Stage < tdilithium3DKGGroupContributionVerified {
				state.Contribution = published
				if err := runner.record.MarkContributionVerified(group, publishedDigest); err != nil {
					return results, err
				}
				dirty[position] = true
			} else if state.ContributionDigest != publishedDigest || state.Contribution != published {
				return results, errTDilithium3DKGJournalTransition
			}
		}
		if err := storeTDilithium3DKGRecords(runners, dirty); err != nil {
			return results, err
		}
		contributions[groupIndex] = published
		if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryContribution) {
			return results, errTDilithium3DKGInjectedCrash
		}
	}

	publicKey, transcriptDigest, err := dilithium3v1.AssembleMode3PublicKey(rho, contributions[:], len(runners[0].session.Committee.Participants))
	if err != nil {
		return results, err
	}
	dirty = [6]bool{}
	for position, runner := range runners {
		if runner.record.Stage < tdilithium3DKGStageAllGroupsComplete {
			if err := runner.record.MarkAllGroupsComplete(publicKey, transcriptDigest); err != nil {
				return results, err
			}
			dirty[position] = true
		} else if runner.record.PublicKey != publicKey || runner.record.TranscriptDigest != transcriptDigest {
			return results, errTDilithium3DKGJournalTransition
		}
	}
	if err := storeTDilithium3DKGRecords(runners, dirty); err != nil {
		return results, err
	}
	if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryAllGroups) {
		return results, errTDilithium3DKGInjectedCrash
	}

	for position, runner := range runners {
		share, err := buildTDilithium3DKGShare(runner, publicKey, transcriptDigest)
		if err != nil {
			return results, err
		}
		if runner.record.Stage < tdilithium3DKGStageShareInstalled {
			if err := runner.shareStore.Store(share, runner.password); err != nil {
				share.Zeroize()
				return results, err
			}
			if err := runner.record.MarkShareInstalled(); err != nil {
				share.Zeroize()
				return results, err
			}
			if err := runner.journal.Store(runner.record); err != nil {
				share.Zeroize()
				return results, err
			}
		}
		results[position] = tdilithium3DKGResult{PublicKey: publicKey, TranscriptDigest: transcriptDigest, Share: share}
	}
	if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryShareInstalled) {
		zeroTDilithium3DKGResults(&results)
		return results, errTDilithium3DKGInjectedCrash
	}
	dirty = [6]bool{}
	for position, runner := range runners {
		if runner.record.Stage < tdilithium3DKGStageAcknowledgementPersisted {
			if err := runner.record.MarkAcknowledgementPersisted(); err != nil {
				zeroTDilithium3DKGResults(&results)
				return results, err
			}
			dirty[position] = true
		}
	}
	if err := storeTDilithium3DKGRecords(runners, dirty); err != nil {
		zeroTDilithium3DKGResults(&results)
		return results, err
	}
	if shouldCrashTDilithium3DKG(faults, tdilithium3DKGBoundaryAcknowledgement) {
		zeroTDilithium3DKGResults(&results)
		return results, errTDilithium3DKGInjectedCrash
	}
	return results, nil
}

func validateTDilithium3DKGCluster(runners [6]*tdilithium3DKGRunner, transport *tdilithium3DKGMemoryTransport) ([32]byte, [32]byte, error) {
	if transport == nil {
		return [32]byte{}, [32]byte{}, errTDilithium3DKGInvalidCluster
	}
	var sessionDigest [32]byte
	var committeeDigest [32]byte
	for position, runner := range runners {
		if runner == nil || runner.participantPosition != uint8(position) {
			return [32]byte{}, [32]byte{}, errTDilithium3DKGInvalidCluster
		}
		candidateSession, err := runner.session.Digest()
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		candidateCommittee, err := runner.session.Committee.CanonicalDigest()
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		if position == 0 {
			sessionDigest = candidateSession
			committeeDigest = candidateCommittee
		} else if candidateSession != sessionDigest || candidateCommittee != committeeDigest {
			return [32]byte{}, [32]byte{}, errTDilithium3DKGInvalidCluster
		}
	}
	return sessionDigest, committeeDigest, nil
}

func recoverOrCreateTDilithium3DKGSeed(runners [6]*tdilithium3DKGRunner, groupIndex int, group dilithium3v1.RSSGroupMask, attempt, leader uint8) ([32]byte, error) {
	var seed [32]byte
	for position, runner := range runners {
		state := runner.record.Groups[groupIndex]
		if state.Stage < tdilithium3DKGGroupSeedPersisted || !group.Contains(uint8(position)) || state.Seed == ([32]byte{}) {
			continue
		}
		if state.Attempt != attempt || state.LeaderPosition != leader {
			return [32]byte{}, errTDilithium3DKGJournalTransition
		}
		if seed != ([32]byte{}) && seed != state.Seed {
			return [32]byte{}, errTDilithium3DKGJournalTransition
		}
		seed = state.Seed
	}
	if seed != ([32]byte{}) {
		return seed, nil
	}
	if err := readTDilithium3DKGRandom(runners[leader].entropy, seed[:]); err != nil {
		return [32]byte{}, err
	}
	return seed, nil
}

func deliverTDilithium3DKGSeedPackets(transport *tdilithium3DKGMemoryTransport, sessionDigest, committeeDigest [32]byte, group dilithium3v1.RSSGroupMask, attempt, leader uint8, seed [32]byte, duplicate bool) error {
	for recipient := uint8(0); recipient < uint8(transport.participants); recipient++ {
		if !group.Contains(recipient) || recipient == leader {
			continue
		}
		message := dilithium3v1.GroupSeedMessage{SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group, LeaderPosition: leader, RecipientPosition: recipient, Attempt: attempt, Seed: seed}
		encoded, err := message.MarshalBinary()
		if err != nil {
			return err
		}
		if err := transport.deliver(tdilithium3DKGPacket{Kind: 1, SessionDigest: sessionDigest, CommitteeDigest: committeeDigest, GroupMask: group, Attempt: attempt, SenderPosition: leader, RecipientPosition: recipient, Payload: encoded}, duplicate); err != nil {
			return err
		}
	}
	return nil
}

func buildTDilithium3DKGShare(runner *tdilithium3DKGRunner, publicKey [1952]byte, transcriptDigest [32]byte) (*dilithium3v1.LocalShare, error) {
	groups, err := dilithium3v1.GroupsForPositionN(runner.participantPosition, len(runner.session.Committee.Participants))
	if err != nil {
		return nil, err
	}
	participantCount := len(runner.session.Committee.Participants)
	share := &dilithium3v1.LocalShare{
		Protocol:            runner.session.Protocol,
		Key:                 protocolThresholdKey(publicKey, runner.session.KeyGeneration),
		Committee:           runner.session.Committee.Clone(),
		ParticipantID:       runner.session.Committee.Participants[runner.participantPosition],
		ParticipantPosition: runner.participantPosition,
		ActivationEpoch:     runner.session.ActivationEpoch,
		TranscriptDigest:    transcriptDigest,
		Rho:                 runner.record.Rho,
	}
	share.Components = make([]dilithium3v1.RSSComponent, len(groups))
	for index, group := range groups {
		groupIndex, _ := tdilithium3DKGGroupIndex(group, participantCount)
		component := runner.record.Groups[groupIndex].Component
		if component.GroupMask != group {
			return nil, errTDilithium3DKGJournalTransition
		}
		share.Components[index] = component
	}
	if err := share.Validate(); err != nil {
		share.Zeroize()
		return nil, err
	}
	return share, nil
}

func protocolThresholdKey(publicKey [1952]byte, generation uint64) protocol.ThresholdKeyID {
	return protocol.ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: generation, PublicKey: append([]byte(nil), publicKey[:]...)}
}

func tdilithium3DKGComponentDigest(group dilithium3v1.RSSGroupMask, leader uint8, contributionDigest [32]byte, s1 dilithium3v1.VectorL, s2 dilithium3v1.VectorK) [32]byte {
	hash := sha3.New256()
	_, _ = hash.Write([]byte("QAU-TDILITHIUM3-V1-JOURNAL-COMPONENT"))
	_, _ = hash.Write([]byte{byte(group), leader})
	_, _ = hash.Write(contributionDigest[:])
	for _, vector := range s1 {
		for _, coefficient := range vector {
			_, _ = hash.Write([]byte{byte(coefficient), byte(coefficient >> 8), byte(coefficient >> 16), byte(coefficient >> 24)})
		}
	}
	for _, vector := range s2 {
		for _, coefficient := range vector {
			_, _ = hash.Write([]byte{byte(coefficient), byte(coefficient >> 8), byte(coefficient >> 16), byte(coefficient >> 24)})
		}
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func readTDilithium3DKGRandom(reader io.Reader, destination []byte) error {
	for attempts := 0; attempts < 4; attempts++ {
		if _, err := io.ReadFull(reader, destination); err != nil {
			return err
		}
		if !allTDilithium3DKGZero(destination) {
			return nil
		}
	}
	return fmt.Errorf("Dilithium3 DKG entropy returned zero repeatedly")
}

func allTDilithium3DKGZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func shouldCrashTDilithium3DKG(faults tdilithium3DKGFaultPlan, boundary tdilithium3DKGBoundary) bool {
	return faults.CrashBoundary != "" && faults.CrashPosition < 6 && faults.CrashBoundary == boundary
}

func checkTDilithium3DKGContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func zeroTDilithium3DKGResults(results *[6]tdilithium3DKGResult) {
	for index := range results {
		if results[index].Share != nil {
			results[index].Share.Zeroize()
			results[index].Share = nil
		}
	}
}

func storeTDilithium3DKGRecords(runners [6]*tdilithium3DKGRunner, dirty [6]bool) error {
	var waitGroup sync.WaitGroup
	errorsByPosition := make([]error, len(runners))
	for position, runner := range runners {
		if !dirty[position] {
			continue
		}
		waitGroup.Add(1)
		go func(position int, runner *tdilithium3DKGRunner) {
			defer waitGroup.Done()
			errorsByPosition[position] = runner.journal.Store(runner.record)
		}(position, runner)
	}
	waitGroup.Wait()
	for _, err := range errorsByPosition {
		if err != nil {
			return err
		}
	}
	return nil
}

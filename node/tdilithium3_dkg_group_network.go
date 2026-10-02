// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// Dilithium3 DKG group network drives one canonical RSS group over the network.
// It is the transport-bound counterpart of the in-process per-group loop in
// runTDilithium3DKGCluster: the leader publishes a private seed to the two other
// group members, every member derives its component from the seed it actually
// received, the leader broadcasts the partial public key, members recompute and
// acknowledge it, and every participant records the group as verified once the
// three members signed matching acknowledgements.
//
// Groups are driven one after another, so messages for a group that the local
// node has not reached yet must not be dropped: the inbox replays each
// (message type, sender, sequence, group, attempt) tuple exactly once, so a
// discarded message would be lost for good. tdilithium3DKGGroupExchange keeps
// those messages until their group is driven.

// tdilithium3DKGGroupExchange retains verified group messages until the driver
// reaches the group that owns them.
type tdilithium3DKGGroupExchange struct {
	mu      sync.Mutex
	pending map[dilithium3v1.RSSGroupMask][]tdilithium3DKGVerifiedMessage
}

func newTDilithium3DKGGroupExchange() *tdilithium3DKGGroupExchange {
	return &tdilithium3DKGGroupExchange{pending: make(map[dilithium3v1.RSSGroupMask][]tdilithium3DKGVerifiedMessage)}
}

// tdilithium3DKGMessagedGroup reports which canonical RSS group owns one
// verified inbound message. Messages that carry no group (randomness traffic
// from the previous round) report scoped=false.
func tdilithium3DKGMessagedGroup(message tdilithium3DKGVerifiedMessage) (dilithium3v1.RSSGroupMask, bool, error) {
	switch message.Type {
	case p2p.MsgTypeTDilithium3DKGGroupSeed:
		seed, err := dilithium3v1.UnmarshalGroupSeedMessage(message.Payload)
		if err != nil {
			return 0, false, err
		}
		return seed.GroupMask, true, nil
	case p2p.MsgTypeTDilithium3DKGContribution:
		contribution, err := dilithium3v1.UnmarshalPublicContribution(message.Payload)
		if err != nil {
			return 0, false, err
		}
		return contribution.GroupMask, true, nil
	case p2p.MsgTypeTDilithium3DKGAcknowledgement:
		acknowledgement, err := dilithium3v1.UnmarshalContributionAcknowledgement(message.Payload)
		if err != nil {
			return 0, false, err
		}
		return acknowledgement.GroupMask, true, nil
	case p2p.MsgTypeTDilithium3DKGComplaint:
		complaint, err := dilithium3v1.UnmarshalComplaint(message.Payload)
		if err != nil {
			return 0, false, err
		}
		return complaint.GroupMask, true, nil
	default:
		return 0, false, nil
	}
}

func (exchange *tdilithium3DKGGroupExchange) store(group dilithium3v1.RSSGroupMask, message tdilithium3DKGVerifiedMessage) {
	if exchange == nil {
		return
	}
	exchange.mu.Lock()
	defer exchange.mu.Unlock()
	exchange.pending[group] = append(exchange.pending[group], message)
}

func (exchange *tdilithium3DKGGroupExchange) take(group dilithium3v1.RSSGroupMask) []tdilithium3DKGVerifiedMessage {
	if exchange == nil {
		return nil
	}
	exchange.mu.Lock()
	defer exchange.mu.Unlock()
	messages := exchange.pending[group]
	delete(exchange.pending, group)
	return messages
}

// runTDilithium3DKGGroup drives one canonical RSS group to completion. It
// returns once the group is durably verified. A context that ends first is a
// hard failure, not a resumable pause: the round reports
// errTDilithium3DKGGroupStalled and the journal stays untouched, so a node that
// fell behind its peers fails closed instead of recording a partial transcript.
func (n *Node) runTDilithium3DKGGroup(
	ctx context.Context,
	runner *tdilithium3DKGRunner,
	group dilithium3v1.RSSGroupMask,
	exchange *tdilithium3DKGGroupExchange,
	sign func([]byte) ([]byte, error),
	broadcast func(uint8, []byte) error,
	sendPrivate func(uint8, uint8, []byte) error,
) error {
	inbox := n.tdilithium3DKGInboxSnapshot()
	if !n.tdilithium3DKGInboundAllowed() || inbox == nil || runner == nil || exchange == nil || sign == nil || broadcast == nil || sendPrivate == nil || ctx == nil {
		return fmt.Errorf("Dilithium3 DKG group network requires an enabled, authenticated local runner")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return fmt.Errorf("Dilithium3 DKG group network requires a deadline")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	localDigest, err := runner.session.Digest()
	if err != nil {
		return err
	}
	activeDigest, err := inbox.session.Digest()
	if err != nil || activeDigest != localDigest || runner.participantPosition != inbox.recipientPosition {
		return errTDilithium3DKGJournalSession
	}
	round, err := newTDilithium3DKGGroupRound(runner, group)
	if err != nil {
		return err
	}
	pump := func() error {
		outbound, err := round.advance(sign)
		if err != nil {
			return err
		}
		return dispatchTDilithium3DKGGroupOutbound(outbound, broadcast, sendPrivate)
	}
	for _, message := range exchange.take(group) {
		if _, err := round.observe(message); err != nil {
			return err
		}
	}
	if err := pump(); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for !round.complete() {
		select {
		case <-ctx.Done():
			return round.stalledError(ctx.Err())
		case message, ok := <-inbox.messages:
			if !ok {
				return fmt.Errorf("Dilithium3 DKG inbox closed")
			}
			owner, scoped, err := tdilithium3DKGMessagedGroup(message)
			if err != nil {
				return err
			}
			switch {
			case !scoped:
				// Randomness traffic from the previous round; already consumed.
			case owner == group:
				if _, err := round.observe(message); err != nil {
					return err
				}
			default:
				exchange.store(owner, message)
			}
			if err := pump(); err != nil {
				return err
			}
		case <-ticker.C:
			if err := ctx.Err(); err != nil {
				return round.stalledError(err)
			}
			if err := pump(); err != nil {
				return err
			}
		}
	}
	return nil
}

func dispatchTDilithium3DKGGroupOutbound(
	outbound []tdilithium3DKGGroupOutbound,
	broadcast func(uint8, []byte) error,
	sendPrivate func(uint8, uint8, []byte) error,
) error {
	for _, message := range outbound {
		if message.Recipient == tdilithium3DKGGroupBroadcast {
			if err := broadcast(message.MessageType, message.Payload); err != nil {
				return err
			}
			continue
		}
		if err := sendPrivate(message.MessageType, message.Recipient, message.Payload); err != nil {
			return err
		}
	}
	return nil
}

// tdilithium3DKGFinalize assembles the mode3 public key from the twenty
// verified group contributions and then installs and acknowledges the local
// share. It is purely local, idempotent, and mirrors the tail of
// runTDilithium3DKGCluster.
func tdilithium3DKGFinalize(runner *tdilithium3DKGRunner) (tdilithium3DKGResult, error) {
	if runner == nil || runner.journal == nil || int(runner.participantPosition) >= len(runner.session.Committee.Participants) || runner.record.ParticipantPosition != runner.participantPosition {
		return tdilithium3DKGResult{}, errTDilithium3DKGInvalidCluster
	}
	if runner.record.Stage < tdilithium3DKGStageGroupsInProgress {
		return tdilithium3DKGResult{}, errTDilithium3DKGJournalTransition
	}
	contributions := make([]dilithium3v1.PublicContribution, len(runner.record.Groups))
	for index, state := range runner.record.Groups {
		if state.Stage != tdilithium3DKGGroupContributionVerified || state.Contribution.GroupMask != state.GroupMask {
			return tdilithium3DKGResult{}, errTDilithium3DKGJournalTransition
		}
		contributions[index] = state.Contribution
	}
	publicKey, transcriptDigest, err := dilithium3v1.AssembleMode3PublicKey(runner.record.Rho, contributions, len(runner.session.Committee.Participants))
	if err != nil {
		return tdilithium3DKGResult{}, err
	}
	if runner.record.Stage < tdilithium3DKGStageAllGroupsComplete {
		record := runner.record.Clone()
		if err := record.MarkAllGroupsComplete(publicKey, transcriptDigest); err != nil {
			return tdilithium3DKGResult{}, err
		}
		if err := runner.journal.Store(record); err != nil {
			return tdilithium3DKGResult{}, err
		}
		runner.record = record
	} else if runner.record.PublicKey != publicKey || runner.record.TranscriptDigest != transcriptDigest {
		return tdilithium3DKGResult{}, errTDilithium3DKGJournalTransition
	}
	share, err := buildTDilithium3DKGShare(runner, publicKey, transcriptDigest)
	if err != nil {
		return tdilithium3DKGResult{}, err
	}
	if runner.record.Stage < tdilithium3DKGStageShareInstalled {
		if err := runner.shareStore.Store(share, runner.password); err != nil {
			share.Zeroize()
			return tdilithium3DKGResult{}, err
		}
		record := runner.record.Clone()
		if err := record.MarkShareInstalled(); err != nil {
			share.Zeroize()
			return tdilithium3DKGResult{}, err
		}
		if err := runner.journal.Store(record); err != nil {
			share.Zeroize()
			return tdilithium3DKGResult{}, err
		}
		runner.record = record
	}
	if runner.record.Stage < tdilithium3DKGStageAcknowledgementPersisted {
		record := runner.record.Clone()
		if err := record.MarkAcknowledgementPersisted(); err != nil {
			share.Zeroize()
			return tdilithium3DKGResult{}, err
		}
		if err := runner.journal.Store(record); err != nil {
			share.Zeroize()
			return tdilithium3DKGResult{}, err
		}
		runner.record = record
	}
	return tdilithium3DKGResult{PublicKey: publicKey, TranscriptDigest: transcriptDigest, Share: share}, nil
}

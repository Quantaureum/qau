// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	"fmt"
	"time"

	"github.com/quantaureum/qau/p2p"
)

func (n *Node) runTDilithium3DKGRandomness(
	ctx context.Context,
	runner *tdilithium3DKGRunner,
	exchange *tdilithium3DKGGroupExchange,
	sign func([]byte) ([]byte, error),
	broadcast func(uint8, []byte) error,
) error {
	inbox := n.tdilithium3DKGInboxSnapshot()
	if !n.tdilithium3DKGInboundAllowed() || inbox == nil || runner == nil || exchange == nil || sign == nil || broadcast == nil || ctx == nil {
		return fmt.Errorf("Dilithium3 DKG network requires an enabled, authenticated local runner")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return fmt.Errorf("Dilithium3 DKG network requires a deadline")
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
	// Skip the randomness round if it was already completed in a previous
	// (partial) ceremony run. The journal's stage and persisted global
	// randomness are the durable evidence; the round constructor requires
	// Stage == Prepared, so without this skip a retry after a partial run
	// fails with "requires a prepared local runner" instead of resuming
	// from the next incomplete round.
	if runner.record.Stage >= tdilithium3DKGStageRandomnessComplete &&
		runner.record.GlobalRandomness != ([64]byte{}) &&
		runner.record.Rho != ([32]byte{}) {
		return nil
	}
	round, err := newTDilithium3DKGRandomnessRound(runner)
	if err != nil {
		return err
	}
	commitment, err := round.outboundCommitment(sign)
	if err != nil {
		return err
	}
	if err := broadcast(p2p.MsgTypeTDilithium3DKGRandomnessCommitment, commitment); err != nil {
		return err
	}
	var reveal []byte
	sendReveal := func() error {
		if !runner.record.CommitmentsPersisted {
			return nil
		}
		if reveal == nil {
			var err error
			reveal, err = round.outbound(sign)
			if err != nil {
				return err
			}
		}
		return broadcast(p2p.MsgTypeTDilithium3DKGRandomness, reveal)
	}
	if err := sendReveal(); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case message, ok := <-inbox.messages:
			if !ok {
				return fmt.Errorf("Dilithium3 DKG inbox closed")
			}
			// A peer that already finished its randomness round can broadcast
			// group traffic before this node leaves the loop. Those messages
			// carry no randomness scope, so observing them here would fail the
			// round outright; retain them for the group driver instead.
			if group, scoped, err := tdilithium3DKGMessagedGroup(message); err != nil {
				return err
			} else if scoped {
				exchange.store(group, message)
				continue
			}
			revealBefore := runner.record.CommitmentsPersisted
			ready, err := round.observe(message)
			if err != nil {
				return err
			}
			if !revealBefore && runner.record.CommitmentsPersisted {
				if err := sendReveal(); err != nil {
					return err
				}
			}
			if ready {
				return nil
			}
		case <-ticker.C:
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := broadcast(p2p.MsgTypeTDilithium3DKGRandomnessCommitment, commitment); err != nil {
				return err
			}
			if err := sendReveal(); err != nil {
				return err
			}
		}
	}
}

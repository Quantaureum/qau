// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"sync"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

type tdilithium3DKGRandomnessRound struct {
	mu            sync.Mutex
	runner        *tdilithium3DKGRunner
	commitments   [][32]byte
	committed     []bool
	pending       [][32]byte
	pendingSeen   []bool
	contributions [][32]byte
	seen          []bool
}

func newTDilithium3DKGRandomnessRound(runner *tdilithium3DKGRunner) (*tdilithium3DKGRandomnessRound, error) {
	if runner == nil || runner.journal == nil || int(runner.participantPosition) >= len(runner.session.Committee.Participants) || runner.record.ParticipantPosition != runner.participantPosition || runner.record.Stage != tdilithium3DKGStagePrepared || runner.record.LocalRandomness == ([32]byte{}) {
		return nil, fmt.Errorf("Dilithium3 DKG randomness requires a prepared local runner")
	}
	if err := runner.session.Validate(); err != nil {
		return nil, err
	}
	sessionDigest, err := runner.session.Digest()
	if err != nil || sessionDigest != runner.record.SessionDigest {
		return nil, errTDilithium3DKGJournalSession
	}
	participantCount := len(runner.session.Committee.Participants)
	round := &tdilithium3DKGRandomnessRound{
		runner:        runner,
		commitments:   make([][32]byte, participantCount),
		committed:     make([]bool, participantCount),
		pending:       make([][32]byte, participantCount),
		pendingSeen:   make([]bool, participantCount),
		contributions: make([][32]byte, participantCount),
		seen:          make([]bool, participantCount),
	}
	round.contributions[runner.participantPosition] = runner.record.LocalRandomness
	round.seen[runner.participantPosition] = true
	localCommitment, err := dilithium3v1.DKGRandomnessCommitment(runner.session, runner.participantPosition, runner.record.LocalRandomness)
	if err != nil {
		return nil, err
	}
	if runner.record.CommitmentsPersisted {
		if runner.record.RandomnessCommitments[runner.participantPosition] != localCommitment {
			return nil, errTDilithium3DKGJournalSession
		}
		round.commitments = append([][32]byte(nil), runner.record.RandomnessCommitments...)
		for position := range round.committed {
			round.committed[position] = true
		}
	} else {
		round.commitments[runner.participantPosition] = localCommitment
		round.committed[runner.participantPosition] = true
	}
	return round, nil
}

func (round *tdilithium3DKGRandomnessRound) outboundCommitment(sign func([]byte) ([]byte, error)) ([]byte, error) {
	if round == nil || round.runner == nil || sign == nil {
		return nil, fmt.Errorf("Dilithium3 DKG commitment requires a local signer")
	}
	round.mu.Lock()
	runner := round.runner
	position := runner.participantPosition
	commitment := round.commitments[position]
	round.mu.Unlock()
	return encodeTDilithium3DKGSignedEnvelope(runner.session, p2p.MsgTypeTDilithium3DKGRandomnessCommitment, position, 1, commitment[:], sign)
}

func (round *tdilithium3DKGRandomnessRound) receivedCount() int {
	round.mu.Lock()
	defer round.mu.Unlock()
	return round.receivedCountLocked()
}

func (round *tdilithium3DKGRandomnessRound) receivedCountLocked() int {
	count := 0
	for _, seen := range round.seen {
		if seen {
			count++
		}
	}
	return count
}

func (round *tdilithium3DKGRandomnessRound) outbound(sign func([]byte) ([]byte, error)) ([]byte, error) {
	if round == nil || round.runner == nil || sign == nil {
		return nil, fmt.Errorf("Dilithium3 DKG randomness outbound requires a local signer")
	}
	round.mu.Lock()
	runner := round.runner
	position := runner.participantPosition
	local := runner.record.LocalRandomness
	committed := runner.record.CommitmentsPersisted
	round.mu.Unlock()
	if local == ([32]byte{}) || !committed {
		return nil, fmt.Errorf("Dilithium3 DKG reveal requires durable commitments")
	}
	return encodeTDilithium3DKGSignedEnvelope(runner.session, p2p.MsgTypeTDilithium3DKGRandomness, position, 1, local[:], sign)
}

func (round *tdilithium3DKGRandomnessRound) observe(message tdilithium3DKGVerifiedMessage) (bool, error) {
	if round == nil || round.runner == nil {
		return false, fmt.Errorf("invalid Dilithium3 DKG randomness round")
	}
	round.mu.Lock()
	defer round.mu.Unlock()
	if round.runner.record.Stage != tdilithium3DKGStagePrepared || (message.Type != p2p.MsgTypeTDilithium3DKGRandomness && message.Type != p2p.MsgTypeTDilithium3DKGRandomnessCommitment) || len(message.Payload) != 32 || message.Sequence != 1 {
		return false, fmt.Errorf("invalid Dilithium3 DKG randomness message or phase")
	}
	position, found := tdilithium3DKGCommitteePosition(round.runner.session.Committee, message.SenderID)
	if !found {
		return false, fmt.Errorf("Dilithium3 DKG randomness sender outside committee")
	}
	var contribution [32]byte
	copy(contribution[:], message.Payload)
	if contribution == ([32]byte{}) {
		return false, fmt.Errorf("zero Dilithium3 DKG randomness contribution")
	}
	if message.Type == p2p.MsgTypeTDilithium3DKGRandomnessCommitment {
		if round.committed[position] && round.commitments[position] != contribution {
			return false, fmt.Errorf("conflicting Dilithium3 DKG randomness commitment")
		}
		if !round.committed[position] {
			if round.runner.record.CommitmentsPersisted {
				return false, errTDilithium3DKGJournalSession
			}
			round.commitments[position] = contribution
			round.committed[position] = true
		}
		if round.runner.record.CommitmentsPersisted {
			return false, nil
		}
		for _, committed := range round.committed {
			if !committed {
				return false, nil
			}
		}
		updated := round.runner.record.Clone()
		if err := updated.MarkRandomnessCommitments(append([][32]byte(nil), round.commitments...)); err != nil {
			return false, err
		}
		if err := round.runner.journal.Store(updated); err != nil {
			return false, err
		}
		round.runner.record = updated
		for pendingPosition, seen := range round.pendingSeen {
			if !seen {
				continue
			}
			ready, err := round.observeRevealLocked(uint8(pendingPosition), round.pending[pendingPosition])
			if err != nil {
				return false, err
			}
			round.pendingSeen[pendingPosition] = false
			round.pending[pendingPosition] = [32]byte{}
			if ready {
				return true, nil
			}
		}
		return false, nil
	}
	if !round.runner.record.CommitmentsPersisted {
		if round.pendingSeen[position] && round.pending[position] != contribution {
			return false, fmt.Errorf("conflicting early Dilithium3 DKG reveal")
		}
		round.pendingSeen[position] = true
		round.pending[position] = contribution
		return false, nil
	}
	return round.observeRevealLocked(position, contribution)
}

func (round *tdilithium3DKGRandomnessRound) observeRevealLocked(position uint8, contribution [32]byte) (bool, error) {
	commitment, err := dilithium3v1.DKGRandomnessCommitment(round.runner.session, position, contribution)
	if err != nil || round.commitments[position] != commitment {
		return false, fmt.Errorf("Dilithium3 DKG reveal does not match signed commitment")
	}
	if round.seen[position] && round.contributions[position] != contribution {
		return false, fmt.Errorf("conflicting Dilithium3 DKG randomness contribution")
	}
	if !round.seen[position] {
		round.contributions[position] = contribution
		round.seen[position] = true
	}
	if round.receivedCountLocked() != len(round.seen) {
		return false, nil
	}
	global, rho, err := dilithium3v1.DeriveDKGRandomness(round.runner.session, round.contributions)
	if err != nil {
		return false, err
	}
	updated := round.runner.record.Clone()
	if err := updated.MarkRandomnessComplete(global, rho); err != nil {
		return false, err
	}
	if err := round.runner.journal.Store(updated); err != nil {
		return false, err
	}
	round.runner.record = updated
	return true, nil
}

package node

import (
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3_reshare_add_driver.go hosts the transport-independent part of
// the R77 add-rotation ceremony: the joiner groups run the regular group
// seed dance under the reshare session digest (production wires that up);
// this runner takes the fresh weave components, lets the weaver publish its
// correction delta, and assembles the rotated store-ready share.

// tdilithium3ReshareAddRunner drives one member (continuing or joining)
// through an add rotation.
type tdilithium3ReshareAddRunner struct {
	plan             *dilithium3v1.ReshareRotationPlan
	old              *dilithium3v1.LocalShare
	next             protocol.CommitteeID
	previousKey      protocol.ThresholdKeyID
	rho              [32]byte
	activationEpoch  uint64
	transcriptDigest [32]byte
	position         uint8
	weave            map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent
	delta            *dilithium3v1.ReshareWeaveDelta
	final            *dilithium3v1.LocalShare
}

// newTDilithium3ReshareAddRunner prepares one member of an add rotation.
// weave carries the freshly derived components of the joiner groups this
// member belongs to; continuing members pass their old share, the joiner
// passes nil plus the previous key identity supplied by the rotation
// request. previousEpochForJoiner is the activation epoch of the previous
// committee (used only by the joiner).
func newTDilithium3ReshareAddRunner(
	plan *dilithium3v1.ReshareRotationPlan,
	old *dilithium3v1.LocalShare,
	next protocol.CommitteeID,
	previousKey protocol.ThresholdKeyID,
	rho [32]byte,
	activationEpoch uint64,
	transcriptDigest [32]byte,
	weave map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent,
) (*tdilithium3ReshareAddRunner, error) {
	if plan == nil || !plan.HasWeaver {
		return nil, fmt.Errorf("%w: add runner requires an add plan", errReshareRunnerInput)
	}
	if len(next.Participants) != plan.NewParticipants {
		return nil, fmt.Errorf("%w: new committee size %d, plan expects %d", errReshareRunnerInput, len(next.Participants), plan.NewParticipants)
	}
	var position uint8
	if old != nil {
		if err := old.Validate(); err != nil {
			return nil, fmt.Errorf("%w: old share: %v", errReshareRunnerInput, err)
		}
		p, found := dilithium3v1.CommitteePositionOf(old.Committee, old.ParticipantID)
		if !found || len(old.Committee.Participants) != plan.OldParticipants {
			return nil, fmt.Errorf("%w: old share not a continuing member of the plan", errReshareRunnerInput)
		}
		position = p
	} else {
		position = plan.Weaver
	}
	runner := &tdilithium3ReshareAddRunner{
		plan:             plan,
		old:              old,
		next:             next.Clone(),
		previousKey:      previousKey.Clone(),
		rho:              rho,
		activationEpoch:  activationEpoch,
		transcriptDigest: transcriptDigest,
		position:         position,
		weave:            make(map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent, len(weave)),
	}
	for group, component := range weave {
		runner.weave[group] = component
	}
	return runner, nil
}

// WeaverDelta produces the signed correction for the correction group.
// Only the weaver (joiner) may call it; everyone else must receive a delta.
func (runner *tdilithium3ReshareAddRunner) WeaverDelta() (dilithium3v1.ReshareWeaveDelta, error) {
	if runner.position != runner.plan.Weaver {
		return dilithium3v1.ReshareWeaveDelta{}, fmt.Errorf("%w: only the weaver signs the correction", errReshareRunnerInput)
	}
	return runner.plan.WeaverDelta(runner.weave)
}

// ReceiveWeaveDelta records the weaver's correction for the correction
// group. Only non-weaver correction-group members call it.
func (runner *tdilithium3ReshareAddRunner) ReceiveWeaveDelta(delta dilithium3v1.ReshareWeaveDelta) error {
	if runner.final != nil {
		return errReshareRunnerClosed
	}
	if runner.position == runner.plan.Weaver {
		return fmt.Errorf("%w: the weaver derives its own correction", errReshareRunnerInput)
	}
	if !runner.plan.CorrectionGroup.Contains(runner.position) {
		return fmt.Errorf("%w: position %d is not in the correction group", errReshareRunnerInput, runner.position)
	}
	if delta.CorrectionGroup != runner.plan.CorrectionGroup {
		return fmt.Errorf("%w: delta names %06b, expected %06b", errReshareRunnerInput, uint16(delta.CorrectionGroup), uint16(runner.plan.CorrectionGroup))
	}
	delete(runner.weave, runner.plan.CorrectionGroup)
	copied := delta
	runner.weave[runner.plan.CorrectionGroup] = copied.Component
	runner.delta = &copied
	return nil
}

// Ready reports whether assembly can proceed: continuing members always
// (their fresh material was delivered by the group rounds), the correction
// group members only after the weaver delta arrived.
func (runner *tdilithium3ReshareAddRunner) Ready() bool {
	if runner.position == runner.plan.Weaver {
		_, ok := runner.weave[runner.plan.CorrectionGroup]
		return ok
	}
	if runner.plan.CorrectionGroup.Contains(runner.position) {
		return runner.delta != nil
	}
	return true
}

// Assemble produces the rotated, store-ready share.
func (runner *tdilithium3ReshareAddRunner) Assemble() (*dilithium3v1.LocalShare, error) {
	if runner.final != nil {
		return nil, errReshareRunnerClosed
	}
	if !runner.Ready() {
		return nil, fmt.Errorf("%w: waiting for the weaver delta", errReshareRunnerInput)
	}
	var delta *dilithium3v1.ReshareWeaveDelta
	if runner.position == runner.plan.Weaver {
		own, err := runner.plan.WeaverDelta(runner.weave)
		if err != nil {
			return nil, err
		}
		delta = &own
	} else if runner.plan.CorrectionGroup.Contains(runner.position) {
		delta = runner.delta
	} else {
		delta = nil
	}
	share, err := runner.plan.ResharedAddedShare(runner.old, runner.next, runner.previousKey, runner.rho, runner.activationEpoch, runner.transcriptDigest, runner.weave, delta)
	if err != nil {
		return nil, err
	}
	runner.final = share
	return share, nil
}

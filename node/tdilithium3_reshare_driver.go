package node

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3_reshare_driver.go hosts the transport-independent part of the
// R77 remove-rotation ceremony: which deltas this member must publish, which
// it must receive, and the assembly step. The p2p adapter delivers the
// outgoing envelopes and feeds inbound ones into Receive; keeping the
// runner free of network types keeps the rotation testable in-process.

var (
	// errReshareRunnerInput marks caller mistakes: wrong plan shape, wrong
	// local share, or a duplicate delta envelope.
	errReshareRunnerInput = errors.New("invalid Dilithium3 v1 reshare runner input")
	// errReshareRunnerClosed marks attempted protocol steps after the
	// runner finalized its rotated share.
	errReshareRunnerClosed = errors.New("Dilithium3 v1 reshare runner is closed")
)

// tdilithium3ReshareDeltaDelivery is the node-level envelope for one fold
// delta hop: the anchor sends it to each non-anchor member of the target
// group, identified by its position in the NEW committee.
type tdilithium3ReshareDeltaDelivery struct {
	RecipientPosition uint8
	Delta             dilithium3v1.ReshareFoldDelta
}

// tdilithium3ReshareRemoveRunner drives one continuing member through a
// remove rotation.
type tdilithium3ReshareRemoveRunner struct {
	plan             *dilithium3v1.ReshareRotationPlan
	old              *dilithium3v1.LocalShare
	next             protocol.CommitteeID
	transcriptDigest [32]byte

	oldPosition uint8
	newPosition uint8
	// pending tracks each fold target group this member belongs to; the
	// runner assembles only when every outstanding delta arrived exactly
	// once.
	pending  map[dilithium3v1.RSSGroupMask]struct{}
	received map[dilithium3v1.RSSGroupMask]dilithium3v1.ReshareFoldDelta
	outgoing []tdilithium3ReshareDeltaDelivery
	final    *dilithium3v1.LocalShare
}

// newTDilithium3ReshareRemoveRunner prepares one continuing member for a
// remove rotation against an already-planned committee pair.
func newTDilithium3ReshareRemoveRunner(
	plan *dilithium3v1.ReshareRotationPlan,
	old *dilithium3v1.LocalShare,
	next protocol.CommitteeID,
	transcriptDigest [32]byte,
) (*tdilithium3ReshareRemoveRunner, error) {
	if plan == nil || !plan.HasLeaver {
		return nil, fmt.Errorf("%w: remove runner requires a remove plan", errReshareRunnerInput)
	}
	if old == nil {
		return nil, fmt.Errorf("%w: the leaver's runner cannot be built here", errReshareRunnerInput)
	}
	if len(old.Committee.Participants) != plan.OldParticipants {
		return nil, fmt.Errorf("%w: old committee size %d, plan expects %d", errReshareRunnerInput, len(old.Committee.Participants), plan.OldParticipants)
	}
	if len(next.Participants) != plan.NewParticipants {
		return nil, fmt.Errorf("%w: new committee size %d, plan expects %d", errReshareRunnerInput, len(next.Participants), plan.NewParticipants)
	}
	position, found := dilithium3v1.CommitteePositionOf(old.Committee, old.ParticipantID)
	if !found {
		return nil, fmt.Errorf("%w: participant %d not in the old committee", errReshareRunnerInput, old.ParticipantID)
	}
	if position == plan.Leaver {
		return nil, fmt.Errorf("%w: the leaver does not carry a reshared share", errReshareRunnerInput)
	}
	runner := &tdilithium3ReshareRemoveRunner{
		plan:             plan,
		old:              old,
		next:             next.Clone(),
		transcriptDigest: transcriptDigest,
		oldPosition:      position,
		newPosition:      position,
		pending:          make(map[dilithium3v1.RSSGroupMask]struct{}),
		received:         make(map[dilithium3v1.RSSGroupMask]dilithium3v1.ReshareFoldDelta),
	}
	if position > plan.Leaver {
		runner.newPosition--
	}
	// Inventory of every fold targeting this member. The anchor of a fold
	// already holds the source, so it solves its own fold immediately;
	// only folds anchored elsewhere sit in pending.
	local := make(map[dilithium3v1.RSSGroupMask]dilithium3v1.RSSComponent, len(old.Components))
	for _, component := range old.Components {
		local[component.GroupMask] = component
	}
	for _, fold := range plan.FoldAssignments {
		if !fold.Target.Contains(runner.newPosition) {
			continue
		}
		if fold.AnchorPosition == position {
			source, ok := local[fold.Source]
			if !ok {
				return nil, fmt.Errorf("%w: self-anchored fold source %06b missing", errReshareRunnerInput, uint16(fold.Source))
			}
			runner.received[fold.Target] = dilithium3v1.ReshareFoldDelta{
				Source:    fold.Source,
				Target:    fold.Target,
				Component: source,
			}
			continue
		}
		runner.pending[fold.Target] = struct{}{}
	}
	// Inventory of the folds this member anchors: it owes a copy of the
	// source component to the two other target members.
	deltas, err := plan.FoldDeltasFor(position, local)
	if err != nil {
		return nil, err
	}
	for _, delta := range deltas {
		// Re-number the anchor to new coordinates for recipient filtering.
		anchorNew := foldAnchorFor(delta, plan)
		for recipient := uint8(0); recipient < uint8(plan.NewParticipants); recipient++ {
			if !delta.Target.Contains(recipient) || recipient == anchorNew {
				continue
			}
			runner.outgoing = append(runner.outgoing, tdilithium3ReshareDeltaDelivery{
				RecipientPosition: recipient,
				Delta:             delta,
			})
		}
	}
	return runner, nil
}

// foldAnchorFor computes the anchor's new-coordinates position for the fold
// assignment backing the delta (Rotate removes exactly one position).
func foldAnchorFor(delta dilithium3v1.ReshareFoldDelta, plan *dilithium3v1.ReshareRotationPlan) uint8 {
	for _, fold := range plan.FoldAssignments {
		if fold.Source == delta.Source && fold.Target == delta.Target {
			anchor := fold.AnchorPosition
			if anchor > plan.Leaver {
				anchor--
			}
			return anchor
		}
	}
	return 0
}

// Position returns this member's old committee position.
func (runner *tdilithium3ReshareRemoveRunner) Position() uint8 {
	return runner.oldPosition
}

// OutgoingDeltas returns every delivery the member's anchor duty owed.
func (runner *tdilithium3ReshareRemoveRunner) OutgoingDeltas() []tdilithium3ReshareDeltaDelivery {
	out := make([]tdilithium3ReshareDeltaDelivery, len(runner.outgoing))
	copy(out, runner.outgoing)
	return out
}

// Receive ingests one delta envelope addressed at this member. Foreign
// target groups and replays are refused; canonical correctness is enforced
// later by Assemble through the plan's carry-fold rules.
func (runner *tdilithium3ReshareRemoveRunner) Receive(delivery tdilithium3ReshareDeltaDelivery) error {
	if runner.final != nil {
		return errReshareRunnerClosed
	}
	if delivery.RecipientPosition != runner.newPosition {
		return fmt.Errorf("%w: delta addressed to %d, this runner is %d", errReshareRunnerInput, delivery.RecipientPosition, runner.newPosition)
	}
	if !delivery.Delta.Target.Contains(runner.newPosition) {
		return fmt.Errorf("%w: delta targets group %06b; position %d is not a member", errReshareRunnerInput, uint16(delivery.Delta.Target), runner.newPosition)
	}
	if _, pending := runner.pending[delivery.Delta.Target]; !pending {
		return fmt.Errorf("%w: no outstanding fold for group %06b", errReshareRunnerInput, uint16(delivery.Delta.Target))
	}
	if _, replay := runner.received[delivery.Delta.Target]; replay {
		return fmt.Errorf("%w: duplicate fold delta for group %06b", errReshareRunnerInput, uint16(delivery.Delta.Target))
	}
	runner.received[delivery.Delta.Target] = delivery.Delta
	delete(runner.pending, delivery.Delta.Target)
	return nil
}

// Pending reports how many fold deltas this member still awaits.
func (runner *tdilithium3ReshareRemoveRunner) Pending() int { return len(runner.pending) }

// PendingDetail renders the still-outstanding fold targets and the
// new-coordinate position of each supplying anchor, for timeout diagnostics.
// An empty pending set renders as "complete".
func (runner *tdilithium3ReshareRemoveRunner) PendingDetail() string {
	if len(runner.pending) == 0 {
		return "complete"
	}
	anchorFor := map[dilithium3v1.RSSGroupMask]uint8{}
	for _, fold := range runner.plan.FoldAssignments {
		anchor := fold.AnchorPosition
		if anchor > runner.plan.Leaver {
			anchor--
		}
		anchorFor[fold.Target] = anchor
	}
	parts := make([]string, 0, len(runner.pending))
	for target := range runner.pending {
		parts = append(parts, fmt.Sprintf("%06b/anchor=%d", uint16(target), anchorFor[target]))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// Ready reports whether every fold targeted at this member has arrived.
func (runner *tdilithium3ReshareRemoveRunner) Ready() bool {
	return len(runner.pending) == 0
}

// Assemble delivers the rotated share once the deltas are complete.
func (runner *tdilithium3ReshareRemoveRunner) Assemble() (*dilithium3v1.LocalShare, error) {
	if runner.final != nil {
		return nil, errReshareRunnerClosed
	}
	if !runner.Ready() {
		return nil, fmt.Errorf("%w: %d fold deltas still outstanding", errReshareRunnerInput, len(runner.pending))
	}
	ordered := make([]dilithium3v1.ReshareFoldDelta, 0, len(runner.received))
	for _, delta := range runner.received {
		ordered = append(ordered, delta)
	}
	share, err := runner.plan.ResharedShare(runner.old, runner.next, runner.transcriptDigest, ordered)
	if err != nil {
		return nil, err
	}
	runner.final = share
	return share, nil
}

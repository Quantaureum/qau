// Quantaureum Node source, version 1.0.0.
package node

// Node-side request schedule of the signing executor (design note, Slice 4).
// One signing request runs up to SigningParallelSlots candidate slots, each
// slot being its own session with its own committed randomness, its own
// one-time record, its own transport and inbox, and its own deadline, until one
// slot produces the signature. A slot that ends in a legitimate filter -- a
// local rejection or a failed public combine check -- is a normal outcome and
// the schedule starts the next candidate; any other failure ends the request.
//
// The schedule mirrors the wallet-side reference schedule (sign_executor_
// schedule.go) at the network boundary: it owns the slot numbering, the
// candidate count, and the per-slot deadline, while the per-slot material is
// built by a factory. The production factory binds the wallet party, the
// identity snapshot, the fresh one-time record, and the signing and broadcast
// callbacks; tests drive the policy with scripted slots.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SigningSlotTimeout bounds one candidate slot. It must exceed the
// spread in when the four signers start the same seal plus the four-round
// exchange, not merely the local cryptographic cost: the signing math is
// milliseconds, but a signer begins a slot only once it has the block and the
// pending seal, so on the devnet the proposer starts ~6s ahead of the other
// three (a fixed block-propagation-plus-announce lag, measured, not jitter).
// The earliest starter's session must stay alive until the latest joiner has
// finished its four rounds, i.e. it must outlast the ~6s spread by the exchange
// time. A window sized only to the spread leaves the earliest starter timing
// out just as the exchange completes, so the slot seals only about half the
// time; this larger window covers the spread with room for the exchange.
// Because distinct slots now seal concurrently, a session that runs past the
// consensus-slot boundary does not block the next slot. The party's own
// randomness is single-use, so a slot that still cannot converge within the
// window is closed rather than retried forever.
const tdilithium3SigningSlotTimeout = 15 * time.Second

// errTDilithium3SigningRequestExhausted reports a request whose candidate slots
// were all filtered: the caller retries with a new request and fresh material.
var errTDilithium3SigningRequestExhausted = errors.New("Dilithium3 signing request exhausted")

// tdilithium3SigningSlotFactory builds one candidate slot's party with the
// transport and inbox of that slot's own session.
type tdilithium3SigningSlotFactory func(slot uint16) (
	tdilithium3SigningSlot, *tdilithium3SigningTransport, *tdilithium3SigningInbox, error,
)

// tdilithium3SigningRequestOutcome records one candidate slot: whether it
// produced the signature, and, for a filtered slot, the bounded reason.
type tdilithium3SigningRequestOutcome struct {
	Slot     uint16
	Accepted bool
	Reason   dilithium3v1.SigningExecutorReason
}

// tdilithium3SigningRequestSchedule drives one request across its candidates.
type tdilithium3SigningRequestSchedule struct {
	node        *Node
	factory     tdilithium3SigningSlotFactory
	slots       uint16
	slotTimeout time.Duration
}

// newTDilithium3SigningRequestSchedule validates the schedule shape.
func newTDilithium3SigningRequestSchedule(
	node *Node,
	factory tdilithium3SigningSlotFactory,
	slots uint16,
	slotTimeout time.Duration,
) (*tdilithium3SigningRequestSchedule, error) {
	if node == nil || factory == nil {
		return nil, fmt.Errorf("Dilithium3 signing request schedule requires a node and a slot factory")
	}
	if slots == 0 || slots > dilithium3v1.SigningParallelSlots {
		return nil, fmt.Errorf(
			"%w: %d candidate slots, want [1, %d]",
			errTDilithium3SigningRequestExhausted, slots, dilithium3v1.SigningParallelSlots,
		)
	}
	if slotTimeout <= 0 {
		return nil, fmt.Errorf("Dilithium3 signing request schedule requires a positive slot timeout")
	}
	return &tdilithium3SigningRequestSchedule{
		node: node, factory: factory, slots: slots, slotTimeout: slotTimeout,
	}, nil
}

// run drives every candidate slot concurrently until one signs. Each candidate
// is its own session with its own committed randomness, one-time record,
// transport, and inbox, so they share no signing state and the shared journal
// and identity key are each internally synchronized. Running them in parallel
// is what the protocol's parallel candidate slots intend: a serial walk makes
// each node drift onto a different candidate index than its peers, so their
// per-candidate sessions never line up and every candidate times out in mutual
// silence. In parallel, all peers hold all candidate sessions at once, so a
// candidate that four peers reach together converges within one slot deadline.
//
// The first candidate to sign wins and cancels the rest. A candidate that ends
// in a legitimate filter -- a local rejection or a failed public combine check
// -- is recorded as a normal outcome; any other failure is remembered and, if
// no candidate signs, returned as the request's error.
func (schedule *tdilithium3SigningRequestSchedule) run(
	ctx context.Context,
) ([]byte, []tdilithium3SigningRequestOutcome, error) {
	if schedule == nil || schedule.node == nil || schedule.factory == nil || ctx == nil {
		return nil, nil, fmt.Errorf("Dilithium3 signing request schedule is not fully wired")
	}

	// Build every candidate up front so a factory error fails the whole request
	// before any session is launched, as the serial schedule did.
	type candidate struct {
		slot   uint16
		driver *tdilithium3SigningSlotDriver
		party  tdilithium3SigningSlot
	}
	candidates := make([]candidate, 0, schedule.slots)
	for slot := uint16(1); slot <= schedule.slots; slot++ {
		party, transport, inbox, err := schedule.factory(slot)
		if err != nil {
			return nil, nil, err
		}
		driver, err := newTDilithium3SigningSlotDriver(schedule.node, party, transport, inbox)
		if err != nil {
			return nil, nil, err
		}
		candidates = append(candidates, candidate{slot: slot, driver: driver, party: party})
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type candidateResult struct {
		slot      uint16
		signature []byte
		err       error
		filtered  bool
	}
	results := make(chan candidateResult, len(candidates))
	for _, c := range candidates {
		go func(c candidate) {
			slotCtx, slotCancel := context.WithTimeout(runCtx, schedule.slotTimeout)
			defer slotCancel()
			signature, err := c.driver.run(slotCtx)
			results <- candidateResult{
				slot: c.slot, signature: signature, err: err, filtered: c.party.Filtered(),
			}
		}(c)
	}

	outcomes := make([]tdilithium3SigningRequestOutcome, 0, len(candidates))
	var hardErr error
	for read := 0; read < len(candidates); read++ {
		result := <-results
		if result.err == nil {
			// A candidate signed. Cancel the rest; their results land in the
			// fully buffered channel and are discarded with it.
			cancel()
			outcomes = append(outcomes, tdilithium3SigningRequestOutcome{Slot: result.slot, Accepted: true})
			return result.signature, outcomes, nil
		}
		if result.filtered {
			outcome, _ := dilithium3v1.SigningExecutorOutcomeOf(result.err)
			outcomes = append(outcomes, tdilithium3SigningRequestOutcome{Slot: result.slot, Reason: outcome.Reason})
			continue
		}
		if hardErr == nil {
			hardErr = result.err
		}
	}
	if hardErr != nil {
		return nil, outcomes, hardErr
	}
	return nil, outcomes, fmt.Errorf(
		"%w: %d candidate slots all filtered", errTDilithium3SigningRequestExhausted, len(outcomes),
	)
}

// tdilithium3SigningPartyConfig binds one local signer to one signing request
// and its candidate slots.
type tdilithium3SigningPartyConfig struct {
	// Request is the base signing request, unbound to any slot.
	Request protocol.SignRequest

	// Share is this signer's own local share.
	Share *dilithium3v1.LocalShare

	// Signers are the four active signer identities in ascending order.
	Signers [4]uint32

	// Journal is this signer's durable signing journal, which lives across the
	// whole request; every candidate slot adds its own burned or finalized
	// entry.
	Journal *dilithium3v1.SigningJournal

	// Identities is the identity snapshot of the four active signers.
	Identities map[uint32]tdilithium3SigningIdentity

	// Sign signs one outbound envelope with this signer's identity key.
	Sign func([]byte) ([]byte, error)

	// Broadcast sends one encoded envelope to the p2p layer.
	Broadcast func(uint8, []byte) error

	// Entropy is this signer's randomness source: the per-slot record metadata
	// and the per-slot ball point are drawn from it. It must be cryptographic
	// in production (crypto/rand.Reader).
	Entropy io.Reader

	// Slots is the candidate count, zero meaning SigningParallelSlots.
	Slots uint16

	// SlotTimeout bounds one candidate slot, zero meaning the default.
	SlotTimeout time.Duration
}

// newTDilithium3SigningSchedule returns the production schedule of one request:
// every candidate slot mints its own one-time record, builds the wallet party,
// and binds the slot's transport and inbox to the party's session.
func newTDilithium3SigningSchedule(
	node *Node,
	config tdilithium3SigningPartyConfig,
) (*tdilithium3SigningRequestSchedule, error) {
	if config.Slots == 0 {
		config.Slots = dilithium3v1.SigningParallelSlots
	}
	if config.SlotTimeout == 0 {
		config.SlotTimeout = tdilithium3SigningSlotTimeout
	}
	if err := config.Request.Validate(); err != nil {
		return nil, fmt.Errorf("Dilithium3 signing request config: %w", err)
	}
	if config.Journal == nil {
		return nil, fmt.Errorf("Dilithium3 signing request config requires a signing journal")
	}
	if config.Sign == nil || config.Broadcast == nil || config.Entropy == nil {
		return nil, fmt.Errorf(
			"Dilithium3 signing request config requires an identity signer, a broadcast, and entropy",
		)
	}
	for index, signer := range config.Signers {
		if signer == 0 || (index > 0 && config.Signers[index-1] >= signer) {
			return nil, fmt.Errorf("Dilithium3 signing request config signers are not strictly ascending")
		}
		if _, found := config.Identities[signer]; !found {
			return nil, fmt.Errorf("Dilithium3 signing request config is missing identity of signer %d", signer)
		}
	}
	if config.Share == nil {
		return nil, fmt.Errorf("Dilithium3 signing request config requires a local share")
	}
	if !slices.Contains(config.Signers[:], config.Share.ParticipantID) {
		return nil, fmt.Errorf(
			"Dilithium3 signing request config share of participant %d is not an active signer",
			config.Share.ParticipantID,
		)
	}
	if err := config.Share.Validate(); err != nil {
		return nil, fmt.Errorf("Dilithium3 signing request config: %w", err)
	}
	factory := func(slot uint16) (
		tdilithium3SigningSlot, *tdilithium3SigningTransport, *tdilithium3SigningInbox, error,
	) {
		record, err := dilithium3v1.NewSigningExecutorRecord(config.Share.ParticipantID, config.Entropy)
		if err != nil {
			return nil, nil, nil, err
		}
		party, err := dilithium3v1.NewSigningExecutorParty(dilithium3v1.SigningExecutorPartyConfig{
			Request: config.Request, Share: config.Share, Signers: config.Signers, Slot: slot,
			Journal: config.Journal, Record: record, Entropy: config.Entropy,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		slotContext := tdilithium3SigningContext{
			SessionID:        party.SessionID(),
			KeyGeneration:    config.Request.Key.Generation,
			CommitteeVersion: config.Request.Committee.Version,
			Signers:          config.Signers,
		}
		inbox, err := newTDilithium3SigningInboxFromIdentitySnapshot(slotContext, config.Identities)
		if err != nil {
			return nil, nil, nil, err
		}
		transport, err := newTDilithium3SigningTransport(
			slotContext, config.Share.ParticipantID, config.Sign, config.Broadcast,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		return party, transport, inbox, nil
	}
	return newTDilithium3SigningRequestSchedule(node, factory, config.Slots, config.SlotTimeout)
}

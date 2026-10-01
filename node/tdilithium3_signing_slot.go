// Quantaureum Node source, version 1.0.0.
package node

// Node-side slot driver of the signing executor (design note, Slice 4). The
// driver owns one slot end to end: it starts the local party, installs the
// slot's authenticated inbox, pumps the party's round messages through the
// per-slot transport, hands every verified inbound message to the party, whose
// gate and round logic decide, retransmits the slot's envelopes on a ticker,
// and closes the slot exactly once.
//
// The driver decides nothing about the slot's outcome: the party's bounded
// outcome is the result. A legitimate filter outcome (a local rejection or a
// failed combine check) is returned like any other abort, and the schedule
// owner one level up decides whether the next candidate slot starts.
//
// Two invariants shape the code. First, the driver is the only writer of the
// node's signing inbox field, and it requires a bounded context: an unbounded
// slot could pin the party's one-time material forever. Second, every path that
// does not end in a signature calls Finish, so the slot's one-time record and
// its journal entry are consumed rather than left live (design note, Slice 3).
// The driver refuses to run at all unless the node is admissible: not the
// mainnet and the experimental gate open. Nothing here enables the executor.

import (
	"context"
	"fmt"
	"time"

	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// tdilithium3SigningRetransmitInterval is how often the slot's envelopes are
// rebroadcast byte for byte. Receivers treat an identical envelope as an
// idempotent duplicate, so a retransmission cannot be mistaken for equivocation.
const tdilithium3SigningRetransmitInterval = time.Second

// tdilithium3SigningSlot is the per-slot party as the node layer sees it: one
// signer's round logic, gate, and single-use lifecycle behind six calls. The
// driver uses the lifecycle; the request schedule additionally asks Filtered
// whether a failed slot was a legitimate filter.
type tdilithium3SigningSlot interface {
	Start() error
	Drain() []dilithium3v1.SigningExecutorRoundMessage
	Deliver(senderID uint32, kind uint16, payload []byte) error
	Done() bool
	Filtered() bool
	Finish() ([]byte, error)
}

// The wallet's per-signer party is the production implementation.
var _ tdilithium3SigningSlot = (*dilithium3v1.SigningExecutorParty)(nil)

// tdilithium3SigningSlotDriver drives one party over one slot.
type tdilithium3SigningSlotDriver struct {
	node       *Node
	slot       tdilithium3SigningSlot
	transport  *tdilithium3SigningTransport
	inbox      *tdilithium3SigningInbox
	retransmit time.Duration
}

// newTDilithium3SigningSlotDriver checks that the three pieces belong to the
// same session and sender: the transport and the inbox must carry one binding,
// and the inbox must admit the transport's own sender.
func newTDilithium3SigningSlotDriver(
	node *Node,
	slot tdilithium3SigningSlot,
	transport *tdilithium3SigningTransport,
	inbox *tdilithium3SigningInbox,
) (*tdilithium3SigningSlotDriver, error) {
	if node == nil || slot == nil || transport == nil || inbox == nil {
		return nil, fmt.Errorf("Dilithium3 signing slot driver requires a node, slot, transport, and inbox")
	}
	if transport.context.SessionID != inbox.context.SessionID ||
		transport.context.KeyGeneration != inbox.context.KeyGeneration ||
		transport.context.CommitteeVersion != inbox.context.CommitteeVersion ||
		transport.context.Signers != inbox.context.Signers ||
		!inbox.context.activeSigner(transport.senderID) {
		return nil, fmt.Errorf("Dilithium3 signing slot driver requires one session across transport and inbox")
	}
	return &tdilithium3SigningSlotDriver{
		node: node, slot: slot, transport: transport, inbox: inbox,
		retransmit: tdilithium3SigningRetransmitInterval,
	}, nil
}

// run drives the slot until it is done, the context ends, or a local failure
// ends it. Every path but a signature consumes the slot's one-time material.
func (driver *tdilithium3SigningSlotDriver) run(ctx context.Context) ([]byte, error) {
	if driver == nil || driver.node == nil || driver.slot == nil || driver.transport == nil || driver.inbox == nil {
		return nil, fmt.Errorf("Dilithium3 signing slot driver is not fully wired")
	}
	if ctx == nil {
		return nil, fmt.Errorf("Dilithium3 signing slot driver requires a context")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, fmt.Errorf("Dilithium3 signing slot driver requires a deadline")
	}
	if !driver.node.tdilithium3SigningInboxAdmissible(driver.inbox) {
		return nil, fmt.Errorf("Dilithium3 signing slot driver requires an admissible node and a bound inbox")
	}
	if err := driver.slot.Start(); err != nil {
		return nil, err
	}
	driver.node.registerTDilithium3SigningInbox(driver.inbox)
	defer driver.node.unregisterTDilithium3SigningInbox(driver.inbox)

	var sent []uint16
	pump := func() error {
		for _, message := range driver.slot.Drain() {
			if err := driver.transport.Send(message.Kind, message.Payload); err != nil {
				return err
			}
			sent = append(sent, message.Kind)
		}
		return nil
	}
	// abandon ends the slot on a local failure: the cause is kept, and Finish
	// consumes the one-time material so no live record or unfinished journal
	// entry is left behind.
	abandon := func(cause error) error {
		_, _ = driver.slot.Finish()
		return cause
	}
	if err := pump(); err != nil {
		return nil, abandon(err)
	}
	ticker := time.NewTicker(driver.retransmit)
	defer ticker.Stop()
	for {
		if driver.slot.Done() {
			return driver.slot.Finish()
		}
		select {
		case <-ctx.Done():
			// The slot is starved: Finish consumes the material and reports the
			// missing input as the party's bounded outcome.
			_, err := driver.slot.Finish()
			if err == nil {
				return nil, fmt.Errorf("Dilithium3 signing slot ended without a signature")
			}
			return nil, err
		case message := <-driver.inbox.messages:
			err := driver.slot.Deliver(message.SenderID, message.Kind, message.Payload)
			if err != nil {
				if outcome, ok := dilithium3v1.SigningExecutorOutcomeOf(err); ok && !outcome.Fatal {
					// An unauthorized refusal leaves the slot running: network
					// noise cannot kill a healthy signing.
					nodeLog.Debug("Dilithium3 signing slot refused an unauthorized message: %v", err)
					continue
				}
				return nil, abandon(err)
			}
			if err := pump(); err != nil {
				return nil, abandon(err)
			}
		case <-ticker.C:
			for _, kind := range sent {
				// A retransmission is best effort: the slot deadline bounds a
				// transport that stays broken.
				if err := driver.transport.Resend(kind); err != nil {
					nodeLog.Debug("Dilithium3 signing retransmission of kind %d failed: %v", kind, err)
				}
			}
		}
	}
}

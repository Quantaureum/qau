// Quantaureum Node source, version 1.0.0.
package node

// Node-side outbound transport of the signing executor (design note, Slice 4).
// One transport carries one local signer's slot messages onto the p2p kinds of
// the executor. It owns the sender's sequence counter -- strictly increasing,
// one fresh envelope per round kind per slot -- and keeps every encoded
// envelope, because a retransmission must reuse its bytes exactly: the inbox's
// replay table recognizes that as idempotent, and a second encoding of the same
// message would be a conflict.
//
// The transport signs through a caller-supplied callback (the node's validator
// identity key) and sends through a caller-supplied broadcast function, so the
// p2p wiring stays outside this unit and its tests need no host. Nothing here
// enables the executor: no transport is constructed unless a slot is driven
// behind the experimental gate.

import (
	"fmt"
	"sync"
)

// tdilithium3SigningTransport is one local signer's slot transport.
type tdilithium3SigningTransport struct {
	context   tdilithium3SigningContext
	senderID  uint32
	sign      func([]byte) ([]byte, error)
	broadcast func(uint8, []byte) error

	mu       sync.Mutex
	sequence uint32
	sent     map[uint16][]byte
}

// newTDilithium3SigningTransport binds one local signer of one slot to the wire.
func newTDilithium3SigningTransport(
	context tdilithium3SigningContext,
	senderID uint32,
	sign func([]byte) ([]byte, error),
	broadcast func(uint8, []byte) error,
) (*tdilithium3SigningTransport, error) {
	if err := context.Validate(); err != nil {
		return nil, err
	}
	if !context.activeSigner(senderID) {
		return nil, fmt.Errorf("Dilithium3 signing transport sender %d is not an active signer", senderID)
	}
	if sign == nil || broadcast == nil {
		return nil, fmt.Errorf("Dilithium3 signing transport requires an identity signer and a broadcast function")
	}
	return &tdilithium3SigningTransport{
		context: context, senderID: senderID, sign: sign, broadcast: broadcast,
		sent: make(map[uint16][]byte),
	}, nil
}

// Send encodes one fresh round message with the sender's next sequence and
// broadcasts it. A round kind of this slot is sent at most once: the party
// emits one message per kind, and a second payload for the same kind would
// equivocate. The envelope is recorded before the broadcast, so a failed
// broadcast leaves the caller a byte-identical retransmission (Resend) rather
// than a second envelope with a new sequence.
func (transport *tdilithium3SigningTransport) Send(kind uint16, payload []byte) error {
	if transport == nil {
		return fmt.Errorf("Dilithium3 signing transport is missing")
	}
	messageType, known := tdilithium3SigningWireKind(kind)
	if !known {
		return fmt.Errorf("Dilithium3 signing transport does not accept round kind %d", kind)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if _, exists := transport.sent[kind]; exists {
		return fmt.Errorf("Dilithium3 signing round kind %d was already sent in this slot", kind)
	}
	if transport.sequence == ^uint32(0) {
		return fmt.Errorf("Dilithium3 signing sequence exhausted")
	}
	sequence := transport.sequence + 1
	encoded, err := encodeTDilithium3SigningEnvelope(
		transport.context, messageType, transport.senderID, sequence, payload, transport.sign,
	)
	if err != nil {
		return err
	}
	transport.sequence = sequence
	transport.sent[kind] = encoded
	return transport.broadcast(messageType, encoded)
}

// Resend broadcasts the stored envelope of one round kind byte for byte. It
// consumes no sequence.
func (transport *tdilithium3SigningTransport) Resend(kind uint16) error {
	if transport == nil {
		return fmt.Errorf("Dilithium3 signing transport is missing")
	}
	messageType, known := tdilithium3SigningWireKind(kind)
	if !known {
		return fmt.Errorf("Dilithium3 signing transport does not accept round kind %d", kind)
	}
	transport.mu.Lock()
	encoded, exists := transport.sent[kind]
	transport.mu.Unlock()
	if !exists {
		return fmt.Errorf("Dilithium3 signing round kind %d has not been sent", kind)
	}
	return transport.broadcast(messageType, encoded)
}

// Sequence returns the last sequence this transport used, zero before the first
// send.
func (transport *tdilithium3SigningTransport) Sequence() uint32 {
	if transport == nil {
		return 0
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.sequence
}

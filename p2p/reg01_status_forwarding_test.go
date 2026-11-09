package p2p

import (
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// REG-01 regression: height hints are decoupled from signature verification.
// A non-validator peer (or a frame that fails the mapping checks) must still
// reach statusCh so cold-start sync is not blocked waiting for a signed
// validator status. The validator→PeerID mapping, however, stays gated by
// verification (the H-01 anti-hijack invariant).
func TestREG01_HeightForwardedWhileMappingStaysVerified(t *testing.T) {
	h := &Host{
		statusCh:         make(chan PeerMessage, 8),
		validatorPeerMap: make(map[types.Address]PeerID),
	}

	// Non-validator peer: zero ValidatorAddress and no signature. It cannot
	// own a mapping, but its height is a valid sync hint.
	unsignedPayload := EncodeStatusMessage(&StatusMessage{NetworkID: 1668, BestHeight: 42})
	h.handleBaseProtocol(&Message{Type: MsgTypeStatus, From: PeerID("peer-unsigned"), Payload: unsignedPayload})
	if len(h.statusCh) != 1 {
		t.Fatalf("unsigned status must still be forwarded as a height hint, got %d entries", len(h.statusCh))
	}
	if len(h.validatorPeerMap) != 0 {
		t.Fatal("unsigned status must not create a validator mapping")
	}

	// Forged validator status: claims a validator address with a bogus
	// signature. Height is forwarded, mapping is not.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	forgedAddr := kp.Public.Address()
	forgedPayload := EncodeStatusMessage(&StatusMessage{
		NetworkID:          1668,
		BestHeight:         42,
		ValidatorAddress:   forgedAddr,
		ValidatorPublicKey: kp.Public.Bytes(),
		ValidatorSignature: []byte{0x01, 0x02, 0x03},
	})
	h.handleBaseProtocol(&Message{Type: MsgTypeStatus, From: PeerID("peer-forged"), Payload: forgedPayload})
	if len(h.statusCh) != 2 {
		t.Fatalf("forged status must still be forwarded as a height hint, got %d entries", len(h.statusCh))
	}
	if _, ok := h.validatorPeerMap[forgedAddr]; ok {
		t.Fatal("forged status must not register a validator mapping")
	}

	// Valid legacy signature: the peer proves ownership of the claimed key,
	// so both the height and the mapping are accepted.
	valid := &StatusMessage{
		NetworkID:          1668,
		BestHeight:         42,
		ValidatorAddress:   forgedAddr,
		ValidatorPublicKey: kp.Public.Bytes(),
	}
	base := EncodeStatusMessage(valid)
	sig, err := kp.Private.Sign(base[:104])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	valid.ValidatorSignature = sig
	validPayload := EncodeStatusMessage(valid)
	validPeer := PeerID("peer-valid")
	h.handleBaseProtocol(&Message{Type: MsgTypeStatus, From: validPeer, Payload: validPayload})
	if len(h.statusCh) != 3 {
		t.Fatalf("validly signed status must be forwarded, got %d entries", len(h.statusCh))
	}
	if got := h.validatorPeerMap[forgedAddr]; got != validPeer {
		t.Fatalf("validly signed status must register the mapping: got %q want %q", got, validPeer)
	}
}

package node

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// H-01 regression: the status producer must place Timestamp + SessionNonce in
// the signed domain, so peers can enforce the freshness window and reject
// replayed frames. Before the fix the producer signed only base[:104] and
// omitted the V2 extension, leaving the host's replay controls inert.
func TestH01_BuildStatusMessageSignsV2Domain(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	s := NewSyncer(nil, block.NewBlockStore(db.NewMemDB()), nil, nil, 1668)
	s.SetValidatorAddress(kp.Public.Address())
	s.SetValidatorSigner(kp.Private, kp.Public.Bytes())

	status := s.buildStatusMessage()
	if status == nil {
		t.Fatal("buildStatusMessage returned nil")
	}
	if status.Timestamp == 0 {
		t.Fatal("expected a fresh Timestamp in the status")
	}
	if status.SessionNonce == ([16]byte{}) {
		t.Fatal("expected a non-zero SessionNonce in the status")
	}
	if len(status.ValidatorSignature) == 0 {
		t.Fatal("expected a validator signature")
	}

	wire := p2p.EncodeStatusMessage(status)
	decoded, err := p2p.DecodeStatusMessage(wire)
	if err != nil {
		t.Fatalf("DecodeStatusMessage: %v", err)
	}
	if decoded.Timestamp != status.Timestamp {
		t.Fatalf("timestamp round-trip mismatch: got %d want %d", decoded.Timestamp, status.Timestamp)
	}
	if decoded.SessionNonce != status.SessionNonce {
		t.Fatal("session nonce round-trip mismatch")
	}

	// Reconstruct the signed domain exactly as the verifier does:
	// base[:104] || Timestamp(8B BE) || SessionNonce(16B).
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, decoded.Timestamp)
	signed := append([]byte(nil), wire[:104]...)
	signed = append(signed, ts...)
	signed = append(signed, decoded.SessionNonce[:]...)

	if !kp.Public.Verify(signed, decoded.ValidatorSignature) {
		t.Fatal("signature does not cover base[:104] || Timestamp || SessionNonce")
	}
}

// H-01 regression: the host's replay tracker must reject the same
// (validator, peer, nonce) tuple the second time it is seen.
func TestH01_SessionNonceTrackerRejectsReplay(t *testing.T) {
	tracker := p2p.NewSessionNonceTracker()
	addr := types.Address{0x01, 0x02}
	var nonce [16]byte
	nonce[0] = 0xaa

	if tracker.Seen(addr, "peer-1", nonce) {
		t.Fatal("first sighting must not be treated as a replay")
	}
	if !tracker.Seen(addr, "peer-1", nonce) {
		t.Fatal("second sighting of the same nonce must be rejected")
	}
	// DIVERGENCE from node 8245a07 (intentional): qau's 443c60c tightened the
	// tracker to scope the replay window per VALIDATOR, not per (validator,
	// peer) pair — replaying a captured frame from a DIFFERENT peer identity
	// must not escape the tracker (see p2p.SessionNonceTracker.Seen's
	// validator-scoped key). Node's snapshot predates that hardening, so its
	// copy of this test expects the weaker per-peer semantics.
	if !tracker.Seen(addr, "peer-2", nonce) {
		t.Fatal("same nonce from a different peer must be treated as a replay (validator-scoped window, 443c60c)")
	}
}

// H-01 regression: the active-set verifier accepts an active validator whose
// public key matches and rejects everything else (unknown address, wrong key).
func TestH01_VerifyActiveValidator(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	vm := consensus.NewValidatorManager()
	addr := kp.Public.Address()
	if err := vm.AddGenesisValidator(addr, addr, kp.Public, big.NewInt(6000), 100, 0); err != nil {
		t.Fatalf("AddGenesisValidator: %v", err)
	}

	n := &Node{validatorManager: vm}

	if err := n.VerifyActiveValidator(addr, kp.Public.Bytes()); err != nil {
		t.Fatalf("active validator must be accepted: %v", err)
	}
	if err := n.VerifyActiveValidator(addr, other.Public.Bytes()); err == nil {
		t.Fatal("public key mismatch must be rejected")
	}
	if err := n.VerifyActiveValidator(other.Public.Address(), other.Public.Bytes()); err == nil {
		t.Fatal("unknown validator address must be rejected")
	}
}

// Quantaureum Node source, version 1.0.0.
// Package node — tests for the isProposerForSlot election contract.
//
// History:
//   - R29 P2-SILENT-ERR (2026-07-26): when QPOS failed to elect a proposer,
//     isProposerForSlot fell back to a modulo (slot % len(validators))
//     round-robin schedule; the fix only made the degradation visible via a
//     Warn log.
//   - R88-A: the round-robin fallback is REVOKED. The modulo
//     schedule is not a consensus schedule — the validator side
//     (VerifyProposer → GetProposerForSlot) derives the expected proposer
//     strictly from the VRF-accumulator shuffle, so a block proposed on the
//     round-robin schedule is rejected by peers whose election succeeded
//     (chain fork), or masks the election failure when it coincidentally
//     matches.
//
// This file verifies that isProposerForSlot:
//  1. FAILS CLOSED — returns (false, empty address) when QPOS cannot elect
//     a proposer (QPOS error / nil proposer / nil QPOS engine).
//  2. Does NOT panic when QPOS is in a degraded state.
//  3. Still uses the QPOS result when the election succeeds.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// r88BPValidatorSet builds a 3-validator set with addresses 0xAA/0xBB/0xCC.
func r88BPValidatorSet(t *testing.T) *consensus.ValidatorSet {
	t.Helper()
	vals := []*consensus.Validator{
		{Address: types.Address{0xAA}, Stake: big.NewInt(1_000_000), Active: true, PublicKeyBytes: []byte{0x01}},
		{Address: types.Address{0xBB}, Stake: big.NewInt(1_000_000), Active: true, PublicKeyBytes: []byte{0x02}},
		{Address: types.Address{0xCC}, Stake: big.NewInt(1_000_000), Active: true, PublicKeyBytes: []byte{0x03}},
	}
	vs, err := consensus.NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	return vs
}

// TestR88A_isProposerForSlot_QPOSElectionErrorFailsClosed verifies the R88-A
// contract: when QPOS's GetProposerForSlot returns an error (here: a QPOS
// built with a nil validator set, which returns ErrNotProposer),
// isProposerForSlot must return (false, empty address) — NOT the old
// modulo round-robin answer.
//
// Fails without the R88-A fix: the old code fell through to
// validators[slot%len] and returned a proposer address.
func TestR88A_isProposerForSlot_QPOSElectionErrorFailsClosed(t *testing.T) {
	bpVS := r88BPValidatorSet(t)

	// NewQPOS(nil) is accepted by the constructor; its GetProposerForSlot
	// returns (nil, ErrNotProposer) on every call.
	qpos, err := consensus.NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS(nil) failed: %v", err)
	}

	bp := &BlockProducer{
		validatorSet:  bpVS,
		qpos:          qpos,
		validatorAddr: types.Address{0xBB},
	}

	// Slots chosen so the OLD modulo fallback would have returned a
	// non-empty proposer on every case: 16959%3=0 → 0xAA (this is the exact
	// slot of the R88 fork), 0%3=0 → 0xAA, 1%3=1 → 0xBB,
	// 16960%3=1 → 0xBB (the slot the restarting node proposed on).
	for _, slot := range []uint64{0, 1, 2, 16959, 16960} {
		isProposer, proposerAddr := bp.isProposerForSlot(slot)
		if isProposer {
			t.Errorf("slot %d: isProposer=true under QPOS election error — fail-open (R88-A regression: proposed on a non-consensus schedule)", slot)
		}
		if proposerAddr != (types.Address{}) {
			t.Errorf("slot %d: proposerAddr=%x under QPOS election error — expected empty address (R88-A fail-closed contract), got the modulo fallback answer",
				slot, proposerAddr[:8])
		}
	}
}

// TestR88A_isProposerForSlot_NilQPOSFailsClosed verifies the nil-QPOS case:
// no consensus engine → cannot elect → must return (false, empty) instead
// of the revoked modulo schedule.
//
// Fails without the R88-A fix: the old code returned
// validators[slot%len] directly.
func TestR88A_isProposerForSlot_NilQPOSFailsClosed(t *testing.T) {
	bpVS := r88BPValidatorSet(t)

	bp := &BlockProducer{
		validatorSet:  bpVS,
		qpos:          nil, // No QPOS engine
		validatorAddr: types.Address{0xAA},
	}

	for _, slot := range []uint64{0, 1, 2, 16959} {
		isProposer, proposerAddr := bp.isProposerForSlot(slot)
		if isProposer {
			t.Errorf("slot %d: isProposer=true with nil QPOS — fail-open (R88-A regression)", slot)
		}
		if proposerAddr != (types.Address{}) {
			t.Errorf("slot %d: proposerAddr=%x with nil QPOS — expected empty address (R88-A fail-closed contract)",
				slot, proposerAddr[:8])
		}
	}
}

// TestP2_SILENT_ERR_isProposerForSlot_EmptyValidatorSet verifies the
// fail-closed behavior: when validatorSet is nil or empty, isProposerForSlot
// returns (false, empty address) — NOT (true, ...) which would be fail-open.
func TestP2_SILENT_ERR_isProposerForSlot_EmptyValidatorSet(t *testing.T) {
	bp := &BlockProducer{
		validatorSet: nil,
		qpos:         nil,
	}

	isProposer, proposerAddr := bp.isProposerForSlot(0)
	if isProposer {
		t.Error("P2-SILENT-ERR REGRESSION: isProposerForSlot returned true with nil validatorSet (fail-open)")
	}
	if proposerAddr != (types.Address{}) {
		t.Errorf("isProposerForSlot returned non-empty address %x with nil validatorSet (expected zero address)",
			proposerAddr[:8])
	}
}

// TestP2_SILENT_ERR_isProposerForSlot_WithValidQPOS verifies that when QPOS
// is healthy and returns a proposer, isProposerForSlot uses the QPOS result
// (not any fallback). This ensures R88-A didn't break the normal path.
func TestP2_SILENT_ERR_isProposerForSlot_WithValidQPOS(t *testing.T) {
	// Generate a real key pair so the validator has a valid public key.
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("crypto.GenerateKeyPair failed: %v", err)
	}
	valAddr := keyPair.Public.Address()

	val := &consensus.Validator{
		Address:        valAddr,
		Stake:          big.NewInt(1_000_000),
		Active:         true,
		PublicKeyBytes: keyPair.Public.Bytes(),
	}
	bpVS, err := consensus.NewValidatorSet([]*consensus.Validator{val})
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	qpos, err := consensus.NewQPOS(bpVS)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	bp := &BlockProducer{
		validatorSet:  bpVS,
		qpos:          qpos,
		validatorAddr: valAddr,
	}

	// With a single validator, every slot should select val.
	isProposer, proposerAddr := bp.isProposerForSlot(0)
	if !isProposer {
		t.Error("slot 0: expected isProposer=true with valid QPOS and single validator")
	}
	if proposerAddr != valAddr {
		t.Errorf("slot 0: proposerAddr = %x, want %x", proposerAddr[:8], valAddr[:8])
	}
}

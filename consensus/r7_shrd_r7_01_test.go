// Quantaureum Node source, version 1.0.0.
package consensus

// SHRD-R7-01 (2026-07-17) regression tests.
//
// These tests verify that ReceiveBlock rejects blocks whose header.Timestamp
// drifts more than ShardMaxTimestampDrift seconds from the receiver's wall
// clock. Before the fix, ReceiveBlock performed no drift check at all,
// despite the ProposeBlock call site comment promising "validators check
// it's within bounds". An elected proposer could sign a block with an
// arbitrary far-future or far-past timestamp, which would then propagate
// unchanged through the receive path.
//
// Attack model covered:
//   - Far-future timestamp: proposer signs a block with a timestamp well
//     beyond now + ShardMaxTimestampDrift.
//   - Far-past timestamp: proposer signs a block with a timestamp well
//     before now - ShardMaxTimestampDrift.
//   - Boundary accepted: a timestamp at exactly now + ShardMaxTimestampDrift
//     is still within the tolerance window and must be accepted.

import (
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// r7_01_newActiveChain builds a fresh active shard chain with the given
// validators' Dilithium3 public keys and a mock election verifier registered.
// Mirrors the r5_03_newActiveChain helper.
func r7_01_newActiveChain(t *testing.T, shardID uint64, validators []types.Address) *ShardChain {
	t.Helper()
	chain := NewShardChain(shardID, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)
	return chain
}

// TestSHRD_R7_01_ValidTimestampAccepted verifies that a block with a
// timestamp close to now (set by ProposeBlock via time.Now().Unix()) is
// accepted by ReceiveBlock. This is the baseline regression check.
func TestSHRD_R7_01_ValidTimestampAccepted(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r7_01_newActiveChain(t, 1, validators)
	chain2 := r7_01_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0],
		[][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	if err := chain2.ReceiveBlock(block); err != nil {
		t.Fatalf("ReceiveBlock should accept a valid-timestamp block, got: %v", err)
	}
	if chain2.LatestHeight() != 1 {
		t.Fatalf("expected latest height 1, got %d", chain2.LatestHeight())
	}
}

// TestSHRD_R7_01_FutureTimestampRejected verifies that a block with a
// timestamp far in the future (now + ShardMaxTimestampDrift + 60s) is
// rejected with ErrShardTimestampOutOfRange. The proposer re-signs the
// header so the signature check passes; only the drift check should reject.
func TestSHRD_R7_01_FutureTimestampRejected(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r7_01_newActiveChain(t, 1, validators)
	chain2 := r7_01_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0],
		[][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Set timestamp well beyond the allowed future drift and re-sign.
	futureDelta := uint64(ShardMaxTimestampDrift + 60)
	block.Header.Timestamp = uint64(time.Now().Unix()) + futureDelta
	block.Header.Signature = signShardBlock(validators[0], block.Header)

	err = chain2.ReceiveBlock(block)
	if !errors.Is(err, ErrShardTimestampOutOfRange) {
		t.Fatalf("ReceiveBlock should reject far-future timestamp with ErrShardTimestampOutOfRange, got: %v", err)
	}
	if chain2.LatestHeight() != 0 {
		t.Fatalf("far-future-timestamp block must not be stored; latest height should remain 0, got %d", chain2.LatestHeight())
	}
}

// TestSHRD_R7_01_PastTimestampRejected verifies that a block with a
// timestamp far in the past (now - ShardMaxTimestampDrift - 60s) is
// rejected with ErrShardTimestampOutOfRange.
func TestSHRD_R7_01_PastTimestampRejected(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r7_01_newActiveChain(t, 1, validators)
	chain2 := r7_01_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0],
		[][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Set timestamp well beyond the allowed past drift and re-sign.
	now := uint64(time.Now().Unix())
	pastDelta := uint64(ShardMaxTimestampDrift + 60)
	if now > pastDelta {
		block.Header.Timestamp = now - pastDelta
	} else {
		block.Header.Timestamp = 0
	}
	block.Header.Signature = signShardBlock(validators[0], block.Header)

	err = chain2.ReceiveBlock(block)
	if !errors.Is(err, ErrShardTimestampOutOfRange) {
		t.Fatalf("ReceiveBlock should reject far-past timestamp with ErrShardTimestampOutOfRange, got: %v", err)
	}
	if chain2.LatestHeight() != 0 {
		t.Fatalf("far-past-timestamp block must not be stored; latest height should remain 0, got %d", chain2.LatestHeight())
	}
}

// TestSHRD_R7_01_BoundaryFutureTimestampAccepted verifies that a block with
// a timestamp exactly at now + ShardMaxTimestampDrift is accepted (the
// check is strictly greater-than, so the boundary value is allowed).
func TestSHRD_R7_01_BoundaryFutureTimestampAccepted(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r7_01_newActiveChain(t, 1, validators)
	chain2 := r7_01_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0],
		[][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Set timestamp to exactly now + ShardMaxTimestampDrift (boundary).
	// The drift check uses strict > comparison, so this should be accepted.
	block.Header.Timestamp = uint64(time.Now().Unix()) + uint64(ShardMaxTimestampDrift)
	block.Header.Signature = signShardBlock(validators[0], block.Header)

	if err := chain2.ReceiveBlock(block); err != nil {
		t.Fatalf("ReceiveBlock should accept boundary-future timestamp, got: %v", err)
	}
	if chain2.LatestHeight() != 1 {
		t.Fatalf("expected latest height 1, got %d", chain2.LatestHeight())
	}
}

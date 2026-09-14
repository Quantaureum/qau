// Quantaureum Node source, version 1.0.0.
package consensus

// SHRD-R5-03 (2026-07-16) regression tests.
//
// These tests verify that ReceiveBlock rejects blocks where the body
// (block.Txs / block.CrossMsgs) does not match the root commitments carried
// in the block header. Before the fix, ReceiveBlock trusted the header roots
// verbatim, allowing a malicious elected proposer to anchor a false state
// root on the main chain by delivering a body inconsistent with the signed
// header.
//
// Attack model covered:
//   - Body tampering: proposer signs a correct header, but delivers different
//     Txs/CrossMsgs. Signature stays valid (covers the header), but the
//     recomputed Merkle roots no longer match the header commitments.
//   - Header StateRoot forgery: proposer re-signs a header with a false
//     StateRoot while keeping TxRoot/CrossMsgRoot consistent with the body.
//     The placeholder stateRoot check catches this when no stateDB is set.
//   - Zero StateRoot: proposer delivers a header with a zero state root.

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// r5_03_newActiveChain builds a fresh active shard chain with the given
// validators' Dilithium3 public keys and a mock election verifier registered.
// The chain starts at height 0 (no blocks).
func r5_03_newActiveChain(t *testing.T, shardID uint64, validators []types.Address) *ShardChain {
	t.Helper()
	chain := NewShardChain(shardID, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)
	return chain
}

// TestSHRD_R5_03_ValidBlockAccepted verifies that a properly built block
// (body roots == header roots) still passes ReceiveBlock after the fix.
// This is the baseline regression check.
func TestSHRD_R5_03_ValidBlockAccepted(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r5_03_newActiveChain(t, 1, validators)
	chain2 := r5_03_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0],
		[][]byte{[]byte("tx1"), []byte("tx2")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	if err := chain2.ReceiveBlock(block); err != nil {
		t.Fatalf("ReceiveBlock should accept a valid block, got: %v", err)
	}
	if chain2.LatestHeight() != 1 {
		t.Fatalf("expected latest height 1, got %d", chain2.LatestHeight())
	}
}

// TestSHRD_R5_03_TxRootMismatch verifies that tampering with block.Txs
// (so the recomputed TxRoot != header.TxRoot) is rejected.
//
// The header (and thus the proposer's signature) is unchanged, so the
// signature check passes. The body-header commitment check must catch the
// inconsistency.
func TestSHRD_R5_03_TxRootMismatch(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r5_03_newActiveChain(t, 1, validators)
	chain2 := r5_03_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0],
		[][]byte{[]byte("original-tx")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Tamper with the body: replace Txs with different content. The header
	// (including header.TxRoot and the signature) is NOT updated, so the
	// recomputed TxRoot will not match header.TxRoot.
	block.Txs = [][]byte{[]byte("tampered-tx")}

	err = chain2.ReceiveBlock(block)
	if !errors.Is(err, ErrShardBodyRootMismatch) {
		t.Fatalf("ReceiveBlock should reject TxRoot mismatch with ErrShardBodyRootMismatch, got: %v", err)
	}
	if chain2.LatestHeight() != 0 {
		t.Fatalf("tampered block must not be stored; latest height should remain 0, got %d", chain2.LatestHeight())
	}
}

// TestSHRD_R5_03_CrossMsgRootMismatch verifies that tampering with
// block.CrossMsgs (so the recomputed CrossMsgRoot != header.CrossMsgRoot)
// is rejected.
func TestSHRD_R5_03_CrossMsgRootMismatch(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r5_03_newActiveChain(t, 1, validators)
	chain2 := r5_03_newActiveChain(t, 1, validators)

	originalMsgs := []*CrossShardMessage{
		{
			ID:          types.Hash{0x01},
			SourceShard: 1,
			DestShard:   2,
			Sender:      validators[0],
			Recipient:   validators[1],
			Payload:     []byte("original-payload"),
			Nonce:       1,
			Timestamp:   1000,
		},
	}

	block, err := proposeShardBlock(chain1, validators[0], [][]byte{[]byte("tx1")}, originalMsgs)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Tamper with the body: replace CrossMsgs with different content. The
	// header is NOT updated, so recomputed CrossMsgRoot != header.CrossMsgRoot.
	block.CrossMsgs = []*CrossShardMessage{
		{
			ID:          types.Hash{0x02}, // different ID
			SourceShard: 1,
			DestShard:   2,
			Sender:      validators[0],
			Recipient:   validators[1],
			Payload:     []byte("tampered-payload"),
			Nonce:       2,
			Timestamp:   2000,
		},
	}

	err = chain2.ReceiveBlock(block)
	if !errors.Is(err, ErrShardBodyRootMismatch) {
		t.Fatalf("ReceiveBlock should reject CrossMsgRoot mismatch with ErrShardBodyRootMismatch, got: %v", err)
	}
	if chain2.LatestHeight() != 0 {
		t.Fatalf("tampered block must not be stored; latest height should remain 0, got %d", chain2.LatestHeight())
	}
}

// TestSHRD_R5_03_StateRootPlaceholderMismatch verifies that when no stateDB
// is attached (placeholder path), a header with a forged StateRoot is
// rejected even if the proposer re-signs the header (so the signature is
// valid) and TxRoot/CrossMsgRoot are consistent with the body.
//
// Attack: malicious proposer signs a header claiming StateRoot = fakeRoot,
// but delivers a body whose (shardID, height, parentHash, txRoot,
// crossMsgRoot) hashes to a different placeholder. The receiver recomputes
// the placeholder from the verified body roots and detects the mismatch.
func TestSHRD_R5_03_StateRootPlaceholderMismatch(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r5_03_newActiveChain(t, 1, validators)
	chain2 := r5_03_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0],
		[][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Forge the StateRoot: set it to a non-zero bogus value and re-sign the
	// header so the signature check passes. TxRoot/CrossMsgRoot are unchanged
	// and still match the body.
	block.Header.StateRoot = types.Hash{0xab, 0xcd, 0xef}
	block.Header.Signature = signShardBlock(validators[0], block.Header)

	err = chain2.ReceiveBlock(block)
	if !errors.Is(err, ErrShardBodyRootMismatch) {
		t.Fatalf("ReceiveBlock should reject StateRoot placeholder mismatch with ErrShardBodyRootMismatch, got: %v", err)
	}
	if chain2.LatestHeight() != 0 {
		t.Fatalf("forged block must not be stored; latest height should remain 0, got %d", chain2.LatestHeight())
	}
}

// TestSHRD_R5_03_ZeroStateRootRejected verifies that a header with a zero
// StateRoot is rejected, even if the proposer re-signs the header.
func TestSHRD_R5_03_ZeroStateRootRejected(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r5_03_newActiveChain(t, 1, validators)
	chain2 := r5_03_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0],
		[][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	// Zero out the StateRoot and re-sign so the signature check passes.
	block.Header.StateRoot = types.Hash{}
	block.Header.Signature = signShardBlock(validators[0], block.Header)

	err = chain2.ReceiveBlock(block)
	if !errors.Is(err, ErrShardStateRootZero) {
		t.Fatalf("ReceiveBlock should reject zero StateRoot with ErrShardStateRootZero, got: %v", err)
	}
	if chain2.LatestHeight() != 0 {
		t.Fatalf("zero-state-root block must not be stored; latest height should remain 0, got %d", chain2.LatestHeight())
	}
}

// TestSHRD_R5_03_EmptyBodyValidBlock verifies that a block with no txs and
// no cross-msgs (empty body) is accepted, since computeTxRoot/computeCrossMsgRoot
// return the zero hash for empty inputs, and the placeholder stateRoot is
// derived from those zero roots consistently.
func TestSHRD_R5_03_EmptyBodyValidBlock(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain1 := r5_03_newActiveChain(t, 1, validators)
	chain2 := r5_03_newActiveChain(t, 1, validators)

	block, err := proposeShardBlock(chain1, validators[0], nil, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}

	if err := chain2.ReceiveBlock(block); err != nil {
		t.Fatalf("ReceiveBlock should accept a valid empty-body block, got: %v", err)
	}
	if chain2.LatestHeight() != 1 {
		t.Fatalf("expected latest height 1, got %d", chain2.LatestHeight())
	}
}

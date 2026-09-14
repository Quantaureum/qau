// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// isAllASCIIHex reports whether every byte is an ASCII hex char (0-9,a-f).
func isAllASCIIHex(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// TestStateRootE2E_NoDoubleHexEncoding reproduces the full path that triggers
// the production WARN: producer computes stateRoot via StateDB.Root(), puts it
// into a block header, serializes/deserializes the block (as over the network),
// then the syncer recomputes via CommitWithBlock and compares. Verifies neither
// side produces an ASCII-hex-double-encoded hash.
func TestStateRootE2E_NoDoubleHexEncoding(t *testing.T) {
	// Use two independent copies to mirror proposer (builds on a copy) and
	// validator (re-derives from its own committed state).
	sdb := state.NewStateDB()
	addr := types.BytesToAddress([]byte{1, 2, 3, 4})
	sdb.SetBalance(addr, big.NewInt(1_000_000))
	validatorDB := sdb.Copy()

	// Producer path: MUST commit dirty state before deriving the root, exactly
	// as the fixed block_producer does (CommitWithBlock), otherwise the root
	// excludes pending balance changes and disagrees with the validator path.
	producerRoot, err := sdb.CommitWithBlock(1)
	if err != nil {
		t.Fatalf("producer CommitWithBlock: %v", err)
	}
	t.Logf("producer CommitWithBlock = %x (len=%d)", producerRoot[:], len(producerRoot))
	if isAllASCIIHex(producerRoot[:]) {
		t.Errorf("producer root DOUBLE-ENCODED: %q", string(producerRoot[:]))
	}

	header := &encoding.BlockHeader{
		Version:      1,
		Height:       1,
		StateRoot:    producerRoot,
		ProposerAddr: addr,
		ChainID:      1668,
	}
	blk := &encoding.Block{Header: header, Transactions: nil}

	data, err := encoding.MarshalBlock(blk)
	if err != nil {
		t.Fatalf("MarshalBlock: %v", err)
	}
	blk2, err := encoding.UnmarshalBlock(data)
	if err != nil {
		t.Fatalf("UnmarshalBlock: %v", err)
	}
	transportedRoot := blk2.Header.StateRoot
	t.Logf("transported StateRoot = %x (len=%d)", transportedRoot[:], len(transportedRoot))
	if isAllASCIIHex(transportedRoot[:]) {
		t.Errorf("transported root DOUBLE-ENCODED: %q", string(transportedRoot[:]))
	}
	if producerRoot != transportedRoot {
		t.Errorf("root changed across serialize/deserialize: %x -> %x", producerRoot[:], transportedRoot[:])
	}

	// Validator path: CommitWithBlock then compare.
	validatorRoot, err := validatorDB.CommitWithBlock(1)
	if err != nil {
		t.Fatalf("CommitWithBlock: %v", err)
	}
	t.Logf("validator CommitWithBlock = %x (len=%d)", validatorRoot[:], len(validatorRoot))
	if isAllASCIIHex(validatorRoot[:]) {
		t.Errorf("validator root DOUBLE-ENCODED: %q", string(validatorRoot[:]))
	}

	// The core invariant: after the fix, proposer and validator derive the
	// SAME state root. Before the fix (proposer used uncommitted Root()),
	// these differed and produced the production WARN on every block.
	if producerRoot != validatorRoot {
		t.Errorf("STATE-ROOT MISMATCH: producer=%x validator=%x", producerRoot[:], validatorRoot[:])
	}

	// Decode for human comparison.
	t.Logf("producerRoot as hex string = %s", hex.EncodeToString(producerRoot[:]))
	t.Logf("validatorRoot as hex string = %s", hex.EncodeToString(validatorRoot[:]))
}

// M4-F5 hardening regression (audit finding: producer publishes stale root
// after a failed state commit). buildBlock used to treat CommitWithBlock
// errors as non-fatal on the produce path: the final commit's failure fell
// back to stateDB.Root() — the root of a partially updated tree — and stamped
// it into the block header that was then signed and published. Both commit
// sites now fail closed: the build is aborted (nil block → the slot is
// abandoned and the buffered copy discarded) instead of signing a block whose
// header contradicts the local state commitment.
package node

import (
	"errors"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// m4F5FailBatch is a db.Batch whose every mutating op fails.
type m4F5FailBatch struct{}

func (b *m4F5FailBatch) Put(key, value []byte) error {
	return errors.New("simulated state commit write failure")
}

func (b *m4F5FailBatch) Delete(key []byte) error {
	return errors.New("simulated state commit delete failure")
}

func (b *m4F5FailBatch) Write() error {
	return errors.New("simulated state batch write failure")
}

func (b *m4F5FailBatch) Reset()         {}
func (b *m4F5FailBatch) ValueSize() int { return 0 }
func (b *m4F5FailBatch) Flush() error {
	return errors.New("simulated state batch flush failure")
}

// m4F5TripwireDB delegates reads/iterators to a real MemDB and hands out
// healthy batches until tripped; from then on every batch fails. This
// simulates a durable-store I/O failure after a healthy baseline commit,
// using only the public StateDB API.
type m4F5TripwireDB struct {
	db.Database
	tripped atomic.Bool
}

func (d *m4F5TripwireDB) Trip() { d.tripped.Store(true) }

func (d *m4F5TripwireDB) NewBatch() db.Batch {
	if d.tripped.Load() {
		return &m4F5FailBatch{}
	}
	return d.Database.NewBatch()
}

// m4F5BrokenBuildState returns a build-copy StateDB whose next commit fails
// deterministically after a healthy baseline commit at height 10.
func m4F5BrokenBuildState(t *testing.T) *state.StateDB {
	t.Helper()
	wrapped := &m4F5TripwireDB{Database: db.NewMemDB()}
	sdb := state.NewStateDB(wrapped)
	if _, err := sdb.CommitWithBlock(10); err != nil {
		t.Fatalf("baseline commit failed: %v", err)
	}
	wrapped.Trip()
	sdb.SetBalance(types.Address{0x77}, big.NewInt(2000))
	if _, err := sdb.CommitWithBlock(11); err == nil {
		t.Fatal("fixture broken: CommitWithBlock must fail after the tripwire is set")
	}
	return sdb
}

// TestM4F5_ProducerAbortsBlockOnFinalCommitFailure pins the audit's exact
// scenario: the FINAL CommitWithBlock (the one whose root goes into the
// header) fails → buildBlock must return nil. The pre-fix code stamped
// stateDB.Root() (partially updated tree) into the header and returned a
// signable block.
func TestM4F5_ProducerAbortsBlockOnFinalCommitFailure(t *testing.T) {
	sdb := m4F5BrokenBuildState(t)

	bp := &BlockProducer{
		node: &Node{
			config:  &Config{Name: "m4f5-final-commit-test", MaxGasLimit: 30_000_000},
			chainID: 1337,
		},
		validatorAddr: types.Address{0x77},
	}
	buildState := &blockBuildState{stateDB: sdb}

	blk := bp.buildBlock(5, 10, types.Hash{}, nil, buildState)
	if blk != nil {
		t.Fatalf("M4-F5 NOT FIXED: buildBlock returned a block despite the failed final state commit — "+
			"header StateRoot=%x was stamped from a partially updated tree and the block would be signed and published",
			blk.Header.StateRoot[:8])
	}
}

// TestM4F5_ProducerAbortsBlockOnTxCommitFailure pins the intermediate commit
// site: with transactions in the block, the post-execution CommitWithBlock
// failure must abort the build (pre-fix it was only debug-logged and the
// build continued on top of uncommitted transaction state).
func TestM4F5_ProducerAbortsBlockOnTxCommitFailure(t *testing.T) {
	sdb := m4F5BrokenBuildState(t)

	to := types.Address{0xbb}
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeTransfer,
		From:     types.Address{0x77},
		To:       &to,
		Value:    big.NewInt(1),
		Nonce:    0,
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1337,
	}

	bp := &BlockProducer{
		node: &Node{
			config:  &Config{Name: "m4f5-tx-commit-test", MaxGasLimit: 30_000_000},
			chainID: 1337,
		},
		validatorAddr: types.Address{0x77},
	}
	buildState := &blockBuildState{stateDB: sdb}

	blk := bp.buildBlock(5, 10, types.Hash{}, []*encoding.Transaction{tx}, buildState)
	if blk != nil {
		t.Fatalf("M4-F5 NOT FIXED: buildBlock returned a block despite the failed transaction-state commit — "+
			"header StateRoot=%x was stamped without the block's transaction state durably committed",
			blk.Header.StateRoot[:8])
	}
}

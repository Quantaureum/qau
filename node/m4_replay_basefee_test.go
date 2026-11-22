// Quantaureum Node source, version 1.0.0.
package node

// M4 follow-up regression: the boot-time state replay
// (Node.replayBlocksToRestoreState) must derive EXACTLY the same state as the
// consensus paths (producer buildBlock / syncer applyBlockInternal) for the
// same block sequence.
//
// The replay's BlockContext omitted the header's BaseFee, so tx-carrying
// blocks were priced with effectiveGasPrice = tx.GasPrice (no EIP-1559 burn,
// the FULL fee credited to the coinbase) while the producer/validator paths
// used min(baseFee+tip, maxFee) with the base-fee portion burned. The
// coinbase balance therefore diverges deterministically on every
// tx-carrying block, and the restored state root can never match the
// canonical header root — the M4 "rebuild keeps mismatching" shape on the
// replay path.
//
// This test builds a short chain through the REAL producer path
// (BlockProducer.buildBlock: empty / tx-carrying / empty), validates each
// block through the REAL validator path (Syncer.applyBlockInternal, strict),
// then restores the state through the REAL boot replay and asserts the
// restored root matches the canonical tip header. It also pins the R10-01
// fail-closed behavior: a tampered tip header must be rejected.

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

const (
	m4rChainID   = 1337
	m4rGasLimit  = 30_000_000
	m4rGasPrice  = 2_000_000_000 // 2 gwei
	m4rTxGasUsed = 21_000
)

var (
	m4rSender   = types.Address{0xAA}
	m4rReceiver = types.Address{0xBB}
	m4rProposer = types.Address{0xCC}
)

// m4r_seed balances identically on every side of the comparison.
func m4r_seed(t *testing.T, sdb *state.StateDB) {
	t.Helper()
	sdb.SetBalance(m4rSender, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	sdb.SetBalance(m4rReceiver, big.NewInt(0))
	sdb.SetBalance(m4rProposer, big.NewInt(0))
}

func m4r_newSyncer(t *testing.T, bs *block.BlockStore) *Syncer {
	t.Helper()
	sdb := state.NewStateDB()
	m4r_seed(t, sdb)
	bv := core.NewBlockValidator(m4rChainID, m4rGasLimit)
	bv.SetDevMode(true)
	return NewSyncer(nil, bs, sdb, bv, m4rChainID)
}

// m4r_produce builds the 3-block chain through the REAL producer path and
// stores it. Block 2 carries one transfer so the EIP-1559 fee handling is
// exercised. With tamperTip the tip header's state root is corrupted before
// it is stored (for the fail-closed case).
func m4r_produce(t *testing.T, bs *block.BlockStore, tamperTip bool) []*encoding.Block {
	t.Helper()
	prodState := state.NewStateDB(db.NewMemDB())
	m4r_seed(t, prodState)

	bp := &BlockProducer{
		node: &Node{
			config:       &Config{Name: "m4r-producer", MaxGasLimit: m4rGasLimit},
			chainID:      m4rChainID,
			receiptCache: make(map[types.Hash]uint64),
		},
		validatorAddr: m4rProposer,
	}

	to := m4rReceiver
	// A dynamic-fee (EIP-1559) transaction is required for the regression to
	// bite: legacy transactions pay tx.GasPrice on every path, so the missing
	// BaseFee on the replay path only shows up here — with BaseFee the
	// base-fee portion is burned and the coinbase receives the tip only;
	// without it the executor falls back to effectiveGasPrice = tx.GasPrice
	// (0 for a dynamic tx) and nobody pays.
	tx := &encoding.Transaction{
		Type:                 encoding.TxTypeDynamicFee,
		From:                 m4rSender,
		To:                   &to,
		Value:                big.NewInt(1_000),
		Nonce:                0,
		GasLimit:             m4rTxGasUsed,
		MaxFeePerGas:         big.NewInt(m4rGasPrice),
		MaxPriorityFeePerGas: big.NewInt(m4rGasPrice / 2),
		ChainID:              m4rChainID,
	}

	var blocks []*encoding.Block
	parentHash := types.Hash{}
	for i := 1; i <= 3; i++ {
		var txs []*encoding.Transaction
		if i == 2 {
			txs = []*encoding.Transaction{tx}
		}
		blk := bp.buildBlock(uint64(i), uint64(i-1), parentHash, txs, &blockBuildState{stateDB: prodState})
		if blk == nil {
			t.Fatalf("buildBlock returned nil for block %d", i)
		}
		if blk.Header.BaseFee == nil || blk.Header.BaseFee.Sign() == 0 {
			t.Fatalf("fixture broken: block %d carries no base fee", i)
		}
		if tamperTip && i == 3 {
			blk.Header.StateRoot = types.Hash{0x99}
		}
		if err := bs.PutBlockWithIndex(blk); err != nil {
			t.Fatalf("store block %d: %v", i, err)
		}
		blocks = append(blocks, blk)
		parentHash = block.ComputeBlockHash(blk.Header)
	}
	return blocks
}

func m4r_newReplayNode(t *testing.T, bs *block.BlockStore) *Node {
	replayState := state.NewStateDB(db.NewMemDB())
	m4r_seed(t, replayState)
	return &Node{
		config:       &Config{Name: "m4r-replay", MaxGasLimit: m4rGasLimit},
		chainID:      m4rChainID,
		blockStore:   bs,
		stateDB:      replayState,
		receiptCache: make(map[types.Hash]uint64),
	}
}

// TestM4Replay_BootReplayMatchesConsensusDerivation is the core regression:
// the boot replay's restored state must equal the state the consensus paths
// derive, block for block, including the EIP-1559 fee handling of
// tx-carrying blocks.
func TestM4Replay_BootReplayMatchesConsensusDerivation(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	blocks := m4r_produce(t, bs, false)

	// Validator path: every block must verify strictly against its header
	// (this is the derivation the replay has to agree with).
	s := m4r_newSyncer(t, bs)
	for _, blk := range blocks {
		if err := s.applyBlockInternal(blk, false); err != nil {
			t.Fatalf("validator path rejected block %d: %v", blk.Header.Height, err)
		}
		if got := s.stateDB.Root(); got != blk.Header.StateRoot {
			t.Fatalf("validator path root mismatch at block %d: computed=%x header=%x",
				blk.Header.Height, got[:8], blk.Header.StateRoot[:8])
		}
	}

	// Boot replay path: fresh state DB, same block store, real replay code.
	replayNode := m4r_newReplayNode(t, bs)
	if err := replayNode.replayBlocksToRestoreState(); err != nil {
		t.Fatalf("boot replay failed: %v", err)
	}

	tip := blocks[len(blocks)-1]
	if got := replayNode.stateDB.Root(); got != tip.Header.StateRoot {
		t.Fatalf("M4 replay divergence: restored root %x != canonical tip header %x — "+
			"the boot replay derivation still disagrees with the consensus paths",
			got[:8], tip.Header.StateRoot[:8])
	}

	// The fee handling must be observable, not vacuous: the proposer's balance
	// must reflect the burned base fee (priority tip only), which is exactly
	// the quantity the missing-BaseFee bug got wrong. effectiveGasPrice =
	// min(maxFee, baseFee+priorityTip); the coinbase keeps only the part above
	// the burned base fee.
	txBlk := blocks[1]
	proposerBal := replayNode.stateDB.GetBalance(m4rProposer)
	wantTip := new(big.Int).Sub(big.NewInt(m4rGasPrice), txBlk.Header.BaseFee)
	wantTip.Mul(wantTip, big.NewInt(m4rTxGasUsed))
	if proposerBal.Cmp(wantTip) != 0 {
		t.Fatalf("proposer balance = %s, want tip-only %s (EIP-1559 burn not applied on the replay path)",
			proposerBal, wantTip)
	}
}

// TestM4Replay_StrictFailClosedOnTamperedTip pins the R10-01 fail-closed
// contract: if the restored root does not match the tip header, the replay
// must ERROR (never silently accept a wrong state).
func TestM4Replay_StrictFailClosedOnTamperedTip(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	m4r_produce(t, bs, true)

	replayNode := m4r_newReplayNode(t, bs)
	if err := replayNode.replayBlocksToRestoreState(); err == nil {
		t.Fatal("boot replay accepted a restored state whose root does not match the tampered tip header — fail-closed broken")
	}
}

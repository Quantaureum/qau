// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// R5-03 (2026-10-21 fifth-round audit): boot-time state replay Executes and
// Commits on the live StateDB, so it must hold that instance's execution frame
// for its whole duration (R4-07 contract C1: one execution frame per live
// StateDB). Before this fix it did not; today the gap is only latent because
// replay runs from initState before the RPC servers exist, but the moment
// someone exposes it as a runtime maintenance action it becomes a live R4-07
// reproduction (a concurrent eth_call reverting mid-replay drops journal
// entries of transactions already applied).
//
// These tests pin both halves of the fix: the frame is acquired while replay
// runs, and it is released on every return path — a leaked frame would wedge
// every later speculative call.

// newReplayTestNode builds a chain of `blocks` blocks holding `txsPerBlock`
// signed transfers each, and a StateDB that has not replayed yet.
//
// The tip header carries the state root the replay is expected to produce.
// R10-01 made boot replay refuse a state it cannot verify against the chain
// head, and no real node can be in that position: every import path rejects a
// zero StateRoot (syncer.go, core/block_validator.go, adapters.go), so a
// fixture whose head has no root describes a chain that cannot exist. The root
// is learned by replaying the identical transaction set once against a
// throwaway state, the same two-pass shape
// TestR10_01_MatchingTipRootIsAccepted uses, so the value is derived rather
// than hard-coded.
func newReplayTestNode(t *testing.T, blocks, txsPerBlock int) (*Node, []*encoding.Transaction) {
	t.Helper()

	// A real keypair, so every replayed transfer passes signature verification
	// and mutates state. Unsigned transactions are rejected before they touch
	// the journal, which would make the frame assertions below vacuous.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	sender := kp.Public.Address()
	receiver := types.Address{0x22}

	// newChain rebuilds the fixture from scratch, so each pass replays over its
	// own blocks and transaction values rather than shared pointers.
	newChain := func() ([]*encoding.Block, []*encoding.Transaction) {
		var (
			allTxs []*encoding.Transaction
			chain  = make([]*encoding.Block, 0, blocks)
			nonce  uint64
		)
		for height := 1; height <= blocks; height++ {
			blk := &encoding.Block{
				Header: &encoding.BlockHeader{
					Height:       uint64(height),
					Timestamp:    int64(height) * 2,
					ProposerAddr: types.Address{0xaa},
				},
				Transactions: make([]*encoding.Transaction, 0, txsPerBlock),
			}
			for i := 0; i < txsPerBlock; i++ {
				tx := &encoding.Transaction{
					Version:  1,
					Type:     encoding.TxTypeTransfer,
					From:     sender,
					To:       &receiver,
					Nonce:    nonce,
					Value:    big.NewInt(1),
					GasLimit: 21000,
					GasPrice: big.NewInt(1),
					ChainID:  1668,
				}
				hash, err := tx.SigningHash()
				if err != nil {
					t.Fatalf("SigningHash: %v", err)
				}
				sig, err := crypto.Sign(kp.Private, hash[:])
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				tx.Signature = sig
				tx.PublicKey = kp.Public.Bytes()
				nonce++
				blk.Transactions = append(blk.Transactions, tx)
				allTxs = append(allTxs, tx)
			}
			chain = append(chain, blk)
		}
		return chain, allTxs
	}

	// newNode starts from the same funded state on every pass; the only thing
	// that may differ between them is the tip header root.
	newNode := func() *Node {
		sdb := state.NewStateDB(db.NewMemDB())
		sdb.SetBalance(sender, new(big.Int).Mul(big.NewInt(1e15), big.NewInt(100000)))
		return &Node{
			config:       &Config{MaxGasLimit: 30_000_000},
			blockStore:   block.NewBlockStore(db.NewMemDB()),
			stateDB:      sdb,
			receiptCache: make(map[types.Hash]uint64),
		}
	}

	storeChain := func(n *Node, chain []*encoding.Block) {
		t.Helper()
		for _, blk := range chain {
			if err := n.blockStore.PutBlock(blk); err != nil {
				t.Fatalf("PutBlock(%d): %v", blk.Header.Height, err)
			}
		}
	}

	tipRoot := types.Hash{}
	if blocks > 0 {
		probe := newNode()
		probeChain, _ := newChain()
		storeChain(probe, probeChain)
		_ = probe.replayBlocksToRestoreState() // rejected on purpose: the head has no root yet
		if tipRoot = probe.stateDB.Root(); tipRoot == (types.Hash{}) {
			t.Fatal("precondition: the replayed state root must be non-zero")
		}
	}

	chain, allTxs := newChain()
	if len(chain) > 0 {
		chain[len(chain)-1].Header.StateRoot = tipRoot
	}
	n := newNode()
	storeChain(n, chain)
	return n, allTxs
}

// TestR5_03_ReplayHoldsExecutionFrame proves the replay path excludes other
// frames while it runs. The busy observation is a conditional assertion: if the
// scheduler happened to finish the replay before any probe, nothing is claimed
// about that run (the release assertions below still are).
func TestR5_03_ReplayHoldsExecutionFrame(t *testing.T) {
	blocks, txsPerBlock := 200, 3
	if testing.Short() {
		blocks, txsPerBlock = 60, 2
	}
	n, _ := newReplayTestNode(t, blocks, txsPerBlock)

	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		done <- result{err: n.replayBlocksToRestoreState()}
	}()

	sawBusy := false
	probes := 0
	replayDone := false
	for !replayDone {
		select {
		case res := <-done:
			replayDone = true
			if res.err != nil {
				t.Fatalf("replayBlocksToRestoreState: %v", res.err)
			}
		default:
			if release, ok := n.stateDB.TryBeginExecution(); ok {
				// Free at this instant: hand it straight back.
				release()
				probes++
				time.Sleep(100 * time.Microsecond)
				continue
			}
			sawBusy = true
			probes++
			time.Sleep(100 * time.Microsecond)
		}
	}

	t.Logf("R5-03: probed the execution frame %d times during replay; observed it busy = %v", probes, sawBusy)
	if !sawBusy && probes > 3 {
		t.Fatal("replay never held the execution frame although it was running while probed more than 3 times")
	}

	// Release half: after replay returns the frame must be free again, and the
	// snapshot journal must be balanced (R4-07 C5 / R4-08).
	release, ok := n.stateDB.TryBeginExecution()
	if !ok {
		t.Fatal("replay leaked its execution frame: the state is locked after replayBlocksToRestoreState returned")
	}
	release()
	if depth := n.stateDB.SnapshotDepth(); depth != 0 {
		t.Fatalf("snapshot journal depth after replay = %d, want 0", depth)
	}
	// Sanity: the replay really applied the transfers, so the frame was held
	// around genuine state mutation rather than an all-rejected loop.
	if bal := n.stateDB.GetBalance(types.Address{0x22}); bal.Sign() <= 0 {
		t.Fatalf("replay did not credit the receiver (balance %s) — fixtures are not executing", bal)
	}
}

// TestR5_03_ReplayReleasesFrameOnEarlyReturn covers the two no-op returns: the
// frame is taken only after those checks, so an early return must not lock the
// state either.
func TestR5_03_ReplayReleasesFrameOnEarlyReturn(t *testing.T) {
	n, _ := newReplayTestNode(t, 3, 1)

	// Nothing stored yet: a nil block store makes replay return early.
	bs := n.blockStore
	n.blockStore = nil
	if err := n.replayBlocksToRestoreState(); err != nil {
		t.Fatalf("replay with no block store: %v", err)
	}
	n.blockStore = bs

	// Fresh, empty chain: latest height 0 → early return.
	spare, _ := newReplayTestNode(t, 0, 0)
	if err := spare.replayBlocksToRestoreState(); err != nil {
		t.Fatalf("replay with an empty chain: %v", err)
	}
	release, ok := spare.stateDB.TryBeginExecution()
	if !ok {
		t.Fatal("state is locked after replay returned with an empty chain")
	}
	release()

	// The populated store path must also leave the frame free once it returns.
	if err := n.replayBlocksToRestoreState(); err != nil {
		t.Fatalf("replay over a short chain: %v", err)
	}
	release, ok = n.stateDB.TryBeginExecution()
	if !ok {
		t.Fatal("state is locked after replay returned")
	}
	release()
}

// Quantaureum Node source, version 1.0.0.
package node

// M4 decisive experiment: replay the REAL mainnet chain from genesis through
// the production syncer derivation (Syncer.applyBlockInternal — the same path
// rebuildState uses) and compare the derived root against EVERY canonical
// header. This proves (or refutes) that the current code reproduces the
// canonical chain, which decides whether a from-genesis resync heals a node
// whose persisted state is poisoned.
//
// Skipped unless the exported chain data exists (local diagnostic only; CI
// never has the file). Data layout is produced by
// .local-only/scripts/m4export (gob-encoded []struct{Height,Hash,Block}).

import (
	"encoding/gob"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
)

// m4frDataDir is provided via the environment so no machine-specific path
// lands in the repository. Set M4_FULLREPLAY_DIR to the directory holding the
// exported chain (m4full.gob + genesis.json) to enable this diagnostic.
func m4frDataDir() string {
	return os.Getenv("M4_FULLREPLAY_DIR")
}

type m4frRec struct {
	Height uint64
	Hash   string
	Block  *encoding.Block
}

func TestM4MainnetFullReplay_FromGenesis(t *testing.T) {
	dataPath := filepath.Join(m4frDataDir(), "m4full.gob")
	if _, err := os.Stat(dataPath); err != nil {
		t.Skipf("mainnet full-chain export not available: %v", err)
	}
	genPath := filepath.Join(m4frDataDir(), "genesis.json")
	genRaw, err := os.ReadFile(genPath)
	if err != nil {
		t.Skipf("mainnet genesis not available: %v", err)
	}

	f, err := os.Open(dataPath)
	if err != nil {
		t.Skipf("cannot open chain export: %v", err)
	}
	var recs []m4frRec
	if err := gob.NewDecoder(f).Decode(&recs); err != nil {
		t.Fatalf("decode chain export: %v", err)
	}
	f.Close()
	if len(recs) == 0 {
		t.Skip("chain export is empty")
	}
	t.Logf("loaded %d mainnet blocks (heights %d..%d)", len(recs), recs[0].Height, recs[len(recs)-1].Height)

	var gen Genesis
	if err := json.Unmarshal(genRaw, &gen); err != nil {
		t.Fatalf("parse genesis: %v", err)
	}

	bs := block.NewBlockStore(db.NewMemDB())
	sdb := state.NewStateDB()

	// Build the genesis state exactly like Node.initState: allocations,
	// genesis stake deduction, nonces, codes, storage. The state stays dirty
	// here (as it does at boot); the first applied block's commit flushes it.
	allocs, err := gen.GetAllocations()
	if err != nil {
		t.Fatalf("genesis allocations: %v", err)
	}
	for addr, bal := range allocs {
		sdb.SetBalance(addr, bal)
	}
	for _, v := range gen.Validators {
		addr, err := parseAddressString(v.Address)
		if err != nil {
			continue
		}
		stake, ok := new(big.Int).SetString(v.Stake, 10)
		if !ok {
			continue
		}
		if cur := sdb.GetBalance(addr); cur.Cmp(stake) >= 0 {
			sdb.SetBalance(addr, new(big.Int).Sub(cur, stake))
		}
	}
	nonces, err := gen.GetAccountNonces()
	if err != nil {
		t.Fatalf("genesis nonces: %v", err)
	}
	for addr, n := range nonces {
		sdb.SetNonce(addr, n)
	}
	codes, err := gen.GetAccountCodes()
	if err != nil {
		t.Fatalf("genesis codes: %v", err)
	}
	for addr, code := range codes {
		sdb.SetCode(addr, code)
	}
	storage, err := gen.GetAccountStorage()
	if err != nil {
		t.Fatalf("genesis storage: %v", err)
	}
	for addr, kv := range storage {
		for k, v := range kv {
			sdb.SetState(addr, k, v)
		}
	}

	// QPOS from the genesis validator set — same construction as the R120
	// replay path and the node's initValidatorSet.
	var vals []*consensus.Validator
	for _, v := range gen.Validators {
		addr, err := parseAddressString(v.Address)
		if err != nil {
			continue
		}
		stake, ok := new(big.Int).SetString(v.Stake, 10)
		if !ok {
			stake = big.NewInt(1000000)
		}
		vals = append(vals, &consensus.Validator{Address: addr, Stake: stake, Active: true})
	}
	vs, err := consensus.NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("validator set: %v", err)
	}
	q, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("qpos: %v", err)
	}

	bv := core.NewBlockValidator(gen.ChainID, gen.GasLimit)
	bv.SetDevMode(true)
	s := NewSyncer(nil, bs, sdb, bv, gen.ChainID)
	s.SetQPOS(q)

	for i, r := range recs {
		blk := r.Block
		if blk == nil || blk.Header == nil {
			t.Fatalf("export entry %d (height %d) has no block", i, r.Height)
		}
		if blk.Header.Height != r.Height {
			t.Fatalf("export height mismatch: entry says %d, header says %d", r.Height, blk.Header.Height)
		}
		if err := bs.PutBlockWithIndex(blk); err != nil {
			t.Fatalf("store block %d: %v", r.Height, err)
		}
		if err := s.applyBlockInternal(blk, true); err != nil {
			t.Fatalf("apply failed at height %d: %v", r.Height, err)
		}
		if got := s.stateDB.Root(); got != blk.Header.StateRoot {
			t.Fatalf("M4 FULL-REPLAY DIVERGENCE at height %d (slot=%d epoch=%d txs=%d): "+
				"computed=%x header=%x — the first canonical root the current derivation cannot reproduce",
				r.Height, blk.Header.Slot, blk.Header.Epoch, len(blk.Transactions), got[:8], blk.Header.StateRoot[:8])
		}
		if (i+1)%20000 == 0 {
			t.Logf("replayed %d/%d blocks, root verified to height %d", i+1, len(recs), r.Height)
		}
	}
	t.Logf("PASS: the current derivation reproduces all %d canonical state roots from genesis", len(recs))
}

// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// Persistence defines the L2 state persistence interface.
//
// W-P1-3 FIX (2026-07-13): Without persistence, the rollup engine loses ALL
// L2 state (account balances, batch history, fraud proofs) on node restart.
// This interface abstracts the storage backend so the rollup package remains
// decoupled from the specific database implementation (bbolt in production,
// MemDB in tests).
//
// Storage layout (key prefixes):
//
//	"s:latest"           → latest state snapshot (all account states + stateRoots)
//	"b:<batchIndex>"     → Batch JSON (all batch fields including transactions)
//	"b:meta:nextIndex"   → next batch index counter
//	"b:meta:lastRoot"    → last state root (for BuildBatch's PrevStateRoot)
//	"f:<batchIndex>"     → FraudProof JSON
//
// The snapshot is a full deep-copy of all account states. This is simple and
// correct; a future optimization could use incremental diffs (Merkle patricia
// trie), but that is out of scope for W-P1-3.
type Persistence interface {
	// SaveStateSnapshot persists the full L2 account state + state roots map.
	// Called after each successful ProcessBatch.
	SaveStateSnapshot(states map[types.Address]*RollupAccount, stateRoots map[uint64]types.Hash) error

	// LoadStateSnapshot restores the latest L2 account state + state roots.
	// Called once on engine startup.
	LoadStateSnapshot() (states map[types.Address]*RollupAccount, stateRoots map[uint64]types.Hash, err error)

	// SaveBatch persists a single batch (including its transactions).
	// Called after SubmitBatch / FinalizeBatch / ChallengeBatch (status update).
	SaveBatch(batch *Batch) error

	// LoadAllBatches restores all persisted batches, ordered by index.
	// Called once on engine startup.
	LoadAllBatches() ([]*Batch, error)

	// SaveBatchMeta persists the next batch index and last state root.
	SaveBatchMeta(nextIndex uint64, lastStateRoot types.Hash) error

	// LoadBatchMeta restores the next batch index and last state root.
	LoadBatchMeta() (nextIndex uint64, lastStateRoot types.Hash, err error)

	// SaveFraudProof persists a single fraud proof.
	SaveFraudProof(proof *FraudProof) error

	// LoadAllFraudProofs restores all persisted fraud proofs.
	LoadAllFraudProofs() ([]*FraudProof, error)

	// W-P1-4 (2026-07-13): L1 anchor persistence.
	// SaveAnchors persists all anchor records (called after each batch anchor).
	SaveAnchors(anchors map[types.Hash]*AnchorRecord) error
	// LoadAnchors restores all anchor records (called on startup).
	LoadAnchors() (map[types.Hash]*AnchorRecord, error)

	// Close releases the underlying database resources.
	Close() error
}

// bboltPersistence implements Persistence using qaudb's Database interface.
// W-P1-3 FIX (2026-07-13)
type bboltPersistence struct {
	db db.Database
}

// NewPersistence wraps a qaudb.Database as a rollup Persistence layer.
// Returns nil if database is nil (in-memory mode, no persistence).
func NewPersistence(database db.Database) Persistence {
	if database == nil {
		return nil
	}
	return &bboltPersistence{db: database}
}

// --- State snapshot ---

// stateSnapshot is the JSON-friendly form used for on-disk persistence.
//
// W-P2-4 FIX (2026-07-14): encoding/json cannot use [N]byte array types
// (types.Address [20]byte, types.Hash [32]byte) as map keys — it rejects
// them with "json: unsupported type: map[types.Address]*rollup.RollupAccount".
// The previous stateSnapshot used byte-array-keyed maps, so SaveStateSnapshot
// silently failed on every batch and the snapshot on disk stayed empty.
// On restart, LoadStateSnapshot returned (nil, nil, nil) → all account
// balances, contract code, and storage were lost, and the next ProcessBatch
// failed with "invalid state transition" because prevStateRoot no longer
// matched computeStateRoot().
//
// The fix serializes byte-array keys as lowercase hex strings. The on-disk
// representation is therefore: Accounts keyed by hex(addr), and each
// account's Storage keyed by hex(slotHash). Values keep their native types
// (types.Hash values marshal fine as base64 []byte).
type stateSnapshot struct {
	Accounts   map[string]*jsonRollupAccount `json:"accounts"`
	StateRoots map[uint64]types.Hash         `json:"stateRoots"`
}

// jsonRollupAccount mirrors RollupAccount but uses hex-string keys for the
// Storage map (types.Hash keys are not JSON-marshalable).
type jsonRollupAccount struct {
	Nonce    uint64                `json:"nonce"`
	Balance  *big.Int              `json:"balance"`
	CodeHash types.Hash            `json:"codeHash"`
	Storage  map[string]types.Hash `json:"storage"`
	Code     []byte                `json:"code"`
}

func (p *bboltPersistence) SaveStateSnapshot(states map[types.Address]*RollupAccount, stateRoots map[uint64]types.Hash) error {
	snap := stateSnapshot{
		Accounts:   make(map[string]*jsonRollupAccount, len(states)),
		StateRoots: make(map[uint64]types.Hash, len(stateRoots)),
	}
	for addr, acc := range states {
		if acc == nil {
			continue
		}
		jAcc := &jsonRollupAccount{
			Nonce:    acc.Nonce,
			Balance:  new(big.Int).Set(acc.Balance),
			CodeHash: acc.CodeHash,
			Storage:  make(map[string]types.Hash, len(acc.Storage)),
		}
		if acc.Code != nil {
			jAcc.Code = append([]byte(nil), acc.Code...)
		}
		for k, v := range acc.Storage {
			jAcc.Storage[hex.EncodeToString(k[:])] = v
		}
		snap.Accounts[hex.EncodeToString(addr[:])] = jAcc
	}
	for k, v := range stateRoots {
		snap.StateRoots[k] = v
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal state snapshot: %w", err)
	}
	if err := p.db.Put([]byte("s:latest"), data); err != nil {
		return fmt.Errorf("persist state snapshot: %w", err)
	}
	return nil
}

func (p *bboltPersistence) LoadStateSnapshot() (map[types.Address]*RollupAccount, map[uint64]types.Hash, error) {
	data, err := p.db.Get([]byte("s:latest"))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, nil, nil // no snapshot — fresh start
		}
		return nil, nil, fmt.Errorf("load state snapshot: %w", err)
	}
	var snap stateSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, nil, fmt.Errorf("unmarshal state snapshot: %w", err)
	}
	states := make(map[types.Address]*RollupAccount, len(snap.Accounts))
	for addrHex, jAcc := range snap.Accounts {
		if jAcc == nil {
			continue
		}
		addrBytes, derr := hex.DecodeString(addrHex)
		if derr != nil {
			return nil, nil, fmt.Errorf("decode address key %q: %w", addrHex, derr)
		}
		if len(addrBytes) != types.AddressLength {
			return nil, nil, fmt.Errorf("address key %q has wrong length %d (want %d)", addrHex, len(addrBytes), types.AddressLength)
		}
		var addr types.Address
		copy(addr[:], addrBytes)
		acc := &RollupAccount{
			Nonce:    jAcc.Nonce,
			Balance:  new(big.Int).Set(jAcc.Balance),
			CodeHash: jAcc.CodeHash,
			Storage:  make(map[types.Hash]types.Hash, len(jAcc.Storage)),
		}
		if jAcc.Code != nil {
			acc.Code = append([]byte(nil), jAcc.Code...)
		}
		for slotHex, val := range jAcc.Storage {
			slotBytes, derr := hex.DecodeString(slotHex)
			if derr != nil {
				return nil, nil, fmt.Errorf("decode storage slot key %q: %w", slotHex, derr)
			}
			if len(slotBytes) != types.HashLength {
				return nil, nil, fmt.Errorf("storage slot key %q has wrong length %d (want %d)", slotHex, len(slotBytes), types.HashLength)
			}
			var slot types.Hash
			copy(slot[:], slotBytes)
			acc.Storage[slot] = val
		}
		states[addr] = acc
	}
	return states, snap.StateRoots, nil
}

// --- Batch ---

func (p *bboltPersistence) SaveBatch(batch *Batch) error {
	if batch == nil {
		return nil
	}
	data, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch %d: %w", batch.Index, err)
	}
	key := fmt.Sprintf("b:%d", batch.Index)
	if err := p.db.Put([]byte(key), data); err != nil {
		return fmt.Errorf("persist batch %d: %w", batch.Index, err)
	}
	return nil
}

func (p *bboltPersistence) LoadAllBatches() ([]*Batch, error) {
	// P1-ROLLUP-03 FIX (2026-07-30): Use NewIteratorWithLimit with limit=0
	// (unlimited) instead of NewIterator which silently truncated at 100K
	// entries. With the default 2s batch time, a node running for ~55 hours
	// would accumulate >100K batches; on restart the truncation would
	// silently drop the oldest batches, making RestoreBatches set
	// lastStateRoot from a non-latest batch → permanent ErrInvalidStateTransition.
	iter := p.db.NewIteratorWithLimit([]byte("b:"), nil, 0)
	defer iter.Release()

	var batches []*Batch
	for iter.Next() {
		key := iter.Key()
		// Skip meta keys ("b:meta:*").
		if len(key) > 4 && string(key[2:6]) == "meta" {
			continue
		}
		var batch Batch
		if err := json.Unmarshal(iter.Value(), &batch); err != nil {
			return nil, fmt.Errorf("unmarshal batch %s: %w", string(key), err)
		}
		batches = append(batches, &batch)
	}
	if err := iter.Error(); err != nil {
		// ErrIteratorTruncated should never fire with limit=0, but if it
		// does (implementation regression), fail-closed rather than silently
		// returning a partial batch set.
		return nil, fmt.Errorf("iterate batches: %w", err)
	}
	return batches, nil
}

// --- Batch meta ---

func (p *bboltPersistence) SaveBatchMeta(nextIndex uint64, lastStateRoot types.Hash) error {
	buf := make([]byte, 8+32)
	binary.BigEndian.PutUint64(buf[:8], nextIndex)
	copy(buf[8:], lastStateRoot[:])
	return p.db.Put([]byte("b:meta:next"), buf)
}

func (p *bboltPersistence) LoadBatchMeta() (uint64, types.Hash, error) {
	data, err := p.db.Get([]byte("b:meta:next"))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return 0, types.Hash{}, nil
		}
		return 0, types.Hash{}, fmt.Errorf("load batch meta: %w", err)
	}
	if len(data) < 40 {
		return 0, types.Hash{}, fmt.Errorf("batch meta corrupt: expected 40 bytes, got %d", len(data))
	}
	nextIndex := binary.BigEndian.Uint64(data[:8])
	var lastRoot types.Hash
	copy(lastRoot[:], data[8:40])
	return nextIndex, lastRoot, nil
}

// --- Fraud proof ---

func (p *bboltPersistence) SaveFraudProof(proof *FraudProof) error {
	if proof == nil {
		return nil
	}
	data, err := json.Marshal(proof)
	if err != nil {
		return fmt.Errorf("marshal fraud proof (batch %d): %w", proof.BatchIndex, err)
	}
	key := fmt.Sprintf("f:%d", proof.BatchIndex)
	if err := p.db.Put([]byte(key), data); err != nil {
		return fmt.Errorf("persist fraud proof (batch %d): %w", proof.BatchIndex, err)
	}
	return nil
}

func (p *bboltPersistence) LoadAllFraudProofs() ([]*FraudProof, error) {
	iter := p.db.NewIterator([]byte("f:"), nil)
	defer iter.Release()

	var proofs []*FraudProof
	for iter.Next() {
		var proof FraudProof
		if err := json.Unmarshal(iter.Value(), &proof); err != nil {
			return nil, fmt.Errorf("unmarshal fraud proof %s: %w", string(iter.Key()), err)
		}
		proofs = append(proofs, &proof)
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate fraud proofs: %w", err)
	}
	return proofs, nil
}

func (p *bboltPersistence) Close() error {
	return p.db.Close()
}

// --- RollupEngine integration ---

// SetPersistence injects the persistence layer into the rollup engine and
// all sub-components (StateManager, BatchManager, FraudProver).
// W-P1-3 FIX (2026-07-13): When non-nil, the engine persists state after each
// batch/fraud-proof operation and restores on startup.
func (e *RollupEngine) SetPersistence(p Persistence) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.persistence = p
	e.stateManager.SetPersistence(p)
	e.batchManager.SetPersistence(p)
	e.fraudProver.SetPersistence(p)
}

// isDevnetChainID returns true if the engine's configured ChainID is one
// of the known devnet / non-production chain IDs where running without
// persistence is acceptable (data loss on restart is fine).
// R43-ROLLUP-PERSIST-01 FIX (2026-08-03): used by RestoreState to gate the
// "nil persistence on non-devnet" warning. Centralized here so adding a
// new devnet ID (the project currently uses 1333 for L1 devnet and 1334
// for L2 devnet-style tests) is a one-liner. Returns true when ChainID
// is 0 (unset — legacy unit-test defaults), 1333 (L1 devnet), or 1334
// (L2 devnet-style test chains). Production rollups use 1670+
// (mainnet) or 1669 (long-running testnet), so any non-zero non-devnet
// ID is treated as production.
func (e *RollupEngine) isDevnetChainID() bool {
	if e.config == nil {
		return true
	}
	switch e.config.ChainID {
	case 0, 1333, 1334:
		return true
	}
	return false
}

// RestoreState loads persisted L2 state from the database into memory.
// W-P1-3 FIX (2026-07-13): Called once on engine Start() before batchLoop
// begins, so the engine resumes from the last persisted state.
func (e *RollupEngine) RestoreState() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.persistence == nil {
		// R43-ROLLUP-PERSIST-01 (2026-08-03): in-memory mode is intended
		// only for devnets / unit tests where data loss on restart is
		// acceptable. If the configured ChainID is NOT a known devnet
		// chain ID, this is almost certainly a misconfiguration on a
		// production or testnet deployment — running without persistence
		// there means batches + L2 state + L1 anchors are LOST on every
		// restart, breaking finality invariants and the fraud-proof
		// window. Emit a WARNING (do NOT fail-closed, so legacy in-memory
		// demos keep working) but make the misconfiguration visible. The
		// operator should call SetPersistence() before Start().
		if !e.isDevnetChainID() {
			log.Printf("[WARN] R43-ROLLUP-PERSIST-01: rollup engine running with nil persistence on non-devnet chainID %d — L2 state / batches / L1 anchors will be LOST on restart; configure persistence before Start()",
				e.config.ChainID)
		}
		return nil
	}

	// 1. Restore account states + state roots.
	states, stateRoots, err := e.persistence.LoadStateSnapshot()
	if err != nil {
		return fmt.Errorf("restore state snapshot: %w", err)
	}
	if states != nil {
		e.stateManager.RestoreFromSnapshot(states, stateRoots)
	}

	// 2. Restore batches.
	batches, err := e.persistence.LoadAllBatches()
	if err != nil {
		return fmt.Errorf("restore batches: %w", err)
	}
	e.batchManager.RestoreBatches(batches)

	// 3. Restore batch meta (nextIndex + lastStateRoot).
	nextIndex, lastRoot, err := e.persistence.LoadBatchMeta()
	if err != nil {
		return fmt.Errorf("restore batch meta: %w", err)
	}
	e.batchManager.RestoreMeta(nextIndex, lastRoot)

	// 4. Restore fraud proofs.
	proofs, err := e.persistence.LoadAllFraudProofs()
	if err != nil {
		return fmt.Errorf("restore fraud proofs: %w", err)
	}
	e.fraudProver.RestoreFraudProofs(proofs)

	// 5. W-P1-4: Restore L1 anchors (only for memoryL1Anchor).
	if e.l1Anchor != nil {
		if mp, ok := e.l1Anchor.(*memoryL1Anchor); ok {
			anchors, err := e.persistence.LoadAnchors()
			if err != nil {
				return fmt.Errorf("restore anchors: %w", err)
			}
			mp.mu.Lock()
			for k, v := range anchors {
				mp.anchors[k] = v
				if v.SubmitHeight > mp.currentHeight {
					mp.currentHeight = v.SubmitHeight
				}
			}
			mp.mu.Unlock()

			// RLLP-R5-08 (2026-07-17): Reconstruct lastAnchorHeight from
			// the restored anchors. Without this, lastAnchorHeight stays 0
			// after restart, which makes updateL1AnchorLag() short-circuit
			// (lastAnchorHeight==0 → return early), disabling the anchor
			// lag alert. We rebuild it as the maximum SubmitHeight across
			// all restored anchors — the same logic used above for
			// mp.currentHeight, since the most recent batch's anchor
			// height is exactly the L1 height we want to track.
			maxSubmitHeight := uint64(0)
			for _, v := range anchors {
				if v.SubmitHeight > maxSubmitHeight {
					maxSubmitHeight = v.SubmitHeight
				}
			}
			e.lastAnchorHeight = maxSubmitHeight
		}
	}

	// 6. Restore engine counters.
	e.totalBatches = uint64(len(batches))
	for _, b := range batches {
		e.totalTxs += uint64(b.TxCount)
	}

	// P1-ROLLUP-03 FIX (2026-07-30): Fail-closed consistency check.
	// The audit found that RestoreState's step 1 (account snapshot) was
	// committed to memory before step 2 (LoadAllBatches) ran; if step 2
	// failed, Start() would log a warning and continue running with
	// "state latest, batches empty, lastStateRoot=genesis root" — a
	// half-restored state where the next ProcessBatch fails permanently
	// with ErrInvalidStateTransition. The fix detects this inconsistency
	// and returns an error so Start() refuses to run with a corrupted view.
	//
	// Inconsistency criteria (any one triggers fail-closed):
	//   - State snapshot exists (states != nil) AND persisted batches are
	//     empty AND meta claims a non-zero nextIndex (state was advanced
	//     but batches are missing).
	//   - Batches exist AND meta claims a non-zero nextIndex, but the meta's
	//     lastStateRoot does not match any persisted batch's PostStateRoot
	//     (stale meta from a non-atomic crash window).
	// When states == nil AND batches == nil, the engine starts fresh
	// (legitimate genesis / first run).
	if states != nil && len(batches) == 0 && nextIndex > 0 {
		return fmt.Errorf("P1-ROLLUP-03: inconsistent persisted state — state snapshot has %d accounts but LoadAllBatches returned 0 batches while meta claims nextIndex=%d (half-restored state would permanently fail on next ProcessBatch); refusing to start (fail-closed)",
			len(states), nextIndex)
	}
	if len(batches) > 0 && nextIndex > 0 && lastRoot != (types.Hash{}) {
		rootMatchesBatch := false
		for _, b := range batches {
			if b.PostStateRoot == lastRoot {
				rootMatchesBatch = true
				break
			}
		}
		if !rootMatchesBatch {
			return fmt.Errorf("P1-ROLLUP-03: inconsistent persisted state — meta lastStateRoot=%x does not match any of the %d persisted batches' PostStateRoot (stale meta from non-atomic crash window); refusing to start (fail-closed)",
				lastRoot[:8], len(batches))
		}
	}

	// RLLP-R5-08 (2026-07-17): missedBatchCount and lastSequencerAddr are
	// NOT reconstructed from persisted state because Batch does not record
	// which sequencer built it. missedBatchCount is left at 0 (its default)
	// — it tracks CONSECUTIVE failures, and after a restart we have no
	// history of consecutive failures. Resetting to 0 is the safe choice:
	// it avoids triggering spurious failover on the first post-restart
	// cycle. lastSequencerAddr is also left at zero (its default); the
	// sequencer-failover state machine will treat the first post-restart
	// sequencer as a "new" sequencer, which correctly resets
	// missedBatchCount to 0 anyway. This is the least-bad option until
	// Batch is extended with a Sequencer field for proper reconstruction.

	log.Printf("[rollup] Restored L2 state: %d accounts, %d batches (nextIndex=%d), %d fraud proofs, lastAnchorHeight=%d",
		len(states), len(batches), nextIndex, len(proofs), e.lastAnchorHeight)
	return nil
}

// persistStateAfterBatch is called after a successful ProcessBatch +
// SubmitBatch to flush state to disk. Errors are logged but non-fatal
// (in-memory state is still correct; only persistence is lost on restart).
func (e *RollupEngine) persistStateAfterBatch(batch *Batch) {
	if e.persistence == nil {
		return
	}
	// Persist the batch first (includes status + postStateRoot).
	if err := e.persistence.SaveBatch(batch); err != nil {
		log.Printf("[rollup] WARN: persist batch %d failed: %v", batch.Index, err)
	}
	// Persist state snapshot (account states + stateRoots map).
	if err := e.stateManager.PersistSnapshot(); err != nil {
		log.Printf("[rollup] WARN: persist state snapshot failed: %v", err)
	}
	// Persist batch meta (nextIndex + lastStateRoot).
	if err := e.batchManager.PersistMeta(); err != nil {
		log.Printf("[rollup] WARN: persist batch meta failed: %v", err)
	}
}

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

// bboltL1Bridge implements L1Bridge with bbolt persistence.
//
// W-P1-6 Phase 3 (2026-07-14): Extends memoryL1Bridge by mirroring every
// write operation to a bbolt database. On startup, all persisted state
// (deposits, processed withdrawals, liquidity, finalized state roots) is
// restored into the embedded memoryL1Bridge's in-memory maps, so reads
// remain fast (no db hit on the hot path).
//
// Storage layout (key prefixes, stored in the rollup's l2.db):
//
//	"l1bd:<hex(hash)>"      → Deposit JSON
//	"l1bw:<hex(hash)>"      → 1 byte (processed-withdrawal marker)
//	"l1bliq"                → big.Int bytes (total locked liquidity)
//	"l1bfr:<batchIndex BE>" → 32 bytes (finalized state root)
//	"l1bwr:<batchIndex BE>" → 32 bytes (dedicated withdrawal tree root)
//
// Persistence errors are non-fatal (logged as warnings) — in-memory state
// remains correct, only crash recovery is affected. This mirrors the
// pattern used by bboltPersistence (see persistence.go).
//
// AUDIT R4-BRDG-02 (2026-07-15): The "l1bwr:" prefix stores the dedicated
// withdrawal tree root per batch. Without persistence, a node restart
// would lose all recorded withdrawal roots, allowing attackers to replay
// withdrawals with tampered amounts (the in-memory check would always fail
// "no withdrawal root recorded" → denial of service, or worse, if the
// bridge contract has a fallback path).
type bboltL1Bridge struct {
	*memoryL1Bridge
	db db.Database
}

// NewBboltL1Bridge creates a persistent L1 bridge backed by the given
// database. On construction, all previously-persisted state is restored
// into memory. Returns an error if the database is nil or restore fails.
//
// W-P1-6 Phase 3 (2026-07-14)
func NewBboltL1Bridge(database db.Database) (L1Bridge, error) {
	if database == nil {
		return nil, fmt.Errorf("cannot create bboltL1Bridge with nil database")
	}
	b := &bboltL1Bridge{
		memoryL1Bridge: NewMemoryL1Bridge().(*memoryL1Bridge),
		db:             database,
	}
	if err := b.restore(); err != nil {
		return nil, fmt.Errorf("restore L1Bridge state: %w", err)
	}
	log.Printf("[rollup-bridge] Restored L1Bridge state: %d deposits, %d withdrawals, liquidity=%s, %d finalized roots, %d withdrawal roots",
		len(b.deposits), len(b.withdrawals), b.liquidity.String(), len(b.finalizedRoots), len(b.withdrawalRoots))
	return b, nil
}

// --- Overridden write methods (persist after in-memory update) ---

// Deposit delegates to the in-memory implementation, then persists the
// new deposit + updated liquidity to bbolt.
//
// R38-P1-12 FIX (2026-08-01): Previously persistDeposit/persistLiquidity
// returned no error and only logged a warning on Put failure — the caller
// had no way to know the in-memory state diverged from the persisted state
// (memory updated, disk write silently lost). Now persistXxx returns the
// error and Deposit propagates the first persistence failure to the caller.
// The in-memory state is still updated first (read path remains fast and
// correct), but the caller can now detect disk failures and surface them
// to the operator / retry / crash-consistent recovery logic.
func (b *bboltL1Bridge) Deposit(depositor types.Address, amount *big.Int) (types.Hash, error) {
	hash, err := b.memoryL1Bridge.Deposit(depositor, amount)
	if err != nil {
		return hash, err
	}
	if pErr := b.persistDeposit(hash); pErr != nil {
		return hash, pErr
	}
	if lErr := b.persistLiquidity(); lErr != nil {
		return hash, lErr
	}
	return hash, nil
}

// ProcessWithdrawal delegates to the in-memory implementation, then
// persists the processed-withdrawal marker + updated liquidity to bbolt.
//
// R38-P1-12 FIX (2026-08-01): propagate persist errors to the caller
// (instead of silently logging a warning and discarding them). The
// in-memory withdrawal marker is still set, but the caller now knows if
// the marker did not reach disk — enabling crash-consistent retry logic.
func (b *bboltL1Bridge) ProcessWithdrawal(
	withdrawer types.Address,
	amount *big.Int,
	batchIndex uint64,
	txIndex int,
	batchHash types.Hash,
	proof *MerkleWithdrawalProof,
) error {
	if err := b.memoryL1Bridge.ProcessWithdrawal(withdrawer, amount, batchIndex, txIndex, batchHash, proof); err != nil {
		return err
	}
	wHash := computeWithdrawalHash(withdrawer, amount, batchIndex, txIndex, batchHash)
	if wErr := b.persistWithdrawal(wHash); wErr != nil {
		return wErr
	}
	if lErr := b.persistLiquidity(); lErr != nil {
		return lErr
	}
	return nil
}

// RecordFinalizedBatch delegates to the in-memory implementation, then
// persists the finalized state root to bbolt.
//
// R38-P1-12 FIX (2026-08-01): propagate persist errors to the caller.
func (b *bboltL1Bridge) RecordFinalizedBatch(batchIndex uint64, stateRoot types.Hash) error {
	if err := b.memoryL1Bridge.RecordFinalizedBatch(batchIndex, stateRoot); err != nil {
		return err
	}
	return b.persistFinalizedRoot(batchIndex, stateRoot)
}

// RecordWithdrawalRoot delegates to the in-memory implementation, then
// persists the dedicated withdrawal tree root to bbolt.
// AUDIT R4-BRDG-02 (2026-07-15)
//
// R38-P1-12 FIX (2026-08-01): propagate persist errors to the caller. A
// lost withdrawal-root persistence would let a post-restart L1Bridge
// replay tampered withdrawals.
func (b *bboltL1Bridge) RecordWithdrawalRoot(batchIndex uint64, root types.Hash) error {
	if err := b.memoryL1Bridge.RecordWithdrawalRoot(batchIndex, root); err != nil {
		return err
	}
	return b.persistWithdrawalRoot(batchIndex, root)
}

// MarkDepositMinted re-persists the deposit JSON so the Minted=true flag
// survives a node restart. Without this, a restart after a successful mint
// would restore Minted=false and ProcessDeposit would re-mint the same L1
// deposit, draining L1 bridge liquidity (double-spend).
// P1-ROLLUP-01 FIX (2026-07-30)
//
// R38-P1-12 FIX (2026-08-01): Previously this method unconditionally
// returned nil even when persistDeposit's bbolt Put failed — the in-memory
// Minted=true flag was correct but the disk still held Minted=false, so a
// crash after the silent failure let a restart re-mint the deposit
// (memory/disk mismatch). Now the persist error is propagated strictly
// so the caller (L2Bridge.ProcessDeposit) can record / surface the
// persistence failure rather than treating it as success.
func (b *bboltL1Bridge) MarkDepositMinted(depositHash types.Hash) error {
	return b.persistDeposit(depositHash)
}

// --- Persistence helpers ---
//
// R38-P1-12 FIX (2026-08-01): All persistXxx helpers now return an error
// instead of silently logging a warning and dropping the bbolt Put failure.
// The in-memory state is mutated by the caller BEFORE these helpers run
// (the in-memory implementation has already returned success), so a
// non-nil error here means the in-memory and on-disk representations have
// diverged. Propagating the error lets writers (Deposit / ProcessWithdrawal
// / RecordFinalizedBatch / RecordWithdrawalRoot / MarkDepositMinted) surface
// the failure so operators / callers can detect the divergence rather than
// be misled into believing the write was durable.

func (b *bboltL1Bridge) persistDeposit(hash types.Hash) error {
	// R36-P3-23 FIX (2026-07-30): Acquire memoryL1Bridge.mu.RLock when
	// reading the deposits map. The map is concurrently mutated by
	// Deposit() (bridge.go:219 b.deposits[hash] = deposit under
	// b.memoryL1Bridge.mu.Lock) and by restore() (line 199, no lock but
	// single-threaded at startup). Without the RLock here, a concurrent
	// Deposit() call could be mutating the map while persistDeposit reads
	// it — a fatal concurrent map read/write that the race detector would
	// flag and that can crash the process in production. The RLock is
	// released before the bbolt Put (which does its own locking) to avoid
	// holding the bridge lock during disk I/O.
	b.memoryL1Bridge.mu.RLock()
	deposit, ok := b.memoryL1Bridge.deposits[hash]
	b.memoryL1Bridge.mu.RUnlock()
	if !ok {
		// Nothing to persist — not an error (e.g. MarkDepositMinted for
		// an unknown hash is a benign no-op rather than a persistence
		// failure).
		return nil
	}
	data, err := json.Marshal(deposit)
	if err != nil {
		log.Printf("[rollup-bridge] WARN: marshal deposit %x: %v", hash[:8], err)
		return fmt.Errorf("marshal deposit %x: %w", hash[:8], err)
	}
	key := "l1bd:" + hex.EncodeToString(hash[:])
	if err := b.db.Put([]byte(key), data); err != nil {
		log.Printf("[rollup-bridge] WARN: persist deposit %x: %v", hash[:8], err)
		return fmt.Errorf("persist deposit %x: %w", hash[:8], err)
	}
	return nil
}

func (b *bboltL1Bridge) persistWithdrawal(wHash types.Hash) error {
	key := "l1bw:" + hex.EncodeToString(wHash[:])
	if err := b.db.Put([]byte(key), []byte{1}); err != nil {
		log.Printf("[rollup-bridge] WARN: persist withdrawal %x: %v", wHash[:8], err)
		return fmt.Errorf("persist withdrawal %x: %w", wHash[:8], err)
	}
	return nil
}

func (b *bboltL1Bridge) persistLiquidity() error {
	b.memoryL1Bridge.mu.RLock()
	liqBytes := b.memoryL1Bridge.liquidity.Bytes()
	b.memoryL1Bridge.mu.RUnlock()
	if err := b.db.Put([]byte("l1bliq"), liqBytes); err != nil {
		log.Printf("[rollup-bridge] WARN: persist liquidity: %v", err)
		return fmt.Errorf("persist liquidity: %w", err)
	}
	return nil
}

func (b *bboltL1Bridge) persistFinalizedRoot(batchIndex uint64, stateRoot types.Hash) error {
	prefix := []byte("l1bfr:")
	key := make([]byte, len(prefix)+8)
	copy(key, prefix)
	binary.BigEndian.PutUint64(key[len(prefix):], batchIndex)
	if err := b.db.Put(key, stateRoot[:]); err != nil {
		log.Printf("[rollup-bridge] WARN: persist finalized root for batch %d: %v", batchIndex, err)
		return fmt.Errorf("persist finalized root for batch %d: %w", batchIndex, err)
	}
	return nil
}

// persistWithdrawalRoot stores the dedicated withdrawal tree root for a batch.
// AUDIT R4-BRDG-02 (2026-07-15)
func (b *bboltL1Bridge) persistWithdrawalRoot(batchIndex uint64, root types.Hash) error {
	prefix := []byte("l1bwr:")
	key := make([]byte, len(prefix)+8)
	copy(key, prefix)
	binary.BigEndian.PutUint64(key[len(prefix):], batchIndex)
	if err := b.db.Put(key, root[:]); err != nil {
		log.Printf("[rollup-bridge] WARN: persist withdrawal root for batch %d: %v", batchIndex, err)
		return fmt.Errorf("persist withdrawal root for batch %d: %w", batchIndex, err)
	}
	return nil
}

// --- Restore on startup ---

func (b *bboltL1Bridge) restore() error {
	// 1. Restore deposits.
	iter := b.db.NewIterator([]byte("l1bd:"), nil)
	maxDepositL1Height := uint64(0)
	for iter.Next() {
		var deposit Deposit
		if err := json.Unmarshal(iter.Value(), &deposit); err != nil {
			iter.Release()
			return fmt.Errorf("unmarshal deposit %s: %w", string(iter.Key()), err)
		}
		b.memoryL1Bridge.deposits[deposit.Hash] = &deposit
		// RLLP-R5-09 (2026-07-17): Track the max L1Height so we can
		// reconstruct currentHeight after restart. Without this, new
		// deposits after restart would get L1Height=0, breaking the
		// finality check.
		if deposit.L1Height > maxDepositL1Height {
			maxDepositL1Height = deposit.L1Height
		}
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterate deposits: %w", err)
	}

	// RLLP-R5-09 (2026-07-17): Reconstruct currentHeight from the max
	// deposit L1Height. This ensures new deposits after restart get a
	// correct L1Height (>= the highest previously-seen deposit height).
	b.memoryL1Bridge.currentHeight = maxDepositL1Height

	// 2. Restore processed withdrawals.
	iter = b.db.NewIterator([]byte("l1bw:"), nil)
	for iter.Next() {
		hashHex := string(iter.Key())[len("l1bw:"):]
		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil || len(hashBytes) != 32 {
			iter.Release()
			return fmt.Errorf("invalid withdrawal hash key %s", string(iter.Key()))
		}
		var wHash types.Hash
		copy(wHash[:], hashBytes)
		b.memoryL1Bridge.withdrawals[wHash] = true
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterate withdrawals: %w", err)
	}

	// 3. Restore liquidity.
	liqBytes, err := b.db.Get([]byte("l1bliq"))
	if err != nil && err != db.ErrKeyNotFound {
		return fmt.Errorf("load liquidity: %w", err)
	}
	if len(liqBytes) > 0 {
		b.memoryL1Bridge.liquidity = new(big.Int).SetBytes(liqBytes)
	}

	// 4. Restore finalized state roots.
	iter = b.db.NewIterator([]byte("l1bfr:"), nil)
	for iter.Next() {
		keySuffix := iter.Key()[len("l1bfr:"):]
		if len(keySuffix) != 8 {
			iter.Release()
			return fmt.Errorf("invalid finalized root key length: %s", string(iter.Key()))
		}
		batchIndex := binary.BigEndian.Uint64(keySuffix)
		if len(iter.Value()) != 32 {
			iter.Release()
			return fmt.Errorf("invalid finalized root value length for batch %d", batchIndex)
		}
		var stateRoot types.Hash
		copy(stateRoot[:], iter.Value())
		b.memoryL1Bridge.finalizedRoots[batchIndex] = stateRoot
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterate finalized roots: %w", err)
	}

	// 5. Restore withdrawal tree roots (audit R4-BRDG-02).
	iter = b.db.NewIterator([]byte("l1bwr:"), nil)
	for iter.Next() {
		keySuffix := iter.Key()[len("l1bwr:"):]
		if len(keySuffix) != 8 {
			iter.Release()
			return fmt.Errorf("invalid withdrawal root key length: %s", string(iter.Key()))
		}
		batchIndex := binary.BigEndian.Uint64(keySuffix)
		if len(iter.Value()) != 32 {
			iter.Release()
			return fmt.Errorf("invalid withdrawal root value length for batch %d", batchIndex)
		}
		var root types.Hash
		copy(root[:], iter.Value())
		b.memoryL1Bridge.withdrawalRoots[batchIndex] = root
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return fmt.Errorf("iterate withdrawal roots: %w", err)
	}

	return nil
}

// Quantaureum Node source, version 1.0.0.
// Package block provides block storage for Quantaureum blockchain.
package block

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Errors
var (
	ErrBlockNotFound = errors.New("block not found")
	ErrTxNotFound    = errors.New("transaction not found")
	ErrInvalidBlock  = errors.New("invalid block")
	// P3-CHAIN-INTEGRITY FIX (2026-08-07): A different block already exists
	// at this height. PutBlock MUST NOT silently overwrite a canonical block
	// with a different hash — that breaks chain integrity (a child block's
	// ParentHash would no longer match its parent's stored hash, causing
	// downstream nodes to detect a false fork and stall forever).
	// Legitimate reorgs must call DeleteBlocksFromHeight BEFORE PutBlock.
	ErrBlockConflict = errors.New("conflicting block at same height")
)

// Key prefixes for database
var (
	blockPrefix      = []byte("b") // block hash -> block data
	headerPrefix     = []byte("h") // block hash -> header data
	numberPrefix     = []byte("n") // block number -> block hash
	txLocationPrefix = []byte("t") // tx hash -> TxLocation
	// R35-P0-09 FIX: receipt storage prefix (tx hash -> receipt data).
	// Previously the codebase had NO persistent receipt storage; receipts
	// were either nil or reconstructed from in-memory caches lost on restart.
	// This prefix keys per-tx receipts persisted via StoreReceipt.
	receiptPrefix = []byte("r") // tx hash -> receipt data
	// AUDIT-FULL C-3 FIX (2026-08-14): persistent sync-unvalidated marker
	// (block hash -> big-endian height). Blocks persisted to the canonical
	// store during sync WITHOUT re-execution-verified state/receipt roots
	// are marked here so a node restart between ProcessBlock (sync path)
	// and rebuildState does NOT silently promote them to "validated".
	//
	// AUDIT-FULL  (2026-08-15): the value layout under unvalidatedPrefix
	// is implicitly versioned: every entry stores a big-endian uint64 height
	// (8 bytes). LoadUnvalidatedMarkers ignores any entry whose Value is NOT
	// 8 bytes (drop-on-schema-mismatch). A future layout change (e.g.
	// height+epoch, or a checksum tag) MUST either bump to a NEW prefix
	// (`u2`) or extend the value with a leading version byte — either way
	// the 8-byte guard above fails closed so a new value schema does not
	// silently mis-decode an old entry.
	//
	// AUDIT-FULL ROUND3 2026-08-15 LOW-01 — CLOSED-IN-PLACE:
	// Round 3's LOW-01 re-raised "unvalidatedPrefix has no schema version".
	// The  length-guard above is the chosen in-place closure mechanism
	// for this codebase: prefer a value-side reject-on-misdecode invariant
	// over a version-byte bump, because (a) it's zero-migration — existing
	// `u`-prefixed entries keep working, (b) it's fail-closed — any format
	// drift is observable as dropped markers (logged via
	// LoadUnvalidatedMarkers' skip count), not as corrupted state, and (c)
	// introducing a NEW byte-prefix convention now would require a costly
	// one-shot migration of all existing entries, providing no safety gain
	// beyond the guard we already have. Should a future format truly need a
	// tagged layout, the contract above ("bump prefix to `u2`, or prefix
	// the value with a version byte") is the documented upgrade path — no
	// further audit action required.
	unvalidatedPrefix = []byte("u") // block hash -> 8-byte big-endian height (sync-unvalidated marker)
	latestBlockKey    = []byte("latest")
	// R58-VRF-PERSIST (2026-08-18): per-epoch on-chain VRF accumulator
	// checkpoint (8-byte big-endian epoch -> 32-byte accumulator hash).
	// Mirrors Ethereum's design where the RANDAO/VRF entropy is a
	// deterministic function of the canonical chain — persisting the last
	// known accumulator lets a restarting node recover the proposer
	// schedule even if the R52 block replay is skipped or interrupted, so
	// sealer proposer election never diverges from the canonical chain.
	vrfAccPrefix = []byte("v") // epoch(8B BE) -> VRF accumulator hash
)

// maxScanHeightRange limits how many heights scanLatestHeightUnlocked will
// probe above the cached latest block when searching for the true tip.
//
//	previously hardcoded as 200 inline; extracted to a named
//
// constant for visibility and tunability.
const maxScanHeightRange = 200

// TxLocation stores the location of a transaction in a block
type TxLocation struct {
	BlockHash   types.Hash
	BlockNumber uint64
	TxIndex     uint32
}

// BlockStore stores and retrieves blocks
type BlockStore struct {
	db db.Database
	mu sync.RWMutex

	// latestBlock/latestBlockHash form an in-memory cache of the chain tip.
	//  NOTE (P3): This cache has NO time-based TTL — it is invalidated
	// implicitly by every write (StoreBlock/AddBlock updates latestBlock under
	// mu) and reloaded from the db on demand. Because the cache is always kept
	// in sync with the latest write, a TTL is unnecessary; staleness is only
	// possible across processes (different nodes), which the consensus/P2P layer
	// resolves via sync. The cache holds at most ONE block (the tip), so memory
	// usage is bounded regardless of chain height.
	latestBlock     *encoding.Block
	latestBlockHash types.Hash
	syncMode        int32
}

// NewBlockStore creates a new block store
func NewBlockStore(database db.Database) *BlockStore {
	return &BlockStore{
		db: database,
	}
}

// GetDB returns the underlying database instance.
// SECURITY FIX (audit C-3): Exposed for vote history persistence in SlashingManager.
func (bs *BlockStore) GetDB() db.Database {
	return bs.db
}

// PutVRFAccumulator durably records the on-chain VRF accumulator for one
// epoch (R58-VRF-PERSIST). Called via the QPOS persistence callback whenever
// SetEpochVRFAccumulator commits an authoritative header value. The write is
// idempotent: re-importing the same canonical block re-persists the same
// value, and re-importing a corrected fork writes the corrected value.
func (bs *BlockStore) PutVRFAccumulator(epoch uint64, acc types.Hash) error {
	if acc == (types.Hash{}) {
		return nil
	}
	var epochKey [8]byte
	binary.BigEndian.PutUint64(epochKey[:], epoch)
	return bs.db.Put(append(vrfAccPrefix, epochKey[:]...), acc[:])
}

// LoadVRFAccumulators reads every persisted per-epoch VRF accumulator
// checkpoint (R58-VRF-PERSIST). The node injects them into a freshly created
// QPOS at startup, BEFORE the R52 block replay overwrites them with the
// authoritative on-chain values — so a restart can never boot with an empty
// accumulator and a diverging proposer schedule, even if the replay is
// skipped or interrupted. Corrupt/oversized values are skipped (fail-closed
// to absent, which the caller then re-establishes from blocks).
func (bs *BlockStore) LoadVRFAccumulators() (map[uint64]types.Hash, error) {
	out := make(map[uint64]types.Hash)
	iter := bs.db.NewIterator(vrfAccPrefix, nil)
	defer iter.Release()
	for iter.Next() {
		key := iter.Key()
		if len(key) != len(vrfAccPrefix)+8 {
			continue
		}
		val := iter.Value()
		if len(val) != types.HashLength {
			continue
		}
		epoch := binary.BigEndian.Uint64(key[len(vrfAccPrefix):])
		var acc types.Hash
		copy(acc[:], val)
		out[epoch] = acc
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return out, nil
}

func (bs *BlockStore) SetSyncMode(enabled bool) {
	if enabled {
		bs.mu.Lock()
		atomic.StoreInt32(&bs.syncMode, 1)
		bs.mu.Unlock()
	} else {
		bs.mu.Lock()
		atomic.StoreInt32(&bs.syncMode, 0)
		needLoadLatest := bs.latestBlock == nil
		bs.mu.Unlock()

		// R34-QAUDB-P0-002 FIX: Load latest block OUTSIDE the write lock to
		// prevent deadlock. GetBlock acquires RLock(), but sync.RWMutex does
		// NOT support recursive locking — holding Lock() while calling GetBlock()
		// would deadlock because the writer blocks all readers including itself.
		// We read the hash under write lock, release, then fetch the block and
		// re-acquire the write lock to update the cache.
		if needLoadLatest {
			var hash types.Hash
			var blk *encoding.Block
			if hashData, err := bs.db.Get(latestBlockKey); err == nil {
				copy(hash[:], hashData)
				if loadedBlk, err := bs.GetBlock(hash); err == nil {
					blk = loadedBlk
				}
			}
			if blk != nil {
				bs.mu.Lock()
				// Double-check after re-acquiring lock: another goroutine may
				// have set latestBlock while we were loading.
				if bs.latestBlock == nil {
					bs.latestBlock = blk
					bs.latestBlockHash = hash
				}
				bs.mu.Unlock()
			}
		}
	}
}

func (bs *BlockStore) IsSyncMode() bool {
	return atomic.LoadInt32(&bs.syncMode) == 1
}

func (bs *BlockStore) latestBlockHeight() uint64 {
	if bs.latestBlock == nil {
		return 0
	}
	return bs.latestBlock.Header.Height
}

// Close closes the block store
func (bs *BlockStore) Close() error {
	return bs.db.Close()
}

// SECURITY FIX: TxLocation binary encoding constants.
// Using fixed-size binary encoding instead of JSON for deterministic serialization.
// JSON field ordering is non-deterministic across Go versions, which can cause
// different nodes to compute different hashes for the same data.
const txLocationBinarySize = 32 + 8 + 4

func marshalTxLocation(loc *TxLocation) ([]byte, error) {
	buf := make([]byte, txLocationBinarySize)
	copy(buf[:32], loc.BlockHash[:])
	binary.BigEndian.PutUint64(buf[32:40], loc.BlockNumber)
	binary.BigEndian.PutUint32(buf[40:44], loc.TxIndex)
	return buf, nil
}

func unmarshalTxLocation(data []byte) (*TxLocation, error) {
	if len(data) != txLocationBinarySize {
		return nil, fmt.Errorf("invalid tx location data length: expected %d, got %d", txLocationBinarySize, len(data))
	}
	loc := &TxLocation{}
	copy(loc.BlockHash[:], data[:32])
	loc.BlockNumber = binary.BigEndian.Uint64(data[32:40])
	loc.TxIndex = binary.BigEndian.Uint32(data[40:44])
	return loc, nil
}

// PutBlock stores a block
func (bs *BlockStore) PutBlock(block *encoding.Block) error {
	if block == nil || block.Header == nil {
		return ErrInvalidBlock
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	blockHash := ComputeBlockHash(block)
	blockNumber := block.Header.Height

	// P3-CHAIN-INTEGRITY FIX (2026-08-07): Check if a block already exists
	// at this height. If the existing block has the SAME hash, this is a
	// legitimate re-index — allow it (no-op effectively). If the existing
	// block has a DIFFERENT hash, this is a fork conflict — REFUSE to
	// overwrite. Silent overwriting breaks chain integrity: a child block's
	// ParentHash would no longer match its parent's stored hash, causing
	// downstream nodes to detect a false fork and stall forever.
	// Legitimate reorgs must call DeleteBlocksFromHeight BEFORE PutBlock.
	// The check uses a direct DB lookup (not GetBlockByNumber) because we
	// already hold bs.mu.Lock() and GetBlockByNumber takes RLock.
	numberKeyCheck := make([]byte, 8)
	binary.BigEndian.PutUint64(numberKeyCheck, blockNumber)
	existingHashData, existingErr := bs.db.Get(append(numberPrefix, numberKeyCheck...))
	var oldTxHashes []types.Hash
	if existingErr == nil {
		var existingHash types.Hash
		copy(existingHash[:], existingHashData)
		if existingHash != blockHash {
			// P3-CHAIN-INTEGRITY FIX: REFUSE to overwrite — return error.
			// The caller (ProcessBlock) should handle this as a fork conflict
			// via fork resolution logic, not by silently corrupting the chain.
			// AUDIT ROUND-3 2026-08-17 FIX: display truncation must be
			// bounds-checked — a corrupted height-index entry shorter than
			// 8 bytes used to panic here via existingHashData[:8] (the
			// non-corrupted value is always types.HashLength bytes).
			existingDisplay := existingHashData
			if len(existingDisplay) > 8 {
				existingDisplay = existingDisplay[:8]
			}
			log.Printf("ERROR: PutBlock: refusing to overwrite block at height %d (existing=%x, new=%x) — use DeleteBlocksFromHeight for reorgs",
				blockNumber, existingDisplay, blockHash[:8])
			return fmt.Errorf("%w: height %d (existing=%x, new=%x)",
				ErrBlockConflict, blockNumber, existingDisplay, blockHash[:8])
		}
		// Same hash — legitimate re-index. Collect old tx hashes for cleanup
		// (in case the block data changed but hash is the same — extremely
		// unlikely but defensive).
		if oldBlockData, gerr := bs.db.Get(append(blockPrefix, existingHash[:]...)); gerr == nil {
			if oldBlock, uerr := encoding.UnmarshalBlock(oldBlockData); uerr == nil {
				for _, tx := range oldBlock.Transactions {
					oldTxHashes = append(oldTxHashes, ComputeTransactionHash(tx))
				}
			}
		}
	}

	// SECURITY FIX: Use deterministic binary encoding instead of json.Marshal.
	// JSON serialization is non-deterministic (map iteration order, float handling),
	// which can cause different nodes to produce different block hashes for the
	// same data, breaking blockchain consensus.
	blockData, err := encoding.MarshalBlock(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	headerData, err := encoding.MarshalBlockHeader(block.Header)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	batch := bs.db.NewBatch()

	if err := batch.Put(append(blockPrefix, blockHash[:]...), blockData); err != nil {
		return fmt.Errorf("failed to put block data: %w", err)
	}

	if err := batch.Put(append(headerPrefix, blockHash[:]...), headerData); err != nil {
		return fmt.Errorf("failed to put header data: %w", err)
	}

	numberKey := make([]byte, 8)
	binary.BigEndian.PutUint64(numberKey, blockNumber)
	if err := batch.Put(append(numberPrefix, numberKey...), blockHash[:]); err != nil {
		return fmt.Errorf("failed to put number mapping: %w", err)
	}

	// R36-P3-3 FIX (2026-07-30): Clean old tx indexes and receipts from the
	// displaced block (same-height overwrite on fork resolution). This
	// prevents GetTransactionReceipt from returning receipts for non-canonical
	// transactions, which would violate Ethereum semantics and mislead
	// exchanges and explorers.
	for _, oldTxHash := range oldTxHashes {
		if err := batch.Delete(append(txLocationPrefix, oldTxHash[:]...)); err != nil {
			return fmt.Errorf("failed to delete old tx location for %x: %w", oldTxHash, err)
		}
		if err := batch.Delete(append(receiptPrefix, oldTxHash[:]...)); err != nil {
			return fmt.Errorf("failed to delete old receipt for %x: %w", oldTxHash, err)
		}
	}

	// Store transaction locations using deterministic binary encoding
	for i, tx := range block.Transactions {
		txHash := ComputeTransactionHash(tx)
		loc := TxLocation{
			BlockHash:   blockHash,
			BlockNumber: blockNumber,
			TxIndex:     uint32(i), //nolint:gosec,G115
		}
		locData, err := marshalTxLocation(&loc)
		if err != nil {
			return fmt.Errorf("failed to marshal tx location: %w", err)
		}
		if err := batch.Put(append(txLocationPrefix, txHash[:]...), locData); err != nil {
			return fmt.Errorf("failed to put tx location: %w", err)
		}
	}

	// SECURITY FIX: Include latestBlockKey in the batch for atomicity.
	// Previously, db.Put(latestBlockKey) was called after batch.Write(),
	// meaning a crash between the two operations would leave the database
	// in an inconsistent state (block data written but "latest" pointer stale).
	isLatest := false
	if !bs.IsSyncMode() {
		// R37-P3-01 FIX (2026-07-31): isLatest must be determined from the
		// authoritative DB latestBlockKey, NOT the in-memory cache. On cold
		// start or after sync the cache may be nil or stale; using it can
		// cause the chain tip to revert to an older block.
		currentLatestHeight := uint64(0)
		if latestHashData, lerr := bs.db.Get(latestBlockKey); lerr == nil {
			var latestHash types.Hash
			copy(latestHash[:], latestHashData)
			if latestBlkData, lerr2 := bs.db.Get(append(blockPrefix, latestHash[:]...)); lerr2 == nil {
				if latestBlk, lerr3 := encoding.UnmarshalBlock(latestBlkData); lerr3 == nil && latestBlk.Header != nil {
					currentLatestHeight = latestBlk.Header.Height
				}
			}
		}
		// R37-P3-02 FIX (2026-07-31): when overwriting the current tip at the
		// same height (fork resolution), latestBlockKey must still be updated
		// so that GetLatestBlock returns the new canonical block.
		if blockNumber >= currentLatestHeight {
			isLatest = true
		}
	}
	if isLatest {
		if err := batch.Put(latestBlockKey, blockHash[:]); err != nil {
			return fmt.Errorf("failed to put latest block key: %w", err)
		}
	}

	if err := batch.Write(); err != nil {
		return err
	}

	// Update in-memory cache only after successful batch write
	if isLatest {
		bs.latestBlock = block
		bs.latestBlockHash = blockHash
	}

	return nil
}

// GetBlock retrieves a block by hash
func (bs *BlockStore) GetBlock(hash types.Hash) (*encoding.Block, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	// audit-fix  return a defensive copy of the cached block to prevent
	// external callers from mutating shared state (headers, transactions, etc.).
	if bs.latestBlock != nil && bs.latestBlockHash == hash {
		return cloneBlock(bs.latestBlock)
	}

	data, err := bs.db.Get(append(blockPrefix, hash[:]...))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, ErrBlockNotFound
		}
		return nil, err
	}

	block, err := encoding.UnmarshalBlock(data)
	if err != nil {
		return nil, err
	}

	return block, nil
}

// GetBlockByNumber retrieves a block by number
func (bs *BlockStore) GetBlockByNumber(number uint64) (*encoding.Block, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	// audit-fix  return a defensive copy of the cached block.
	if bs.latestBlock != nil && bs.latestBlock.Header.Height == number {
		return cloneBlock(bs.latestBlock)
	}

	// Get hash from number
	numberKey := make([]byte, 8)
	binary.BigEndian.PutUint64(numberKey, number)
	hashData, err := bs.db.Get(append(numberPrefix, numberKey...))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, ErrBlockNotFound
		}
		return nil, err
	}

	var hash types.Hash
	copy(hash[:], hashData)

	// Get block data
	data, err := bs.db.Get(append(blockPrefix, hash[:]...))
	if err != nil {
		return nil, err
	}

	block, err := encoding.UnmarshalBlock(data)
	if err != nil {
		return nil, err
	}

	return block, nil
}

// GetLatestBlock returns the latest block
func (bs *BlockStore) GetLatestBlock() (*encoding.Block, error) {
	// First try with read lock
	bs.mu.RLock()
	if bs.latestBlock != nil {
		// audit-fix  return a defensive copy of the cached block.
		block, err := cloneBlock(bs.latestBlock)
		bs.mu.RUnlock()
		return block, err
	}
	bs.mu.RUnlock()

	// Cache miss — acquire write lock to load and cache
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// Double-check after acquiring write lock
	if bs.latestBlock != nil {
		return cloneBlock(bs.latestBlock)
	}

	// Try to load from database
	hashData, err := bs.db.Get(latestBlockKey)
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, ErrBlockNotFound
		}
		return nil, err
	}

	var hash types.Hash
	copy(hash[:], hashData)

	data, err := bs.db.Get(append(blockPrefix, hash[:]...))
	if err != nil {
		return nil, err
	}

	block, err := encoding.UnmarshalBlock(data)
	if err != nil {
		return nil, err
	}

	bs.latestBlock = block
	bs.latestBlockHash = hash

	return block, nil
}

// GetHeader retrieves a block header by hash
func (bs *BlockStore) GetHeader(hash types.Hash) (*encoding.BlockHeader, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	data, err := bs.db.Get(append(headerPrefix, hash[:]...))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, ErrBlockNotFound
		}
		return nil, err
	}

	header, err := encoding.UnmarshalBlockHeader(data)
	if err != nil {
		return nil, err
	}

	return header, nil
}

// GetTransactionLocation retrieves the location of a transaction
func (bs *BlockStore) GetTransactionLocation(txHash types.Hash) (*TxLocation, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	data, err := bs.db.Get(append(txLocationPrefix, txHash[:]...))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, ErrTxNotFound
		}
		return nil, err
	}

	loc, err := unmarshalTxLocation(data)
	if err != nil {
		return nil, err
	}

	return loc, nil
}

// HasBlock checks if a block exists
func (bs *BlockStore) HasBlock(hash types.Hash) (bool, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	return bs.db.Has(append(blockPrefix, hash[:]...))
}

// GetBlockHash returns the block hash for a given block number
func (bs *BlockStore) GetBlockHash(number uint64) (types.Hash, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	numberKey := make([]byte, 8)
	binary.BigEndian.PutUint64(numberKey, number)
	hashData, err := bs.db.Get(append(numberPrefix, numberKey...))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return types.Hash{}, ErrBlockNotFound
		}
		return types.Hash{}, err
	}

	var hash types.Hash
	copy(hash[:], hashData)
	return hash, nil
}

// GetBlockHeader retrieves just the header for a block at a given height or hash
// Accepts either uint64 (height) or types.Hash
func (bs *BlockStore) GetBlockHeader(heightOrHash any) (*encoding.BlockHeader, error) {
	switch v := heightOrHash.(type) {
	case uint64:
		block, err := bs.GetBlockByNumber(v)
		if err != nil {
			return nil, err
		}
		return block.Header, nil
	case types.Hash:
		block, err := bs.GetBlock(v)
		if err != nil {
			return nil, err
		}
		return block.Header, nil
	default:
		return nil, ErrBlockNotFound
	}
}

// IndexTransactions indexes all transactions in a block.
// NOTE: PutBlock already indexes transactions. Use this only for re-indexing.
func (bs *BlockStore) IndexTransactions(block *encoding.Block) error {
	if block == nil || block.Header == nil {
		return ErrInvalidBlock
	}

	bs.mu.Lock()
	defer bs.mu.Unlock()

	blockHash := ComputeBlockHash(block)
	blockNumber := block.Header.Height

	batch := bs.db.NewBatch()

	for i, tx := range block.Transactions {
		txHash := ComputeTransactionHash(tx)
		loc := TxLocation{
			BlockHash:   blockHash,
			BlockNumber: blockNumber,
			TxIndex:     uint32(i), //nolint:gosec,G115
		}
		locData, err := marshalTxLocation(&loc)
		if err != nil {
			return fmt.Errorf("failed to marshal tx location: %w", err)
		}
		if err := batch.Put(append(txLocationPrefix, txHash[:]...), locData); err != nil {
			return fmt.Errorf("failed to put tx location: %w", err)
		}
	}

	return batch.Write()
}

// PutBlockWithIndex stores a block and indexes its transactions.
// PutBlock already indexes transactions internally, so this is equivalent to PutBlock.
// Kept for API compatibility.
func (bs *BlockStore) PutBlockWithIndex(block *encoding.Block) error {
	return bs.PutBlock(block)
}

// GetLatestBlockNumber returns the latest block number
func (bs *BlockStore) GetLatestBlockNumber() (uint64, error) {
	block, err := bs.GetLatestBlock()
	if err != nil {
		return 0, err
	}
	return block.Header.Height, nil
}

// GetLatestHeight returns the latest block height (alias for GetLatestBlockNumber)
func (bs *BlockStore) GetLatestHeight() (uint64, error) {
	if !bs.IsSyncMode() {
		return bs.GetLatestBlockNumber()
	}
	height, err := bs.GetLatestBlockNumber()
	if err != nil || height == 0 {
		scanned := bs.scanLatestHeight()
		if scanned > 0 {
			return scanned, nil
		}
	}
	return height, err
}

func (bs *BlockStore) scanLatestHeight() uint64 {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.scanLatestHeightUnlocked()
}

func (bs *BlockStore) scanLatestHeightUnlocked() uint64 {
	startHeight := uint64(0)
	if bs.latestBlock != nil {
		startHeight = bs.latestBlock.Header.Height
	} else if hashData, err := bs.db.Get(latestBlockKey); err == nil {
		// R36-P2-BS-01 FIX: cache is cold — use the persisted latestBlockKey
		// to find a better starting point. Previously only scanned from 0,
		// which missed blocks when cache lag exceeded maxScanHeightRange.
		var hash types.Hash
		copy(hash[:], hashData)
		if blkData, err := bs.db.Get(append(blockPrefix, hash[:]...)); err == nil {
			if blk, err := encoding.UnmarshalBlock(blkData); err == nil && blk.Header != nil {
				startHeight = blk.Header.Height
			}
		}
	}
	height := startHeight
	for h := startHeight + 1; h <= startHeight+maxScanHeightRange; h++ {
		numberKey := make([]byte, 8)
		binary.BigEndian.PutUint64(numberKey, h)
		if _, err := bs.db.Get(append(numberPrefix, numberKey...)); err != nil {
			break
		}
		height = h
	}
	return height
}

// findContinuousTipLocked scans from height 1 upward to find the highest
// block whose parent chain is unbroken. Caller MUST hold bs.mu.
// R37-P3-04 FIX (2026-07-31): extracted from FindContinuousTip so that
// DeleteBlocksFromHeight can use it while already holding the write lock.
func (bs *BlockStore) findContinuousTipLocked() uint64 {
	latestHeight := bs.scanLatestHeightUnlocked()
	if latestHeight == 0 {
		return 0
	}

	tip := uint64(0)
	for h := uint64(1); h <= latestHeight; h++ {
		numberKey := make([]byte, 8)
		binary.BigEndian.PutUint64(numberKey, h)
		hash, err := bs.db.Get(append(numberPrefix, numberKey...))
		if err != nil {
			break
		}
		// R37-P3-12 FIX (2026-07-31): read only the header bucket instead of
		// the full block. The old code deserialized every block (including
		// all transactions) on every height of the scan — O(chain length *
		// tx count) work while holding the lock. Only the header's
		// ParentHash is needed for continuity verification.
		hdrData, err := bs.db.Get(append(headerPrefix, hash...))
		if err != nil {
			break
		}
		hdr, err := encoding.UnmarshalBlockHeader(hdrData)
		if err != nil {
			break
		}
		// R37-P3-03 FIX (2026-07-31): nil-Header defense — a corrupted
		// header record must not panic on ParentHash dereference.
		if hdr == nil {
			break
		}
		if h > 1 {
			parentKey := make([]byte, 8)
			binary.BigEndian.PutUint64(parentKey, h-1)
			parentHash, err := bs.db.Get(append(numberPrefix, parentKey...))
			if err != nil {
				break
			}
			if hdr.ParentHash != types.BytesToHash(parentHash) {
				break
			}
		}
		tip = h
	}
	return tip
}

func (bs *BlockStore) FindContinuousTip() uint64 {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.findContinuousTipLocked()
}

// GetBlockByHeight retrieves a block by height (alias for GetBlockByNumber)
func (bs *BlockStore) GetBlockByHeight(height uint64) (*encoding.Block, error) {
	return bs.GetBlockByNumber(height)
}

// GetTransaction retrieves a transaction by hash, returning the transaction and its location
func (bs *BlockStore) GetTransaction(hash types.Hash) (*encoding.Transaction, *TxLocation, error) {
	loc, err := bs.GetTransactionLocation(hash)
	if err != nil {
		return nil, nil, err
	}

	block, err := bs.GetBlock(loc.BlockHash)
	if err != nil {
		return nil, loc, err
	}

	if int(loc.TxIndex) >= len(block.Transactions) {
		return nil, loc, ErrTxNotFound
	}

	return block.Transactions[loc.TxIndex], loc, nil
}

// StoreReceipt persists a single transaction receipt keyed by tx hash.
//
// R35-P0-09 FIX: Previously the codebase had NO persistent receipt storage.
// Receipts were either nil (GraphQL path) or reconstructed from an
// in-memory receiptCache (JSON-RPC path) that was lost on node restart,
// making eth_getTransactionReceipt return incorrect/nil data after restart.
//
// This method persists receipts to disk so they survive restarts. It is
// called by the node layer after each block's transactions are executed.
// The receipt is serialized via encoding.MarshalReceipt (deterministic
// binary encoding) to ensure all nodes produce identical bytes.
//
// Idempotency: storing the same receipt twice (same tx hash) overwrites
// silently. This is safe because receipts are immutable once persisted.
//
// Thread-safety: acquires bs.mu.Lock() to serialize with other writes.
func (bs *BlockStore) StoreReceipt(receipt *encoding.StoredReceipt) error {
	if receipt == nil {
		return fmt.Errorf("cannot store nil receipt")
	}
	data, err := encoding.MarshalReceipt(receipt)
	if err != nil {
		return fmt.Errorf("failed to marshal receipt: %w", err)
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if err := bs.db.Put(append(receiptPrefix, receipt.TxHash[:]...), data); err != nil {
		return fmt.Errorf("failed to put receipt: %w", err)
	}
	return nil
}

// StoreReceipts persists multiple receipts atomically in a single batch.
// This is the preferred method for storing all receipts from a block at once,
// ensuring atomicity — either all receipts are persisted or none.
//
// R35-P0-09 FIX: see StoreReceipt docs for context.
func (bs *BlockStore) StoreReceipts(receipts []*encoding.StoredReceipt) error {
	if len(receipts) == 0 {
		return nil
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	batch := bs.db.NewBatch()
	for _, r := range receipts {
		if r == nil {
			continue
		}
		data, err := encoding.MarshalReceipt(r)
		if err != nil {
			return fmt.Errorf("failed to marshal receipt for tx %x: %w", r.TxHash, err)
		}
		if err := batch.Put(append(receiptPrefix, r.TxHash[:]...), data); err != nil {
			return fmt.Errorf("failed to batch-put receipt for tx %x: %w", r.TxHash, err)
		}
	}
	return batch.Write()
}

// GetReceipt retrieves a persisted receipt by tx hash.
//
// R35-P0-09 FIX: returns the receipt previously stored via StoreReceipt.
// Returns ErrTxNotFound when no receipt is persisted for the given hash
// (e.g., pre-R35 blocks, or tx not yet executed). Callers should fall
// back to the simulated receipt path in that case.
func (bs *BlockStore) GetReceipt(txHash types.Hash) (*encoding.StoredReceipt, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	data, err := bs.db.Get(append(receiptPrefix, txHash[:]...))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, ErrTxNotFound
		}
		return nil, err
	}
	return encoding.UnmarshalReceipt(data)
}

// HasReceipt checks whether a persisted receipt exists for the given tx hash.
func (bs *BlockStore) HasReceipt(txHash types.Hash) (bool, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.db.Has(append(receiptPrefix, txHash[:]...))
}

// DeleteReceipt removes a persisted receipt (used during fork resolution).
func (bs *BlockStore) DeleteReceipt(txHash types.Hash) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.db.Delete(append(receiptPrefix, txHash[:]...))
}

// SetLatestBlock sets the latest block (used during sync)
//
// R33 STATE-04 FIX (2026-07-28): Previously db.Put failure was logged but the
// in-memory cache (bs.latestBlock, bs.latestBlockHash) was already mutated,
// leaving memory and DB inconsistent. On restart, GetLatestBlock would read
// a stale latestBlockKey from DB while the cache held a different value,
// causing eth_blockNumber and fork-resolution to diverge between hot path
// and restart. Fix: stage the DB write first; only mutate the in-memory
// cache if the write succeeds. On failure, leave the cache untouched so
// callers see the previously persisted state (the block will be re-set on
// the next successful Put).
func (bs *BlockStore) SetLatestBlock(block *encoding.Block) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if block != nil {
		// R37-P3-03 FIX (2026-07-31): reject blocks with nil Header — they
		// would corrupt the cache and cause nil-pointer panics downstream.
		if block.Header == nil {
			h := ComputeBlockHash(block)
			log.Printf("SetLatestBlock: rejecting block with nil header (hash=%x)", h[:8])
			return
		}
		blockHash := ComputeBlockHash(block)
		if err := bs.db.Put(latestBlockKey, blockHash[:]); err != nil {
			log.Printf("SetLatestBlock: failed to update latestBlockKey in db: %v (in-memory cache left untouched)", err)
			return
		}
		bs.latestBlock = block
		bs.latestBlockHash = blockHash
	} else {
		if err := bs.db.Delete(latestBlockKey); err != nil {
			log.Printf("SetLatestBlock: failed to delete latestBlockKey in db: %v (in-memory cache left untouched)", err)
			return
		}
		bs.latestBlock = nil
		bs.latestBlockHash = types.Hash{}
	}
}

// DeleteBlockAtHeight removes a block and all associated data at the given height.
// Used during fork resolution to reset the chain to a known good state.
func (bs *BlockStore) DeleteBlockAtHeight(height uint64) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	return bs.deleteBlockAtHeightLocked(height)
}

// deleteBlockAtHeightLocked is the lock-free internal of DeleteBlockAtHeight.
// Caller MUST hold bs.mu.
// R35-P1-12 FIX (2026-07-29): Extracted so DeleteBlocksFromHeight can hold
// the write lock for the ENTIRE multi-block deletion + latestBlockKey fixup,
// closing the race where a concurrent PutBlock inserts a new block between
// the loop's last DeleteBlockAtHeight (releases lock) and the fixup
// (re-acquires lock), making the new block an orphan.
func (bs *BlockStore) deleteBlockAtHeightLocked(height uint64) error {
	numberKey := make([]byte, 8)
	binary.BigEndian.PutUint64(numberKey, height)
	numberLookupKey := append(numberPrefix, numberKey...)

	blockHashBytes, err := bs.db.Get(numberLookupKey)
	if err != nil {
		return fmt.Errorf("block not found at height %d: %w", height, err)
	}

	var blockHash types.Hash
	copy(blockHash[:], blockHashBytes)

	blockData, err := bs.db.Get(append(blockPrefix, blockHash[:]...))
	var txHashes []types.Hash
	if err == nil {
		if blk, err2 := encoding.UnmarshalBlock(blockData); err2 == nil {
			for _, tx := range blk.Transactions {
				txHashes = append(txHashes, ComputeTransactionHash(tx))
			}
		} else {
			// R37-P3-05 FIX (2026-07-31): log corruption instead of silently
			// skipping tx/receipt cleanup. Silent skips leave orphan indexes
			// that can resurface via GetTransactionReceipt after restart.
			log.Printf("WARN: deleteBlockAtHeightLocked %d: block data corrupt (unmarshal failed: %v), skipping tx/receipt cleanup", height, err2)
		}
	} else {
		// R37-P3-05 FIX (2026-07-31): log missing block data. This indicates
		// prior partial deletion or DB corruption; orphan tx indexes may remain.
		log.Printf("WARN: deleteBlockAtHeightLocked %d: block data missing (%v), skipping tx/receipt cleanup", height, err)
	}

	batch := bs.db.NewBatch()

	if err := batch.Delete(append(blockPrefix, blockHash[:]...)); err != nil {
		return fmt.Errorf("failed to delete block data: %w", err)
	}
	if err := batch.Delete(append(headerPrefix, blockHash[:]...)); err != nil {
		return fmt.Errorf("failed to delete header data: %w", err)
	}
	if err := batch.Delete(numberLookupKey); err != nil {
		return fmt.Errorf("failed to delete number mapping: %w", err)
	}

	for _, txHash := range txHashes {
		// R36-P3-2 FIX (2026-07-30): Return Delete errors instead of only
		// logging. Previously a failed tx-index or receipt Delete was silently
		// swallowed, leaving orphan index/receipt entries that could resurface
		// via GetTransactionReceipt for transactions no longer on the canonical
		// chain. Fail-closed ensures the caller knows the deletion was partial.
		if err := batch.Delete(append(txLocationPrefix, txHash[:]...)); err != nil {
			return fmt.Errorf("failed to delete tx location for %x: %w", txHash, err)
		}
		// R35-P0-09 FIX: also delete persisted receipts on fork resolution
		// so stale receipts from the orphaned block don't leak into RPC.
		if err := batch.Delete(append(receiptPrefix, txHash[:]...)); err != nil {
			return fmt.Errorf("failed to delete receipt for %x: %w", txHash, err)
		}
	}

	// R36-P3-4 FIX (2026-07-30): Determine isLatest by checking the DB
	// latestBlockKey rather than the in-memory cache (bs.latestBlock).
	// On cold start or after concurrent operations that set the cache to
	// nil, the old check would skip updating the DB chain head pointer
	// when deleting the tip, leaving latestBlockKey pointing at a deleted
	// block. The DB check is authoritative and cache-independent.
	isLatest := false
	if latestHashData, lerr := bs.db.Get(latestBlockKey); lerr == nil {
		var latestHash types.Hash
		copy(latestHash[:], latestHashData)
		isLatest = latestHash == blockHash
	}

	if isLatest {
		if height > 0 {
			prevNumberKey := make([]byte, 8)
			binary.BigEndian.PutUint64(prevNumberKey, height-1)
			if prevHash, err := bs.db.Get(append(numberPrefix, prevNumberKey...)); err == nil {
				if err := batch.Put(latestBlockKey, prevHash); err != nil {
					log.Printf("block_store: failed to update latestBlockKey on rollback: %v", err)
				}
			} else {
				if err := batch.Delete(latestBlockKey); err != nil {
					log.Printf("block_store: failed to delete latestBlockKey on rollback: %v", err)
				}
			}
		} else {
			if err := batch.Delete(latestBlockKey); err != nil {
				log.Printf("block_store: failed to delete latestBlockKey at genesis: %v", err)
			}
		}
	}

	if err := batch.Write(); err != nil {
		return err
	}

	if isLatest {
		bs.latestBlock = nil
		bs.latestBlockHash = types.Hash{}
	}

	return nil
}

// DeleteBlocksFromHeight removes all blocks from the given height upward.
// Returns the number of blocks deleted.
func (bs *BlockStore) DeleteBlocksFromHeight(fromHeight uint64) (int, error) {
	// R36-P2-BS-01 FIX (2026-07-30): Acquire the write lock BEFORE reading
	// latestHeight. Previously, GetLatestHeight() was called outside the write
	// lock, so a concurrent PutBlock could insert a new block between the
	// height read and the lock acquisition. The loop would only delete up to
	// the stale latestHeight, then the fixup would roll latestBlockKey back to
	// fromHeight-1, orphaning the new block permanently. We now determine
	// latestHeight via scanLatestHeightUnlocked() (no internal lock acquisition)
	// while already holding the write lock.
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// scanLatestHeightUnlocked is safe to call here because we already hold
	// the write lock — it does NOT acquire any lock internally (unlike
	// GetLatestHeight which calls GetLatestBlock → RLock/Lock → deadlock).
	latestHeight := bs.scanLatestHeightUnlocked()

	count := 0
	var delErr error
	// STATE-BS-01 FIX (deep-audit 2026-07-12): iterate with an explicit break at
	// h==0. The old `for h := latestHeight; h >= fromHeight; h--` underflowed on
	// DeleteBlocksFromHeight(0): after deleting genesis, h-- wrapped to 2^64-1,
	// the `>= 0` guard stayed true, and DeleteBlockAtHeight(2^64-1) returned a
	// spurious "block not found" error that skipped the latestBlockKey fixup
	// below. Fork recovery to genesis (fromHeight==0) hits exactly this path.
	if latestHeight >= fromHeight {
		for h := latestHeight; ; h-- {
			// R35-P1-12 FIX: call deleteBlockAtHeightLocked (no lock) since
			// we already hold bs.mu — calling DeleteBlockAtHeight would deadlock.
			if err := bs.deleteBlockAtHeightLocked(h); err != nil {
				delErr = fmt.Errorf("failed to delete block at height %d: %w", h, err)
				break
			}
			count++
			if h == fromHeight {
				break
			}
		}
	}

	// R37-P3-04 FIX (2026-07-31): when deletion fails mid-loop (chain gap or
	// DB error), the fixup must NOT blindly roll latestBlockKey back to
	// fromHeight-1. If blocks above fromHeight-1 still exist, that creates
	// orphans and loses the real tip. Instead, find the actual continuous
	// tip from the remaining data and point latestBlockKey there. If no
	// continuous tip exists, delete latestBlockKey so the node can resync.
	batch := bs.db.NewBatch()
	var newLatestBlock *encoding.Block
	var newLatestHash types.Hash
	actualTip := bs.findContinuousTipLocked()
	if actualTip > 0 {
		tipNumberKey := make([]byte, 8)
		binary.BigEndian.PutUint64(tipNumberKey, actualTip)
		if tipHash, err := bs.db.Get(append(numberPrefix, tipNumberKey...)); err == nil {
			if err := batch.Put(latestBlockKey, tipHash); err != nil {
				log.Printf("DeleteBlocksFromHeight: failed to stage latestBlockKey update: %v", err)
			}
			copy(newLatestHash[:], tipHash)
			if blkData, err := bs.db.Get(append(blockPrefix, newLatestHash[:]...)); err == nil {
				if blk, err := encoding.UnmarshalBlock(blkData); err == nil {
					newLatestBlock = blk
				}
			}
		} else {
			// actualTip is derived from numberPrefix lookups, so this should
			// not happen; defensive fallback to deleting latestBlockKey.
			if err := batch.Delete(latestBlockKey); err != nil {
				log.Printf("DeleteBlocksFromHeight: failed to stage latestBlockKey delete: %v", err)
			}
		}
	} else {
		// No continuous chain remains — clear latestBlockKey so the node
		// resyncs from genesis rather than pointing to a dangling block.
		if err := batch.Delete(latestBlockKey); err != nil {
			log.Printf("DeleteBlocksFromHeight: failed to stage latestBlockKey delete: %v", err)
		}
	}
	// R36-P2-BS-02 FIX: Return the batch.Write() error instead of swallowing
	// it as success. Previously, a failed Write was logged and nil returned,
	// leaving the caller (and GetLatestBlock) with a dangling latestBlockKey.
	if err := batch.Write(); err != nil {
		return count, fmt.Errorf("failed to commit latestBlockKey batch: %w", err)
	}
	bs.latestBlock = newLatestBlock
	bs.latestBlockHash = newLatestHash

	if delErr != nil {
		return count, delErr
	}
	return count, nil
}

// cloneBlock returns a deep copy of a block via JSON round-trip.
// audit-fix  prevents callers from mutating the internal cache.
func cloneBlock(src *encoding.Block) (*encoding.Block, error) {
	data, err := encoding.MarshalBlock(src)
	if err != nil {
		return nil, err
	}
	return encoding.UnmarshalBlock(data)
}

// ComputeBlockHash computes the hash of a block or block header
// Accepts either *encoding.Block or *encoding.BlockHeader
func ComputeBlockHash(blockOrHeader any) types.Hash {
	switch v := blockOrHeader.(type) {
	case *encoding.Block:
		if v == nil || v.Header == nil {
			return types.Hash{}
		}
		return ComputeHeaderHash(v.Header)
	case *encoding.BlockHeader:
		if v == nil {
			return types.Hash{}
		}
		return ComputeHeaderHash(v)
	default:
		return types.Hash{}
	}
}

// ComputeHeaderHash computes the hash of a block header.
// Uses deterministic protobuf-compatible serialization from the encoding package.
func ComputeHeaderHash(header *encoding.BlockHeader) types.Hash {
	if header == nil {
		return types.Hash{}
	}

	// Use deterministic protobuf encoding (not JSON, which has non-deterministic field ordering)
	data, err := encoding.MarshalBlockHeader(header)
	if err != nil {
		return types.Hash{}
	}

	h := sha3.New256()
	h.Write(data)

	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// ComputeTransactionHash computes the hash of a transaction.
// Uses deterministic protobuf-compatible serialization from the encoding package.
func ComputeTransactionHash(tx *encoding.Transaction) types.Hash {
	if tx == nil {
		return types.Hash{}
	}

	// Use deterministic protobuf encoding (not JSON, which has non-deterministic field ordering)
	data, err := encoding.MarshalTransaction(tx)
	if err != nil {
		return types.Hash{}
	}

	h := sha3.New256()
	h.Write(data)

	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// ComputeTxRoot computes the Merkle root of transactions.
//
// AUDIT (2026) R4-DATA-08 (CVE-2012-2459 — LATENT): Uses duplicate-last
// padding for odd leaf counts (line 861). See core/block_builder.go
// computeMerkleRoot for the full analysis. This block-store helper is used for
// re-deriving TxRoot during block persistence/lookup; the active defense
// (duplicate-transaction-hash rejection in BlockValidator.validateTransactions)
// ensures no duplicate-leaf exploit shape reaches this code path. Note: this
// implementation does NOT apply a leaf domain separator (0x00) before hashing
// the transaction hash, unlike core/block_builder.go and miner/block_builder.go.
// This is a pre-existing inconsistency tracked separately; the second-preimage
// risk is mitigated by the 32-byte tx-hash input size making leaf/internal
// confusion structurally difficult.
//
// R33 P3-09 FIX (2026-07-28): Added leaf domain separator (0x00) to match
// core/block_builder.go and miner/block_builder.go. Previously, leaves
// (transaction hashes) and internal nodes (hashPair output) used different
// prefixes (none vs 0x01), creating a theoretical second-preimage risk:
// an attacker who finds an internal node whose hash equals a transaction
// hash could substitute one for the other. The 0x00 leaf prefix makes
// this structurally impossible regardless of input sizes.
func ComputeTxRoot(txs []*encoding.Transaction) types.Hash {
	if len(txs) == 0 {
		return types.Hash{}
	}

	// Compute transaction hashes with leaf domain separator
	hashes := make([]types.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = hashLeaf(ComputeTransactionHash(tx))
	}

	// Build Merkle tree (duplicate last hash when odd, per standard)
	for len(hashes) > 1 {
		newHashes := make([]types.Hash, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				newHashes[i/2] = hashPair(hashes[i], hashes[i+1])
			} else {
				// Duplicate last hash for odd count (standard Merkle tree behavior)
				newHashes[i/2] = hashPair(hashes[i], hashes[i])
			}
		}
		hashes = newHashes
	}

	return hashes[0]
}

// hashLeaf applies the leaf domain separator (0x00) to a transaction hash
// before it enters the Merkle tree. This prevents second-preimage attacks
// where an internal node hash could be substituted for a leaf.
// R33 P3-09 FIX (2026-07-28)
func hashLeaf(txHash types.Hash) types.Hash {
	h := sha3.New256()
	h.Write([]byte{0x00}) // Leaf domain separator
	h.Write(txHash[:])
	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// hashPair hashes two hashes together
func hashPair(left, right types.Hash) types.Hash {
	h := sha3.New256()
	h.Write([]byte{0x01}) // Internal node domain separator
	h.Write(left[:])
	h.Write(right[:])

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// MarkBlockUnvalidated persists the sync-unvalidated marker for a block.
// AUDIT-FULL C-3 FIX (2026-08-14): the in-memory Syncer.unvalidatedBlocks
// map is lost on restart, so downstream consumers (RPC, state readers)
// wrongly treated sync-persisted-but-not-reapplied blocks as fully
// validated after a restart mid-sync. This durable marker closes that
// MarkBlockUnvalidated flags a block as sync-persisted-but-not-rebuilt so
// downstream consumers can fail-closed if they read canonical state before
// rebuildState finishes (R38-P1-08). The marker survives the sync gap: it
// survives restarts and is cleared only when the block's roots are
// re-verified by re-execution (applyBlock / rebuildState).
func (bs *BlockStore) MarkBlockUnvalidated(hash types.Hash, height uint64) error {
	if hash == (types.Hash{}) {
		return fmt.Errorf("cannot mark zero hash as unvalidated")
	}
	heightBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBuf, height)
	return bs.db.Put(append(unvalidatedPrefix, hash[:]...), heightBuf)
}

// UnvalidatedMarker is a (hash, height) pair used by the batch-API variant
// of MarkBlockUnvalidated (MarkBlocksUnvalidatedBatch).
type UnvalidatedMarker struct {
	Hash   types.Hash
	Height uint64
}

// MarkBlocksUnvalidatedBatch atomically marks multiple blocks as
// sync-unvalidated in a SINGLE bbolt transaction (one fsync for the whole
// batch). FIX (2026-08-15): the per-block
// MarkBlockUnvalidated call issues one bs.db.Put per ProcessBlock — fine in
// steady-state (blocks arrive ~1/s) but a bursty sync from a far-behind peer
// streams many blocks back-to-back, each one fsyncing the marker key. This
// batch API lets callers (Syncer) accumulate pending markers and flush them
// as a single batch, amortizing the fsync. Callers that still prefer the
// per-block path can keep using MarkBlockUnvalidated; both APIs leave the
// same byte layout (append(unvalidatedPrefix, hash[:]...) → 8-byte BE
// height), so iteration and ClearBlockUnvalidated don't care which one
// wrote the entry.
func (bs *BlockStore) MarkBlocksUnvalidatedBatch(markers []UnvalidatedMarker) error {
	if len(markers) == 0 {
		return nil
	}
	batch := bs.db.NewBatch()
	for _, m := range markers {
		if m.Hash == (types.Hash{}) {
			return fmt.Errorf("cannot mark zero hash as unvalidated")
		}
		heightBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(heightBuf, m.Height)
		key := append(unvalidatedPrefix, m.Hash[:]...)
		batch.Put(key, heightBuf)
	}
	return batch.Write()
}

// ClearBlockUnvalidated removes the sync-unvalidated marker for a block.
// Called after re-execution verified the block's state/receipt roots.
// A missing entry is a no-op (block was never marked).
func (bs *BlockStore) ClearBlockUnvalidated(hash types.Hash) error {
	return bs.db.Delete(append(unvalidatedPrefix, hash[:]...))
}

// HasUnvalidatedMarker reports whether a block carries the persistent
// sync-unvalidated marker.
func (bs *BlockStore) HasUnvalidatedMarker(hash types.Hash) (bool, error) {
	return bs.db.Has(append(unvalidatedPrefix, hash[:]...))
}

// LoadUnvalidatedMarkers returns all persistent sync-unvalidated markers
// keyed by block hash. Used at Syncer construction to restore the in-memory
// fail-closed surface after a restart.
func (bs *BlockStore) LoadUnvalidatedMarkers() (map[types.Hash]uint64, error) {
	markers := make(map[types.Hash]uint64)
	iter := bs.db.NewIterator(unvalidatedPrefix, nil)
	defer iter.Release()
	for iter.Next() {
		key := iter.Key()
		if len(key) != len(unvalidatedPrefix)+32 {
			continue
		}
		var hash types.Hash
		copy(hash[:], key[len(unvalidatedPrefix):])
		val := iter.Value()
		if len(val) != 8 {
			continue
		}
		markers[hash] = binary.BigEndian.Uint64(val)
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	return markers, nil
}

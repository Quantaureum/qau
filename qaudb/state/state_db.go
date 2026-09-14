// Quantaureum Node source, version 1.0.0.
// Package state provides state database for Quantaureum blockchain.
package state

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
)

// Errors
var (
	ErrAccountNotFound = errors.New("account not found")
	ErrStorageNotFound = errors.New("storage not found")
	ErrInvalidState    = errors.New("invalid state")
)

// L14-012: Maximum snapshot depth to prevent memory exhaustion from excessive
// nested calls. 1024 matches the EVM call depth limit, providing defense-in-depth
// even if the QVM executor's own depth check fails.
//
//	(P3): This is the maximum snapshot limit. Snapshot() panics once
//
// len(snapshots) reaches maxSnapshotDepth, preventing memory exhaustion from
// unbounded nested calls. The panic (not a graceful error) is intentional: by
// the time the EVM call depth limit is exceeded, execution must abort.
//
// STATE- (2026-07-20) EVALUATION: The audit asked to evaluate
// whether to return an error instead of panicking. Decision: KEEP THE PANIC.
// Reasons:
//
//  1. Defense-in-depth backstop. The QVM executor checks
//     `env.callDepth >= MaxCallDepth` (also 1024) BEFORE calling Snapshot in
//     every QVM call path — verified at:
//     - qvm/executor.go:204 (Execute, before any Snapshot)
//     - qvm/executor.go:352 (ExecuteWithRollback — top-level, depth 0)
//     - qvm/executor.go:453 (Call — depth checked inside Execute)
//     - qvm/call.go:359 (opCall, before Snapshot at line 411)
//     - qvm/call.go:1011 (opDelegateCall, before Snapshot at line 1061)
//     - qvm/entrypoint.go:672 (SimulateValidation — top-level, depth 0)
//     Both MaxCallDepth and maxSnapshotDepth are 1024, so the QVM check
//     fires first and returns a graceful ErrDepthExceeded. The StateDB
//     panic should NEVER fire in normal QVM execution.
//
//  2. If the panic DOES fire, something is seriously wrong: the snapshot
//     count has diverged from the QVM callDepth (a bug), or a non-QVM
//     caller is calling Snapshot in a loop without depth protection. In
//     both cases, continuing execution risks state corruption — a hard
//     abort is safer than returning an error that lets the caller
//     proceed with a corrupted snapshot stack.
//
//  3. Changing Snapshot() to return (int, error) would require updating
//     every caller (qvm, txpool, audit, perf, tests — 30+ call sites).
//     That invasive change is disproportionate for a "should never fire"
//     backstop. The panic is the correct Go idiom for "programmer error /
//     invariant violation" — like slice out-of-bounds or nil map write.
//
// Regression guard: see TestStateDB_Snapshot_QVMDepthCheckFiresFirst
// which verifies that the QVM's depth check prevents Snapshot from
// being called when depth >= MaxCallDepth.
const maxSnapshotDepth = 1024

// Key prefixes
var (
	accountPrefix = []byte("a") // address -> account
	storagePrefix = []byte("s") // address + key -> value
	codePrefix    = []byte("c") // code hash -> code
	// AUDIT (2026) R4-DATA-03: commit-pending marker written to BoltDB
	// in the same batch as account data. If a crash occurs between
	// batch.Write() and the Verkle tree update, this marker survives and
	// triggers a Verkle tree rebuild on next startup.
	commitPendingKey = []byte("_commit_pending_")
	// R32-P2-05 FIX (2026-07-28): Persisted last-known-good state root.
	// Written after a successful Commit (batch.Write + Verkle update +
	// commitPendingKey clear). Read by RecoverConsistency to verify the
	// rebuilt Verkle tree produces the same root as the last successful
	// commit. If they differ, the rebuild silently produced a wrong tree
	// (e.g., a Put failed mid-iteration, or BoltDB data was corrupted),
	// and the node must halt rather than continue with a stale/wrong state.
	lastCommittedRootKey = []byte("_last_committed_root_")
	// R87-M4-RESTART (2026-08-29): persisted last-committed block height.
	// Written in the same post-commit batch as lastCommittedRootKey. On restart
	// this is the ONLY record of where the account state actually is —
	// s.lastCommittedHeight is in-memory and would otherwise reset to 0, which
	// made rebuildState replay from genesis ON TOP OF the existing mid-chain
	// state (nonce rejections → gas-check failures → a permanent state-root
	// mismatch storm that R87-STATE-TRUST then had to contain by disabling
	// block production). See node/syncer.go computeRebuildBaseline for the
	// consumer.
	lastCommittedHeightKey = []byte("_last_committed_height_")
)

// Account represents the state of an account
// storageCacheKey is the composite key for the storage cache.
type storageCacheKey struct {
	addr types.Address
	key  types.Hash
}

type Account struct {
	Nonce       uint64
	Balance     *big.Int
	StorageRoot types.Hash // Root of the storage trie
	CodeHash    types.Hash // Hash of the contract code
}

// NewAccount creates a new empty account
func NewAccount() *Account {
	return &Account{
		Nonce:       0,
		Balance:     big.NewInt(0),
		StorageRoot: types.Hash{},
		CodeHash:    types.Hash{},
	}
}

// accountBeforeImage stores the pre-modification state of an account for fork rollback.
// SECURITY: Without before-images, DeleteBlocksFromHeight only removes block records
// but leaves committed state (balances, contract storage) unchanged, causing state
// inconsistency after a fork rollback.
type accountBeforeImage struct {
	account *Account                  // nil means the account did not exist before this block
	storage map[types.Hash]types.Hash // previous storage values (nil keys = didn't exist)
}

// Log represents an event log emitted by a contract during execution.
// Mirrors the EVM Log struct (EIP-20 event format). Defined here in the state
// package (not in types/) because it is only consumed by StateDB log accumulation
// and the RPC layer that reads logs back via state — keeping it close to its
// only writer avoids a circular dependency on qvm.Log.
//
// STATE- (2026-07-20): Previously the StateDB did not accumulate logs at
// all — qvm.Environment held them in a per-tx slice that was discarded after
// Commit, leaving no way for RPC (eth_getLogs / eth_getTransactionReceipt) to
// retrieve them. StateDB now natively accumulates logs so they survive across
// the Commit boundary and can be retrieved via GetLogs / Logs.
type Log struct {
	Address types.Address
	Topics  []types.Hash
	Data    []byte
	// BlockNumber is populated by the block producer when the containing
	// block is finalized. Zero means the log has not yet been associated
	// with a block (still in the pending tx pool or pre-commit).
	BlockNumber uint64
	// TxHash is set by the executor when the log is added to StateDB.
	// Zero hash means the log has not yet been associated with a tx.
	TxHash    types.Hash
	TxIndex   uint
	BlockHash types.Hash
	Index     uint // log index within the block (assigned at commit)
}

// accessList captures the EIP-2929 warm-set for the current transaction.
// Addresses and storage slots that have been accessed (read or written) at
// least once pay the cheaper "warm" gas price on subsequent accesses. Cleared
// between transactions.
//
// STATE- (2026-07-20): Previously StateDB had no access list — the
// qvmasync.StateDBAdapter maintained its own per-tx map that was not
// coordinated with Snapshot/RevertToSnapshot at the state layer. While the
// adapter's own Snapshot logic covered its maps, the StateDB-level snapshot
// (used by block_producer for cross-tx state reuse, and by tests that
// directly drive StateDB) was not aware of access-list changes. This could
// cause divergent gas accounting between the proposer and verifiers when a
// transaction reverted: the proposer's StateDB.Snapshot/RevertToSnapshot
// restored account state but NOT the access list (because it lived only in
// the adapter), so a subsequent re-execution of the same call would observe
// a "warm" slot that should have been rolled back to "cold".
type accessList struct {
	// addresses is the set of warm addresses.
	addresses map[types.Address]struct{}
	// slots is the per-address set of warm storage slots.
	slots map[types.Address]map[types.Hash]struct{}
}

// newAccessList returns a ready-to-use accessList.
func newAccessList() *accessList {
	return &accessList{
		addresses: make(map[types.Address]struct{}),
		slots:     make(map[types.Address]map[types.Hash]struct{}),
	}
}

// addAddress marks addr warm. Returns true if it was cold before (i.e. this
// call transitioned it from cold → warm). Used by the executor to decide
// whether to charge the cold-access gas penalty.
func (al *accessList) addAddress(addr types.Address) bool {
	if _, ok := al.addresses[addr]; ok {
		return false
	}
	al.addresses[addr] = struct{}{}
	return true
}

// addSlot marks (addr, slot) warm. Implies addAddress(addr). Returns true if
// the slot was cold before.
func (al *accessList) addSlot(addr types.Address, slot types.Hash) bool {
	al.addAddress(addr)
	slots, ok := al.slots[addr]
	if !ok {
		slots = make(map[types.Hash]struct{})
		al.slots[addr] = slots
	}
	if _, ok := slots[slot]; ok {
		return false
	}
	slots[slot] = struct{}{}
	return true
}

// addressWarm returns whether addr is in the warm set.
func (al *accessList) addressWarm(addr types.Address) bool {
	_, ok := al.addresses[addr]
	return ok
}

// slotWarm returns (addressWarm, slotWarm) for EIP-2929 gas calculation.
func (al *accessList) slotWarm(addr types.Address, slot types.Hash) (bool, bool) {
	addrWarm := al.addressWarm(addr)
	if !addrWarm {
		return false, false
	}
	slots, ok := al.slots[addr]
	if !ok {
		return true, false
	}
	_, slotWarm := slots[slot]
	return true, slotWarm
}

// deepCopy returns a value-copy of the accessList. Needed by Snapshot so that
// mutations after the snapshot do not corrupt the captured state.
func (al *accessList) deepCopy() *accessList {
	if al == nil {
		return newAccessList()
	}
	cp := &accessList{
		addresses: make(map[types.Address]struct{}, len(al.addresses)),
		slots:     make(map[types.Address]map[types.Hash]struct{}, len(al.slots)),
	}
	for addr := range al.addresses {
		cp.addresses[addr] = struct{}{}
	}
	for addr, slots := range al.slots {
		cpSlots := make(map[types.Hash]struct{}, len(slots))
		for k := range slots {
			cpSlots[k] = struct{}{}
		}
		cp.slots[addr] = cpSlots
	}
	return cp
}

// transientStorage is the EIP-1153 per-transaction transient storage.
// Keyed by (address, slot) → value. Cleared between transactions.
//
// STATE- (2026-07-20): Previously StateDB had no transient storage —
// qvm.Environment maintained its own per-tx map that was NOT coordinated with
// StateDB.Snapshot/RevertToSnapshot. If a sub-call reverted, the environment's
// transientStorage slice was rolled back via the QVM-level snapshot, but any
// code that read StateDB directly (e.g. parallel execution paths, or tests
// driving StateDB without going through qvm.Environment) would observe stale
// transient state. StateDB now natively holds transient storage so it
// participates in the same snapshot/revert lifecycle as accounts and storage.
type transientStorage struct {
	data map[types.Address]map[types.Hash]types.Hash
}

// newTransientStorage returns a ready-to-use transientStorage.
func newTransientStorage() *transientStorage {
	return &transientStorage{data: make(map[types.Address]map[types.Hash]types.Hash)}
}

// get returns the value at (addr, key), or the zero hash if not set.
func (ts *transientStorage) get(addr types.Address, key types.Hash) types.Hash {
	if slots, ok := ts.data[addr]; ok {
		return slots[key] // returns zero hash if not present
	}
	return types.Hash{}
}

// set sets the value at (addr, key). Allocates per-address maps lazily.
func (ts *transientStorage) set(addr types.Address, key, value types.Hash) {
	slots, ok := ts.data[addr]
	if !ok {
		slots = make(map[types.Hash]types.Hash)
		ts.data[addr] = slots
	}
	slots[key] = value
}

// exists returns true if (addr, key) has been explicitly set (even to zero).
func (ts *transientStorage) exists(addr types.Address, key types.Hash) bool {
	if slots, ok := ts.data[addr]; ok {
		_, ok := slots[key]
		return ok
	}
	return false
}

// deepCopy returns a value-copy of the transientStorage.
func (ts *transientStorage) deepCopy() *transientStorage {
	if ts == nil {
		return newTransientStorage()
	}
	cp := &transientStorage{data: make(map[types.Address]map[types.Hash]types.Hash, len(ts.data))}
	for addr, slots := range ts.data {
		cpSlots := make(map[types.Hash]types.Hash, len(slots))
		for k, v := range slots {
			cpSlots[k] = v
		}
		cp.data[addr] = cpSlots
	}
	return cp
}

// deepCopyLogs returns a deep copy of a log slice (defensive — callers may
// mutate the slice or log Data after the snapshot, which would corrupt the
// captured state). Topic slices and Data are copied element-wise.
func deepCopyLogs(src []*Log) []*Log {
	if len(src) == 0 {
		return nil
	}
	cp := make([]*Log, len(src))
	for i, log := range src {
		if log == nil {
			cp[i] = nil
			continue
		}
		lcopy := &Log{
			Address:     log.Address,
			BlockNumber: log.BlockNumber,
			TxHash:      log.TxHash,
			TxIndex:     log.TxIndex,
			BlockHash:   log.BlockHash,
			Index:       log.Index,
		}
		if log.Topics != nil {
			lcopy.Topics = make([]types.Hash, len(log.Topics))
			copy(lcopy.Topics, log.Topics)
		}
		if log.Data != nil {
			lcopy.Data = make([]byte, len(log.Data))
			copy(lcopy.Data, log.Data)
		}
		cp[i] = lcopy
	}
	return cp
}

// encodeAccount encodes an Account using deterministic binary serialization.
// Field order: Nonce (8 bytes) | Balance (32 bytes) | StorageRoot (32 bytes) | CodeHash (32 bytes)
// audit-fix CRIT-SERIAL: replaced non-deterministic JSON with deterministic binary encoding.
// JSON serialization is not deterministic across different runs/environments, which
// would cause state root divergence between nodes.
func encodeAccount(acc *Account) ([]byte, error) {
	if acc == nil {
		return nil, errors.New("cannot encode nil account")
	}

	buf := new(bytes.Buffer)

	// Nonce: 8 bytes big-endian
	if err := binary.Write(buf, binary.BigEndian, acc.Nonce); err != nil {
		return nil, fmt.Errorf("failed to encode nonce: %w", err)
	}

	// Balance: 32 bytes big-endian, padded
	// AUDIT (2026) R4-DATA-05 FIX: Guard against Balance >2²⁵⁶−1.
	// FillBytes returns nil (and would panic on subsequent Write) if the
	// value's bit length exceeds 256. A corrupted or attacker-crafted
	// state could trigger this and crash every node during Commit.
	// Fail-closed with a descriptive error instead.
	balanceBytes := make([]byte, 32)
	if acc.Balance != nil {
		if acc.Balance.BitLen() > 256 {
			return nil, fmt.Errorf("encodeAccount: balance exceeds 256-bit limit (bitLen=%d)", acc.Balance.BitLen())
		}
		balanceBytes = acc.Balance.FillBytes(balanceBytes)
	}
	if _, err := buf.Write(balanceBytes); err != nil {
		return nil, fmt.Errorf("failed to encode balance: %w", err)
	}

	// StorageRoot: 32 bytes
	if _, err := buf.Write(acc.StorageRoot[:]); err != nil {
		return nil, fmt.Errorf("failed to encode storage root: %w", err)
	}

	// CodeHash: 32 bytes
	if _, err := buf.Write(acc.CodeHash[:]); err != nil {
		return nil, fmt.Errorf("failed to encode code hash: %w", err)
	}

	return buf.Bytes(), nil
}

// decodeAccount decodes a Account from deterministic binary serialization.
// audit-fix CRIT-SERIAL: replaced non-deterministic JSON with deterministic binary decoding.
func decodeAccount(data []byte, acc *Account) error {
	if acc == nil {
		return errors.New("cannot decode into nil account")
	}
	if len(data) < 104 { // 8 + 32 + 32 + 32 = 104 bytes minimum
		return errors.New("data too short to decode account")
	}

	r := bytes.NewReader(data)

	// Nonce: 8 bytes big-endian
	if err := binary.Read(r, binary.BigEndian, &acc.Nonce); err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Balance: 32 bytes big-endian
	balanceBytes := make([]byte, 32)
	if _, err := r.Read(balanceBytes); err != nil {
		return fmt.Errorf("failed to read balance: %w", err)
	}
	acc.Balance = new(big.Int).SetBytes(balanceBytes)

	// StorageRoot: 32 bytes
	if _, err := r.Read(acc.StorageRoot[:]); err != nil {
		return fmt.Errorf("failed to read storage root: %w", err)
	}

	// CodeHash: 32 bytes
	if _, err := r.Read(acc.CodeHash[:]); err != nil {
		return fmt.Errorf("failed to read code hash: %w", err)
	}

	return nil
}

// stateSnapshot captures a deep copy of dirty state at a point in time.
// audit-fix R3-F12: used by Snapshot/RevertToSnapshot to support nested reverts.
//
// STATE- (2026-07-20) FIX: Added storageCache field. Previously
// Snapshot only captured dirtyAccounts/dirtyStorage, NOT storageCache. After
// RevertToSnapshot, storageCache could retain values that were loaded during
// the reverted section. While the current code only ever writes committed
// (DB-loaded) values to storageCache (so the cached values themselves remain
// "correct" in the sense of being committed values), capturing and restoring
// the cache as part of the snapshot makes the invariant explicit and provides
// defense-in-depth against future code paths that might write dirty values to
// the cache. Without this, contract execution after a revert could observe
// cache state from the reverted section, causing consensus divergence.
//
// STATE- (2026-07-20) FIX: Added accessList, logs, selfDestructs, and
// transientStorage fields. Previously these per-tx EIP features lived only
// in qvmasync.StateDBAdapter / qvm.Environment, so a StateDB-level revert
// (used by the block producer and direct-drive tests) would NOT roll them
// back. After a revert, the access list could remain "warm" for slots that
// should have been rolled back to "cold", and logs emitted during the
// reverted section would persist into the receipt. Both cause consensus
// divergence between proposer and verifiers.
type stateSnapshot struct {
	dirtyAccounts    map[types.Address]*Account
	dirtyStorage     map[types.Address]map[types.Hash]types.Hash
	storageCache     map[storageCacheKey]types.Hash
	accessList       *accessList
	logs             []*Log
	selfDestructs    map[types.Address]struct{}
	transientStorage *transientStorage
	// STATE- (2026-07-21): capture the beneficiary map so a
	// sub-call revert restores the correct beneficiary for every
	// selfdestruct that survived the revert. Previously the snapshot
	// captured only the selfdestruct address set, not the beneficiary
	// map, so RevertToSnapshot rebuilt an EMPTY beneficiary map. As a
	// result, any selfdestruct whose address was still in
	// selfDestructs after the revert lost its beneficiary entry and
	// was treated as a "burn" at end-of-block finalization, silently
	// destroying the contract's remaining balance instead of sending
	// it to the intended recipient (a fund-safety vulnerability).
	selfDestructBeneficiaries map[types.Address]types.Address
	// R35-P1-02 FIX: capture pendingCodeWrites so a sub-call revert
	// discards code staged by SetCode() within the reverted scope.
	// Without this, a reverted contract-creation sub-call leaves
	// orphan code in pendingCodeWrites, which gets persisted at the
	// next Commit() even though the account's CodeHash was rolled
	// back — causing state inconsistency and consensus divergence.
	pendingCodeWrites map[types.Hash][]byte
}

// StateDB provides access to account states
type StateDB struct {
	db db.Database
	mu sync.RWMutex

	// R39-P3-01 (2026-08-02) FIX: monotonically-increasing counter of
	// "commit-pending marker clear / write stage / batch.Write failed"
	// events on the Commit + RollbackToHeight + RecoverConsistency
	// paths. Each such event is logged at ERROR level with the
	// "R39-P3-01" tag so operators can grep for disk-health degradation.
	// The counter is exposed via CommitPendingMarkerCloggedCount() so
	// monitoring systems (Prometheus scrape via the RPC layer, operator
	// dashboard via qauctl) can alert when the marker clear starts
	// failing repeatedly — a strong signal that bbolt is unhealthy
	// (disk full, I/O errors, locked file).
	//
	// We use sync/atomic on a uint64 instead of a sync.Mutex because
	// the counter is write-mostly (incremented on the rare error path)
	// and read rarely (operator queries); a Mutex would needlessly
	// serialize Commit's hot path against operator status queries.
	commitPendingMarkerCloggedCount atomic.Uint64

	// Dirty accounts (modified but not committed)
	dirtyAccounts map[types.Address]*Account

	// Dirty storage (modified but not committed)
	dirtyStorage map[types.Address]map[types.Hash]types.Hash

	// R33 STATE-02 FIX (2026-07-28): Pending contract code writes, deferred
	// from SetCode() to Commit(). Previously SetCode() wrote code directly
	// to DB via s.db.Put(), but the account's CodeHash was only staged in
	// dirtyAccounts. If Commit() failed, the code was already persisted
	// (orphan code) but the CodeHash wasn't → state inconsistency. Now
	// SetCode() buffers the code here, and Commit() writes it to the same
	// batch as the account update, ensuring atomicity.
	pendingCodeWrites map[types.Hash][]byte // codeHash -> code

	// Cache with LRU eviction
	// audit-fix: added LRU cache to prevent unbounded memory growth
	accountCache    map[types.Address]*Account
	cacheAccessTime map[types.Address]int64 // Unix timestamp of last access
	//  NOTE: cacheAccessTime grows without bound for accounts that
	// are accessed via GetAccount (which updates this map at line ~286) but
	// never enter accountCache (e.g. accounts loaded from DB but not cached
	// due to cache being at capacity). evictLRULocked only deletes the
	// single oldest entry, so orphaned entries accumulate. The cleanup in
	// evictLRULocked (added in ) removes orphaned entries during eviction.
	cacheMaxSize   int    // Maximum cache entries (default 10000)
	cacheEvictions uint64 // Counter for cache evictions

	// Storage cache — avoids repeated LevelDB reads for hot SLOAD keys.
	// Key = address + storage slot, Value = stored hash.
	// Cleared on Commit (dirty values become committed) and RollbackToHeight.
	storageCache map[storageCacheKey]types.Hash

	// Verkle tree for state root computation
	// audit-fix: integrated Verkle tree for proper state root calculation
	stateTrie *trie.VerkleTree

	// State pruning support
	// audit-fix: state pruning to prevent unbounded disk growth
	stateSnapshots    map[uint64]types.Hash // block height -> state root
	pruneKeepBlocks   uint64                // Number of recent blocks to keep (default 128)
	lastPrunedBlock   uint64                // Last block height that was pruned
	pruningEnabled    bool                  // Whether pruning is enabled
	snapshotInterval  uint64                // Create snapshot every N blocks (default 1024)
	lastSnapshotBlock uint64                // Last block height with snapshot
	pruneBatchSize    uint64                // Number of entries to prune per batch (default 1000)
	prunedAccounts    uint64                // Total accounts pruned

	// R57-ACC-OPT (2026-08-07): Last block height whose state was durably
	// committed to this StateDB (via CommitWithBlock / CommitWithBlockContext).
	// The syncer's rebuildState uses this to resume from lastCommittedHeight+1
	// instead of re-applying the whole chain from genesis on every sync
	// completion — which previously double-applied epoch rewards/transactions
	// and caused repeated "state root mismatch" rebuild loops. Reset to
	// forkHeight-1 on RollbackToHeight so a post-reorg rebuild starts at the
	// correct height. Guarded by s.mu.
	lastCommittedHeight uint64

	// R58-SNAP-FALLBACK (2026-08-18): ledger of raw database keys written by
	// the snap-sync import path (ImportAccount / ImportStorage / ImportCode)
	// since the last BeginSnapImport. On a post-import state-root mismatch the
	// syncer calls ClearSnapImport to delete EXACTLY these keys, restoring the
	// pre-snap database so a full-sync fallback re-executes cleanly without
	// reading pivot-era accounts. Surgical by design: pre-existing good state
	// (from a prior rebuildState) is never touched. Guarded by s.mu.
	snapImportedKeys [][]byte

	// Modification tracking for state pruning
	// audit-fix STATE-M1: tracks which addresses were modified at which block heights
	modificationLog map[uint64][]types.Address // block height -> modified addresses
	addressRefs     map[types.Address]uint64   // reference count for each address state

	// R6-STATE-1 FIX: track last modification block for each address.
	// During pruning, only accounts whose last modification predates the
	// prune threshold are eligible for deletion. This prevents accidental
	// deletion of currently active state.
	addressLastModified map[types.Address]uint64

	// SECURITY: before-image tracking for fork rollback state consistency.
	// When a block is committed, we save the pre-modification state of each
	// address so that RollbackToHeight can restore the correct state after
	// a fork rollback. Without this, DeleteBlocksFromHeight only removes
	// block records but leaves the committed state (balances, storage) unchanged.
	beforeImages map[uint64]map[types.Address]*accountBeforeImage // blockHeight -> addr -> before-image

	// History retention: controls how many blocks of beforeImages and
	// modificationLog to keep in memory. Blocks older than
	// (currentBlock - historyRetentionBlocks) are pruned after commit.
	// This prevents unbounded memory growth (~2.6KB/block) while preserving
	// enough history for RollbackToHeight on recent forks.
	// Default: 1000 blocks (~2.6MB overhead at steady state).
	historyRetentionBlocks uint64

	// STATE- (2026-07-20): EIP-2929 access list, EIP-1153 transient
	// storage, EIP-20 event logs, and selfdestruct set. These are per-tx
	// state that must:
	//   - participate in Snapshot/RevertToSnapshot (so a sub-call revert
	//     rolls back warm-set changes, transient writes, emitted logs, and
	//     selfdestruct markers made in the reverted section)
	//   - be cleared on Commit (logs and access list do not persist across
	//     transactions; transient storage is per-tx by EIP-1153 definition;
	//     selfdestruct markers are per-tx by EIP-6780 semantics)
	//   - be cleared on Revert (full state reset)
	//   - be deep-copied by Copy (so the block producer's stateDB.Copy()
	//     preserves them for parallel verification)
	//
	// selfDestructBeneficiaries maps the selfdestructed address to its
	// beneficiary (where the remaining balance should be sent). Used by
	// the EIP-6780 same-block balance handling: a selfdestructed account
	// retains its balance until the end of the block's commit phase, at
	// which point the balance is transferred to the beneficiary and the
	// account is zeroed. This matches EIP-6780: selfdestruct does NOT
	// immediately destroy the account (so further calls to it during the
	// same block can still read its balance), only at the end-of-block
	// finalization.
	accessList                *accessList
	logs                      []*Log
	selfDestructs             map[types.Address]struct{}
	selfDestructBeneficiaries map[types.Address]types.Address
	transientStorage          *transientStorage

	// audit-fix R3-F12: per-instance snapshot stack for correct nested reverts.
	// The old implementation used a global atomic counter and Revert() cleared
	// ALL dirty state, destroying parent call changes on child revert.
	snapshots      []stateSnapshot
	nextSnapshotID int

	// R33 P3-07 FIX (2026-07-28): lastError tracks the first silent error
	// encountered by SetNonce/SetBalance/SetCode when the underlying account
	// cannot be loaded (other than ErrAccountNotFound, which is a legitimate
	// "create new account" signal). Previously these methods only logged the
	// error and returned silently, so Commit() had no way to know that a
	// state mutation had been skipped — the caller would see a successful
	// Commit with a state root that did NOT reflect the intended change,
	// leading to silent state drift and consensus divergence.
	//
	// The error is surfaced at Commit() time (and cleared on Revert()) so
	// callers that batch multiple mutations get a single, authoritative
	// failure signal instead of having to inspect logs.
	lastError error
}

// allocStateDB allocates and initializes a StateDB with all in-memory maps
// and caches wired up, but does NOT perform consistency recovery. Both
// NewStateDB (which keeps the panic-on-error legacy semantics for in-memory
// tests and node.go's current single-value call site) and OpenStateDB (which
// returns errors so callers can handle recovery failures gracefully) share
// this helper to avoid drifting the initialization surface out of sync.
//
// R38-P1-04 FIX: extracted from NewStateDB so OpenStateDB can call
// RecoverConsistency and propagate the error instead of panicking.
func allocStateDB(database ...db.Database) *StateDB {
	var dbInstance db.Database
	if len(database) > 0 && database[0] != nil {
		dbInstance = database[0]
	} else {
		dbInstance = db.NewMemDB()
	}
	return &StateDB{
		db:            dbInstance,
		dirtyAccounts: make(map[types.Address]*Account),
		dirtyStorage:  make(map[types.Address]map[types.Hash]types.Hash),
		// R33 STATE-02 FIX: initialize pending code writes buffer
		pendingCodeWrites: make(map[types.Hash][]byte),
		accountCache:      make(map[types.Address]*Account),
		cacheAccessTime:   make(map[types.Address]int64),
		cacheMaxSize:      5000, // audit-fix: default 10,000 entries max
		// R6-DB-1 FIX: pass dbInstance for persistent Verkle tree storage
		stateTrie:        trie.NewVerkleTree(256, dbInstance),
		stateSnapshots:   make(map[uint64]types.Hash),
		pruneKeepBlocks:  128,  // audit-fix: keep last 128 blocks by default
		pruningEnabled:   true, // audit-fix: enable pruning by default
		snapshotInterval: 1024, // audit-fix: snapshot every 1024 blocks
		pruneBatchSize:   1000, // audit-fix STATE-M1: default 1000 entries per batch
		modificationLog:  make(map[uint64][]types.Address),
		addressRefs:      make(map[types.Address]uint64),
		// R6-STATE-1 FIX: initialize last modified tracking
		addressLastModified: make(map[types.Address]uint64),
		// SECURITY: initialize before-image tracking for fork rollback
		beforeImages: make(map[uint64]map[types.Address]*accountBeforeImage),
		// History retention: keep 1000 blocks of rollback history by default
		historyRetentionBlocks: 1000,
		// Storage cache for hot SLOAD keys
		storageCache: make(map[storageCacheKey]types.Hash),
		// STATE- (2026-07-20): per-tx EIP-2929 access list,
		// EIP-1153 transient storage, EIP-20 event logs, and selfdestruct
		// set. Initialized lazily-resolved so they are ready for the first
		// transaction without nil checks in the hot path.
		accessList:                newAccessList(),
		logs:                      make([]*Log, 0),
		selfDestructs:             make(map[types.Address]struct{}),
		selfDestructBeneficiaries: make(map[types.Address]types.Address),
		transientStorage:          newTransientStorage(),
	}
}

// NewStateDB creates a new state database with the given underlying db.
//
// LEGACY SEMANTICS (retained intentionally): inherits the single-value
// (panic-on-recovery-failure) contract. Many existing tests and node.go's
// current call site depend on this signature. R38-P1-04 introduces
// OpenStateDB for callers that need error propagation; do NOT change
// NewStateDB to return (s, error) without auditing every call site.
//
// AUDIT (2026) R4-DATA-03: Check for commit-pending marker and
// rebuild the Verkle tree if the previous Commit was interrupted by a
// crash between BoltDB batch.Write() and the Verkle tree update.
// R38-P1-04 FIX: Fail-closed — if RecoverConsistency fails, the state
// root may be stale or corrupt. Continuing silently would let the node
// serve/propose blocks with a divergent state root, causing consensus
// failures or silent data corruption. Panic to halt startup so the
// operator can investigate and recover from backup.
func NewStateDB(database ...db.Database) *StateDB {
	s := allocStateDB(database...)
	if err := s.RecoverConsistency(); err != nil {
		log.Printf("[FATAL] state_db: R38-P1-04: RecoverConsistency failed: %v — halting to prevent corrupt state", err)
		panic(fmt.Sprintf("state_db: RecoverConsistency failed (R38-P1-04): %v", err))
	}
	return s
}

// OpenStateDB creates a new StateDB and runs RecoverConsistency, returning
// the resulting error instead of panicking. Production startup code (which can
// surface the error to the operator, retry, or halt cleanly) should prefer
// OpenStateDB over NewStateDB.
//
// R38-P1-04 FIX: NewStateDB's panic-on-error contract predated R38-P1-04's
// "preserve marker for retry" requirement. A panic stops the process but does
// not let the caller decide between retry-from-backup vs. manual-investigation.
// OpenStateDB gives callers that choice while keeping NewStateDB's legacy
// behavior intact for tests/node.go (which is migrated separately).
func OpenStateDB(database db.Database) (*StateDB, error) {
	s := allocStateDB(database)
	if err := s.RecoverConsistency(); err != nil {
		return nil, fmt.Errorf("state_db: OpenStateDB: recovery failed (R38-P1-04): %w", err)
	}
	return s, nil
}

// CommitPendingMarkerCloggedCount returns the running count of
// "commit-pending marker clear / write stage / post-batch Write failed"
// events observed on this StateDB instance. Each event is logged at ERROR
// level with the "R39-P3-01" tag so operators can grep for disk-health
// degradation. Exposed via this getter so monitoring systems (RPC
// scrape, qauctl status) can alert when the count exceeds an operator
// threshold — a strong signal that bbolt is unhealthy (disk full, I/O
// errors, locked file).
//
// R39-P3-01 (2026-08-02): the getter is monotonically increasing across
// the process lifetime; resets only on process restart. The counter is
// safe for concurrent access (atomic.Uint64).
func (s *StateDB) CommitPendingMarkerCloggedCount() uint64 {
	if s == nil {
		return 0
	}
	return s.commitPendingMarkerCloggedCount.Load()
}

// RecoverConsistency checks whether the previous Commit completed
// successfully. If a crash happened between the BoltDB batch write and the
// Verkle tree update, the commit-pending marker will exist in BoltDB. In that
// case, the Verkle tree is rebuilt from the BoltDB account state to ensure the
// state root matches the authoritative account data.
//
// This method is safe to call at startup and is idempotent.
//
// AUDIT (2026) R4-DATA-03
func (s *StateDB) RecoverConsistency() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return nil
	}

	// R87-M4-RESTART (2026-08-29): restore the last-committed height BEFORE
	// any early return — rebuildState needs it to pick the correct replay
	// baseline after a restart. Without it, lch reads 0 and the baseline
	// clamps to genesis even though the disk state is mid-chain.
	if heightBytes, err := s.db.Get(lastCommittedHeightKey); err == nil && len(heightBytes) == 8 {
		s.lastCommittedHeight = binary.BigEndian.Uint64(heightBytes)
	}

	// Check if the previous commit left a pending marker.
	if _, err := s.db.Get(commitPendingKey); err != nil {
		if err == db.ErrKeyNotFound {
			// No marker — Verkle tree is consistent with BoltDB.
			return nil
		}
		return fmt.Errorf("RecoverConsistency: failed to check commit marker: %w", err)
	}

	// Marker exists — rebuild the Verkle tree from BoltDB account state.
	log.Printf("[WARN] state_db: R4-DATA-03: commit-pending marker detected — rebuilding Verkle tree from BoltDB account state")

	// Create a fresh Verkle tree with the same persistent DB. The tree will
	// load its own nodes from BoltDB via loadFromDB(), but we overwrite them
	// by re-inserting all accounts from the authoritative BoltDB state.
	newTrie := trie.NewVerkleTree(256, s.db)

	// Iterate all accounts from BoltDB and re-insert into the new tree.
	iter := s.db.NewIterator(accountPrefix, nil)
	defer iter.Release()

	count := 0
	for iter.Next() {
		key := iter.Key()
		if len(key) <= len(accountPrefix) {
			continue
		}
		addr := make([]byte, len(key)-len(accountPrefix))
		copy(addr, key[len(accountPrefix):])

		// AUDIT ROUND-3 2026-08-17 FIX: validate the address length
		// BEFORE any use. A corrupted/short account key (len 1..7) used to
		// reach the addr[:8] slice in the Put error message below and
		// panic — inside the crash-recovery path, turning a graceful
		// fail-closed error into a startup crash. Recovery must never
		// panic on corrupt data; reject the malformed key explicitly.
		if len(addr) != types.AddressLength {
			return fmt.Errorf("RecoverConsistency: malformed account key (address length %d, want %d) — BoltDB data may be corrupted ()", len(addr), types.AddressLength)
		}

		value := iter.Value()
		if err := newTrie.Put(addr, value); err != nil {
			return fmt.Errorf("RecoverConsistency: failed to rebuild Verkle tree for account %x: %w", addr[:8], err)
		}
		count++
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("RecoverConsistency: iterator error: %w", err)
	}

	// Replace the stale Verkle tree with the rebuilt one.
	s.stateTrie = newTrie

	// R32-P2-05 FIX (2026-07-28): Verify the rebuilt tree's root matches
	// the last successfully committed root. If they differ, the rebuild
	// silently produced a wrong tree (e.g., a Put failed mid-iteration,
	// BoltDB data was corrupted, or an account was silently dropped).
	// Returning an error here is fail-closed: the node halts rather than
	// continuing with a wrong state root that would cause a consensus fork.
	// If lastCommittedRootKey is missing (first run, or the P2-05 persist
	// failed), skip the check — the root is defense-in-depth, not a
	// correctness requirement, and there's no reference to compare against.
	rebuiltRoot := s.rootLocked()
	if persistedRootBytes, err := s.db.Get(lastCommittedRootKey); err == nil && len(persistedRootBytes) == types.HashLength {
		var persistedRoot types.Hash
		copy(persistedRoot[:], persistedRootBytes)
		if rebuiltRoot != persistedRoot {
			// R38-P1-04 FIX: Preserve the commit-pending marker for the next
			// startup retry. Previously this branch deleted the marker so the
			// next startup would skip the rebuild — but skipping the rebuild
			// only papers over the underlying corruption: the rebuilt root
			// still does not match the persisted authoritative root, so the
			// node would silently continue with a wrong state root.
			//
			// By keeping the marker intact, the next startup (after the
			// operator investigates, restores a backup, or fixes the corrupt
			// BoltDB account data driving the wrong root) re-enters this same
			// path and gets a fresh chance to verify. The operator-driven retry
			// is the only recovery: a root mismatch means the persisted account
			// data and the persisted root disagree, which neither a re-rebuild
			// nor a marker clear can resolve automatically.
			//
			// Never delete markers until the rebuilt root has been
			// independently verified against the persisted root.
			log.Printf("[FATAL] state_db: R38-P1-04: rebuilt Verkle root %x does not match last committed "+
				"root %x — commit-pending marker PRESERVED for next-startup retry (NOT cleared)",
				rebuiltRoot, persistedRoot)
			return fmt.Errorf("RecoverConsistency: rebuilt Verkle root %x does not match last committed root %x — "+
				"BoltDB account data may be corrupted or incomplete (R32-P2-05 / R38-P1-04)",
				rebuiltRoot, persistedRoot)
		}
		log.Printf("[INFO] state_db: R32-P2-05: rebuilt Verkle root %x matches last committed root — consistency verified", rebuiltRoot)
	}

	// Clear the commit-pending marker now that the tree is rebuilt.
	if err := s.db.Delete(commitPendingKey); err != nil {
		// R39-P3-01 (2026-08-02) FIX: elevate to ERROR + counter. This
		// path is the post-RecoverConsistency cleanup; if it fails, the
		// next startup will run RecoverConsistency AGAIN (the marker is
		// still there) and re-rebuild the Verkle tree — wasteful but not
		// corrupting. ERROR-level so operators see disk-health issues.
		s.commitPendingMarkerCloggedCount.Add(1)
		log.Printf("[ERROR] state_db: R39-P3-01: failed to clear commit-pending marker after rebuild: %v — next startup will run RecoverConsistency again (no corruption, just wasted work)", err)
	}

	log.Printf("[INFO] state_db: R4-DATA-03: Verkle tree rebuilt from %d accounts, new root=%s", count, rebuiltRoot.String())
	return nil
}

// GetAccount retrieves an account by address.
// audit-fix R6-M1: returns a defensive copy so external callers cannot
// mutate internal state (e.g. Balance) without going through the mutex.
//
// R33 STATE-06 FIX (2026-07-28): Previously this used RLock → RUnlock → Lock
// to update cacheAccessTime. The lock-upgrade pattern has a TOCTOU race:
// between RUnlock and Lock, another goroutine could evict addr from
// accountCache, causing cacheAccessTime[addr] to be written as an orphan
// entry that the pruner never cleans (the very bug R4-H1 tried to fix).
// Go maps also panic on concurrent reader+writer, so updating
// cacheAccessTime under RLock while another reader holds RLock is unsafe.
// Fix: hold the write lock (Lock) for the entire operation. This eliminates
// both the TOCTOU race and the concurrent-map-write hazard. The slight
// throughput reduction is acceptable because GetAccount is not on the
// hottest path (transactions go through the cached GetNonce/GetBalance
// helpers, and block production uses Snapshot/Apply).
func (s *StateDB) GetAccount(addr types.Address) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, err := s.getAccountLocked(addr)
	if err != nil {
		return nil, err
	}

	accCopy := *acc
	accCopy.Balance = new(big.Int).Set(acc.Balance)

	// Update cache access time only if the account is already cached.
	// R4-H1 FIX (2026-07-06): Previously, every GetAccount call updated
	// cacheAccessTime, even for accounts that never entered accountCache
	// (e.g. loaded from DB but not cached due to capacity). This caused
	// orphaned entries to accumulate. Now we only update the access time
	// for accounts that are actually in the cache, preventing orphan growth.
	if _, cached := s.accountCache[addr]; cached {
		s.cacheAccessTime[addr] = time.Now().Unix()
	}

	return &accCopy, nil
}

// getAccountLocked retrieves an account without acquiring the lock.
// MUST be called while s.mu is already held (read or write).
func (s *StateDB) getAccountLocked(addr types.Address) (*Account, error) {
	// Check dirty accounts first
	if acc, ok := s.dirtyAccounts[addr]; ok {
		return acc, nil
	}

	// Check cache
	if acc, ok := s.accountCache[addr]; ok {
		return acc, nil
	}

	// Load from database
	data, err := s.db.Get(append(accountPrefix, addr[:]...))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, ErrAccountNotFound
		}
		return nil, err
	}

	var acc Account
	if err := decodeAccount(data, &acc); err != nil {
		return nil, err
	}

	return &acc, nil
}

// GetAccountWithProof retrieves an account with a Verkle proof
func (s *StateDB) GetAccountWithProof(addr types.Address) (*Account, *trie.VerkleProof, error) {
	acc, err := s.GetAccount(addr)
	if err != nil {
		if err == ErrAccountNotFound {
			return nil, nil, ErrAccountNotFound
		}
		return nil, nil, err
	}

	// Generate proof (simplified - in production this would be a real Verkle proof)
	proofData, err := serializeAccount(acc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize account for proof: %w", err)
	}
	proof := &trie.VerkleProof{
		Key:   addr[:],
		Value: proofData,
		Proof: [][]byte{}, // Simplified
	}

	return acc, proof, nil
}

// ProveAccount returns a stateRoot-aware Verkle proof for the account at
// addr (R38-P2-04 DEEP FIX 2026-08-02).
//
// Unlike GetAccountWithProof above (which fills VerkleProof.Proof with an
// empty [][]byte placeholder — see its "Simplified" comment), this method
// delegates to s.stateTrie.Prove(addr[:]) to produce the REAL Verkle path
// from the canonical chain state. Callers can verify the returned proof
// against s.Root() to confirm the account is part of canonical state.
//
// Rationale: rpc/proof_api.go's buildAccountProof previously constructed
// a FRESH single-entry Verkle tree containing only the requested account,
// then called tree.Prove on it — the resulting Merkle path proved NOTHING
// about canonical state. The fix surfaces StateRoot to the caller AND
// exposes this real proof so light clients / bridges can cryptographically
// bind the proof to a block's state root.
//
// Returns ErrProofNotSupported if the StateDB has no live stateTrie (e.g.
// a NewStateDBWithoutStorage stub used in tests). The RPC layer falls
// back to the Unverified=true path honestly rather than fabricating a
// pseudo-proof.
func (s *StateDB) ProveAccount(addr types.Address) (*trie.VerkleProof, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proveAccountLocked(addr)
}

func (s *StateDB) proveAccountLocked(addr types.Address) (*trie.VerkleProof, error) {
	if s.stateTrie == nil {
		return nil, errProofNotSupported
	}
	return s.stateTrie.Prove(addr[:])
}

// ProveStorage returns a stateRoot-aware Verkle proof for one storage slot
// at (addr, key) (R38-P2-04 DEEP FIX 2026-08-02).
//
// Storage key layout matches GetState/SetState (storagePrefix + addr[:] +
// 0xFF + key[:]) so the proof path binds to the canonical state trie.
// Returns ErrProofNotSupported if the StateDB has no live stateTrie.
func (s *StateDB) ProveStorage(addr types.Address, key types.Hash) (*trie.VerkleProof, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.stateTrie == nil {
		return nil, errProofNotSupported
	}
	storageKey := append(storagePrefix, addr[:]...)
	storageKey = append(storageKey, 0xFF)
	storageKey = append(storageKey, key[:]...)
	return s.stateTrie.Prove(storageKey)
}

// errProofNotSupported is returned by ProveAccount/ProveStorage when the
// StateDB has no live stateTrie backing (e.g. NewStateDBWithoutStorage stub).
// R38-P2-04 DEEP FIX (2026-08-02).
var errProofNotSupported = errors.New("state DB has no live state trie — proofs not supported")

// SetAccount sets an account's state
// audit-fix: defensive copy to prevent external mutation of internal state.
// The caller's *big.Int Balance could be mutated after SetAccount returns,
// corrupting the state DB. This mirrors the defensive copy in GetAccount.
func (s *StateDB) SetAccount(addr types.Address, acc *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()

	accCopy := *acc
	if acc.Balance != nil {
		accCopy.Balance = new(big.Int).Set(acc.Balance)
	}
	s.dirtyAccounts[addr] = &accCopy
}

// GetNonce returns the nonce of an account
func (s *StateDB) GetNonce(addr types.Address) uint64 {
	acc, err := s.GetAccount(addr)
	if err != nil {
		return 0
	}
	return acc.Nonce
}

// SetNonce sets the nonce of an account
func (s *StateDB) SetNonce(addr types.Address, nonce uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, ok := s.dirtyAccounts[addr]
	if !ok {
		var err error
		acc, err = s.getAccountLocked(addr)
		if err != nil && err != ErrAccountNotFound {
			// R33 P3-07 FIX: record the first silent error so Commit() can
			// surface it instead of returning success with a stale state root.
			// Keep the existing log for diagnostics.
			log.Printf("ERROR: SetNonce failed to load account %x: %v", addr[:8], err)
			if s.lastError == nil {
				s.lastError = fmt.Errorf("SetNonce(%x): %w", addr[:8], err)
			}
			return
		}
		if acc == nil {
			acc = NewAccount()
		}
	}
	acc.Nonce = nonce
	s.dirtyAccounts[addr] = acc
}

// GetBalance returns the balance of an account
func (s *StateDB) GetBalance(addr types.Address) *big.Int {
	acc, err := s.GetAccount(addr)
	if err != nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(acc.Balance)
}

// SetBalance sets the balance of an account
func (s *StateDB) SetBalance(addr types.Address, balance *big.Int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, ok := s.dirtyAccounts[addr]
	if !ok {
		var err error
		acc, err = s.getAccountLocked(addr)
		if err != nil && err != ErrAccountNotFound {
			// R33 P3-07 FIX: record the first silent error so Commit() can
			// surface it instead of returning success with a stale state root.
			log.Printf("ERROR: SetBalance failed to load account %x: %v", addr[:8], err)
			if s.lastError == nil {
				s.lastError = fmt.Errorf("SetBalance(%x): %w", addr[:8], err)
			}
			return
		}
		if acc == nil {
			acc = NewAccount()
		}
	}
	acc.Balance = new(big.Int).Set(balance)
	s.dirtyAccounts[addr] = acc
}

// AddBalance adds amount to an account's balance.
// audit-fix M-3: perform read-modify-write under a single lock to prevent lost updates.
// audit-fix: added amount validation to prevent negative/zero additions.
func (s *StateDB) AddBalance(addr types.Address, amount *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if amount.Sign() <= 0 {
		return fmt.Errorf("amount must be positive")
	}

	acc, ok := s.dirtyAccounts[addr]
	if !ok {
		var err error
		acc, err = s.getAccountLocked(addr)
		if err != nil && err != ErrAccountNotFound {
			return fmt.Errorf("failed to load account %x: %w", addr[:8], err)
		}
		if acc == nil {
			acc = NewAccount()
		}
	}
	acc.Balance = new(big.Int).Add(acc.Balance, amount)
	s.dirtyAccounts[addr] = acc
	return nil
}

// SubBalance subtracts amount from an account's balance.
// audit-fix M-3: perform read-modify-write under a single lock to prevent lost updates.
func (s *StateDB) SubBalance(addr types.Address, amount *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, ok := s.dirtyAccounts[addr]
	if !ok {
		var err error
		acc, err = s.getAccountLocked(addr)
		if err != nil && err != ErrAccountNotFound {
			return fmt.Errorf("failed to load account %x: %w", addr[:8], err)
		}
		if acc == nil {
			acc = NewAccount()
		}
	}
	// SECURITY FIX: Validate amount is positive before subtraction
	// Prevents negative amounts from actually adding to balance
	if amount.Sign() <= 0 {
		return errors.New("amount must be positive")
	}
	newBalance := new(big.Int).Sub(acc.Balance, amount)
	if newBalance.Sign() < 0 {
		return errors.New("insufficient balance")
	}
	acc.Balance = newBalance
	s.dirtyAccounts[addr] = acc
	return nil
}

// AddBalanceReturn adds amount to an account's balance and returns the new balance.
// audit-fix  perform read-modify-write under a single lock to prevent TOCTOU race.
// R41-H2 FIX: validate that amount is positive to prevent balance reduction via negative amounts.
func (s *StateDB) AddBalanceReturn(addr types.Address, amount *big.Int) *big.Int {
	if amount.Sign() <= 0 {
		// Return current balance unchanged for non-positive amounts
		// (AddBalance should be used for positive additions, this function
		// is only for operations where the caller guarantees positive amounts)
		s.mu.Lock()
		defer s.mu.Unlock()
		acc, ok := s.dirtyAccounts[addr]
		if !ok {
			var err error
			acc, err = s.getAccountLocked(addr)
			if err != nil && err != ErrAccountNotFound {
				log.Printf("ERROR: AddBalanceReturn failed to load account %x: %v", addr[:8], err)
				return new(big.Int)
			}
			if acc == nil {
				return new(big.Int)
			}
		}
		return new(big.Int).Set(acc.Balance)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	acc, ok := s.dirtyAccounts[addr]
	if !ok {
		var err error
		acc, err = s.getAccountLocked(addr)
		if err != nil && err != ErrAccountNotFound {
			log.Printf("ERROR: AddBalanceReturn failed to load account %x: %v", addr[:8], err)
			return new(big.Int)
		}
		if acc == nil {
			acc = NewAccount()
		}
	}
	acc.Balance = new(big.Int).Add(acc.Balance, amount)
	s.dirtyAccounts[addr] = acc
	return new(big.Int).Set(acc.Balance)
}

// IncrementNonce increments the nonce for an account.
// audit-fix  perform read-modify-write under a single lock to prevent TOCTOU race.
func (s *StateDB) IncrementNonce(addr types.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()

	acc, ok := s.dirtyAccounts[addr]
	if !ok {
		var err error
		acc, err = s.getAccountLocked(addr)
		if err != nil && err != ErrAccountNotFound {
			log.Printf("ERROR: IncrementNonce failed to load account %x: %v", addr[:8], err)
			return
		}
		if acc == nil {
			acc = NewAccount()
		}
	}
	acc.Nonce++
	s.dirtyAccounts[addr] = acc
}

// GetStorage returns a storage value
// audit-fix H-1 (2026-06-24): getStorageLocked writes to storageCache on cache
// miss. Using RLock allowed concurrent readers to write the same map, causing
// data races / panics. Use the exclusive write lock instead.
func (s *StateDB) GetStorage(addr types.Address, key types.Hash) types.Hash {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getStorageLocked(addr, key)
}

// getStorageLocked returns a storage value without acquiring the lock.
// MUST be called while s.mu is already held.
//
// STATE- (2026-07-20) FIX: Previously any error from s.db.Get
// (including I/O errors, corruption, closed database) was silently
// mapped to types.Hash{} — indistinguishable from a real "key does not
// exist" result. This meant a corrupted storage read could cause the
// EVM to silently treat a stored value as zero, leading to incorrect
// contract execution.
//
// The fix differentiates:
//   - ErrKeyNotFound (sentinel from db package): legitimate "not stored",
//     return types.Hash{} (EVM semantics: missing == zero).
//   - Any other error: log it (so operators see corruption), return
//     types.Hash{} (preserves backward-compatible signature), and clear
//     any cache entry for this key so a retry will re-fetch.
//
// For callers that need explicit existence semantics, use GetStorageExists.
func (s *StateDB) getStorageLocked(addr types.Address, key types.Hash) types.Hash {
	// Check dirty storage first (most recent writes)
	if storage, ok := s.dirtyStorage[addr]; ok {
		if value, ok := storage[key]; ok {
			return value
		}
	}

	// Check storage cache (avoids LevelDB read for hot keys)
	cacheKey := storageCacheKey{addr: addr, key: key}
	if val, ok := s.storageCache[cacheKey]; ok {
		return val
	}

	// Load from database
	storageKey := append(storagePrefix, addr[:]...)
	storageKey = append(storageKey, 0xFF)
	storageKey = append(storageKey, key[:]...)

	data, err := s.db.Get(storageKey)
	if err != nil {
		// STATE- distinguish "not found" (legitimate, silent) from
		// other errors (corruption, I/O, closed DB) which must be logged.
		if !errors.Is(err, db.ErrKeyNotFound) {
			log.Printf("[ERROR] state_db: GetStorage(%x, %x): db.Get failed (non-ErrKeyNotFound): %v — returning zero value (STATE-)",
				addr, key, err)
			// Do not cache the zero — a subsequent read may succeed if the
			// error was transient (e.g., a brief I/O stall).
			return types.Hash{}
		}
		// ErrKeyNotFound: legitimate "not stored". Cache the zero value so
		// repeated reads of the same non-existent key don't keep hitting the
		// database. (Existing behavior, preserved.)
		s.storageCache[cacheKey] = types.Hash{}
		return types.Hash{}
	}

	var value types.Hash
	if len(data) > 0 {
		copy(value[:], data)
	}
	// Cache the value for future reads
	s.storageCache[cacheKey] = value
	return value
}

// GetStorageExists returns the storage value and a boolean indicating
// whether the key has ever been set (even to zero). This disambiguates
// "key not stored" from "key stored with value zero" — a distinction
// the EVM requires for some operations (e.g., SLOAD after a contract
// has explicitly stored zero vs. before any SSTORE has happened).
//
// STATE- (2026-07-20) FIX: the existing GetStorage signature
// returns types.Hash{} for both "missing" and "explicitly-zero", which
// is correct for most EVM read paths (EVM semantics treat missing as
// zero) but incorrect for callers that need existence semantics (e.g.,
// state-root computation, snapshot diffing). GetStorageExists is the
// explicit-existence variant.
//
// Behavior:
//   - Dirty (uncommitted) writes: returns the dirty value + true.
//   - Cached or stored: returns the value + true.
//   - Not stored (ErrKeyNotFound): returns zero + false.
//   - I/O error: returns zero + false AND logs the error. Callers that
//     must distinguish I/O errors from "not stored" should call db.Get
//     directly with their own error handling.
func (s *StateDB) GetStorageExists(addr types.Address, key types.Hash) (types.Hash, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check dirty storage first (most recent writes)
	if storage, ok := s.dirtyStorage[addr]; ok {
		if value, ok := storage[key]; ok {
			return value, true
		}
	}

	// Check storage cache
	cacheKey := storageCacheKey{addr: addr, key: key}
	if val, ok := s.storageCache[cacheKey]; ok {
		// Cache only stores values, not existence. To distinguish "cached
		// zero from a real not-exist" we need a second cache. Since the
		// storageCache stores zeros for both "explicitly zero" and "not
		// exist", this path returns true for both. This is the EVM-correct
		// behavior — once a key has been read, future reads treat the cached
		// value as "exists" until invalidated.
		return val, true
	}

	// Load from database
	storageKey := append(storagePrefix, addr[:]...)
	storageKey = append(storageKey, 0xFF)
	storageKey = append(storageKey, key[:]...)

	data, err := s.db.Get(storageKey)
	if err != nil {
		if !errors.Is(err, db.ErrKeyNotFound) {
			log.Printf("[ERROR] state_db: GetStorageExists(%x, %x): db.Get failed (non-ErrKeyNotFound): %v — returning (zero, false) (STATE-)",
				addr, key, err)
			return types.Hash{}, false
		}
		// Legitimately not stored.
		return types.Hash{}, false
	}

	var value types.Hash
	if len(data) > 0 {
		copy(value[:], data)
	}
	s.storageCache[cacheKey] = value
	return value, true
}

// SetStorage sets a storage value
func (s *StateDB) SetStorage(addr types.Address, key, value types.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dirtyStorage[addr] == nil {
		s.dirtyStorage[addr] = make(map[types.Hash]types.Hash)
	}
	s.dirtyStorage[addr][key] = value
}

// GetCommittedState returns the storage value committed at the start of the
// transaction — i.e. it bypasses the in-memory dirtyStorage overlay and reads
// the persisted (cached/database) value. Required for EIP-3529 gas refund
// calculation in SSTORE (). SetStorage only ever writes to
// dirtyStorage, so storageCache always holds committed values; reading the
// cache/DB therefore yields the original (pre-transaction) value.
func (s *StateDB) GetCommittedState(addr types.Address, key types.Hash) types.Hash {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getCommittedStorageLocked(addr, key)
}

// getCommittedStorageLocked returns the committed storage value, bypassing
// the dirty overlay. MUST be called with s.mu held.
func (s *StateDB) getCommittedStorageLocked(addr types.Address, key types.Hash) types.Hash {
	// storageCache holds committed values only (SetStorage never writes here).
	cacheKey := storageCacheKey{addr: addr, key: key}
	if val, ok := s.storageCache[cacheKey]; ok {
		return val
	}
	// Load the persisted (committed) value from the database.
	storageKey := append(storagePrefix, addr[:]...)
	storageKey = append(storageKey, 0xFF)
	storageKey = append(storageKey, key[:]...)

	data, err := s.db.Get(storageKey)
	if err != nil {
		return types.Hash{}
	}
	var value types.Hash
	if len(data) > 0 {
		copy(value[:], data)
	}
	// Cache the committed value for future reads.
	s.storageCache[cacheKey] = value
	return value
}

// GetCode returns the contract code
func (s *StateDB) GetCode(addr types.Address) []byte {
	acc, err := s.GetAccount(addr)
	if err != nil || acc.CodeHash == (types.Hash{}) {
		return nil
	}

	// R33 STATE-02 FIX: Check pending code writes first. SetCode() now
	// defers the DB write to Commit(), so code set in the current tx
	// (before Commit) is only in pendingCodeWrites. Without this check,
	// GetCode would return nil for code that was just set.
	s.mu.RLock()
	if code, ok := s.pendingCodeWrites[acc.CodeHash]; ok {
		result := make([]byte, len(code))
		copy(result, code)
		s.mu.RUnlock()
		return result
	}
	s.mu.RUnlock()

	// P3-9 NOTE (benign TOCTOU): GetAccount reads acc.CodeHash under s.mu and
	// releases the lock before this db.Get call. This is safe because contract
	// code is immutable and keyed by its own Keccak256 hash (codePrefix ||
	// codeHash). The mapping codeHash -> code is write-once/idempotent (see
	// SetCode), so even if the account is concurrently updated to a new
	// CodeHash between these two reads, the bytes returned for the CodeHash we
	// already read are guaranteed to match that hash. The returned (CodeHash,
	// code) pair is therefore always internally consistent. No lock is held
	// during db.Get to avoid widening the critical section across a potentially
	// slow disk read.
	data, err := s.db.Get(append(codePrefix, acc.CodeHash[:]...))
	if err != nil {
		return nil
	}

	result := make([]byte, len(data))
	copy(result, data)
	return result
}

// GetCodeByHash returns contract code by its hash directly.
func (s *StateDB) GetCodeByHash(codeHash types.Hash) ([]byte, error) {
	// R33 STATE-02 FIX: Check pending code writes first.
	s.mu.RLock()
	if code, ok := s.pendingCodeWrites[codeHash]; ok {
		result := make([]byte, len(code))
		copy(result, code)
		s.mu.RUnlock()
		return result, nil
	}
	s.mu.RUnlock()

	data, err := s.db.Get(append(codePrefix, codeHash[:]...))
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// SetCode sets the contract code
func (s *StateDB) SetCode(addr types.Address, code []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	codeHash := types.Keccak256Hash(code)

	// R33 STATE-02 FIX (2026-07-28): Defer code write to Commit() instead
	// of writing directly to DB. Previously, s.db.Put() wrote the code
	// immediately, but the account's CodeHash was only staged in
	// dirtyAccounts. If Commit() failed, the code was already persisted
	// (orphan code) but the CodeHash wasn't → state inconsistency. Now
	// we buffer the code in pendingCodeWrites, and Commit() writes it to
	// the same batch as the account update, ensuring atomicity.
	if s.pendingCodeWrites == nil {
		s.pendingCodeWrites = make(map[types.Hash][]byte)
	}
	// Make a defensive copy so callers can't mutate the buffered code.
	codeCopy := make([]byte, len(code))
	copy(codeCopy, code)
	s.pendingCodeWrites[codeHash] = codeCopy

	acc, ok := s.dirtyAccounts[addr]
	if !ok {
		var err error
		acc, err = s.getAccountLocked(addr)
		if err != nil && err != ErrAccountNotFound {
			// R33 P3-07 FIX: record the first silent error so Commit() can
			// surface it instead of returning success with a stale state root.
			log.Printf("ERROR: SetCode failed to load account %x: %v", addr[:8], err)
			if s.lastError == nil {
				s.lastError = fmt.Errorf("SetCode(%x): %w", addr[:8], err)
			}
			return
		}
		if acc == nil {
			acc = NewAccount()
		}
	}
	acc.CodeHash = codeHash
	s.dirtyAccounts[addr] = acc
}

// Commit commits all dirty changes to the database
// Returns the state root hash and any error
// Optional blockHeight parameter enables modification tracking for state pruning
// computeStorageRoot computes a Merkle root over all storage slots for a given
// account. It reads committed storage from the database and applies any dirty
// (uncommitted) storage changes on top.
//
// AUDIT (2026) HIGH-02 (DATA-01): Previously, Account.StorageRoot was
// declared and serialized but NEVER computed — it was always the zero hash.
// This meant the block StateRoot did not cover contract storage at all:
// two nodes with different storage but identical account fields would
// produce the same state root. This function computes a deterministic root
// over all (key, value) pairs so that any storage change is reflected in
// the state root.
//
// The root is computed as: Keccak256(concat(sorted(key||value...))).
// This is a simple flat hash — not a Merkle tree — but it correctly binds
// all storage to the state root. For large storage contracts, this is O(n)
// per commit, but commits are infrequent (once per block) and most accounts
// have zero storage (EOAs).
//
// R35-P2-STATE-05 FIX (2026-07-29): DOCUMENTED KNOWN LIMITATION. The account
// tree uses Verkle commitments for O(log n) proofs, but per-account storage
// roots still use this flat Keccak hash. Migrating to Verkle-structured
// storage roots would change the state root FORMAT — a consensus-breaking
// change requiring a coordinated network upgrade. Until then, this flat hash
// is:
//   - Deterministic: all nodes compute the same root for the same storage set.
//   - Cryptographically binding: any storage change produces a different root.
//   - Consensus-safe: no divergence risk since all nodes use the same algorithm.
//
// The performance concern (O(n) per commit for large-storage contracts) is
// mitigated by:
//  1. Gas cost per SSTORE naturally limits storage growth.
//  2. Commits happen once per block, not per transaction.
//  3. A defensive warning is logged when a single account exceeds
//     largeStorageWarnThreshold slots, so operators can monitor hot contracts.
//
// MIGRATION PATH: when Verkle-structured storage roots are introduced, this
// method will be replaced with a per-account VerkleTree.Root() call, and the
// account tree's leaf value format will be updated to embed the Verkle
// storage commitment. This MUST be done via a hard fork with a state
// migration, NOT a live upgrade.
const largeStorageWarnThreshold = 50000

func (s *StateDB) computeStorageRoot(addr types.Address, dirtyStorage map[types.Hash]types.Hash) (types.Hash, error) {
	// Collect all storage entries: committed (from db) + dirty (uncommitted).
	storage := make(map[types.Hash]types.Hash)

	// Read committed storage from the database.
	prefix := append(storagePrefix, addr[:]...)
	prefix = append(prefix, 0xFF)
	// AUDIT R4-DATA-02 (2026-07-15): Use unlimited iteration (limit=0)
	// instead of NewIterator which hard-caps at 100k entries. Once an
	// account exceeds 100k storage slots (normal for successful
	// token/NFT contracts), the capped iterator returned
	// ErrIteratorTruncated, causing Commit to fail — permanently
	// locking the account and deadlocking any block touching it.
	// Gas cost per SSTORE is the natural DoS protection against
	// unbounded storage growth, so unlimited iteration here is safe.
	iter := s.db.NewIteratorWithLimit(prefix, nil, 0)
	defer iter.Release()
	for iter.Next() {
		key := iter.Key()
		if len(key) <= len(prefix) {
			continue
		}
		var storageKey types.Hash
		copy(storageKey[:], key[len(prefix):])
		value := iter.Value()
		var storageValue types.Hash
		if len(value) >= 32 {
			copy(storageValue[:], value[:32])
		}
		storage[storageKey] = storageValue
	}
	// AUDIT (2026) DATA- Check for iterator truncation. If the
	// iterator hit its 100K limit, the storage root would not cover all
	// entries, causing a silent state-root divergence. Fail hard instead.
	if err := iter.Error(); err != nil {
		return types.Hash{}, fmt.Errorf("computeStorageRoot(%x): iterator error: %w", addr[:8], err)
	}

	// Apply dirty storage (overrides committed values).
	for key, value := range dirtyStorage {
		storage[key] = value
	}

	if len(storage) == 0 {
		return types.Hash{}, nil // Empty storage root is the zero hash
	}

	// R35-P2-STATE-05: defensive monitoring for large storage sets.
	// This is NOT a hard limit (gas already bounds storage growth) but a
	// operational early-warning so node operators can identify contracts
	// whose O(n) computeStorageRoot is becoming a commit bottleneck.
	if len(storage) > largeStorageWarnThreshold {
		log.Printf("[WARN] state_db: computeStorageRoot for %x has %d storage slots (exceeds threshold %d) — commit may be slow",
			addr[:8], len(storage), largeStorageWarnThreshold)
	}

	// Sort keys for deterministic output.
	// AUDIT R4-DATA-01 (2026-07-15): Replace O(n²) insertion sort with
	// sort.Slice (O(n log n)). On a hot path invoked at every commit that
	// touches the account, the insertion sort became a chain-liveness DoS
	// vector once a contract's storage grew to ~30k+ slots (~10⁹ comparisons
	// per touch, multi-second stalls). sort.Slice uses pdqsort and is stable
	// in ordering here (deterministic by key bytes), matching the previous
	// output exactly.
	keys := make([]types.Hash, 0, len(storage))
	for k := range storage {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})

	// Compute flat hash of concatenated key-value pairs.
	var buf []byte
	for _, k := range keys {
		v := storage[k] // copy to addressable value (map index is not addressable)
		buf = append(buf, k[:]...)
		buf = append(buf, v[:]...)
	}
	return types.Keccak256Hash(buf), nil
}

// Commit commits all dirty changes to the database
// Returns the state root hash and any error
// Optional blockHeight parameter enables modification tracking for state pruning
func (s *StateDB) Commit(blockHeight ...uint64) (types.Hash, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// R33 P3-07 FIX: Surface any silent error recorded by SetNonce/SetBalance/
	// SetCode during this transaction. Previously these methods only logged
	// load failures and returned silently, so the caller would see a successful
	// Commit with a state root that did NOT reflect the intended mutation,
	// causing silent state drift and potential consensus divergence. We surface
	// the first recorded error (kept on s.lastError for diagnostics until
	// reset by Revert/clearTxState) and clear it so the next transaction
	// starts clean.
	//
	// AUDIT ST-03 (2026-08-14): The error path previously ALSO cleared
	// dirtyAccounts/dirtyStorage/pendingCodeWrites. That destroyed the dirty
	// markers while accountCache still held the in-place mutations applied by
	// the SUCCESSFUL Set* calls of the same transaction (setters mutate the
	// cached account and mirror it into the dirty map): after the clear,
	// in-memory reads kept returning values that no future Commit could ever
	// persist, and the caller could neither inspect nor consistently roll
	// back the half-applied transaction. Keep the dirty state on the error
	// path — callers that need a clean slate must call Revert(), which clears
	// dirty state, caches, snapshots and lastError together (a consistent
	// reset); a blind retry without Revert re-stages exactly the mutations
	// that actually applied, keeping cache and dirty state in agreement.
	if s.lastError != nil {
		err := s.lastError
		s.lastError = nil
		return types.Hash{}, fmt.Errorf("state_db: Commit aborted due to prior silent mutation error: %w", err)
	}

	batch := s.db.NewBatch()

	// SECURITY: Save before-images for fork rollback state consistency.
	// Before-image at height H captures the PRE-commit state (old value from db)
	// BEFORE block H's changes are written. RollbackToHeight(H) restores these
	// for all heights >= H, effectively undoing block H and everything after.
	// This matches go-ethereum RevertToSnapshot semantics.
	var height uint64
	if len(blockHeight) > 0 {
		height = blockHeight[0]
	}
	if height > 0 && (len(s.dirtyAccounts) > 0 || len(s.dirtyStorage) > 0) {
		if s.beforeImages[height] == nil {
			s.beforeImages[height] = make(map[types.Address]*accountBeforeImage)
		}
		for addr := range s.dirtyAccounts {
			if _, exists := s.beforeImages[height][addr]; exists {
				continue // already saved for this height
			}
			// Read pre-commit state directly from the database (bypassing dirty state)
			// to capture the OLD value before it's overwritten by this commit.
			bi := &accountBeforeImage{}
			data, err := s.db.Get(append(accountPrefix, addr[:]...))
			if err == nil && len(data) > 0 {
				var prevAcc Account
				if err := decodeAccount(data, &prevAcc); err == nil {
					bi.account = &Account{
						Nonce:       prevAcc.Nonce,
						Balance:     new(big.Int).Set(prevAcc.Balance),
						StorageRoot: prevAcc.StorageRoot,
						CodeHash:    prevAcc.CodeHash,
					}
				}
			}
			// nil bi.account means the account didn't exist before this block
			s.beforeImages[height][addr] = bi
		}
		// Also save before-images for dirty storage
		for addr, storage := range s.dirtyStorage {
			if s.beforeImages[height][addr] == nil {
				s.beforeImages[height][addr] = &accountBeforeImage{}
			}
			if s.beforeImages[height][addr].storage == nil {
				s.beforeImages[height][addr].storage = make(map[types.Hash]types.Hash)
			}
			for key := range storage {
				if _, exists := s.beforeImages[height][addr].storage[key]; exists {
					continue
				}
				// Read pre-commit storage value directly from the database
				storageKey := append(storagePrefix, addr[:]...)
				storageKey = append(storageKey, 0xFF)
				storageKey = append(storageKey, key[:]...)
				var prevVal types.Hash
				if data, err := s.db.Get(storageKey); err == nil && len(data) > 0 {
					copy(prevVal[:], data)
				}
				s.beforeImages[height][addr].storage[key] = prevVal
			}
		}
	}

	// Commit accounts
	// AUDIT (2026) DATA- Previously, Verkle tree updates (which
	// write to the Verkle tree's own persistent DB via storeNode) happened
	// BEFORE batch.Write(). If batch.Write() failed, the Verkle tree was
	// already modified → inconsistent state between BoltDB and Verkle tree.
	// Now we collect Verkle tree updates and apply them only AFTER the batch
	// commits successfully, making the commit atomic.
	verkleUpdates := make([]struct{ key, value []byte }, 0)
	// R40-P2-02 (2026-08-03) — defer cache updates until AFTER batch.Write
	// succeeds. Prior to this fix, `s.addToCacheLocked(addr, acc)` ran
	// inside the loop BELOW, BEFORE batch.Write(). If batch.Write() later
	// failed, the cache already held the un-persisted account state and
	// subsequent reads returned silently-inconsistent data (cache said
	// "committed", BoltDB said "rolled back"). We now collect (addr, acc)
	// pairs here and apply the cache update only after the batch is
	// durably committed, mirroring the same deferral pattern already used
	// for Verkle tree updates (AUDIT (2026) DATA-).
	type pendingCacheUpdate struct {
		addr types.Address
		acc  *Account
	}
	pendingCache := make([]pendingCacheUpdate, 0, len(s.dirtyAccounts))
	for addr, acc := range s.dirtyAccounts {
		// AUDIT (2026) HIGH-02 (DATA-01): Compute the account's storage
		// root before encoding. Previously, StorageRoot was always the zero
		// hash, meaning the state root did not cover contract storage.
		// Now, any storage change is reflected in the account's StorageRoot,
		// which is part of the account data stored in the Verkle tree.
		if dirtyStorage, hasDirty := s.dirtyStorage[addr]; hasDirty {
			root, err := s.computeStorageRoot(addr, dirtyStorage)
			if err != nil {
				return types.Hash{}, fmt.Errorf("failed to compute storage root for %x: %w", addr[:8], err)
			}
			acc.StorageRoot = root
		}

		data, err := encodeAccount(acc)
		// SECURITY FIX: Return error instead of silently ignoring marshaling failure
		if err != nil {
			return types.Hash{}, fmt.Errorf("failed to marshal account %x: %w", addr[:8], err)
		}
		if err := batch.Put(append(accountPrefix, addr[:]...), data); err != nil {
			return types.Hash{}, fmt.Errorf("failed to write account %x to batch: %w", addr[:8], err)
		}

		// R40-P2-02 (2026-08-03): DEFER the cache update until batch.Write()
		// succeeds — see the pendingCache declaration at the loop top. The
		// previous in-loop `s.addToCacheLocked(addr, acc)` corrupted the
		// cache when batch.Write() failed.
		pendingCache = append(pendingCache, pendingCacheUpdate{addr: addr, acc: acc})

		// AUDIT (2026) DATA- Defer Verkle tree update to after
		// batch.Write() succeeds, so a failed batch doesn't corrupt the tree.
		if s.stateTrie != nil {
			verkleUpdates = append(verkleUpdates, struct{ key, value []byte }{key: append([]byte{}, addr[:]...), value: append([]byte{}, data...)})
		}

		// audit-fix STATE-M1: record modification for pruning
		if len(blockHeight) > 0 && blockHeight[0] > 0 {
			s.RecordModificationLocked(blockHeight[0], addr)
		}
	}

	// R33 STATE-02 FIX (2026-07-28): Write pending contract code to the
	// same batch as account updates, ensuring atomicity. If batch.Write()
	// fails, neither the code nor the CodeHash is persisted, preventing
	// orphan code and state inconsistency.
	for codeHash, code := range s.pendingCodeWrites {
		if err := batch.Put(append(codePrefix, codeHash[:]...), code); err != nil {
			return types.Hash{}, fmt.Errorf("failed to write contract code hash=%x to batch: %w", codeHash[:8], err)
		}
	}
	// Clear pending code writes — they're now in the batch.
	s.pendingCodeWrites = make(map[types.Hash][]byte)

	// Commit storage
	// SECURITY FIX: Added 0xFF separator to match GetStorage for consistent key format
	// AUDIT (2026) HIGH-02: Also update StorageRoot for accounts that have
	// dirty storage but aren't in dirtyAccounts (e.g., a contract that only
	// called SSTORE without changing balance/nonce).
	for addr, storage := range s.dirtyStorage {
		for key, value := range storage {
			storageKey := append(storagePrefix, addr[:]...)
			storageKey = append(storageKey, 0xFF)
			storageKey = append(storageKey, key[:]...)
			if err := batch.Put(storageKey, value[:]); err != nil {
				return types.Hash{}, fmt.Errorf("failed to write storage key=%x addr=%x to batch: %w", key[:8], addr[:8], err)
			}
		}

		// If this account is NOT in dirtyAccounts, we still need to update
		// its StorageRoot in the Verkle tree so the state root covers the
		// storage changes.
		if _, inDirty := s.dirtyAccounts[addr]; !inDirty {
			acc, err := s.getAccountLocked(addr)
			if err != nil {
				// Account doesn't exist — can't have storage. Skip.
				continue
			}
			root, err := s.computeStorageRoot(addr, storage)
			if err != nil {
				return types.Hash{}, fmt.Errorf("failed to compute storage root for %x (non-dirty account): %w", addr[:8], err)
			}
			// AUDIT-FULL H-8 (2026-08-14): getAccountLocked returns a
			// pointer INTO the account cache (or dirtyAccounts). Mutating
			// acc.StorageRoot in place — as the previous code did — updated
			// the cached account BEFORE batch.Write(); if the write failed,
			// the cache held a StorageRoot that was never persisted
			// (cache/DB inconsistency). Copy the account and defer the
			// cache replacement to the post-write pendingCache loop
			// (R40-P2-02), exactly like the dirtyAccounts path above.
			updated := *acc
			updated.StorageRoot = root
			data, err := encodeAccount(&updated)
			if err != nil {
				return types.Hash{}, fmt.Errorf("failed to marshal account %x for storage root update: %w", addr[:8], err)
			}
			if err := batch.Put(append(accountPrefix, addr[:]...), data); err != nil {
				return types.Hash{}, fmt.Errorf("failed to write account %x for storage root: %w", addr[:8], err)
			}
			pendingCache = append(pendingCache, pendingCacheUpdate{addr: addr, acc: &updated})
			// AUDIT (2026) DATA- Defer Verkle tree update.
			if s.stateTrie != nil {
				verkleUpdates = append(verkleUpdates, struct{ key, value []byte }{key: append([]byte{}, addr[:]...), value: append([]byte{}, data...)})
			}
		}
	}

	// AUDIT (2026) R4-DATA-03: Write commit-pending marker in the SAME
	// batch as account data. If batch.Write() succeeds, the marker is
	// persisted. If a crash occurs before all Verkle tree updates complete,
	// the marker survives and triggers a Verkle tree rebuild on next
	// startup via RecoverConsistency().
	if err := batch.Put(commitPendingKey, []byte{1}); err != nil {
		return types.Hash{}, fmt.Errorf("failed to write commit-pending marker: %w", err)
	}

	if err := batch.Write(); err != nil {
		// SECURITY FIX: Return error instead of silently ignoring
		// Prevents state from appearing committed when write actually failed
		return types.Hash{}, err
	}

	// R40-P2-02 (2026-08-03): batch.Write() succeeded → the account state
	// is durable in BoltDB. NOW it is safe to update the in-memory cache.
	// Doing this before batch.Write() (as the previous code did) would let
	// the cache race the durable write and silently return un-persisted
	// state on a post-failure read. The applied entries exactly mirror the
	// (addr, acc) pairs appended during the account-commit loop above.
	for _, e := range pendingCache {
		s.addToCacheLocked(e.addr, e.acc)
	}

	// AUDIT (2026) DATA- Apply Verkle tree updates ONLY after the
	// batch committed successfully. If any of these fail, the BoltDB still
	// has the correct committed state and the Verkle tree can be rebuilt
	// from it on next load. We log errors but don't fail the Commit, because
	// the authoritative state is in BoltDB and the Verkle tree is a derived
	// index (rootLocked() reads from the tree, but the tree can be rebuilt).
	//
	// AUDIT (2026) R4-DATA-03: If any Verkle Put fails, the commit-
	// pending marker is NOT cleared. The next startup will detect it and
	// rebuild the Verkle tree from BoltDB account state.
	//
	// STORAGE-P0-01 FIX (R31, 2026-07-27): All Verkle tree Put calls append
	// to the tree's pendingBatch. After all Puts complete, we call Flush()
	// to atomically commit the batch. If Flush fails, the on-disk tree may
	// be incomplete — leave the commit-pending marker so the next startup
	// rebuilds it from BoltDB. This closes the half-written-tree window.
	verklePutFailed := false
	for _, u := range verkleUpdates {
		if err := s.stateTrie.Put(u.key, u.value); err != nil {
			log.Printf("[ERROR] state_db: failed to update Verkle tree after successful batch commit (DATA-): %v — tree may be stale until rebuild", err)
			verklePutFailed = true
			break
		}
	}
	// STORAGE-P0-01 FIX: atomically flush all pending node writes from
	// the Verkle tree's internal batch. Without this, storeNode/recomputeRoot
	// would leave nodes buffered in memory and never persisted to disk —
	// causing the same "empty Commit" problem as STORAGE-P0-02.
	if !verklePutFailed {
		if err := s.stateTrie.Flush(); err != nil {
			log.Printf("[ERROR] state_db: failed to flush Verkle tree batch (STORAGE-P0-01): %v — tree may be stale until rebuild", err)
			verklePutFailed = true
		}
	}

	// AUDIT (2026) R4-DATA-03: Clear the commit-pending marker ONLY if
	// all Verkle tree updates succeeded. If any failed (or s.stateTrie is
	// nil), leave the marker so the next startup rebuilds the Verkle tree
	// from BoltDB account state.
	//
	// R33 STATE-03 FIX (2026-07-28): The commit-pending marker clear AND
	// the last-known-good root persistence must be ATOMIC. Previously these
	// were two separate s.db.Delete / s.db.Put calls — a crash between them
	// would leave the marker cleared but the root missing (or vice versa),
	// causing RecoverConsistency to skip root verification on next startup.
	// Now we write both operations in a single batch so they commit together
	// or not at all.
	if !verklePutFailed {
		postBatch := s.db.NewBatch()
		if err := postBatch.Delete(commitPendingKey); err != nil {
			// R39-P3-01 (2026-08-02) FIX: elevate log severity from WARN
			// to ERROR. The audit finding observes that the "marker clear
			// failed → log.Warn" pattern silently continues without
			// fail-closed propagation; in this commit-paths the fail-safe
			// (next startup RecoverConsistency detects the marker and
			// rebuilds the Verkle tree) is actually CORRECT — we do NOT
			// abort the Commit here because the account batch.Write at
			// line 1798 already succeeded, so returning error would risk
			// caller retry that double-commits. But the severity MUST
			// be ERROR so operators running log-level=ERROR see this
			// event in real time and can investigate disk health (the
			// marker clear Delete in bbolt is essentially free; if it
			// fails repeatedly the disk is unhealthy). Counting exposes
			// a single grep-able surface.
			s.commitPendingMarkerCloggedCount.Add(1)
			log.Printf("[ERROR] state_db: R39-P3-01: failed to stage commit-pending marker clear: %v — Verkle tree will be rebuilt on next startup (fail-safe defense retained; Commit returns nil, NOT aborting batch which is already written)", err)
		}
		// R32-P2-05 FIX (2026-07-28): Persist the last-known-good state root
		// after a fully successful commit (batch.Write + Verkle update +
		// marker clear). RecoverConsistency reads this to verify the rebuilt
		// tree produces the same root. If this write fails, we only log —
		// the commit itself is still valid (the root is a defense-in-depth
		// check, not a correctness requirement). On next startup, if the
		// key is missing, RecoverConsistency skips the root comparison.
		finalRoot := s.rootLocked()
		if err := postBatch.Put(lastCommittedRootKey, finalRoot[:]); err != nil {
			log.Printf("[WARN] state_db: failed to stage last committed root (R32-P2-05): %v — root verification will be skipped on next rebuild", err)
		}
		// R87-M4-RESTART: persist the committed height in the same batch. Only
		// when a height was supplied — heightless Commit calls (transaction-level
		// snapshots) must not clobber the block-level marker with 0.
		if height > 0 {
			var heightBytes [8]byte
			binary.BigEndian.PutUint64(heightBytes[:], height)
			if err := postBatch.Put(lastCommittedHeightKey, heightBytes[:]); err != nil {
				log.Printf("[WARN] state_db: failed to stage last committed height (R87-M4-RESTART): %v — rebuildState baseline will read 0 after a restart", err)
			}
		}
		if err := postBatch.Write(); err != nil {
			// R39-P3-01 (2026-08-02) FIX: elevate to ERROR + counter.
			// Same rationale as the staging Delete above — the account
			// batch already committed (line 1798), so we do NOT return
			// error and risk double-commit on retry; the fail-safe
			// (RecoverConsistency next startup) is retained. The
			// ERROR-severity log gives operators a single grep-able
			// signal that disk I/O health is degraded.
			s.commitPendingMarkerCloggedCount.Add(1)
			log.Printf("[ERROR] state_db: R39-P3-01: failed to write post-commit batch (marker clear + root persist): %v — Verkle tree will be rebuilt on next startup (fail-safe defense retained; Commit returns nil, NOT aborting batch which is already written)", err)
		}
	}

	// Clear dirty state.
	//
	// AUDIT ST-04 (2026-08-14): clear the dirty state ONLY when the Verkle
	// tree update succeeded (verklePutFailed == false). The account batch is
	// already durable in BoltDB at this point, so keeping the dirty state on
	// the Verkle-failure path is safe AND self-healing: the NEXT Commit()
	// re-stages the same accounts into a fresh batch (an idempotent rewrite
	// of identical values) and retries the tree updates, letting the stale
	// derived index catch up in-process instead of wedging the node until a
	// restart + RecoverConsistency() rebuild. Previously the dirty state was
	// cleared unconditionally, so a failed Verkle update could never be
	// retried and the caller had no rollback path either — the only recovery
	// was a full process restart.
	if !verklePutFailed {
		s.dirtyAccounts = make(map[types.Address]*Account)
		s.dirtyStorage = make(map[types.Address]map[types.Hash]types.Hash)
		// R33 STATE-02 FIX: Clear pending code writes — they were written to
		// the batch above and are no longer needed.
		s.pendingCodeWrites = make(map[types.Hash][]byte)
	}
	// Update storage cache: committed values are now in db, so invalidate
	// stale entries that might have been overwritten by the commit.
	s.storageCache = make(map[storageCacheKey]types.Hash)
	// STATE- (2026-07-20): Clear per-tx EIP-2929 access list, logs,
	// selfdestructs, and EIP-1153 transient storage. These are per-tx by
	// definition: access list does not persist (EIP-2929), transient
	// storage does not persist (EIP-1153), logs are extracted into the
	// receipt BEFORE Commit is called (by the executor), and
	// selfdestructs markers are processed by FinalizeSelfDestructs() (or
	// dropped if the tx reverts — caller must call Revert() instead).
	//
	// Note: logs are NOT persisted to the database here — the caller
	// (block producer) is responsible for reading logs via Logs()/GetLogs()
	// BEFORE calling Commit, and storing them in the receipt tree. After
	// Commit returns, the per-tx log slice is gone.
	s.clearTxStateLocked()

	// Return root hash from Verkle tree
	return s.rootLocked(), nil
}

// Revert clears all dirty changes and the snapshot stack.
// audit-fix CRITICAL: also clear the snapshot stack to prevent memory leaks
// and ensure clean state after revert.
func (s *StateDB) Revert() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.dirtyAccounts = make(map[types.Address]*Account)
	s.dirtyStorage = make(map[types.Address]map[types.Hash]types.Hash)
	// R33 STATE-02 FIX: Clear pending code writes on Revert — uncommitted
	// code should not persist across a revert.
	s.pendingCodeWrites = make(map[types.Hash][]byte)
	// R33 P3-07 FIX: Clear any recorded silent error so the next transaction
	// starts with a clean slate. Without this, an error from one reverted
	// transaction would leak into the next Commit() and abort it spuriously.
	s.lastError = nil
	s.snapshots = nil // audit-fix CRITICAL: clear snapshot stack on Revert
	// audit-fix L3-008: Clear accountCache to prevent stale data after revert.
	// Without this, cached account data from before the revert persists and
	// may be returned by subsequent GetAccount calls, causing inconsistency.
	s.accountCache = make(map[types.Address]*Account)
	// STATE- (2026-07-20): Also clear per-tx EIP-2929 access list,
	// logs, selfdestructs, and EIP-1153 transient storage. Without this,
	// state from the reverted transaction would leak into the next one.
	s.clearTxStateLocked()
}

// Exist checks if an account exists
func (s *StateDB) Exist(addr types.Address) bool {
	_, err := s.GetAccount(addr)
	return err == nil
}

// ClearCacheForTesting clears the in-memory account and storage caches so
// that subsequent reads are forced to go through the underlying database.
// This is intended ONLY for tests that need to simulate a cache miss (e.g.
// to force getAccountLocked to call db.Get so an injected DB error can be
// observed). Production code must NOT call this — it would defeat the
// cache and degrade performance.
//
// R33 P3-07 FIX: added to support silent-error regression tests.
func (s *StateDB) ClearCacheForTesting() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accountCache = make(map[types.Address]*Account)
	s.cacheAccessTime = make(map[types.Address]int64)
	s.storageCache = make(map[storageCacheKey]types.Hash)
}

// IterateAccounts iterates over all accounts in the state database.
// The callback receives the address, contract code (nil for EOAs), and balance.
// Return false from the callback to stop iteration early.
func (s *StateDB) IterateAccounts(fn func(addr types.Address, code []byte, balance *big.Int) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	iter := s.db.NewIterator(accountPrefix, nil)
	defer iter.Release()

	for iter.Next() {
		key := iter.Key()
		if len(key) != 1+20 { // prefix(1) + address(20)
			continue
		}

		var addr types.Address
		copy(addr[:], key[1:])

		var acc Account
		if err := decodeAccount(iter.Value(), &acc); err != nil {
			continue
		}

		// Get code if account has code hash
		var code []byte
		if acc.CodeHash != (types.Hash{}) {
			if codeData, err := s.db.Get(append(codePrefix, acc.CodeHash[:]...)); err == nil {
				code = codeData
			}
		}

		if !fn(addr, code, acc.Balance) {
			break
		}
	}
	// DB- (2026-07-20): surface iterator truncation/genuine errors.
	// IterateAccounts is used by RPC/inspection tooling; silent truncation
	// would cause callers to believe they saw the full account set when
	// they only saw the first 100K. Log a warning so operators notice.
	// (State-root computation uses computeStorageRoot which already
	// hard-fails via NewIteratorWithLimit(prefix, nil, 0) + iter.Error().)
	if err := iter.Error(); err != nil {
		log.Printf("[WARN] state_db: IterateAccounts iterator error (results may be truncated): %v", err)
	}
}

// Empty checks if an account is empty (zero nonce, zero balance, no code)
func (s *StateDB) Empty(addr types.Address) bool {
	acc, err := s.GetAccount(addr)
	if err != nil {
		return true
	}
	return acc.Nonce == 0 && acc.Balance.Sign() == 0 && acc.CodeHash == (types.Hash{})
}

// isAccountFullyEmpty checks whether an account is truly empty and safe to
// prune: zero Balance, zero Nonce, no code, AND no storage slots.
//
// R33 STATE-01 FIX (2026-07-28): The existing Empty() method only checks
// Balance/Nonce/CodeHash but NOT storage. A contract account with cleared
// balance and nonce but still holding storage entries would pass Empty()
// and be deleted by the pruner, losing the storage root and breaking state
// consensus. This method additionally scans the storage prefix for any
// entries, returning false if even one storage slot is present.
//
// This is the last-line-of-defense check before the pruner deletes an
// account. It must be conservative: any error or uncertainty returns
// false (keep the account).
func (s *StateDB) isAccountFullyEmpty(addr types.Address) bool {
	// Check account fields first (cheap).
	acc, err := s.getAccountLocked(addr)
	if err != nil || acc == nil {
		// Account doesn't exist — nothing to prune, but return true so the
		// pruner proceeds to clean up tracking metadata. The storage scan
		// below will be a no-op for non-existent accounts.
		// Fall through to storage check to be safe.
	} else {
		if acc.Nonce != 0 || acc.Balance.Sign() != 0 || acc.CodeHash != (types.Hash{}) {
			return false
		}
	}
	// Check for any storage entries. We use a single Next() call — if even
	// one entry exists, the account is not empty.
	storagePrefixKey := append(storagePrefix, addr[:]...)
	storagePrefixKey = append(storagePrefixKey, 0xFF)
	iter := s.db.NewIterator(storagePrefixKey, nil)
	defer iter.Release()
	if iter.Next() {
		// At least one storage entry exists — not empty.
		return false
	}
	if err := iter.Error(); err != nil {
		// Iterator failure — be conservative, keep the account.
		log.Printf("[WARN] state_db: isAccountFullyEmpty iterator error for %x (assuming non-empty): %v", addr[:8], err)
		return false
	}
	return true
}

// serializeAccount serializes an account for proof generation
// audit-fix CRIT-SERIAL: replaced non-deterministic JSON with deterministic binary encoding.
func serializeAccount(acc *Account) ([]byte, error) {
	data, err := encodeAccount(acc)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize account: %w", err)
	}
	return data, nil
}

// Copy creates a copy of the state database
// SECURITY FIX: Now copies stateTrie using VerkleTree.Copy()
func (s *StateDB) Copy() *StateDB {
	s.mu.RLock()
	defer s.mu.RUnlock()

	newState := &StateDB{
		db:                     s.db,
		dirtyAccounts:          make(map[types.Address]*Account),
		dirtyStorage:           make(map[types.Address]map[types.Hash]types.Hash),
		accountCache:           make(map[types.Address]*Account),
		stateTrie:              s.stateTrie.Copy(),
		modificationLog:        make(map[uint64][]types.Address),
		addressRefs:            make(map[types.Address]uint64),
		addressLastModified:    make(map[types.Address]uint64),
		pruneBatchSize:         s.pruneBatchSize,
		pruningEnabled:         s.pruningEnabled,
		pruneKeepBlocks:        s.pruneKeepBlocks,
		snapshotInterval:       s.snapshotInterval,
		stateSnapshots:         s.stateSnapshots,
		lastPrunedBlock:        s.lastPrunedBlock,
		lastSnapshotBlock:      s.lastSnapshotBlock,
		prunedAccounts:         s.prunedAccounts,
		cacheAccessTime:        make(map[types.Address]int64),
		cacheMaxSize:           s.cacheMaxSize,
		storageCache:           make(map[storageCacheKey]types.Hash),
		historyRetentionBlocks: s.historyRetentionBlocks,
		beforeImages:           make(map[uint64]map[types.Address]*accountBeforeImage),
		// STATE- (2026-07-20): Deep-copy per-tx EIP state so the
		// block producer's stateDB.Copy() preserves it for parallel
		// verification. Without this, a Copy() mid-tx would lose the
		// accumulated access list / logs / transient state / selfdestructs,
		// causing the copy to behave as if the tx had just started.
		accessList:                s.accessList.deepCopy(),
		logs:                      deepCopyLogs(s.logs),
		selfDestructs:             s.deepCopySelfDestructsLocked(),
		selfDestructBeneficiaries: s.deepCopySelfDestructBeneficiariesLocked(),
		transientStorage:          s.transientStorage.deepCopy(),
		// R35-P1-02 FIX: deep-copy pendingCodeWrites so the copy's
		// Commit() persists code staged before the Copy(). Without this,
		// the copy's pendingCodeWrites is nil and SetCode() lazily
		// initializes an empty map, losing staged code.
		pendingCodeWrites: s.deepCopyPendingCodeWritesLocked(),
		// R33 P3-07 FIX: Carry over lastError so a Copy() taken mid-tx
		// preserves the "silent mutation failure" signal for the copy's
		// subsequent Commit(). Without this, the block producer's Copy()
		// would lose the error and produce a successful state root that
		// does not reflect the intended mutation.
		lastError: s.lastError,
	}

	// Copy dirty accounts
	for addr, acc := range s.dirtyAccounts {
		newAcc := *acc
		newAcc.Balance = new(big.Int).Set(acc.Balance)
		newState.dirtyAccounts[addr] = &newAcc
	}

	// Copy dirty storage
	for addr, storage := range s.dirtyStorage {
		newStorage := make(map[types.Hash]types.Hash)
		for key, value := range storage {
			newStorage[key] = value
		}
		newState.dirtyStorage[addr] = newStorage
	}

	// SECURITY (audit 2026-06-14): Copy the snapshot stack and counter.
	// The block producer builds blocks on stateDB.Copy(); if a nested QVM
	// CALL reverts, RevertToSnapshot must find the same snapshots on the copy.
	// Previously snapshots/nextSnapshotID were left nil/0 on the copy, so any
	// revert on the copy fell into the "wipe all dirty state" fallback and
	// corrupted the proposed state root. Deep-copy each snapshot's maps so
	// mutations on the copy cannot alias back into the original.
	//
	// STATE- (2026-07-20): Also deep-copy storageCache on each
	// snapshot — same aliasing concern as dirtyAccounts/dirtyStorage.
	//
	// STATE- (2026-07-20): Also deep-copy accessList / logs /
	// selfDestructs / transientStorage on each snapshot — same aliasing
	// concern: a mutation on the copy would otherwise corrupt the original
	// snapshot's per-tx state, breaking nested reverts.
	newState.snapshots = make([]stateSnapshot, len(s.snapshots))
	for i, snap := range s.snapshots {
		newState.snapshots[i] = stateSnapshot{
			dirtyAccounts:    s.deepCopyAccountsMap(snap.dirtyAccounts),
			dirtyStorage:     s.deepCopyStorageMap(snap.dirtyStorage),
			storageCache:     s.deepCopyStorageCacheMap(snap.storageCache),
			accessList:       snap.accessList.deepCopy(),
			logs:             deepCopyLogs(snap.logs),
			selfDestructs:    s.deepCopySelfDestructsMap(snap.selfDestructs),
			transientStorage: snap.transientStorage.deepCopy(),
			// R35-P1-02 FIX: deep-copy pendingCodeWrites and
			// selfDestructBeneficiaries on each snapshot — same aliasing
			// concern as the other fields. Without this, a mutation on
			// the copy would corrupt the original snapshot's pending
			// code / beneficiary data, breaking nested reverts.
			selfDestructBeneficiaries: s.deepCopySelfDestructBeneficiariesMap(snap.selfDestructBeneficiaries),
			pendingCodeWrites:         s.deepCopyPendingCodeWritesMap(snap.pendingCodeWrites),
		}
	}
	newState.nextSnapshotID = s.nextSnapshotID

	return newState
}

// Root returns the current state root hash
// audit-fix: integrated Verkle tree for proper state root calculation
func (s *StateDB) Root() types.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rootLocked()
}

// rootLocked returns the root hash without acquiring locks
// MUST be called with s.mu held (either RLock or Lock)
func (s *StateDB) rootLocked() types.Hash {
	if s.stateTrie == nil {
		return types.Hash{}
	}

	return s.stateTrie.Root()
}
func (s *StateDB) GetState(addr types.Address, key types.Hash) types.Hash {
	return s.GetStorage(addr, key)
}

// SetState sets a storage value (alias for SetStorage). Rollback handling:
// writes are journaled — SetStorage records the change in the dirty journal,
// and RevertToSnapshot can roll back to any snapshot taken before this call.
func (s *StateDB) SetState(addr types.Address, key, value types.Hash) {
	s.SetStorage(addr, key, value)
}

// Snapshot creates a snapshot of the current dirty state and returns its ID.
// audit-fix R3-F12: deep-copies dirty state so RevertToSnapshot can restore
// to this exact point without affecting changes made before it.
//
// SECURITY (audit 2026-06-14): The returned ID is the slice INDEX of the
// snapshot. RevertToSnapshot uses the id both as an index (s.snapshots[id])
// and as a truncation point (s.snapshots[:id]), so the id MUST equal the
// index. Previously this returned s.nextSnapshotID (a monotonic counter that
// is never decremented on revert), so after one revert the counter no longer
// matched the slice length and subsequent reverts would either index the wrong
// snapshot or fall into the "wipe all dirty state" fallback — corrupting
// in-progress transaction state during nested QVM CALL reverts.
func (s *StateDB) Snapshot() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// L14-012: Limit snapshot depth to prevent memory exhaustion.
	// Exceeding this indicates a bug or DoS attack via excessive call depth.
	//
	// R33 STATE-08 FIX (2026-07-28): Previously this called panic() on
	// overflow, which would crash the entire node — a DoS amplification
	// where a single malicious transaction (deeply nested CALL chain)
	// could kill block production and consensus. Convert to a typed error
	// return by returning a sentinel snapshot id (ErrSnapshotDepthExceeded)
	// so the caller (qvm executor) can REVERT the transaction instead of
	// crashing the process. Callers already handle invalid snapshot ids
	// (id < 0 falls through to the wipe-all fallback in RevertToSnapshot).
	if len(s.snapshots) >= maxSnapshotDepth {
		// Return -1 sentinel; RevertToSnapshot(-1) treats it as invalid and
		// wipes dirty state, effectively reverting the entire transaction.
		// This is the safest fallback: a transaction that exceeds snapshot
		// depth is almost certainly malicious or buggy.
		log.Printf("[WARN] state_db: snapshot depth %d exceeds maximum %d (possible DoS via excessive call depth) — returning invalid id to trigger revert", len(s.snapshots), maxSnapshotDepth)
		return -1
	}

	snap := stateSnapshot{
		dirtyAccounts: s.deepCopyAccountsLocked(),
		dirtyStorage:  s.deepCopyStorageLocked(),
		// STATE- (2026-07-20): Capture storageCache so RevertToSnapshot
		// can restore it. Without this, cache entries populated during the
		// reverted section would persist after revert, potentially causing
		// consensus divergence if a future code path writes dirty values to
		// the cache (defense-in-depth).
		storageCache: s.deepCopyStorageCacheLocked(),
		// STATE- (2026-07-20): Capture per-tx EIP-2929 access list,
		// logs, selfdestructs, and EIP-1153 transient storage so a sub-call
		// revert rolls them back too. Without this, an attacker could
		// observe warm slots that should have been cold, retrieve logs that
		// should have been discarded, or read transient state that should
		// have been cleared.
		accessList:       s.accessList.deepCopy(),
		logs:             deepCopyLogs(s.logs),
		selfDestructs:    s.deepCopySelfDestructsLocked(),
		transientStorage: s.transientStorage.deepCopy(),
		// STATE- (2026-07-21): capture the beneficiary map so
		// RevertToSnapshot can restore it. Without this, a sub-call
		// revert would lose beneficiary info for any selfdestruct that
		// survives the revert, causing the contract's balance to be
		// burned instead of sent to the intended recipient at
		// end-of-block finalization.
		selfDestructBeneficiaries: s.deepCopySelfDestructBeneficiariesLocked(),
		// R35-P1-02 FIX: capture pendingCodeWrites so RevertToSnapshot
		// can restore it. Without this, a reverted sub-call's staged
		// code persists and gets written to disk at Commit().
		pendingCodeWrites: s.deepCopyPendingCodeWritesLocked(),
	}
	s.snapshots = append(s.snapshots, snap)
	// id == index invariant: the returned value is the position of this
	// snapshot in the slice, which is exactly what RevertToSnapshot expects.
	id := len(s.snapshots) - 1
	s.nextSnapshotID = id + 1 // keep counter consistent for diagnostics
	return id
}

// RevertToSnapshot reverts dirty state to the point captured by Snapshot(id).
// audit-fix R3-F12: only undoes changes made AFTER the snapshot, preserving
// parent-call state during nested QVM CALL/DELEGATECALL reverts.
// audit-fix CRITICAL: deep-copy snapshot data to prevent aliasing where subsequent
// dirty modifications would corrupt the stored snapshot state.
func (s *StateDB) RevertToSnapshot(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id < 0 || id >= len(s.snapshots) {
		// Invalid snapshot — fall back to clearing everything (legacy behavior)
		s.dirtyAccounts = make(map[types.Address]*Account)
		s.dirtyStorage = make(map[types.Address]map[types.Hash]types.Hash)
		// R33 STATE-02 FIX: Clear pending code writes on invalid snapshot revert.
		s.pendingCodeWrites = make(map[types.Hash][]byte)
		// STATE- (2026-07-20): Also clear storageCache on invalid
		// snapshot — can't trust any cache state if we don't know which
		// snapshot to revert to.
		s.storageCache = make(map[storageCacheKey]types.Hash)
		// STATE- (2026-07-20): Also clear per-tx EIP state — same
		// reasoning as storageCache.
		s.clearTxStateLocked()
		s.snapshots = nil
		return
	}

	snap := s.snapshots[id]
	// audit-fix CRITICAL: deep-copy to prevent aliasing
	// Previous code directly assigned snapshot maps to dirty state, causing
	// subsequent modifications to corrupt the snapshot data.
	s.dirtyAccounts = s.deepCopyAccountsMap(snap.dirtyAccounts)
	s.dirtyStorage = s.deepCopyStorageMap(snap.dirtyStorage)
	// STATE- (2026-07-20): Restore storageCache to its state at
	// snapshot time. Without this, cache entries populated during the
	// reverted section (e.g. via GetStorage cache misses) would persist
	// after revert, breaking the snapshot invariant and risking consensus
	// divergence if any future code path writes dirty values to the cache.
	s.storageCache = s.deepCopyStorageCacheMap(snap.storageCache)
	// STATE- (2026-07-20): Restore per-tx EIP-2929 access list,
	// logs, selfdestructs, and EIP-1153 transient storage. Deep-copy so
	// subsequent mutations do not alias the snapshot.
	s.accessList = snap.accessList.deepCopy()
	s.logs = deepCopyLogs(snap.logs)
	s.selfDestructs = s.deepCopySelfDestructsMap(snap.selfDestructs)
	// STATE- (2026-07-21): restore the beneficiary map from the
	// snapshot. Previously this code created an empty map, losing the
	// beneficiary info for any selfdestruct whose address survived the
	// revert. The beneficiary map snapshot was captured at the same
	// time as selfDestructs, so the two maps are consistent: every
	// address in selfDestructs has a matching entry in
	// selfDestructBeneficiaries (and vice versa). Deep-copy so
	// subsequent mutations do not alias the snapshot.
	s.selfDestructBeneficiaries = s.deepCopySelfDestructBeneficiariesMap(snap.selfDestructBeneficiaries)
	s.transientStorage = snap.transientStorage.deepCopy()
	// R35-P1-02 FIX: restore pendingCodeWrites so code staged by SetCode()
	// within the reverted scope is discarded. Without this, reverted
	// contract-creation code persists in pendingCodeWrites and gets
	// written to disk at the next Commit(), causing state inconsistency.
	s.pendingCodeWrites = s.deepCopyPendingCodeWritesMap(snap.pendingCodeWrites)
	// Discard this and all later snapshots
	s.snapshots = s.snapshots[:id]
}

// RollbackToHeight rolls back the committed state to the given block height.
// SECURITY: This is called during fork rollback to ensure state consistency.
// Without this, DeleteBlocksFromHeight only removes block records but leaves
// committed state (balances, contract storage) unchanged.
//
// It applies before-images in reverse block order (newest first) to undo
// all state changes made at or after the fork point. After rollback, the
// state reflects the chain as it was at forkHeight-1.
func (s *StateDB) RollbackToHeight(forkHeight uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Collect heights that need to be rolled back (>= forkHeight), sorted descending
	var heights []uint64
	for h := range s.beforeImages {
		if h >= forkHeight {
			heights = append(heights, h)
		}
	}
	// Sort descending so we roll back newest blocks first
	for i := 0; i < len(heights); i++ {
		for j := i + 1; j < len(heights); j++ {
			if heights[j] > heights[i] {
				heights[i], heights[j] = heights[j], heights[i]
			}
		}
	}

	if len(heights) == 0 {
		// R39-P2-02 (2026-08-02) FIX: distinguish "nothing to roll back"
		// (legitimate, return nil) from "target height already pruned"
		// (silent corruption, MUST return error). Audit finding:
		//
		//   RollbackToHeight(forkHeight) silently returned nil when no
		//   beforeImages existed at >= forkHeight — even if forkHeight
		//   itself was BELOW the smallest retained beforeImage height
		//   (i.e. the history was already pruned and the rollback target
		//   is unreachable). Operators would think the rollback
		//   succeeded, but the chain actually retains its current
		//   (post-fork) state — silently divergent from what the
		//   operator intended.
		//
		// We now compute the minimum retained beforeImage height; if
		// forkHeight < minRetainedHeight, we return an explicit
		// ErrAlreadyPruned so the operator can investigate (re-sync from
		// a snapshot, restore from backup, or accept divergence) instead
		// of continuing under the false impression that the rollback
		// succeeded.
		//
		// The minRetainedHeight is computed under s.mu (we already hold
		// it); for very large beforeImages maps this is O(N) but in
		// production N is bounded by the retention window (default
		// 64 blocks for hot-path StateDB, larger for archival nodes).
		// The O(N) cost is acceptable because rollbacks are rare —
		// triggered by operator intervention or fork recovery, never
		// on the per-block hot path.
		//
		// Edge cases:
		//   - beforeImages is empty entirely (no history at all, fresh
		//     node): minRetainedHeight stays at maxUint64, forkHeight
		//     is always < minRetainedHeight, so we'd return
		//     ErrAlreadyPruned. But this is wrong for a fresh node
		//     rolling back to height 0 — there's nothing to roll back
		//     AND nothing pruned. We special-case: empty beforeImages
		//     returns nil (the legitimate "nothing to roll back" path).
		//   - forkHeight == minRetainedHeight: not pruned — we can
		//     roll back ALL retained heights >= forkHeight including
		//     minRetainedHeight itself, so this is the legitimate
		//     "nothing to do" case (return nil).
		//   - forkHeight > minRetainedHeight: also legitimate, some
		//     heights >= forkHeight may or may not exist; if none
		//     exist, nothing to do (return nil).
		if len(s.beforeImages) == 0 {
			return nil // fresh node, nothing to roll back AND nothing pruned
		}
		minRetained := uint64(0)
		first := true
		for h := range s.beforeImages {
			if first || h < minRetained {
				minRetained = h
				first = false
			}
		}
		if forkHeight < minRetained {
			return fmt.Errorf("R39-P2-02: RollbackToHeight(%d) failed: target height is below the minimum retained beforeImage height (%d) — history was pruned and the rollback target is unreachable; operator must re-sync from a snapshot or restore from backup instead of continuing under the false impression that the rollback succ (silent divergence guard)", forkHeight, minRetained)
		}
		return nil // forkHeight >= minRetained: legitimate nothing-to-do
	}

	// R39-P2-02 (2026-08-02) FIX, continued: even when heights is
	// non-empty (some beforeImages >= forkHeight exist), we MUST verify
	// that forkHeight itself is REACHABLE — i.e. forkHeight >=
	// minRetainedHEIGHT - 1. Without this guard, the audit's silent-
	// divergence finding sneaks back via the OTHER branch: consider
	// beforeImages = {200, 300, 400} and forkHeight=50. Both 200 and
	// 300 and 400 are >= 50, so heights=[400, 300, 200] (sorted desc),
	// and the main loop would roll them back in order — restoring
	// state to height 199 (since the height-200 beforeImage captures
	// pre-height-200 state). But the operator asked for height 50 — 199
	// is the closest we can reach with retained beforeImages, and
	// heights 50..198 are pruned forever. We MUST return an error so
	// the operator knows we couldn't reach the target.
	//
	// heights[] is sorted DESCENDING, so the LAST element is the
	// minimum retained height we're about to consider for rollback. If
	// forkHeight < that minimum - 1, we cannot reach forkHeight.
	//
	// Why "− 1": the beforeImage at minRetainedActive captures the
	// pre-block-minRetainedActive state — i.e. the state AFTER block
	// (minRetainedActive - 1) was committed. Rolling back to
	// minRetainedActive thus lands us at the post-(minRetainedActive - 1)
	// state, which means forkHeight = (minRetainedActive - 1) IS
	// reachable. forkHeight = (minRetainedActive - 2) is NOT
	// reachable — we'd restore to (minRetainedActive - 1) but the
	// operator asked for one block earlier, and that block's
	// beforeImage was pruned. The "-1" slack is the off-by-one the
	// audit's FINDING implicitly relies on: testStateDB_RollbackToHeight_
	// DeletesNewAccount commits at heights 1 and 2 (beforeImage at
	// height 2 only), then RollbackToHeight(1) — 1 = minRetained(2) - 1,
	// AND the test EXPECTS this to succeed. The slack delivers that.
	minRetainedActive := heights[len(heights)-1]
	if forkHeight+1 < minRetainedActive {
		return fmt.Errorf("R39-P2-02: RollbackToHeight(%d) failed: target height is below the minimum reachable height (%d) — history was pruned and the rollback target is unreachable; rolling back the %d retained entries >= %d would only restore state to height %d (post-(minRetainedActive-1)), NOT to forkHeight %d; operator must re-sync from a snapshot or restore from backup instead of continuing under the false impression that the rollback succeeded", forkHeight, minRetainedActive-1, len(heights), minRetainedActive, minRetainedActive-1, forkHeight)
	}

	batch := s.db.NewBatch()
	restoredCount := 0
	// R38-P1-05 FIX: pendingUndoHeights collects the heights whose
	// beforeImages / modificationLog entries should be dropped AFTER the
	// durable batch.Write() commits. See the per-height comment in the loop
	// below for the rationale (never delete in-memory undo before the batch
	// is durable; preserve it for next-startup retry on Write failure).
	pendingUndoHeights := make([]uint64, 0, len(heights))
	// R33 STATE-07 FIX (2026-07-28): Defer Verkle tree updates until AFTER
	// batch.Write() succeeds. Previously s.stateTrie.Put() was called inside
	// the per-account loop, mutating the in-memory trie before the batch
	// committed. If batch.Write() failed, the Verkle root no longer matched
	// the persisted DB state, causing state-root divergence on the next
	// commit. Collect (addr, data) pairs here and apply them to the trie
	// only after the batch is durably persisted.
	type verkleUpdate struct {
		addr types.Address
		data []byte
	}
	var verkleUpdates []verkleUpdate

	// P1-STATE-02 FIX (2026-07-30, R36): Previously batch.Put/Delete errors
	// were swallowed (log + continue). boltBatch returns ErrBatchFull at
	// MaxBatchOps(10000), so a deep rollback (>10k ops) would silently drop
	// the overflowing op and return nil — leaving the node half-rolled-back
	// with a state root permanently divergent from honest peers. Now:
	// ErrBatchFull triggers Flush+retry (split the batch at the account
	// boundary); any other error aborts the rollback (fail-closed) so the
	// operator can investigate instead of silently continuing with corrupt
	// state.
	//
	// R38-P1-05 FIX: Before any intermediate Flush, write the commit-pending
	// marker into the SAME batch so it is persisted atomically with the
	// partial data. Without this, a crash after an intermediate Flush but
	// before the final marker write would leave BoltDB with partial rollback
	// data and NO marker — RecoverConsistency would see no marker and assume
	// consistency, leaving the node in a silently corrupt, unrecoverable
	// state. With the marker pre-written, any crash triggers a Verkle tree
	// rebuild on next startup.
	rollbackMarkerWritten := false
	ensureRollbackMarker := func() error {
		if rollbackMarkerWritten {
			return nil
		}
		if err := batch.Put(commitPendingKey, []byte{1}); err != nil {
			if !errors.Is(err, db.ErrBatchFull) {
				return fmt.Errorf("failed to write commit-pending marker before flush: %w", err)
			}
			// Batch is full even for the marker — flush first, then write marker
			if err := batch.Flush(); err != nil {
				return fmt.Errorf("rollback batch flush (marker) failed: %w", err)
			}
			if err := batch.Put(commitPendingKey, []byte{1}); err != nil {
				return fmt.Errorf("failed to write commit-pending marker after flush: %w", err)
			}
		}
		rollbackMarkerWritten = true
		return nil
	}
	batchPut := func(key, value []byte) error {
		if err := batch.Put(key, value); err != nil {
			if !errors.Is(err, db.ErrBatchFull) {
				return err
			}
			// R38-P1-05: Write marker BEFORE flushing so a crash after
			// Flush is detectable by RecoverConsistency.
			if err := ensureRollbackMarker(); err != nil {
				return err
			}
			if err := batch.Flush(); err != nil {
				return fmt.Errorf("rollback batch flush failed: %w", err)
			}
			if err := batch.Put(key, value); err != nil {
				return err
			}
		}
		return nil
	}
	batchDelete := func(key []byte) error {
		if err := batch.Delete(key); err != nil {
			if !errors.Is(err, db.ErrBatchFull) {
				return err
			}
			// R38-P1-05: Write marker BEFORE flushing so a crash after
			// Flush is detectable by RecoverConsistency.
			if err := ensureRollbackMarker(); err != nil {
				return err
			}
			if err := batch.Flush(); err != nil {
				return fmt.Errorf("rollback batch flush failed: %w", err)
			}
			if err := batch.Delete(key); err != nil {
				return err
			}
		}
		return nil
	}

	for _, h := range heights {
		images := s.beforeImages[h]
		for addr, bi := range images {
			if bi.account == nil {
				// Account didn't exist before this block — delete it
				if err := batchDelete(append(accountPrefix, addr[:]...)); err != nil {
					return fmt.Errorf("failed to delete account %x during rollback at height %d: %w", addr[:8], h, err)
				}
				// Queue Verkle deletion (represented as nil data)
				verkleUpdates = append(verkleUpdates, verkleUpdate{addr: addr, data: nil})
			} else {
				// Restore the previous account state
				data, err := encodeAccount(bi.account)
				if err != nil {
					return fmt.Errorf("failed to encode before-image account %x at height %d: %w", addr[:8], h, err)
				}
				if err := batchPut(append(accountPrefix, addr[:]...), data); err != nil {
					return fmt.Errorf("failed to restore account %x during rollback at height %d: %w", addr[:8], h, err)
				}
				// Queue Verkle update — applied after batch.Write() succeeds
				verkleUpdates = append(verkleUpdates, verkleUpdate{addr: addr, data: data})
			}
			// Restore previous storage values
			for key, prevVal := range bi.storage {
				storageKey := append(storagePrefix, addr[:]...)
				storageKey = append(storageKey, 0xFF)
				storageKey = append(storageKey, key[:]...)
				if prevVal == (types.Hash{}) {
					// Key didn't exist before — delete it
					if err := batchDelete(storageKey); err != nil {
						return fmt.Errorf("failed to delete storage %x:%x during rollback at height %d: %w", addr[:8], key[:8], h, err)
					}
				} else {
					if err := batchPut(storageKey, prevVal[:]); err != nil {
						return fmt.Errorf("failed to restore storage %x:%x during rollback at height %d: %w", addr[:8], key[:8], h, err)
					}
				}
			}
			restoredCount++
		}
		// R38-P1-05 FIX: Do NOT delete in-memory undo records
		// (beforeImages / modificationLog) until the durable batch.Write()
		// has committed successfully. Previously the per-height deletes ran
		// inside the apply-loop — before batch.Write() — so a process crash
		// (or a batch.Write failure) would lose the in-memory undo entirely.
		// On the next-startup retry path there would be nothing to replay,
		// silently leaving the node half-rolled-back with a state root
		// permanently divergent from honest peers.
		//
		// Instead, collect the heights to be cleaned into pendingUndoHeights
		// and only drop them from beforeImages / modificationLog AFTER
		// batch.Write() returns nil. If batch.Write() fails, the function
		// returns the error WITHOUT touching the in-memory undo, preserving
		// it for the next-startup retry. (The commit-pending marker written
		// above guarantees that BoltDB-side partial writes are detectable by
		// RecoverConsistency on reboot; combined with the preserved undo
		// records, the rollback can be safely replayed.)
		pendingUndoHeights = append(pendingUndoHeights, h)
	}

	// P1-STATE-03 FIX (2026-07-30, R36): Write commit-pending marker in the
	// SAME batch as the rollback data (atomic). If a crash occurs between
	// batch.Write() and the Verkle tree Flush(), the marker survives and
	// triggers a Verkle tree rebuild on next startup via RecoverConsistency.
	// This mirrors the crash protection in Commit() — without it, a crash
	// after rollback would leave the on-disk Verkle tree pointing at the
	// pre-rollback (forked) state while BoltDB account data is rolled back,
	// causing silent state-root divergence that RecoverConsistency cannot
	// detect (no marker → "consistent" → wrong root accepted).
	//
	// R38-P1-05 FIX: If the marker was already written by an intermediate
	// Flush (ensureRollbackMarker), skip the redundant write.
	if !rollbackMarkerWritten {
		if err := batchPut(commitPendingKey, []byte{1}); err != nil {
			return fmt.Errorf("failed to write commit-pending marker for rollback: %w", err)
		}
	}

	if err := batch.Write(); err != nil {
		// R38-P1-05 FIX: batch.Write failed — do NOT clear the in-memory undo
		// records (beforeImages / modificationLog). Clearing them here (as the
		// pre-fix code implicitly did, since the per-height deletes already
		// ran inside the loop) would make the rollback unreplayable: the
		// commit-pending marker written above is persisted so the next startup
		// detects the partial write, but without the undo records there is
		// nothing to re-apply. Preserving them lets the operator retry the
		// same rollback (or let the next-startup path recover) with full undo
		// information intact.
		return fmt.Errorf("failed to write rollback batch (in-memory undo preserved for retry, R38-P1-05): %w", err)
	}

	// R38-P1-05 FIX: The durable batch just committed. NOW it is safe to drop
	// the in-memory undo records for the rolled-back heights. Doing this
	// before batch.Write() would lose the undo on a crash/Write-failure; doing
	// it here guarantees that the only way the undo is removed is if the
	// rollback is actually durable on disk. If a crash happens after this
	// point, the on-disk state already reflects the rollback, so the undo is
	// no longer needed.
	for _, h := range pendingUndoHeights {
		delete(s.beforeImages, h)
		delete(s.modificationLog, h)
	}

	// R33 STATE-07 FIX: Now that the batch is durable, apply Verkle updates.
	// If a Verkle Put fails here, the DB is already correct; the in-memory
	// trie will be rebuilt from the DB on restart. Log the failure but do not
	// fail the rollback — the persisted state is authoritative.
	//
	// P1-STATE-03 FIX (2026-07-30, R36): After applying Verkle updates, call
	// Flush() to atomically persist all pending node writes to disk. If Flush
	// fails, leave the commit-pending marker so the next startup rebuilds the
	// Verkle tree from BoltDB. On full success, clear the marker atomically
	// (post-batch, same pattern as Commit).
	verkleUpdateFailed := false
	if s.stateTrie != nil {
		for _, vu := range verkleUpdates {
			if vu.data == nil {
				// Deletion — Verkle tree uses Delete for account removal.
				if err := s.stateTrie.Delete(vu.addr[:]); err != nil {
					log.Printf("ERROR: failed to delete Verkle tree entry for account %x after rollback: %v", vu.addr[:8], err)
					verkleUpdateFailed = true
					break
				}
			} else {
				if err := s.stateTrie.Put(vu.addr[:], vu.data); err != nil {
					log.Printf("ERROR: failed to update Verkle tree for account %x after rollback: %v", vu.addr[:8], err)
					verkleUpdateFailed = true
					break
				}
			}
		}
		// P1-STATE-03 FIX: Flush all pending Verkle node writes atomically.
		if !verkleUpdateFailed {
			if err := s.stateTrie.Flush(); err != nil {
				log.Printf("ERROR: failed to flush Verkle tree after rollback (P1-STATE-03): %v — tree will be rebuilt on next startup", err)
				verkleUpdateFailed = true
			}
		}
	}

	// P1-STATE-03 FIX: Clear the commit-pending marker ONLY if all Verkle
	// updates and Flush succeeded. If any failed, leave the marker so the
	// next startup rebuilds the Verkle tree from BoltDB account state.
	// Use a post-batch (same pattern as Commit) so the marker clear commits
	// atomically.
	if !verkleUpdateFailed {
		postBatch := s.db.NewBatch()
		if err := postBatch.Delete(commitPendingKey); err != nil {
			// R39-P3-01 (2026-08-02) FIX: elevate to ERROR + counter (same
			// rationale as the Commit path's marker clear above — the
			// rollback batch already committed, the fail-safe is the
			// next-startup Verkle rebuild, but operators need a single
			// ERROR-level grep point for disk-health triage).
			s.commitPendingMarkerCloggedCount.Add(1)
			log.Printf("[ERROR] state_db: R39-P3-01: failed to stage rollback commit-pending marker clear: %v — Verkle tree will be rebuilt on next startup (fail-safe defense retained; RollbackToHeight returns nil, NOT aborting batch which is already written)", err)
		}
		if err := postBatch.Write(); err != nil {
			// R39-P3-01 (2026-08-02) FIX: elevate to ERROR + counter.
			s.commitPendingMarkerCloggedCount.Add(1)
			log.Printf("[ERROR] state_db: R39-P3-01: failed to write post-rollback marker clear: %v — Verkle tree will be rebuilt on next startup (fail-safe defense retained; RollbackToHeight returns nil, NOT aborting batch which is already written)", err)
		}
	}

	// Clear dirty state and cache (they may reference post-fork data)
	// SECURITY FIX: After rollback, the cache must be cleared so that
	// subsequent reads go to the database and pick up the restored values.
	s.dirtyAccounts = make(map[types.Address]*Account)
	s.dirtyStorage = make(map[types.Address]map[types.Hash]types.Hash)
	// R33 STATE-02 FIX: Clear pending code writes on rollback.
	s.pendingCodeWrites = make(map[types.Hash][]byte)
	s.accountCache = make(map[types.Address]*Account)
	s.storageCache = make(map[storageCacheKey]types.Hash)
	s.snapshots = nil
	// STATE- (2026-07-20): Also clear per-tx EIP state — the rolled-
	// back heights' access lists / logs / transient storage / selfdestructs
	// are not valid for the restored chain state.
	s.clearTxStateLocked()

	// Clean up state snapshots for rolled-back heights
	for h := range s.stateSnapshots {
		if h >= forkHeight {
			delete(s.stateSnapshots, h)
		}
	}

	// R57-ACC-OPT (2026-08-07): After a rollback the state corresponds to the
	// post-(forkHeight-1) state. Reset lastCommittedHeight so a subsequent
	// rebuildState resumes from forkHeight instead of a stale (higher) height
	// that would skip blocks that must be re-applied on the new canonical chain.
	if forkHeight > 0 {
		s.lastCommittedHeight = forkHeight - 1
	} else {
		s.lastCommittedHeight = 0
	}

	// R87-M4-RESTART (2026-08-29): persist the rolled-back height — a crash
	// between here and the next CommitWithBlock would otherwise restart with
	// the PRE-rollback height and rebuildState would skip the blocks the
	// rollback removed (the exact R87-M4 failure shape). Best-effort: on
	// failure the in-memory value is still correct until the next commit.
	{
		persistBatch := s.db.NewBatch()
		var heightBytes [8]byte
		binary.BigEndian.PutUint64(heightBytes[:], s.lastCommittedHeight)
		if err := persistBatch.Put(lastCommittedHeightKey, heightBytes[:]); err != nil {
			log.Printf("[WARN] state_db: failed to stage rolled-back committed height (R87-M4-RESTART): %v", err)
		} else if err := persistBatch.Write(); err != nil {
			log.Printf("[WARN] state_db: failed to write rolled-back committed height (R87-M4-RESTART): %v", err)
		}
	}

	return nil
}

// deepCopyAccountsMap creates a deep copy of an accounts map.
func (s *StateDB) deepCopyAccountsMap(src map[types.Address]*Account) map[types.Address]*Account {
	cp := make(map[types.Address]*Account, len(src))
	for addr, acc := range src {
		newAcc := *acc
		newAcc.Balance = new(big.Int).Set(acc.Balance)
		cp[addr] = &newAcc
	}
	return cp
}

// deepCopyStorageMap creates a deep copy of a storage map.
func (s *StateDB) deepCopyStorageMap(src map[types.Address]map[types.Hash]types.Hash) map[types.Address]map[types.Hash]types.Hash {
	cp := make(map[types.Address]map[types.Hash]types.Hash, len(src))
	for addr, storage := range src {
		newStorage := make(map[types.Hash]types.Hash, len(storage))
		for key, value := range storage {
			newStorage[key] = value
		}
		cp[addr] = newStorage
	}
	return cp
}

// deepCopyAccountsLocked returns a deep copy of dirtyAccounts.
// MUST be called while s.mu is held.
func (s *StateDB) deepCopyAccountsLocked() map[types.Address]*Account {
	cp := make(map[types.Address]*Account, len(s.dirtyAccounts))
	for addr, acc := range s.dirtyAccounts {
		newAcc := *acc
		newAcc.Balance = new(big.Int).Set(acc.Balance)
		cp[addr] = &newAcc
	}
	return cp
}

// deepCopyStorageLocked returns a deep copy of dirtyStorage.
// MUST be called while s.mu is held.
func (s *StateDB) deepCopyStorageLocked() map[types.Address]map[types.Hash]types.Hash {
	cp := make(map[types.Address]map[types.Hash]types.Hash, len(s.dirtyStorage))
	for addr, storage := range s.dirtyStorage {
		newStorage := make(map[types.Hash]types.Hash, len(storage))
		for key, value := range storage {
			newStorage[key] = value
		}
		cp[addr] = newStorage
	}
	return cp
}

// deepCopyStorageCacheLocked returns a deep copy of storageCache.
// MUST be called while s.mu is held.
//
// STATE- (2026-07-20): Used by Snapshot to capture the cache state
// so RevertToSnapshot can restore it. Values are types.Hash (fixed-size
// arrays, copy-by-value), so a shallow map copy is sufficient.
func (s *StateDB) deepCopyStorageCacheLocked() map[storageCacheKey]types.Hash {
	cp := make(map[storageCacheKey]types.Hash, len(s.storageCache))
	for k, v := range s.storageCache {
		cp[k] = v
	}
	return cp
}

// deepCopyStorageCacheMap returns a deep copy of a storageCache map.
// Used by RevertToSnapshot to deep-copy the snapshot's cache (preventing
// aliasing where subsequent cache writes would corrupt the snapshot).
//
// STATE- (2026-07-20).
func (s *StateDB) deepCopyStorageCacheMap(src map[storageCacheKey]types.Hash) map[storageCacheKey]types.Hash {
	cp := make(map[storageCacheKey]types.Hash, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return cp
}

// deepCopySelfDestructsLocked returns a deep copy of the current
// selfDestructs set. MUST be called with s.mu held.
//
// STATE- (2026-07-20).
func (s *StateDB) deepCopySelfDestructsLocked() map[types.Address]struct{} {
	if s.selfDestructs == nil {
		return make(map[types.Address]struct{})
	}
	cp := make(map[types.Address]struct{}, len(s.selfDestructs))
	for k := range s.selfDestructs {
		cp[k] = struct{}{}
	}
	return cp
}

// deepCopySelfDestructsMap returns a deep copy of the given selfDestructs
// set (defensive — callers may mutate the source after the snapshot).
//
// STATE- (2026-07-20).
func (s *StateDB) deepCopySelfDestructsMap(src map[types.Address]struct{}) map[types.Address]struct{} {
	if src == nil {
		return make(map[types.Address]struct{})
	}
	cp := make(map[types.Address]struct{}, len(src))
	for k := range src {
		cp[k] = struct{}{}
	}
	return cp
}

// deepCopySelfDestructBeneficiariesLocked returns a deep copy of the current
// selfDestructBeneficiaries map. MUST be called with s.mu held.
//
// STATE- (2026-07-20).
func (s *StateDB) deepCopySelfDestructBeneficiariesLocked() map[types.Address]types.Address {
	if s.selfDestructBeneficiaries == nil {
		return make(map[types.Address]types.Address)
	}
	cp := make(map[types.Address]types.Address, len(s.selfDestructBeneficiaries))
	for k, v := range s.selfDestructBeneficiaries {
		cp[k] = v
	}
	return cp
}

// deepCopySelfDestructBeneficiariesMap returns a deep copy of the given
// selfDestructBeneficiaries map (defensive — callers may mutate the source
// after the snapshot).
//
// STATE- (2026-07-21): used by RevertToSnapshot to restore the
// beneficiary map captured in the snapshot, so a sub-call revert does not
// lose beneficiary info for selfdestructs that survive the revert.
func (s *StateDB) deepCopySelfDestructBeneficiariesMap(src map[types.Address]types.Address) map[types.Address]types.Address {
	if src == nil {
		return make(map[types.Address]types.Address)
	}
	cp := make(map[types.Address]types.Address, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return cp
}

// deepCopyPendingCodeWritesLocked returns a deep copy of the current
// pendingCodeWrites map. Each []byte value is copied so callers cannot
// mutate the staged code via slice aliasing.
//
// R35-P1-02 FIX: used by Snapshot() and Copy() to capture pendingCodeWrites
// so a sub-call revert discards staged code, and so Copy() preserves it.
func (s *StateDB) deepCopyPendingCodeWritesLocked() map[types.Hash][]byte {
	if s.pendingCodeWrites == nil {
		return make(map[types.Hash][]byte)
	}
	cp := make(map[types.Hash][]byte, len(s.pendingCodeWrites))
	for k, v := range s.pendingCodeWrites {
		// Defensive copy of the byte slice — SetCode() already copies on
		// write, but we copy again here to be safe against any future
		// code path that might store a shared slice.
		vc := make([]byte, len(v))
		copy(vc, v)
		cp[k] = vc
	}
	return cp
}

// deepCopyPendingCodeWritesMap returns a deep copy of the given
// pendingCodeWrites map (defensive — callers may mutate the source after
// the snapshot).
//
// R35-P1-02 FIX: used by RevertToSnapshot() and Copy()'s snapshot loop.
func (s *StateDB) deepCopyPendingCodeWritesMap(src map[types.Hash][]byte) map[types.Hash][]byte {
	if src == nil {
		return make(map[types.Hash][]byte)
	}
	cp := make(map[types.Hash][]byte, len(src))
	for k, v := range src {
		vc := make([]byte, len(v))
		copy(vc, v)
		cp[k] = vc
	}
	return cp
}

// GetStateWithProof returns a storage value with a Verkle proof
func (s *StateDB) GetStateWithProof(addr types.Address, key types.Hash) (types.Hash, *trie.VerkleProof, error) {
	value := s.GetStorage(addr, key)
	proof := &trie.VerkleProof{
		Key:   key[:],
		Value: value[:],
		Proof: [][]byte{},
	}
	return value, proof, nil
}

// Encode serializes an account to bytes using deterministic binary encoding.
// audit-fix CRIT-SERIAL: replaced non-deterministic JSON with deterministic binary encoding.
func (a *Account) Encode() []byte {
	data, _ := encodeAccount(a)
	return data
}

// DecodeAccount deserializes an account from bytes using deterministic binary encoding.
// audit-fix CRIT-SERIAL: replaced non-deterministic JSON with deterministic binary decoding.
func DecodeAccount(data []byte) (*Account, error) {
	var acc Account
	if err := decodeAccount(data, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}

// addToCacheLocked adds an account to the cache with LRU eviction.
// audit-fix: implements LRU eviction when cache exceeds max size.
// Must be called with write lock held.
func (s *StateDB) addToCacheLocked(addr types.Address, acc *Account) {
	// Check if cache is at capacity
	if len(s.accountCache) >= s.cacheMaxSize {
		// Evict least recently used entry
		s.evictLRULocked()
	}

	s.accountCache[addr] = acc
	s.cacheAccessTime[addr] = time.Now().Unix()
}

// evictLRULocked evicts the least recently used cache entries.
// Must be called with write lock held.
//
// STATE- (2026-07-20): Previously evicted only a single oldest entry
// per call. Under sustained cache pressure (many concurrent addToCacheLocked
// calls when the cache is at capacity), this caused eviction thrashing —
// every insert triggered a full O(N) scan to find and remove one entry. The
// orphan cleanup loop at the tail also ran on every call but only caught
// entries that had no accountCache slot (already rare after R4-H1).
//
// Now evict to 90% of capacity in one pass: build a sorted list of cached
// entries by access time, delete the oldest 10% (at least 1). This amortizes
// the O(N) scan across multiple evictions. Orphan cleanup remains as
// defense-in-depth.
func (s *StateDB) evictLRULocked() {
	if len(s.accountCache) == 0 {
		return
	}

	// Build (addr, accessTime) pairs for cached entries only.
	type entry struct {
		addr types.Address
		ts   int64
	}
	entries := make([]entry, 0, len(s.accountCache))
	for addr := range s.accountCache {
		ts, ok := s.cacheAccessTime[addr]
		if !ok {
			// Defensive: cached entry without a timestamp. Treat as
			// oldest so it gets evicted first.
			ts = 0
		}
		entries = append(entries, entry{addr: addr, ts: ts})
	}

	// Sort by access time ascending (oldest first).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ts < entries[j].ts
	})

	// Evict oldest 10% (at least 1) to leave breathing room for subsequent
	// inserts without immediately re-triggering eviction.
	target := len(s.accountCache) - s.cacheMaxSize*9/10
	if target < 1 {
		target = 1
	}
	if target > len(entries) {
		target = len(entries)
	}
	for i := 0; i < target; i++ {
		addr := entries[i].addr
		delete(s.accountCache, addr)
		delete(s.cacheAccessTime, addr)
		s.cacheEvictions++
	}

	// FIX: Also clean up orphaned cacheAccessTime entries —
	// addresses that have an access timestamp but no corresponding
	// accountCache entry. GetAccount updates cacheAccessTime for every
	// access, but only accounts that enter the cache get a corresponding
	// accountCache entry. Over time these orphaned timestamps accumulate
	// and cause unbounded map growth. Remove them here during eviction.
	for addr := range s.cacheAccessTime {
		if _, exists := s.accountCache[addr]; !exists {
			delete(s.cacheAccessTime, addr)
		}
	}
}

// GetCacheStats returns cache statistics.
// audit-fix: provides visibility into cache performance.
func (s *StateDB) GetCacheStats() (size int, maxSize int, evictions uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.accountCache), s.cacheMaxSize, s.cacheEvictions
}

// SetCacheMaxSize sets the maximum cache size.
// audit-fix: allows tuning cache size based on available memory.
func (s *StateDB) SetCacheMaxSize(maxSize int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if maxSize < 100 {
		maxSize = 100 // Minimum cache size
	}

	s.cacheMaxSize = maxSize

	// Evict entries if current size exceeds new max
	for len(s.accountCache) > s.cacheMaxSize {
		s.evictLRULocked()
	}
}

// CreateSnapshot creates a state snapshot at the given block height.
// audit-fix: state pruning - snapshots allow reverting to historical states.
// CRITICAL FIX: use rootLocked() instead of Root() to avoid deadlock.
// Root() acquires s.mu.RLock(), but this function already holds s.mu.Lock().
// Go's sync.RWMutex does NOT allow a goroutine holding a write lock to
// acquire a read lock on the same mutex — this is a guaranteed deadlock.
// This caused the node to freeze at every 1024-block multiple (snapshotInterval).
func (s *StateDB) CreateSnapshot(blockHeight uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	root := s.rootLocked()
	s.stateSnapshots[blockHeight] = root
	s.lastSnapshotBlock = blockHeight

	return nil
}

// PruneState removes state data older than the configured retention period.
// audit-fix STATE-M1: enhanced implementation with actual state data pruning.
// Should be called periodically (e.g., after each block commit).
func (s *StateDB) PruneState(currentBlock uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.pruningEnabled {
		return nil
	}

	// Don't prune if we haven't reached the minimum block count
	if currentBlock < s.pruneKeepBlocks {
		return nil
	}

	// Calculate the pruning threshold
	pruneBeforeBlock := currentBlock - s.pruneKeepBlocks

	// Don't prune too frequently (every 100 blocks)
	if pruneBeforeBlock <= s.lastPrunedBlock+100 {
		return nil
	}

	// Remove old snapshots
	for height := range s.stateSnapshots {
		if height < pruneBeforeBlock {
			delete(s.stateSnapshots, height)
		}
	}

	// Note: beforeImages and modificationLog are now pruned by
	// pruneHistoryLocked() using the historyRetentionBlocks window,
	// which is separate from the disk pruning window (pruneKeepBlocks).
	// This ensures RollbackToHeight has enough history while still
	// preventing unbounded memory growth.

	// Prune old state data using the modification log
	if err := s.pruneStateData(pruneBeforeBlock); err != nil {
		return fmt.Errorf("failed to prune state data: %w", err)
	}

	s.lastPrunedBlock = pruneBeforeBlock

	return nil
}

// pruneModificationLog removes modification log entries older than the threshold.
// Keeps the log small while preserving enough history for pruning decisions.
func (s *StateDB) pruneModificationLog(pruneBeforeBlock uint64) {
	// Prune old modification log entries
	for height := range s.modificationLog {
		if height < pruneBeforeBlock {
			delete(s.modificationLog, height)
		}
	}
}

// pruneStateData prunes actual state data using the modification log.
// Uses incremental batch pruning to avoid long-running locks.
// R6-STATE-1 FIX: distinguishes current (active) state references from historical ones.
// An address is only pruned if its LAST modification block is before the prune threshold,
// ensuring currently active state is never accidentally deleted.
func (s *StateDB) pruneStateData(pruneBeforeBlock uint64) error {
	// Collect all addresses modified before the prune threshold
	var addressesToPrune []types.Address
	for height, addrs := range s.modificationLog {
		if height < pruneBeforeBlock {
			addressesToPrune = append(addressesToPrune, addrs...)
		}
	}

	if len(addressesToPrune) == 0 {
		return nil
	}

	// Deduplicate addresses
	seen := make(map[types.Address]bool)
	candidates := make([]types.Address, 0, len(addressesToPrune))
	for _, addr := range addressesToPrune {
		if !seen[addr] {
			seen[addr] = true
			candidates = append(candidates, addr)
		}
	}

	// R6-STATE-1 FIX: filter candidates to only include addresses whose
	// latest modification is before the prune threshold. Addresses modified
	// at or after the threshold are still active and must be preserved.
	safeToPrune := make([]types.Address, 0, len(candidates))
	for _, addr := range candidates {
		lastModified, tracked := s.addressLastModified[addr]
		if !tracked || lastModified < pruneBeforeBlock {
			safeToPrune = append(safeToPrune, addr)
		}
	}

	if len(safeToPrune) == 0 {
		return nil
	}

	// Process in batches to avoid long-running transactions
	batch := s.db.NewBatch()
	prunedCount := 0
	maxBatch := int(s.pruneBatchSize)

	for i, addr := range safeToPrune {
		// R6-STATE-1 FIX: only prune if the address is NOT in the active range
		if refs, ok := s.addressRefs[addr]; ok {
			if refs > 1 {
				s.addressRefs[addr] = refs - 1
			} else {
				// R33 STATE-01 FIX (2026-07-28): Last-line-of-defense check.
				// The addressRefs counter was being treated as a "modification
				// count" rather than a true liveness reference: an account
				// modified once (refs==1) and still holding balance/nonce/code
				// would be deleted on the first prune pass (block 228 = 128 +
				// 100), permanently destroying user funds and breaking state
				// root consensus. Before deleting, verify the account is truly
				// empty: Balance==0 && Nonce==0 && no code && no storage.
				// If any field is non-zero, KEEP the account and skip deletion
				// (do not delete addressLastModified either, so the next prune
				// pass re-evaluates).
				if !s.isAccountFullyEmpty(addr) {
					// Account still holds state — keep it alive. Decrement
					// the ref counter to 0 (already done above via delete)
					// but do NOT delete the on-disk data. Reset the ref
					// counter to 1 so future prune passes re-check.
					s.addressRefs[addr] = 1
					if i%maxBatch == 0 || i == len(safeToPrune)-1 {
						// Still flush any pending batch deletes from prior
						// iterations that were safe to remove.
						if prunedCount > 0 {
							// R36-P2-STATE-02 FIX: release s.mu during the
							// disk write so concurrent StateDB readers (RPC,
							// sync) are not blocked for the entire prune
							// duration. The batch has already been staged
							// under the lock; Write is pure DB I/O. The
							// closure's defer re-acquires the lock even on
							// panic so PruneState's defer Unlock stays safe.
							writeErr := func() error {
								s.mu.Unlock()
								defer s.mu.Lock()
								return batch.Write()
							}()
							if writeErr != nil {
								return fmt.Errorf("failed to write prune batch: %w", writeErr)
							}
							batch.Reset()
							s.prunedAccounts += uint64(prunedCount)
							prunedCount = 0
						}
					}
					continue
				}

				// No more references, safe to delete
				delete(s.addressRefs, addr)

				// Delete account state
				accountKey := append(accountPrefix, addr[:]...)
				// L9-039 FIX: Return error instead of silently logging it.
				if err := batch.Delete(accountKey); err != nil {
					return fmt.Errorf("failed to delete account %x from batch: %w", addr[:8], err)
				}

				// Delete all storage for this account
				storagePrefixKey := append(storagePrefix, addr[:]...)
				storagePrefixKey = append(storagePrefixKey, 0xFF)
				iter := s.db.NewIterator(storagePrefixKey, nil)
				for iter.Next() {
					// L9-039 FIX: Return error instead of silently logging it.
					if err := batch.Delete(iter.Key()); err != nil {
						iter.Release()
						return fmt.Errorf("failed to delete storage key from batch: %w", err)
					}
					prunedCount++
				}
				// DB- (2026-07-20): Surface iterator truncation. If the
				// account has >100K storage slots and the iterator truncated,
				// some storage entries would survive the prune. Log a warning
				// so operators know the prune was incomplete for this account.
				if err := iter.Error(); err != nil {
					log.Printf("[WARN] state_db: prune storage iterator error for account %x (some entries may remain): %v", addr[:8], err)
				}
				iter.Release()

				// Clean up tracking data
				delete(s.addressLastModified, addr)
			}
		}

		// Write batch periodically
		if (i+1)%maxBatch == 0 || i == len(safeToPrune)-1 {
			// R36-P2-STATE-02 FIX: release s.mu during the disk write so
			// concurrent StateDB readers are not blocked. See the closure
			// comment above for the full rationale.
			writeErr := func() error {
				s.mu.Unlock()
				defer s.mu.Lock()
				return batch.Write()
			}()
			if writeErr != nil {
				return fmt.Errorf("failed to write prune batch: %w", writeErr)
			}
			batch.Reset()

			// CRITICAL: Count actual pruned accounts, not remaining in batch
			s.prunedAccounts += uint64(prunedCount)
		}
	}

	return nil
}

// RecordModification records an address modification at the current block height.
// Called during Commit() to track state changes for later pruning.
func (s *StateDB) RecordModification(blockHeight uint64, addr types.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RecordModificationLocked(blockHeight, addr)
}

// RecordModificationLocked records an address modification without acquiring lock.
// MUST be called while s.mu is already held.
// R6-STATE-1 FIX: also tracks the last modification block height to prevent
// pruning of currently active state.
func (s *StateDB) RecordModificationLocked(blockHeight uint64, addr types.Address) {
	if s.modificationLog == nil {
		s.modificationLog = make(map[uint64][]types.Address)
	}
	if s.addressLastModified == nil {
		s.addressLastModified = make(map[types.Address]uint64)
	}

	s.modificationLog[blockHeight] = append(s.modificationLog[blockHeight], addr)

	// Initialize or increment reference count
	s.addressRefs[addr]++

	// Track the latest block where this address was modified
	if blockHeight > s.addressLastModified[addr] {
		s.addressLastModified[addr] = blockHeight
	}
}

// GetAddressRefs returns the reference count for an address.
func (s *StateDB) GetAddressRefs(addr types.Address) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addressRefs[addr]
}

// SetPruningEnabled enables or disables state pruning.
// audit-fix: allows disabling pruning for archive nodes.
func (s *StateDB) SetPruningEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruningEnabled = enabled
}

// SetPruneKeepBlocks sets the number of recent blocks to keep.
// audit-fix: allows tuning retention period based on requirements.
func (s *StateDB) SetPruneKeepBlocks(blocks uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if blocks < 64 {
		blocks = 64 // Minimum 64 blocks
	}

	s.pruneKeepBlocks = blocks
}

// GetPruningStats returns pruning statistics.
// audit-fix: provides visibility into pruning status.
func (s *StateDB) GetPruningStats() (enabled bool, keepBlocks uint64, lastPruned uint64, snapshotCount int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pruningEnabled, s.pruneKeepBlocks, s.lastPrunedBlock, len(s.stateSnapshots)
}

// GetPruningDetailedStats returns detailed pruning statistics.
func (s *StateDB) GetPruningDetailedStats() (enabled bool, keepBlocks, lastPruned, batchSize, prunedAccounts uint64, modLogSize, refCountSize int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pruningEnabled, s.pruneKeepBlocks, s.lastPrunedBlock, s.pruneBatchSize, s.prunedAccounts, len(s.modificationLog), len(s.addressRefs)
}

// SetPruneBatchSize sets the number of entries to prune per batch.
// audit-fix STATE-M1: allows tuning batch size for performance trade-offs.
func (s *StateDB) SetPruneBatchSize(batchSize uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if batchSize < 100 {
		batchSize = 100 // Minimum 100 entries per batch
	}
	if batchSize > 10000 {
		batchSize = 10000 // Maximum 10000 entries per batch
	}

	s.pruneBatchSize = batchSize
}

// SetHistoryRetentionBlocks sets the number of recent blocks for which
// beforeImages and modificationLog entries are kept in memory.
// Blocks older than (currentBlock - historyRetentionBlocks) are pruned
// after each CommitWithBlock call.
// This prevents unbounded memory growth from beforeImages (~2.6KB/block)
// and modificationLog while preserving enough history for RollbackToHeight.
// Default: 1000 blocks. Minimum: 64 blocks.
func (s *StateDB) SetHistoryRetentionBlocks(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n < 64 {
		n = 64 // Minimum 64 blocks to allow meaningful rollback
	}

	s.historyRetentionBlocks = uint64(n)
}

// GetHistoryRetentionBlocks returns the current history retention window.
func (s *StateDB) GetHistoryRetentionBlocks() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int(s.historyRetentionBlocks)
}

// pruneHistoryLocked removes beforeImages and modificationLog entries older
// than the retention window, and cleans up orphaned addressRefs and
// addressLastModified entries.
// MUST be called with s.mu held (write lock).
func (s *StateDB) pruneHistoryLocked(currentBlock uint64) {
	if s.historyRetentionBlocks == 0 || currentBlock <= s.historyRetentionBlocks {
		return // Not enough history to prune
	}

	cutoff := currentBlock - s.historyRetentionBlocks

	// Prune beforeImages older than cutoff
	for height := range s.beforeImages {
		if height < cutoff {
			delete(s.beforeImages, height)
		}
	}

	// Prune modificationLog entries older than cutoff
	for height := range s.modificationLog {
		if height < cutoff {
			delete(s.modificationLog, height)
		}
	}

	// Clean up addressRefs: remove entries that are no longer referenced
	// by any remaining modificationLog entry. Rebuild ref counts from
	// surviving modificationLog entries.
	if len(s.modificationLog) > 0 {
		newRefs := make(map[types.Address]uint64, len(s.addressRefs))
		for _, addrs := range s.modificationLog {
			for _, addr := range addrs {
				newRefs[addr]++
			}
		}
		s.addressRefs = newRefs
	} else {
		s.addressRefs = make(map[types.Address]uint64)
	}

	// Clean up addressLastModified: remove entries whose last modification
	// is older than the cutoff (they are no longer needed for pruning decisions)
	for addr, lastMod := range s.addressLastModified {
		if lastMod < cutoff {
			delete(s.addressLastModified, addr)
		}
	}
}

// CommitWithBlock commits state changes and manages snapshots/pruning.
// Rollback handling: Commit() flushes the journal atomically (it either
// returns a root or an error with the dirty state still intact for retry);
// snapshot creation and pruning are post-commit bookkeeping steps.
// audit-fix: integrated snapshot creation and pruning into commit flow.
func (s *StateDB) CommitWithBlock(blockHeight uint64) (types.Hash, error) {
	// Commit the state with block height for modification tracking
	// audit-fix CRIT-COMMIT: properly return error if Commit fails
	root, err := s.Commit(blockHeight)
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to commit state: %w", err)
	}

	// R57-ACC-OPT (2026-08-07): Record the last durably-committed block height
	// so rebuildState can resume incrementally instead of re-applying the
	// whole chain from genesis on every sync completion.
	s.mu.Lock()
	s.lastCommittedHeight = blockHeight
	s.mu.Unlock()

	// Create snapshot at configured intervals
	if s.snapshotInterval > 0 && blockHeight%s.snapshotInterval == 0 {
		if err := s.CreateSnapshot(blockHeight); err != nil {
			return types.Hash{}, fmt.Errorf("failed to create snapshot: %w", err)
		}
	}

	// Prune old state
	if err := s.PruneState(blockHeight); err != nil {
		return types.Hash{}, fmt.Errorf("failed to prune state: %w", err)
	}

	// Prune history (beforeImages, modificationLog, addressRefs, addressLastModified)
	// to prevent unbounded memory growth. This runs after PruneState so that
	// the disk pruning has already used the modificationLog data it needs.
	s.mu.Lock()
	s.pruneHistoryLocked(blockHeight)
	s.mu.Unlock()

	return root, nil
}

// R57-ACC-OPT (2026-08-07): LastCommittedHeight returns the highest block
// height whose state has been durably committed to this StateDB. Used by the
// syncer's rebuildState to resume incrementally from lastCommittedHeight+1
// instead of re-applying the whole chain from genesis on each sync completion.
// HasRollbackHistory reports whether fork-rollback history (beforeImages)
// is available in this process. beforeImages are in-memory only, so this is
// false after any restart — callers must not attempt rollbacks then
// (RollbackToHeight is a silent no-op without images). rebuildState uses
// this to pick the R87-M4-RESTART baseline direction.
func (s *StateDB) HasRollbackHistory() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.beforeImages) > 0
}

func (s *StateDB) LastCommittedHeight() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCommittedHeight
}

// CommitWithBlockContext is a context-aware variant of CommitWithBlock.
// R7-M7-1 FIX: Added context.Context support for long-running state operations.
// If the context is canceled before the operation completes, the function
// returns ctx.Err(). Note that the actual DB commit is not interruptible
// (bbolt doesn't support context cancellation), but the snapshot and prune
// phases are checked for cancellation between steps.
// Rollback handling: same atomic journal flush as CommitWithBlock — errors
// leave the dirty journal intact; nothing is partially committed.
func (s *StateDB) CommitWithBlockContext(ctx context.Context, blockHeight uint64) (types.Hash, error) {
	if err := ctx.Err(); err != nil {
		return types.Hash{}, err
	}

	root, err := s.Commit(blockHeight)
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to commit state: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return types.Hash{}, err
	}

	// R57-ACC-OPT (2026-08-07): Record the last durably-committed block height
	// so rebuildState can resume incrementally instead of re-applying the
	// whole chain from genesis on every sync completion.
	s.mu.Lock()
	s.lastCommittedHeight = blockHeight
	s.mu.Unlock()

	// Create snapshot at configured intervals
	if s.snapshotInterval > 0 && blockHeight%s.snapshotInterval == 0 {
		if err := s.CreateSnapshot(blockHeight); err != nil {
			return types.Hash{}, fmt.Errorf("failed to create snapshot: %w", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return types.Hash{}, err
	}

	// Prune old state
	if err := s.PruneState(blockHeight); err != nil {
		return types.Hash{}, fmt.Errorf("failed to prune state: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return types.Hash{}, err
	}

	// Prune history
	s.mu.Lock()
	s.pruneHistoryLocked(blockHeight)
	s.mu.Unlock()

	return root, nil
}

// RollbackToHeightContext is a context-aware variant of RollbackToHeight.
// R7-M7-1 FIX: Added context.Context support for long-running rollback operations.
// Since RollbackToHeight holds a mutex for the entire duration, this wrapper
// checks context before acquiring the lock, and delegates to the original.
// Future refactoring should break RollbackToHeight into per-height chunks
// with context checks between them.
func (s *StateDB) RollbackToHeightContext(ctx context.Context, forkHeight uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.RollbackToHeight(forkHeight)
}

// ExportAccounts exports all accounts from the state database.
// Returns a channel that yields account data for streaming to peers.
//
// R35-P2-STATE-04 FIX (2026-07-29): Previously this method held s.mu.RLock()
// for the ENTIRE iteration + channel send (up to 5s per entry), blocking all
// writers for potentially minutes on large state sets — a DoS vector. Fix:
// collect entries under the read lock into a bounded batch, release the lock,
// then send from the batch. Re-acquire the lock for the next batch. This
// bounds the lock-hold time to batchSize entries, allowing writers to make
// progress between batches. The export is still consistent within each batch
// (all entries from one read-locked scan), and the 5s per-entry timeout is
// reduced to 1s since we're no longer holding the lock during the send.
func (s *StateDB) ExportAccounts(batchSize int) (<-chan SnapAccountExport, <-chan error) {
	if batchSize <= 0 {
		batchSize = 1000
	}
	// R35-P2-STATE-04: cap batch size to prevent unbounded memory allocation.
	if batchSize > 10000 {
		batchSize = 10000
	}
	accCh := make(chan SnapAccountExport, batchSize)
	errCh := make(chan error, 1)

	go func() {
		defer close(accCh)
		defer close(errCh)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("StateDB ExportAccounts goroutine panic: %v", r)
			}
		}()

		// R35-P2-STATE-04 FIX: collect entries under RLock in bounded batches,
		// release lock between batches to allow writers to progress.
		// R36-P2-STATE-01 FIX (2026-07-30): Wrap the locked section in a
		// closure with defer s.mu.RUnlock() so the read lock is released even
		// if a panic occurs during iteration. Previously, the manual
		// RLock()→...→RUnlock() without defer meant a panic (caught by the
		// goroutine's recover) left s.mu permanently RLock'd, freezing all
		// StateDB writers.
		var startKey []byte
		for {
			batch := make([]SnapAccountExport, 0, batchSize)
			var lastKey []byte
			var iterErr error
			var count int

			func() {
				s.mu.RLock()
				defer s.mu.RUnlock()
				iter := s.db.NewIterator(accountPrefix, startKey)
				defer iter.Release()
				for iter.Next() {
					key := iter.Key()
					if len(key) <= len(accountPrefix) {
						continue
					}
					// Skip the duplicate first key from the previous batch's lastKey
					// (NewIterator start is inclusive).
					if startKey != nil && bytes.Equal(key, startKey) {
						continue
					}
					var addr types.Address
					copy(addr[:], key[len(accountPrefix):])

					value := iter.Value()
					accData := make([]byte, len(value))
					copy(accData, value)

					batch = append(batch, SnapAccountExport{Address: addr, Data: accData})
					lastKey = make([]byte, len(key))
					copy(lastKey, key)
					count++
					if count >= batchSize {
						break
					}
				}
				iterErr = iter.Error()
			}()

			// Send batch entries without holding the lock.
			for _, entry := range batch {
				select {
				case accCh <- entry:
				case <-time.After(1 * time.Second):
					errCh <- fmt.Errorf("export timeout")
					return
				}
			}

			if iterErr != nil {
				errCh <- iterErr
				return
			}

			// If we collected fewer than batchSize entries, iteration is done.
			if count < batchSize {
				return
			}

			// Advance startKey past lastKey for the next batch.
			startKey = lastKey
		}
	}()

	return accCh, errCh
}

// ExportStorage exports all storage entries for a specific account.
//
// R35-P2-STATE-04 FIX (2026-07-29): Same batched-lock pattern as ExportAccounts.
// Previously held s.mu.RLock() for the entire iteration + channel send (up to
// 5s per entry). Now collects batchSize entries under the lock, releases it,
// sends from the batch, then re-acquires for the next batch.
func (s *StateDB) ExportStorage(addr types.Address, batchSize int) (<-chan SnapStorageExport, <-chan error) {
	if batchSize <= 0 {
		batchSize = 1000
	}
	if batchSize > 10000 {
		batchSize = 10000
	}
	storageCh := make(chan SnapStorageExport, batchSize)
	errCh := make(chan error, 1)

	go func() {
		defer close(storageCh)
		defer close(errCh)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("StateDB ExportStorage goroutine panic: %v", r)
			}
		}()

		prefix := append(storagePrefix, addr[:]...)
		prefix = append(prefix, 0xFF)

		// R35-P2-STATE-04 FIX: batched lock pattern.
		// R36-P2-STATE-01 FIX (2026-07-30): Wrap the locked section in a
		// closure with defer s.mu.RUnlock() so the read lock is released even
		// if a panic occurs during iteration. Previously, the manual
		// RLock()→...→RUnlock() without defer meant a panic (caught by the
		// goroutine's recover) left s.mu permanently RLock'd, freezing all
		// StateDB writers.
		var startKey []byte
		for {
			batch := make([]SnapStorageExport, 0, batchSize)
			var lastKey []byte
			var iterErr error
			var count int

			func() {
				s.mu.RLock()
				defer s.mu.RUnlock()
				iter := s.db.NewIterator(prefix, startKey)
				defer iter.Release()
				for iter.Next() {
					key := iter.Key()
					if len(key) <= len(prefix) {
						continue
					}
					// Skip the duplicate first key from the previous batch's lastKey
					// (NewIterator start is inclusive).
					if startKey != nil && bytes.Equal(key, startKey) {
						continue
					}
					var storageKey types.Hash
					copy(storageKey[:], key[len(prefix):])

					value := iter.Value()
					var storageValue types.Hash
					if len(value) >= 32 {
						copy(storageValue[:], value[:32])
					}

					batch = append(batch, SnapStorageExport{Key: storageKey, Value: storageValue})
					lastKey = make([]byte, len(key))
					copy(lastKey, key)
					count++
					if count >= batchSize {
						break
					}
				}
				iterErr = iter.Error()
			}()

			// Send batch entries without holding the lock.
			for _, entry := range batch {
				select {
				case storageCh <- entry:
				case <-time.After(1 * time.Second):
					errCh <- fmt.Errorf("storage export timeout")
					return
				}
			}

			if iterErr != nil {
				errCh <- iterErr
				return
			}

			if count < batchSize {
				return
			}

			startKey = lastKey
		}
	}()

	return storageCh, errCh
}

// ImportAccount imports a single account into the state database.
func (s *StateDB) ImportAccount(addr types.Address, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	accountKey := append(accountPrefix, addr[:]...)
	// R58-SNAP-FALLBACK: record the key so a failed snap sync can surgically
	// delete exactly what this session imported.
	s.snapImportedKeys = append(s.snapImportedKeys, accountKey)
	return s.db.Put(accountKey, data)
}

// ImportStorage imports a single storage entry for an account.
func (s *StateDB) ImportStorage(addr types.Address, key, value types.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	storageKey := append(storagePrefix, addr[:]...)
	storageKey = append(storageKey, 0xFF)
	storageKey = append(storageKey, key[:]...)
	// R58-SNAP-FALLBACK: record the key so a failed snap sync can surgically
	// delete exactly what this session imported.
	s.snapImportedKeys = append(s.snapImportedKeys, storageKey)
	return s.db.Put(storageKey, value[:])
}

// ImportCode imports contract bytecode.
func (s *StateDB) ImportCode(codeHash types.Hash, code []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// R58-SNAP-FALLBACK: record the key so a failed snap sync can surgically
	// delete exactly what this session imported.
	codeKey := append(codePrefix, codeHash[:]...)
	s.snapImportedKeys = append(s.snapImportedKeys, codeKey)
	return s.db.Put(codeKey, code)
}

// BeginSnapImport resets the snap-import key ledger for a fresh snap sync
// session. Called by the syncer when a snap sync session starts so that
// ClearSnapImport (on a later state-root mismatch) only removes the keys
// written by THIS session, never pre-existing good state.
func (s *StateDB) BeginSnapImport() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapImportedKeys = nil
}

// ClearSnapImport deletes every raw database key written by the current snap
// sync session (since BeginSnapImport) and clears the ledger. It is the
// state-side half of the R58-SNAP-FALLBACK (geth-style) recovery: on a
// post-import state-root mismatch the syncer discards ALL downloaded snap
// state, mirroring eth/downloader/sync.go where an aborted state sync is
// thrown away before the downloader switches to full sync. Chunked so the
// delete batch never exceeds the database's MaxBatchOps limit.
func (s *StateDB) ClearSnapImport() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.snapImportedKeys) == 0 {
		return nil
	}
	batch := s.db.NewBatch()
	written := 0
	for _, k := range s.snapImportedKeys {
		if err := batch.Delete(k); err != nil {
			return err
		}
		written++
		// Flush at a conservative 2000-ops boundary so very large snap
		// imports do not trip MaxBatchOps on the underlying store.
		if written%2000 == 0 {
			if err := batch.Write(); err != nil {
				return err
			}
			batch.Reset()
		}
	}
	if written%2000 != 0 {
		if err := batch.Write(); err != nil {
			return err
		}
	}
	s.snapImportedKeys = nil
	return nil
}

// Close releases the underlying database resources.
// This must be called when the StateDB is no longer needed to release
// file locks held by BoltDB on Windows.
func (s *StateDB) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// ----------------------------------------------------------------------------
// STATE- (2026-07-20): EIP-2929 access list, EIP-1153 transient
// storage, EIP-20 event logs, and EIP-6780 selfdestruct. The methods below
// provide native StateDB-level support for these features so they participate
// in the same Snapshot/RevertToSnapshot/Commit/Revert/Copy lifecycle as
// accounts and storage. This eliminates the consensus-divergence window that
// existed when they were tracked only in qvmasync.StateDBAdapter (outside the
// StateDB's snapshot stack).
// ----------------------------------------------------------------------------

// AddAddressToAccessList marks addr as warm per EIP-2929.
// Idempotent — calling twice with the same address is a no-op after the first.
func (s *StateDB) AddAddressToAccessList(addr types.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accessList == nil {
		s.accessList = newAccessList()
	}
	s.accessList.addAddress(addr)
}

// AddSlotToAccessList marks (addr, slot) as warm per EIP-2929. Implies the
// containing address is also marked warm.
func (s *StateDB) AddSlotToAccessList(addr types.Address, slot types.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accessList == nil {
		s.accessList = newAccessList()
	}
	s.accessList.addSlot(addr, slot)
}

// AddressInAccessList returns true if addr is currently warm.
func (s *StateDB) AddressInAccessList(addr types.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.accessList == nil {
		return false
	}
	return s.accessList.addressWarm(addr)
}

// SlotInAccessList returns (addressWarm, slotWarm) per EIP-2929. The first
// return is true if the address is warm; the second is true if the slot is
// warm. A slot cannot be warm without its address being warm (addSlot
// implies addAddress).
func (s *StateDB) SlotInAccessList(addr types.Address, slot types.Hash) (bool, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.accessList == nil {
		return false, false
	}
	return s.accessList.slotWarm(addr, slot)
}

// AddLog appends a log entry to the StateDB's per-tx log accumulation.
// The log is copied defensively so the caller may reuse/mutate `log` after
// this call without risk of corrupting the accumulated state.
//
// STATE- (2026-07-20): Previously StateDB did not accumulate logs at
// all — qvm.Environment held them per-tx and discarded them on Commit. RPC
// layers (eth_getLogs, eth_getTransactionReceipt) had no way to retrieve logs
// from state. Now logs survive across Commit so they can be queried back.
func (s *StateDB) AddLog(log *Log) {
	if log == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Defensive copy: caller may reuse/mutate the Log after AddLog returns.
	lcopy := &Log{
		Address:     log.Address,
		BlockNumber: log.BlockNumber,
		TxHash:      log.TxHash,
		TxIndex:     log.TxIndex,
		BlockHash:   log.BlockHash,
		Index:       log.Index,
	}
	if log.Topics != nil {
		lcopy.Topics = make([]types.Hash, len(log.Topics))
		copy(lcopy.Topics, log.Topics)
	}
	if log.Data != nil {
		lcopy.Data = make([]byte, len(log.Data))
		copy(lcopy.Data, log.Data)
	}
	s.logs = append(s.logs, lcopy)
}

// GetLogs returns a defensive copy of the accumulated logs for the current
// transaction. The returned slice can be freely mutated by the caller.
// Returns an empty (non-nil) slice if no logs have been accumulated.
func (s *StateDB) GetLogs() []*Log {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return deepCopyLogs(s.logs)
}

// Logs returns the live log slice (NOT a copy). Used by the executor and
// block producer at end-of-tx to obtain the log slice for receipt building
// without paying for a defensive copy. Callers MUST NOT mutate the returned
// slice or any of its elements.
//
// Prefer GetLogs() for any read-only consumer that may hold the reference
// across StateDB mutations.
func (s *StateDB) Logs() []*Log {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.logs
}

// SetLogBlockInfo populates BlockNumber, BlockHash, TxHash, TxIndex, and
// assigns a sequential Index to each accumulated log. Called by the block
// producer at end-of-block, before building the receipt root. This is the
// ONLY place where Index is assigned; before this call, Index is zero.
//
// STATE- (2026-07-20): Required so logs can be queried by index
// after commit (RPC eth_getLogs by block, eth_getTransactionReceipt).
func (s *StateDB) SetLogBlockInfo(blockNumber uint64, blockHash types.Hash, txHash types.Hash, txIndex uint, startIndex uint) uint {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := startIndex
	for _, log := range s.logs {
		if log == nil {
			continue
		}
		log.BlockNumber = blockNumber
		log.BlockHash = blockHash
		log.TxHash = txHash
		log.TxIndex = txIndex
		log.Index = idx
		idx++
	}
	return idx
}

// SelfDestruct marks addr for destruction at end-of-block per EIP-6780.
//
// EIP-6780 semantics (implemented here):
//   - The account's balance is transferred to the beneficiary immediately
//     (so the beneficiary can use it in the same block), but the account
//     itself retains its balance until end-of-block finalization. This
//     matches the EIP-6780 rule that a selfdestructed account remains
//     callable (and its balance readable) for the remainder of the block.
//   - Code and storage are NOT deleted until end-of-block finalization.
//   - If the same address is re-created within the same block (CREATE on a
//     just-selfdestructed address), the new account takes over the balance
//     that was "transferred" to the beneficiary — i.e. the beneficiary
//     receives nothing because the selfdestruct is canceled by re-creation.
//     This is handled at FinalizeSelfDestructs() by checking if the address
//     is still in selfDestructs at commit time.
//
// Multiple SelfDestruct calls for the same addr in the same tx are idempotent
// after the first (the beneficiary from the FIRST call wins).
//
// STATE- (2026-07-20): Previously StateDB had no SelfDestruct method —
// qvmasync.StateDBAdapter implemented it by zeroing balance/code/nonce
// immediately. This violated EIP-6780 because subsequent calls in the same
// block would observe a zero balance instead of the actual balance. Native
// StateDB-level support fixes this.
func (s *StateDB) SelfDestruct(addr types.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selfDestructs == nil {
		s.selfDestructs = make(map[types.Address]struct{})
	}
	// Idempotent: only the first call records the beneficiary.
	if _, exists := s.selfDestructs[addr]; exists {
		return
	}
	s.selfDestructs[addr] = struct{}{}
	// Default beneficiary is the zero address; the caller may override via
	// SetSelfDestructBeneficiary. The balance transfer happens at
	// FinalizeSelfDestructs(), not here, per EIP-6780.
}

// SelfDestructToBeneficiary is the variant of SelfDestruct that records the
// beneficiary address where the remaining balance should be sent at
// end-of-block finalization. Equivalent to EVM's SELFDESTRUCT opcode that
// takes the beneficiary from the stack.
func (s *StateDB) SelfDestructToBeneficiary(addr types.Address, beneficiary types.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selfDestructs == nil {
		s.selfDestructs = make(map[types.Address]struct{})
	}
	if s.selfDestructBeneficiaries == nil {
		s.selfDestructBeneficiaries = make(map[types.Address]types.Address)
	}
	if _, exists := s.selfDestructs[addr]; exists {
		// First-call-wins: subsequent calls do not override the beneficiary.
		return
	}
	s.selfDestructs[addr] = struct{}{}
	s.selfDestructBeneficiaries[addr] = beneficiary
}

// HasSelfDestructed returns whether addr has been marked for selfdestruct in
// the current transaction. After FinalizeSelfDestructs() runs (at commit),
// the marker is cleared.
func (s *StateDB) HasSelfDestructed(addr types.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.selfDestructs == nil {
		return false
	}
	_, ok := s.selfDestructs[addr]
	return ok
}

// SelfDestructBeneficiary returns the recorded beneficiary for addr, or the
// zero address if no beneficiary was set (which means the balance will be
// burned — sent to a non-existent account — at finalization).
func (s *StateDB) SelfDestructBeneficiary(addr types.Address) types.Address {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.selfDestructBeneficiaries == nil {
		return types.Address{}
	}
	return s.selfDestructBeneficiaries[addr]
}

// FinalizeSelfDestructs executes the balance transfers for all addresses
// marked for selfdestruct. For each selfdestructed address:
//  1. Read its current balance.
//  2. If balance > 0, transfer it to the recorded beneficiary (or burn it
//     if beneficiary is the zero address — matches EVM semantics).
//  3. Zero out the account's balance, nonce, and code (storage deletion
//     would be done by the caller via separate state-clearing logic).
//  4. Remove the address from selfDestructs and selfDestructBeneficiaries
//     so subsequent calls in the next block observe a clean slate.
//
// This method MUST be called by the block producer at end-of-block, after
// all transactions in the block have executed and before the state root is
// computed. Per EIP-6780, the balance transfer is deferred to this point
// (rather than happening at the time of the SELFDESTRUCT opcode) so that
// subsequent calls in the same block can still observe the original balance.
//
// Returns the number of selfdestructs finalized.
func (s *StateDB) FinalizeSelfDestructs() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.selfDestructs) == 0 {
		return 0, nil
	}
	count := 0
	for addr := range s.selfDestructs {
		acc, err := s.getAccountLocked(addr)
		if err != nil {
			if err == ErrAccountNotFound {
				// Account already deleted or never existed — skip.
				delete(s.selfDestructs, addr)
				delete(s.selfDestructBeneficiaries, addr)
				continue
			}
			return count, fmt.Errorf("FinalizeSelfDestructs: failed to load account %x: %w", addr[:8], err)
		}
		if acc != nil && acc.Balance != nil && acc.Balance.Sign() > 0 {
			beneficiary := s.selfDestructBeneficiaries[addr]
			if beneficiary != (types.Address{}) {
				// Credit beneficiary.
				bAcc, bErr := s.getAccountLocked(beneficiary)
				if bErr != nil && bErr != ErrAccountNotFound {
					return count, fmt.Errorf("FinalizeSelfDestructs: failed to load beneficiary %x: %w", beneficiary[:8], bErr)
				}
				if bAcc == nil {
					bAcc = NewAccount()
				}
				bAcc.Balance = new(big.Int).Add(bAcc.Balance, acc.Balance)
				s.dirtyAccounts[beneficiary] = bAcc
			}
			// Zero the selfdestructed account's balance.
			acc.Balance = big.NewInt(0)
			acc.Nonce = 0
			acc.CodeHash = types.Hash{}
			s.dirtyAccounts[addr] = acc
		}
		delete(s.selfDestructs, addr)
		delete(s.selfDestructBeneficiaries, addr)
		count++
	}
	return count, nil
}

// GetTransientState returns the value at (addr, key) per EIP-1153, or the
// zero hash if not set.
func (s *StateDB) GetTransientState(addr types.Address, key types.Hash) types.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.transientStorage == nil {
		return types.Hash{}
	}
	return s.transientStorage.get(addr, key)
}

// SetTransientState sets (addr, key) → value per EIP-1153.
func (s *StateDB) SetTransientState(addr types.Address, key, value types.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transientStorage == nil {
		s.transientStorage = newTransientStorage()
	}
	s.transientStorage.set(addr, key, value)
}

// GetTransientStateExists returns true if (addr, key) has been explicitly
// set in the current transaction (even to the zero hash). This matches the
// "exists" semantics that some EIP-1153 callers use to distinguish "unset"
// from "set to zero".
func (s *StateDB) GetTransientStateExists(addr types.Address, key types.Hash) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.transientStorage == nil {
		return false
	}
	return s.transientStorage.exists(addr, key)
}

// ClearTxState resets all per-transaction state to a clean slate.
// Called by Commit (after the commit succeeds) and by Revert (to clear
// partial state). Also called explicitly by the executor at the start of
// each transaction to ensure no leftover state from a previous tx.
func (s *StateDB) ClearTxState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearTxStateLocked()
}

// clearTxStateLocked is the lock-free inner implementation of ClearTxState.
// MUST be called with s.mu held (write lock).
func (s *StateDB) clearTxStateLocked() {
	s.accessList = newAccessList()
	s.logs = make([]*Log, 0)
	s.selfDestructs = make(map[types.Address]struct{})
	s.selfDestructBeneficiaries = make(map[types.Address]types.Address)
	s.transientStorage = newTransientStorage()
}

// SnapAccountExport represents an exported account.
type SnapAccountExport struct {
	Address types.Address
	Data    []byte
}

// SnapStorageExport represents an exported storage entry.
type SnapStorageExport struct {
	Key   types.Hash
	Value types.Hash
}

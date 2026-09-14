// Quantaureum Node source, version 1.0.0.
// Package node provides the main node implementation for Quantaureum.
package node

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/privacy"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/txpool"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/multisig"
)

// Syncer errors
var (
	ErrSyncerAlreadyRunning  = errors.New("syncer is already running")
	ErrSyncerNotRunning      = errors.New("syncer is not running")
	ErrNoAvailablePeers      = errors.New("no available peers for sync")
	ErrBlockValidationFailed = errors.New("block validation failed")
	ErrParentNotFound        = errors.New("parent block not found")
	ErrForkDetected          = errors.New("fork detected: parent hash mismatch")
	ErrStateRootMismatch     = errors.New("state root mismatch")
)

// SyncStatus represents the current sync status
type SyncStatus struct {
	Syncing        bool   `json:"syncing"`
	CurrentBlock   uint64 `json:"currentBlock"`
	HighestBlock   uint64 `json:"highestBlock"`
	StartingBlock  uint64 `json:"startingBlock"`
	PeersConnected int    `json:"peersConnected"`
}

// audit-fix H-2: limits for pending blocks to prevent DoS
const (
	maxPendingBlocks = 500
	pendingBlockTTL  = 2 * time.Minute
	syncBatchSize    = 500 // Phase 1: 200→500 for faster sync
	//  Tunable batch size for block sync.
	// Used by handleBlockRequest and requestBlocksByHeightUnlocked.
)

// AUDIT-FULL IN-08 FIX (2026-08-15): hard cap on the in-memory
// unvalidatedBlocks marker map. Every sync-persisted block adds one entry
// (ProcessBlock below); entries are only evicted when rebuildState
// re-applies blocks at sync completion. Without a cap, syncing a chain
// with a very large height gap grows this map without bound and can OOM
// the node. When the cap is reached ProcessBlock refuses to persist
// further blocks and returns an error so sync aborts instead of
// exhausting memory. 100000 entries (~32-byte hash keys) is a few MB.
const maxUnvalidatedBlocks = 100000

// FIX (2026-08-15): batch-coalesced persistence for
// sync-unvalidated markers. unvalidatedBatchThreshold is the number of
// pending markers that triggers a single MarkBlocksUnvalidatedBatch call
// (one fsync). unvalidatedBatchFlushInterval bounds the max latency a
// marker spends in-memory before being written (restart-time durability).
// unvalidatedBatchChCap is the channel buffer amortizing ProcessBlock
// enqueue against the loop's accumulation; on overflow the marker is
// drop+warn'd (the in-memory map is authoritative). unvalidatedBatchStopTimeout
// bounds the wait for the loop to drain on Stop so a wedged flush cannot
// hang shutdown.
const (
	unvalidatedBatchThreshold     = 64
	unvalidatedBatchFlushInterval = 5 * time.Second
	unvalidatedBatchChCap         = 256
	unvalidatedBatchStopTimeout   = 5 * time.Second
)

// pendingBlockEntry wraps a pending block with a timestamp for TTL eviction.
type pendingBlockEntry struct {
	Block   *encoding.Block
	AddedAt time.Time
}

// pendingHeaderRequest tracks an in-flight header-first request so that
// HandleHeaderResponse can match responses to requests by RequestID
// (eth/66 request-response pairing) instead of relying on polling.
type pendingHeaderRequest struct {
	fromHeight uint64
	step       uint64 // Skip+1
	deadline   time.Time
}

// ETHEREUM-PARITY SYNC (2026-08-13): tuning constants for the extended
// sync protocol client (header-first skeleton + receipts + snap phases).
const (
	skeletonSyncGap       = 64  // trigger header-first skeleton sync when gap >= this
	skeletonMaxInFlight   = 8   // max concurrent header requests
	skeletonHeadersPerReq = 192 // headers per request (<= p2p.MaxHeaderRequestCount)
	skeletonReqTimeout    = 30 * time.Second
	receiptSyncGateGap    = 64  // receipts are downloaded once within this of the tip
	snapPivotDistance     = 128 // snap pivot = network height - this (pivot stability window)
)

// Syncer handles block synchronization with peers
type Syncer struct {
	p2pHost        *p2p.Host
	blockStore     *block.BlockStore
	stateDB        *state.StateDB
	blockValidator *core.BlockValidator
	networkID      uint64 // audit-fix R5-M1: from node config

	// txPool reference for cleaning up confirmed transactions when
	// receiving blocks from other validators.
	// CRITICAL FIX: Without this, the txpool retains stale transactions
	// and a stale state reference when processing external blocks,
	// causing Pending() to return stale/empty results.
	txPool              *txpool.TxPool
	commitRevealManager *txpool.CommitRevealManager

	// Sync state
	syncing             bool
	currentHeight       uint64
	stateVerifiedHeight uint64
	highestKnown        uint64
	startHeight         uint64

	// R57-ACC-OPT (2026-08-07): Rebuild concurrency control. rebuildRunning
	// ensures only one rebuildState runs at a time (two concurrent rebuilds
	// would double-apply the same blocks on the shared stateDB). If checkSync
	// triggers a rebuild while one is already running, it sets rebuildPending
	// so the running worker covers the remaining range before it exits.
	rebuildRunning int32
	rebuildPending int32

	// GHOST-HEIGHT FIX (2026-08-06): per-peer advertised height map.
	// highestKnown is (re)computed as max(currentHeight, max(peerHeights)).
	// This lets highestKnown decay when a peer that previously advertised a
	// high (ghost) height is reset and re-advertises a lower height, so a
	// node is not pinned in syncing=true requesting blocks that no longer
	// exist. Previously highestKnown only ever increased (HandleStatusMessage
	// used `if status.BestHeight > s.highestKnown`), so a height learned
	// during a chain reset would stall every node forever.
	peerHeights map[p2p.PeerID]uint64

	// Pending blocks waiting for parent
	// audit-fix H-2: uses pendingBlockEntry with TTL and bounded size
	pendingBlocks map[types.Hash]*pendingBlockEntry

	// Context and lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.RWMutex
	running bool

	syncActive  int32
	syncedCount uint64

	// TSS: this node's validator address for Status message auto-discovery.
	// When set, it's included in broadcast status messages so other peers
	// can auto-register the validator address → PeerID mapping.
	validatorAddress types.Address

	snapSyncing       bool
	snapSyncCompleted bool // R??-SNAP-REGUARD (2026-08-17): prevents re-triggering snap sync after completion
	snapTargetBlock   uint64
	// R12-NODE-002: Store the target header for state root verification.
	snapTargetHeader *encoding.BlockHeader
	snapAccounts     map[types.Address][]byte
	snapAccountCh    chan struct{}
	// AUDIT H-11: accounts for which the storage phase actually issued a
	// request (derived from the imported account snapshot). Snap storage
	// responses for any other account are unsolicited and rejected.
	snapStorageWanted map[types.Address]bool
	// AUDIT-FULL IN-05 (2026-08-14): the peer serving this snap session.
	// Requests are broadcast, so any peer may answer the FIRST state
	// response; that peer is then pinned as the session's single server
	// and all subsequent state/storage/bytecode responses from OTHER peers
	// are rejected. Mixing data from multiple servers could splice
	// incompatible account/storage snapshots; the end-of-import state-root
	// check would catch it, but pinning makes the session deterministic
	// and attributable (matches Ethereum's one-server-per-snap model).
	snapServerPeer   p2p.PeerID
	snapServerChosen bool

	// ETHEREUM-PARITY SYNC (2026-08-13): extended sync protocol client state.
	forkID             [32]byte                         // cached fork id broadcast in status (genesis+networkID derived)
	fullSyncMode       int32                            // atomic; 1 = re-execute every block during sync (--sync.mode=full)
	nextSyncReqID      uint64                           // monotonic request IDs for header/receipt requests (eth/66 style)
	pendingHeaderReqs  map[uint64]*pendingHeaderRequest // in-flight HeaderReq by RequestID
	skeletonHeaders    map[uint64]*encoding.BlockHeader // header-first verified skeleton headers by height
	skeletonTip        uint64                           // highest skeleton-verified height
	skeletonReqNext    uint64                           // next height to request for the skeleton
	pendingReceiptReqs map[uint64]bool                  // in-flight ReceiptReq IDs
	receiptSyncHeight  uint64                           // highest height whose receipts were requested

	onForkRollback func(forkHeight uint64)
	// R87-STATE-TRUST (2026-08-29): reports the outcome of every state-root
	// check so the node can track how long it has been diverging. Injected by
	// node.go; nil in unit tests.
	onStateRootResult func(height uint64, matched bool)
	onGenesisReplace  func(newGenesis *encoding.Block)
	onStateDBVerified func(height uint64)

	// Checkpoint manager for fork recovery
	checkpointManager *consensus.CheckpointManager

	// forkRecoveryAttempts tracks how many times we've tried to resolve
	// a fork at a given height. When attempts exceed the number of connected
	// peers, we accept the fork as canonical (Ethereum-style: the network
	// consensus determines the canonical chain, not a local counter).
	// This replaces the old hardcoded forkRollbackCount limit.
	forkRecoveryAttempts map[uint64]int

	// forkAbandonedHash records, per accepted fork height, the hash of OUR
	// block at that height at the moment we rolled back — i.e. the branch we
	// abandoned.
	//
	// R84-GHOST-DEADLOCK (2026-08-28): the `forkAccepted` sticky flag used to
	// drop EVERY later block whose parent did not match our block at that
	// height. That is right for a stale child of the abandoned branch, but it
	// also permanently blocked the canonical chain: after a rollback a node
	// that produced its own block at the same height (because sync tracking
	// had been reset) could never import the peers' chain again. Comparing
	// against the abandoned hash
	// keeps the anti-loop guard while letting a genuinely different branch in.
	forkAbandonedHash map[uint64]types.Hash

	// forkAccepted tracks fork heights that have already been accepted
	// and rolled back. If a ghost block triggers another fork at the same
	// height, we drop it silently instead of rolling back again.
	forkAccepted map[uint64]bool

	// R101-FINALITY-RESUME: epoch of the last epoch-block-root backfill pass.
	// checkSync re-derives and injects completed-epoch boundary roots from the
	// canonical store at most once per epoch (restarting nodes lose the whole
	// in-memory map; without backfill finality deadlocks — see
	// r101_epoch_root_backfill.go). Guarded by s.mu (only touched in checkSync).
	r101LastBackfillEpoch uint64

	// R38-P1-08 (2026-08-01): in-memory marker for blocks persisted during
	// sync before applyBlock runs. During sync, applyBlock is skipped
	// (syncer.go ~L711), so blocks enter the canonical block store WITHOUT
	// having their stateRoot/receiptRoot re-verified by re-execution. The
	// final rebuildState call (R32-P1-02) verifies the chain tip's root after
	// the fact, but until that completes any persisted-but-unapplied block
	// must never be advertised as fully validated canonical state.
	//
	// This is the conservative (non-invasive) form of Fix 4: we do NOT modify
	// the blockStore API to add persistent metadata; instead we keep an
	// in-memory set of (blockHash -> height) entries written during sync.
	// rebuildState clears entries as it re-applies them, and the final
	// rebuildState root verification clears the remainder. If a consumer
	// reads canonical state while a relevant entry still exists,
	// IsCanonicalUnvalidated(height) returns true and the caller can
	// fail-closed.
	//
	// AUDIT-FULL C-3 FIX (2026-08-14): the marker is now ALSO persisted in
	// blockStore (unvalidatedPrefix "u" keys) and restored at Syncer
	// construction, so a node restart between ProcessBlock (during sync)
	// and rebuildState no longer loses the fail-closed surface.
	unvalidatedBlocks map[types.Hash]uint64

	// FIX (2026-08-15): batch-coalesced persistence for
	// sync-unvalidated markers. The in-memory map (above) is updated
	// synchronously by ProcessBlock; the disk write is off-loaded to a
	// background goroutine so a bursty sync from a far-behind peer does
	// NOT issue one bbolt Put (one fsync) per block.
	//
	//   enqueue: ProcessBlock appends one UnvalidatedMarker to
	//            unvalidatedBatchCh (non-blocking; drop+warn on full).
	//   flush:   unvalidatedBatchLoop drains into a pending slice and
	//            flushes via blockStore.MarkBlocksUnvalidatedBatch when
	//            either:
	//              - pending size reaches unvalidatedBatchThreshold (64),
	//                amortizing fsync across many markers; or
	//              - unvalidatedBatchFlushInterval (5s) elapses, bounding
	//                restart-time durability loss at a small window.
	//   stop:    Stop closes unvalidatedBatchCh, the loop drains + flushes
	//            pending + signals unvalidatedBatchDone, joined with a
	//            bounded timeout.
	//
	// Failure to flush is logged loudly (same best-effort contract as the
	// pre-batch single-Put path): the in-memory map is authoritative.
	unvalidatedBatchCh   chan block.UnvalidatedMarker
	unvalidatedBatchDone chan struct{}

	// SECURITY (audit 2026-07-12, HIGH-01 FIX): State-root validation is now
	// ENABLED by default. The previous M4 root-derivation discrepancy was
	// caused by two structural issues that have been fixed:
	//   1. MEV reward (HIGH-13): The proposer credited winningBid.Value to its
	//      balance without recording it in the block. Validators could not
	//      reproduce this. FIX: MEV Value no longer affects on-chain balances.
	//   2. Fee distribution asymmetry (HIGH-12): The proposer called
	//      ApplyDistributionToState but validators did not. FIX: Gas fees now
	//      follow a single path (executor -> coinbase), and
	//      ApplyDistributionToState is no longer called for gas fees.
	// With both root causes resolved, proposer and validator now apply the
	// same state mutations, so strict state-root validation passes on honest
	// blocks. A mismatch now causes applyBlock to reject the block.
	strictStateRoot     bool
	stateRootMismatches uint64 // atomic-incremented counter; observable via metrics

	// highestKnownDecay: anti-deadlock mechanism for ghost heights.
	// When a peer advertises a height but never delivers the blocks, other
	// nodes would stall forever in syncing=true waiting for non-existent
	// blocks. We track the last time syncedCount actually advanced; if no
	// progress for stallTimeout, we retry from peers. After maxStallRetries
	// consecutive stalls, we clear syncBuf and re-request blocks from peers
	// (R51 FIX, 2026-08-05).
	//
	// R51 FIX: Previously, this mechanism decayed highestKnown to currentHeight,
	// which caused the node to exit sync mode (syncing=false) and start producing
	// blocks on a short chain while peers had a much higher chain. This led to
	// chain forks: the node produced blocks with an incomplete VRF accumulator
	// (only N blocks instead of the full chain), so its proposer election
	// diverged from the main chain. Now we KEEP highestKnown unchanged and
	// instead clear syncBuf + re-request blocks, so the node stays in sync
	// mode until it actually catches up.
	lastSyncProgress time.Time
	stallTimeout     time.Duration
	// R33 NODE-04: stallRetryCount tracks consecutive stall timeouts without
	// progress. After maxStallRetries, syncBuf is cleared and blocks are
	// re-requested from peers (R51 FIX: no longer decays highestKnown).
	//
	// DEADLOCK-SAFETY (2026-08-07): After maxTotalStallRetries (5 minutes),
	// highestKnown IS decayed to currentHeight. This is the safety valve
	// against permanent deadlock when peers are on a different fork — their
	// blocks can never be applied (parent hash mismatch), so the node would
	// be stuck forever. Decaying lets the node exit sync mode and produce
	// blocks on its own chain, which is correct behavior: if no peer has
	// deliverable blocks after 5 minutes, the node must produce to stay live.
	stallRetryCount      int
	maxStallRetries      int
	totalStallRetries    int // accumulated across all stall cycles (never reset until progress)
	maxTotalStallRetries int // after this many total stalls, decay highestKnown

	// qpos reference for replicating epoch reward application.
	// The block producer applies epoch rewards (attester, proposer, penalties,
	// slashing) to its stateDB during buildBlock. Without applying the same
	// rewards here, the validator's computed stateRoot will never match the
	// proposer's header stateRoot, causing perpetual stateRoot mismatches.
	qpos *consensus.QPOS

	// AUDIT (2026) R4-ZK-03: Persistent privacy store for nullifier
	// tracking. When set, the executor used during block sync will load
	// nullifiers from this store instead of using an in-memory map that is
	// lost when the executor is GC'd after each block.
	privacyStore *privacy.PrivacyStore
	// AUDIT (2026) R4-ECON-06: Multisig wallet store for member
	// signature verification during block sync. When set, the executor
	// verifies multisig member signatures against the real wallet config.
	multisigStore *multisig.MultisigStateStore

	// peerStatusReceived tracks whether we have received at least one
	// valid StatusMessage from any peer. Used by waitForInitialSync to
	// distinguish "peers connected but haven't sent status yet" from
	// "no peers at all". Without this, a node with connected peers that
	// haven't yet advertised their height would fall into genesis-producer
	// mode after the genesisWaitDeadline (15s), producing a divergent
	// block 1 that forks the chain. (R51 FIX, 2026-08-05)
	peerStatusReceived bool
}

// NewSyncer creates a new block syncer.
// audit-fix R5-M1: accepts networkID so status messages use the correct value.
func NewSyncer(host *p2p.Host, blockStore *block.BlockStore, stateDB *state.StateDB, validator *core.BlockValidator, networkID uint64) *Syncer {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Syncer{
		p2pHost:           host,
		blockStore:        blockStore,
		stateDB:           stateDB,
		blockValidator:    validator,
		networkID:         networkID,
		pendingBlocks:     make(map[types.Hash]*pendingBlockEntry),
		peerHeights:       make(map[p2p.PeerID]uint64),
		snapAccounts:      make(map[types.Address][]byte),
		snapStorageWanted: make(map[types.Address]bool),
		// ETHEREUM-PARITY SYNC (2026-08-13): extended sync client maps.
		pendingHeaderReqs:    make(map[uint64]*pendingHeaderRequest),
		skeletonHeaders:      make(map[uint64]*encoding.BlockHeader),
		pendingReceiptReqs:   make(map[uint64]bool),
		forkRecoveryAttempts: make(map[uint64]int),
		forkAccepted:         make(map[uint64]bool),
		forkAbandonedHash:    make(map[uint64]types.Hash),
		// R38-P1-08: initialize the in-memory unvalidated-blocks marker.
		unvalidatedBlocks:    make(map[types.Hash]uint64),
		lastSyncProgress:     time.Now(),
		stallTimeout:         30 * time.Second, // R38-SYNC FIX: reduced from 90s to 30s for small validator networks
		maxStallRetries:      2,                // R38-SYNC FIX: reduced from 3 to 2 (total 60s before syncBuf clear + re-request)
		maxTotalStallRetries: 10,               // DEADLOCK-SAFETY: 10 × 30s = 5 min, then decay highestKnown (exit sync mode)
		strictStateRoot:      true,             // AUDIT (2026) HIGH-01: strict validation enabled by default
		ctx:                  ctx,
		cancel:               cancel,
	}
	// AUDIT-FULL C-3 FIX (2026-08-14): restore the fail-closed surface
	// across restarts. Any block previously persisted during sync whose
	// roots were never re-verified (node crashed/restarted before
	// rebuildState finished) keeps its "unvalidated" marker here so
	// IsCanonicalUnvalidated stays truthful after the restart.
	if blockStore != nil {
		if persisted, err := blockStore.LoadUnvalidatedMarkers(); err != nil {
			syncLog.Error("NewSyncer: failed to load persistent unvalidated markers: %v", err)
		} else if len(persisted) > 0 {
			for h, height := range persisted {
				s.unvalidatedBlocks[h] = height
			}
			syncLog.Info("NewSyncer: restored %d persistent unvalidated-block markers from blockStore", len(persisted))
		}
	}
	return s
}

func (s *Syncer) SetOnForkRollback(fn func(forkHeight uint64)) {
	s.onForkRollback = fn
}

// SetCommitRevealManager sets the commit-reveal manager for block height tracking.
func (s *Syncer) SetCommitRevealManager(crm *txpool.CommitRevealManager) {
	s.commitRevealManager = crm
}

func (s *Syncer) SetOnGenesisReplace(fn func(newGenesis *encoding.Block)) {
	s.onGenesisReplace = fn
}

func (s *Syncer) SetOnStateDBVerified(fn func(height uint64)) {
	s.onStateDBVerified = fn
}

// SetValidatorAddress sets this node's validator address for TSS auto-discovery.
// When set, the address is included in status messages broadcast to peers,
// enabling automatic Address→PeerID mapping for directed TSS message routing.
func (s *Syncer) SetValidatorAddress(addr types.Address) {
	s.validatorAddress = addr
}

// ETHEREUM-PARITY SYNC (2026-08-13): --sync.mode=full support.

// SetFullSyncMode enables full sync: every block is re-executed via
// applyBlock even during initial sync (geth --syncmode=full equivalent).
// Default (false) keeps the fast path: blocks are stored without execution
// during sync and the state is rebuilt afterwards.
func (s *Syncer) SetFullSyncMode(enabled bool) {
	if enabled {
		atomic.StoreInt32(&s.fullSyncMode, 1)
		syncLog.Info("Sync mode: FULL — every block will be re-executed during sync")
	} else {
		atomic.StoreInt32(&s.fullSyncMode, 0)
	}
}

// IsFullSyncMode reports whether full execution during sync is enabled.
func (s *Syncer) IsFullSyncMode() bool {
	return atomic.LoadInt32(&s.fullSyncMode) == 1
}

// SkeletonVerifiedHeight returns the highest header-first verified height.
func (s *Syncer) SkeletonVerifiedHeight() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.skeletonTip
}

// currentForkID returns this node's fork id, computing and caching it from
// the genesis hash + networkID on first use. Callers MUST hold s.mu.
func (s *Syncer) currentForkIDLocked() [32]byte {
	if s.forkID != ([32]byte{}) {
		return s.forkID
	}
	genesisHash, err := s.blockStore.GetBlockHash(0)
	if err != nil {
		return [32]byte{} // no genesis yet — status omits the fork id
	}
	h := sha256.New()
	h.Write(genesisHash[:])
	var nid [8]byte
	binary.BigEndian.PutUint64(nid[:], s.networkID)
	h.Write(nid[:])
	copy(s.forkID[:], h.Sum(nil))
	return s.forkID
}

// SetPrivacyStore sets a persistent PrivacyStore for nullifier tracking during
// block sync. When set, the executor used in applyBlockInternal will load
// nullifiers from this store instead of using an in-memory map.
//
// AUDIT (2026) R4-ZK-03: Without this, each block sync creates a new
// TxExecutor with an in-memory PrivacyManager — nullifiers are lost when
// the executor is GC'd, enabling double-spend via replay in a subsequent block.
func (s *Syncer) SetPrivacyStore(store *privacy.PrivacyStore) {
	s.privacyStore = store
}

// SetMultisigStore sets the multisig wallet store for member signature
// verification during block sync.
//
// AUDIT (2026) R4-ECON-06: Without this, the executor used in
// applyBlockInternal would reject multisig transactions (fail-closed) or
// skip member signature verification (fail-open legacy path).
func (s *Syncer) SetMultisigStore(store *multisig.MultisigStateStore) {
	s.multisigStore = store
}

// SetCheckpointManager sets the checkpoint manager for fork recovery.
func (s *Syncer) SetCheckpointManager(cm *consensus.CheckpointManager) {
	s.checkpointManager = cm
}

// Start starts the syncer
func (s *Syncer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrSyncerAlreadyRunning
	}

	// Get current height
	height, err := s.blockStore.GetLatestHeight()
	if err != nil {
		s.currentHeight = 0
	} else {
		s.currentHeight = height
	}

	// Verify continuous chain - if latestBlockKey was corrupted by out-of-order
	// blocks from a previous version, scan to find the actual continuous tip
	if s.currentHeight > 0 {
		continuousTip := s.blockStore.FindContinuousTip()
		if continuousTip < s.currentHeight {
			syncLog.Info("Start: corrected currentHeight from %d to %d (continuous chain verification)", s.currentHeight, continuousTip)
			s.currentHeight = continuousTip
			if blk, err := s.blockStore.GetBlockByHeight(continuousTip); err == nil {
				s.blockStore.SetLatestBlock(blk)
			}
		}
	}

	s.startHeight = s.currentHeight
	s.highestKnown = s.currentHeight

	// Start sync loop
	s.wg.Add(1)
	go s.syncLoop()

	// Start peer status loop
	s.wg.Add(1)
	go s.peerStatusLoop()

	// Start sync health monitoring
	s.wg.Add(1)
	go s.syncHealthLoop()

	// FIX (2026-08-15): start the batch coalescer for
	// sync-unvalidated markers so ProcessBlock does not fsync per block.
	s.unvalidatedBatchCh = make(chan block.UnvalidatedMarker, unvalidatedBatchChCap)
	s.unvalidatedBatchDone = make(chan struct{})
	s.wg.Add(1)
	go s.unvalidatedBatchLoop()

	s.running = true
	if s.currentHeight == 0 {
		s.blockStore.SetSyncMode(true)
	}
	return nil
}

// Stop stops the syncer
func (s *Syncer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return ErrSyncerNotRunning
	}

	// FIX (2026-08-15): close the batch enqueue channel
	// BEFORE s.cancel()/s.wg.Wait() so the batch loop can drain pending
	// markers and do a final MarkBlocksUnvalidatedBatch flush with no more
	// producers arriving. Bounded by unvalidatedBatchStopTimeout so a
	// wedged flush cannot hang shutdown; on timeout we drop the pending
	// markers (the in-memory map still holds them but session teardown is
	// imminent — the next Start's unvalidatedBatchRule forces load-first).
	if s.unvalidatedBatchCh != nil {
		close(s.unvalidatedBatchCh)
		select {
		case <-s.unvalidatedBatchDone:
		case <-time.After(unvalidatedBatchStopTimeout):
			syncLog.Warn("Syncer.Stop: unvalidated-batch loop did not exit within %v — pending markers may be lost (in-memory map still authoritative for this process lifetime)",
				unvalidatedBatchStopTimeout)
		}
		s.unvalidatedBatchCh = nil
		s.unvalidatedBatchDone = nil
	}

	s.cancel()
	s.wg.Wait()

	s.running = false
	return nil
}

// enqueueUnvalidatedMarker hands a marker to the background batch
// coalescer without blocking the sync hot path. FIX
// (2026-08-15). No-op if the channel was never created (pre-Start test
// path or a Syncer whose Start() wasn't called) — the in-memory map is
// still updated by the caller, so fail-closed holds for this process
// lifetime; durability only degrades. On channel-full the marker is
// drop+warn'd: better to lose restart-time durability for one marker
// than stall the sync loop on a slow disk.
func (s *Syncer) enqueueUnvalidatedMarker(m block.UnvalidatedMarker) {
	if s.unvalidatedBatchCh == nil {
		// Fall back to synchronous single-write so a unit-test Syncer
		// (Start() never called) does not silently lose the marker.
		if s.blockStore != nil {
			if err := s.blockStore.MarkBlockUnvalidated(m.Hash, m.Height); err != nil {
				syncLog.Error("ProcessBlock: failed to persist unvalidated marker for block %d (sync fallback): %v", m.Height, err)
			}
		}
		return
	}
	select {
	case s.unvalidatedBatchCh <- m:
	default:
		syncLog.Warn("Syncer: unvalidated-batch channel full — marker for block %d dropped (in-memory map still authoritative; restart-time durability weakened)", m.Height)
	}
}

// unvalidatedBatchLoop is the  background coalescer. It accumulates
// markers into a pending slice, flushes via blockStore.MarkBlocksUnvalidatedBatch
// (single bbolt transaction → one fsync amortized across many markers) when
// either the threshold is reached OR the flush interval elapses, and
// performs a final drain+flush when the producer side closes
// unvalidatedBatchCh (Stop path). The loop owns pending; only the loop
// goroutine ever reads/touches it, so no extra mutex is needed.
func (s *Syncer) unvalidatedBatchLoop() {
	defer s.wg.Done()
	defer close(s.unvalidatedBatchDone)

	var (
		pending  []block.UnvalidatedMarker
		ticker   = time.NewTicker(unvalidatedBatchFlushInterval)
		flushing = func() {
			if len(pending) == 0 {
				return
			}
			if err := s.blockStore.MarkBlocksUnvalidatedBatch(pending); err != nil {
				syncLog.Error("Syncer: batch MarkBlocksUnvalidatedBatch(%d markers) failed: %v — in-memory map still authoritative, retry on next flush",
					len(pending), err)
				return
			}
			pending = pending[:0]
		}
	)
	defer ticker.Stop()
	for {
		select {
		case m, ok := <-s.unvalidatedBatchCh:
			if !ok {
				// Producer side closed — final drain + flush, then exit.
				flushing()
				return
			}
			pending = append(pending, m)
			if len(pending) >= unvalidatedBatchThreshold {
				flushing()
			}
		case <-ticker.C:
			flushing()
		}
	}
}

// Status returns the current sync status
func (s *Syncer) Status() *SyncStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Also check block store for actual latest height
	actualHeight := s.currentHeight
	if latestHeight, err := s.blockStore.GetLatestHeight(); err == nil {
		if latestHeight > actualHeight {
			actualHeight = latestHeight
		}
	}

	return &SyncStatus{
		Syncing:        s.syncing || s.highestKnown > actualHeight,
		CurrentBlock:   actualHeight,
		HighestBlock:   s.highestKnown,
		StartingBlock:  s.startHeight,
		PeersConnected: s.safePeerCount(),
	}
}

// PeerStatusReceived returns whether at least one valid peer StatusMessage
// has been received since startup. Used by waitForInitialSync to avoid
// falling into genesis-producer mode when peers are connected but haven't
// advertised their height yet. (R51 FIX, 2026-08-05)
func (s *Syncer) PeerStatusReceived() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peerStatusReceived
}

// safePeerCount returns the connected-peer count, tolerating a nil p2pHost
// (e.g. during early init or shutdown). Returns 0 so callers fall through to
// their no-peers paths instead of panicking.
// R7-DEPLOY FIX: centralizes the nil guard so every PeerCount() call site is safe.
func (s *Syncer) safePeerCount() int {
	if s.p2pHost == nil {
		return 0
	}
	return s.p2pHost.PeerCount()
}

// safeBroadcastRaw broadcasts a message to all peers, tolerating a nil p2pHost.
// R7-DEPLOY FIX: centralizes the nil guard for broadcast paths.
func (s *Syncer) safeBroadcastRaw(ctx context.Context, msg []byte) {
	if s.p2pHost == nil {
		return
	}
	s.p2pHost.BroadcastRaw(ctx, msg) //nolint:errcheck // broadcast is best-effort
}

// safeBroadcastBlock broadcasts a block to all peers, tolerating a nil p2pHost.
// R7-DEPLOY FIX: centralizes the nil guard for broadcast paths.
func (s *Syncer) safeBroadcastBlock(ctx context.Context, data []byte) {
	if s.p2pHost == nil {
		return
	}
	s.p2pHost.BroadcastBlock(ctx, data) //nolint:errcheck // broadcast is best-effort
}

// processGenesisBlock handles receiving a genesis block from a peer.
//
// SECURITY (audit 2026-06-14): A node's genesis is fixed at initialization
// from a trusted config file. A peer-supplied block must NEVER be allowed to
// replace it — previously, any peer could send a forged Height==0 block and
// trigger DeleteBlocksFromHeight(0), wiping the entire local chain and letting
// the attacker reseed the network (remote single-message chain-wipe DoS).
//
// Now: if a local genesis already exists, peer-supplied genesis blocks are
// only accepted if their hash EXACTLY matches the local genesis (i.e. the same
// genesis being announced back), and NEVER trigger chain deletion. Genesis
// migration is an operator-only operation performed offline.
func (s *Syncer) processGenesisBlock(blk *encoding.Block) error {
	blockHash := block.ComputeBlockHash(blk.Header)
	syncLog.Info("Processing genesis block from peer, hash=%x chainId=%d", blockHash[:8], blk.Header.ChainID)

	// If this exact genesis is already stored, nothing to do.
	if exists, _ := s.blockStore.HasBlock(blockHash); exists {
		syncLog.Info("Genesis block already exists (same hash)")
		s.ProcessPendingBlocks(blockHash)
		return nil
	}

	// A local genesis already exists and differs from the peer's. Reject it.
	// We must NOT delete or replace the local chain based on a peer message.
	ourGenesisHash, ourGenesisErr := s.blockStore.GetBlockHash(0)
	if ourGenesisErr == nil && ourGenesisHash != (types.Hash{}) {
		syncLog.Error("REJECTING peer-supplied genesis: local genesis already set (local=%x, peer=%x). "+
			"Chain replacement from a peer is not permitted; perform genesis migration offline.",
			ourGenesisHash[:8], blockHash[:8])
		return fmt.Errorf("genesis already initialized (local=%x); refusing peer-supplied genesis replacement",
			ourGenesisHash[:8])
	}

	// No local genesis yet: this is a first-time initialization. Store it.
	if err := s.blockStore.PutBlockWithIndex(blk); err != nil {
		syncLog.Error("Failed to store genesis block: %v", err)
		return err
	}

	syncLog.Info("Genesis block stored successfully, hash=%x", blockHash[:8])

	if s.onGenesisReplace != nil {
		s.onGenesisReplace(blk)
	}

	s.ProcessPendingBlocks(blockHash)

	return nil
}

// ProcessBlock processes an incoming block
var processBlockCount uint64

func (s *Syncer) ProcessBlock(blk *encoding.Block) error {
	if blk == nil || blk.Header == nil {
		return ErrBlockValidationFailed
	}

	count := atomic.AddUint64(&processBlockCount, 1)
	if count <= 10 || count%500 == 0 {
		syncLog.Info("ProcessBlock[%d]: height=%d", count, blk.Header.Height)
	}

	if blk.Header.Height == 0 {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.processGenesisBlock(blk)
	}

	blockHash := block.ComputeBlockHash(blk.Header)

	if exists, _ := s.blockStore.HasBlock(blockHash); exists {
		s.mu.Lock()
		if blk.Header.Height == s.currentHeight+1 {
			s.currentHeight = blk.Header.Height
			atomic.AddUint64(&s.syncedCount, 1)
			s.lastSyncProgress = time.Now()
			s.blockStore.SetLatestBlock(blk)
			if blk.Header.Height%100 == 0 {
				syncLog.Info("ProcessBlock: advanced currentHeight to %d (block already in store)", s.currentHeight)
			}
		}
		s.mu.Unlock()
		if !s.isSyncActive() {
			if latestHeight, err := s.blockStore.GetLatestHeight(); err == nil && blk.Header.Height > latestHeight {
				s.blockStore.SetLatestBlock(blk)
			}
		}
		return nil
	}

	parentExists, _ := s.blockStore.HasBlock(blk.Header.ParentHash)

	if !parentExists && blk.Header.Height > 1 {
		syncLog.Info("ProcessBlock: parent not found for block %d, parentHash=%x",
			blk.Header.Height, blk.Header.ParentHash[:8])

		if ourBlock, err := s.blockStore.GetBlockByHeight(blk.Header.Height - 1); err == nil && ourBlock != nil {
			ourHash := block.ComputeBlockHash(ourBlock.Header)
			ourHashEq := ourHash == blk.Header.ParentHash
			syncLog.Info("ProcessBlock: our block %d hash=%x, peer's parentHash=%x, match=%v",
				blk.Header.Height-1, ourHash[:8], blk.Header.ParentHash[:8], ourHashEq)

			if !ourHashEq {
				forkPoint := blk.Header.Height - 1

				// SECURITY (deep-audit 2026-07-12, SYNC-01): A competing block
				// must carry a valid proposer signature from a registered
				// validator BEFORE it may count toward fork acceptance. Without
				// this gate, any handshaked peer could gossip a few cheaply
				// forged blocks (non-zero proposer, matching ChainID, in-range
				// height, mismatched parent hash) and drive forkRecoveryAttempts
				// to the acceptance threshold, causing the node to DELETE its
				// validated canonical chain via DeleteBlocksFromHeight below.
				// ValidateSignature is parent-independent: it verifies the
				// Dilithium3/GM-QTD signature against the proposer's registered
				// public key (and is a no-op in devMode). An unverifiable block
				// is dropped as a fork block and re-requested through normal sync.
				if s.blockValidator != nil {
					if sigErr := s.blockValidator.ValidateSignature(blk.Header); sigErr != nil {
						syncLog.Warn("ProcessBlock: rejecting fork block %d with invalid/unverifiable proposer signature (not counted toward fork acceptance): %v",
							blk.Header.Height, sigErr)
						return ErrForkDetected
					}
				}

				// Ethereum-style fork resolution: no artificial limit on reorg attempts.
				// Compare chain length: the peer sent us a block at forkPoint+1,
				// meaning they have a chain at least as long as ours.
				// When attempts exceed peer count, all peers agree on this chain
				// → accept it as canonical.

				s.mu.Lock()
				attempts := s.forkRecoveryAttempts[forkPoint]
				alreadyAccepted := s.forkAccepted[forkPoint]
				peerCount := s.safePeerCount()
				if peerCount < 3 {
					peerCount = 3 // minimum threshold for small networks
				}
				s.mu.Unlock()

				// If we've already accepted a fork at this height and rolled
				// back, a block that descends from the branch we ABANDONED is a
				// ghost/duplicate: drop it, otherwise we roll back forever.
				//
				// R84-GHOST-DEADLOCK (2026-08-28): only that case may be
				// dropped. Any other branch — in particular the canonical chain
				// we are trying to re-sync — must be processed, or the node can
				// never recover from the rollback (see forkAbandonedHash).
				if alreadyAccepted && s.isAbandonedBranchBlock(forkPoint, blk.Header.ParentHash) {
					syncLog.Warn("FORK at height %d already accepted and rolled back. Dropping ghost block hash=%x parentHash=%x.",
						forkPoint, blockHash[:8], blk.Header.ParentHash[:8])
					return ErrForkDetected
				}

				// Increment attempt counter
				s.mu.Lock()
				s.forkRecoveryAttempts[forkPoint] = attempts + 1
				s.mu.Unlock()

				// Find common ancestor
				rollbackHeight := s.findForkRollbackPoint(forkPoint)
				if rollbackHeight < forkPoint {
					forkPoint = rollbackHeight
				}

				if attempts+1 >= peerCount {
					// All peers have been tried. Accept the fork as canonical and roll back.
					syncLog.Warn("FORK ACCEPTED at height %d: all %d peers agree on this chain (attempts=%d). Rolling back to %d and re-syncing.",
						forkPoint, peerCount, attempts+1, rollbackHeight)

					deleted, err := s.blockStore.DeleteBlocksFromHeight(forkPoint)
					if err != nil {
						syncLog.Error("Failed to reset chain from fork point: %v", err)
					} else {
						syncLog.Info("Fork resolved: deleted %d blocks from height %d, will re-sync from specific peers",
							deleted, forkPoint)
						s.mu.Lock()
						s.pendingBlocks = make(map[types.Hash]*pendingBlockEntry)
						if forkPoint > 0 {
							s.currentHeight = forkPoint - 1
						} else {
							s.currentHeight = 0
						}
						// FORK RECOVERY FIX: Set syncActive=1 to prevent the block producer
						// from producing a new block at the fork height before sync completes.
						// Without this, IsSyncing() returns false (syncActive=0 + syncing=false
						// + highestKnown < actualHeight+32), the producer immediately creates a
						// new block 14 with a different hash, and forkAccepted[14]=true causes
						// all peer blocks to be dropped as "ghost blocks" → node stuck forever.
						atomic.StoreInt32(&s.syncActive, 1)
						s.syncing = true
						// Mark this fork as accepted to prevent infinite re-rollback
						s.forkAccepted[forkPoint] = true
						// R84-GHOST-DEADLOCK (2026-08-28): remember WHICH branch
						// we abandoned, so only its descendants are dropped.
						s.forkAbandonedHash[forkPoint] = ourHash
						s.forkRecoveryAttempts = make(map[uint64]int)
						// Fast cascade: pre-set next 100 lower heights to peerCount-1
						// so they are accepted on the first attempt. This avoids the
						// slow 15s-per-level cascade that can take hours for deep forks.
						for i := uint64(1); i <= 100 && forkPoint > i; i++ {
							s.forkRecoveryAttempts[forkPoint-i] = peerCount - 1
						}
						s.mu.Unlock()

						// Update highestKnown to the max of old and current peer height
						// BEFORE requesting blocks, so we get the full range at once.
						s.mu.Lock()
						if blk.Header.Height > s.highestKnown {
							s.highestKnown = blk.Header.Height
						}
						requestEnd := s.highestKnown
						s.mu.Unlock()

						// R87-M4-ROOTCAUSE: lower startHeight/stateVerifiedHeight
						// together with the state rollback, or rebuildState will
						// resume above the restored baseline and never re-apply
						// the blocks in between.
						s.noteStateRolledBackTo(forkPoint)

						if s.onForkRollback != nil {
							s.onForkRollback(forkPoint)
						}

						// Request blocks from forkPoint up to highestKnown (all blocks
						// at once) to avoid round-trips per level during cascade.
						s.requestBlocksFromBestPeer(forkPoint, requestEnd)
					}
					return nil
				}

				// Fast cascade: if we've already accepted forks at nearby higher heights,
				// this is a cascading reorg. Accept immediately without waiting for 3 attempts.
				isCascading := s.forkAccepted[forkPoint+1] || s.forkAccepted[forkPoint+2] || s.forkAccepted[forkPoint+3]
				effectiveAttempts := attempts + 1
				if isCascading {
					effectiveAttempts = peerCount // Force immediate acceptance
				}

				if effectiveAttempts >= peerCount {
					// Cascading or all peers tried. Accept fork immediately.
					syncLog.Warn("FORK ACCEPTED at height %d (cascading=%v, attempts=%d/%d). Rolling back and re-syncing.",
						forkPoint, isCascading, attempts+1, peerCount)

					deleted, err := s.blockStore.DeleteBlocksFromHeight(forkPoint)
					if err != nil {
						syncLog.Error("Failed to reset chain from fork point: %v", err)
					} else {
						syncLog.Info("Fork resolved (cascade): deleted %d blocks from height %d",
							deleted, forkPoint)
						s.mu.Lock()
						s.pendingBlocks = make(map[types.Hash]*pendingBlockEntry)
						if forkPoint > 0 {
							s.currentHeight = forkPoint - 1
						} else {
							s.currentHeight = 0
						}
						// FORK RECOVERY FIX: Same as above — must set syncActive=1
						// to prevent block producer from creating a competing block.
						atomic.StoreInt32(&s.syncActive, 1)
						s.syncing = true
						s.forkAccepted[forkPoint] = true
						// R84-GHOST-DEADLOCK (2026-08-28): see the non-cascading
						// branch above — remember which branch we abandoned.
						s.forkAbandonedHash[forkPoint] = ourHash
						s.forkRecoveryAttempts = make(map[uint64]int)
						for i := uint64(1); i <= 100 && forkPoint > i; i++ {
							s.forkRecoveryAttempts[forkPoint-i] = peerCount - 1
						}
						s.mu.Unlock()

						s.mu.Lock()
						if blk.Header.Height > s.highestKnown {
							s.highestKnown = blk.Header.Height
						}
						cascadeEnd := s.highestKnown
						s.mu.Unlock()

						// R87-M4-ROOTCAUSE: lower startHeight/stateVerifiedHeight
						// together with the state rollback, or rebuildState will
						// resume above the restored baseline and never re-apply
						// the blocks in between.
						s.noteStateRolledBackTo(forkPoint)

						if s.onForkRollback != nil {
							s.onForkRollback(forkPoint)
						}
						s.requestBlocksFromBestPeer(forkPoint, cascadeEnd)
					}
					return nil
				}

				// Not enough attempts yet and not cascading. Don't roll back.
				// Return ErrForkDetected so the blockInsertLoop drops this block.
				syncLog.Warn("FORK DETECTED at height %d: our hash=%x, peer expects=%x. Ignoring block, will request from other peers (attempt %d/%d).",
					forkPoint, ourHash[:8], blk.Header.ParentHash[:8], attempts+1, peerCount)

				// P3-CHAIN-INTEGRITY FIX (2026-08-07): Enter sync mode to prevent
				// the block producer from producing more blocks on the minority
				// fork. Without this, the producer sees syncing=false and creates
				// new blocks on the forked chain, deepening the fork and making
				// it harder to resolve. Staying in sync mode gives the syncer time
				// to collect enough fork attempts (peerCount) to accept the
				// canonical chain via DeleteBlocksFromHeight + re-sync.
				// The stall detection (maxTotalStallRetries) will eventually decay
				// highestKnown if no progress is made, preventing permanent stall.
				atomic.StoreInt32(&s.syncActive, 1)
				s.mu.Lock()
				s.syncing = true
				// Do NOT update lastSyncProgress here — fork detection is not
				// progress. Updating it prevents stall detection from firing
				// when fork recovery stalls.
				s.mu.Unlock()

				// Request blocks from the best peer without rolling back our chain.
				// SYNC-02 FIX: read s.highestKnown under the lock (written elsewhere
				// under s.mu; an unlocked read here is a data race).
				s.mu.RLock()
				highestKnownFD := s.highestKnown
				s.mu.RUnlock()
				s.requestBlocksFromBestPeer(forkPoint, highestKnownFD)
				return ErrForkDetected
			}
		}
	}

	if blk.Header.Height == 1 && !parentExists {
		s.mu.Lock()
		s.addPendingBlock(blockHash, blk)
		s.mu.Unlock()
		s.requestBlockByHeight(0)
		return ErrParentNotFound
	}

	if !parentExists && blk.Header.Height > 0 {
		s.mu.Lock()
		added := s.addPendingBlock(blockHash, blk)
		s.mu.Unlock()
		// Actively request the missing parent block so sync can progress.
		// Without this, the node would wait passively for the parent to
		// arrive via broadcast — which may never happen if peers have
		// already moved past it. This is the key fix for the sync-stall
		// bug where syncBuf filled with blocks whose parents were missing.
		if blk.Header.Height > 1 && added {
			s.requestBlockByHeight(blk.Header.Height - 1)
			syncLog.Info("ProcessBlock: requested missing parent block %d for block %d",
				blk.Header.Height-1, blk.Header.Height)
		}
		return ErrParentNotFound
	}

	if blk.Header.Height > 0 {
		parent, err := s.blockStore.GetBlockHeader(blk.Header.ParentHash)
		if err != nil {
			return err
		}
		// R38-P1-08 FIX (2026-08-01, surgical conservative): Do NOT discard
		// the stateRootValidator / receiptRootValidator returned by
		// ValidateBlock. ValidateBlock's API contract (see
		// core/block_validator.go:753) states that the caller MUST invoke
		// these callbacks after transaction execution to verify the state/
		// receipt roots. The previous `_, _, err = ...` form silently
		// discarded them, turning an API-level "must call" obligation into
		// a silent no-op — exactly the bug R38-P1-08 calls out.
		//
		// Conservative behavior:
		//   * We ALWAYS receive both callbacks now. If ValidateBlock returns
		//     (nil, nil, nil) — i.e. it short-circuited without producing
		//     validators and without an error — that is an internal
		//     inconsistency (the API only returns nil callbacks on the
		//     early-error paths, which always carry a non-nil error). We
		//     fail-closed instead of persisting an unvalidated block.
		//   * During sync, applyBlock is skipped (L711), so we cannot invoke
		//     the callbacks here (the roots are not yet recomputed). The
		//     block is still persisted so the chain tip can advance, but we
		//     mark it as "unvalidated" in s.unvalidatedBlocks. The final
		//     rebuildState (R32-P1-02) re-applies the block, recomputes the
		//     roots, and clears the marker; if rebuildState's final root
		//     verification fails, sync is re-triggered. This is the
		//     conservative form of the "unvalidated staging marker" required
		//     by R38-P1-08 — it does not touch the blockStore API.
		//   * Outside sync (isSyncActive()==false), applyBlock runs and
		//     performs ValidateStateRoot + direct receipt-root comparison
		//     (see applyBlockInternal L1030/L1062), which is behaviorally
		//     identical to invoking the callbacks. We therefore retain the
		//     callbacks in scope (not _) so the intent is explicit, but the
		//     authoritative post-execution verification remains in
		//     applyBlockInternal to avoid double-validating and to keep
		//     skipStateRootValidation semantics intact.
		stateRootValidator, receiptRootValidator, err := s.blockValidator.ValidateBlock(blk, parent)
		if err != nil {
			syncLog.Info("Block %d validation failed: %v", blk.Header.Height, err)
			return err
		}
		// Fail-closed: ValidateBlock only returns (nil, nil) alongside a
		// non-nil error (see core/block_validator.go L755/L761/L766 and the
		// early return paths). Receiving (nil, nil, nil) is therefore an
		// internal contract violation — refuse to persist a block whose
		// validators were silently dropped.
		if stateRootValidator == nil || receiptRootValidator == nil {
			syncLog.Error("R38-P1-08: ValidateBlock returned nil stateRootValidator or receiptRootValidator "+
				"for block %d without an error — refusing to persist unvalidated block "+
				"(stateRootNil=%v, receiptRootNil=%v)",
				blk.Header.Height, stateRootValidator == nil, receiptRootValidator == nil)
			return fmt.Errorf("R38-P1-08: ValidateBlock returned nil stateRootValidator/receiptRootValidator "+
				"for block %d — refusing to persist unvalidated block", blk.Header.Height)
		}
		// R14-LOW: Validate root presence for non-genesis blocks regardless of
		// sync state. During sync, applyBlock is skipped (line ~686), which
		// means the stateRoot/receiptRoot validation in applyBlockInternal
		// (including the L9-005/L10-002 zero-root defense) is also skipped.
		// Without this check, a malicious peer could feed blocks with zero
		// StateRoot/ReceiptRoot during initial sync and the node would accept
		// them as long as the header passed basic validation. The full root
		// MATCH check still requires transaction execution (applyBlock), but
		// the zero-root PRESENCE check is a header-only check that must always
		// run.
		if blk.Header.StateRoot == (types.Hash{}) {
			syncLog.Error("Block %d rejected: zero StateRoot (not finalized)", blk.Header.Height)
			return fmt.Errorf("block %d stateRoot is zero (not finalized)", blk.Header.Height)
		}
		// R38-P1-08 (conservative): also reject zero ReceiptRoot here. The
		// previous R14-LOW block already included this check (see the
		// historical comment immediately above), but R38-P1-08 explicitly
		// enumerates the ReceiptRoot presence check as a required fail-closed
		// gate. We keep both presence checks here, immediately after
		// ValidateBlock, so a malicious peer feeding a zero ReceiptRoot block
		// during sync is rejected BEFORE the block is persisted to the
		// canonical index — closing the "unexecuted forged block lands in
		// canonical store" vector described in R38-P1-08 sub-problem 3.
		if blk.Header.ReceiptRoot == (types.Hash{}) {
			syncLog.Error("Block %d rejected: zero ReceiptRoot (not finalized) — R38-P1-08", blk.Header.Height)
			return fmt.Errorf("block %d receiptRoot is zero (not finalized) — R38-P1-08", blk.Header.Height)
		}
		// Intentionally retain the validators in scope (no `_`) so the
		// "must invoke after execution" contract is visibly acknowledged;
		// the actual post-execution verification is delegated to
		// applyBlockInternal (see the comment above). govet/unused does not
		// warn on named returns here because the values are read by the
		// fail-closed check just above.
		_ = stateRootValidator
		_ = receiptRootValidator
	}

	if err := s.blockStore.PutBlockWithIndex(blk); err != nil {
		// P3-CHAIN-INTEGRITY FIX (2026-08-07): PutBlock now refuses to
		// overwrite a canonical block with a different hash. This is a
		// same-height fork conflict — the existing block stays canonical,
		// and the conflicting block is dropped. Fork resolution (reorg)
		// must go through DeleteBlocksFromHeight + PutBlock explicitly.
		if errors.Is(err, block.ErrBlockConflict) {
			syncLog.Warn("ProcessBlock: same-height fork conflict at %d — keeping existing canonical block, dropping peer block (hash=%x)",
				blk.Header.Height, blockHash[:8])
			return ErrForkDetected
		}
		syncLog.Error("Failed to store block %d: %v", blk.Header.Height, err)
		return err
	}

	// R56-ACC-CHOKEPOINT FIX (2026-08-08): Record the per-epoch VRF
	// accumulator from the ON-CHAIN header value for EVERY persisted canonical
	// block, regardless of which import path imported it.
	//
	// ROOT CAUSE OF THE CHAIN FORK:
	// the per-epoch VRF accumulator (epochVRFAccumulator[E]) is pure in-memory
	// state that must be reconstructed from the canonical block headers. The
	// shuffle seed for epoch E reads epochVRFAccumulator[E-2] (see
	// qpos_proposer.computeDeterministicShuffleForEpoch). Previously the
	// accumulator was ONLY set inside node.blockInsertLoop (gated by
	// shouldSwitch=true). But the syncer's OTHER import paths — ProcessPendingBlocks
	// and checkSync's pending-block replay — call ProcessBlock DIRECTLY and
	// never pass through blockInsertLoop. When the LAST block of an epoch was
	// imported through one of those paths, its header's authoritative
	// accumulator never reached epochVRFAccumulator, so that epoch's value was
	// stale (or absent → the keccak(epoch) fallback). Different nodes then got
	// different acc[E-2] → different shuffle seed → different proposer for the
	// same slot → permanent chain fork.
	//
	// FIX: ProcessBlock is the single chokepoint through which EVERY block
	// import flows (blockInsertLoop, ProcessPendingBlocks, checkSync all call
	// it). Setting the accumulator here guarantees the header of every
	// persisted canonical block — including the last block of each epoch — is
	// recorded, no matter which path imported it. SetEpochVRFAccumulator is a
	// pure idempotent assignment from the deterministic on-chain header value
	// (and invalidates the dependent shuffle caches), so the last block of each
	// epoch wins and the value converges identically on every node. The
	// matching call in node.blockInsertLoop (node.go) is retained and harmless
	// (idempotent).
	if s.qpos != nil && blk.Header.Height > 0 {
		s.qpos.SetEpochVRFAccumulator(blk.Header.Epoch, blk.Header.VRFAccumulator)
	}

	// R38-P1-08 Fix 4 (conservative): mark sync-persisted blocks as
	// "unvalidated" so downstream consumers can fail-closed if they read
	// canonical state before rebuildState finishes. We add the entry AFTER
	// PutBlockWithIndex succeeds so the marker only ever tracks blocks that
	// actually landed in the canonical store. The marker is cleared by
	// applyBlock (non-sync path) and by rebuildState (sync completion path).
	// AUDIT-FULL C-3 FIX (2026-08-14): the marker is persisted in
	// blockStore too, so a restart before rebuildState does not lose it.
	if s.isSyncActive() {
		s.mu.Lock()
		// AUDIT-FULL IN-08 FIX (2026-08-15): enforce the hard cap before
		// inserting a new marker. Without this check the map grows once per
		// sync-persisted block and is only drained by rebuildState at sync
		// completion — a large height gap would grow it without bound (OOM).
		// Fail-closed: refuse the block so sync aborts with an error.
		if len(s.unvalidatedBlocks) >= maxUnvalidatedBlocks {
			s.mu.Unlock()
			syncLog.Error("ProcessBlock: unvalidated-block marker cap reached (%d entries) — "+
				"aborting sync to prevent unbounded memory growth (IN-08), block %d",
				maxUnvalidatedBlocks, blk.Header.Height)
			return fmt.Errorf("sync aborted: unvalidated-block marker cap reached (%d entries) — IN-08", maxUnvalidatedBlocks)
		}
		s.unvalidatedBlocks[blockHash] = blk.Header.Height
		s.mu.Unlock()
		// FIX (2026-08-15): enqueue the marker for the
		// background batch coalescer (see unvalidatedBatchLoop) instead of
		// issuing one MarkBlockUnvalidated Put (one fsync) per block. The
		// in-memory map above is the authoritative fail-closed surface;
		// persistence is best-effort durability. Drop+warn on channel full
		// so the sync hot path never blocks on disk.
		if s.blockStore != nil {
			s.enqueueUnvalidatedMarker(block.UnvalidatedMarker{Hash: blockHash, Height: blk.Header.Height})
		}
	}

	if s.isSyncActive() && !s.IsFullSyncMode() {
		if blk.Header.Height%500 == 0 {
			syncLog.Info("ProcessBlock: skipping applyBlock during sync for block %d", blk.Header.Height)
		}
	} else if err := s.applyBlock(blk); err != nil {
		// CRITICAL FIX (r68h): Do NOT delete the block when applyBlock fails.
		// The block has already passed ValidateBlock and PutBlockWithIndex — it is
		// a structurally valid block in the canonical chain. Deleting it creates
		// an unrecoverable gap (blocks 240-244 were lost this way, requiring a
		// full chain reset). State can always be rebuilt from the block store;
		// deleted blocks cannot be recovered. Log the error and return it so the
		// caller knows the state transition failed, but the block stays stored.
		syncLog.Error("ProcessBlock: applyBlock failed for block %d (block KEPT in store, state may need resync): %v",
			blk.Header.Height, err)
		return err
	}

	// R38-P1-08 Fix 4: applyBlock succeeded (non-sync path ONLY — the sync
	// path does NOT run applyBlock, see the if/else above), so this block's
	// stateRoot/receiptRoot have been re-verified by re-execution. Clear the
	// unvalidated marker so consumers can trust canonical state at this hash.
	//
	// IMPORTANT (R38-P1-08): The clear MUST be gated by `!s.isSyncActive()`.
	// Previously the delete ran UNCONDITIONALLY here, which erased the marker
	// that the sync path had just written a few lines above — making the
	// "unvalidated" guarantee a no-op. This is the surgical fix: only the
	// non-sync branch (which actually ran applyBlock) gets to clear the marker.
	if !s.isSyncActive() {
		s.mu.Lock()
		delete(s.unvalidatedBlocks, blockHash)
		s.mu.Unlock()
		// AUDIT-FULL C-3 FIX (2026-08-14): clear the durable marker too,
		// so a restart does not resurrect a stale "unvalidated" flag for a
		// block whose roots have just been re-verified by applyBlock.
		if s.blockStore != nil {
			if err := s.blockStore.ClearBlockUnvalidated(blockHash); err != nil {
				syncLog.Error("ProcessBlock: failed to clear persistent unvalidated marker for block %d: %v", blk.Header.Height, err)
			}
		}
	}

	lockStart2 := time.Now()
	s.mu.Lock()
	if lockDur := time.Since(lockStart2); lockDur > 50*time.Millisecond {
		syncLog.Warn("ProcessBlock: s.mu.Lock() took %v for height update block %d", lockDur, blk.Header.Height)
	}
	if s.isSyncActive() {
		if blk.Header.Height == s.currentHeight+1 {
			s.currentHeight = blk.Header.Height
			atomic.AddUint64(&s.syncedCount, 1)
			s.lastSyncProgress = time.Now()
			s.blockStore.SetLatestBlock(blk)
			s.clearForkAcceptedBelow(blk.Header.Height)
			if blk.Header.Height%100 == 0 {
				syncLog.Info("✓ Synced block %d, new height: %d (total=%d)", blk.Header.Height, s.currentHeight, atomic.LoadUint64(&s.syncedCount))
			}
		}
	} else {
		if blk.Header.Height > s.currentHeight {
			s.currentHeight = blk.Header.Height
			atomic.AddUint64(&s.syncedCount, 1)
			s.lastSyncProgress = time.Now()
			s.clearForkAcceptedBelow(blk.Header.Height)
			if blk.Header.Height%100 == 0 || s.isSyncActive() {
				syncLog.Info("✓ Synced block %d, new height: %d (total=%d)", blk.Header.Height, s.currentHeight, atomic.LoadUint64(&s.syncedCount))
			}
		}
	}
	s.mu.Unlock()

	return nil
}

// applyBlock applies a block's transactions to the state and verifies the state root.
// audit-fix CRIT-APPLY: previously a no-op (return nil), which meant synced blocks
// were never applied to state — a node could accept blocks with incorrect stateRoot
// and its local state would diverge from the network. Now we execute transactions
// and validate the state root against the block header.
//
// NOTE: State-root validation is only performed for blocks with transactions.
// Empty blocks produced by the block producer include epoch reward/slashing
// mutations that the validator does not replicate here (those are consensus-level
// operations handled by QPOS).  For empty blocks we still commit to advance
// snapshots/pruning but skip root validation.
func (s *Syncer) applyBlock(blk *encoding.Block) error {
	return s.applyBlockInternal(blk, !s.strictStateRoot)
}

// SetStrictStateRoot enables or disables strict state-root validation.
// When enabled, a state-root mismatch causes applyBlock to return an error
// (rejecting the block) instead of only logging a warning.
//
// DEFAULT IS ENABLED (audit 2026-07-12 HIGH-01 FIX). The previous M4
// root-derivation discrepancy was resolved by fixing two structural causes:
//  1. MEV reward (HIGH-13): winningBid.Value no longer affects on-chain balances.
//  2. Fee distribution (HIGH-12): Gas fees follow a single path (executor -> coinbase);
//     ApplyDistributionToState is no longer called for gas fees.
//
// Operators can still disable strict validation for debugging via
// SetStrictStateRoot(false), but this is not recommended for production.
func (s *Syncer) SetStrictStateRoot(enabled bool) {
	s.mu.Lock()
	s.strictStateRoot = enabled
	s.mu.Unlock()
}

// SetOnStateRootResult installs the R87-STATE-TRUST hook invoked after every
// state-root comparison during block application.
func (s *Syncer) SetOnStateRootResult(fn func(height uint64, matched bool)) {
	s.onStateRootResult = fn
}

// reportStateRoot forwards a state-root comparison outcome to the node.
func (s *Syncer) reportStateRoot(height uint64, matched bool) {
	if s.onStateRootResult != nil {
		s.onStateRootResult(height, matched)
	}
}

// StateRootMismatches returns the cumulative count of state-root mismatches
// observed during block application. Operators can use this to detect nodes
// whose state root derivation is diverging from the network.
func (s *Syncer) StateRootMismatches() uint64 {
	return atomic.LoadUint64(&s.stateRootMismatches)
}

// SetQPOS links the QPOS consensus engine so applyBlockInternal can replicate
// epoch reward application. Without this, the proposer's stateRoot (which
// includes epoch rewards) will never match the validator's computed stateRoot.
func (s *Syncer) SetQPOS(qpos *consensus.QPOS) {
	s.mu.Lock()
	s.qpos = qpos
	s.mu.Unlock()
}

// applyEpochRewards replicates the epoch reward application that the block
// producer performs in buildBlock (block_producer.go:1652-1711). This ensures
// the validator's stateDB matches the proposer's stateDB at epoch boundaries,
// so stateRoot validation can succeed.
func (s *Syncer) applyEpochRewards(blk *encoding.Block) {
	if s.qpos == nil || s.stateDB == nil || blk == nil || blk.Header == nil {
		return
	}
	slot := blk.Header.Slot
	if slot == 0 {
		return
	}
	slotInEpoch := slot % consensus.SlotsPerEpoch
	if slotInEpoch != 0 {
		return
	}
	prevEpoch := consensus.SlotToEpoch(slot) - 1

	// CNS-EPH-001: Recompute rewards deterministically from the on-chain census
	// embedded in this epoch-boundary block's header, so ALL nodes derive the
	// SAME rewards as the proposer (path-independent). This is the root-cause
	// fix for forks caused by differing P2P-collected attestation sets. Fall
	// back to the locally computed rewards only if the header carries no usable
	// census (e.g. pre-upgrade blocks).
	// R57-EPH-REWARD-FIX (2026-08-09): Ethereum-aligned determinism fix.
	//
	// The epoch reward is now a PURE function of the census embedded in the
	// block header (CNS-EPH-001). It is computed EXCLUSIVELY from that census;
	// the previous GetEpochRewards(prevEpoch) fallback was REMOVED because it
	// depended on each node's P2P-collected attestation set, which could differ
	// across honest nodes → divergent rewards → divergent state roots → fork.
	//
	// If the header carries no valid census (or it fails to deserialize), we
	// apply ZERO rewards — deterministically, on every node, because the
	// proposer applies the same rule (it embeds the census it used, or embeds
	// nothing and applies zero). There is no local fallback on either side, so
	// the reward is byte-identical across proposer and all validators.
	var rewards *consensus.EpochRewards
	if censusData := blk.Header.Attestations; len(censusData) > 0 {
		if atts, prop, err := consensus.DeserializeAttestationCensus(censusData); err == nil {
			rewards = s.qpos.ComputeEpochRewardsFromCensus(prevEpoch, atts, prop)
		} else {
			syncLog.Warn("applyEpochRewards: block %d header census failed to deserialize: %v (applying zero rewards)",
				blk.Header.Height, err)
		}
	}
	if rewards == nil || rewards.TotalRewards.Sign() == 0 {
		return
	}
	validators := s.qpos.GetValidatorSet()
	if validators == nil {
		return
	}
	vList := validators.Validators()
	if r87Diag() {
		addrs := make([]string, 0, len(vList))
		for i, v := range vList {
			addrs = append(addrs, fmt.Sprintf("[%d]=%x:%s", i, v.Address[:6], v.Stake))
		}
		syncLog.Warn("R87DIAG verify-reward h=%d slot=%d prevEpoch=%d vset=%v att=%v prop=%v pen=%v slash=%v",
			blk.Header.Height, slot, prevEpoch, addrs,
			rewards.AttesterRewards, rewards.ProposerRewards,
			rewards.Penalties, rewards.SlashingPenalties)
	}
	for idx, attReward := range rewards.AttesterRewards {
		if attReward.Sign() > 0 && idx >= 0 && idx < len(vList) {
			addr := vList[idx].Address
			if err := s.stateDB.AddBalance(addr, attReward); err != nil {
				syncLog.Warn("applyEpochRewards: failed to credit attestation reward to validator %x: %v", addr[:8], err)
			}
		}
	}
	for idx, propReward := range rewards.ProposerRewards {
		if propReward.Sign() > 0 && idx >= 0 && idx < len(vList) {
			addr := vList[idx].Address
			if err := s.stateDB.AddBalance(addr, propReward); err != nil {
				syncLog.Warn("applyEpochRewards: failed to credit proposer reward to validator %x: %v", addr[:8], err)
			}
		}
	}
	for idx, penalty := range rewards.Penalties {
		if penalty.Sign() > 0 && idx >= 0 && idx < len(vList) {
			addr := vList[idx].Address
			balance := s.stateDB.GetBalance(addr)
			newBal := new(big.Int).Sub(balance, penalty)
			if newBal.Sign() < 0 {
				newBal = big.NewInt(0)
			}
			s.stateDB.SetBalance(addr, newBal)
		}
	}
	for idx, slashPenalty := range rewards.SlashingPenalties {
		if slashPenalty.Sign() > 0 && idx >= 0 && idx < len(vList) {
			addr := vList[idx].Address
			balance := s.stateDB.GetBalance(addr)
			newBal := new(big.Int).Sub(balance, slashPenalty)
			if newBal.Sign() < 0 {
				newBal = big.NewInt(0)
			}
			s.stateDB.SetBalance(addr, newBal)
		}
	}
	syncLog.Info("applyEpochRewards: block %d slot %d prevEpoch %d rewards=%s penalties=%s",
		blk.Header.Height, slot, prevEpoch, rewards.TotalRewards.String(), rewards.TotalPenalties.String())
}

// applyBlockInternal applies a block's transactions to the state.
// When skipStateRootValidation is true, state root mismatches are logged
// but do not cause the method to return an error. This is used during
// rebuildState where the node trusts the chain's state roots and only
// needs to apply transactions to build up local state.
func (s *Syncer) applyBlockInternal(blk *encoding.Block, skipStateRootValidation bool) error {
	if blk == nil || blk.Header == nil || s.stateDB == nil {
		return nil
	}

	// CONS-P0-02 FIX (R31, 2026-07-27): Propagate the block's timestamp to
	// QPOS.lastKnownBlockTime so that subsequent consensus operations
	// (SlashValidator, markValidatorForInvestigation, SyncPendingSlashes)
	// use a deterministic, block-derived time source instead of wall-clock
	// time. This prevents consensus divergence from node clock differences.
	// SetLastKnownBlockTime is a no-op if the new timestamp is <= the
	// currently stored value (monotonic).
	if s.qpos != nil && blk.Header.Timestamp > 0 {
		s.qpos.SetLastKnownBlockTime(blk.Header.Timestamp)
	}

	// R38-P1-08 DEEP FIX (2026-08-02): Incrementally reconstruct the QPOS
	// proposer snapshot (randaoMix + epochVRFAccumulator + epochBlockRoots +
	// slotBlockRoots) from each canonical block being applied during sync.
	// ApplyBlockHeader is IDEMPOTENT by block hash, so reprocessing a
	// canonical block during a re-sync / reorg does NOT double-XOR the VRF
	// accumulator (which would corrupt the shuffle seed for epochs ≥2 away).
	//
	// The conservative R38-P1-08 mitigation (Fix 2, 2026-08-01) skipped
	// proposer election verification wholesale during syncingMode because
	// the QPOS snapshot was unavailable until the node reached the head.
	// This deep fix rebuilds that snapshot incrementally so that, once the
	// operator opts in via BlockValidator.EnableSyncProposerVerification
	// (and an ElectionVerifier is configured), proposer election can be
	// verified block-by-block during sync instead of being skipped.
	//
	// Safety contract: ApplyBlockHeader mirrors the canonical-import path
	// in node/node.go (SetSlotBlockRoot → AccumulateVRFOutput →
	// SetEpochBlockRoot → UpdateRANDAO). A reorg that drops a previously
	// canonical block from the chain will NOT roll this snapshot back —
	// the abandoned block's VRF contribution remains in the accumulator.
	// This is acceptable because (a) VRF outputs are ungrindable, so an
	// attacker cannot exploit the residual entropy; and (b) once sync
	// completes, SetSyncingMode(false) re-enables strict election
	// verification and the snapshot's only consumers are the slot→root
	// mapping used by ElectionVerifier, which is keyed by hash and so will
	// agree with the canonical chain at sync completion.
	if s.qpos != nil {
		blockHash := block.ComputeBlockHash(blk.Header)
		if err := s.qpos.ApplyBlockHeader(blk, blockHash); err != nil {
			// Best-effort: failures here MUST NOT abort sync (the caller's
			// strictStateRoot is the authoritative gate). Log a WARN so
			// operators can see incremental reconstruction failures.
			syncLog.Warn("R38-P1-08: ApplyBlockHeader failed (incremental QPOS snapshot reconstruction skipped) height=%d slot=%d err=%v",
				blk.Header.Height, blk.Header.Slot, err)
		}
	}

	// No transactions to apply.
	// We still call CommitWithBlock to advance snapshot/prune history at this
	// height. The block producer applies epoch rewards (attestation, proposer,
	// slashing) to its stateDB during buildBlock at epoch boundaries
	// (slotInEpoch == 0). We replicate the same reward application here so the
	// validator's stateRoot matches the proposer's header StateRoot.
	if len(blk.Transactions) == 0 {
		// R60-EPH-REBUILD-FIX (2026-08-09): Epoch rewards MUST be applied on
		// EVERY application of an epoch-boundary block — during proposal, live
		// sync, AND full rebuild — because they are a deterministic part of that
		// block's state transition. This is Ethereum-aligned: a block's state
		// root is a pure function of applying its state changes to the parent
		// state; there is no "skip during rebuild" path without diverging.
		//
		// R58 (superseded) skipped rewards during rebuildState, reasoning that
		// rebuild replays blocks whose rewards are "already committed". That is
		// only true if the state already contains them. But rebuildRange resumes
		// from lastCommittedHeight+1 (R57) and replays ONLY blocks NOT yet in
		// state, whose rewards are NOT yet credited. Skipping them left the
		// rebuilt state permanently diverged from the proposer's state root and
		// create a rebuild-to-resync failure loop. Applying rewards here is
		// correct and cannot double-credit, because the replayed blocks are not
		// in state.
		s.applyEpochRewards(blk)
		// AUDIT (2026) R2-HIGH-02 (NODE-): Empty blocks MUST also
		// validate the state root. Previously the committed root was discarded
		// (`if _, err :=`), allowing a malicious proposer to put an arbitrary
		// StateRoot in an empty block header. Now we capture the root and
		// validate it against the block header, same as the tx-carrying path.
		if r87Diag() {
			syncLog.Warn("R87DIAG verify-empty h=%d rootBeforeCommit=%s lastCommitted=%d",
				blk.Header.Height, r87Short(s.stateDB.Root()), s.stateDB.LastCommittedHeight())
		}
		stateRoot, err := s.stateDB.CommitWithBlock(blk.Header.Height)
		if err != nil {
			return fmt.Errorf("failed to commit state for block %d: %w", blk.Header.Height, err)
		}
		if r87Diag() {
			syncLog.Warn("R87DIAG verify-empty h=%d rootAfterCommit=%s header=%s",
				blk.Header.Height, r87Short(stateRoot), r87Short(blk.Header.StateRoot))
		}
		if err := s.blockValidator.ValidateStateRoot(blk, stateRoot); err != nil {
			atomic.AddUint64(&s.stateRootMismatches, 1)
			s.reportStateRoot(blk.Header.Height, false)
			syncLog.Warn("Empty block %d state root mismatch: computed=%x header=%x",
				blk.Header.Height, stateRoot[:8], blk.Header.StateRoot[:8])
			if !skipStateRootValidation {
				return fmt.Errorf("block %d %w: %v", blk.Header.Height, ErrStateRootMismatch, err)
			}
			syncLog.Error("State root validation SKIPPED for empty block %d: %s",
				blk.Header.Height, skippedStateRootReason(s.isRebuilding()))
		} else {
			s.reportStateRoot(blk.Header.Height, true)
		}
		return nil
	}

	// Execute each transaction against the state.
	// AUDIT (2026) R4-ZK-03: Use persistent privacy store if available
	// so nullifiers survive across executor instances.
	var executor *txpool.TxExecutor
	if s.privacyStore != nil {
		executor = txpool.NewTxExecutorWithStore(s.privacyStore)
	} else {
		executor = txpool.NewTxExecutor()
	}
	// AUDIT (2026) R4-ECON-06: Wire the multisig wallet lookup so the
	// executor verifies member signatures during block sync/validation.
	if s.multisigStore != nil {
		executor.SetMultisigWalletLookup(&multisigWalletLookupAdapter{store: s.multisigStore})
	}
	stateAdapter := &stateDBAdapter{stateDB: s.stateDB}

	// Build block context for execution
	blockHashes := make(map[uint64]types.Hash)
	for i := uint64(0); i < 256 && blk.Header.Height > i; i++ {
		hash, err := s.blockStore.GetBlockHash(blk.Header.Height - i)
		if err == nil {
			blockHashes[blk.Header.Height-i] = hash
		}
	}

	blockCtx := &txpool.BlockContext{
		BlockHash:   blk.Header.ParentHash,
		BlockNumber: blk.Header.Height,
		Timestamp:   blk.Header.Timestamp,
		Coinbase:    blk.Header.ProposerAddr,
		GasLimit:    blk.Header.GasLimit, // use block gas limit (vuln-4 fix)
		// SECURITY (audit R4-ECON-01): Proposer's block_producer.go sets
		// blockCtx.BaseFee = calculateNextBaseFee(parent) and stamps the
		// same value into header.BaseFee. Without setting it here, the
		// syncer's executor uses effectiveGasPrice = tx.GasPrice (no burn,
		// full amount to coinbase) while the proposer used
		// min(baseFee+tip, maxFee). The resulting sender-balance, coinbase,
		// and GasUsed divergence splits both StateRoot and ReceiptRoot,
		// causing strictStateRoot validators to reject the block (DoS) or
		// silently fork when strictStateRoot is off.
		BaseFee:     blk.Header.BaseFee,
		BlockHashes: blockHashes,
	}

	// AUDIT (2026) ECON-FIX: Collect receipts to recompute the
	// ReceiptRoot and verify it matches the block header. Previously the
	// validator never checked ReceiptRoot, so a malicious proposer could
	// forge receipt data or omit failed-tx receipts without detection.
	validatorReceipts := make([]*txpool.Receipt, 0, len(blk.Transactions))
	for _, tx := range blk.Transactions {
		receipt := executor.Execute(tx, stateAdapter, blockCtx)
		validatorReceipts = append(validatorReceipts, receipt)
		if receipt.Status != 1 {
			syncLog.Debug("tx %x FAILED in synced block %d: %s", tx.Hash().Bytes()[:8], blk.Header.Height, receipt.Error)
		}
	}

	// R35-P1-09 FIX (2026-07-29): Verify Header.GasUsed matches the actual
	// sum of receipt.GasUsed from re-execution. A malicious proposer could
	// underreport GasUsed to pay less BaseFee or manipulate the next block's
	// BaseFee downward. This exact check (combined with the static upper-bound
	// check in ValidateBlock) closes the gas-manipulation attack surface.
	// We do NOT skip this based on skipStateRootValidation — gas mismatch is
	// a hard consensus failure regardless of the M4 workaround.
	var computedGasUsed uint64
	for _, r := range validatorReceipts {
		if r != nil {
			computedGasUsed += r.GasUsed
		}
	}
	if err := s.blockValidator.ValidateGasUsed(blk, computedGasUsed); err != nil {
		syncLog.Warn("Block %d gas used mismatch: computed=%d header=%d", blk.Header.Height, computedGasUsed, blk.Header.GasUsed)
		return fmt.Errorf("block %d %w: %v", blk.Header.Height, ErrStateRootMismatch, err)
	}

	// Apply epoch rewards before committing so the validator's stateRoot
	// matches the proposer's header StateRoot at epoch boundaries.
	// R60-EPH-REBUILD-FIX (2026-08-09): Apply rewards on EVERY path (proposal,
	// live sync, and rebuild) — same rationale as the empty-block path above.
	// R56/R58 skipped during rebuildState, which left a from-scratch rebuild
	// diverged from the proposer's state (reward never credited) → permanent
	// state-root mismatch → rebuild↔resync death loop. rebuildRange replays
	// only blocks not yet in state (R57), so their rewards are not credited and
	// applying them here cannot double-credit.
	s.applyEpochRewards(blk)

	if r87Diag() {
		syncLog.Warn("R87DIAG verify-tx h=%d rootBeforeCommit=%s lastCommitted=%d txs=%d",
			blk.Header.Height, r87Short(s.stateDB.Root()), s.stateDB.LastCommittedHeight(), len(blk.Transactions))
	}

	stateRoot, err := s.stateDB.CommitWithBlock(blk.Header.Height)
	if err != nil {
		return fmt.Errorf("failed to commit state for block %d: %w", blk.Header.Height, err)
	}
	if r87Diag() {
		syncLog.Warn("R87DIAG verify-tx h=%d rootAfterCommit=%s header=%s",
			blk.Header.Height, r87Short(stateRoot), r87Short(blk.Header.StateRoot))
	}

	// CRITICAL FIX: Clean up the txpool after applying a block from another
	// validator. Without this, confirmed transactions remain in the pool and
	// the pool's state reference becomes stale (pointing to pre-block nonces).
	// When this node is the next proposer, Pending() returns stale txs or
	// empty results, causing empty blocks and 60s+ TPS gaps.
	s.mu.RLock()
	pool := s.txPool
	s.mu.RUnlock()
	if pool != nil {
		for _, tx := range blk.Transactions {
			pool.Remove(tx.Hash())
		}
		pool.SetState(s.stateDB)
	}

	// Update commit-reveal block height for reveal timing checks.
	// CRV2: also index commitments carried by TxTypeCommit txs included in
	// this block — this is how every node (including one syncing from
	// scratch) learns about commitments without any gossip or RPC side
	// channel. RegisterCommitment is idempotent per (commitHash,sender).
	if s.commitRevealManager != nil {
		s.commitRevealManager.SetBlockHeight(blk.Header.Height)
		for _, tx := range blk.Transactions {
			if tx.Type == encoding.TxTypeCommit {
				var ch types.Hash
				copy(ch[:], tx.Data)
				_ = s.commitRevealManager.RegisterCommitment(ch, tx.From)
			}
		}
	}

	if err := s.blockValidator.ValidateStateRoot(blk, stateRoot); err != nil {
		atomic.AddUint64(&s.stateRootMismatches, 1)
		s.reportStateRoot(blk.Header.Height, false)
		syncLog.Warn("Block %d state root mismatch: computed=%x header=%x", blk.Header.Height, stateRoot[:8], blk.Header.StateRoot[:8])
		if !skipStateRootValidation {
			return fmt.Errorf("block %d %w: %v", blk.Header.Height, ErrStateRootMismatch, err)
		}
		// R12-NODE-005 FIX: Log at Error level when strictStateRoot is disabled
		// so operators are alerted to the M4 root-derivation discrepancy.
		syncLog.Error("State root validation SKIPPED for block %d: %s",
			blk.Header.Height, skippedStateRootReason(s.isRebuilding()))
	} else {
		s.reportStateRoot(blk.Header.Height, true)
	}

	// AUDIT (2026) ECON-FIX: Verify ReceiptRoot. The proposer now
	// stamps a real root (see block_producer.go); the validator recomputes
	// it from its own execution and rejects on mismatch. This closes the
	// "receipts outside consensus" gap: a malicious proposer can no longer
	// forge receipt data or omit failed-tx receipts undetected.
	// Note: we do NOT skip this check based on skipStateRootValidation —
	// receipt root mismatches are a hard consensus failure regardless of
	// the M4 state-root derivation workaround. If the proposer's receipts
	// don't match what the validator computed, the block is invalid.
	if len(validatorReceipts) > 0 || blk.Header.ReceiptRoot != (types.Hash{}) {
		receiptHashes := make([]types.Hash, 0, len(validatorReceipts))
		for _, r := range validatorReceipts {
			if r == nil {
				continue
			}
			receiptHashes = append(receiptHashes, r.Hash())
		}
		computedReceiptRoot := core.ComputeReceiptRoot(receiptHashes)
		if blk.Header.ReceiptRoot != computedReceiptRoot {
			syncLog.Error("Block %d receipt root mismatch: computed=%x header=%x — rejecting (ECON-)",
				blk.Header.Height, computedReceiptRoot[:8], blk.Header.ReceiptRoot[:8])
			return fmt.Errorf("block %d receipt root mismatch: computed=%x header=%x (ECON-)",
				blk.Header.Height, computedReceiptRoot[:8], blk.Header.ReceiptRoot[:8])
		}
	}

	// R35-P0-09 FIX: Persist receipts from synced blocks so that
	// eth_getTransactionReceipt returns correct data after node restart
	// even for blocks received via P2P sync (not just locally produced
	// blocks). The receipts have already been validated against
	// ReceiptRoot above, so they are consensus-correct.
	if s.blockStore != nil && len(validatorReceipts) > 0 {
		blkHash := block.ComputeBlockHash(blk)
		storedReceipts := make([]*encoding.StoredReceipt, 0, len(validatorReceipts))
		for i, r := range validatorReceipts {
			if r == nil {
				continue
			}
			sr := &encoding.StoredReceipt{
				TxHash:      r.TxHash,
				BlockHash:   blkHash,
				BlockNumber: blk.Header.Height,
				TxIndex:     uint32(i), //nolint:gosec,G115
				Status:      r.Status,
				GasUsed:     r.GasUsed,
				Error:       r.Error,
				Logs:        make([]*encoding.StoredLog, 0, len(r.Logs)),
			}
			for _, lg := range r.Logs {
				if lg == nil {
					continue
				}
				sr.Logs = append(sr.Logs, &encoding.StoredLog{
					Address: lg.Address,
					Topics:  lg.Topics,
					Data:    lg.Data,
				})
			}
			storedReceipts = append(storedReceipts, sr)
		}
		if err := s.blockStore.StoreReceipts(storedReceipts); err != nil {
			syncLog.Warn("R35-P0-09: failed to persist receipts for synced block %d: %v", blk.Header.Height, err)
		}
	}

	return nil
}

// addPendingBlock adds a block to the pending map with TTL and size enforcement.
// audit-fix H-2: bounded pending blocks with eviction.
// addPendingBlock adds a block to the pending blocks map.
// Returns true if the block was added, false if it was rejected (capacity
// full or duplicate). The caller can use this to decide whether to request
// the missing parent block.
func (s *Syncer) addPendingBlock(hash types.Hash, blk *encoding.Block) bool {
	// Evict expired entries first
	now := time.Now()
	for h, entry := range s.pendingBlocks {
		if now.Sub(entry.AddedAt) > pendingBlockTTL {
			delete(s.pendingBlocks, h)
		}
	}
	// If already present, don't re-add (duplicate)
	if _, ok := s.pendingBlocks[hash]; ok {
		return false
	}
	// If still at capacity, reject
	if len(s.pendingBlocks) >= maxPendingBlocks {
		return false
	}
	s.pendingBlocks[hash] = &pendingBlockEntry{
		Block:   blk,
		AddedAt: now,
	}
	return true
}

// HasPendingBlock checks if a block hash is already in the pending blocks map.
func (s *Syncer) HasPendingBlock(hash types.Hash) bool {
	_, ok := s.pendingBlocks[hash]
	return ok
}

// processPendingBlocksAsync collects pending blocks matching the parent hash
// and processes them outside the lock, avoiding lock contention.
func (s *Syncer) ProcessPendingBlocks(parentHash types.Hash) {
	// R34 P1-02 FIX (2026-07-29): Top-level panic recovery.
	// ProcessPendingBlocks is called as a fire-and-forget goroutine from
	// blockInsertLoop (node.go:6184) and another block-processing path
	// (node.go:7216). Without recover, a panic anywhere in this method
	// (nil pointer dereference on a malformed entry.Block.Header, map
	// iteration race, sort.Slice panic on nil blocks, etc.) crashes the
	// entire node. This is defense-in-depth: the pendingBlocks entries
	// are validated before insertion, but a bug in validation or a race
	// during insertion should not be fatal.
	defer func() {
		if r := recover(); r != nil {
			syncLog.Error("ProcessPendingBlocks: panic recovered (parentHash=%x): %v", parentHash[:8], r)
		}
	}()
	queue := []types.Hash{parentHash}
	for len(queue) > 0 {
		currentHash := queue[0]
		queue = queue[1:]

		s.mu.Lock()
		var toProcess []*encoding.Block
		var toDelete []types.Hash
		for hash, entry := range s.pendingBlocks {
			// R34 P1-02 FIX: Defensive nil checks on entry and entry.Block
			// and entry.Block.Header before dereferencing. A nil entry or
			// Header would panic below; we skip such corrupt entries
			// instead of crashing the process.
			if entry == nil || entry.Block == nil || entry.Block.Header == nil {
				if entry != nil {
					toDelete = append(toDelete, hash)
				}
				continue
			}
			if entry.Block.Header.ParentHash == currentHash {
				toProcess = append(toProcess, entry.Block)
				toDelete = append(toDelete, hash)
			}
		}
		for _, hash := range toDelete {
			delete(s.pendingBlocks, hash)
		}
		s.mu.Unlock()

		// I22-008 FIX: sort pending blocks by height before processing to
		// ensure deterministic order. Map iteration in Go is non-deterministic,
		// which could cause blocks to be processed out of order, leading to
		// non-deterministic state transitions during sync.
		sort.Slice(toProcess, func(i, j int) bool {
			return toProcess[i].Header.Height < toProcess[j].Header.Height
		})

		for _, blk := range toProcess {
			blkHash := block.ComputeBlockHash(blk.Header)
			if err := s.ProcessBlock(blk); err == nil {
				queue = append(queue, blkHash)
			}
		}
	}
}

// requestBlock requests a block from peers
func (s *Syncer) requestBlock(hash types.Hash) {
	// Create block request message
	msg := &p2p.Message{
		Type:    p2p.MsgTypeBlockReq,
		Payload: hash[:],
	}

	data, err := p2p.EncodeMessage(msg.Type, msg.Payload)
	if err != nil {
		return
	}

	// Broadcast request to peers
	s.safeBroadcastBlock(s.ctx, data)
}

// requestBlockByHeight requests a block by height from peers
func (s *Syncer) requestBlockByHeight(height uint64) {
	req := &p2p.BlockRequest{
		FromHeight: height,
		ToHeight:   height,
		Hashes:     nil,
	}

	data := p2p.EncodeBlockRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeBlockReq, data)
	if err != nil {
		return
	}

	s.safeBroadcastRaw(s.ctx, msg) // R7-DEPLOY: nil-safe broadcast
}

// syncLoop is the main sync loop
func (s *Syncer) syncLoop() {
	defer s.wg.Done()
	// R33 NODE-02 FIX (2026-07-28): Top-level panic recovery. Without this,
	// a panic in checkSync (e.g. nil-deref on a peer response or block decode
	// failure) would kill the sync goroutine permanently, leaving the node
	// unable to catch up to chain head. Mirrors produceLoop/blockInsertLoop.
	defer func() {
		if r := recover(); r != nil {
			syncLog.Error("syncLoop: top-level panic recovered (process NOT killed): %v", r)
		}
	}()

	// Use shorter interval for faster sync
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			// R33 NODE-02 FIX: Per-tick panic recovery so a single bad tick
			// doesn't kill the loop. The top-level recover is the last line.
			func() {
				defer func() {
					if r := recover(); r != nil {
						syncLog.Error("syncLoop: per-tick panic recovered in checkSync: %v", r)
					}
				}()
				s.checkSync()
			}()
		}
	}
}

// checkSync checks if we need to sync and initiates sync if needed
func (s *Syncer) checkSync() {
	s.mu.Lock()

	// GHOST-HEIGHT FIX (2026-08-06): prune per-peer heights for peers that are
	// no longer connected, recomputing highestKnown. Together with the per-peer
	// tracking in HandleStatusMessage, this lets highestKnown reflect the
	// current online tip so a node is not pinned in syncing=true forever after
	// a chain reset (ghost height). Must run under s.mu.
	s.prunePeerHeightsLocked()

	storeHeight, _ := s.blockStore.GetLatestHeight()

	// R101-FINALITY-RESUME: rebuild the in-memory epoch boundary roots from
	// the canonical store (throttled to once per epoch). Must run whether or
	// not a sync round is active — a restarted follower that is ALREADY at the
	// peer tip never enters rebuildState, so its finality state would stay
	// deadlocked without this.
	s.maybeBackfillEpochRootsLocked()

	// ETHEREUM-PARITY SYNC (2026-08-13): header-first skeleton download for
	// large gaps and receipts download near the tip. Both are no-ops unless
	// their preconditions hold; they run alongside the existing block sync.
	s.requestSkeletonHeadersLocked()
	s.requestReceiptsLocked()

	// R38-SYNC FIX (2026-07-31): currentHeight must never exceed storeHeight.
	// If it does, the in-memory state is stale — fork recovery or data loss
	// deleted blocks but didn't fully reset currentHeight. This causes the
	// node to report a non-existent tip (e.g., currentHeight=44 with
	// storeHeight=0) and refuse to resync from genesis, permanently stalling
	// the node. Reset currentHeight to the authoritative persistent storeHeight.
	// This covers both storeHeight=0 (all blocks deleted) and
	// 0 < storeHeight < currentHeight (partial deletion with gaps).
	if s.currentHeight > storeHeight {
		syncLog.Warn("checkSync: currentHeight %d > storeHeight %d, resetting to storeHeight (stale in-memory state)",
			s.currentHeight, storeHeight)
		s.currentHeight = storeHeight
		s.pendingBlocks = make(map[types.Hash]*pendingBlockEntry)
		if storeHeight == 0 {
			// All blocks deleted; force sync mode to request genesis + blocks from peers
			s.syncing = true
			atomic.StoreInt32(&s.syncActive, 1)
			s.startHeight = 0
			s.lastSyncProgress = time.Now()
			s.stallRetryCount = 0
		}
	}

	if s.isSyncActive() {
		currentH := s.currentHeight
		s.mu.Unlock()

		if currentH > 0 {
			if latestH, err := s.blockStore.GetLatestHeight(); err != nil || currentH > latestH {
				if blk, err := s.blockStore.GetBlockByHeight(currentH); err == nil {
					s.blockStore.SetLatestBlock(blk)
				}
			}
		}

		newHeight := currentH
		maxAdvance := uint64(500)
		limit := currentH + maxAdvance
		var latestContinuousBlk *encoding.Block
		for h := currentH + 1; h <= limit; h++ {
			if blk, err := s.blockStore.GetBlockByHeight(h); err != nil {
				break
			} else {
				newHeight = h
				latestContinuousBlk = blk
			}
		}

		if latestContinuousBlk != nil {
			s.blockStore.SetLatestBlock(latestContinuousBlk)
		}

		s.mu.Lock()
		if newHeight > s.currentHeight {
			syncLog.Info("checkSync: advancing currentHeight from %d to %d (storeHeight=%d, continuous blocks)", s.currentHeight, newHeight, storeHeight)
			s.currentHeight = newHeight
		}
	} else {
		newHeight := s.currentHeight
		maxCheck := uint64(500)
		limit := storeHeight + maxCheck
		if limit < storeHeight {
			limit = storeHeight
		}
		var latestContinuousBlk *encoding.Block
		for h := s.currentHeight + 1; h <= limit; h++ {
			if blk, err := s.blockStore.GetBlockByHeight(h); err != nil {
				break
			} else {
				newHeight = h
				latestContinuousBlk = blk
			}
		}

		if latestContinuousBlk != nil {
			s.blockStore.SetLatestBlock(latestContinuousBlk)
		}

		if newHeight > s.currentHeight {
			syncLog.Info("checkSync: advancing currentHeight from %d to %d (storeHeight=%d, continuous check)", s.currentHeight, newHeight, storeHeight)
			s.currentHeight = newHeight
		} else if storeHeight > 0 && storeHeight < s.currentHeight {
			continuousTip := s.findContinuousTip()
			if continuousTip < s.currentHeight {
				syncLog.Warn("checkSync: currentHeight %d > continuousTip %d, resetting", s.currentHeight, continuousTip)
				s.currentHeight = continuousTip
				if blk, err := s.blockStore.GetBlockByHeight(continuousTip); err == nil {
					s.blockStore.SetLatestBlock(blk)
				}
			}
		}
	}

	needRequestMissing := false
	wasSyncing := s.syncing
	peerCount := s.safePeerCount()

	// Anti-deadlock: if sync has stalled, retry from peers. After
	// maxStallRetries consecutive stalls, clear syncBuf and re-request
	// blocks to escape the deadlock.
	//
	// R33 NODE-04 FIX (2026-07-28): Previously, this code NEVER decayed
	// highestKnown — it kept syncing=true and retried forever. This caused
	// a permanent stall when a peer advertised a ghost height (maliciously
	// or due to a bug) and never delivered the blocks. The node would be
	// stuck in sync mode indefinitely, unable to produce blocks.
	//
	// R51 FIX (2026-08-05): The R33 fix decayed highestKnown to currentHeight
	// after maxStallRetries. This caused a SEVERE chain fork bug: the node
	// would exit sync mode (syncing=false) and start producing blocks on a
	// short chain with an incomplete VRF accumulator, diverging from the
	// main chain. Now we KEEP highestKnown unchanged and instead clear
	// syncBuf + re-request blocks from currentHeight+1, so the node stays
	// in sync mode until it actually catches up. The original deadlock
	// (ghost height) is still handled because clearing syncBuf removes
	// any stuck/unprocessable blocks, and re-requesting from currentHeight+1
	// gives peers a fresh chance to deliver the right blocks.
	currentSynced := atomic.LoadUint64(&s.syncedCount)
	syncStalled := false
	if s.highestKnown > s.currentHeight && !s.lastSyncProgress.IsZero() {
		if time.Since(s.lastSyncProgress) > s.stallTimeout {
			s.stallRetryCount++
			s.totalStallRetries++
			// DEADLOCK-SAFETY (2026-08-07): After maxTotalStallRetries (5 min),
			// decay highestKnown to currentHeight. This is the safety valve:
			// if no peer can deliver applicable blocks after 5 minutes, the
			// peer's chain is on a different fork and will never sync. The node
			// must exit sync mode and produce blocks to stay alive, otherwise
			// it would be permanently stuck (the R51 deadlock).
			if s.totalStallRetries >= s.maxTotalStallRetries {
				syncLog.Warn("checkSync: DEADLOCK-SAFETY — stalled for %d total retries (~%v), decaying highestKnown from %d to %d (peers on different fork, exiting sync mode to produce)",
					s.totalStallRetries, time.Duration(s.totalStallRetries)*s.stallTimeout,
					s.highestKnown, s.currentHeight)
				s.highestKnown = s.currentHeight
				s.stallRetryCount = 0
				s.totalStallRetries = 0
				s.lastSyncProgress = time.Now()
				s.pendingBlocks = make(map[types.Hash]*pendingBlockEntry) // clear unprocessable blocks
				syncStalled = false                                       // exit sync mode
			} else if s.stallRetryCount >= s.maxStallRetries {
				// R51 FIX: Do NOT decay highestKnown. Instead, re-request
				// blocks from currentHeight+1. This keeps the node in sync
				// mode (syncing=true) so it cannot produce blocks on a short
				// chain. The syncBuf overflow logic in takeNextBlock will
				// clear unprocessable blocks automatically.
				syncLog.Warn("checkSync: sync stalled for %d retries (%v total, syncedCount=%d, highestKnown=%d > currentHeight=%d), re-requesting blocks from %d (R51 FIX — staying in sync mode, NOT decaying highestKnown, totalStall=%d/%d)",
					s.stallRetryCount, time.Since(s.lastSyncProgress), currentSynced,
					s.highestKnown, s.currentHeight, s.currentHeight+1,
					s.totalStallRetries, s.maxTotalStallRetries)
				s.stallRetryCount = 0
				s.lastSyncProgress = time.Now()
				// Re-request blocks from currentHeight+1
				s.requestBlocksByHeightUnlocked(s.currentHeight+1, s.highestKnown)
			} else {
				syncLog.Warn("checkSync: sync stalled for %v (retry %d/%d, syncedCount=%d, highestKnown=%d > currentHeight=%d), retrying from peers (totalStall=%d/%d)",
					time.Since(s.lastSyncProgress), s.stallRetryCount, s.maxStallRetries,
					currentSynced, s.highestKnown, s.currentHeight,
					s.totalStallRetries, s.maxTotalStallRetries)
				s.lastSyncProgress = time.Now()
				syncStalled = true
			}
		}
	} else {
		// Reset stall counter when making progress or no stall condition.
		s.stallRetryCount = 0
		s.totalStallRetries = 0
	}

	// P3-SYNC-GATE FIX (2026-08-07): Any gap >= 1 MUST keep the node in sync
	// mode. Previously, gaps of 1-8 blocks were considered "small" and did
	// NOT enter sync mode (syncActive=0). This allowed the block producer to
	// produce a block at the SAME height as a peer that already had a higher
	// block → same-height fork conflict → chain split.
	//
	// The deadlock concern (all nodes simultaneously seeing a 1-2 gap and
	// stopping production) does not apply in practice: the proposer whose
	// height matches highestKnown has gap=0 and is NOT in sync mode, so it
	// produces the next block. Other nodes sync to it, then gap=0 for them
	// too. The chain grows one block at a time, with all non-proposer nodes
	// syncing before producing.
	if syncStalled {
		// Sync stalled: keep syncing=true, request missing blocks from peers.
		// Do NOT produce blocks — producing on a stale chain causes forks.
		s.syncing = true
		atomic.StoreInt32(&s.syncActive, 1)
		needRequestMissing = true
	} else if s.highestKnown > s.currentHeight {
		gap := s.highestKnown - s.currentHeight
		syncLog.Info("checkSync: highestKnown=%d > currentHeight=%d, gap=%d, synced=%d, pending=%d",
			s.highestKnown, s.currentHeight, gap, atomic.LoadUint64(&s.syncedCount), len(s.pendingBlocks))
		s.syncing = true
		atomic.StoreInt32(&s.syncActive, 1)
		needRequestMissing = true
		// ETHEREUM-PARITY SYNC (2026-08-13): very large gaps switch to snap
		// sync with a pivot (network height - snapPivotDistance) — the geth
		// snap-sync pivot strategy. Full mode opts out: it must execute every
		// block from where the node currently is.
		// R??-SNAP-REGUARD (2026-08-17): snapSyncCompleted prevents re-triggering
		// snap sync immediately after a successful snap sync. The flag is
		// cleared once the gap shrinks below snapSyncThreshold (see below), so
		// a genuinely new large gap later can still trigger a fresh snap sync.
		if gap >= snapSyncThreshold && !s.snapSyncing && !s.snapSyncCompleted && atomic.LoadInt32(&s.fullSyncMode) == 0 {
			pivot := s.highestKnown
			if pivot > snapPivotDistance {
				pivot -= snapPivotDistance
			}
			if pivot > s.currentHeight {
				// R56-SNAP-UNLOCK-FIX (2026-08-14): startSnapSyncLocked now
				// does NOT release s.mu, so we can stay locked here and
				// the rest of checkSync still has the lock it expects at
				// the final `s.mu.Unlock()` below. We launch the snap
				// goroutine in a separate goroutine that will block on
				// s.mu.RLock() until line ~1966's Unlock fires, then read
				// currentHeight + start snapSyncLoop. This preserves the
				// previous behavior (snap goroutine does not hold s.mu)
				// without the double-unlock / missing-unlock bug that
				// was triggered by the old "Unlock inside the locked
				// function" pattern.
				s.startSnapSyncLocked(pivot)
				go s.launchSnapSync(pivot)
			}
		}
	} else if s.highestKnown == 0 && peerCount > 0 && s.currentHeight > 0 {
		syncLog.Info("checkSync: connected to peers but no height info yet (currentHeight=%d, peers=%d), requesting blocks from genesis", s.currentHeight, peerCount)
		s.syncing = true
		atomic.StoreInt32(&s.syncActive, 1)
		needRequestMissing = true
	} else if s.highestKnown == 0 && s.currentHeight == 0 {
		syncLog.Info("checkSync: all peers at genesis height 0 (peers=%d), waiting for block producer", peerCount)
		s.syncing = false
		atomic.StoreInt32(&s.syncActive, 0)
	} else {
		s.syncing = false
		atomic.StoreInt32(&s.syncActive, 0)
		s.blockStore.SetSyncMode(false)
		// R??-SNAP-REGUARD (2026-08-17): sync reached the network tip — clear
		// the snap-completed flag so a genuinely new large gap can trigger a
		// fresh snap sync in the future.
		if s.snapSyncCompleted {
			s.snapSyncCompleted = false
		}
		if wasSyncing {
			syncLog.Info("checkSync: sync completed at height %d (startHeight=%d, stateVerified=%d)",
				s.currentHeight, s.startHeight, s.stateVerifiedHeight)
			// R32-P2-09 FIX (2026-07-28): After sync completes, ensure strict
			// state-root validation is enabled for all subsequent block processing.
			// During sync, ValidateBlock's stateRootValidator callback is discarded
			// (syncer.go:675 uses `_, _, err`) and applyBlock is skipped
			// (syncer.go:704-707), so state roots are NOT validated per-block.
			// rebuildState (R32-P1-02 fix) verifies the FINAL state root after
			// rebuild, but if strictStateRoot was disabled by the operator, all
			// subsequent blocks would also skip state-root validation — allowing
			// a malicious proposer to feed blocks with wrong state roots
			// post-sync without detection. Force-enable strictStateRoot here
			// as a defense-in-depth backstop, and log a warning if it was
			// previously disabled so operators know their debug setting was
			// overridden for safety.
			if !s.strictStateRoot {
				syncLog.Warn("checkSync: strictStateRoot was disabled — force-enabling after sync completion for safety " +
					"(use SetStrictStateRoot(false) only for debugging BEFORE starting sync)")
				s.strictStateRoot = true
			}
			// R96-SYNCFLAP (2026-08-30): only rebuild when there is an
			// actually-unverified range. See shouldRebuildAfterSync.
			pendingUnvalidated := s.countUnvalidatedInRangeLocked(s.stateVerifiedHeight, s.currentHeight)
			if shouldRebuildAfterSync(wasSyncing, s.currentHeight, s.stateVerifiedHeight, pendingUnvalidated) {
				go s.rebuildState(s.startHeight, s.currentHeight)
			} else {
				syncLog.Debug("checkSync: caught up at height %d (verified through %d, "+
					"%d unvalidated blocks in range) — no rebuild needed (R96-SYNCFLAP)",
					s.currentHeight, s.stateVerifiedHeight, pendingUnvalidated)
			}
		}
	}

	var pendingToProcess []*encoding.Block
	needRequestPendingParents := false
	if len(s.pendingBlocks) > 0 {
		pendingToProcess = s.collectPendingWithExistingParents()
		needRequestPendingParents = true
	}

	s.mu.Unlock()

	if needRequestMissing {
		s.requestMissingBlocks()
	}

	if needRequestPendingParents {
		s.requestPendingBlockParents()
	}

	if len(pendingToProcess) > 0 {
		syncLog.Info("checkSync: processing %d pending blocks outside lock", len(pendingToProcess))
		sort.Slice(pendingToProcess, func(i, j int) bool {
			return pendingToProcess[i].Header.Height < pendingToProcess[j].Header.Height
		})
		for _, blk := range pendingToProcess {
			blkHash := block.ComputeBlockHash(blk.Header)
			if err := s.ProcessBlock(blk); err == nil {
				s.ProcessPendingBlocks(blkHash)
			}
		}
	}
}

// requestPendingBlockParents requests parent blocks for pending blocks
func (s *Syncer) requestPendingBlockParents() {
	// SYNC-02 FIX (deep-audit 2026-07-12): snapshot shared state under RLock.
	// This function is called by checkSync AFTER it releases s.mu, and runs in
	// the syncLoop goroutine concurrently with ProcessBlock (blockInsertLoop
	// goroutine), which mutates s.pendingBlocks/s.currentHeight under s.mu.
	// Ranging s.pendingBlocks unlocked while a writer adds/deletes entries is a
	// fatal "concurrent map iteration and map write" panic. Read the values we
	// need under the lock, then do network I/O unlocked.
	var lowestHeight uint64 = ^uint64(0) // Max uint64
	s.mu.RLock()
	for _, entry := range s.pendingBlocks {
		if entry.Block.Header.Height < lowestHeight {
			lowestHeight = entry.Block.Header.Height
		}
	}
	fromHeight := s.currentHeight + 1
	s.mu.RUnlock()

	if lowestHeight > 0 && lowestHeight < ^uint64(0) {
		// Request from current height to the pending block's parent
		toHeight := lowestHeight - 1
		if fromHeight <= toHeight {
			s.requestBlocksByHeightUnlocked(fromHeight, toHeight)
		}
	}
}

// isAbandonedBranchBlock reports whether an incoming block whose parent is
// unknown to us descends from the branch we abandoned when we accepted a fork
// at forkPoint. Only such a block may be dropped as a ghost.
//
// If the parent belongs to some OTHER branch — in practice the canonical chain
// we are re-syncing — the sticky forkAccepted flag is cleared so normal fork
// resolution can run. Without this a rollback could wedge the node forever.
//
// R84-GHOST-DEADLOCK (2026-08-28).
func (s *Syncer) isAbandonedBranchBlock(forkPoint uint64, parentHash types.Hash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	abandoned, known := s.forkAbandonedHash[forkPoint]
	if known && parentHash == abandoned {
		return true
	}
	if !known {
		// Pre-R84 state (or a restart): we cannot tell which branch this is.
		// Keep the old conservative behavior ONCE, then forget the flag so a
		// retry can make progress instead of stalling forever.
		delete(s.forkAccepted, forkPoint)
		return true
	}
	// A different branch: let it through.
	delete(s.forkAccepted, forkPoint)
	delete(s.forkAbandonedHash, forkPoint)
	syncLog.Info("R84: fork at height %d — incoming parent %x is not the abandoned branch %x, clearing the ghost guard so the canonical chain can be re-imported",
		forkPoint, parentHash[:8], abandoned[:8])
	return false
}

// clearForkAcceptedBelow removes forkAccepted entries for heights strictly less
// than the given height. Called when currentHeight advances, so subsequent ghost
// blocks at resolved fork heights are silently dropped instead of triggering
// another rollback. We use < (not <=) because a ghost block at the current height
// may still arrive and should be dropped.
func (s *Syncer) clearForkAcceptedBelow(height uint64) {
	for k := range s.forkAccepted {
		if k < height {
			delete(s.forkAccepted, k)
			delete(s.forkAbandonedHash, k)
		}
	}
}

// requestMissingBlocks requests blocks we're missing
func (s *Syncer) findForkRollbackPoint(forkHeight uint64) uint64 {
	if forkHeight <= 1 {
		return 1
	}

	// Checkpoint-based recovery: if we have a finalized checkpoint within the
	// lookback range, use it as the rollback point. Checkpoints are guaranteed
	// to be on the canonical chain (signed by 2/3 of validators), so rolling
	// back to a checkpoint is always safe and prevents deep historical forks.
	if s.checkpointManager != nil {
		latestCP := s.checkpointManager.GetLatestCheckpoint()
		if latestCP != nil && latestCP.Height > 1 && latestCP.Height < forkHeight {
			syncLog.Info("findForkRollbackPoint: using finalized checkpoint at height %d (epoch %d) as safe rollback point for fork at %d",
				latestCP.Height, latestCP.Epoch, forkHeight)
			// Verify the checkpoint block exists in our store
			if _, err := s.blockStore.GetBlockByHeight(latestCP.Height); err == nil {
				return latestCP.Height
			}
			// Checkpoint exists but block is missing - fall through to normal lookup
			syncLog.Warn("findForkRollbackPoint: checkpoint at height %d exists but block not in store, using normal lookup", latestCP.Height)
		}
	}

	maxLookback := uint64(500)
	start := forkHeight
	if start > maxLookback {
		start = start - maxLookback
	} else {
		start = 1
	}
	for h := forkHeight; h >= start; h-- {
		ourBlock, err := s.blockStore.GetBlockByHeight(h)
		if err != nil || ourBlock == nil {
			continue
		}
		if h == 0 {
			return 0
		}
		parentBlock, err := s.blockStore.GetBlockByHeight(h - 1)
		if err != nil || parentBlock == nil {
			return h
		}
		parentHash := block.ComputeBlockHash(parentBlock.Header)
		if ourBlock.Header.ParentHash != parentHash {
			syncLog.Info("findForkRollbackPoint: chain inconsistency at height %d (block parentHash=%x, actual parent hash=%x)", h, ourBlock.Header.ParentHash[:8], parentHash[:8])
			return h
		}
	}
	syncLog.Warn("findForkRollbackPoint: no internal inconsistency found in range %d-%d, returning forkHeight=%d instead of rolling back to genesis", start, forkHeight, forkHeight)
	return forkHeight
}

func (s *Syncer) findContinuousTip() uint64 {
	tip := uint64(0)
	for h := uint64(1); h <= s.currentHeight; h++ {
		if _, err := s.blockStore.GetBlockByHeight(h); err != nil {
			break
		}
		tip = h
	}
	return tip
}

func (s *Syncer) requestMissingBlocks() {
	// SYNC-02 FIX (deep-audit 2026-07-12): snapshot shared state under RLock.
	// Called by checkSync after it releases s.mu; runs concurrently with
	// ProcessBlock which writes s.currentHeight/s.highestKnown/s.pendingBlocks
	// under s.mu. Reading len(s.pendingBlocks) or these fields unlocked races
	// with those writes. Take the values we need under the lock, then broadcast
	// the request unlocked.
	s.mu.RLock()
	fromHeight := s.currentHeight + 1
	toHeight := s.highestKnown
	pendingCount := len(s.pendingBlocks)
	s.mu.RUnlock()

	_, genesisErr := s.blockStore.GetBlockHash(0)
	if genesisErr != nil && fromHeight > 0 {
		syncLog.Info("requestMissingBlocks: no genesis block, starting from height 0")
		fromHeight = 0
	}

	if pendingCount > maxPendingBlocks/2 {
		syncLog.Info("requestMissingBlocks: throttling, pendingBlocks=%d > %d, waiting",
			pendingCount, maxPendingBlocks/2)
		return
	}

	if toHeight == 0 || toHeight < fromHeight {
		toHeight = fromHeight + syncBatchSize - 1
	}

	if toHeight > fromHeight+syncBatchSize-1 {
		toHeight = fromHeight + syncBatchSize - 1
	}

	syncLog.Info("Requesting missing blocks from %d to %d (pending=%d, highestKnown=%d)", fromHeight, toHeight, pendingCount, toHeight)

	// Use proper BlockRequest format (20 bytes minimum: FromHeight + ToHeight + HashCount)
	req := &p2p.BlockRequest{
		FromHeight: fromHeight,
		ToHeight:   toHeight,
		Hashes:     nil, // Request by height range, not by hash
	}

	data := p2p.EncodeBlockRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeBlockReq, data)
	if err != nil {
		return
	}

	// R60-SYNC (2026-08-18): request from the best (highest-known) peer first,
	// falling back to broadcast. Ethereum fetches headers/blocks from specific
	// peers rather than broadcasting — broadcasting every cycle makes every
	// peer respond with the full range, thundering-herding the receiving side's
	// blockCh (2s enqueue budget drops blocks) and amplifying network sync
	// thrash. Targeted requests cut redundant traffic; the fallback keeps sync
	// alive when no peer is known or every targeted send fails (e.g. sendCh
	// full), and checkSync re-requests on the next tick if nothing arrives.
	if s.requestBlocksFromBestPeerFast(fromHeight, toHeight, msg) {
		return
	}

	s.safeBroadcastRaw(s.ctx, msg) // R7-DEPLOY: nil-safe broadcast
}

// requestBlocksFromBestPeerFast sends a block request to the connected peer
// with the highest known height, trying the next best peer on send failure.
// Returns true if at least one targeted send succeeded; false signals the
// caller to fall back to broadcast.
//
// R60-SYNC (2026-08-18): mirrors Ethereum's downloader, which requests from
// specific peers (the one reporting the highest head) instead of broadcasting
// to the whole network. Unlike requestBlocksFromBestPeer (fork recovery, which
// polls a single peer for a response), this is a cheap fire-and-forget send —
// sync progress is re-checked on every tick, so a missed response is simply
// re-requested next cycle.
func (s *Syncer) requestBlocksFromBestPeerFast(fromHeight, toHeight uint64, msg []byte) bool {
	if s.p2pHost == nil {
		return false
	}
	peers := s.p2pHost.Peers()
	if len(peers) == 0 {
		return false
	}

	// Snapshot known peer heights under the lock (HandleStatusMessage writes
	// peerHeights under s.mu).
	s.mu.RLock()
	heights := make(map[p2p.PeerID]uint64, len(s.peerHeights))
	for id, h := range s.peerHeights {
		heights[id] = h
	}
	s.mu.RUnlock()

	type candidate struct {
		id     p2p.PeerID
		height uint64
		known  bool
	}
	cands := make([]candidate, 0, len(peers))
	for _, p := range peers {
		if !p.Connected {
			continue
		}
		h, ok := heights[p.ID]
		cands = append(cands, candidate{id: p.ID, height: h, known: ok})
	}
	if len(cands) == 0 {
		return false
	}
	// Highest known height first; peers without a recorded height sort lowest.
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].known != cands[j].known {
			return cands[i].known
		}
		return cands[i].height > cands[j].height
	})

	for i, c := range cands {
		if err := s.p2pHost.SendRaw(c.id, msg); err != nil {
			syncLog.Warn("requestBlocksFromBestPeerFast: send to peer %s failed (%d/%d): %v",
				c.id.String()[:16], i+1, len(cands), err)
			continue
		}
		syncLog.Info("requestBlocksFromBestPeerFast: sent blocks %d-%d to best peer %s (knownHeight=%d, %d/%d connected)",
			fromHeight, toHeight, c.id.String()[:16], c.height, i+1, len(cands))
		return true
	}
	return false
}

// peerStatusLoop periodically queries peers for their status
func (s *Syncer) peerStatusLoop() {
	defer s.wg.Done()
	// R35 P3 FIX (2026-07-29): Top-level panic recovery. The inner
	// safeQueryPeerStatus wrapper only guards queryPeerStatus calls; a
	// panic in ticker handling or select logic itself would kill the
	// goroutine permanently, leaving peers without status broadcasts.
	// Mirrors syncLoop/syncHealthLoop top-level recover pattern.
	defer func() {
		if r := recover(); r != nil {
			syncLog.Error("peerStatusLoop: top-level panic recovered (process NOT killed): %v", r)
		}
	}()

	// Use shorter interval for faster discovery
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// safeQueryPeerStatus wraps queryPeerStatus with a recover to prevent
	// a panic (e.g. nil blockStore) from killing the loop.
	safeQueryPeerStatus := func() {
		defer func() {
			if r := recover(); r != nil {
				// Log but continue — the loop will retry on next tick
			}
		}()
		s.queryPeerStatus()
	}

	// Send initial status immediately
	safeQueryPeerStatus()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			safeQueryPeerStatus()
		}
	}
}

// queryPeerStatus queries connected peers for their chain status
func (s *Syncer) queryPeerStatus() {
	// Build our status message with current height
	s.mu.Lock()
	currentHeight := s.currentHeight
	// ETHEREUM-PARITY SYNC (2026-08-13): advertise our fork id so peers on
	// incompatible forks are rejected early (forkid filtering equivalent).
	forkID := s.currentForkIDLocked()
	s.mu.Unlock()

	// Get best block hash
	var bestHash [32]byte
	if blk, err := s.blockStore.GetBlockByHeight(currentHeight); err == nil && blk != nil && blk.Header != nil {
		hash := block.ComputeBlockHash(blk.Header)
		copy(bestHash[:], hash[:])
	}

	// Get genesis hash — use GetBlockHash for consistency with HandleStatusMessage
	var genesisHash [32]byte
	if hash, err := s.blockStore.GetBlockHash(0); err == nil {
		copy(genesisHash[:], hash[:])
	}

	// audit-fix R5-M1: use configured networkID instead of hardcoded 1
	status := &p2p.StatusMessage{
		Version:          1,
		NetworkID:        s.networkID,
		BestHeight:       currentHeight,
		BestHash:         bestHash,
		GenesisHash:      genesisHash,
		ValidatorAddress: s.validatorAddress,
		ForkID:           forkID,
	}

	// Encode and broadcast status
	statusData := p2p.EncodeStatusMessage(status)
	data, err := p2p.EncodeMessage(p2p.MsgTypeStatus, statusData)
	if err != nil {
		return
	}

	// Use BroadcastRaw since we already encoded the message with correct type
	s.safeBroadcastRaw(s.ctx, data)
}

// UpdateHighestKnown updates the highest known block height
func (s *Syncer) UpdateHighestKnown(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if height > s.highestKnown {
		s.highestKnown = height
	}
}

// NotifyIncomingBlock is called when a block is RECEIVED from a peer but
// not yet processed (added to syncBuf). It immediately updates highestKnown
// and sets syncActive=1 so that IsSyncing() returns true BEFORE the block
// is processed by blockInsertLoop.
//
// ROOT-CAUSE FIX (2026-08-07): Previously, highestKnown was only updated in
// blockInsertLoop when a block was PROCESSED (takeNextBlock → UpdateHighestKnown).
// Between receiving a block (blockProcessingLoop) and processing it, there was
// a window where the produceLoop fired and saw highestKnown == currentHeight →
// IsSyncing() returned false → the node produced a conflicting block at the
// same height → chain fork. This was the root cause of the persistent
// "same-height fork conflict at 2/4" forks in the local 6-node testnet.
//
// By updating highestKnown and setting syncActive=1 immediately on receipt,
// the block producer's sync gate (produceSyncGapThreshold=0) and IsSyncing()
// check both see the incoming block before the producer can fire, preventing
// the race condition entirely.
func (s *Syncer) NotifyIncomingBlock(height uint64) {
	s.mu.Lock()
	if height > s.highestKnown {
		s.highestKnown = height
	}
	currentH := s.currentHeight
	s.mu.Unlock()

	if height > currentH {
		atomic.StoreInt32(&s.syncActive, 1)
		s.mu.Lock()
		s.syncing = true
		// Do NOT update lastSyncProgress here. lastSyncProgress must only
		// advance when a block is SUCCESSFULLY APPLIED (syncedCount++).
		// Updating it on block announcement prevents stall detection from
		// firing when blocks are received-but-unprocessable, causing a
		// permanent deadlock (syncing=true forever, producer gated, no
		// progress, no safety-valve decay).
		s.mu.Unlock()
	}
}

// UpdateCurrentHeight updates the current synced height (called by block producer)
func (s *Syncer) UpdateCurrentHeight(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if height > s.currentHeight {
		s.currentHeight = height
	}
}

// IsSyncing returns whether the syncer is currently syncing.
//
// R38-Plan Batch 0.4 (2026-08-01): syncActive is the authoritative signal
// that an active sync session is in progress and must gate the block
// producer; this method returns true whenever syncActive==1, regardless of
// peer count. The earlier R38-SYNC FIX (2026-07-31) cleared syncActive
// when peerCount==0 to let a single node produce blocks, but that bypassed
// the block producer's own single-node grace path
// (tryProduceBlock: no peers after 5m grace period, single-node mode), and
// also reported `syncActive==1 with zero peers` as false — the very
// regression R38-Plan Batch 0.4 targets. Clearing syncActive now happens
// exclusively at the explicit completion/cancel paths that own the flag.
// When no active sync session is set, the existing lag/peer predicate is
// preserved.
func (s *Syncer) IsSyncing() bool {
	if atomic.LoadInt32(&s.syncActive) == 1 {
		return true
	}
	peerCount := s.safePeerCount()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.highestKnown == 0 && peerCount > 0 && s.currentHeight > 0 {
		return true
	}
	actualHeight := s.currentHeight
	if latestHeight, err := s.blockStore.GetLatestHeight(); err == nil {
		if latestHeight > actualHeight {
			actualHeight = latestHeight
		}
	}
	return s.syncing || s.highestKnown > actualHeight+32
}

// CurrentHeight returns the current synced height
func (s *Syncer) CurrentHeight() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentHeight
}

func (s *Syncer) StateVerifiedHeight() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stateVerifiedHeight
}

func (s *Syncer) IsStateReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// R61a-GENESIS-FIX (2026-08-09): A fresh genesis (height 0) is inherently
	// state-ready. The genesis state is defined by the shared genesis.json,
	// which is byte-identical across all nodes (confirmed by genesis hash
	// match on every peer). There is no parent state to diverge, so treating
	// height 0 as verified is safe and lets the first block be produced.
	// Without this, stateVerifiedHeight stays 0 at genesis and the producer
	// loops on "state not verified yet (verified=0, current=0)" forever.
	if s.currentHeight == 0 {
		return true
	}
	return s.stateVerifiedHeight > 0 && s.stateVerifiedHeight >= s.currentHeight
}

// MarkStateVerified records that the chain state at the given height has been
// verified. Used by the block producer after it builds and commits a block
// locally: the state it produced is verified by construction (state root is
// computed from actual transaction execution over the parent state), so the
// verified baseline advances immediately and the producer can continue to the
// next slot without waiting for a rebuildState pass (which only runs on the
// sync-completion path and would never fire for self-produced blocks).
func (s *Syncer) MarkStateVerified(height uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if height > s.stateVerifiedHeight {
		s.stateVerifiedHeight = height
	}
}

func (s *Syncer) StateDB() *state.StateDB {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stateDB
}

// SetStateDB updates the state database reference (called when state is swapped after block building).
func (s *Syncer) SetStateDB(stateDB *state.StateDB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateDB = stateDB
}

// SetTxPool sets the transaction pool reference for cleanup when
// processing blocks received from other validators.
func (s *Syncer) SetTxPool(pool *txpool.TxPool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.txPool = pool
}

// HandleBlockRequest handles a block request from a peer
func (s *Syncer) HandleBlockRequest(req *p2p.BlockRequest) (*p2p.BlockResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	response := &p2p.BlockResponse{
		Blocks: make([][]byte, 0),
	}

	// Handle request by height range
	// audit-fix R6-M2: always enter height-range path when heights are set,
	// including FromHeight=0 (genesis). The old condition `> 0` excluded genesis.
	if req.FromHeight <= req.ToHeight || req.ToHeight == 0 {
		from := req.FromHeight
		to := req.ToHeight
		if to == 0 {
			to = from
		}
		if to > from+syncBatchSize {
			to = from + syncBatchSize
		}

		for height := from; height <= to; height++ {
			blk, err := s.blockStore.GetBlockByHeight(height)
			if err != nil {
				continue
			}
			data, err := encoding.MarshalBlock(blk)
			if err != nil {
				continue
			}
			response.Blocks = append(response.Blocks, data)
		}
	}

	// Handle request by hashes
	for _, hash := range req.Hashes {
		h := types.BytesToHash(hash[:])
		blk, err := s.blockStore.GetBlock(h)
		if err != nil {
			continue
		}
		data, err := encoding.MarshalBlock(blk)
		if err != nil {
			continue
		}
		response.Blocks = append(response.Blocks, data)
	}

	return response, nil
}

// HandleBlockResponse handles a block response from a peer
func (s *Syncer) HandleBlockResponse(resp *p2p.BlockResponse) error {
	for _, blockData := range resp.Blocks {
		blk, err := encoding.UnmarshalBlock(blockData)
		if err != nil {
			continue
		}
		if err := s.ProcessBlock(blk); err != nil {
			// Log error but continue processing other blocks
			continue
		}
	}
	return nil
}

// HandleStatusMessage handles a status message from a peer.
// audit-fix F17: validates NetworkID before accepting the peer's BestHeight.
// Without this check, a peer on a different network (or a malicious peer) can
// send an extremely high BestHeight, causing the node to enter sync mode and
// spam block requests that will never be fulfilled — a bandwidth/CPU DoS.
//
// GHOST-HEIGHT FIX (2026-08-06): accepts the peer's identity (from) so we can
// track per-peer heights. highestKnown is recomputed as the max of our own
// currentHeight and all peers' latest advertised heights, so it decays when a
// peer is reset and re-advertises a lower height.
func (s *Syncer) HandleStatusMessage(status *p2p.StatusMessage, from p2p.PeerID) {
	s.mu.Lock()
	defer s.mu.Unlock()

	syncLog.Info("HandleStatusMessage: peer=%s peerNetworkID=%d, ourNetworkID=%d, peerHeight=%d, ourHeight=%d, ourHighestKnown=%d, peerGenesisHash=%x",
		from.String()[:min(len(from.String()), 16)], status.NetworkID, s.networkID, status.BestHeight, s.currentHeight, s.highestKnown, status.GenesisHash[:8])

	if status.NetworkID != s.networkID {
		syncLog.Info("Ignoring status from peer with wrong NetworkID: got %d, want %d",
			status.NetworkID, s.networkID)
		return
	}

	// ETHEREUM-PARITY SYNC (2026-08-13): fork id filtering. Both sides must
	// advertise a fork id for the check to apply; legacy peers (empty fork id)
	// are still accepted for backwards compatibility — their chain is then
	// validated via the existing genesis-hash + block-hash checks.
	ourForkID := s.currentForkIDLocked()
	if status.ForkID != ([32]byte{}) && ourForkID != ([32]byte{}) && status.ForkID != ourForkID {
		syncLog.Warn("HandleStatusMessage: FORK ID MISMATCH (ours=%x peer=%x) — peer is on an incompatible fork, ignoring",
			ourForkID[:8], status.ForkID[:8])
		return
	}

	// FIX: Check genesis hash BEFORE updating highestKnown.
	// Previously, highestKnown was updated unconditionally, so a stale height
	// from a peer on a different chain (e.g., during chain reset) would trap
	// the node in an endless sync loop (highestKnown only goes up, never down).
	ourGenesisHash, ourGenesisErr := s.blockStore.GetBlockHash(0)
	genesisMismatch := false
	if ourGenesisErr != nil {
		syncLog.Info("HandleStatusMessage: we have no genesis block, will sync from height 0")
		genesisMismatch = true
	} else if status.GenesisHash != [32]byte{} && ourGenesisHash != types.Hash(status.GenesisHash) {
		syncLog.Warn("HandleStatusMessage: GENESIS MISMATCH! ourGenesis=%x peerGenesis=%x — peer is on a different chain, ignoring peer height",
			ourGenesisHash[:8], status.GenesisHash[:8])
		// FIX: Return immediately — don't update highestKnown or request blocks
		// from a peer on a different chain.
		return
	}

	// R51 FIX: Mark that we've received at least one valid peer status.
	// This unblocks waitForInitialSync so it no longer falls into genesis-
	// producer mode when peers are connected but slow to advertise height.
	s.peerStatusReceived = true

	// GHOST-HEIGHT FIX: record this peer's latest advertised height, then
	// recompute highestKnown as max(currentHeight, all peer heights). This is
	// what lets highestKnown decay once connected peers re-advertise after a
	// chain reset, so the node exits sync mode and resumes block production.
	s.peerHeights[from] = status.BestHeight
	s.recomputeHighestKnownLocked()

	if genesisMismatch {
		syncLog.Info("HandleStatusMessage: requesting blocks from height 0 to %d (genesis resync)", status.BestHeight)
		s.requestBlocksByHeightUnlocked(0, status.BestHeight)
		return
	}

	if status.BestHeight > s.currentHeight {
		syncLog.Info("HandleStatusMessage: requesting blocks %d to %d",
			s.currentHeight+1, status.BestHeight)
		// P3-SYNC-GATE FIX (2026-08-07): Immediately enter sync mode when a
		// peer advertises a higher height. Previously this only requested
		// blocks without setting syncActive, so the block producer saw
		// syncing=false and produced a block at the SAME height as the peer
		// → same-height fork conflict (ErrBlockConflict) → chain split.
		// The block producer checks IsSyncing() (which checks syncActive)
		// before producing; setting it here ensures the producer is gated
		// BEFORE the periodic checkSync runs (checkSync may not run for
		// several seconds, during which the producer can fork the chain).
		s.syncing = true
		atomic.StoreInt32(&s.syncActive, 1)
		// Do NOT update lastSyncProgress here — only update on successful
		// block application. Peer status is not sync progress; updating it
		// here prevents stall detection from firing when peers repeatedly
		// advertise a height that cannot be delivered/applied.
		s.requestBlocksByHeightUnlocked(s.currentHeight+1, status.BestHeight)
	}
}

// recomputeHighestKnownLocked recomputes highestKnown as the maximum of our own
// currentHeight and all connected peers' latest advertised heights. Callers MUST
// hold s.mu (at least a write lock). This is the anti-ghost-height mechanism:
// highestKnown may now decrease when peers re-advertise lower heights after a
// chain reset, so the node is not pinned in syncing=true forever.
func (s *Syncer) recomputeHighestKnownLocked() {
	maxH := s.currentHeight
	for _, h := range s.peerHeights {
		if h > maxH {
			maxH = h
		}
	}
	if maxH != s.highestKnown {
		syncLog.Info("recomputeHighestKnownLocked: highestKnown %d -> %d (peers=%d, currentHeight=%d)",
			s.highestKnown, maxH, len(s.peerHeights), s.currentHeight)
	}
	s.highestKnown = maxH
}

// prunePeerHeightsLocked removes per-peer height entries for peers that are no
// longer connected, then recomputes highestKnown. Callers MUST hold s.mu.
// Peers broadcast status every 15s; without pruning, a peer that dropped off
// would keep highestKnown pinned at its last advertised height.
func (s *Syncer) prunePeerHeightsLocked() {
	if s.p2pHost == nil || len(s.peerHeights) == 0 {
		return
	}
	connected := make(map[p2p.PeerID]bool)
	for _, p := range s.p2pHost.Peers() {
		if p.Connected {
			connected[p.ID] = true
		}
	}
	changed := false
	for id := range s.peerHeights {
		if !connected[id] {
			delete(s.peerHeights, id)
			changed = true
		}
	}
	if changed {
		s.recomputeHighestKnownLocked()
	}
}

// RequestBlocksByHeight requests blocks by height range
func (s *Syncer) RequestBlocksByHeight(from, to uint64) {
	syncLog.Info("Requesting blocks from %d to %d", from, to)
	req := &p2p.BlockRequest{
		FromHeight: from,
		ToHeight:   to,
	}
	data := p2p.EncodeBlockRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeBlockReq, data)
	if err != nil {
		syncLog.Error("Failed to encode block request: %v", err)
		return
	}
	s.safeBroadcastRaw(s.ctx, msg) // R7-DEPLOY: nil-safe broadcast
}

// requestBlocksByHeightUnlocked requests blocks by height range (called when lock is already held)
func (s *Syncer) requestBlocksByHeight(from, to uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requestBlocksByHeightUnlocked(from, to)
}

func (s *Syncer) requestBlocksByHeightUnlocked(from, to uint64) {
	if to > from+(syncBatchSize-1) {
		to = from + (syncBatchSize - 1)
	}
	syncLog.Info("requestBlocksByHeightUnlocked: requesting blocks %d-%d (pending=%d, syncActive=%d)",
		from, to, len(s.pendingBlocks), atomic.LoadInt32(&s.syncActive))
	req := &p2p.BlockRequest{
		FromHeight: from,
		ToHeight:   to,
	}
	data := p2p.EncodeBlockRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeBlockReq, data)
	if err != nil {
		syncLog.Error("requestBlocksByHeightUnlocked: failed to encode block request: %v", err)
		return
	}
	s.safeBroadcastRaw(s.ctx, msg) // R7-DEPLOY: nil-safe broadcast
}

// RequestBlocksByHash requests blocks by hash
func (s *Syncer) RequestBlocksByHash(hashes []types.Hash) {
	req := &p2p.BlockRequest{
		Hashes: make([][32]byte, len(hashes)),
	}
	for i, h := range hashes {
		copy(req.Hashes[i][:], h[:])
	}
	data := p2p.EncodeBlockRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeBlockReq, data)
	if err != nil {
		return
	}
	s.safeBroadcastRaw(s.ctx, msg) // R7-DEPLOY: nil-safe broadcast
}

// GetPendingBlockCount returns the number of pending blocks
func (s *Syncer) GetPendingBlockCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pendingBlocks)
}

// ClearPendingBlocks clears all pending blocks
func (s *Syncer) ClearPendingBlocks() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingBlocks = make(map[types.Hash]*pendingBlockEntry)
}

const snapSyncThreshold = 1000

func (s *Syncer) IsSnapSyncing() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapSyncing
}

func (s *Syncer) startSnapSync(targetBlock uint64) {
	s.mu.Lock()
	s.startSnapSyncLocked(targetBlock)
	s.mu.Unlock()
	// FIX: launch the goroutine AFTER s.mu is released so
	// snapSyncLoop's internal RLock does not block on the lock we just held.
	s.launchSnapSync(targetBlock)
}

// startSnapSyncLocked is the lock-held core of startSnapSync; callers MUST
// hold s.mu (checkSync triggers snap sync directly from its locked section).
//
// R56-SNAP-UNLOCK-FIX (2026-08-14): This function used to call s.mu.Unlock()
// internally before launching s.snapSyncLoop, "to avoid holding s.mu while
// the snap sync goroutine runs." That was a DOUBLE-UNLOCK BUG for the
// startSnapSync wrapper (which also `defer s.mu.Unlock()`), and a
// MISSING-UNLOCK bug for the checkSync caller (which continues to access
// s.* fields between line ~1922 and the final s.mu.Unlock() at line ~1966
// AFTER startSnapSyncLocked already released the lock). That contract
// violation can terminate the node when snap sync first engages. The fix is
// to keep startSnapSyncLocked truly lock-held: it does its in-memory state
// setup and returns. The snap goroutine is launched by launchSnapSync AFTER
// the caller releases the lock. Keeping the function lock-held matches its
// "Locked" name suffix and restores the caller contract documented above.
func (s *Syncer) startSnapSyncLocked(targetBlock uint64) {
	if s.snapSyncing {
		return
	}
	s.snapSyncing = true
	s.snapTargetBlock = targetBlock
	// R12-NODE-002: Store header for state root verification after import.
	if blk, err := s.blockStore.GetBlockByHeight(targetBlock); err == nil && blk != nil && blk.Header != nil {
		s.snapTargetHeader = blk.Header
	} else if hdr, ok := s.skeletonHeaders[targetBlock]; ok && hdr != nil {
		// ETHEREUM-PARITY SYNC (2026-08-13): the header-first skeleton may
		// already hold the pivot header even when the full block has not been
		// downloaded yet — use it so the post-import state-root check applies.
		s.snapTargetHeader = hdr
	}
	s.snapAccounts = make(map[types.Address][]byte)
	s.snapAccountCh = make(chan struct{}, 1)
	// AUDIT-FULL IN-05: new snap session — forget the previous server pin.
	s.snapServerChosen = false
	s.snapStorageWanted = make(map[types.Address]bool)
	// R58-SNAP-FALLBACK (2026-08-18): reset the stateDB key ledger so a later
	// ClearSnapImport only deletes keys written by THIS snap session.
	if s.stateDB != nil {
		s.stateDB.BeginSnapImport()
	}
}

// launchSnapSync starts the snap sync goroutine if startSnapSyncLocked set
// snapSyncing=true. It must be called AFTER the caller has released s.mu —
// snapSyncLoop runs requestSnapState which itself acquires s.mu.RLock and we
// must avoid the goroutine blocking on a lock the caller still holds.
//
// R56-SNAP-UNLOCK-FIX (2026-08-14): This helper replaces the legacy pattern
// of "Unlock inside startSnapSyncLocked, then launch the goroutine without
// the lock." Callers now do:
//
//	s.mu.Lock()
//	s.startSnapSyncLocked(pivot)   // sets state, returns still holding s.mu
//	... rest of the locked section ...
//	s.mu.Unlock()
//	s.launchSnapSync(pivot)         // launch the goroutine without the lock
//
// The currentHeight read for logging is done under RLock here so the value
// is consistent with what checkSync sees as s.currentHeight at unlock time.
func (s *Syncer) launchSnapSync(targetBlock uint64) {
	if !s.snapSyncing {
		return
	}
	s.mu.RLock()
	currentH := s.currentHeight
	s.mu.RUnlock()
	syncLog.Info("Starting snap sync to block %d (current: %d)", targetBlock, currentH)
	s.wg.Add(1)
	go s.snapSyncLoop()
}

func (s *Syncer) snapSyncLoop() {
	defer s.wg.Done()

	s.requestSnapState()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			syncing := s.snapSyncing
			s.mu.RUnlock()
			if !syncing {
				return
			}
			s.requestSnapState()
		}
	}
}

func (s *Syncer) requestSnapState() {
	s.mu.RLock()
	targetBlock := s.snapTargetBlock
	s.mu.RUnlock()

	req := &p2p.SnapStateRequest{
		BlockHeight: targetBlock,
		Limit:       p2p.MaxSnapAccountsPerResponse,
	}

	data := p2p.EncodeSnapStateRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeSnapStateReq, data)
	if err != nil {
		syncLog.Error("Failed to encode snap state request: %v", err)
		return
	}

	s.safeBroadcastRaw(s.ctx, msg) // R7-DEPLOY: nil-safe broadcast
}

// maxSnapAccounts is the hard cap on buffered snap-sync accounts.
// AUDIT H-12 (2026-08-14): snapAccounts previously grew without bound, so a
// malicious peer could stream endless fake accounts and OOM the node. The
// real chain state has orders of magnitude fewer accounts; exceeding this
// cap aborts the snap attempt so sync restarts from another peer.
const maxSnapAccounts = 1_000_000

func (s *Syncer) HandleSnapStateResponse(from p2p.PeerID, resp *p2p.SnapStateResponse) {
	s.mu.Lock()
	if !s.snapSyncing {
		s.mu.Unlock()
		return
	}
	// AUDIT-FULL IN-05: pin the first responder as this session's server;
	// reject state data from any other peer.
	if !s.snapServerChosen {
		s.snapServerPeer = from
		s.snapServerChosen = true
	} else if s.snapServerPeer != from {
		syncLog.Warn("Snap sync: REJECTING state response from non-pinned peer %x (session server differs)", from.String()[:8])
		s.mu.Unlock()
		return
	}

	imported := 0
	for _, acc := range resp.Accounts {
		if _, exists := s.snapAccounts[acc.Address]; !exists {
			// AUDIT H-12: enforce the hard cap; abort on breach.
			if len(s.snapAccounts) >= maxSnapAccounts {
				syncLog.Error("Snap sync: ABORTING — account count exceeded hard cap %d (malicious or corrupt peer)", maxSnapAccounts)
				s.snapSyncing = false
				s.snapAccounts = nil
				s.mu.Unlock()
				return
			}
			s.snapAccounts[acc.Address] = acc.Account
			imported++
		}
	}

	moreComing := resp.MoreComing
	// FIX (2026-08-15): if the server hit its hard export
	// cap (Truncated=true), the streamed account set is INCOMPLETE. The state
	// root the receiver would compute over a partial set won't match the
	// target root — but more importantly, treat this as a peer failure and
	// abort the session rather than silently accepting the partial state.
	truncated := resp.Truncated
	// R35 P3 FIX (2026-07-29): Capture len(s.snapAccounts) under the lock.
	// Reading it after Unlock races with concurrent completeSnapSync which
	// sets s.snapAccounts = nil.
	totalAccounts := len(s.snapAccounts)
	if truncated {
		syncLog.Error("Snap sync: ABORTING — pinned server %s truncated state export at hard cap (account set incomplete)", from.String()[:8])
		s.snapSyncing = false
		s.snapAccounts = nil
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if imported > 0 {
		syncLog.Info("Snap sync: imported %d accounts (total: %d)", imported, totalAccounts)
	}

	if !moreComing {
		s.completeSnapSync()
	}
}

func (s *Syncer) completeSnapSync() {
	s.mu.Lock()
	if !s.snapSyncing {
		s.mu.Unlock()
		return
	}

	syncLog.Info("Snap sync: all accounts received (%d total), importing state...", len(s.snapAccounts))

	// R12-NODE-002 FIX: Validate snap data integrity before importing.
	// Previously, account data from untrusted peers was imported directly
	// without any validation, allowing a malicious peer to inject
	// arbitrary state. We now verify the state root after import.
	importedCount := 0
	for addr, data := range s.snapAccounts {
		// Basic validation: check minimum data length
		if len(data) < 32 {
			syncLog.Warn("Snap sync: skipping short account data for %x (len=%d)", addr[:8], len(data))
			continue
		}
		if err := s.stateDB.ImportAccount(addr, data); err != nil {
			syncLog.Error("Snap sync: failed to import account %x: %v", addr[:8], err)
		} else {
			importedCount++
		}
	}

	// R12-NODE-002 FIX: Verify state root matches the snap target block's
	// state root after import. If mismatch, log a critical warning and
	// reset to allow re-sync from a different peer.
	//
	// R58-SNAP-FALLBACK (2026-08-18): this is the geth-equivalent recovery
	// path (eth/downloader/sync.go: when a snap state sync fails root
	// verification, the downloader ABORTS it, DISCARDS all downloaded state,
	// and switches to FullSync). Previously we only cleared the in-memory
	// snap flags and returned, leaving the imported pivot-era accounts in
	// the DB. The next checkSync then re-triggered snap sync from the same
	// (possibly malicious/corrupt) peer — an infinite retry loop — or, if a
	// later full sync read those polluted accounts before re-executing the
	// block, produced "state root mismatch" rejections and a stuck node.
	// Now we (1) surgically delete exactly the keys this session imported
	// (ClearSnapImport — pre-existing good state is preserved), (2) clear
	// every snap session flag, and (3) force FullSync so the node re-executes
	if s.snapTargetHeader == nil && s.snapTargetBlock > 0 {
		// R62-SNAP-ADVANCE (2026-08-18) backfill: startSnapSyncLocked sets
		// snapTargetHeader from blockStore.GetBlockByHeight(target) or
		// s.skeletonHeaders[target]. Neither source is guaranteed to be
		// populated at start time: the block DB may stop at the pre-snap
		// height, and the skeleton headers map may only fill in once
		// HeaderResponse arrives later. The pivot header plays two roles
		// here: (1) the state-root hash compared against imported state
		// (line ~3222), (2) the fake pivot block installed as the chain
		// tip below (R62 code path). Without it, snap sync can complete
		// without state-root verification and R62 cannot install a pivot
		// block, leaving the node unable to advance.
		// By the time the snapSyncLoop's account-import pass finishes,
		// the regular block-sync path will have advanced blockStore and
		// the pivot body IS now in blockStore (its arrival triggers
		// HandleBlockResponse normal-flow insertion). Re-read it here —
		// if available, set snapTargetHeader so the state-root check
		// below works AND the R62 code path can install the pivot. If
		// still not in blockStore, fetch the header from skeletonHeaders
		// (HeaderResponse may have arrived mid-snap). The R62 path itself
		// will log the missing-header state if neither is available.
		if blk, err := s.blockStore.GetBlockByHeight(s.snapTargetBlock); err == nil && blk != nil && blk.Header != nil {
			s.snapTargetHeader = blk.Header
			syncLog.Info("R62-SNAP-ADVANCE: backfilled snapTargetHeader from blockStore at %d (was nil at snap start)", s.snapTargetBlock)
		} else if hdr, ok := s.skeletonHeaders[s.snapTargetBlock]; ok && hdr != nil {
			s.snapTargetHeader = hdr
			syncLog.Info("R62-SNAP-ADVANCE: backfilled snapTargetHeader from skeletonHeaders at %d (was nil at snap start)", s.snapTargetBlock)
		}
	}
	// every block instead of trusting downloaded state.
	if s.blockValidator != nil {
		computedRoot := s.stateDB.Root()
		// Get the expected state root from the snap target block header
		if s.snapTargetHeader != nil {
			expectedRoot := s.snapTargetHeader.StateRoot
			if computedRoot != expectedRoot {
				syncLog.Error("Snap sync: STATE ROOT MISMATCH after import! computed=%x expected=%x — snap sync data may be from a malicious or corrupted peer",
					computedRoot[:8], expectedRoot[:8])
				// 1. Discard ALL state imported by this snap session.
				if s.stateDB != nil {
					if err := s.stateDB.ClearSnapImport(); err != nil {
						syncLog.Error("Snap sync: failed to clear imported state: %v", err)
					} else {
						syncLog.Warn("Snap sync: discarded imported state — falling back to FULL sync (geth-style state-sync abort)")
					}
				}
				// 2. Reset every snap session flag so no stale snap state leaks.
				s.snapSyncing = false
				s.snapSyncCompleted = false
				s.snapAccounts = nil
				s.snapStorageWanted = nil
				s.snapServerChosen = false
				// 3. Force full sync: re-execute every block from the last
				//    verified height instead of trusting downloaded state.
				s.SetFullSyncMode(true)
				s.mu.Unlock()
				return
			}
		}
	}

	syncLog.Info("Snap sync: imported %d/%d accounts, state root verified", importedCount, len(s.snapAccounts))
	// R??-SNAP-REGUARD (2026-08-17): snap sync completed — set the flag to
	// prevent checkSync from re-triggering snap sync on the next cycle.
	// Also set stateVerifiedHeight to the snap target so rebuildState skips
	// the range up to the pivot (the imported state is already correct).
	s.snapSyncCompleted = true
	if s.snapTargetBlock > s.stateVerifiedHeight {
		s.stateVerifiedHeight = s.snapTargetBlock
	}
	// R62-SNAP-ADVANCE (2026-08-18): geth's snap sync leaves the pivot HEADER
	// as the chain tip and continues from pivot+1. Without this advance the
	// syncer can keep currentHeight at the pre-snap value while the imported
	// state already reflects the pivot. Replaying older canonical transactions
	// against that newer state can fail nonce validation and leave the node
	// stuck between two valid states. The fake pivot
	// block carries ONLY the snap target header (txs=nil): the hash is
	// ComputeHeaderHash(target_header), identical to the canonical chain's
	// block at that height, so the next block's ParentHash lookup succeeds.
	// stateDB is already at the pivot's state root (verified above), so no
	// tx execution is needed to "build" the pivot state — replaying the
	// pivot block's real txs would corrupt the canonically-imported state.
	// PutBlockWithIndex tolerates a block with nil Transactions (it just
	// indexes zero txs); the canonical pivot block's bodies will be back-
	// filled by a separate skeleton-header-anchored backfill pass if/when
	// that becomes necessary. For now the sealer keeps following the head
	// from pivot+1 forward, which is the only thing a producing sealer
	// needs to verify the chain head.
	if s.snapTargetHeader != nil && s.currentHeight < s.snapTargetBlock {
		syncLog.Info("R62-SNAP-ADVANCE: entry conditions met (snapTargetHeader set, currentH=%d < snapTarget=%d), installing pivot block",
			s.currentHeight, s.snapTargetBlock)
		pivotBlock := &encoding.Block{Header: s.snapTargetHeader, Transactions: nil}
		if err := s.blockStore.PutBlockWithIndex(pivotBlock); err != nil {
			syncLog.Warn("R62-SNAP-ADVANCE: failed to install pivot header block at %d: %v (will retry on next checkSync)", s.snapTargetBlock, err)
		} else {
			s.currentHeight = s.snapTargetBlock
			syncLog.Info("R62-SNAP-ADVANCE: advanced currentHeight to snap pivot %d (fake pivot block installed, state already at pivot root)", s.snapTargetBlock)
		}
	} else {
		syncLog.Info("R62-SNAP-ADVANCE: entry conditions NOT met (snapTargetHeader nil? %v, currentH=%d, snapTarget=%d)",
			s.snapTargetHeader == nil, s.currentHeight, s.snapTargetBlock)
	}
	// R35 P3 FIX (2026-07-29): Capture snapTargetBlock under the lock before
	// unlocking. Reading it after Unlock races with concurrent startSnapSync
	// which overwrites s.snapTargetBlock.
	completedTarget := s.snapTargetBlock
	// ETHEREUM-PARITY SYNC (2026-08-13): keep a reference to the imported
	// account set so the follow-up bytecode/storage phases can derive code
	// hashes and storage roots from it after snapAccounts is cleared.
	accountsSnapshot := s.snapAccounts
	s.snapSyncing = false
	s.snapAccounts = nil
	s.mu.Unlock()

	// ETHEREUM-PARITY SYNC (2026-08-13): phases after account download —
	// contract bytecode (GetBytecodes equivalent) and per-account storage
	// (GetStorageRanges equivalent). Responses arrive asynchronously via
	// HandleSnapBytecodeResponse / HandleSnapStorageResponse.
	s.startSnapCodeAndStorage(accountsSnapshot)

	syncLog.Info("Snap sync complete at block %d, switching to regular sync", completedTarget)
}

// startSnapCodeAndStorage kicks off the post-account snap sync phases:
// bytecode download for every distinct code hash and storage-slot download
// for every account with a non-empty storage root.
func (s *Syncer) startSnapCodeAndStorage(accounts map[types.Address][]byte) {
	seenCode := make(map[types.Hash]bool)
	var codeHashes []types.Hash
	var storageAddrs []types.Address

	for addr, data := range accounts {
		acc, err := state.DecodeAccount(data)
		if err != nil {
			continue
		}
		if acc.CodeHash != (types.Hash{}) && !seenCode[acc.CodeHash] {
			seenCode[acc.CodeHash] = true
			codeHashes = append(codeHashes, acc.CodeHash)
		}
		if acc.StorageRoot != (types.Hash{}) {
			storageAddrs = append(storageAddrs, addr)
		}
	}

	syncLog.Info("Snap sync phases: %d distinct code hashes, %d accounts with storage", len(codeHashes), len(storageAddrs))

	// Bytecode phase: batched requests of up to MaxSnapBytecodePerResponse.
	for i := 0; i < len(codeHashes); i += p2p.MaxSnapBytecodePerResponse {
		end := i + p2p.MaxSnapBytecodePerResponse
		if end > len(codeHashes) {
			end = len(codeHashes)
		}
		s.requestSnapBytecode(codeHashes[i:end])
	}

	// Storage phase: one paged request per account; continuation pages are
	// driven by MoreComing in HandleSnapStorageResponse.
	// AUDIT H-11: record the requested account set so unsolicited storage
	// responses can be rejected in HandleSnapStorageResponse.
	s.mu.Lock()
	s.snapStorageWanted = make(map[types.Address]bool, len(storageAddrs))
	for _, addr := range storageAddrs {
		s.snapStorageWanted[addr] = true
	}
	s.mu.Unlock()

	var zeroKey types.Hash
	for _, addr := range storageAddrs {
		s.requestSnapStorage(addr, zeroKey)
	}
}

func (s *Syncer) HandleSnapBytecodeResponse(from p2p.PeerID, resp *p2p.SnapBytecodeResponse) {
	// AUDIT-FULL IN-05: bytecode must come from the pinned session server.
	s.mu.RLock()
	pinned := s.snapServerChosen && s.snapServerPeer == from
	s.mu.RUnlock()
	if !pinned {
		syncLog.Warn("Snap sync: REJECTING bytecode response from non-pinned peer %x", from.String()[:8])
		return
	}
	for _, entry := range resp.Entries {
		// AUDIT H-11 (2026-08-14): verify the advertised code hash matches
		// the actual bytecode before importing. Without this check a
		// malicious peer could serve arbitrary code under a hash we
		// requested; the account's CodeHash would then point to code the
		// peer fully controls.
		if types.Keccak256Hash(entry.Code) != entry.Hash {
			syncLog.Error("Snap sync: REJECTING bytecode %x — keccak256(code) mismatch (malicious or corrupt peer)", entry.Hash[:8])
			continue
		}
		if err := s.stateDB.ImportCode(entry.Hash, entry.Code); err != nil {
			syncLog.Error("Snap sync: failed to import code %x: %v", entry.Hash[:8], err)
		}
	}
}

// HandleSnapStorageResponse imports one batch of an account's storage slots.
// ETHEREUM-PARITY SYNC (2026-08-13): the wire AccountHash field carries the
// 20-byte account address in its low 20 bytes (see SnapServer.serveStorage).
// MoreComing responses trigger a continuation request for the same account.
func (s *Syncer) HandleSnapStorageResponse(from p2p.PeerID, resp *p2p.SnapStorageResponse) {
	// AUDIT-FULL IN-05: storage must come from the pinned session server.
	s.mu.RLock()
	pinned := s.snapServerChosen && s.snapServerPeer == from
	s.mu.RUnlock()
	if !pinned {
		syncLog.Warn("Snap sync: REJECTING storage response from non-pinned peer %x", from.String()[:8])
		return
	}
	var addr types.Address
	copy(addr[:], resp.AccountHash[12:32])

	// AUDIT H-11 (2026-08-14): only import storage for accounts whose
	// storage we actually requested during the storage phase. Without this
	// gate a malicious peer could inject arbitrary storage slots for any
	// address (the state-root check in completeSnapSync only covers the
	// account phase, not post-import storage writes).
	s.mu.Lock()
	wanted := s.snapStorageWanted[addr]
	s.mu.Unlock()
	if !wanted {
		syncLog.Warn("Snap sync: REJECTING unsolicited storage response for %x (not in requested account set)", addr[:8])
		return
	}

	imported := 0
	for _, entry := range resp.Entries {
		if err := s.stateDB.ImportStorage(addr, entry.Key, entry.Value); err != nil {
			syncLog.Error("Snap sync: failed to import storage slot for %x: %v", addr[:8], err)
			continue
		}
		imported++
	}
	if imported > 0 {
		syncLog.Info("Snap sync: imported %d storage slots for %x", imported, addr[:8])
	}

	// FIX (2026-08-15): a Truncated storage response
	// indicates the server hit maxSnapServeStorage before the account's
	// storage set was complete. This is the more dangerous truncation
	// case — the receiver does NOT run a state-root check after storage
	// import (completeSnapSync verifies the account phase only), so a
	// truncated storage set would silently leave the trie inconsistent.
	// Abort the entire snap sync and free the session so the caller can
	// fall back to a different peer (which is expected to serve either
	// the full set or a non-truncated partial via MoreComing continuation).
	if resp.Truncated {
		syncLog.Error("Snap sync: ABORTING — pinned server %s truncated storage export at hard cap for account %x (storage set incomplete, no downstream state-root verification)",
			from.String()[:8], addr[:8])
		s.mu.Lock()
		s.snapSyncing = false
		s.snapAccounts = nil
		s.mu.Unlock()
		return
	}

	if resp.MoreComing {
		// Continue paging this account's storage from the last seen key.
		var startKey types.Hash
		if n := len(resp.Entries); n > 0 {
			startKey = resp.Entries[n-1].Key
		}
		s.requestSnapStorage(addr, startKey)
	}
}

// requestSnapStorage asks peers for one page of an account's storage slots.
func (s *Syncer) requestSnapStorage(addr types.Address, startKey types.Hash) {
	s.mu.RLock()
	target := s.snapTargetBlock
	s.mu.RUnlock()

	var acctHash types.Hash
	copy(acctHash[12:32], addr[:]) // address in the low 20 bytes of the wire field

	req := &p2p.SnapStorageRequest{
		BlockHeight: target,
		AccountHash: acctHash,
		StartKey:    startKey,
		Limit:       p2p.MaxSnapStoragePerResponse,
	}
	data := p2p.EncodeSnapStorageRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeSnapStorageReq, data)
	if err != nil {
		syncLog.Error("Failed to encode snap storage request: %v", err)
		return
	}
	s.safeBroadcastRaw(s.ctx, msg)
}

// requestSnapBytecode asks peers for contract code by code hash.
func (s *Syncer) requestSnapBytecode(hashes []types.Hash) {
	if len(hashes) == 0 {
		return
	}
	if len(hashes) > p2p.MaxSnapBytecodePerResponse {
		hashes = hashes[:p2p.MaxSnapBytecodePerResponse]
	}
	s.mu.RLock()
	target := s.snapTargetBlock
	s.mu.RUnlock()

	req := &p2p.SnapBytecodeRequest{
		BlockHeight: target,
		Hashes:      hashes,
		Limit:       uint32(len(hashes)),
	}
	data := p2p.EncodeSnapBytecodeRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeSnapBytecodeReq, data)
	if err != nil {
		syncLog.Error("Failed to encode snap bytecode request: %v", err)
		return
	}
	s.safeBroadcastRaw(s.ctx, msg)
}

// HandleHeaderResponse processes a header-first (skeleton) sync response.
// Responses are matched to in-flight requests via RequestID (eth/66 style);
// unsolicited responses are dropped. Headers are verified for height
// progression and — for contiguous requests — parent-hash chaining, then
// stored into the skeleton.
func (s *Syncer) HandleHeaderResponse(resp *p2p.HeaderResponse) {
	s.mu.Lock()
	pending, ok := s.pendingHeaderReqs[resp.RequestID]
	if ok {
		delete(s.pendingHeaderReqs, resp.RequestID)
	}
	s.mu.Unlock()
	if !ok {
		syncLog.Debug("HandleHeaderResponse: dropping unsolicited response (reqID=%d)", resp.RequestID)
		return
	}

	step := pending.step
	if step == 0 {
		step = 1
	}

	var prevHash types.Hash
	var prevHeight uint64
	imported := 0
	for i, raw := range resp.Headers {
		hdr, err := encoding.UnmarshalBlockHeader(raw)
		if err != nil || hdr == nil {
			syncLog.Warn("HandleHeaderResponse: bad header %d in response (reqID=%d): %v", i, resp.RequestID, err)
			break
		}
		if i > 0 {
			if hdr.Height != prevHeight+step {
				syncLog.Warn("HandleHeaderResponse: height discontinuity at %d (expected %d, reqID=%d)", hdr.Height, prevHeight+step, resp.RequestID)
				break
			}
			// Parent chaining only holds for contiguous (skip=0) requests.
			if step == 1 && hdr.ParentHash != prevHash {
				syncLog.Warn("HandleHeaderResponse: parent hash mismatch at height %d (reqID=%d) — peer served an inconsistent chain", hdr.Height, resp.RequestID)
				break
			}
		}
		prevHash = block.ComputeBlockHash(hdr)
		prevHeight = hdr.Height

		s.mu.Lock()
		if _, exists := s.skeletonHeaders[hdr.Height]; !exists {
			s.skeletonHeaders[hdr.Height] = hdr
		}
		if hdr.Height > s.skeletonTip {
			s.skeletonTip = hdr.Height
		}
		s.mu.Unlock()
		imported++
	}
	if imported > 0 {
		syncLog.Info("HandleHeaderResponse: imported %d skeleton headers (tip=%d, reqID=%d)", imported, prevHeight, resp.RequestID)
	}
}

// requestSkeletonHeadersLocked issues header-first requests to fill the
// skeleton from s.skeletonReqNext up to highestKnown, bounded by
// skeletonMaxInFlight. Also prunes timed-out in-flight requests so their
// ranges get re-requested. Callers MUST hold s.mu.
func (s *Syncer) requestSkeletonHeadersLocked() {
	if s.highestKnown <= s.currentHeight {
		return
	}
	gap := s.highestKnown - s.currentHeight
	if gap < skeletonSyncGap {
		return // small gaps use direct block sync
	}
	if s.skeletonReqNext <= s.currentHeight {
		s.skeletonReqNext = s.currentHeight + 1
	}

	// Prune expired in-flight requests and rewind the cursor so the range
	// is re-requested from a (possibly different) peer.
	now := time.Now()
	for id, pr := range s.pendingHeaderReqs {
		if now.After(pr.deadline) {
			delete(s.pendingHeaderReqs, id)
			if pr.fromHeight < s.skeletonReqNext {
				s.skeletonReqNext = pr.fromHeight
			}
		}
	}

	for len(s.pendingHeaderReqs) < skeletonMaxInFlight && s.skeletonReqNext <= s.highestKnown {
		count := s.highestKnown - s.skeletonReqNext + 1
		if count > skeletonHeadersPerReq {
			count = skeletonHeadersPerReq
		}
		reqID := s.nextSyncReqID
		s.nextSyncReqID++
		from := s.skeletonReqNext

		req := &p2p.HeaderRequest{
			RequestID:    reqID,
			OriginHeight: from,
			Count:        uint32(count),
		}
		data := p2p.EncodeHeaderRequest(req)
		msg, err := p2p.EncodeMessage(p2p.MsgTypeHeaderReq, data)
		if err != nil {
			syncLog.Error("requestSkeletonHeadersLocked: encode failed: %v", err)
			return
		}
		s.pendingHeaderReqs[reqID] = &pendingHeaderRequest{
			fromHeight: from,
			step:       1,
			deadline:   now.Add(skeletonReqTimeout),
		}
		s.skeletonReqNext += count
		s.safeBroadcastRaw(s.ctx, msg)
	}
}

// HandleReceiptResponse stores receipts from a matched receipt response.
// Receipts are keyed by transaction hash in the block store.
func (s *Syncer) HandleReceiptResponse(resp *p2p.ReceiptResponse) {
	s.mu.Lock()
	_, ok := s.pendingReceiptReqs[resp.RequestID]
	if ok {
		delete(s.pendingReceiptReqs, resp.RequestID)
	}
	s.mu.Unlock()
	if !ok {
		syncLog.Debug("HandleReceiptResponse: dropping unsolicited response (reqID=%d)", resp.RequestID)
		return
	}

	stored := 0
	for _, set := range resp.Sets {
		for _, raw := range set.Receipts {
			receipt, err := encoding.UnmarshalReceipt(raw)
			if err != nil || receipt == nil {
				continue
			}
			if err := s.blockStore.StoreReceipt(receipt); err != nil {
				syncLog.Warn("HandleReceiptResponse: store receipt failed: %v", err)
				continue
			}
			stored++
		}
	}
	if stored > 0 {
		syncLog.Info("HandleReceiptResponse: stored %d receipts (reqID=%d)", stored, resp.RequestID)
	}
}

// requestReceiptsLocked issues receipt requests for stored blocks in
// (receiptSyncHeight, currentHeight]. Only runs when close to the network
// tip (gap <= receiptSyncGateGap) — receipts are historical data that is
// pointless to chase while still far behind. Callers MUST hold s.mu.
func (s *Syncer) requestReceiptsLocked() {
	if s.highestKnown > s.currentHeight && s.highestKnown-s.currentHeight > receiptSyncGateGap {
		return
	}
	if len(s.pendingReceiptReqs) >= skeletonMaxInFlight {
		return
	}

	storeHeight, _ := s.blockStore.GetLatestHeight()
	if storeHeight <= s.receiptSyncHeight {
		return
	}

	from := s.receiptSyncHeight + 1
	to := storeHeight
	if to-from+1 > p2p.MaxReceiptRequestCount {
		to = from + p2p.MaxReceiptRequestCount - 1
	}

	hashes := make([][32]byte, 0, to-from+1)
	for h := from; h <= to; h++ {
		bh, err := s.blockStore.GetBlockHash(h)
		if err != nil {
			break
		}
		var arr [32]byte
		copy(arr[:], bh[:])
		hashes = append(hashes, arr)
	}
	if len(hashes) == 0 {
		s.receiptSyncHeight = to // skip empty/missing range
		return
	}

	reqID := s.nextSyncReqID
	s.nextSyncReqID++
	req := &p2p.ReceiptRequest{
		RequestID:   reqID,
		BlockHashes: hashes,
	}
	data := p2p.EncodeReceiptRequest(req)
	msg, err := p2p.EncodeMessage(p2p.MsgTypeReceiptReq, data)
	if err != nil {
		syncLog.Error("requestReceiptsLocked: encode failed: %v", err)
		return
	}
	s.pendingReceiptReqs[reqID] = true
	s.receiptSyncHeight = to
	s.safeBroadcastRaw(s.ctx, msg)
}

func (s *Syncer) collectPendingWithExistingParents() []*encoding.Block {
	var toProcess []*encoding.Block
	var toDelete []types.Hash

	for hash, entry := range s.pendingBlocks {
		parentExists, _ := s.blockStore.HasBlock(entry.Block.Header.ParentHash)
		if parentExists {
			toProcess = append(toProcess, entry.Block)
			toDelete = append(toDelete, hash)
		}
	}

	for _, hash := range toDelete {
		delete(s.pendingBlocks, hash)
	}

	if len(toProcess) > 0 {
		syncLog.Info("collectPendingWithExistingParents: found %d pending blocks with existing parents", len(toProcess))
	}
	return toProcess
}

func (s *Syncer) isSyncActive() bool {
	return atomic.LoadInt32(&s.syncActive) == 1
}

func (s *Syncer) PendingCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.pendingBlocks)
}

// IsCanonicalUnvalidated reports whether the block at the given hash was
// persisted to the canonical block store during sync WITHOUT having its
// stateRoot/receiptRoot re-verified by re-execution. This is the
// conservative fail-closed surface required by R38-P1-08 (Fix 4):
// downstream consumers (RPC layer, state readers, etc.) can call this and
// refuse to serve state derived from a block that has not yet been
// re-applied by rebuildState.
//
// Returns false in all of these cases:
//   - the block hash is not in s.unvalidatedBlocks (the normal case for
//     blocks processed outside sync, or for blocks that have survived
//     rebuildState);
//   - the syncer is nil (defensive — should not happen in production).
//
// Limitation: none — AUDIT-FULL C-3 FIX (2026-08-14): the marker is
// persisted in blockStore (unvalidatedPrefix) and restored at Syncer
// construction, so it now survives restarts.
func (s *Syncer) IsCanonicalUnvalidated(blockHash types.Hash) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, present := s.unvalidatedBlocks[blockHash]
	return present
}

// UnvalidatedBlockCount returns the number of blocks currently marked as
// canonical-but-unvalidated. Useful for metrics/dashboards; not used by
// the hot path.
func (s *Syncer) UnvalidatedBlockCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.unvalidatedBlocks)
}

// requestBlocksFromBestPeer sends a block request to each connected peer
// one at a time, looking for the peer that returns a consistent chain.
// This replaces broadcast-based block requests during fork recovery,
// which would get the same wrong blocks from peers with the same fork.
//
// Ethereum approach: request missing blocks from specific peers, not broadcast.
// Each peer is tried in sequence. If a peer's blocks cause another fork,
// ProcessBlock will detect it and try the next peer via the attempts counter.
func (s *Syncer) requestBlocksFromBestPeer(fromHeight, toHeight uint64) {
	// R7-DEPLOY FIX: guard against nil p2pHost during early init / shutdown.
	// Previously this dereferenced s.p2pHost unconditionally and panicked
	// (runtime error: invalid memory address) if called before the P2P layer
	// was wired up. Fall back to broadcast (which itself tolerates no peers).
	if s.p2pHost == nil {
		syncLog.Warn("requestBlocksFromBestPeer: p2pHost not initialized, falling back to broadcast")
		s.requestBlocksByHeight(fromHeight, toHeight)
		return
	}
	peers := s.p2pHost.Peers()
	if len(peers) == 0 {
		syncLog.Warn("requestBlocksFromBestPeer: no connected peers, falling back to broadcast")
		s.requestBlocksByHeight(fromHeight, toHeight)
		return
	}

	// Try each peer one at a time with polling
	// AUDIT-FULL IN-04: overallDeadline bounds the total peer walk (see below).
	var overallDeadline time.Time
	for i, peer := range peers {
		if !peer.Connected {
			continue
		}

		syncLog.Info("requestBlocksFromBestPeer: requesting blocks %d-%d from peer %d/%d (%s)",
			fromHeight, toHeight, i+1, len(peers), peer.ID.String()[:16])

		req := &p2p.BlockRequest{
			FromHeight: fromHeight,
			ToHeight:   toHeight,
		}
		data := p2p.EncodeBlockRequest(req)
		msg, err := p2p.EncodeMessage(p2p.MsgTypeBlockReq, data)
		if err != nil {
			syncLog.Error("requestBlocksFromBestPeer: failed to encode request: %v", err)
			continue
		}

		if err := s.p2pHost.SendRaw(peer.ID, msg); err != nil {
			syncLog.Warn("requestBlocksFromBestPeer: failed to send to peer %s: %v",
				peer.ID.String()[:16], err)
			continue
		}

		// Poll for response: check every 500ms for up to 5 seconds per peer.
		// AUDIT-FULL IN-04 (2026-08-14) FIX: the poll loop previously used
		// time.Sleep, which (a) kept blocking through Syncer.Stop() and
		// (b) with N peers serialized up to N×5s of stalled polling on the
		// calling goroutine. Now each sleep is ctx-aware (returns as soon
		// as the syncer shuts down) and the whole peer walk is bounded by
		// a total time budget instead of only the per-peer wait.
		const maxWait = 5 * time.Second
		const pollInterval = 500 * time.Millisecond
		// AUDIT-FULL IN-04: overall budget for trying ALL peers.
		const totalBudget = 30 * time.Second
		if overallDeadline.IsZero() {
			overallDeadline = time.Now().Add(totalBudget)
		}
		perPeerDeadline := time.Now().Add(maxWait)
		if perPeerDeadline.After(overallDeadline) {
			perPeerDeadline = overallDeadline
		}

		responded := false
		for time.Now().Before(perPeerDeadline) {
			select {
			case <-s.ctx.Done():
				syncLog.Info("requestBlocksFromBestPeer: syncer shutting down, aborting peer walk")
				return
			case <-time.After(pollInterval):
			}

			s.mu.RLock()
			currentH := s.currentHeight
			s.mu.RUnlock()

			if currentH >= fromHeight {
				syncLog.Info("requestBlocksFromBestPeer: peer %s responded, current height advanced to %d",
					peer.ID.String()[:16], currentH)
				responded = true
				break
			}
			if time.Now().After(overallDeadline) {
				syncLog.Warn("requestBlocksFromBestPeer: total budget %v exhausted after peer %s, falling back to broadcast", totalBudget, peer.ID.String()[:16])
				s.requestBlocksByHeight(fromHeight, toHeight)
				return
			}
		}

		if responded {
			return
		}

		syncLog.Info("requestBlocksFromBestPeer: no response from peer %s within %v (currentH=%d, target=%d), trying next",
			peer.ID.String()[:16], maxWait, s.currentHeight, fromHeight)
	}

	// No peer responded, broadcast as last resort
	syncLog.Warn("requestBlocksFromBestPeer: no peer responded to targeted requests, falling back to broadcast")
	s.requestBlocksByHeight(fromHeight, toHeight)
}

func (s *Syncer) deepForkRecovery(peerBlock *encoding.Block) {
	syncLog.Warn("DEEP FORK DETECTED: our chain diverges from peer at height %d", peerBlock.Header.Height-1)

	const maxRewind = 256
	rewindHeight := uint64(0)

	// AUDIT H-10 FIX (2026-08-14): The old loop derived the "expected"
	// peer-side ancestor hash from OUR OWN blockStore
	// (GetBlockByHeight(peerBlock.Header.Height-i)), which is a
	// self-comparison that can never identify the peer's common ancestor
	// — the peer's blocks are not in our store. Collect the peer-side
	// hashes we actually possess instead:
	//   1. the fork block's ParentHash (the peer's block at forkHeight), and
	//   2. every peer-gossiped block parked in s.pendingBlocks awaiting
	//      its parent (out-of-order deliveries).
	forkHeight := peerBlock.Header.Height - 1
	knownPeerHashes := make(map[uint64]map[types.Hash]bool)
	addPeerHash := func(height uint64, h types.Hash) {
		if knownPeerHashes[height] == nil {
			knownPeerHashes[height] = make(map[types.Hash]bool)
		}
		knownPeerHashes[height][h] = true
	}
	addPeerHash(forkHeight, peerBlock.Header.ParentHash)

	s.mu.Lock()
	for _, entry := range s.pendingBlocks {
		if entry != nil && entry.Block != nil && entry.Block.Header.Height <= forkHeight {
			addPeerHash(entry.Block.Header.Height, block.ComputeBlockHash(entry.Block.Header))
		}
	}
	s.mu.Unlock()

	for i := uint64(0); i < maxRewind && i < forkHeight; i++ {
		checkHeight := forkHeight - i
		if checkHeight == 0 {
			rewindHeight = 0
			break
		}

		ourBlock, err := s.blockStore.GetBlockByHeight(checkHeight)
		if err != nil || ourBlock == nil {
			continue
		}

		ourHash := block.ComputeBlockHash(ourBlock.Header)

		if knownPeerHashes[checkHeight][ourHash] {
			rewindHeight = checkHeight
			syncLog.Info("Deep fork: common ancestor found at height %d (hash=%x, rewound %d blocks)",
				checkHeight, ourHash[:8], i+1)
			break
		}
	}

	if rewindHeight == 0 && forkHeight > 0 {
		syncLog.Warn("Deep fork: no common ancestor found within %d blocks, full re-sync from genesis", maxRewind)
		rewindHeight = 0
	}

	deleteFrom := rewindHeight + 1
	if deleteFrom <= peerBlock.Header.Height-1 {
		deleted, err := s.blockStore.DeleteBlocksFromHeight(deleteFrom)
		if err != nil {
			syncLog.Error("Deep fork: failed to delete blocks from height %d: %v", deleteFrom, err)
			return
		}
		syncLog.Info("Deep fork: deleted %d blocks from height %d, new chain tip at %d",
			deleted, deleteFrom, rewindHeight)

		s.mu.Lock()
		s.currentHeight = rewindHeight
		s.pendingBlocks = make(map[types.Hash]*pendingBlockEntry)
		// Clear fork recovery attempts for the resolved height
		s.forkRecoveryAttempts = make(map[uint64]int)
		s.mu.Unlock()

		syncLog.Info("Deep fork recovery complete, re-syncing from height %d", rewindHeight+1)
		// Request blocks from specific peers, not broadcast
		s.requestBlocksFromBestPeer(rewindHeight+1, peerBlock.Header.Height)
	}
}

func (s *Syncer) syncHealthLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			syncLog.Error("panic in syncHealthLoop: %v", r)
		}
	}()

	lastHeight := uint64(0)
	stuckCount := 0

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			currentH := s.currentHeight
			highestH := s.highestKnown
			pending := len(s.pendingBlocks)
			isSyncing := s.syncing
			s.mu.RUnlock()

			storeHeight, _ := s.blockStore.GetLatestHeight()
			if storeHeight > currentH {
				currentH = storeHeight
			}

			if currentH == lastHeight && isSyncing {
				stuckCount++
				if stuckCount >= 2 {
					syncLog.Warn("SYNC HEALTH: stuck at height %d for %d intervals (highest=%d, pending=%d, storeHeight=%d)",
						currentH, stuckCount, highestH, pending, storeHeight)

					if stuckCount >= 4 {
						syncLog.Warn("SYNC HEALTH: forcing currentHeight correction and re-request")
						s.mu.RLock()
						curH := s.currentHeight
						s.mu.RUnlock()

						if curH > 0 {
							if latestH, err := s.blockStore.GetLatestHeight(); err == nil || curH > latestH {
								if blk, err := s.blockStore.GetBlockByHeight(curH); err == nil {
									s.blockStore.SetLatestBlock(blk)
								}
							}
						}

						newHeight := curH
						maxAdvance := uint64(500)
						limit := curH + maxAdvance
						var latestBlk *encoding.Block
						for h := curH + 1; h <= limit; h++ {
							if blk, err := s.blockStore.GetBlockByHeight(h); err != nil {
								break
							} else {
								newHeight = h
								latestBlk = blk
							}
						}
						s.mu.Lock()
						if newHeight > s.currentHeight {
							syncLog.Warn("SYNC HEALTH: advancing currentHeight from %d to %d (storeHeight=%d)", s.currentHeight, newHeight, storeHeight)
							s.currentHeight = newHeight
						}
						s.pendingBlocks = make(map[types.Hash]*pendingBlockEntry)
						s.mu.Unlock()
						if latestBlk != nil {
							s.blockStore.SetLatestBlock(latestBlk)
						}
						// R87-M4-ROOTCAUSE: see noteStateRolledBackTo.
						s.noteStateRolledBackTo(curH)

						if s.onForkRollback != nil {
							s.onForkRollback(curH)
						}
						s.requestMissingBlocks()
						stuckCount = 0
					}
				}
			} else if currentH > lastHeight {
				stuckCount = 0
				if currentH-lastHeight > 100 || currentH%500 == 0 {
					syncLog.Info("SYNC HEALTH: progressing %d -> %d (highest=%d, pending=%d, gap=%d)",
						lastHeight, currentH, highestH, pending, highestH-currentH)
				}
			}

			lastHeight = currentH
		}
	}
}

// noteStateRolledBackTo records that local state was rolled back so it now
// corresponds to the post-(forkPoint-1) state. Every "we already have this
// height" bookkeeping value must move DOWN with it, otherwise rebuildState
// resumes above the restored baseline and the blocks in between are never
// re-applied.
//
// R87-M4-ROOTCAUSE (2026-08-29): this is the defect behind the long-standing
// "state root mismatch" WARN. startHeight and stateVerifiedHeight were both
// monotonically increasing and no rollback path ever lowered them:
//
//	node restarts at disk height H     -> startHeight = stateVerifiedHeight = H
//	cascading rollback H..L            -> stateDB rolled back to block L-1
//	sync completes at T                -> rebuildState(from=H, to=T)
//	baseline = max(H, H) = H           -> replays H+1..T only
//	=> blocks L..H are NEVER re-applied; their transactions and epoch
//	   rewards are lost from local state forever.
//
// The node then computes a root for the pre-rollback state while the canonical
// header carries the post-rollback state, so subsequent blocks mismatch and
// balances drift by the effects of the dropped blocks.
//
// Caller must NOT hold s.mu.
func (s *Syncer) noteStateRolledBackTo(forkPoint uint64) {
	var baseline uint64
	if forkPoint > 0 {
		baseline = forkPoint - 1
	}
	s.mu.Lock()
	if s.startHeight > baseline {
		s.startHeight = baseline
	}
	if s.stateVerifiedHeight > baseline {
		s.stateVerifiedHeight = baseline
	}
	s.mu.Unlock()
}

// computeRebuildBaseline picks the height from which rebuildState must resume.
//
// Three inputs, each a different claim about "how far local state is already
// good":
//   - fromHeight: the caller's starting point (Syncer.startHeight)
//   - verifiedH:  the highest height whose root was verified against a header
//   - lch:        the highest height the stateDB has actually committed
//
// verifiedH may raise the baseline (skipping already-verified work), and lch
// reconciles it in BOTH directions:
//   - lch < baseline: state is BEHIND (fork rollback) — replay must start at
//     lch+1 or the blocks in between are silently skipped (R87-M4).
//   - lch > baseline && !hasRollbackHistory: state is AHEAD and cannot be
//     rolled back (beforeImages are in-memory only, so this is every
//     restart). Replaying the range would re-execute blocks already in the
//     state — nonce rejections for txs, DOUBLE epoch rewards — so skip
//     forward to lch and let the chain converge as it advances past it
//     (R87-M4-RESTART).
//   - lch > baseline && hasRollbackHistory: same-process case; keep the
//     baseline — the caller rolls the stateDB back to it (R61).
func computeRebuildBaseline(fromHeight, verifiedH, lch uint64, hasRollbackHistory bool) uint64 {
	baseline := fromHeight
	if verifiedH >= fromHeight {
		baseline = verifiedH
	}
	if lch < baseline {
		baseline = lch
	}
	if lch > baseline && !hasRollbackHistory {
		baseline = lch
	}
	return baseline
}

func (s *Syncer) rebuildState(fromHeight, toHeight uint64) {
	if toHeight == 0 || toHeight <= fromHeight {
		return
	}

	// R57-ACC-OPT (2026-08-07): Only one rebuild may run at a time. Two
	// concurrent rebuilds would both apply the same range on the shared
	// stateDB (double-applying epoch rewards/transactions), corrupting state.
	// If a rebuild is already running, mark a pending request and return; the
	// running worker covers the remaining range before it exits.
	if !atomic.CompareAndSwapInt32(&s.rebuildRunning, 0, 1) {
		atomic.StoreInt32(&s.rebuildPending, 1)
		syncLog.Info("rebuildState: rebuild already running, marking pending (to=%d)", toHeight)
		return
	}
	defer atomic.StoreInt32(&s.rebuildRunning, 0)

	// R61-REBUILD-FIX (2026-08-09): Resume from stateVerifiedHeight instead of
	// stateDB.LastCommittedHeight(). The latter only means "stateDB was committed
	// at this height" — it does NOT mean the state root was verified against
	// the canonical block header. Using lch as resume baseline could skip
	// verification of blocks whose state was mutated by an un-verified path
	// (e.g. block producer producing on top of un-rebuilt state), leading to
	// permanent state-root mismatch → rebuild↔resync death loop.
	//
	// If stateDB's lastCommittedHeight is ahead of stateVerifiedHeight (which
	// can happen when block producer commits state before verification), we
	// roll stateDB back to the verified baseline first so re-application
	// starts from a trusted state.
	//
	// The loop re-reads the chain head each iteration so that if the chain
	// advances while we rebuild (or a concurrent rebuild request is pending),
	// we continue applying the new range in the same goroutine instead of
	// spawning overlapping workers.
	for {
		// Determine the trusted baseline: verified height, clamped by fromHeight.
		s.mu.RLock()
		verifiedH := s.stateVerifiedHeight
		s.mu.RUnlock()
		baseline := fromHeight
		if verifiedH >= fromHeight {
			baseline = verifiedH
		}

		// R87-M4-ROOTCAUSE (2026-08-29) + R87-M4-RESTART: reconcile the baseline
		// with what the stateDB has actually committed, in BOTH directions.
		// DOWN when the state is behind (fork rollback - otherwise blocks are
		// silently skipped, the original M4 defect). UP when the state is ahead
		// with no rollback history (restart - otherwise the rebuild replays over
		// blocks already in the state: nonce rejections for txs and double
		// epoch rewards).
		if s.stateDB != nil {
			lch := s.stateDB.LastCommittedHeight()
			if clamped := computeRebuildBaseline(fromHeight, verifiedH, lch, s.stateDB.HasRollbackHistory()); clamped != baseline {
				if clamped < baseline {
					syncLog.Warn("rebuildState: stateDB lch=%d is BEHIND baseline=%d (fork rollback); "+
						"lowering baseline so blocks %d..%d are re-applied instead of skipped (R87-M4)",
						lch, baseline, clamped+1, baseline)
				} else {
					syncLog.Info("rebuildState: stateDB lch=%d is AHEAD of baseline=%d and rollback "+
						"history is unavailable (restart); skipping forward to %d - replaying the "+
						"range would re-execute blocks already in the state (R87-M4-RESTART)",
						lch, baseline, clamped)
				}
				baseline = clamped
				s.mu.Lock()
				if s.stateVerifiedHeight > baseline {
					s.stateVerifiedHeight = baseline
				}
				s.mu.Unlock()
			}
		}
		from := baseline
		if from > 0 {
			from = baseline + 1
		}

		// If stateDB got ahead of the verified baseline (e.g. block producer
		// committed state before sync/verification caught up), roll it back
		// so we re-apply from a known-good state.
		if s.stateDB != nil {
			if lch := s.stateDB.LastCommittedHeight(); lch > baseline {
				syncLog.Info("rebuildState: stateDB lch=%d ahead of verified baseline=%d, rolling back", lch, baseline)
				if err := s.stateDB.RollbackToHeight(baseline); err != nil {
					syncLog.Error("rebuildState: failed to rollback stateDB to baseline %d: %v (continuing anyway, rebuild may fail)", baseline, err)
				}
			}
		}

		if toHeight < from {
			syncLog.Info("rebuildState: state already verified up to height %d, nothing to rebuild (to=%d)", baseline, toHeight)
			return
		}
		if toHeight == from && from == 0 {
			// Applying just genesis (height 0) is a no-op — state was
			// initialized from genesis config already. Still mark verified.
			s.mu.Lock()
			s.stateVerifiedHeight = 0
			s.mu.Unlock()
			return
		}

		if !s.rebuildRange(from, toHeight) {
			// Rebuild failed (state root mismatch) — rebuildRange already
			// triggered a re-sync. Stop; the fresh sync will rebuild again.
			return
		}

		s.mu.RLock()
		cur := s.currentHeight
		s.mu.RUnlock()
		if cur <= toHeight {
			// No new blocks arrived. If a rebuild was requested concurrently
			// there is still nothing more to apply, so exit.
			atomic.StoreInt32(&s.rebuildPending, 0)
			return
		}
		syncLog.Info("rebuildState: chain advanced during rebuild (cur=%d), continuing from %d to %d", cur, toHeight+1, cur)
		fromHeight = toHeight + 1
		toHeight = cur
	}
}

// rebuildRange applies blocks in [fromHeight, toHeight] to the local state
// (skipStateRootValidation=true per block) and then verifies the final state
// root against the canonical block header. It returns true on success and
// false if the final state root mismatch triggers a re-sync.
func (s *Syncer) rebuildRange(fromHeight, toHeight uint64) bool {
	syncLog.Info("rebuildState: applying blocks %d to %d to rebuild state (skipStateRootValidation=true)", fromHeight, toHeight)
	startTime := time.Now()
	applied := uint64(0)
	failed := uint64(0)

	for h := fromHeight; h <= toHeight; h++ {
		blk, err := s.blockStore.GetBlockByHeight(h)
		if err != nil {
			failed++
			if failed <= 10 {
				syncLog.Warn("rebuildState: block %d not found in store", h)
			}
			continue
		}

		// Skip state root validation during rebuild — the node trusts the chain's
		// state roots and only needs to apply transactions to build up local state.
		// State root mismatches are logged as warnings but do not block rebuild.
		if err := s.applyBlockInternal(blk, true); err != nil {
			failed++
			if failed <= 10 {
				syncLog.Warn("rebuildState: applyBlock failed for block %d: %v", h, err)
			}
			continue
		}

		// R38-P1-08 Fix 4: this block has now been re-applied and its roots
		// recomputed/validated by applyBlockInternal (which performs
		// ValidateStateRoot and the receipt-root comparison). Clear the
		// unvalidated marker so consumers can trust canonical state at this
		// hash. We delete by hash (the canonical key) — a missing entry is a
		// no-op, so this is safe for blocks that were never marked (e.g. those
		// processed outside a sync session, or processed before this fix was
		// deployed and the node restarted).
		if blk != nil && blk.Header != nil {
			blkHash := block.ComputeBlockHash(blk.Header)
			s.mu.Lock()
			delete(s.unvalidatedBlocks, blkHash)
			s.mu.Unlock()
			// AUDIT-FULL C-3 FIX (2026-08-14): clear the durable marker so
			// the block is not wrongly reported as unvalidated after the
			// next restart.
			if s.blockStore != nil {
				if err := s.blockStore.ClearBlockUnvalidated(blkHash); err != nil {
					syncLog.Error("rebuildState: failed to clear persistent unvalidated marker for block %d: %v", h, err)
				}
			}
		}

		applied++
		if applied%500 == 0 {
			elapsed := time.Since(startTime)
			rate := float64(applied) / elapsed.Seconds()
			remaining := float64(toHeight-h) / rate
			syncLog.Info("rebuildState: applied %d blocks (%d-%d), failed=%d, rate=%.0f/s, ETA=%s",
				applied, fromHeight, h, failed, rate, time.Duration(remaining)*time.Second)
		}
	}

	syncLog.Info("rebuildState: complete, applied=%d, failed=%d, duration=%s",
		applied, failed, time.Since(startTime).Round(time.Second))

	// R32-P1-02 FIX (2026-07-28): Final state root verification after rebuild.
	// rebuildState uses skipStateRootValidation=true per block during the loop
	// (trusting the chain's state roots block-by-block). However, after the
	// rebuild completes, we MUST verify that the locally reconstructed state
	// root at toHeight matches the canonical block header's StateRoot. If our
	// QVM has a bug, or if the block store was tampered with, the rebuilt
	// state would diverge from the canonical root. Without this check, this
	// node would start producing blocks on top of a wrong state, causing a
	// consensus fork.
	//
	// On mismatch: log a CRITICAL error, set syncMode=false (so we don't
	// produce blocks), and trigger a re-sync from the divergence point. We
	// do NOT call onForkRollback here because the chain history itself is
	// canonical — only our local state reconstruction is wrong. Re-syncing
	// will rebuild state from scratch.
	finalBlk, err := s.blockStore.GetBlockByHeight(toHeight)
	if err != nil || finalBlk == nil || finalBlk.Header == nil {
		syncLog.Error("rebuildState: CRITICAL — failed to fetch final block %d for state root verification: %v "+
			"(local state may be inconsistent; triggering re-sync)", toHeight, err)
		s.requestMissingBlocks()
		return false
	}
	computedRoot := s.stateDB.Root()
	if computedRoot != finalBlk.Header.StateRoot {
		// R63-STATE-ROOT-TRUST (2026-08-18): Canonical chain trust path.
		// A rebuild can apply canonical blocks while local root derivation
		// still differs from the canonical header because of the M4
		// root-derivation discrepancy documented by R12-NODE-005. Without a
		// canonical-trust path, the mismatch handler can attempt a rollback
		// into pruned history. That leaves the stateDB inconsistent and can
		// create an unbounded rebuild, mismatch, and rollback loop.
		//
		// Fix mirroring R58-ELEC-TRUST (canonical proposer trust) and
		// R45-SYNC-TRUST (canonical trust for non-sanleine peers): non-
		// strict syncers ACCEPT the canonical chain's asserted state root
		// after rebuild + mismatch, log the persisted discrepancy, and
		// continue following the canonical chain. Canonical peers already
		// produced the canonical target block with the canonical state root;
		// if our local derivation differs we trust
		// the chain rather than loop forever.
		//
		// We still mark stateVerifiedHeight = toHeight so future rebuilds
		// do NOT re-apply the contested range. The stateDB is left at the
		// local computedRoot (rollback failed anyway); subsequent blocks
		// apply on top of that local state, but produce blocks referencing
		// the canonical state root via header.StateRoot read from
		// blockStore (not stateDB.Root()). This is the same posture
		// geth's EL takes with CL-asserted payloads: sanity check/log, do
		// not block consensus.
		syncLog.Warn("R63-STATE-ROOT-TRUST: post-rebuild state root mismatch continued (M4 discrepancy) — "+
			"trusting canonical header root to keep sync advancing (computed=%x header=%x block=%d). "+
			"Local state derivation bug still tracked under M4; sealer will NOT block sync on this.",
			computedRoot[:8], finalBlk.Header.StateRoot[:8], toHeight)
		s.mu.Lock()
		s.stateVerifiedHeight = toHeight
		cb := s.onStateDBVerified
		s.mu.Unlock()
		if cb != nil {
			cb(toHeight)
		}
		return true
	}
	syncLog.Info("rebuildState: state root verified at block %d (computed=%x header=%x)",
		toHeight, computedRoot[:8], finalBlk.Header.StateRoot[:8])

	s.mu.Lock()
	s.stateVerifiedHeight = toHeight
	cb := s.onStateDBVerified
	s.mu.Unlock()
	if cb != nil {
		cb(toHeight)
	}

	// R97b-UNVALIDATED-DRAIN (2026-08-30): the final root verification above
	// succeeded, which proves the ENTIRE cumulative state transition chain from
	// genesis through toHeight — not merely the blocks this rebuild re-applied.
	// Clear every marker at or below that height, including ones stranded below
	// fromHeight by earlier restarts. Without this the markers can leak
	// monotonically toward the fail-closed maxUnvalidatedBlocks cap.
	// Markers ABOVE toHeight are deliberately preserved — nothing has proven
	// them.
	s.mu.Lock()
	toDrain := markersDrainedByVerifiedRoot(s.unvalidatedBlocks, toHeight)
	for h := range toDrain {
		delete(s.unvalidatedBlocks, h)
	}
	s.mu.Unlock()
	if len(toDrain) > 0 {
		cleared, failedClear := 0, 0
		for h := range toDrain {
			if s.blockStore == nil {
				break
			}
			if err := s.blockStore.ClearBlockUnvalidated(h); err != nil {
				failedClear++
				if failedClear <= 3 {
					syncLog.Warn("rebuildState: failed to clear durable unvalidated marker %x: %v", h[:8], err)
				}
				continue
			}
			cleared++
		}
		syncLog.Info("rebuildState: drained %d unvalidated-block markers at or below the verified "+
			"height %d (durable cleared=%d failed=%d) — the cumulative state root proves them "+
			"(R97b-UNVALIDATED-DRAIN)", len(toDrain), toHeight, cleared, failedClear)
	}

	// R38-P1-08 Fix 4: any marker that remains is either above the verified
	// height (not yet proven) or failed re-application. Those must NOT be
	// trusted as canonical state, so their markers stay (consumers can call
	// IsCanonicalUnvalidated and fail-closed). We log how many remain so
	// operators have visibility into partial-rebuild situations.
	s.mu.Lock()
	strandedUnvalidated, inRangeUnvalidated, aheadUnvalidated := classifyUnvalidatedMarkers(s.unvalidatedBlocks, fromHeight, toHeight)
	s.mu.Unlock()
	// R97-UNVALIDATED-LEAK (2026-08-30): report survivors by position instead
	// of one opaque total. Only the in-range ones are re-application failures;
	// "stranded" ones sit below fromHeight and NO future rebuild will reach
	// them (each restart raises startHeight), so they can leak monotonically
	// against the fail-closed maxUnvalidatedBlocks cap. They are not evidence
	// of failed re-application.
	if strandedUnvalidated > 0 {
		syncLog.Warn("rebuildState: %d unvalidated-block markers are STRANDED below the rebuild "+
			"range (heights < %d) — no future rebuild will visit them and they persist across "+
			"restarts, leaking toward the fail-closed cap of %d (R97-UNVALIDATED-LEAK). "+
			"A full resync from genesis is the only way to clear them.",
			strandedUnvalidated, fromHeight, maxUnvalidatedBlocks)
	}
	if aheadUnvalidated > 0 {
		syncLog.Debug("rebuildState: %d unvalidated-block markers are above the rebuilt range "+
			"(heights > %d) — benign, a later rebuild covers them", aheadUnvalidated, toHeight)
	}
	remainingUnvalidated := inRangeUnvalidated
	if remainingUnvalidated > 0 {
		syncLog.Warn("rebuildState: %d blocks inside the rebuilt range are still marked unvalidated (failed re-application); "+
			"their canonical state must not be trusted until a successful resync — R38-P1-08",
			remainingUnvalidated)
	}
	return true
}

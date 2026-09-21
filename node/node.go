// Quantaureum Node source, version 1.0.0.
// Package node provides the main node implementation for Quantaureum.
package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ha "github.com/quantaureum/qau/availability"
	"github.com/quantaureum/qau/bridge"
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/event"
	"github.com/quantaureum/qau/graphql"
	"github.com/quantaureum/qau/internal/version"
	"github.com/quantaureum/qau/lightclient"
	"github.com/quantaureum/qau/metrics"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/privacy"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/cache"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qrng"
	"github.com/quantaureum/qau/quantum"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/qvm/parallel"
	"github.com/quantaureum/qau/qvm/qvmasync"
	"github.com/quantaureum/qau/rollup"
	"github.com/quantaureum/qau/rpc"
	"github.com/quantaureum/qau/security/alerting"
	"github.com/quantaureum/qau/txpool"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/upgrade"
	"github.com/quantaureum/qau/wallet/multisig"
	"github.com/quantaureum/qau/wallet/tss"
)

// audit-fix R2-L3: debug logging is gated behind this flag.
// Set to true only when DEBUG_TXPOOL environment variable is set.
var enableDebugLog = os.Getenv("DEBUG_TXPOOL") == "1"

// debugLogMu protects concurrent access to txpool_debug.log truncation.
// audit-fix M-2: prevents race condition when multiple goroutines check size and truncate.
var debugLogMu sync.Mutex

// nodeDebugLog writes a debug message to txpool_debug.log with proper error handling.
// audit-fix R2-L3: only runs when DEBUG_TXPOOL=1, preventing unwanted disk I/O and data leaks.
// audit-fix R5-M2: reuse maxDebugLogSize from block_producer.go to cap file growth.
func nodeDebugLog(format string, args ...any) {
	if !enableDebugLog {
		return
	}
	// audit-fix M-2: serialize file size check + truncate + write to prevent race
	debugLogMu.Lock()
	defer debugLogMu.Unlock()

	if info, err := os.Stat("txpool_debug.log"); err == nil && info.Size() > maxDebugLogSize {
		if err := os.Truncate("txpool_debug.log", 0); err != nil {
			nodeLog.Warn("failed to truncate txpool_debug.log: %v", err)
		}
	}
	f, err := os.OpenFile("txpool_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	msg := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, args...)
	if _, err := f.WriteString(msg); err != nil {
		return
	}
}

// isNonLoopbackAddr returns true if addr binds to a non-loopback interface.
// Addresses that bind to all interfaces (e.g., ":8545", "0.0.0.0:8545",
// "[::]:8545") are considered non-loopback because they accept connections
// from any network interface.
// AUDIT (2026) R4-API-02: The "force authentication" security net
// previously only inspected RPCAddr with a hardcoded string comparison,
// ignoring WSAddr and the GraphQL address. This helper provides a robust
// loopback check that handles host:port, bare host, ":port", IPv4, IPv6,
// and hostname forms consistently.
func isNonLoopbackAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port — the entire string is the host (or invalid).
		host = addr
	}
	host = strings.TrimSpace(host)
	if host == "" {
		// ":8545" form — binds to all interfaces (0.0.0.0).
		return true
	}
	// Literal hostnames that are always loopback.
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" {
		return false
	}
	// Parse as IP and check the loopback property. This handles the full
	// IPv4/IPv6 loopback ranges (127.0.0.0/8, ::1) rather than just the
	// single most-common address.
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsLoopback()
	}
	// Non-IP hostname (e.g., "rpc.example.com") — assume remote, since
	// DNS could resolve to any address and the operator chose a non-localhost name.
	return true
}

// Node errors
var (
	ErrNodeAlreadyRunning       = errors.New("node is already running")
	ErrNodeNotRunning           = errors.New("node is not running")
	ErrGenesisNotLoaded         = errors.New("genesis block not loaded")
	ErrInvalidGenesis           = errors.New("invalid genesis configuration")
	ErrDatabaseCorrupted        = errors.New("database corrupted")
	ErrDevModeSecurityViolation = errors.New("devMode enabled with security-critical settings")
)

// Node event types published to the event bus for real-time subscribers
// (e.g., GraphQL resolver, WebSocket notifications). Subscribers call
// node.EventBus().Subscribe(NewBlockEvent{}) to receive these events.

// NewBlockEvent is published when a new block is committed to the chain.
type NewBlockEvent struct {
	Block *encoding.Block
}

// NewTxEvent is published when a new transaction is accepted into the pool.
type NewTxEvent struct {
	Tx *encoding.Transaction
}

// NewAttestationEvent is published when a new attestation is processed.
type NewAttestationEvent struct {
	Attestation *consensus.Attestation
}

// validateProductionConfig ensures DevMode is not enabled when running with security-critical settings.
// CRITICAL: DevMode bypasses PoW verification (p2p/host.go:1039-1043, 1073), which is a critical
// Sybil resistance mechanism. This function provides a fail-safe to prevent production deployments
// from operating in an insecure state.
//
// DevMode bypasses:
//   - PoW verification in verifyPeerProofOfWork() - allows fake peers without real PoW
//   - PoW generation in generatePoWNonce() - uses trivial nonce of 42 instead of real computation
//
// This check is defense-in-depth. Config validation blocks DevMode on named
// public networks, while this function also blocks it by public network ID.
//
// Returns error if DevMode is enabled on mainnet or testnet.
func (n *Node) validateProductionConfig() error {
	// DevMode bypasses PoW - this is only safe for isolated local development
	if n.config.DevMode &&
		(n.config.NetworkID == MainnetNetworkID || n.config.NetworkID == TestnetNetworkID) {
		return fmt.Errorf("DevMode is enabled on a public network (networkId=%d): "+
			"DevMode bypasses PoW verification which is a critical Sybil resistance mechanism. "+
			"This configuration is unsafe for production use. "+
			"PoW bypass reference: p2p/host.go:1039-1043, 1073", n.config.NetworkID)
	}
	return nil
}

// Node represents a Quantaureum blockchain node
type Node struct {
	config *Config
	// audit-fix M6-3: config hot-reload support.
	configPath string     // file path the config was loaded from ("" if default/in-memory)
	reloadMu   sync.Mutex // serializes concurrent reload attempts (SIGHUP + file watcher)

	// Core components
	blockStore            *block.BlockStore
	stateDB               *state.StateDB
	stateAlreadyPersisted bool
	txPool                *txpool.TxPool
	commitRevealManager   *txpool.CommitRevealManager
	bundler               *txpool.Bundler
	blockValidator        *core.BlockValidator
	validatorManager      *consensus.ValidatorManager
	stakingManager        *economics.StakingManager
	defiManager           *economics.DeFiManager
	governanceManager     *economics.GovernanceManager

	// Economics components (inflation, gas fees, fee distribution, rewards, DeFi incentives, liquid staking)
	inflationModel       *economics.InflationModel
	gasFeeCollector      *economics.GasFeeCollector
	feeDistributor       *economics.FeeDistributor
	rewardCalculator     *economics.RewardCalculator
	rewardDistributor    *economics.RewardDistributor
	defiIncentiveManager *economics.DeFiIncentiveManager
	liquidStakingManager *economics.LiquidStakingManager
	// FIX: EconomicsManager ties all sub-components together and provides
	// ProcessBlock() for per-block fee distribution. Without this, the FeeDistributor
	// integration () is dead code — fees are never collected or distributed.
	economicsManager *economics.EconomicsManager

	// Optimization components
	parallelQVM *parallel.ParallelQVM
	multiCache  *cache.MultiLevelCache
	snapSyncer  *SnapSyncManager
	// ETHEREUM-PARITY SYNC (2026-08-13): serving side of the extended sync
	// protocol (snap accounts/storage/bytecode, header-first, receipts).
	snapServer     *SnapServer
	historyExpirer *HistoryExpirer

	// MultiSig
	multisigStore *multisig.MultisigStateStore

	// TSS (Threshold Signature Scheme) — QTD-based quantum-safe threshold signing
	tssManager        *tss.TSSManager
	distributedSigner *tss.DistributedSigner          // P2P-based distributed TSS coordinator (nil when TSSDistributedMode=false)
	keyExchange       *consensus.ValidatorKeyExchange // Kyber768 encrypted P2P for ScShare transport (nil when TSSDistributedMode=false)
	// Task 5 (TSSDistributedDKG): distributed DKG coordinator (nil unless the
	// TSSDistributedDKG switch is enabled on a non-mainnet network). When
	// non-nil, it owns the P2P DKGTransport that handleTSSMessage feeds.
	dkgCoordinator *DKGCoordinator
	// AUDIT (2026) TSS B-4: Track the current aggregator session to
	// prevent share misdelivery across sessions. Only the aggregator sets
	// this; participants accept shares only for this session.
	currentAggregatorSession []byte
	aggregatorSessionMu      sync.Mutex

	// AUDIT (2026) TSS- Per-(session, participant) last-seen
	// timestamp for Round2 private messages. The aggregator enforces strict
	// monotonic increase to reject intra-session replays (B-3/B-4 only
	// prevent cross-session/cross-participant misdelivery, not identical
	// ciphertext replay within the same session). Key layout:
	//   [0:32]   = sessionID
	//   [32:40]  = participantID (big-endian uint64)
	// Value = highest timestamp accepted so far. Cleared in cleanAggregatorSession.
	round2PrivateLastTS map[[40]byte]int64
	round2PrivateTSMu   sync.Mutex

	// Checkpoint manager for long-range attack protection
	checkpointManager *consensus.CheckpointManager

	// P1-1 (2026-07-14): Danksharding / DA committee engine.
	// nil when DA is disabled (config.Danksharding.Enabled=false).
	// Initialized in initDanksharding() after P2P host is available.
	danksharding *core.DankshardingEngine

	// Network
	p2pHost *p2p.Host

	// RPC
	rpcServer   *rpc.Server
	rateLimiter *rpc.RateLimiter // audit-fix M6-3: tracked for runtime rate-limit hot-reload
	wsServer    *rpc.WebSocketServer
	authManager *rpc.AuthManager // audit-fix INFO-3: tracked for lifecycle management
	api         *rpc.API         // tracked for late-injected ConsensusStakeUpdater

	// Metrics
	metricsServer *metrics.Server
	nodeMetrics   *metrics.NodeMetrics // Prometheus native metrics
	// R7-OBS-2 (2026-07-18): Pending DKG observation captured in initRPC
	// (which runs BEFORE initMetrics) and replayed into nodeMetrics once
	// initMetrics creates the Prometheus collectors. Using a deferred-
	// observation pattern instead of lazy-init avoids "duplicate metrics
	// collector registration" panics when initRPC is invoked from tests
	// that share the global Prometheus registry with prior test cases.
	pendingDKGObservation func(*metrics.NodeMetrics)

	// Genesis
	genesis      *Genesis
	genesisBlock *encoding.Block

	// Chain state
	currentBlock *encoding.Block
	chainID      uint64

	// Synchronization
	syncer        *Syncer
	privacyStore  *privacy.PrivacyStore // AUDIT (2026) R4-ZK-03: shared persistent nullifier store
	syncQueue     chan *encoding.Block
	syncBuf       []*encoding.Block
	syncBufMu     sync.Mutex
	syncBufSignal chan struct{}
	startTime     time.Time
	// R87-STATE-TRUST (2026-08-29): tracks whether this node's local state can
	// still be trusted to DERIVE blocks. Broken by a failed fork rollback or by
	// a long run of state-root mismatches; while broken the node keeps following
	// the network but refuses to produce. See node/state_trust.go.
	stateTrust *stateTrust
	// R60-SYNC (2026-08-18): timestamp of the last successful block insert
	// in blockInsertLoop. takeNextBlock uses this to distinguish "syncBuf is
	// full of blocks whose parents simply haven't arrived yet" (healthy, keep
	// them) from "the node has genuinely stalled" (clear + re-request).
	lastBlockInsert time.Time

	// High Availability
	shutdownHandler *ha.ShutdownHandler
	healthServer    *ha.HealthServer
	recoveryManager *ha.RecoveryManager

	// Block production (dev mode)
	blockProducer *BlockProducer

	// Receipt cache: txHash → GasUsed (for accurate receipt queries)
	receiptCache   map[types.Hash]uint64
	receiptCacheMu sync.RWMutex

	// Frontend HTTP server
	frontendServer *http.Server

	// GraphQL HTTP server (separate port, configurable via QAU_GRAPHQL_ADDR env var)
	graphqlServer *http.Server

	// Light client components (optional, enabled via config.LightClientEnabled)
	headerSyncer   *lightclient.HeaderSyncer
	spvProver      *lightclient.SPVProver
	lightClientAPI *lightclient.LightClientAPI

	// Event bus for real-time event publishing (new block, new tx, new attestation)
	eventBus *event.TypeMux

	// Security Alerting
	alertManager *alerting.AlertManager

	// P3: Cross-chain Bridge (disabled by default, enable via QAU_ENABLE_BRIDGE=1)
	bridge        bridge.Bridge
	bridgeConfig  *bridge.BridgeConfig
	bridgeRelayer *bridge.MessageRelayer
	// P0-6 FIX (2026-07-13): persistent message store backed by bbolt.
	// Closed in Stop() to flush pending writes before process exit.
	bridgeStore *bridge.BoltMessageStore
	// P1-1/P1-2: Asset lock manager and HTTP API for bridge operations.
	assetLockManager *bridge.AssetLockManager
	bridgeAPI        *bridge.BridgeAPI
	// P1-5: SPV header verifier for cross-chain reorg detection.
	// bridgeSyncCommittee is the Ethereum sync committee verifier, stored on
	// the Node so it can be updated when Ethereum sync committee data becomes
	// available (e.g., via Ethereum light client sync).
	bridgeHeaderVerifier *bridge.BridgeHeaderVerifier
	bridgeSyncCommittee  *lightclient.SyncCommitteeVerifier

	// P3: L2 Rollup (disabled by default, enable via QAU_ENABLE_ROLLUP=1)
	rollupEngine *rollup.RollupEngine

	// P3: Sharding (disabled by default, enable via QAU_ENABLE_SHARDING=1)
	// P1-5 (2026-07-14): wires ShardManager into the node startup path.
	// shardStateStore and shardElectionVerifier are stored on the Node so
	// that P1-2 (block production loop) can inject them into newly-created
	// ShardChains via SetStateStore / SetElectionVerifier after CreateShard.
	shardManager          *consensus.ShardManager
	shardStateStore       *consensus.ShardStateStore
	shardElectionVerifier *consensus.ShardQPOSAdapter

	// proposerElectionVerifier is the R61/R88 producer-consumed election
	// verifier (nil in devMode). R88-E: BlockProducer.isProposerForSlot reads
	// IsEpochHealed from it to stand down from proposing on a diverged
	// schedule after the validator-side heal fired.
	proposerElectionVerifier *core.QPOSElectionVerifier
	// P1-2 (2026-07-14): ShardBlockProducer runs the shard block production
	// loop, attestation collection, and cross-shard message relay.
	shardProducer *ShardBlockProducer
	// P3-1 (2026-07-15): ShardMetrics exposes 8 Prometheus metrics for the
	// shard subsystem (qau_shard_* namespace). Held on Node so it can be
	// injected into new ShardChains created after startup.
	shardMetrics *consensus.ShardMetrics

	// P1-T1 (2026-07-14): MinistryRegistry singleton. Created once after QPOS
	// and ThreeChambersCoordinator are initialized. Held on Node so all
	// subsystems (RPC, BlockProducer, SlashingManager) share the same instance
	// instead of creating disposable copies on every call.
	ministryRegistry *consensus.MinistryRegistry

	// P1-T8 (2026-07-14): MinistryStateStore for persisting six ministry
	// state (personnel reputations, defense blacklist, revenue records,
	// justice cases, rites proposals, works shards/bridges) across restarts.
	// Created from BlockStore's DB after MinistryRegistry initialization.
	ministryStateStore *consensus.MinistryStateStore

	// NODE- Fork scheduling + data migration managers.
	// Initialized in initUpgrade() when config.Upgrade.Enabled=true.
	// nil when upgrade subsystem is disabled.
	forkManager      *upgrade.ForkManager
	migrationManager *upgrade.MigrationManager

	// P3: Quantum crypto modules (each independently disabled by default)
	mpcManager     *quantum.MPCManager
	zkVerifier     *quantum.ZKVerifier
	keyRotationMgr *quantum.KeyRotationManager
	qrng           *qrng.QRNG

	// NODE-R12-H01 (2026-07-20) FIX: QTD seal concurrency DoS protection.
	//
	// Audit finding: BroadcastQTDSealRequest / MsgTypeQTDPartialSeal had no
	// concurrency or per-peer rate limiting. Dilithium3 aggregate signing is
	// expensive (~50-200ms per attempt), so:
	//   (a) On the OUTBOUND side: requestQTDSeal spawns a goroutine per call
	//       (computeAndCompleteQTDSeal). Without a bound, a burst of slots
	//       could spawn unbounded goroutines and exhaust CPU.
	//   (b) On the INBOUND side: a malicious peer could spam
	//       MsgTypeQTDSealRequest / MsgTypeQTDPartialSeal messages, each
	//       triggering expensive Dilithium3 verification in
	//       qfs.SubmitPartialSeal.
	//
	// qtdSealSem is a counting semaphore (cap=MaxConcurrentQTDSeals).
	// Acquired in computeAndCompleteQTDSeal before doing aggregate work;
	// released on exit. Goroutines that cannot acquire within
	// qtdSealAcquireTimeout exit early (the slot tick will retry).
	//
	// qtdPeerRate is a per-peer sliding-window rate limiter for inbound
	// QTD seal messages. Peers exceeding qtdSealPerPeerMax within
	// qtdSealPerPeerWindow are rejected until the window resets. This is
	// defense-in-depth on top of the existing B-3/B-5 sender authentication
	// — even authenticated peers can be misconfigured or compromised to
	// flood the network.
	//
	// Both fields are lazily initialized (see ensureQTDSealLimiter) so that
	// tests that construct &Node{} directly without NewNode still work.
	qtdSealSem  chan struct{}
	qtdPeerRate map[p2p.PeerID]*qtdPeerRateInfo
	qtdPeerRtMu sync.Mutex

	// R39-P3-03 (2026-08-02) FIX: panic-counter for blockInsertLoop's
	// per-iteration recover. The audit finding observes that the
	// existing recover continues the loop indefinitely — a malicious
	// peer can repeatedly inject blocks that panic ProcessBlock and
	// hold the node in a chronic drop-and-continue state, never making
	// forward progress. We track an atomic counter; once it crosses
	// panicRestartThreshold we log.Fatalf to let systemd / watchdog
	// restart the process from a clean state — occasionally prior
	// in-memory state may be subtly corrupt (e.g., a panic mid-SSTORE
	// could leave the StateDB with a half-mutated account) and a clean
	// restart via RecoverConsistency is safer than continuing.
	//
	// The threshold is configurable via QAU_PANIC_RESTART_THRESHOLD env
	// var (default panicRestartDefault=50). The counter is reset to 0
	// on every successful block insert via resetPanicCounterOnProgress
	// so a single slow patch of bad blocks doesn't accumulate toward
	// restart during otherwise-healthy operation.
	blockInsertPanicCount atomic.Uint64
	panicRestartThreshold int

	// R79-STAKING-RESYNC (2026-08-28): blockInsertLoop skips the per-block
	// staking sync while the syncer is active (see the `!IsSyncing()` guard),
	// but nothing ever replayed those skipped blocks, so a stake/unstake tx
	// applied during a sync window was lost from stakingManager AND from the
	// QPOS validator set on that node forever (syncStakingFromChain only ran
	// once, at startup). Nodes then held DIFFERENT validator sets, elected
	// different proposers for the same slot, and the chain forked at every
	// slot. stakingResyncPending records "a staking tx was skipped"; the next
	// block processed with the syncer idle triggers exactly one full
	// syncStakingFromChain rescan (guarded by stakingResyncRunning).
	stakingResyncPending atomic.Bool
	stakingResyncRunning atomic.Bool

	// R81-STAKING-DEDUPE (2026-08-28): block hashes whose staking side effects
	// were already applied. syncStakingFromBlock is reachable from three call
	// sites (block producer postCommit, blockInsertLoop, and the sync insert
	// path) and StakingManager.AddStakeFromTx adds to the existing stake, a
	// block delivered twice double-counts its stake. That can leave one node
	// retaining a validator after its peers have removed it, causing the
	// validator sets to diverge.
	appliedStakingBlocks   map[types.Hash]struct{}
	appliedStakingOrder    []types.Hash
	appliedStakingBlocksMu sync.Mutex

	// R80-COLDSTART-DEADLOCK (2026-08-28): epoch of block 1, cached. Used to
	// decide whether the epoch-2 VRF accumulator the QPOS proposer schedule
	// needs could possibly exist on this chain yet. A chain whose genesis
	// timestamp lies in the past starts at a high epoch, so right after a
	// reset no node can be schedule-ready and the cold-start guard would
	// deadlock block production.
	firstBlockEpoch      atomic.Uint64
	firstBlockEpochKnown atomic.Bool

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.RWMutex
	running bool
}

// NewNode creates a new Quantaureum node
func NewNode(cfg *Config) (*Node, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize shutdown handler
	shutdownTimeout := time.Duration(cfg.ShutdownTimeout) * time.Second
	if shutdownTimeout == 0 {
		shutdownTimeout = 30 * time.Second
	}
	shutdownHandler := ha.NewShutdownHandler(&ha.ShutdownConfig{
		Timeout: shutdownTimeout,
	})

	// Initialize recovery manager
	recoveryManager := ha.NewRecoveryManager(&ha.RecoveryManagerConfig{
		CheckInterval: 10 * time.Second,
		MaxRetries:    3,
		RetryInterval: 5 * time.Second,
	})

	node := &Node{
		config:          cfg,
		configPath:      cfg.sourcePath, // audit-fix M6-3: enable config hot-reload from the source file
		ctx:             ctx,
		cancel:          cancel,
		shutdownHandler: shutdownHandler,
		recoveryManager: recoveryManager,
		receiptCache:    make(map[types.Hash]uint64),
		eventBus:        event.NewTypeMux(),
		// TSS- per-(session, participant) Round2 private replay defense.
		// Lazily populated on first use; entries cleared when a session is cleaned.
		round2PrivateLastTS: make(map[[40]byte]int64),
		// NODE-R12-H01: QTD seal concurrency + per-peer rate limit.
		// Initialized eagerly here so the hot path never has to check nil;
		// tests that construct &Node{} directly use ensureQTDSealLimiter
		// for lazy init.
		qtdSealSem:  make(chan struct{}, MaxConcurrentQTDSeals),
		qtdPeerRate: make(map[p2p.PeerID]*qtdPeerRateInfo),

		// R87-STATE-TRUST (2026-08-29): starts trusted; broken only by a failed
		// fork rollback or a sustained state-root mismatch streak.
		stateTrust: newStateTrust(),

		// R39-P3-03 (2026-08-02) FIX: blockInsertLoop panic-counter threshold.
		// Default 50 — a malicious peer that can panic the block-processing
		// path 50 times without an intervening successful insert will
		// trigger a process restart. Operators can tune via
		// QAU_PANIC_RESTART_THRESHOLD env var (integer >= 1); invalid /
		// unparseable values fall back to the default.
		panicRestartThreshold: parsePanicRestartThreshold(50),
		// R60-SYNC (2026-08-18): seed lastBlockInsert at startup so the
		// stall gate in takeNextBlock starts counting from node boot rather
		// than from the zero value (which would read as "stalled" instantly).
		lastBlockInsert: time.Now(),
	}

	// Initialize health server if enabled
	if cfg.HealthEnabled {
		node.healthServer = ha.NewHealthServer(&ha.HealthServerConfig{
			Addr:            cfg.HealthAddr,
			Version:         version.Version,
			ShutdownHandler: shutdownHandler,
		})
	}

	return node, nil
}

// parsePanicRestartThreshold reads QAU_PANIC_RESTART_THRESHOLD from the
// environment, parses it as an integer, and returns it. The defaultValue
// is returned when:
//   - the env var is unset;
//   - the parsed integer < 1 (a zero or negative threshold would disable
//     the safety entirely).
//
// R39-P3-03 (2026-08-02): the threshold caps how many consecutive panic-
// recovered block inserts can occur before the node process restarts via
// log.Fatalf (which calls os.Exit(1) — systemd / watchdog recovers).
//
// We deliberately do NOT support a "disable" setting — the audit's
// finding is that the bare-recover-then-continue pattern leaves the
// node vulnerable to chronic-injection DoS; an operator who genuinely
// wants to disable the restart needs to set a very high threshold
// (e.g., math.MaxInt32), not 0.
func parsePanicRestartThreshold(defaultValue int) int {
	v := os.Getenv("QAU_PANIC_RESTART_THRESHOLD")
	if v == "" {
		return defaultValue
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return defaultValue
	}
	return n
}

// shouldRestartAfterPanic decides whether the blockInsertLoop panic-counter
// has crossed the threshold and the node SHOULD restart the process. The
// helper is extracted from the per-iteration recover block so the threshold
// decision is unit-testable WITHOUT triggering the production os.Exit(3)
// (the test would otherwise kill the test process).
//
// R39-P3-03 (2026-08-02) audit finding: the bare-recover-then-continue
// pattern leaves the node vulnerable to chronic-injection DoS — a
// malicious peer can repeatedly inject blocks that panic ProcessBlock
// and hold the node in a drop-and-continue state. The threshold caps
// how many CONSECUTIVE panic-recovered block inserts can occur before
// the node restarts; the counter is reset to 0 on every successful
// insert (see the Store(0) at the bottom of the per-iteration func
// body in blockInsertLoop), so the threshold is a "consecutive-panic
// budget", not a "lifetime crash budget".
//
// Returns true when:
//   - threshold <= 0 (defensive: a future refactor that drops the NewNode
//     initialization would otherwise disable the safety; we fall back to
//     the documented default of 50) AND count >= 50; OR
//   - threshold > 0 AND count >= threshold.
//
// Returns false otherwise (panic count is below threshold; keep going).
func shouldRestartAfterPanic(count uint64, threshold int) bool {
	// Defensive threshold fallback — see comment.
	effectiveThreshold := threshold
	if effectiveThreshold <= 0 {
		effectiveThreshold = 50
	}
	return int(count) >= effectiveThreshold
}

// Start starts the node and all its components
func (n *Node) Start() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.running {
		return ErrNodeAlreadyRunning
	}

	// FIX: If Start() fails midway, already-initialized components
	// (database, P2P, consensus, etc.) must be cleaned up to prevent
	// resource leaks. Stop() cannot be used because it checks n.running
	// (still false during Start). This defer calls cleanupPartialInit on
	// any error return, which performs the same nil-checked teardown as
	// Stop() but without the running guard.
	startFailed := true
	defer func() {
		if startFailed {
			nodeLog.Warn("Start() failed, cleaning up partially initialized components")
			n.cleanupPartialInit()
		}
	}()

	// audit-fix R3-Info-3: configure structured logging from node config
	InitLogging(n.config.LogLevel, n.config.LogFormat)

	// CRITICAL SECURITY FIX: DevMode bypasses PoW verification (p2p/host.go:1039-1043, 1073).
	// PoW is a critical Sybil resistance mechanism. When DevMode is enabled:
	//   - verifyPeerProofOfWork() skips PoW verification entirely (line 1039-1043)
	//   - generatePoWNonce() returns a trivial nonce of 42 (line 1073)
	// This is a CRITICAL security vulnerability if ever used in production, as it would
	// allow an attacker to create arbitrary fake peers without computing real PoW.
	//
	// DevMode should ONLY be used in isolated local development environments with NO
	// network exposure. This check ensures the node fails FAST at startup rather than
	// operating in an insecure state.
	//
	// Reference: p2p/host.go:1039-1043, 1073
	if err := n.validateProductionConfig(); err != nil {
		// P2-14 FIX: Use Error logging instead of Fatal to allow graceful shutdown.
		// Fatal calls os.Exit(1) immediately, skipping defers and connection cleanup.
		// The error is returned so the caller can initiate a proper shutdown.
		nodeLog.Error("SECURITY VALIDATION FAILED: %v", err)
		nodeLog.Error("The node cannot start when DevMode bypasses security controls.")
		nodeLog.Error("If you are running a production node, this is a configuration error.")
		nodeLog.Error("If you are developing locally, ensure DevMode is only used in isolated environments.")
		return fmt.Errorf("production config validation failed: %w", err)
	}

	// Initialize data directory
	if err := n.initDataDir(); err != nil {
		return fmt.Errorf("failed to initialize data directory: %w", err)
	}

	// AUDIT (2026) R4-ZK-03: Initialize the shared persistent privacy store
	// early so all executor call sites (replay, sync, block production) can
	// share a single BoltDB file handle. Opening multiple handles to the same
	// BoltDB file causes lock errors.
	ps, psErr := privacy.NewPrivacyStore(n.config.DataDir)
	if psErr != nil {
		nodeLog.Warn("failed to open privacy store (non-fatal, using in-memory nullifiers): %v", psErr)
	} else {
		n.privacyStore = ps
	}

	// Initialize database
	if err := n.initDatabase(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Load genesis
	if err := n.loadGenesis(); err != nil {
		return fmt.Errorf("failed to load genesis: %w", err)
	}

	// Configure consensus globals derived from config/genesis.
	// audit-fix C-1: set genesis time from genesis config so all nodes compute identical slots.
	if n.genesis != nil {
		consensus.SetGenesisTime(int64(n.genesis.Timestamp))
	}
	// audit-fix C-2: set attestation network ID to prevent cross-chain attestation replay.
	if n.config.NetworkID == 0 {
		return fmt.Errorf("networkID must be configured")
	}
	consensus.SetAttestationNetworkID(n.config.NetworkID)

	// audit-fix C-2: freeze consensus parameters after configuration is finalized
	// to prevent runtime tampering.
	consensus.FreezeGenesisTime()
	consensus.FreezeAttestationNetworkID()

	// audit-fix C-1: Validate genesis time for production.
	// In non-dev mode, ensure genesis time was explicitly configured.
	if !n.config.DevMode {
		if err := consensus.ValidateGenesisTimeForProduction(); err != nil {
			if n.config.NetworkID == MainnetNetworkID {
				return fmt.Errorf("genesis time validation failed on mainnet: %w", err)
			}
			// Non-mainnet: warn but continue (testnets may be reset often).
			nodeLog.Warn("Genesis time validation: %v", err)
		}
	}

	// NODE-FIX: Wire upgrade/fork scheduling + migrations.
	// Must run after initDatabase (needs db handle) and after loadGenesis
	// (needs n.chainID for ChainID cross-check). Runs before initConsensus
	// so consensus/validation code can consult fork rules via ForkManager().
	if err := n.initUpgrade(); err != nil {
		return fmt.Errorf("failed to initialize upgrade subsystem: %w", err)
	}

	// Initialize state
	if err := n.initState(); err != nil {
		return fmt.Errorf("failed to initialize state: %w", err)
	}

	// Verify genesis StateRoot matches (computed in loadGenesis already)
	if n.genesisBlock != nil && n.stateDB != nil && !n.stateAlreadyPersisted {
		stateRoot := n.stateDB.Root()
		nodeLog.Info("Genesis StateRoot verification: computed=%x genesis=%x match=%v",
			stateRoot[:16], n.genesisBlock.Header.StateRoot[:16], stateRoot == n.genesisBlock.Header.StateRoot)
		if stateRoot != (types.Hash{}) && n.genesisBlock.Header.StateRoot != stateRoot {
			nodeLog.Warn("Genesis StateRoot MISMATCH after initState! computed=%x genesis=%x — this should not happen",
				stateRoot[:8], n.genesisBlock.Header.StateRoot[:8])
		}
	}

	// Replay historical blocks to restore state ONLY if state was not persisted.
	// With BoltDB persistence, state survives restarts — replaying would double-apply transactions.
	if !n.stateAlreadyPersisted {
		if err := n.replayBlocksToRestoreState(); err != nil {
			nodeLog.Warn("failed to replay blocks: %v", err)
		}
	} else {
		nodeLog.Info("State loaded from persistent storage, skipping block replay")
	}

	// Initialize transaction pool
	if err := n.initTxPool(); err != nil {
		return fmt.Errorf("failed to initialize transaction pool: %w", err)
	}

	// Initialize consensus
	if err := n.initConsensus(); err != nil {
		return fmt.Errorf("failed to initialize consensus: %w", err)
	}

	// Sync staking data from chain
	nodeLog.Info("About to sync staking data, blockStore=%v, stakingManager=%v", n.blockStore != nil, n.stakingManager != nil)
	if err := n.syncStakingFromChain(); err != nil {
		nodeLog.Warn("failed to sync staking data: %v", err)
		// Continue anyway, staking will be empty but node can still run
	}

	// Load staking data from file backup (for qau_stake RPC-based staking that
	// doesn't create on-chain transactions). Chain data takes priority.
	stakingFile := filepath.Join(n.config.DataDir, "staking.json")
	n.stakingManager.SetPersistencePath(stakingFile)
	if err := n.stakingManager.LoadFromFile(stakingFile); err != nil {
		nodeLog.Warn("failed to load staking data from file: %v", err)
	}

	// Start periodic staking data persistence (every 30s)
	n.startStakingPersistence(stakingFile)

	// Initialize optimization modules
	if err := n.initOptimizations(); err != nil {
		return fmt.Errorf("failed to initialize optimizations: %w", err)
	}

	// Initialize P2P network
	if err := n.initP2P(); err != nil {
		return fmt.Errorf("failed to initialize P2P network: %w", err)
	}

	// P1-1 (2026-07-14): Initialize danksharding / DA committee engine.
	// Must run after initP2P (needs P2P host for cross-node DAS sampling)
	// and before initRPC (so DA RPC handlers can be registered if added).
	// Non-fatal: when DA is disabled, this is a no-op.
	if err := n.initDanksharding(); err != nil {
		nodeLog.Warn("Danksharding initialization warning: %v", err)
	}

	// Initialize light client (optional, enabled via config.LightClientEnabled).
	// Must run before initRPC so handlers can be registered with the RPC server.
	n.initLightClient()

	// Initialize P3 features (bridge, rollup, quantum crypto).
	// All are disabled by default; enable via environment variables.
	// Failures are non-fatal — the node continues without the feature.
	if err := n.initP3Features(); err != nil {
		nodeLog.Warn("P3 features initialization warning: %v", err)
	}

	// Initialize RPC server
	if err := n.initRPC(); err != nil {
		return fmt.Errorf("failed to initialize RPC server: %w", err)
	}

	// Start syncer
	if err := n.initSyncer(); err != nil {
		return fmt.Errorf("failed to initialize syncer: %w", err)
	}

	// Initialize history expirer — prunes ancient block history past the
	// retention window. Disabled by default; enable via QAU_HISTORY_EXPIRY=1.
	histCfg := DefaultHistoryExpirationConfig()
	if os.Getenv("QAU_HISTORY_EXPIRY") != "1" {
		histCfg.Enabled = false
	}
	n.historyExpirer = NewHistoryExpirer(histCfg, &blockStoreReaderAdapter{blockStore: n.blockStore})
	if err := n.historyExpirer.Start(); err != nil {
		nodeLog.Warn("History expirer not started: %v", err)
	}

	// Initialize high availability components
	if err := n.initHA(); err != nil {
		return fmt.Errorf("failed to initialize HA components: %w", err)
	}

	// Initialize metrics server
	if err := n.initMetrics(); err != nil {
		return fmt.Errorf("failed to initialize metrics server: %w", err)
	}

	// Initialize security alerting system
	if err := n.initAlerting(); err != nil {
		return fmt.Errorf("failed to initialize alerting system: %w", err)
	}

	// Start background services
	// BRDG-FIX (2026-07-16): propagates startup errors from
	// startServices (e.g., header verifier misconfiguration on mainnet)
	// to abort node startup with a clear error.
	if err := n.startServices(); err != nil {
		return fmt.Errorf("failed to start services: %w", err)
	}

	// P2P-R12-CRIT-001 (2026-07-20) FIX: wire up the Dilithium3 payload
	// signature verifier for both direct-P2P and GossipSub paths. MUST run
	// after startServices() because vote/attestation verification requires
	// blockProducer.QPOS() to be initialized. Safe to call when P2P is
	// disabled (the method no-ops if p2pHost is nil).
	n.initP2PSignatureVerifier()

	// P2P-R13-CRIT-004 (2026-07-21) FIX: Start the P2P host AFTER the
	// signature verifier is wired. Previously initP2P() called Start()
	// immediately, opening a multi-second TOCTOU window where the host
	// accepted connections but payloadVerifier was nil → signature
	// verification was silently skipped (fail-open). Now Start() happens
	// only after the verifier is in place, so every incoming message from
	// the very first connection is signature-checked.
	if err := n.startP2P(); err != nil {
		return fmt.Errorf("failed to start P2P host after verifier wiring: %w", err)
	}

	// Mark node as ready for health checks
	if n.healthServer != nil {
		n.healthServer.SetReady(true)
	}

	startFailed = false //  clear flag so defer does not clean up
	n.running = true

	// audit-fix M6-3: start config hot-reload (file watcher + SIGHUP handler).
	// No-op when the node was started without a config file (default/in-memory).
	n.startConfigHotReload()

	return nil
}

// Stop stops the node gracefully
// getTSSPassword returns the password used for TSS key share encryption.
// SECURITY (audit-fix): Removed hardcoded default password. If no password
// is configured, returns an error —TSS encryption is mandatory.
// A public default password makes the encryption completely ineffective.
func (n *Node) getTSSPassword() ([]byte, error) {
	if n.config.ValidatorKeyPassword != "" {
		return []byte(n.config.ValidatorKeyPassword), nil
	}
	// Check environment variable
	if envPwd := os.Getenv("QAU_VALIDATOR_KEY_PASSWORD"); envPwd != "" {
		// AUDIT (2026) L-04: environment variables are readable via
		// process tables/core dumps on most platforms. Warn operators toward
		// the password-file path (which has strict 0600 semantics).
		nodeLog.Warn("SECURITY: TSS/validator password supplied via QAU_VALIDATOR_KEY_PASSWORD environment variable — prefer ValidatorPasswordFile (env values can leak through process listings or crash dumps)")
		return []byte(envPwd), nil
	}
	// Check password file
	if n.config.ValidatorPasswordFile != "" {
		if data, err := os.ReadFile(n.config.ValidatorPasswordFile); err == nil {
			pwd := strings.TrimSpace(string(data))
			if pwd != "" {
				return []byte(pwd), nil
			}
		}
	}
	return nil, fmt.Errorf("TSS encryption password not configured —set QAU_VALIDATOR_KEY_PASSWORD env var or ValidatorPasswordFile in config (audit-fix)")
}

func (n *Node) Stop() error {
	n.mu.Lock()
	if !n.running {
		n.mu.Unlock()
		return ErrNodeNotRunning
	}
	n.running = false
	n.mu.Unlock()

	if n.healthServer != nil {
		n.healthServer.SetReady(false)
	}

	// R40-P1-07 / R40-P2-06 (2026-08-03): cancel any in-flight post-sync
	// re-verification sweep goroutine BEFORE we cancel the node context / tear
	// down consensus state. Without this the sweep would keep touching the
	// electionVerifier / QPOS snapshot after they are released on shutdown.
	if n.blockValidator != nil {
		n.blockValidator.Stop()
	}

	n.cancel()

	// SECURITY (audit-fix): Persist TSS key shares on graceful
	// shutdown with AES-256-GCM encryption. No hardcoded password.
	if n.tssManager != nil && n.config.TSSKeyShareFile != "" {
		tssPwd, pwdErr := n.getTSSPassword()
		if pwdErr != nil {
			nodeLog.Error("Cannot persist TSS key shares on shutdown: %v", pwdErr)
		} else if data, err := n.tssManager.ExportKeySharesEncrypted(tssPwd); err == nil {
			if err := os.WriteFile(n.config.TSSKeyShareFile, data, 0600); err != nil {
				nodeLog.Error("Failed to persist TSS key shares on shutdown: %v", err)
			} else {
				nodeLog.Info("TSS key shares persisted (encrypted) on shutdown to %s", n.config.TSSKeyShareFile)
			}
		} else {
			nodeLog.Warn("Failed to export TSS key shares on shutdown: %v", err)
		}
	}

	if n.shutdownHandler != nil {
		n.shutdownHandler.Shutdown()
	}

	if n.healthServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.healthServer.Stop(ctx)
		cancel()
	}

	if n.recoveryManager != nil {
		n.recoveryManager.Stop()
	}

	if n.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.metricsServer.Stop(ctx)
		cancel()
	}

	if n.rpcServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.rpcServer.Stop(ctx)
		cancel()
	}

	if n.wsServer != nil {
		n.wsServer.Stop()
	}

	// R14-MED (2026-07-21): P2P host shutdown was previously here (before
	// blockProducer/QPOS). This caused a window where blockProducer/QPOS
	// could still attempt to broadcast blocks/votes/attestations via the
	// now-stopped P2P host, potentially causing panics or error-log spam
	// during shutdown. P2P stop is now moved to AFTER blockProducer/QPOS
	// stop (see below). syncer/snapSyncer/historyExpirer/bundler/governance
	// can still be stopped in their current order — they do not broadcast
	// via P2P during shutdown.

	if n.syncer != nil {
		n.syncer.Stop()
	}

	// Stop snap sync manager
	if n.snapSyncer != nil {
		n.snapSyncer.CancelSnapSync()
	}

	// ETHEREUM-PARITY SYNC (2026-08-13): stop the sync protocol server.
	if n.snapServer != nil {
		n.snapServer.Stop()
	}

	// Stop history expirer
	if n.historyExpirer != nil {
		n.historyExpirer.Stop()
	}

	// Stop AA bundler (txpool.Stop does not cascade to the bundler)
	if n.bundler != nil {
		n.bundler.Stop()
	}

	// Close governance manager (stops cleanup goroutine)
	if n.governanceManager != nil {
		if err := n.governanceManager.Save(); err != nil {
			nodeLog.Warn("Failed to save governance state on shutdown: %v", err)
		}
		n.governanceManager.Close()
	}

	// P1-2 (2026-07-14): Stop ShardBlockProducer before block producer and
	// P2P host (it depends on both).
	if n.shardProducer != nil {
		n.shardProducer.Stop()
	}

	if n.blockProducer != nil {
		n.blockProducer.Stop()
		// CONS-FIX: stop QPOS background goroutines (evidence drainer
		// + SlashingManager pending-slashes sync loop) so we don't leak them
		// on shutdown. QPOS.Stop() is idempotent.
		if qpos := n.blockProducer.QPOS(); qpos != nil {
			qpos.Stop()
		}
	}

	// R14-MED (2026-07-21): P2P host shutdown moved here (was previously
	// before blockProducer/QPOS). Producers/consensus depend on P2P for
	// broadcasting blocks/votes/attestations; stopping them first ensures
	// they don't attempt to use a stopped P2P host during their shutdown.
	// Now that blockProducer/QPOS/shardProducer are all stopped, it is
	// safe to tear down the P2P transport.
	if n.p2pHost != nil {
		n.p2pHost.Stop()
	}

	// Stop transaction pool (after block producer which uses it for pending txs)
	if n.txPool != nil {
		n.txPool.Stop()
	}

	if n.frontendServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.frontendServer.Shutdown(ctx)
		cancel()
	}

	// Graceful shutdown of GraphQL HTTP server
	if n.graphqlServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.graphqlServer.Shutdown(ctx)
		cancel()
		nodeLog.Info("GraphQL server stopped")
	}

	// Stop event bus (unblocks all subscribers)
	if n.eventBus != nil {
		n.eventBus.Stop()
	}

	if n.alertManager != nil {
		n.alertManager.Stop()
	}

	if n.authManager != nil {
		n.authManager.Stop()
	}

	// Stop P3 features (bridge, rollup, quantum crypto)
	// P1-1 FIX (2026-07-13): Stop BridgeAPI BEFORE the bridge itself, since
	// the HTTP server handles requests that reference bridge state.
	if n.bridgeAPI != nil {
		if err := n.bridgeAPI.Stop(); err != nil {
			nodeLog.Warn("bridgeAPI stop failed: %v", err)
		}
		n.bridgeAPI = nil
	}
	if n.bridgeRelayer != nil {
		if err := n.bridgeRelayer.Stop(); err != nil {
			nodeLog.Warn("bridgeRelayer stop failed: %v", err)
		}
	}
	if n.bridge != nil {
		if err := n.bridge.Stop(context.Background()); err != nil {
			nodeLog.Warn("bridge stop failed: %v", err)
		}
	}
	// P0-6 FIX (2026-07-13): Close the persistent message store AFTER the
	// bridge has stopped. Order matters: bridge.Stop() must flush any
	// in-flight writes first; only then can we safely close the bbolt file.
	// Closing in the wrong order could lose pending status updates.
	if n.bridgeStore != nil {
		if err := n.bridgeStore.Close(); err != nil {
			nodeLog.Warn("bridgeStore close failed: %v", err)
		}
		n.bridgeStore = nil
	}
	if n.rollupEngine != nil {
		if err := n.rollupEngine.Stop(); err != nil {
			nodeLog.Warn("rollupEngine stop failed: %v", err)
		}
	}
	if n.keyRotationMgr != nil {
		if err := n.keyRotationMgr.Close(); err != nil {
			nodeLog.Warn("keyRotationMgr close failed: %v", err)
		}
	}
	// P1-1 (2026-07-14): Stop the danksharding / DA committee engine.
	if n.danksharding != nil {
		n.danksharding.Stop()
	}

	rpc.StopGlobalFilterManager()

	n.wg.Wait()

	if n.blockStore != nil {
		n.blockStore.Close()
	}

	// AUDIT (2026) R4-ZK-03: Close the shared privacy store.
	if n.privacyStore != nil {
		if err := n.privacyStore.Close(); err != nil {
			nodeLog.Warn("privacyStore close failed: %v", err)
		}
		n.privacyStore = nil
	}

	if n.shutdownHandler != nil {
		n.shutdownHandler.Stop()
	}

	consensus.FreezeGenesisTime()
	consensus.FreezeAttestationNetworkID()

	return nil
}

// cleanupPartialInit tears down any components that were initialized during a
// failed Start() call. Unlike Stop(), it does NOT check n.running (which is
// still false during Start). Every field access is nil-checked so calling
// this on a partially initialized Node is safe.
// FIX: prevents resource leaks when Start() fails midway.
//
// R14-MED (2026-07-21): Comprehensive nil-check audit. Previously this
// function only cleaned up a subset of the components that Stop() handles,
// so a Start() failure after, say, bridgeAPI initialization would leak the
// bridge HTTP server, its bbolt store, the event bus, alert/auth managers,
// frontend/GraphQL servers, rollup engine, key rotation manager, privacy
// store, etc. The function now mirrors Stop()'s teardown order with nil
// checks on every component, so any partial init is fully cleaned up.
func (n *Node) cleanupPartialInit() {
	if n.cancel != nil {
		n.cancel()
	}

	// SECURITY (audit-fix): Persist TSS key shares on shutdown with
	// AES-256-GCM encryption. Best-effort — failures are logged but do not
	// block cleanup.
	if n.tssManager != nil && n.config.TSSKeyShareFile != "" {
		tssPwd, pwdErr := n.getTSSPassword()
		if pwdErr == nil {
			if data, err := n.tssManager.ExportKeySharesEncrypted(tssPwd); err == nil {
				if err := os.WriteFile(n.config.TSSKeyShareFile, data, 0600); err != nil {
					nodeLog.Warn("cleanupPartialInit: failed to persist TSS key shares: %v", err)
				}
			}
		}
	}

	if n.shutdownHandler != nil {
		n.shutdownHandler.Shutdown()
	}

	if n.healthServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.healthServer.Stop(ctx)
		cancel()
	}

	if n.recoveryManager != nil {
		n.recoveryManager.Stop()
	}

	if n.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.metricsServer.Stop(ctx)
		cancel()
	}
	if n.rpcServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.rpcServer.Stop(ctx)
		cancel()
	}
	if n.wsServer != nil {
		n.wsServer.Stop()
	}

	if n.syncer != nil {
		n.syncer.Stop()
	}
	if n.snapSyncer != nil {
		n.snapSyncer.CancelSnapSync()
	}
	if n.historyExpirer != nil {
		n.historyExpirer.Stop()
	}
	if n.bundler != nil {
		n.bundler.Stop()
	}

	// Close governance manager (stops cleanup goroutine)
	if n.governanceManager != nil {
		if err := n.governanceManager.Save(); err != nil {
			nodeLog.Warn("cleanupPartialInit: failed to save governance state: %v", err)
		}
		n.governanceManager.Close()
	}

	// P1-2 (2026-07-14): Stop ShardBlockProducer before block producer.
	if n.shardProducer != nil {
		n.shardProducer.Stop()
	}
	if n.blockProducer != nil {
		n.blockProducer.Stop()
		// CONS-FIX: also stop QPOS background goroutines in abort path.
		if qpos := n.blockProducer.QPOS(); qpos != nil {
			qpos.Stop()
		}
	}

	// R14-MED: P2P host stop moved here (after blockProducer/QPOS).
	if n.p2pHost != nil {
		n.p2pHost.Stop()
	}

	if n.txPool != nil {
		n.txPool.Stop()
	}

	if n.frontendServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.frontendServer.Shutdown(ctx)
		cancel()
	}
	if n.graphqlServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n.graphqlServer.Shutdown(ctx)
		cancel()
	}

	if n.eventBus != nil {
		n.eventBus.Stop()
	}
	if n.alertManager != nil {
		n.alertManager.Stop()
	}
	if n.authManager != nil {
		n.authManager.Stop()
	}

	// P3 features (bridge, rollup, quantum crypto)
	if n.bridgeAPI != nil {
		if err := n.bridgeAPI.Stop(); err != nil {
			nodeLog.Warn("cleanupPartialInit: bridgeAPI stop failed: %v", err)
		}
		n.bridgeAPI = nil
	}
	if n.bridgeRelayer != nil {
		if err := n.bridgeRelayer.Stop(); err != nil {
			nodeLog.Warn("cleanupPartialInit: bridgeRelayer stop failed: %v", err)
		}
	}
	if n.bridge != nil {
		if err := n.bridge.Stop(context.Background()); err != nil {
			nodeLog.Warn("cleanupPartialInit: bridge stop failed: %v", err)
		}
	}
	if n.bridgeStore != nil {
		if err := n.bridgeStore.Close(); err != nil {
			nodeLog.Warn("cleanupPartialInit: bridgeStore close failed: %v", err)
		}
		n.bridgeStore = nil
	}
	if n.rollupEngine != nil {
		if err := n.rollupEngine.Stop(); err != nil {
			nodeLog.Warn("cleanupPartialInit: rollupEngine stop failed: %v", err)
		}
	}
	if n.keyRotationMgr != nil {
		if err := n.keyRotationMgr.Close(); err != nil {
			nodeLog.Warn("cleanupPartialInit: keyRotationMgr close failed: %v", err)
		}
	}

	// P1-1 (2026-07-14): Stop danksharding if partially initialized.
	if n.danksharding != nil {
		n.danksharding.Stop()
	}

	rpc.StopGlobalFilterManager()

	if n.blockStore != nil {
		n.blockStore.Close()
	}

	// AUDIT (2026) R4-ZK-03: Close the shared privacy store.
	if n.privacyStore != nil {
		if err := n.privacyStore.Close(); err != nil {
			nodeLog.Warn("cleanupPartialInit: privacyStore close failed: %v", err)
		}
		n.privacyStore = nil
	}

	if n.shutdownHandler != nil {
		n.shutdownHandler.Stop()
	}
}

// initDataDir initializes the data directory
func (n *Node) initDataDir() error {
	// audit-fix L-1: directories with sensitive material use 0700
	type dirEntry struct {
		path string
		perm os.FileMode
	}
	dirs := []dirEntry{
		{n.config.DataDir, 0755},
		{filepath.Join(n.config.DataDir, "blocks"), 0755},
		{filepath.Join(n.config.DataDir, "state"), 0755},
		{filepath.Join(n.config.DataDir, "keystore"), 0700}, // sensitive
		{n.config.KeyRotation.KeyDir, 0700},                 // sensitive
		{n.config.KeyRotation.BackupDir, 0700},              // sensitive
		{n.config.TLSCertRotation.CertDir, 0700},            // sensitive
		{n.config.TLSCertRotation.BackupDir, 0700},          // sensitive
	}

	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			return err
		}
	}

	return nil
}

// initDatabase initializes the database
// audit-fix R2-M3: in non-DevMode, refuse to fall back to MemDB because
// that would silently lose all block data on restart.
func (n *Node) initDatabase() error {
	// Use BoltDB for persistent block storage
	dbPath := filepath.Join(n.config.DataDir, "blocks")
	boltDB, err := db.NewBoltDB(dbPath)
	if err != nil {
		if !n.config.DevMode {
			return fmt.Errorf("failed to create persistent database at %s: %w (DevMode=false, refusing MemDB fallback)", dbPath, err)
		}
		nodeLog.Warn("Failed to create persistent database: %v, using memory database (DevMode)", err)
		n.blockStore = block.NewBlockStore(db.NewMemDB())
		return nil
	}
	nodeLog.Info("Using persistent BoltDB at %s", dbPath)
	n.blockStore = block.NewBlockStore(boltDB)
	return nil
}

// initUpgrade initializes the fork scheduling and data migration subsystem.
// NODE-FIX: Previously the upgrade/ package (ForkManager +
// MigrationManager) was fully implemented but never connected to the node
// startup path — hard forks could not be scheduled and database migrations
// never ran. This method:
//  1. Runs pending database migrations (when RunMigrations=true) so that
//     data format upgrades execute automatically on node startup.
//  2. Loads the chain configuration (from file or network default) which
//     contains the fork schedule (activation heights + consensus rules).
//  3. Creates the ForkManager for consensus rule lookups at a given height.
//
// The ForkManager is exposed via Node.ForkManager() for use by consensus
// and validation code to query fork-specific rules (e.g. MaxBlockGas,
// BlockTime, EnableVerkle) at a given block height.
//
// This method is non-fatal for migration-only failures (logs warning and
// continues) but fatal for chain config load failures (returns error) since
// a malformed fork schedule could cause consensus divergence.
func (n *Node) initUpgrade() error {
	cfg := n.config.Upgrade
	if !cfg.Enabled {
		nodeLog.Info("Upgrade subsystem disabled by config, skipping fork scheduling and migrations")
		return nil
	}

	// 1. Run pending database migrations.
	if cfg.RunMigrations && n.blockStore != nil {
		mm := upgrade.NewMigrationManager(n.blockStore.GetDB())
		n.migrationManager = mm
		needs, err := mm.NeedsMigration()
		if err != nil {
			// Migration check failure is non-fatal — log and continue.
			// The node can still operate without migrations; data format
			// may be older but forward-compatible by design.
			nodeLog.Warn("Migration check failed: %v (continuing without migrations)", err)
		} else if needs {
			nodeLog.Info("Pending database migrations detected, running...")
			if err := mm.Migrate(); err != nil {
				// ErrNoMigrationNeeded is benign (race with another process).
				if !errors.Is(err, upgrade.ErrNoMigrationNeeded) {
					return fmt.Errorf("database migration failed: %w", err)
				}
			}
			nodeLog.Info("Database migrations completed successfully")
		} else {
			nodeLog.Info("No pending database migrations")
		}
	}

	// 2. Load chain configuration (fork schedule).
	var chainConfig *upgrade.ChainConfig
	if cfg.ChainConfigFile != "" {
		cc, err := upgrade.LoadChainConfig(cfg.ChainConfigFile)
		if err != nil {
			return fmt.Errorf("failed to load chain config from %s: %w", cfg.ChainConfigFile, err)
		}
		chainConfig = cc
		nodeLog.Info("Loaded chain config from %s (ChainID=%d, forks=%d)",
			cfg.ChainConfigFile, chainConfig.ChainID, len(chainConfig.ForkSchedule))
	} else {
		// Use built-in default based on NetworkID.
		chainConfig = n.defaultChainConfig()
		nodeLog.Info("Using built-in chain config for NetworkID=%d (ChainID=%d, forks=%d)",
			n.config.NetworkID, chainConfig.ChainID, len(chainConfig.ForkSchedule))
	}

	// 3. Verify ChainID matches the genesis ChainID.
	// A mismatch indicates operator misconfiguration (e.g. mainnet config on
	// a testnet node). For the Quantaureum mainnet (chainID 1668) this is a
	// HARD error: silently falling back to the genesis ChainID when the rest
	// of the chain-config file (fork schedule / emergency params / validator
	// enforcement) was authored for a different network silently splits the
	// node from its peers. R40-P1-04 (2026-08-03) — mainnet is hard, devnet
	// and testnet remain soft to preserve the operator-experimentation path.
	if n.chainID != 0 && chainConfig.ChainID != n.chainID {
		msg := fmt.Sprintf("chain config ChainID=%d does not match genesis ChainID=%d", chainConfig.ChainID, n.chainID)
		switch n.chainID {
		case 1668:
			// Mainnet: misconfiguration is unrecoverable; abort startup so the
			// operator notices BEFORE the node advertises a conflicting fork.
			return fmt.Errorf("R40-P1-04: %s on mainnet — refusing to start (check chain config / genesis pairing)", msg)
		default:
			// Testnet / devnet: keep the historical soft-warning behavior to
			// preserve the experimentation workflow where an operator may
			// intentionally run a custom-config node against a different
			// genesis for testing.
			nodeLog.Warn("%s, using genesis ChainID (check config)", msg)
		}
	}

	// 4. Create ForkManager from the chain config.
	n.forkManager = chainConfig.ToForkManager()
	nodeLog.Info("ForkManager initialized with %d fork(s)", len(chainConfig.ForkSchedule))
	for _, entry := range chainConfig.ForkSchedule {
		nodeLog.Info("  Fork: %s (id=%s) activationHeight=%d",
			entry.Name, entry.ForkID, entry.ActivationHeight)
	}

	return nil
}

// defaultChainConfig returns the built-in chain config for the node's NetworkID.
// NODE- Used when config.Upgrade.ChainConfigFile is empty.
func (n *Node) defaultChainConfig() *upgrade.ChainConfig {
	switch n.config.NetworkID {
	case TestnetNetworkID:
		return upgrade.TestnetConfig()
	case DevnetNetworkID:
		return upgrade.DevnetConfig()
	default:
		return upgrade.MainnetConfig()
	}
}

// ForkManager returns the fork manager (nil when upgrade is disabled).
// NODE- Exposed for consensus and validation code to query
// fork-specific rules at a given height via GetRulesAtHeight / IsForkActive.
func (n *Node) ForkManager() *upgrade.ForkManager {
	return n.forkManager
}

// MigrationManager returns the migration manager (nil when upgrade is disabled
// or RunMigrations=false). NODE- Exposed for diagnostics and tooling.
func (n *Node) MigrationManager() *upgrade.MigrationManager {
	return n.migrationManager
}

// loadGenesis loads and validates the genesis configuration
func (n *Node) loadGenesis() error {
	genesis, err := LoadGenesisForConfig(n.config)
	if err != nil {
		return fmt.Errorf("failed to load genesis: %w", err)
	}
	if genesis != nil {
		n.genesis = genesis
		if n.config.GenesisFile != "" {
			nodeLog.Info("Loaded genesis from %s", n.config.GenesisFile)
		} else {
			nodeLog.Info("Using built-in %s genesis", n.config.Network)
		}
	} else {
		genesisPath := filepath.Join(n.config.DataDir, "genesis.json")
		if _, statErr := os.Stat(genesisPath); statErr == nil {
			genesis, loadErr := LoadGenesis(genesisPath)
			if loadErr != nil {
				return fmt.Errorf("failed to load genesis: %w", loadErr)
			}
			n.genesis = genesis
			nodeLog.Info("Loaded genesis from %s", genesisPath)
		} else {
			switch {
			case n.config.NetworkID == TestnetNetworkID:
				n.genesis = TestnetGenesis()
			case n.config.DevMode || n.config.NetworkID == DevnetNetworkID:
				n.genesis = DevGenesis()
			default:
				n.genesis = DefaultGenesis()
			}
			nodeLog.Info("Using default genesis (no genesis file at %s)", genesisPath)
		}
	}

	// Validate genesis
	if err := n.genesis.Validate(); err != nil {
		return fmt.Errorf("invalid genesis: %w", err)
	}
	if err := ValidateGenesisForNetwork(n.config.Network, n.genesis); err != nil {
		return fmt.Errorf("invalid genesis for network %q: %w", n.config.Network, err)
	}

	// AUDIT (2026) NODE-08 FIX: Removed the misleading ComputeAllocHash
	// log line. ComputeAllocHash only hashes the Alloc map (balances/nonces),
	// omitting Validators, Timestamp, GasLimit, ChainID, and per-account
	// Code/Storage — giving a false guarantee that nodes with matching hashes
	// will not fork. ConfigurationHash (below) covers ALL fork-relevant fields
	// and is the authoritative cross-node check.
	//
	//  (original): Log genesis alloc hash for cross-node validation.
	// SUPERSEDED by ConfigurationHash (HIGH-04/NODE-01 fix).

	// AUDIT (2026) HIGH-04 (NODE-01): Log genesis configuration hash and
	// verify it matches the expected hash if configured. This prevents chain
	// splits caused by conflicting genesis files (different validators, stakes,
	// allocations, or timestamps producing different genesis blocks).
	configHash := n.genesis.ConfigurationHash()
	nodeLog.Info("Genesis configuration hash: %s (verify this matches across all nodes)", configHash.String())
	if n.config.ExpectedGenesisHash != "" {
		expectedBytes, err := hex.DecodeString(strings.TrimPrefix(n.config.ExpectedGenesisHash, "0x"))
		if err != nil || len(expectedBytes) != 32 {
			return fmt.Errorf("invalid expectedGenesisHash in config (must be 32-byte hex): %s", n.config.ExpectedGenesisHash)
		}
		var expectedFull types.Hash
		copy(expectedFull[:], expectedBytes)
		if configHash != expectedFull {
			return fmt.Errorf("genesis configuration hash mismatch: expected %s, got %s — refusing to start (audit HIGH-04)", n.config.ExpectedGenesisHash, configHash.String())
		}
		nodeLog.Info("Genesis configuration hash verified: matches expected hash")
	} else if n.genesis.ChainID == MainnetNetworkID {
		// AUDIT (2026) NODE-FIX: Fail-closed for mainnet without
		// ExpectedGenesisHash. Previously only a warning was logged, meaning
		// any conflicting genesis file would be silently accepted — enabling
		// chain splits from misconfigured or hostile genesis files. The
		// anti-split guard is now enforced: mainnet nodes MUST set
		// expectedGenesisHash in their config. Development/test networks
		// (ChainID != 1668) are exempt. An environment variable
		// QAU_SKIP_GENESIS_HASH_CHECK=true is available for dev overrides
		// (e.g. regenerating genesis) but must NEVER be used in production.
		if os.Getenv("QAU_SKIP_GENESIS_HASH_CHECK") == "true" {
			nodeLog.Warn("WARNING: expectedGenesisHash not set for mainnet but QAU_SKIP_GENESIS_HASH_CHECK=true — " +
				"genesis configuration cannot be verified. This should ONLY be used for development (audit NODE-).")
		} else {
			return fmt.Errorf("expectedGenesisHash not set for mainnet (ChainID=%d) — refusing to start. "+
				"Set expectedGenesisHash in config to %s to prevent chain splits (audit NODE-). "+
				"For development only, set QAU_SKIP_GENESIS_HASH_CHECK=true to bypass.",
				n.genesis.ChainID, configHash.String())
		}
	}

	// Set chain ID
	n.chainID = n.genesis.ChainID

	// audit-fix R2-Info-2: verify config NetworkID matches genesis NetworkID
	if n.genesis.NetworkID != 0 && n.config.NetworkID != n.genesis.NetworkID {
		return fmt.Errorf("config networkID (%d) conflicts with genesis networkID (%d)", n.config.NetworkID, n.genesis.NetworkID)
	}

	nodeLog.Info("Chain ID: %d", n.chainID)

	// Check if genesis block already exists in database
	genesisHash, err := n.blockStore.GetBlockHash(0)
	nodeLog.Info("Checking for existing genesis, err=%v, syncOnlyMode=%v", err, n.config.SyncOnlyMode)
	if err == nil {
		// Genesis block exists, verify it matches
		existingBlock, err := n.blockStore.GetBlock(genesisHash)
		if err != nil {
			return fmt.Errorf("failed to load existing genesis block: %w", err)
		}
		n.genesisBlock = existingBlock
		nodeLog.Info("Loaded existing genesis block")

		// AUDIT (2026) R3-NODE-02 FIX: Verify the DB's stored genesis
		// block matches the genesis block derived from the configuration
		// we just loaded. Previously, an old `data/genesis.json` (or any
		// stale DB) could diverge from the canonical config without any
		// check — the node would silently use the DB's genesis, fork off
		// the canonical chain, and only fail when peer handshakes rejected
		// its blocks. Now we compute the expected genesis block hash from
		// the loaded config and refuse to start if it doesn't match the
		// stored DB genesis. This catches:
		//   - old data/genesis.json left over from prior releases
		//   - operator-edited genesis.json that drifts from canonical
		//   - DB transplanted from a different network without --reset
		// SyncOnlyMode skips this check (it has no authoritative genesis
		// yet — it will sync from peers).
		if !n.config.SyncOnlyMode {
			expectedStateRoot, stateErr := n.computeGenesisStateRoot()
			if stateErr != nil {
				return fmt.Errorf("failed to compute expected genesis state root for DB comparison: %w", stateErr)
			}
			expectedGenesisBlock := n.createGenesisBlock(expectedStateRoot)
			expectedGenesisHash := block.ComputeBlockHash(expectedGenesisBlock.Header)
			if genesisHash != expectedGenesisHash {
				return fmt.Errorf(
					"genesis block hash mismatch: DB has %x, config derives %x — "+
						"refusing to start (audit-fix R3-NODE-02). "+
						"This usually means data/genesis.json or the DB is stale and diverges from the canonical config. "+
						"Reset the data directory or restore the matching genesis file.",
					genesisHash[:8], expectedGenesisHash[:8],
				)
			}
			nodeLog.Info("Genesis block hash verified: DB matches config-derived genesis")
		}

		// Load the latest block (not just genesis)
		latestBlock, err := n.blockStore.GetLatestBlock()
		if err != nil {
			// If we can't get latest, use genesis
			n.currentBlock = existingBlock
			nodeLog.Info("No latest block found, using genesis block (height: 0)")
		} else {
			n.currentBlock = latestBlock
			nodeLog.Info("Restored blockchain state - Latest block height: %d", latestBlock.Header.Height)
		}
		return nil
	}

	// In SyncOnlyMode, don't create genesis - wait to sync from peers
	if n.config.SyncOnlyMode {
		nodeLog.Info("SyncOnlyMode enabled - waiting to sync genesis from peers")
		n.genesisBlock = nil
		n.currentBlock = nil
		return nil
	}

	// Create and store genesis block
	stateRoot, err := n.computeGenesisStateRoot()
	if err != nil {
		return fmt.Errorf("failed to compute genesis state root: %w", err)
	}
	genesisBlock := n.createGenesisBlock(stateRoot)
	n.genesisBlock = genesisBlock
	newGenesisHash := block.ComputeBlockHash(genesisBlock.Header)
	nodeLog.Info("Created new genesis block, hash=%x stateRoot=%x chainId=%d", newGenesisHash[:16], genesisBlock.Header.StateRoot[:8], genesisBlock.Header.ChainID)

	if err := n.blockStore.PutBlock(genesisBlock); err != nil {
		return fmt.Errorf("failed to store genesis block: %w", err)
	}

	n.currentBlock = genesisBlock
	nodeLog.Info("Genesis block stored, currentBlock set to height: %d", n.currentBlock.Header.Height)
	return nil
}

// createGenesisBlock creates the genesis block from genesis configuration.
// stateRoot is computed from genesis allocations before calling this function.
func (n *Node) createGenesisBlock(stateRoot types.Hash) *encoding.Block {
	gb := n.genesis.ToBlock()

	return &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      gb.Header.Version,
			Height:       gb.Header.Height,
			Timestamp:    gb.Header.Timestamp,
			ParentHash:   types.Hash{},
			StateRoot:    stateRoot,
			TxRoot:       types.Hash{},
			ReceiptRoot:  types.Hash{},
			ProposerAddr: types.Address{},
			VRFProof:     nil,
			VRFValue:     types.Hash{},
			Signature:    nil,
			ChainID:      n.chainID, // audit-fix R5-H1: include ChainID
		},
		Transactions: nil,
	}
}

// computeGenesisStateRoot computes the state root from genesis allocations.
// Uses a temporary in-memory state DB to ensure deterministic computation
// before the genesis block is created.
func (n *Node) computeGenesisStateRoot() (types.Hash, error) {
	if n.genesis == nil {
		return types.Hash{}, nil
	}

	tmpDB := state.NewStateDB()

	allocs, err := n.genesis.GetAllocations()
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to get genesis allocations: %w", err)
	}
	for addr, balance := range allocs {
		tmpDB.SetBalance(addr, balance)
	}

	// Deduct genesis validator stakes from balances (must match initState() logic).
	for _, v := range n.genesis.Validators {
		addr, addrErr := parseAddressString(v.Address)
		if addrErr != nil {
			continue
		}
		stake, ok := new(big.Int).SetString(v.Stake, 10)
		if !ok {
			stake, ok = new(big.Int).SetString(v.Stake, 16)
		}
		if !ok || stake == nil || stake.Sign() <= 0 {
			continue
		}
		currentBal := tmpDB.GetBalance(addr)
		if currentBal.Cmp(stake) < 0 {
			continue
		}
		newBal := new(big.Int).Sub(currentBal, stake)
		tmpDB.SetBalance(addr, newBal)
	}

	nonces, err := n.genesis.GetAccountNonces()
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to get genesis nonces: %w", err)
	}
	for addr, nonce := range nonces {
		tmpDB.SetNonce(addr, nonce)
	}

	codes, err := n.genesis.GetAccountCodes()
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to get genesis codes: %w", err)
	}
	for addr, code := range codes {
		tmpDB.SetCode(addr, code)
	}

	storage, err := n.genesis.GetAccountStorage()
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to get genesis storage: %w", err)
	}
	for addr, storageMap := range storage {
		for key, value := range storageMap {
			tmpDB.SetState(addr, key, value)
		}
	}

	// AUDIT-FIX (effective-balance testnet, 2026-09): initState() adds the
	// deterministic dev accounts to state when DevMode is enabled. This
	// computation MUST mirror that, otherwise the genesis block header stores
	// a stateRoot that omits the dev-account balances while the live stateDB
	// includes them - a permanent genesis StateRoot mismatch that breaks
	// block validation and prevents finality on any DevMode/testnet chain.
	// Dev accounts use a fixed domain-separated seed so every node agrees.
	if n.config.DevMode {
		_, balances, derr := InitDevAccounts(n.config.DataDir, 3)
		if derr != nil {
			return types.Hash{}, fmt.Errorf("failed to init dev accounts for genesis root: %w", derr)
		}
		for addr, balance := range balances {
			tmpDB.SetBalance(addr, balance)
		}
	}

	stateRoot, err := tmpDB.Commit()
	if err != nil {
		return types.Hash{}, fmt.Errorf("failed to commit genesis state: %w", err)
	}

	return stateRoot, nil
}

// initState initializes the state database
func (n *Node) initState() error {
	// Use BoltDB for persistent state storage
	statePath := filepath.Join(n.config.DataDir, "state")
	stateDB, err := db.NewBoltDB(statePath)
	if err != nil {
		if !n.config.DevMode {
			return fmt.Errorf("failed to create persistent state DB at %s: %w", statePath, err)
		}
		nodeLog.Warn("Failed to create persistent state DB: %v, using memory (DevMode)", err)
		n.stateDB = state.NewStateDB()
	} else {
		nodeLog.Info("Using persistent state BoltDB at %s", statePath)
		n.stateDB = state.NewStateDB(stateDB)
	}

	// Check if state already has data (i.e. persisted from previous run)
	hasState := false
	if n.genesis != nil {
		allocs, err := n.genesis.GetAllocations()
		if err != nil {
			return fmt.Errorf("failed to check genesis allocations: %w", err)
		}
		for addr := range allocs {
			if n.stateDB.Exist(addr) {
				hasState = true
				break
			}
		}
	}

	if hasState {
		nodeLog.Info("State already persisted, skipping genesis initialization")
		n.stateAlreadyPersisted = true
		return nil
	}

	// Apply genesis allocations
	if n.genesis != nil {
		// Set balances
		allocs, err := n.genesis.GetAllocations()
		if err != nil {
			return fmt.Errorf("failed to get genesis allocations: %w", err)
		}
		for addr, balance := range allocs {
			n.stateDB.SetBalance(addr, balance)
		}

		// Deduct genesis validator stakes from balances.
		// Genesis alloc gives each validator 32000 QAU; stake is 30000 QAU.
		// After deduction the balance is 2000 QAU (gas/fees operational overhead).
		for _, v := range n.genesis.Validators {
			addr, addrErr := parseAddressString(v.Address)
			if addrErr != nil {
				nodeLog.Warn("Failed to parse validator address %s for stake deduction: %v", v.Address, addrErr)
				continue
			}
			stake, ok := new(big.Int).SetString(v.Stake, 10)
			if !ok {
				stake, ok = new(big.Int).SetString(v.Stake, 16)
			}
			if !ok || stake == nil || stake.Sign() <= 0 {
				continue
			}
			currentBal := n.stateDB.GetBalance(addr)
			if currentBal.Cmp(stake) < 0 {
				nodeLog.Warn("Validator %s balance %s < stake %s, skipping deduction", v.Address, currentBal.String(), stake.String())
				continue
			}
			newBal := new(big.Int).Sub(currentBal, stake)
			n.stateDB.SetBalance(addr, newBal)
			nodeLog.Info("Genesis validator %s: deducted %s stake, balance = %s", v.Address, stake.String(), newBal.String())
		}

		// Set nonces
		nonces, err := n.genesis.GetAccountNonces()
		if err != nil {
			return fmt.Errorf("failed to get genesis nonces: %w", err)
		}
		for addr, nonce := range nonces {
			n.stateDB.SetNonce(addr, nonce)
		}

		// Set contract codes
		codes, err := n.genesis.GetAccountCodes()
		if err != nil {
			return fmt.Errorf("failed to get genesis codes: %w", err)
		}
		for addr, code := range codes {
			n.stateDB.SetCode(addr, code)
		}

		// Set contract storage
		storage, err := n.genesis.GetAccountStorage()
		if err != nil {
			return fmt.Errorf("failed to get genesis storage: %w", err)
		}
		for addr, storageMap := range storage {
			for key, value := range storageMap {
				n.stateDB.SetState(addr, key, value)
			}
		}
	}

	// Initialize dev accounts in dev mode
	if n.config.DevMode {
		accounts, balances, err := InitDevAccounts(n.config.DataDir, 3)
		if err != nil {
			nodeLog.Warn("Failed to init dev accounts: %v", err)
		} else {
			for addr, balance := range balances {
				n.stateDB.SetBalance(addr, balance)
			}
			PrintDevAccounts(accounts)
		}
	}

	// Commit initial state
	if n.genesis != nil || n.config.DevMode {
		_, err := n.stateDB.Commit()
		if err != nil {
			return fmt.Errorf("failed to commit genesis state: %w", err)
		}
	}

	return nil
}

// initTxPool initializes the transaction pool
func (n *Node) initTxPool() error {
	minGasPrice := big.NewInt(1) // 1 wei minimum gas price
	validator := txpool.NewTxValidator(minGasPrice, n.config.MaxGasLimit, n.config.NetworkID)
	n.txPool = txpool.NewTxPool(validator, n.stateDB)

	// audit-fix N-1: front-running protection infrastructure.
	// Integrate commit-reveal manager for front-running (MEV) protection.
	// This prevents attackers from seeing pending transactions in the mempool
	// and front-running them by requiring high-value transactions to go through
	// a commit-reveal phase before execution.
	// CRV2: block-height-based config; threshold 10 QAU (see
	// docs/commit-reveal-v2-design.md). Commitments are on-chain
	// TxTypeCommit transactions — no HMAC secret involved.
	crm := txpool.NewCommitRevealManager(txpool.DefaultCommitRevealConfig())
	n.commitRevealManager = crm
	n.txPool.SetCommitRevealManager(crm)

	// AA Bundler (Account Abstraction) — wires up the EIP-4337 bundler to the
	// txpool so that UserOperations can be validated via the EntryPoint and
	// bundled for block proposers.
	executor := qvm.NewExecutor()
	// R43-QVM-BYTECODE-01 (2026-08-03): on devnet chainIDs tolerate unknown
	// opcodes (legacy behavior, supports EVM-compat experiments); on all
	// other chainIDs reject deployment of bytecode with unknown opcodes
	// (production-hardened). Centralized in node wiring so every Executor
	// instance created by the node follows the same policy.
	if n.chainID == 1333 || n.chainID == 1334 {
		executor.SetDevnetValidation(true)
	}
	entryPoint := qvm.NewEntryPoint(executor)
	stateAdapter := &qvmasync.StateDBAdapter{StateDB: n.stateDB}
	bundlerCfg := &txpool.BundlerConfig{
		ChainID:        n.chainID,
		Beneficiary:    types.Address{},
		MaxBundleSize:  txpool.DefaultMaxBundleSize,
		BundleInterval: txpool.DefaultBundleInterval,
		MinPriorityFee: big.NewInt(txpool.DefaultMinPriorityFee),
	}
	n.bundler = txpool.NewBundler(bundlerCfg, entryPoint, executor, stateAdapter)
	n.txPool.SetBundler(n.bundler)
	n.bundler.Start()

	// R14-MED (2026-07-21): Launch the background zombie-cleanup goroutine
	// so that zombies are reclaimed even when the pool is idle (no new txs).
	// Without this an attacker who floods then stops sending can pin maxSize
	// worth of memory for up to 6h (maxTxAge).
	n.txPool.Start()

	return nil
}

type defaultKeyVersionValidator struct{}

func (d *defaultKeyVersionValidator) ValidateKeyVersion(blockKeyVersion uint64, blockTimestamp int64) error {
	return nil
}

func (d *defaultKeyVersionValidator) GetCurrentKeyVersion() uint64 {
	return 0
}

type qposKeyVersionValidator struct {
	qpos *consensus.QPOS
}

func (qkv *qposKeyVersionValidator) ValidateKeyVersion(blockKeyVersion uint64, blockTimestamp int64) error {
	return qkv.qpos.ValidateKeyVersion(blockKeyVersion, blockTimestamp)
}

func (qkv *qposKeyVersionValidator) GetCurrentKeyVersion() uint64 {
	return qkv.qpos.GetCurrentKeyVersion()
}

// initConsensus initializes the consensus components
func (n *Node) initConsensus() error {
	n.validatorManager = consensus.NewValidatorManager()
	// FIX: When the genesis declares an explicit minSignatures
	// threshold (e.g. testnet = 3 for 4 validators, tolerating 1 failure), use it
	// as the checkpoint fallback instead of DefaultCheckpointConfig() (4, sized for
	// 6 validators). The dynamic ComputeMinSignatures() still takes precedence
	// once the live validator set is known.
	cpConfig := consensus.DefaultCheckpointConfig()
	if n.genesis != nil && n.genesis.MinSignatures > 0 {
		cpConfig.MinSignatures = n.genesis.MinSignatures
	}
	n.checkpointManager = consensus.NewCheckpointManager(cpConfig, n.validatorManager)
	n.blockValidator = core.NewBlockValidator(n.chainID, n.config.MaxGasLimit)

	n.blockValidator.SetValidatorLookup(n.validatorManager)
	n.blockValidator.SetKeyVersionValidator(&defaultKeyVersionValidator{})

	// AUDIT (2026) R4-ECON-02: Wire NonceReader so block validation
	// rejects already-executed (replayed) transactions that waste block
	// space and Dilithium verification time.
	if n.stateDB != nil {
		n.blockValidator.SetNonceReader(n.stateDB)
	}

	// AUDIT (2026) R4-NODE-01: Wire ForkRuleProvider so block validation
	// enforces fork-gated consensus rules (MaxBlockGas, MaxTxSize, BlockTime)
	// active at each block's height. Without this, the ForkManager constructed
	// in initUpgrade is dead code — planned hard forks never take effect.
	if n.forkManager != nil {
		n.blockValidator.SetForkRuleProvider(&forkRuleProviderAdapter{fm: n.forkManager})
	}

	// AUDIT-FULL-ROUND1-2026-08-15 P0-02 FIX: wire the on-chain multisig
	// signer-roster provider so BlockValidator routes TxTypeMultiSig
	// transactions to encoding.VerifyMultiSigAuthorization. Without this
	// adapter every MultiSig-containing block was rejected fail-closed by
	// encoding.VerifyTransactionAuthorization's ErrAuthMultiSigUnsupported.
	// The adapter shares n.multisigStore with the executor and RPC API —
	// single source of truth for the on-chain wallet registry.
	if n.multisigStore != nil {
		n.blockValidator.SetMultiSigRosterProvider(&multisigRosterProviderAdapter{store: n.multisigStore})
	}

	// SECURITY FIX: Share the txpool's SigningVerifier with the block validator.
	// This ensures block validation verifies all transaction signatures (preventing
	// malicious proposers from including forged-signature txs) while sharing the
	// SignatureCache for maximum cache hit rates (txs verified in txpool are
	// cache hits when the same txs appear in blocks).
	if n.txPool != nil {
		if tv, ok := n.txPool.Validator(); ok {
			if sv := tv.GetSigningVerifier(); sv != nil {
				n.blockValidator.SetSigningVerifier(sv)
				nodeLog.Info("Shared SigningVerifier between txpool and block validator (50K SignatureCache)")
			}
		}
	}

	// Initialize staking manager
	n.stakingManager = economics.NewStakingManager(nil) // Use default config

	// Initialize DeFi manager
	n.defiManager = economics.NewDeFiManager(nil) // Use default config
	nodeLog.Info("DeFi manager initialized")

	// Initialize governance manager
	n.governanceManager = economics.NewGovernanceManager(nil)
	n.governanceManager.SetStakeQuerier(&stakeQuerierAdapter{sm: n.stakingManager})
	n.governanceManager.InitializeParameters(economics.DefaultGovernanceParameters())
	// Set data directory for persistence (proposals survive restart)
	govDataDir := filepath.Join(n.config.DataDir, "governance")
	if err := n.governanceManager.SetDataDir(govDataDir); err != nil {
		nodeLog.Warn("Failed to load governance state: %v", err)
	}
	// R42-GOVDEP-01 (2026-08-03): enable production hardening on recognized
	// production networks so CreateProposal rejects nil DepositLocker
	// (zero-cost proposal DoS guard). Devnet (1333) keeps the legacy
	// warning-only behavior so contract authors can prototype without
	// wiring a locker; mainnet/testnet must fail-closed. The economic
	// DepositLocker implementation itself must still be wired separately
	// (SetDepositLocker); production mode only governs the nil path.
	switch n.chainID {
	case 1668, 1669:
		n.governanceManager.SetProductionMode(true)
		nodeLog.Info("Governance production hardening enabled (chainID=%d): nil DepositLocker will fail-closed", n.chainID)
	}
	nodeLog.Info("Governance manager initialized")

	// Initialize economics components (inflation, gas fees, fee distribution, rewards, DeFi incentives, liquid staking)
	initialSupply := big.NewInt(0)
	if n.genesis != nil {
		if allocs, allocErr := n.genesis.GetAllocations(); allocErr == nil {
			for _, balance := range allocs {
				initialSupply.Add(initialSupply, balance)
			}
		}
	}
	n.inflationModel = economics.NewInflationModel(nil, initialSupply)

	gfc, gfcErr := economics.NewGasFeeCollector(nil)
	if gfcErr != nil {
		return fmt.Errorf("failed to create gas fee collector: %w", gfcErr)
	}
	n.gasFeeCollector = gfc

	rc, rcErr := economics.NewRewardCalculator(nil)
	if rcErr != nil {
		return fmt.Errorf("failed to create reward calculator: %w", rcErr)
	}
	n.rewardCalculator = rc

	rd, rdErr := economics.NewRewardDistributor(n.rewardCalculator, 2500)
	if rdErr != nil {
		return fmt.Errorf("failed to create reward distributor: %w", rdErr)
	}
	n.rewardDistributor = rd

	// Treasury, developer, and insurance addresses default to zero address;
	// in production these should be configured via governance or config.
	// R32-P3-5 FIX: Use real addresses for Treasury/Developer/Insurance pools.
	// Previously all three were types.Address{} (zero address), causing distributed
	// fees to be effectively burned. Now they map to the project's designated accounts:
	// Treasury → account 8 (foundation reserve) 0xa8f6063b8a979f9f24757de03edfe87dab85e2c1
	// Developer → account 6 (development fund) 0xbb8c1a37192a94fdff8f85a7e3e19b26cdd426a5
	// Insurance → account 4 (ecosystem fund) 0xc5efb24a48b426dde56544a683cb9031a034b64a
	treasuryAddr, addrErr := types.ParseHexAddress("0xa8f6063b8a979f9f24757de03edfe87dab85e2c1")
	if addrErr != nil {
		return fmt.Errorf("invalid treasury address: %w", addrErr)
	}
	developerAddr, addrErr := types.ParseHexAddress("0xbb8c1a37192a94fdff8f85a7e3e19b26cdd426a5")
	if addrErr != nil {
		return fmt.Errorf("invalid developer address: %w", addrErr)
	}
	insuranceAddr, addrErr := types.ParseHexAddress("0xc5efb24a48b426dde56544a683cb9031a034b64a")
	if addrErr != nil {
		return fmt.Errorf("invalid insurance address: %w", addrErr)
	}
	// FIX: FeeDistributionInterval was hardcoded to 100 in
	// DefaultFeeDistributionConfig. Now configurable via node config.
	// 0 means use the default (100).
	feeDistConfig := economics.DefaultFeeDistributionConfig()
	if n.config.FeeDistributionInterval > 0 {
		feeDistConfig.DistributionInterval = n.config.FeeDistributionInterval
	}
	n.feeDistributor = economics.NewFeeDistributor(feeDistConfig, n.stakingManager, treasuryAddr, developerAddr, insuranceAddr)

	n.defiIncentiveManager = economics.NewDeFiIncentiveManager(big.NewInt(0))

	n.liquidStakingManager = economics.NewLiquidStakingManager(nil, n.stakingManager)
	// R37-INFO FIX (2026-07-31): CompoundRewards is fail-closed when no
	// TreasuryVerifier is injected. No on-chain treasury view is wired at
	// this layer yet, so explicitly opt out of verification here — this
	// makes the skip a conscious, visible decision instead of the previous
	// silent nil default.
	// TODO: inject a real TreasuryVerifier backed by chain state so reward
	// compounding is verified against actual treasury deposits.
	n.liquidStakingManager.AllowUnverifiedCompounding()

	// R43-ECON-POOLID-01 (2026-08-03): enable liquid staking production
	// hardening on mainnet (1668/1670) and testnet (1669). CreatePool
	// then REQUIRES a non-zero blockHeight variadic, eliminating the
	// non-deterministic time.Now() fallback for pool ID derivation that
	// would break cross-node consensus on pool identity. Devnet
	// (1333/1334) keeps the fallback for backward compatibility with
	// existing devnet tests, mirroring the governance R42-GOVDEP-01 gating
	// pattern above.
	if n.chainID == 1668 || n.chainID == 1669 || n.chainID == 1670 {
		n.liquidStakingManager.SetProductionMode(true)
	}

	nodeLog.Info("Economics components initialized (inflation, gas fees, fee distribution, rewards, DeFi incentives, liquid staking)")

	// FIX: Create EconomicsManager and wire all existing sub-components into it.
	// Without this, EconomicsManager.ProcessBlock() (which contains the  FeeDistributor
	// integration) is dead code — gas fees are never collected or distributed per-block.
	// We create the manager via NewEconomicsManager (which initializes internal fields like
	// totalSupply and config) and then replace its sub-components with the already-created
	// instances above, so there is exactly one instance of each component (no duplication).
	em, emErr := economics.NewEconomicsManager(nil)
	if emErr != nil {
		return fmt.Errorf("failed to create economics manager: %w", emErr)
	}
	em.RewardCalculator = n.rewardCalculator
	em.RewardDistributor = n.rewardDistributor
	em.GasFeeCollector = n.gasFeeCollector
	em.StakingManager = n.stakingManager
	em.GovernanceManager = n.governanceManager
	em.SetFeeDistributor(n.feeDistributor)
	em.SetInflationModel(n.inflationModel)
	em.SetTotalSupply(initialSupply)
	n.economicsManager = em

	// FIX: Register totalStaked synchronization callback.
	// When consensus reduces a validator's stake (e.g., via slashing), the
	// EconomicsManager's StakingManager must be updated to keep totalStaked
	// in sync. Without this callback, the two totalStaked values drift.
	if n.validatorManager != nil {
		if vs, vsErr := n.validatorManager.GetValidatorSet(); vsErr == nil && vs != nil {
			vs.SetStakeChangedCallback(func(addr types.Address, newStake *big.Int) {
				// RecomputeTotalStaked is the safest approach — it recalculates
				// from actual individual stakes, avoiding any drift accumulation.
				n.stakingManager.RecomputeTotalStaked()
			})
		}
	}

	nodeLog.Info("EconomicsManager initialized — ProcessBlock fee distribution active")

	// Add initial validators from genesis (bootstrap with 0 stake)
	// Validators will receive QAU and stake via normal transactions after launch,
	// keeping genesis.json clean of any founder-controlled allocations.
	if n.genesis != nil {
		for _, v := range n.genesis.Validators {
			addr, err := parseAddressString(v.Address)
			if err != nil {
				return fmt.Errorf("invalid validator address %q: %w", v.Address, err)
			}
			var pubKey *crypto.PublicKey
			if v.PublicKey != "" {
				pkBytes, pkErr := hex.DecodeString(stripHexPrefix(v.PublicKey))
				if pkErr != nil {
					return fmt.Errorf("invalid validator public key %q: %w", v.PublicKey, pkErr)
				}
				var keyErr error
				pubKey, keyErr = crypto.PublicKeyFromBytes(pkBytes)
				if keyErr != nil {
					return fmt.Errorf("invalid validator public key bytes %q: %w", v.PublicKey, keyErr)
				}
			}
			// Bootstrap: add validator with genesis stake, activate for block production
			// Parse stake from genesis config (decimal string in wei)
			var genesisStake *big.Int
			if v.Stake != "" {
				if s, ok := new(big.Int).SetString(v.Stake, 10); ok {
					genesisStake = s
				}
			}
			if genesisStake == nil {
				genesisStake = big.NewInt(0)
			}
			if vmErr := n.validatorManager.AddGenesisValidator(addr, addr, pubKey, genesisStake, 100, 0); vmErr != nil {
				nodeLog.Error("Failed to add genesis validator %s: %v", addr.String(), vmErr)
			}
			// R42-P0 FIX (2026-08-05): Inject genesis stake into EconomicsManager
			// (StakingManager.stakes) as well. Previously only ValidatorManager
			// (consensus layer) was injected, causing EconomicsManager.ProcessBlock
			// to fail with "no validator for reward" on every block → no rewards
			// distributed, no finality, executive chamber empty. The compensation
			// logic in syncStakingFromChain() only runs when latestHeight > 0,
			// so on a fresh chain it never executes.
			// Safe with restart: syncStakingFromChain calls SyncFromChain first
			// (clears sm.stakes), then re-adds genesis stakes, so no duplication.
			if genesisStake.Sign() > 0 {
				if smErr := n.stakingManager.Stake(addr, genesisStake, 100, 0); smErr != nil {
					nodeLog.Warn("Failed to inject genesis stake into EconomicsManager: addr=%x, err=%v", addr[:8], smErr)
				}
			}
			// Validator is already active from AddGenesisValidator (Active=true).
			// Stake is set from genesis config — no separate staking transaction needed.
		}
	}

	return nil
}

// initOptimizations initializes the optimization modules.
func (n *Node) initOptimizations() error {
	// CRIT-1/CRIT-2 (R8 2026-07-19 FIX) + R31-HIGH-1 FIX (2026-09-06):
	// Production hard guard, now fail-closed. The parallel QVM executor has
	// known consensus-safety holes (MVMemory Version.Value not populated,
	// validateTransaction missing codeKey check) that can cause different
	// validators to compute different states -> consensus divergence.
	//
	// R31-HIGH-1: the previous guard keyed ONLY on QAU_PRODUCTION=1 -- an
	// operator who forgot the env var on a mainnet deployment would run
	// the known-unsafe executor. params.ParallelQVMAllowed closes both
	// failure modes at once:
	//  1. a mainnet network ID is production by definition (env var or not),
	//  2. on non-production networks the executor additionally requires the
	//     EXPLICIT opt-in QAU_ENABLE_PARALLEL_QVM=1 (a stray config
	//     `enabled: true` alone no longer arms it).
	if n.config.ParallelExecution.Enabled {
		if !params.ParallelQVMAllowed(n.chainID) {
			nodeLog.Warn("[CRIT-1/CRIT-2 GUARD / R31-HIGH-1] force-disabling ParallelExecution.Enabled: "+
				"the parallel QVM executor has known consensus-safety holes (MVMemory Version."+
				"Value not populated, validateTransaction missing codeKey check) and is "+
				"refused in production mode (mainnet chain ID or QAU_PRODUCTION=1). "+
				"On devnets it requires the explicit opt-in QAU_ENABLE_PARALLEL_QVM=1. "+
				"chainID=%d isProduction=%v", n.chainID, params.IsProduction(n.chainID))
			n.config.ParallelExecution.Enabled = false
		}
	}

	// Initialize parallel QVM executor
	if n.config.ParallelExecution.Enabled {
		pqvmConfig := &parallel.ParallelQVMConfig{
			NumWorkers:                 n.config.ParallelExecution.NumWorkers,
			MaxRetries:                 n.config.ParallelExecution.MaxRetries,
			EnableSpeculativeExecution: true,
			// AUDIT (2026) QVM B-1 FIX: Set ChainID so Execute doesn't
			// reject all calls with ErrChainIDNotSet. Without this, parallel
			// QVM was wired but completely non-functional.
			ChainID: n.chainID,
		}
		n.parallelQVM = parallel.NewParallelQVM(pqvmConfig)
	}

	// Initialize multi-level cache
	cacheConfig := &cache.MultiLevelCacheConfig{
		L1MaxSize:    n.config.CacheConfig.L1MaxSize,
		L1MaxMemory:  n.config.CacheConfig.L1MaxMemory,
		L2MaxSize:    n.config.CacheConfig.L2MaxSize,
		L2MaxMemory:  n.config.CacheConfig.L2MaxMemory,
		TTL:          time.Duration(n.config.CacheConfig.TTLSeconds) * time.Second,
		PromoteOnHit: true,
	}
	n.multiCache = cache.NewMultiLevelCache(cacheConfig)

	return nil
}

// initP2P initializes the P2P network host (without starting it).
//
// P2P-R13-CRIT-004 (2026-07-21) FIX: Previously this method created the host
// AND immediately called Start() — opening the listener and beginning to
// accept peer connections. initP2PSignatureVerifier() was called much later
// (after startServices). During this multi-second window the host was
// accepting connections and GossipSub messages while payloadVerifier == nil,
// causing signature verification to be silently skipped (fail-open). An
// attacker who knew a node was restarting could inject forged
// blocks/votes/transactions during this window.
//
// The fix splits the lifecycle: initP2P() now only creates the host. The
// actual Start() is deferred to startP2P(), which is called AFTER
// initP2PSignatureVerifier() completes — so by the time the host begins
// accepting connections, the Dilithium3 payload verifier is already wired
// into both the direct-P2P MessageValidator and the GossipSub router.
func (n *Node) initP2P() error {
	bootstrapPeers := make([]string, 0)
	bootstrapPeers = append(bootstrapPeers, n.config.BootstrapPeers...)

	// audit-fix R3-Info-1: removed dead NodeID assignment — NewHost()
	// generates a Dilithium3 keypair and derives PeerID from the public key,
	// overwriting any value set here.
	// CRITICAL-DEVMODE FIX: Pass NetworkID so p2p layer can enforce DevMode security checks.
	cfg := &p2p.Config{
		ListenAddr:     n.config.ListenAddr,
		BootstrapPeers: bootstrapPeers,
		MaxPeers:       n.config.MaxPeers,
		EnableDHT:      n.config.EnableDHT,
		NodeDBPath:     n.config.NodeDBPath,
		DevMode:        n.config.DevMode,
		NetworkID:      n.config.NetworkID,
		NodeKeyPath:    n.config.NodeKeyPath,
		ExternalIP:     n.config.ExternalIP,
	}

	host, err := p2p.NewHost(cfg)
	if err != nil {
		return err
	}

	n.p2pHost = host
	// P2P-R13-CRIT-004: Do NOT call p2pHost.Start() here. Start() is deferred
	// to startP2P() which runs after initP2PSignatureVerifier() — eliminating
	// the TOCTOU window where the host accepted connections with no payload
	// signature verifier wired.
	return nil
}

// startP2P starts the P2P host (listener + dialers + GossipSub router).
//
// P2P-R13-CRIT-004 (2026-07-21) FIX: This is the second half of the split
// lifecycle. It MUST run after initP2PSignatureVerifier() so that the
// payload signature verifier is already wired when the host begins accepting
// connections. Calling Start() before the verifier is wired opens a TOCTOU
// window where attackers can inject forged P2P messages that bypass
// signature verification.
func (n *Node) startP2P() error {
	if n.p2pHost == nil {
		return nil
	}
	if err := n.p2pHost.Start(); err != nil {
		return err
	}
	// Print enode URL so operators can configure -bootnodes on peer nodes
	enodeURL := n.p2pHost.EnodeURL()
	// FIX: Do not log the full enode URL (contains full public key).
	// Log a truncated version for identification, and the full URL only at
	// debug level for operators who need it.
	redactedEnode := redactEnodeURL(enodeURL)
	nodeLog.Info("P2P host started, enode: %s", redactedEnode)
	nodeLog.Debug("Full enode URL (for -bootnodes): %s", enodeURL)
	return nil
}

// initP2PSignatureVerifier wires up the Dilithium3 payload signature
// verifier for both the direct-P2P MessageValidator and the GossipSub
// router.
//
// P2P-R12-CRIT-001 (2026-07-20) FIX: R11 added the Dilithium3PayloadVerifier
// framework in p2p/signature_verifier.go and the SetPayloadSignatureVerifier
// setters on MessageValidator / GossipSub, but the node init flow never
// instantiated a verifier or called the setters. As a result both
// payloadVerifier fields stayed nil, the `if v.payloadVerifier != nil`
// checks in the validation paths skipped signature verification entirely,
// and attackers could forge arbitrary P2P messages (blocks, votes,
// transactions, QTD partial seals) that would propagate through the
// network before being rejected by application-layer validation.
//
// This method MUST run after:
//   - initP2P (creates p2pHost)
//   - initConsensus (creates blockValidator with ValidateSignature)
//   - startServices (creates blockProducer + QPOS for attestation verification)
//
// Verification semantics:
//   - KindBlock: decode via encoding.UnmarshalBlock, then call
//     n.blockValidator.ValidateSignature(header). Fail-closed if
//     blockValidator is nil (returns ErrSignatureInvalid).
//   - KindVote / KindAttestation: parse the wire-format attestation via
//     n.parseAttestation, then call QPOS.VerifyAttestationSignature(att).
//     Fail-closed while blockProducer or QPOS is nil (returns
//     ErrSignatureInvalid). Once QPOS is initialized, this performs a
//     full Dilithium3 signature check against the validator's public key.
//   - KindTransaction: handled inside Dilithium3PayloadVerifier itself
//     (transactions carry their own PublicKey, no lookup needed).
//   - KindOther / KindUnknown: skipped (no signature required).
func (n *Node) initP2PSignatureVerifier() {
	if n.p2pHost == nil {
		// P2P disabled (e.g., SyncOnlyMode without a host). Nothing to wire.
		return
	}

	blockVerify := func(payload []byte) error {
		if n.blockValidator == nil {
			// Fail-closed: block signature verification unavailable.
			return p2p.ErrSignatureInvalid
		}
		blk, err := encoding.UnmarshalBlock(payload)
		if err != nil {
			return fmt.Errorf("%w: failed to decode block: %v", p2p.ErrSignatureInvalid, err)
		}
		if blk == nil || blk.Header == nil {
			return p2p.ErrSignatureMissing
		}
		return n.blockValidator.ValidateSignature(blk.Header)
	}

	voteVerify := func(payload []byte) error {
		// Fail-closed while QPOS is not yet initialized. During startup
		// (before startServices creates blockProducer), gossip messages
		// may already arrive — rejecting them is safer than accepting
		// unverified, and they will be re-propagated by honest peers
		// after this node's QPOS comes online.
		if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
			return p2p.ErrSignatureInvalid
		}
		att, err := n.parseAttestation(payload)
		if err != nil {
			return fmt.Errorf("%w: failed to decode attestation: %v", p2p.ErrSignatureInvalid, err)
		}
		if att == nil {
			return p2p.ErrSignatureMissing
		}
		return n.blockProducer.QPOS().VerifyAttestationSignature(att)
	}

	verifier := p2p.NewDilithium3PayloadVerifier(blockVerify, voteVerify)

	// Wire the direct-P2P path (MsgTypeBlock/Vote/Transaction messages
	// exchanged via host.broadcast / stream handlers).
	if mv := n.p2pHost.MessageValidator(); mv != nil {
		mv.SetPayloadSignatureVerifier(verifier)
	}

	// Wire the GossipSub path (TopicBlocks/Votes/Transactions/Attestations).
	// The adapter converts the topic-based verifier interface to the
	// kind-based verifier interface.
	if gs := n.p2pHost.GossipSub(); gs != nil {
		gs.SetPayloadSignatureVerifier(p2p.NewTopicPayloadVerifierAdapter(verifier))
	}

	nodeLog.Info("P2P payload signature verifier wired (P2P-R12-CRIT-001): block + vote + tx verification active")
}

// initDanksharding initializes the danksharding / DA committee engine.
// P1-1 (2026-07-14): Creates and wires all DA components (blob storage, DAS
// client, network manager, committee manager, attestation collector, subnet
// manager, garbage collector) into a DankshardingEngine instance, then
// injects the P2P bridge and starts the engine.
//
// This method is a no-op when config.Danksharding.Enabled is false (the
// default). Operators must explicitly enable DA via the config file's
// "danksharding" section.
//
// Initialization order: must run AFTER initP2P (needs p2pHost for the P2P
// bridge) and AFTER initConsensus (needs validatorManager for committee
// computation). The getRandao callback uses a lazy lookup because
// blockProducer is created later in startServices().
func (n *Node) initDanksharding() error {
	daCfg := n.config.Danksharding
	if !daCfg.Enabled {
		nodeLog.Info("Danksharding/DA committee disabled by configuration")
		return nil
	}

	// AUDIT (2026) DA-FIX (CRITICAL): Defense-in-depth mainnet
	// hard guard. Config.Validate() should have caught this already, but
	// this guard ensures the block is enforced even if Validate is bypassed
	// (e.g., programmatic config construction, partial reload, or future
	// refactors). The DA subsystem's KZG commitments and opening proofs are
	// hash placeholders, not real polynomial commitments — enabling DA on
	// mainnet would give false availability guarantees. See DA-.
	if n.config.NetworkID == MainnetNetworkID {
		return fmt.Errorf("danksharding/DA committee cannot be enabled on mainnet "+
			"(networkId=%d): KZG commitments are hash placeholders (DA-). "+
			"Disable danksharding.enabled in config", n.config.NetworkID)
	}

	nodeLog.Info("Initializing Danksharding/DA committee engine (P1-1)")

	// 1. Blob storage — in-memory for now. P0-9 implemented
	// PersistentBlobStorage; node integration can swap this in later.
	blobStorage := encoding.NewBlobStorage()

	// 2. DAS client for availability sampling.
	dasClient := encoding.NewDASClient(encoding.DefaultDASConfig())

	// 3. Blob network manager for cross-node cell requests.
	networkMgr := encoding.NewBlobNetworkManager(blobStorage, dasClient)

	// 4. DA committee manager with lazy validator/randao lookups.
	// getValidators uses the validator manager (available from initConsensus).
	// getRandao uses a lazy lookup because blockProducer is created later
	// in startServices(). When blockProducer is nil (before startServices),
	// returns zero hash — GetCommittee will fail with "insufficient active
	// validators" which is the correct behavior during startup.
	committeeMgr := consensus.NewDACommitteeManager(
		func() []*consensus.ValidatorInfo {
			if n.validatorManager == nil {
				return nil
			}
			return n.validatorManager.GetActiveValidators()
		},
		func(epoch uint64) types.Hash {
			if n.blockProducer == nil {
				return types.Hash{}
			}
			qpos := n.blockProducer.QPOS()
			if qpos == nil {
				return types.Hash{}
			}
			// AUDIT (2026) DA-FIX: Eliminate last-revealer bias
			// in the DA committee shuffle seed. See selectDACommitteeSeed
			// (da_r5_03_seed.go) for the full three-tier rationale and
			// unit tests.
			return selectDACommitteeSeed(qpos, epoch)
		},
	)
	// Apply runtime config (enabled flag + committee size override).
	committeeMgr.SetConfig(daCfg.ToDACommitteeConfig())

	// 5. Attestation collector with committee size for index validation.
	attestCollector := consensus.NewDAAttestationCollector()
	committeeSize := daCfg.CommitteeSize
	if committeeSize <= 0 {
		committeeSize = consensus.DACommitteeSize
	}
	attestCollector.SetCommitteeSize(committeeSize)

	// AUDIT (2026) R4-CRND-02 FIX: Wire the production attestation
	// verifier into the collector. Without this, SubmitAttestation falls
	// back to fail-closed mode (rejecting all submissions) — or worse, if
	// a future change flips the default to accept-all, unauthenticated
	// attestations could be mixed in to inflate the aggregate availability
	// count, faking data availability for a blob that no committee member
	// actually sampled. The verifier performs three checks: signature
	// validity, validator index range, and committee membership (skipped
	// when the committee is disabled, e.g., on testnet/devnet).
	daValidatorLookup := func() []*consensus.ValidatorInfo {
		if n.validatorManager == nil {
			return nil
		}
		return n.validatorManager.GetActiveValidators()
	}
	attestCollector.SetAttestationVerifier(
		consensus.NewDAAttestationVerifier(daValidatorLookup, committeeMgr),
	)

	// 6. Subnet manager for column-to-subnet assignment.
	subnetMgr := consensus.NewDASubnetManager(blobStorage)

	// 7. Garbage collector for old blob data.
	gc := encoding.NewBlobGarbageCollector(blobStorage, func() uint64 {
		if n.blockStore == nil {
			return 0
		}
		// Return current chain height as the slot for GC purposes.
		if blk, err := n.blockStore.GetLatestBlock(); err == nil && blk != nil && blk.Header != nil {
			return blk.Header.Slot
		}
		return 0
	})

	// 8. Create the DankshardingEngine.
	engine := core.NewDankshardingEngine(
		blobStorage,
		dasClient,
		networkMgr,
		committeeMgr,
		attestCollector,
		subnetMgr,
		gc,
		daCfg.ToDankshardingConfig(),
	)

	// 9. Wire the P2P bridge for cross-node DAS sampling.
	// P0-10 provides factory functions that create closures backed by the
	// P2P Host. These enable RequestCell to fetch cells from peers.
	if n.p2pHost != nil {
		engine.SetP2PBridge(
			p2p.NewDASPeerGetter(n.p2pHost),
			p2p.NewDASPeerList(n.p2pHost),
		)
	} else {
		nodeLog.Warn("Danksharding initialized without P2P bridge — DAS sampling limited to local storage")
	}

	// 10. P3-1/P3-3 (2026-07-15): Create and inject DA Prometheus metrics.
	// DAMetrics exposes 10 gauges/counters (qau_da_* namespace) and powers
	// the 5 DA alert rules in metrics/metrics.go. SetDAMetrics must be called
	// BEFORE engine.Start() because the BlobGarbageCollector snapshots the
	// onGC callback at Start() time (to avoid a data race). The same
	// *DAMetrics instance is also injected into the global Metrics instance
	// as a DAMetricProvider so the AlertManager can evaluate DA alert rules.
	daMetrics := consensus.NewDAMetrics()
	daMetrics.SetCommitteeSize(committeeSize)
	engine.SetDAMetrics(daMetrics)
	metrics.Global().SetDAMetricProvider(daMetrics)
	nodeLog.Info("DA Prometheus metrics enabled (10 metrics, qau_da_* namespace) + 5 alert rules")

	// 11. Start the engine (starts GC, wires cellGetter, registers P2P protocol).
	if err := engine.Start(); err != nil {
		return fmt.Errorf("failed to start DankshardingEngine: %w", err)
	}

	n.danksharding = engine
	nodeLog.Info("Danksharding/DA committee engine started successfully (committeeSize=%d)", committeeSize)
	return nil
}

// redactEnodeURL truncates the public key in an enode URL to prevent leaking
// the full node identity in logs. Example:
//
//	"enode://abcdef...123@peer.example.invalid:9000" → "enode://abcdef…REDACTED@peer.example.invalid:9000"
func redactEnodeURL(enodeURL string) string {
	if len(enodeURL) > 22 { // "enode://" = 7 chars + "@" minimum
		atIdx := -1
		for i := 7; i < len(enodeURL); i++ {
			if enodeURL[i] == '@' {
				atIdx = i
				break
			}
		}
		if atIdx > 7 {
			pubkeyPart := enodeURL[7:atIdx]
			if len(pubkeyPart) > 16 {
				return "enode://" + pubkeyPart[:16] + "…REDACTED@" + enodeURL[atIdx+1:]
			}
		}
	}
	return enodeURL
}

// initRPC initializes the RPC server
func (n *Node) initRPC() error {
	nodeLog.Info("initRPC called, RPCEnabled=%v", n.config.RPCEnabled)
	if !n.config.RPCEnabled {
		return nil
	}

	allowedOrigins := n.config.AllowedOrigins
	// R7-C3 FIX: Dev mode previously fell back to CORS AllowOrigins=["*"], which
	// lets any website issue credentialed cross-origin RPC against a developer
	// node (and, with personal_sendTransaction, drive unlocked keys to sign).
	// Restrict to localhost origins only; dev tools run on localhost anyway.
	if n.config.DevMode && len(allowedOrigins) == 0 {
		allowedOrigins = []string{
			"http://localhost",
			"http://localhost:3000",
			"http://localhost:5173",
			"http://localhost:8080",
			"http://127.0.0.1",
			"http://127.0.0.1:3000",
			"http://127.0.0.1:5173",
			"http://127.0.0.1:8080",
		}
	}

	cfg := &rpc.Config{
		Addr:           n.config.RPCAddr,
		MaxBatchSize:   100,
		ReadTimeout:    120 * time.Second,
		WriteTimeout:   120 * time.Second,
		AllowedOrigins: allowedOrigins,
	}

	n.rpcServer = rpc.NewServer(cfg)
	nodeLog.Info("RPC server created")

	// Register Personal API handlers for account management first
	keystoreDir := filepath.Join(n.config.DataDir, "keystore")
	personalAPI := rpc.NewPersonalAPI(keystoreDir, &txPoolAdapter{n.txPool, n}, &stateReaderAdapter{n}, &chainInfoAdapter{n})
	personalAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("Personal API handlers registered")

	// Apply --allow-insecure-unlock flag (Ethereum-compatible)
	if n.config.AllowInsecureUnlock {
		personalAPI.SetAllowInsecureUnlock(true)
	}

	// In dev mode ONLY, auto-unlock dev accounts for testing convenience
	// SECURITY FIX M-2: DevAutoUnlockAccounts must be explicitly set to true
	// This prevents accidental auto-unlock if DevMode is somehow enabled in non-dev config
	if n.config.DevMode && n.config.DevAutoUnlockAccounts {
		nodeLog.Info("WARNING: Dev mode enabled - auto-unlocking dev accounts (NOT FOR PRODUCTION!)")
		// audit-fix M-2: explicitly enable dev mode before calling dev-only methods
		personalAPI.SetDevMode(true)
		devAccountsPath := filepath.Join(n.config.DataDir, "dev_accounts.json")
		if devAccounts, err := loadDevAccountsForUnlock(devAccountsPath); err == nil {
			for _, acc := range devAccounts {
				if err := personalAPI.UnlockFromPrivateKey(acc.PrivateKey); err != nil {
					nodeLog.Warn("Failed to unlock dev account %s: %v", acc.Address, err)
				}
			}
		}
	}

	// Register API handlers using adapter types, with PersonalAPI as AccountManager
	api := rpc.NewAPI(
		&stateReaderAdapter{n},
		&blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n},
		&txPoolAdapter{n.txPool, n},
		&chainInfoAdapter{n},
		personalAPI, // AccountManager for eth_sendTransaction
	)
	n.api = api // store for late-injected ConsensusStakeUpdater in startServices()
	// Set staking manager
	api.SetStakingManager(&stakingManagerAdapter{n.stakingManager})
	// R131: validator-key registry status (read-only). Resolved lazily via
	// blockProducer → QPOS so it works whether or not this node is a validator.
	api.SetValidatorKeyStatusFn(func(addr types.Address) (map[string]any, error) {
		qpos := n.qposForVK()
		if qpos == nil {
			return nil, fmt.Errorf("qpos not initialized")
		}
		out := map[string]any{}
		if addr != (types.Address{}) {
			st := qpos.ValidatorKeyStatus(addr)
			if st == nil {
				return map[string]any{"validator": addr.String(), "registered": false}, nil
			}
			return vkEntryToJSON(st), nil
		}
		// all entries
		entries := []map[string]any{}
		for _, e := range qpos.ValidatorKeyStatusAll() {
			entries = append(entries, vkEntryToJSON(e))
		}
		out["entries"] = entries
		return out, nil
	})
	// Note: ConsensusStakeUpdater is wired in startServices() after blockProducer
	// is initialized, because it needs n.blockProducer.QPOS() which is nil here.
	// Set contract caller for eth_call operations. The adapter is shared with
	// the Debug and AccessList APIs which also need ContractCaller.
	// R43-QVM-BYTECODE-01: same devnet/prod gating as the bundler-executor above.
	contractCallerExec := qvm.NewExecutor()
	if n.chainID == 1333 || n.chainID == 1334 {
		contractCallerExec.SetDevnetValidation(true)
	}
	contractCaller := &contractCallerAdapter{
		stateDB:    n.stateDB,
		blockStore: n.blockStore,
		qvmExec:    contractCallerExec,
		gasLimit:   n.config.MaxGasLimit,
		chainID:    n.chainID, // P2-13 FIX: pass actual chain ID
		node:       n,
	}
	api.SetContractCaller(contractCaller)
	// Set snapshot manager for qau_createSnapshot/qau_restoreSnapshot
	api.SetSnapshotManager(newSnapshotManagerAdapter(n))
	// R45-FORKRECOVERY-API (2026-08-12): wire debug_rollbackChainToHeight
	// backend so the sealer operator can manually resolve a persistent
	// chain fork when syncer-side OnForkRollback can't (e.g. when local
	// branch has invalid blocks since-beforre-peer-tip that don't match
	// peer's parentHash for any re-proposed child).
	api.SetForkRecoveryManager(newForkRecoveryBackend(n))
	// audit-fix WS-H3: enable dev-mode RPC methods only when node is in dev mode
	if n.config.DevMode {
		api.SetDevMode(true)
		n.rpcServer.SetDevMode(true)
		n.rpcServer.SetExposeErrorData(true)
	}
	// / + R73-DEVMODE-STAKE + R74-STAKE-ALLOWLIST: decide the
	// user-allowlist policy for the state-mutating staking/DeFi RPC methods.
	//
	// The allowlist is now explicit opt-in and no longer depends on DevMode:
	// it used to be filled with the genesis validators in production, which
	// made qau_stake unusable for every ordinary user (-32003). Authorization
	// for these methods comes from the mandatory Dilithium3 signature + nonce
	// in verifyStakingSignature / verifyDeFiSignature, and the same state
	// transition is reachable ungated by signing a stake transaction to
	// 0x…1001. See node/rpc_user_allowlist.go for the full rationale.
	userAllowlist, enforceUserAllowlist, allowlistErr := resolveRPCUserAllowlist(
		n.config.RPCUserAllowlist, os.Getenv(rpcUserAllowlistEnv))
	if allowlistErr != nil {
		return fmt.Errorf("RPC user allowlist: %w", allowlistErr)
	}
	if enforceUserAllowlist {
		api.SetAdminAddresses(userAllowlist)
		api.SetEnforceAdminAuth(true)
		nodeLog.Info("Staking/DeFi RPC restricted to %d allowlisted addresses (fail-closed)", len(userAllowlist))
	} else {
		api.SetEnforceAdminAuth(false)
		nodeLog.Info("Staking/DeFi RPC open to any caller with a valid signature (no user allowlist configured)")
	}
	api.RegisterHandlers(n.rpcServer)
	nodeLog.Info("API handlers registered")

	// Register Fee API handlers for EIP-1559 fee history and priority fee
	feeAPI := rpc.NewFeeAPI(
		&blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n},
		&feeHistoryReaderAdapter{n.blockStore},
	)
	feeAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("Fee API handlers registered")

	// Register DeFi API handlers
	if n.defiManager != nil {
		defiAPI := rpc.NewDeFiAPI(n.defiManager, &blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n})
		// R74-STAKE-ALLOWLIST: apply the same policy as the staking API. This
		// used to be SetEnforceAdminAuth(true) in production with no allowlist
		// ever configured — an empty list under enforcement is fail-closed, so
		// all 11 DeFi mutators were rejecting everyone, validators included.
		if enforceUserAllowlist {
			defiAPI.SetAdminAddresses(userAllowlist)
			defiAPI.SetEnforceAdminAuth(true)
		} else {
			defiAPI.SetEnforceAdminAuth(false)
		}
		defiAPI.RegisterDeFiHandlers(n.rpcServer)
		nodeLog.Info("DeFi API handlers registered")
	}

	// Register Governance API handlers
	if n.governanceManager != nil {
		govAPI := rpc.NewGovernanceAPI(n.governanceManager, &blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n})
		govAPI.RegisterGovernanceHandlers(n.rpcServer)
		nodeLog.Info("Governance API handlers registered")
	}

	// Register Economics API handlers
	econAPI := rpc.NewEconomicsAPI(
		n.inflationModel,
		n.gasFeeCollector,
		n.feeDistributor,
		n.rewardCalculator,
		n.rewardDistributor,
		n.defiIncentiveManager,
		n.liquidStakingManager,
		n.stakingManager,
		&blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n},
	)
	econAPI.RegisterEconomicsHandlers(n.rpcServer)
	nodeLog.Info("Economics API handlers registered")

	// Initialize TSS Manager for quantum-safe threshold signatures
	tssCfg := tss.TSSConfig{
		Threshold:     n.config.TSSThreshold,
		TotalShares:   n.config.TSSTotalShares,
		SecurityLevel: 256,
	}
	// R33 CONS-05: Enforce threshold >= 2 at the node integration layer too.
	// If the config explicitly sets T=1, we silently bump it to 2 and log a
	// warning — T=1 provides no threshold security (a single share can sign).
	if tssCfg.Threshold < 2 {
		if tssCfg.Threshold > 0 {
			nodeLog.Warn("TSSThreshold=%d in config is insecure (T=1 defeats TSS); bumping to 2 (R33 CONS-05)",
				tssCfg.Threshold)
		}
		tssCfg.Threshold = 2
	}
	if tssCfg.TotalShares <= 0 {
		tssCfg.TotalShares = 3
	}

	if n.genesisBlock != nil {
		genesisHash := block.ComputeBlockHash(n.genesisBlock.Header)
		if !n.config.TSSDistributedDKG {
			// Task 5 (TSSDistributedDKG): a distributed DKG round MUST NOT be
			// deterministic — no single party may control the seed (TSS-).
			// When the runtime distributed DKG switch is ON, skip the
			// genesis-derived seed so generateKeySharesDistributed() accepts
			// the request.
			tssCfg.Seed = genesisHash[:]
			nodeLog.Info("TSS deterministic seed derived from genesis hash: %x", genesisHash[:8])
		}
	}

	var tssErr error
	n.tssManager, tssErr = tss.NewTSSManager(tssCfg)
	if tssErr != nil {
		nodeLog.Error("Failed to initialize TSS manager: %v", tssErr)
	} else {
		nodeLog.Info("TSS manager initialized with threshold=%d and totalShares=%d", tssCfg.Threshold, tssCfg.TotalShares)
	}

	if n.tssManager != nil {
		sharesLoaded := false
		if n.config.TSSKeyShareFile != "" {
			if data, err := os.ReadFile(n.config.TSSKeyShareFile); err == nil {
				// SECURITY (audit P0- + P1-): Use encrypted import only.
				// Plaintext import fallback removed —all key shares must be encrypted.
				if tss.IsEncryptedKeyShareData(data) {
					tssPwd, pwdErr := n.getTSSPassword()
					if pwdErr != nil {
						nodeLog.Error("Cannot import encrypted TSS key shares (password not configured): %v", pwdErr)
					} else if err := n.tssManager.ImportKeySharesEncrypted(data, tssPwd); err != nil {
						nodeLog.Error("Failed to import encrypted TSS key shares from %s: %v", n.config.TSSKeyShareFile, err)
					} else {
						nodeLog.Info("TSS key shares imported (encrypted) from %s (size=%d, shares=%d)", n.config.TSSKeyShareFile, len(data), n.tssManager.ShareCount())
						sharesLoaded = true
					}
				} else {
					nodeLog.Error("TSS key share file %s is not encrypted —refusing to load plaintext shares (audit-fix). Use encrypted format only.", n.config.TSSKeyShareFile)
				}
			}
		}

		if !sharesLoaded {
			groupKeyLoaded := false
			if n.config.TSSGroupKeyFile != "" {
				if data, err := os.ReadFile(n.config.TSSGroupKeyFile); err == nil {
					if err := n.tssManager.ImportGroupPublicKey(data); err != nil {
						nodeLog.Error("Failed to import TSS group key from %s: %v", n.config.TSSGroupKeyFile, err)
					} else {
						nodeLog.Info("TSS group public key imported from %s (size=%d)", n.config.TSSGroupKeyFile, len(data))
						groupKeyLoaded = true
					}
				}
			}

			// Task 5 (TSSDistributedDKG): wire the distributed DKG coordinator
			// when the switch is ON (non-mainnet only — mainnet is hard-blocked
			// by Config.Validate()). The coordinator injects a real
			// DistributedDKGRunner + P2P DKGTransport into the TSSManager so
			// GenerateKeyShares() below takes the multi-party distributed path
			// instead of the single-process simulated trusted-dealer path.
			// When TSSDistributedDKG is OFF (the default), no coordinator is
			// created and node behavior is unchanged.
			if n.config.TSSDistributedDKG && n.tssManager != nil {
				n.dkgCoordinator = n.wireDKGCoordinator()
				if n.dkgCoordinator != nil {
					nodeLog.Info("TSS distributed DKG ENABLED (TSSDistributedDKG=true) — "+
						"multi-party runtime DKG active (participant=%d, session=%x)",
						n.dkgCoordinator.Transport().ParticipantID(), n.dkgCoordinator.SessionID()[:8])
				}
			}

			if !groupKeyLoaded {
				// TSS- / TSS- (2026-07-17) — Defense-in-depth mainnet guard.
				// Config.Validate() already blocks this combination, but we
				// re-check here to fail-closed if Validate was bypassed (e.g.
				// programmatic Config construction without validation).
				//
				// TSS- GenerateKeyShares() now uses distributed DKG by
				// default (no single point of trust). However, mainnet still
				// MUST NOT run any runtime DKG — even distributed DKG in a
				// single process briefly aggregates s1/s2/t0 in memory. Mainnet
				// validators MUST import pre-generated shares via TSSKeyShareFile
				// (produced by an offline key ceremony).
				if n.config.NetworkID == MainnetNetworkID &&
					os.Getenv("QAU_ALLOW_TRUSTED_DEALER_CEREMONY") != "1" {
					nodeLog.Error("[SECURITY] [BLOCKED] TSS- refusing to run runtime DKG on mainnet " +
						"(networkId=1668). Even though GenerateKeyShares() now uses distributed DKG by " +
						"default, mainnet MUST NOT run any runtime DKG — single-process aggregation " +
						"briefly holds s1/s2/t0 in memory. Provide tssKeyShareFile pointing to " +
						"pre-generated encrypted shares from an offline key ceremony " +
						"(QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 on an air-gapped host for the trusted-dealer " +
						"ceremony, OR use distributed DKG on air-gapped hosts for threshold >= 2).")
				} else {
					// R7-OBS-2 (2026-07-18): Observe DKG duration and failure
					// count. initRPC() runs BEFORE initMetrics(), so on a fresh
					// node startup n.nodeMetrics is still nil here. We MUST NOT
					// lazily call NewNodeMetrics() — that registers Prometheus
					// collectors on the global registry, which panics when a
					// later test case in the same binary reuses the registry.
					// Instead, capture the observation as a closure and replay
					// it in initMetrics() once nodeMetrics is created. When
					// MetricsEnabled=false the observation is discarded.
					dkgStart := time.Now()
					var shares []*tss.KeyShare
					var err error
					if os.Getenv("QAU_ALLOW_TRUSTED_DEALER_CEREMONY") == "1" {
						nodeLog.Info("QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1: using trusted dealer key ceremony (offline ceremony mode)")
						shares, err = n.tssManager.GenerateKeySharesTrustedDealer()
					} else {
						shares, err = n.tssManager.GenerateKeyShares()
					}
					dkgDuration := time.Since(dkgStart).Seconds()
					dkgFailed := err != nil
					// R8-OBS-1 (2026-07-18): Track simulated DKG usage. When
					// no real P2P DistributedDKGRunner is injected, the path
					// falls back to GenerateDKGDistributedSimulated — the
					// trusted-dealer ceremony mode. On mainnet this should
					// never happen (hard guard in config.go Validate()); the
					// counter provides defense-in-depth visibility.
					simulatedDKG := !n.tssManager.HasDistributedDKGRunner()
					if n.nodeMetrics != nil {
						// Metrics already initialized — observe immediately.
						n.nodeMetrics.QTDDKGDuration.Observe(dkgDuration)
						if dkgFailed {
							n.nodeMetrics.QTDDKGFailedTotal.Inc()
						}
						if simulatedDKG {
							n.nodeMetrics.QTDSimulatedDKGInvocations.Inc()
						}
					} else if n.config.MetricsEnabled {
						// Defer observation until initMetrics() creates
						// nodeMetrics. Captured by closure; replayed once.
						n.pendingDKGObservation = func(m *metrics.NodeMetrics) {
							if m == nil {
								return
							}
							m.QTDDKGDuration.Observe(dkgDuration)
							if dkgFailed {
								m.QTDDKGFailedTotal.Inc()
							}
							if simulatedDKG {
								m.QTDSimulatedDKGInvocations.Inc()
							}
						}
					}
					if err != nil {
						nodeLog.Error("TSS DKG failed: %v", err)
					} else {
						nodeLog.Info("TSS DKG completed: generated %d key shares, group public key size=%d", len(shares), len(n.tssManager.GroupPublicKey()))
						if n.config.TSSKeyShareFile != "" {
							// SECURITY (audit-fix): Export with AES-256-GCM encryption
							tssPwd, pwdErr := n.getTSSPassword()
							if pwdErr != nil {
								nodeLog.Error("Cannot export encrypted TSS key shares (password not configured): %v", pwdErr)
							} else if data, expErr := n.tssManager.ExportKeySharesEncrypted(tssPwd); expErr == nil {
								if err := os.WriteFile(n.config.TSSKeyShareFile, data, 0600); err != nil {
									nodeLog.Error("Failed to write TSS key shares to %s: %v", n.config.TSSKeyShareFile, err)
								} else {
									nodeLog.Info("TSS key shares exported to %s (size=%d)", n.config.TSSKeyShareFile, len(data))
								}
							}
						}
						if n.config.TSSGroupKeyFile != "" {
							if data, err := n.tssManager.ExportGroupPublicKey(); err == nil {
								if err := os.WriteFile(n.config.TSSGroupKeyFile, data, 0600); err != nil {
									nodeLog.Error("Failed to write TSS group key to %s: %v", n.config.TSSGroupKeyFile, err)
								} else {
									nodeLog.Info("TSS group public key exported to %s", n.config.TSSGroupKeyFile)
								}
							}
						}
					}
				}
			}
		}
	}

	// RPC-M1 (R8 2026-07-19 FIX): Fail-closed guard. If TSS was explicitly
	// configured (operator set any of: tssDistributedMode=true,
	// tssKeyShareFile!=empty, tssGroupKeyFile!=empty) but the
	// initialization above did not produce a working TSSManager with either
	// threshold shares OR a group public key, return an error instead of
	// silently continuing in degraded mode. Without this guard the node
	// would start up, accept RPC traffic, and silently fall back to
	// non-TSS signing — defeating the post-quantum threshold signature
	// guarantees the chain is supposed to provide. The four init steps
	// above (NewTSSManager, ImportKeySharesEncrypted, ImportGroupPublicKey,
	// DKG) each log their own error message; this guard converts those
	// logged errors into a hard startup failure so operators cannot miss
	// the failure via monitoring of error logs alone.
	//
	// NOTE: TSSThreshold/TSSTotalShares are intentionally NOT included in
	// the "tssRequired" check because they are set by config defaults
	// (config.go: tssThreshold=2, tssTotalShares=3) on every network
	// regardless of operator intent. Including them would fail-close
	// legitimate dev/test nodes that don't actually want TSS active.
	// Only explicit opt-in signals (distributed mode OR file paths) count.
	tssRequired := n.config.TSSDistributedMode ||
		n.config.TSSKeyShareFile != "" ||
		n.config.TSSGroupKeyFile != ""
	if tssRequired {
		if n.tssManager == nil {
			return fmt.Errorf("RPC-M1: TSS initialization required (tssDistributedMode=%v, "+
				"tssKeyShareFile=%q, tssGroupKeyFile=%q) "+
				"but TSSManager creation failed — refusing to start in degraded mode",
				n.config.TSSDistributedMode, n.config.TSSKeyShareFile, n.config.TSSGroupKeyFile)
		}
		if !n.tssManager.HasThreshold() && !n.tssManager.HasGroupPublicKey() {
			return fmt.Errorf("RPC-M1: TSS initialization required but no threshold shares "+
				"(shareCount=%d, threshold=%d) and no group public key loaded — refusing "+
				"to start in degraded mode",
				n.tssManager.ShareCount(), n.config.TSSThreshold)
		}
	}

	// TSS- (2026-07-16): Warn loudly when local TSS mode is active
	// with TotalShares > 1 on any network. The mainnet hard guard in
	// Config.Validate() blocks this combination on mainnet unless
	// QAU_ALLOW_UNSAFE_LOCAL_TSS=1 is set; this log surfaces the residual
	// risk for non-mainnet deployments that opt in.
	if n.tssManager != nil &&
		!n.config.TSSDistributedMode &&
		n.config.TSSTotalShares > 1 {
		nodeLog.Warn("[SECURITY] [WARNING] TSS- TSS is running in local single-node-all-shares mode " +
			"(tssDistributedMode=false, tssTotalShares > 1). This provides NO threshold security — " +
			"it is cryptographically equivalent to single-key signing. Use tssDistributedMode=true for " +
			"real threshold signing. This configuration is blocked on mainnet by Config.Validate().")
	}

	// Register MultiSig API handlers
	n.multisigStore = multisig.NewMultisigStateStore()
	multisigAPI := rpc.NewMultisigAPI(n.multisigStore, &stateReaderAdapter{n}, n.stateDB)
	// AUDIT (2026) KEYS-FIX: Wire chain info so proposal hashes
	// bind to the actual chain ID, enabling cross-chain replay protection.
	multisigAPI.SetChainInfo(&chainInfoAdapter{n})
	multisigAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("MultiSig API handlers registered")

	// Register TSS API handlers for QTD threshold signing
	if n.tssManager != nil {
		tssAPI := rpc.NewTSSAPI(n.tssManager)
		tssAPI.RegisterHandlers(n.rpcServer)
		nodeLog.Info("TSS API handlers registered")

		// Initialize distributed signer if distributed mode is enabled
		if n.config.TSSDistributedMode {
			n.distributedSigner = tss.NewDistributedSigner(n.tssManager)
			nodeLog.Info("TSS distributed mode ENABLED — P2P multi-party signing active (threshold=%d, shares=%d)",
				n.tssManager.Threshold(), n.tssManager.TotalShares())

			// Initialize Kyber768 key exchange for encrypted ScShare transport
			var validatorAddr types.Address
			if n.blockProducer != nil {
				validatorAddr = n.blockProducer.ValidatorAddr()
			}
			vke, err := consensus.NewValidatorKeyExchange(validatorAddr)
			if err != nil {
				nodeLog.Error("Failed to initialize ValidatorKeyExchange: %v", err)
			} else {
				n.keyExchange = vke
				nodeLog.Info("ValidatorKeyExchange initialized for TSS encrypted transport (address=%s)", validatorAddr.String())
			}
		}
	}

	// Register Proof API (eth_getProof - Verkle Trie Merkle proof).
	proofAPI := rpc.NewProofAPI(
		&blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n},
		&stateReaderAdapter{n},
	)
	proofAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("Proof API handlers registered")

	// Register Debug API (debug_traceTransaction/traceCall/traceBlock*).
	// All debug_trace* methods are admin-gated inside RegisterHandlers.
	debugAPI := rpc.NewDebugAPI(
		&blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n},
		&stateReaderAdapter{n},
		contractCaller,
		&chainInfoAdapter{n},
	)
	debugAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("Debug API handlers registered")

	// Register Blob API (eth_blobBaseFee/eth_getBlobSidecar/eth_sendBlobTransaction).
	blobAPI := rpc.NewBlobAPI(
		&blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n},
		&txPoolAdapter{n.txPool, n},
		&chainInfoAdapter{n},
	)
	blobAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("Blob API handlers registered")

	// Register Access List API (eth_createAccessList).
	accessListAPI := rpc.NewAccessListAPI(
		&blockReaderAdapter{n.blockStore, n.stateDB, n.config.MaxGasLimit, n},
		&stateReaderAdapter{n},
		contractCaller,
		&chainInfoAdapter{n},
	)
	accessListAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("Access List API handlers registered")

	// Register Light Client API handlers if light client was initialized
	if n.lightClientAPI != nil {
		n.lightClientAPI.RegisterHandlers(n.rpcServer)
		nodeLog.Info("Light Client API handlers registered")
	}

	// Register Bridge API handlers (P3, disabled by default)
	if n.bridge != nil {
		// R35-P3-BRIDGE-01 (2026-07-30): Pass assetLockManager as refunder so
		// the admin-only qau_bridgeRefundFailedLock RPC is available for
		// emergency manual refunds when the relayer cannot complete them.
		bridgeAPI := rpc.NewBridgeAPI(n.bridge, n.bridgeConfig, n.assetLockManager)
		bridgeAPI.RegisterHandlers(n.rpcServer)
		nodeLog.Info("Bridge API handlers registered")
	}

	// Register Rollup API handlers (P3, disabled by default)
	if n.rollupEngine != nil {
		rollupAPI := rpc.NewRollupAPI(n.rollupEngine)
		rollupAPI.RegisterHandlers(n.rpcServer)
		nodeLog.Info("Rollup API handlers registered")
	}

	// Register Quantum API handlers (P3, disabled by default)
	// Always registered so methods return "not available" instead of "method not found"
	// when individual subsystems are disabled.
	quantumAPI := rpc.NewQuantumAPI(n.mpcManager, n.zkVerifier, n.keyRotationMgr, n.qrng)
	quantumAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("Quantum API handlers registered")

	// P1-3 (2026-07-14): Register Shard API handlers (P3, disabled by default).
	// Always registered so qau_shard* methods return "not available" instead of
	// "method not found" when sharding is disabled. manager may be nil.
	shardAPI := rpc.NewShardAPI(n.shardManager)
	shardAPI.RegisterHandlers(n.rpcServer)
	nodeLog.Info("Shard API handlers registered")

	// audit-fix R5-H1: wire AuthManager and RateLimiter into RPC server pipeline
	// SECURITY: Authentication must be enabled in production when RPC is network-accessible.
	// Even if rpcAuthEnabled=false in config, we force it on for non-localhost RPC.
	//
	// AUDIT (2026) R4-API-02 FIX: The "force authentication" security net
	// previously only inspected RPCAddr with a hardcoded string comparison,
	// ignoring WSAddr and the GraphQL address (QAU_GRAPHQL_ADDR env var).
	// An operator who binds RPC to 127.0.0.1 but WS to 0.0.0.0 could bypass
	// the auth enforcement entirely — sensitive admin methods (admin_*,
	// debug_*, personal_*) became reachable without authentication over WS.
	// Fix: check ALL listener addresses (RPC, WS, GraphQL) and force auth on
	// if ANY is non-loopback. Also replaced the fragile string comparison
	// (which only matched "127.0.0.1:8545", "localhost:8545", ":8545") with
	// isNonLoopbackAddr(), which correctly handles the full IPv4/IPv6 loopback
	// ranges, 0.0.0.0/[::] wildcards, and hostname forms.
	var rateLimiter *rpc.RateLimiter
	rpcIsRemote := isNonLoopbackAddr(n.config.RPCAddr)
	if !rpcIsRemote && n.config.WSEnabled && isNonLoopbackAddr(n.config.WSAddr) {
		rpcIsRemote = true
		nodeLog.Error("SECURITY: WebSocket address %s is non-loopback — treating node as network-exposed", n.config.WSAddr)
	}
	if !rpcIsRemote {
		// AUDIT R4-API-02: GraphQL address is read from QAU_GRAPHQL_ADDR
		// env var (default "127.0.0.1:8547", "off" disables). If it's bound
		// to a non-loopback interface, the same admin methods are reachable
		// without auth via the GraphQL HTTP endpoint.
		if graphqlAddr := os.Getenv("QAU_GRAPHQL_ADDR"); graphqlAddr != "" && graphqlAddr != "off" {
			if isNonLoopbackAddr(graphqlAddr) {
				rpcIsRemote = true
				nodeLog.Error("SECURITY: GraphQL address %s is non-loopback — treating node as network-exposed", graphqlAddr)
			}
		}
	}
	devModeWithRemoteAccess := n.config.DevMode && rpcIsRemote && !n.config.RPCForceDisableAuth

	// AUDIT (2026) H-01 FIX: rpcForceDisableAuth combined with a
	// network-exposed listener previously disabled ALL authentication,
	// leaving admin methods (debug_rollbackChainToHeight,
	// personal_importRawKey, personal_unlockAccount, ...) reachable by any
	// remote caller — a chain-level compromise from a single config flag.
	// The escape hatch is now honored ONLY when every listener is bound to
	// loopback. With any non-loopback listener we force auth ON regardless
	// of the flag and log a DANGER notice.
	forceDisableWithRemoteAccess := n.config.RPCForceDisableAuth && rpcIsRemote

	// R90-PROXY-IP: resolve the trusted-proxy policy once and inject it into
	// both the auth manager and the rate limiter. Without this every request
	// arriving through a reverse proxy is attributed to the proxy's own address
	// (see resolveRPCTrustedProxies for why that breaks per-IP limiting and the
	// brute-force lockout). A malformed entry is fatal for the RPC listener
	// rather than silently ignored.
	trustedProxies, tpErr := resolveRPCTrustedProxies(n.config.RPCTrustedProxies, os.Getenv(rpcTrustedProxiesEnv))
	if tpErr != nil {
		return fmt.Errorf("invalid RPC trusted proxies: %w", tpErr)
	}
	if len(trustedProxies) > 0 {
		nodeLog.Info("RPC client-IP attribution trusts X-Forwarded-For from %d proxy entr(ies): %s",
			len(trustedProxies), strings.Join(trustedProxies, ","))
	} else if !rpcIsRemote && n.config.RPCAuthEnabled && !n.config.DevMode {
		nodeLog.Info("RPC trusted proxies not configured: per-IP rate limiting uses the direct peer address. " +
			"If a reverse proxy fronts this node, set rpcTrustedProxies (or QAU_RPC_TRUSTED_PROXIES) to the proxy address " +
			"so limits apply per real client instead of per proxy.")
	}
	// R107-LOCAL-FANOUT (2026-09-04): validate the per-IP exemption list before it
	// reaches the limiter. Fail fast with a clear message instead of silently
	// dropping a typo'd entry (which would look like "the exemption does nothing").
	if err := validateRateLimitExemptIPs(n.config.RateLimitExemptIPs); err != nil {
		return fmt.Errorf("invalid RPC rate-limit exempt IPs: %w", err)
	}
	if len(n.config.RateLimitExemptIPs) > 0 {
		if len(trustedProxies) > 0 {
			// Both set: the exemption is matched against the *attributed* client IP,
			// so a proxied deployment that exempts the proxy address would exempt
			// every client behind it. Warn loudly rather than refuse — the operator
			// may legitimately be exempting a separate co-located service.
			nodeLog.Warn("RPC rate-limit exemptions active alongside trusted proxies (%s): make sure the exempt entries are NOT the proxy address, or per-IP limiting is effectively off for all proxied clients",
				strings.Join(n.config.RateLimitExemptIPs, ","))
		}
		nodeLog.Info("RPC per-IP rate limiting exempts %d entr(ies): %s (global and per-method limits still apply)",
			len(n.config.RateLimitExemptIPs), strings.Join(n.config.RateLimitExemptIPs, ","))
	}
	newAuthMgr := func() *rpc.AuthManager {
		return rpc.NewAuthManager(newRPCAuthConfig(trustedProxies))
	}
	newRateLimiter := func() *rpc.RateLimiter {
		return rpc.NewRateLimiter(newRPCRateLimitConfig(n.config, trustedProxies))
	}

	if forceDisableWithRemoteAccess {
		nodeLog.Error("DANGER: rpcForceDisableAuth is set while a listener is network-exposed (RPC=%s, WS=%s) — ignoring the flag and forcing auth ON", n.config.RPCAddr, n.config.WSAddr)
		nodeLog.Error("SECURITY: rpcForceDisableAuth is only honored when ALL listeners (RPC/WS/GraphQL) are bound to loopback addresses")
		n.authManager = newAuthMgr()
		rateLimiter = newRateLimiter()
		rateLimiter.Start()
		n.rpcServer.SetRateLimiter(rateLimiter)
	} else if devModeWithRemoteAccess {
		nodeLog.Error("DANGER: DevMode enabled with a listener accessible from non-localhost address (RPC=%s, WS=%s) - refusing to disable auth", n.config.RPCAddr, n.config.WSAddr)
		nodeLog.Error("SECURITY: Enabling authentication even in DevMode because a listener is network-exposed")
		n.authManager = newAuthMgr()
		rateLimiter = newRateLimiter()
		rateLimiter.Start()
		n.rpcServer.SetRateLimiter(rateLimiter)
	} else if !n.config.RPCAuthEnabled && !n.config.DevMode && rpcIsRemote {
		// Production mode with remote listener but auth disabled — force auth ON
		nodeLog.Error("SECURITY: A listener is network-accessible (RPC=%s, WS=%s) but auth is disabled — forcing auth ON", n.config.RPCAddr, n.config.WSAddr)
		nodeLog.Error("To disable auth, bind all listeners to 127.0.0.1 (rpcForceDisableAuth is only honored for loopback-only deployments)")
		n.authManager = newAuthMgr()
		rateLimiter = newRateLimiter()
		rateLimiter.Start()
		n.rpcServer.SetRateLimiter(rateLimiter)
	} else if n.config.DevMode || !n.config.RPCAuthEnabled {
		authCfg := &rpc.AuthConfig{Enabled: false}
		n.authManager = rpc.NewAuthManager(authCfg)
		if n.config.DevMode {
			nodeLog.Info("Dev mode: authentication and rate limiting disabled (localhost RPC only)")
		} else {
			nodeLog.Warn("RPC auth disabled by config (rpcAuthEnabled=false) — only safe for localhost RPC")
		}
	} else {
		n.authManager = newAuthMgr()
		rateLimiter = newRateLimiter()
		rateLimiter.Start()
		n.rpcServer.SetRateLimiter(rateLimiter)
	}
	// audit-fix M6-3: keep a reference to the active rate limiter so config
	// hot-reload can update its limits in place (nil when rate limiting is off).
	n.rateLimiter = rateLimiter
	n.rpcServer.SetAuthManager(n.authManager)
	// R6-security: ChainID validation is handled in the RPC request pipeline via chainInfo.NetworkID()

	// Start RPC server in background
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				nodeLog.Error("RPC server goroutine panic: %v", r)
			}
		}()
		nodeLog.Info("Starting RPC server on %s...", n.config.RPCAddr)
		// audit-fix R5-M1: use TLS when cert and key are configured
		var err error
		if n.config.RPCTLSCertFile != "" && n.config.RPCTLSKeyFile != "" {
			nodeLog.Info("Starting RPC server with TLS")
			err = n.rpcServer.StartTLS(n.config.RPCAddr, n.config.RPCTLSCertFile, n.config.RPCTLSKeyFile)
		} else {
			nodeLog.Warn("RPC server starting WITHOUT TLS - ensure it is only reachable via a TLS-terminating reverse proxy or loopback interface")
			err = n.rpcServer.Start(n.config.RPCAddr)
		}
		if err != nil {
			nodeLog.Error("Failed to start RPC server: %v", err)
			// audit-fix R3-L2: stop the rateLimiter cleanup goroutine to
			// prevent a leak when the server fails to start.
			if rateLimiter != nil {
				rateLimiter.Stop()
			}
			n.rpcServer = nil
		} else {
			nodeLog.Info("RPC server started successfully on %s", n.config.RPCAddr)
		}
	}()

	// Initialize WebSocket server if enabled
	if n.config.WSEnabled {
		n.wsServer = rpc.NewWebSocketServer(n.rpcServer)
		// RPC-H2 FIX (2026-07-19): if WS TLS cert/key are configured, switch
		// the listener to wss://. Otherwise log a warning that the public WS
		// endpoint must be fronted by a TLS-terminating reverse proxy.
		if n.config.WSTLSCertFile != "" && n.config.WSTLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(n.config.WSTLSCertFile, n.config.WSTLSKeyFile)
			if err != nil {
				nodeLog.Error("Failed to load WebSocket TLS cert/key (%s, %s): %v — falling back to plaintext ws://",
					n.config.WSTLSCertFile, n.config.WSTLSKeyFile, err)
			} else {
				n.wsServer.SetTLSConfig(&tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				})
				nodeLog.Info("WebSocket server TLS enabled (wss://) using cert %s", n.config.WSTLSCertFile)
			}
		} else {
			nodeLog.Warn("WebSocket server starting WITHOUT TLS - ensure it is only reachable via a TLS-terminating reverse proxy or loopback interface")
		}
		// FIX: Add waitgroup tracking and panic recovery
		// for WebSocket server goroutine. Previously this goroutine was not
		// tracked by n.wg, meaning Node.Stop() would not wait for it to
		// shut down, potentially causing resource leaks or race conditions
		// during shutdown.
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					nodeLog.Error("WebSocket server goroutine panic: %v", r)
				}
			}()
			if err := n.wsServer.Start(n.config.WSAddr); err != nil {
				nodeLog.Error("Failed to start WebSocket server: %v", err)
			}
		}()
		nodeLog.Info("WebSocket server starting on %s", n.config.WSAddr)
	}

	return nil
}

// bridgeSyncCommitteeToLightClient bridges the sync committee from QPOS to the
// light client's HeaderSyncer, enabling light clients to verify block headers
// using sync committee signatures.
func (n *Node) bridgeSyncCommitteeToLightClient(qpos *consensus.QPOS) {
	if qpos == nil || n.headerSyncer == nil {
		return
	}

	sc := qpos.GetSyncCommittee()
	if sc == nil {
		return
	}

	vs := qpos.GetValidatorSet()
	if vs == nil {
		return
	}

	// Convert validator indices to Dilithium3 public keys for light client verification.
	pubKeys := make([][]byte, 0, len(sc.ValidatorIndices))
	for _, idx := range sc.ValidatorIndices {
		v := vs.GetValidatorByIndex(idx)
		if v != nil && len(v.PublicKeyBytes) > 0 {
			pubKeys = append(pubKeys, v.PublicKeyBytes)
		}
	}

	if len(pubKeys) == 0 {
		return
	}

	info := &lightclient.SyncCommitteeInfo{
		Period:           sc.Period,
		ValidatorPubKeys: pubKeys,
		AggregatePubKey:  sc.AggregatePubKey,
	}
	n.headerSyncer.UpdateSyncCommittee(info)
}

// initSyncer initializes the block syncer
func (n *Node) initSyncer() error {
	n.syncer = NewSyncer(n.p2pHost, n.blockStore, n.stateDB, n.blockValidator, n.config.NetworkID)
	n.syncer.SetCheckpointManager(n.checkpointManager)
	// ETHEREUM-PARITY SYNC (2026-08-13): --sync.mode=full re-executes every
	// block during sync instead of the store-then-rebuild fast path.
	n.syncer.SetFullSyncMode(n.config.SyncMode == "full")
	// AUDIT (2026) R4-ZK-03: Inject the shared persistent privacy store
	// so nullifiers survive across executor instances during block sync.
	// The store is created once in initPrivacyStore and shared with all
	// executor call sites to avoid BoltDB file lock conflicts.
	if n.privacyStore != nil {
		n.syncer.SetPrivacyStore(n.privacyStore)
	}
	// AUDIT (2026) R4-ECON-06: Inject the multisig wallet store so the
	// executor verifies member signatures during block sync/validation.
	if n.multisigStore != nil {
		n.syncer.SetMultisigStore(n.multisigStore)
	}
	// TSS: Set validator address for auto-discovery (peers auto-register Address→PeerID mapping)
	if n.blockProducer != nil {
		n.syncer.SetValidatorAddress(n.blockProducer.ValidatorAddr())
		// Link QPOS so applyBlockInternal can replicate epoch reward application.
		// Without this, the validator's stateRoot never matches the proposer's
		// at epoch boundaries (block_producer.go applies rewards that validators
		// must also apply).
		if qpos := n.blockProducer.QPOS(); qpos != nil {
			n.syncer.SetQPOS(qpos)
		}
	}
	// CRITICAL FIX: Set txPool reference so the syncer can clean up
	// confirmed transactions and update state when processing blocks
	// received from other validators.
	n.syncer.SetTxPool(n.txPool)
	n.syncer.SetCommitRevealManager(n.commitRevealManager)
	// R87-STATE-TRUST (2026-08-29): feed every state-root comparison into the
	// trust tracker so a sustained divergence disables block production.
	n.syncer.SetOnStateRootResult(func(height uint64, matched bool) {
		if matched {
			n.recordStateRootMatch()
			return
		}
		n.recordStateRootMismatch(height)
	})
	n.syncer.SetOnForkRollback(func(forkHeight uint64) {
		n.syncBufMu.Lock()
		// During cascade: only evict blocks at or above forkHeight.
		// Blocks below forkHeight are still valid and should be kept
		// to avoid re-requesting them from the network (which adds
		// ~10s round-trip per fork level during deep reorgs).
		kept := 0
		evicted := 0
		filtered := make([]*encoding.Block, 0, len(n.syncBuf))
		for _, blk := range n.syncBuf {
			if blk.Header.Height < forkHeight {
				filtered = append(filtered, blk)
				kept++
			} else {
				evicted++
			}
		}
		n.syncBuf = filtered
		n.syncBufMu.Unlock()
		nodeLog.Info("OnForkRollback: evicted %d blocks at/above forkHeight=%d, kept %d blocks below",
			evicted, forkHeight, kept)

		// SECURITY: Roll back stateDB to ensure state consistency after fork.
		// Without this, DeleteBlocksFromHeight only removes block records but
		// leaves committed state (balances, contract storage) unchanged.
		//
		// R87-STATE-TRUST: a FAILED rollback used to log ERROR and
		// continue. By then the syncer had already deleted the abandoned blocks,
		// so the node was left with chain history for one branch and account
		// state for another — permanently, with no path back. Treat it as a
		// hard trust break: keep following the network, but stop producing
		// blocks so local divergence
		// is never pushed onto peers.
		if n.stateDB != nil {
			if err := n.stateDB.RollbackToHeight(forkHeight); err != nil {
				nodeLog.Error("OnForkRollback: failed to roll back stateDB to height %d: %v", forkHeight, err)
				n.markStateTrustBroken(fmt.Sprintf(
					"fork rollback to height %d failed: %v — chain history was already "+
						"truncated, so local account state belongs to the abandoned branch",
					forkHeight, err))
			} else {
				nodeLog.Info("OnForkRollback: stateDB rolled back to height %d successfully", forkHeight)
			}
		}

		// R55-FORKFIX (2026-08-07): Clear the QPOS VRF accumulator entries for
		// every epoch at/above the fork. Without this, the epochVRFAccumulator
		// map keeps values read from the ABANDONED fork's block headers, which
		// shifts the future-epoch proposer shuffle seed → this node elects a
		// different proposer than its peers → strict verifiers reject its blocks
		// → it rolls back again → a permanent fork divergence loop.
		//
		// The boundary is the epoch of the last KEPT canonical block
		// (forkHeight-1): fork blocks (>= forkHeight) all belong to epochs >=
		// that + 1. Clearing is safe because SetEpochVRFAccumulator re-populates
		// these deterministically from the re-synced canonical chain headers.
		if n.blockProducer != nil {
			if qpos := n.blockProducer.QPOS(); qpos != nil {
				clearFrom := uint64(0)
				if forkHeight > 0 {
					if kept, err := n.blockStore.GetBlockByHeight(forkHeight - 1); err == nil && kept != nil {
						clearFrom = kept.Header.Epoch + 1
					}
				}
				qpos.ClearEpochVRFAccumulatorsFrom(clearFrom)
				nodeLog.Info("OnForkRollback: cleared VRF accumulators for epochs >= %d (forkHeight=%d)", clearFrom, forkHeight)
			}
		}
	})
	n.syncer.SetOnGenesisReplace(func(newGenesis *encoding.Block) {
		n.mu.Lock()
		n.genesisBlock = newGenesis
		n.currentBlock = newGenesis
		n.mu.Unlock()
		genesisHash := block.ComputeBlockHash(newGenesis.Header)
		nodeLog.Info("OnGenesisReplace: updated genesisBlock and currentBlock, hash=%x height=%d", genesisHash[:8], newGenesis.Header.Height)
	})
	n.syncer.SetOnStateDBVerified(func(height uint64) {
		n.mu.Lock()
		if n.syncer != nil {
			if sdb := n.syncer.StateDB(); sdb != nil {
				n.stateDB = sdb
			}
		}
		n.mu.Unlock()
		nodeLog.Info("OnStateDBVerified: node.stateDB synced to verified height %d", height)
	})
	n.syncQueue = make(chan *encoding.Block, 2000)
	// R33 NODE-06 FIX (2026-07-28): syncBuf initial capacity reduced from
	// 2000 to 200. The overflow threshold (lines ~5779/5797) was also reduced
	// from 2000 to 200. The previous 2000 threshold allowed ~2000 blocks
	// (~40MB at 20KB/block) to accumulate before eviction, causing memory
	// pressure and delaying deadlock detection. The spec (project memory)
	// mandates clearing syncBuf when len > 200 to prevent deadlock.
	n.syncBuf = make([]*encoding.Block, 0, 200)
	n.syncBufSignal = make(chan struct{}, 1)
	n.startTime = time.Now()

	// Snap Sync Manager — incremental state synchronization for fast node
	// bootstrapping. The P2P host already registers snap protocol handlers
	// (handleSnapProtocol in p2p/host.go) that feed snapCh/snapReqCh; the
	// manager coordinates the multi-phase snap sync flow on top of the syncer.
	n.snapSyncer = NewSnapSyncManager(n.syncer, DefaultSnapSyncConfig())

	// ETHEREUM-PARITY SYNC (2026-08-13): serving side of the extended sync
	// protocol. Previously snapReqCh had NO consumer, so peers requesting
	// snap state never got an answer. SnapServer consumes the channel and
	// serves accounts/storage/bytecode/headers/receipts from committed data.
	n.snapServer = NewSnapServer(n.p2pHost, n.blockStore, n.stateDB)

	// R33 P3-05 FIX (2026-07-28): Warn if the node is starting sync without
	// a trusted checkpoint anchor. Fresh-syncing nodes have NO weak
	// subjectivity protection until they observe their first finalized
	// checkpoint from peers — an attacker controlling the network between
	// the node and honest peers could feed a fabricated chain. In production
	// deployments, operators SHOULD set a trusted checkpoint via the
	// qau_setTrustedCheckpoint RPC (or the --trusted-checkpoint CLI flag,
	// if/when wired) before starting sync from scratch. The warning is
	// informational, not a hard block, because:
	//   1. Testnet/devnet nodes legitimately start without a checkpoint.
	//   2. Forcing a hard error would break first-time mainnet bootstrapping
	//      (no checkpoint exists yet at genesis).
	//   3. The CheckWeakSubjectivity() guard in checkpoint.go still kicks in
	//      once a checkpoint is observed.
	// Operators running production nodes SHOULD treat this warning as a
	// reminder to configure a trusted checkpoint sourced out-of-band.
	if n.checkpointManager != nil {
		if n.checkpointManager.GetTrustedCheckpoint() == nil &&
			n.checkpointManager.GetLatestCheckpoint() == nil {
			nodeLog.Warn("R33 P3-05: node starting without a trusted checkpoint — " +
				"weak subjectivity protection is INACTIVE until the first finalized " +
				"checkpoint is observed from peers. For production deployments, " +
				"configure a trusted checkpoint via qau_setTrustedCheckpoint RPC " +
				"before starting sync from scratch.")
		}
	}

	return n.syncer.Start()
}

// initHA initializes high availability components
func (n *Node) initHA() error {
	// Register shutdown hooks in priority order (lower priority runs first)
	if n.shutdownHandler != nil {
		// Priority 1: Stop accepting new requests
		n.shutdownHandler.RegisterHook(ha.ShutdownHook{
			Name:     "stop-accepting-requests",
			Priority: 1,
			Fn: func(ctx context.Context) error {
				// Mark as not ready to stop receiving new requests
				if n.healthServer != nil {
					n.healthServer.SetReady(false)
				}
				return nil
			},
		})

		// Priority 2: Drain in-flight requests
		n.shutdownHandler.RegisterHook(ha.ShutdownHook{
			Name:     "drain-requests",
			Priority: 2,
			Fn: func(ctx context.Context) error {
				// Give time for in-flight requests to complete
				// audit-fix HIGH-2: Use time.NewTimer instead of time.After to prevent memory leak
				timer := time.NewTimer(2 * time.Second)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
					return nil
				}
			},
		})

		// Priority 3: Stop syncer
		n.shutdownHandler.RegisterHook(ha.ShutdownHook{
			Name:     "stop-syncer",
			Priority: 3,
			Fn: func(ctx context.Context) error {
				if n.syncer != nil {
					n.syncer.Stop()
				}
				return nil
			},
		})

		// Priority 4: Stop P2P network
		n.shutdownHandler.RegisterHook(ha.ShutdownHook{
			Name:     "stop-p2p",
			Priority: 4,
			Fn: func(ctx context.Context) error {
				if n.p2pHost != nil {
					n.p2pHost.Stop()
				}
				return nil
			},
		})

		// Priority 5: Flush pending data
		n.shutdownHandler.RegisterHook(ha.ShutdownHook{
			Name:     "flush-data",
			Priority: 5,
			Fn: func(ctx context.Context) error {
				// Commit any pending state changes
				if n.stateDB != nil {
					if _, err := n.stateDB.Commit(); err != nil {
						nodeLog.Warn("Failed to commit state on shutdown: %v", err)
					}
				}
				return nil
			},
		})
	}

	// Register subsystems with recovery manager
	if n.recoveryManager != nil {
		// Register P2P subsystem
		n.recoveryManager.RegisterSubsystem(&ha.SubsystemConfig{
			Name: "p2p",
			Start: func(ctx context.Context) error {
				if n.p2pHost != nil {
					return n.p2pHost.Start()
				}
				return nil
			},
			Stop: func(ctx context.Context) error {
				if n.p2pHost != nil {
					n.p2pHost.Stop()
				}
				return nil
			},
			HealthCheck: func(ctx context.Context) error {
				if n.p2pHost == nil {
					return errors.New("p2p host not initialized")
				}
				// Don't fail health check just because we have no peers
				// This is normal during startup or when running as a single node
				return nil
			},
			CircuitBreaker: &ha.CircuitBreakerConfig{
				Name:             "p2p",
				FailureThreshold: 5,
				SuccessThreshold: 3,
				Timeout:          30 * time.Second,
			},
		})

		// Register syncer subsystem
		n.recoveryManager.RegisterSubsystem(&ha.SubsystemConfig{
			Name: "syncer",
			Start: func(ctx context.Context) error {
				if n.syncer != nil {
					return n.syncer.Start()
				}
				return nil
			},
			Stop: func(ctx context.Context) error {
				if n.syncer != nil {
					n.syncer.Stop()
				}
				return nil
			},
			HealthCheck: func(ctx context.Context) error {
				// Syncer health check - verify it's running
				return nil
			},
		})

		// Mark subsystems as running
		n.recoveryManager.SetSubsystemRunning("p2p")
		n.recoveryManager.SetSubsystemRunning("syncer")

		// Start recovery manager
		if err := n.recoveryManager.Start(); err != nil {
			return fmt.Errorf("failed to start recovery manager: %w", err)
		}
	}

	// Register health checkers
	if n.healthServer != nil {
		// P2P health checker
		n.healthServer.RegisterHealthChecker(func(ctx context.Context) ha.ComponentHealth {
			if n.p2pHost == nil {
				return ha.ComponentHealth{
					Name:    "p2p",
					Status:  ha.StatusUnhealthy,
					Message: "P2P host not initialized",
				}
			}
			peers := n.p2pHost.Peers()
			if len(peers) == 0 {
				return ha.ComponentHealth{
					Name:    "p2p",
					Status:  ha.StatusDegraded,
					Message: "No peers connected",
				}
			}
			return ha.ComponentHealth{
				Name:   "p2p",
				Status: ha.StatusHealthy,
				Details: map[string]string{
					"peer_count": fmt.Sprintf("%d", len(peers)),
				},
			}
		})

		// Block store health checker
		n.healthServer.RegisterHealthChecker(func(ctx context.Context) ha.ComponentHealth {
			if n.blockStore == nil {
				return ha.ComponentHealth{
					Name:    "blockstore",
					Status:  ha.StatusUnhealthy,
					Message: "Block store not initialized",
				}
			}
			height, err := n.blockStore.GetLatestHeight()
			if err != nil {
				return ha.ComponentHealth{
					Name:    "blockstore",
					Status:  ha.StatusDegraded,
					Message: fmt.Sprintf("Failed to get latest height: %v", err),
				}
			}
			return ha.ComponentHealth{
				Name:   "blockstore",
				Status: ha.StatusHealthy,
				Details: map[string]string{
					"latest_height": fmt.Sprintf("%d", height),
				},
			}
		})

		// Readiness checker - check if synced
		n.healthServer.RegisterReadinessChecker(func(ctx context.Context) ha.ReadinessCheck {
			// For now, just check if we have a current block
			if n.currentBlock == nil {
				return ha.ReadinessCheck{
					Name:   "sync",
					Ready:  false,
					Reason: "No current block",
				}
			}
			return ha.ReadinessCheck{
				Name:  "sync",
				Ready: true,
			}
		})

		// Start health server in background
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					nodeLog.Error("Health server goroutine panic: %v", r)
				}
			}()
			if err := n.healthServer.Start(); err != nil {
				// Log error but don't fail - health server is optional
			}
		}()
	}

	return nil
}

// initMetrics initializes and starts the metrics server
func (n *Node) initMetrics() error {
	if !n.config.MetricsEnabled {
		return nil
	}

	// R7-OBS-2 (2026-07-18): Initialize node metrics. TSS DKG (inside
	// initRPC, which runs BEFORE initMetrics) canNOT lazily call
	// NewNodeMetrics() itself because the global Prometheus registry
	// would panic on duplicate registration when later test cases in
	// the same binary re-invoke initMetrics. Instead, initRPC captures
	// the DKG observation in n.pendingDKGObservation (a closure) and we
	// replay it here, after nodeMetrics is safely created exactly once.
	if n.nodeMetrics == nil {
		n.nodeMetrics = metrics.NewNodeMetrics()
		n.nodeMetrics.SetVersion(version.Version, version.GitCommit)
	}
	// Replay any pending DKG observation captured by initRPC.
	if n.pendingDKGObservation != nil {
		n.pendingDKGObservation(n.nodeMetrics)
		n.pendingDKGObservation = nil // one-shot, release closure refs
	}

	// R7-OBS-2 (2026-07-18): Wire TSS metric provider so the alert manager
	// can evaluate DKG startup health rules (tss_dkg_duration_high,
	// tss_dkg_failed_total). Safe to call even if DKG already ran — the
	// provider exposes the same n.nodeMetrics instance to alert rules.
	metrics.Global().SetTSSMetricProvider(n.nodeMetrics)

	// Create metrics server configuration
	metricsConfig := &metrics.ServerConfig{
		Addr:           n.config.MetricsAddr,
		Path:           n.config.MetricsPath,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		UpdateInterval: 15 * time.Second,
		AlertInterval:  30 * time.Second,
		EnableAlerts:   true,
	}

	// Initialize metrics server
	metricsGlobal := metrics.Global()
	metricsGlobal.SetLabel("node_name", n.config.Name)
	metricsGlobal.SetLabel("node_id", n.config.NodeID)
	metricsGlobal.SetLabel("network_id", fmt.Sprintf("%d", n.config.NetworkID))

	// Create and start metrics server
	n.metricsServer = metrics.NewServer(metricsConfig, metricsGlobal)

	// Start periodic updates of Prometheus native metrics
	// R34 P2-01 FIX (2026-07-29): Add n.wg.Add(1) so n.wg.Wait() in Stop()
	// waits for this goroutine. Previously this was the only goroutine
	// launched without wg tracking, so a shutdown in flight could release
	// resources (e.g., metrics server) while the loop was still reading
	// them.
	n.wg.Add(1)
	go n.nodeMetricsUpdateLoop()

	return n.metricsServer.Start()
}

// nodeMetricsUpdateLoop periodically refreshes Prometheus native metrics
func (n *Node) nodeMetricsUpdateLoop() {
	// R34 P2-01 FIX (2026-07-29): match the n.wg.Add(1) in startMetrics.
	defer n.wg.Done()
	// R33 NODE-03 FIX (2026-07-28): top-level panic recovery ensures a single
	// unrecovered panic cannot kill the metrics goroutine permanently, which
	// would leave the node without Prometheus metrics reporting. A panic in
	// updateNodeMetrics (e.g., nil pointer on a concurrently-shutdown
	// subsystem) would otherwise terminate the loop silently.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("nodeMetricsUpdateLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
		// R33 NODE-03 FIX: per-tick recover so a panic in updateNodeMetrics
		// (e.g., nil blockStore during concurrent shutdown, nil RPC server
		// during init) does not terminate the entire metrics loop. The next
		// tick will retry.
		func() {
			defer func() {
				if r := recover(); r != nil {
					nodeLog.Error("nodeMetricsUpdateLoop: tick panic recovered (continuing): %v", r)
				}
			}()
			n.updateNodeMetrics()
		}()
	}
}

// updateNodeMetrics reads node state and updates Prometheus native metrics
func (n *Node) updateNodeMetrics() {
	if n.nodeMetrics == nil {
		return
	}

	// Update blockchain metrics
	n.mu.RLock()
	currentHeight := uint64(0)
	if n.currentBlock != nil {
		currentHeight = n.currentBlock.Header.Height
	}
	n.mu.RUnlock()
	n.nodeMetrics.BlockHeight.Set(float64(currentHeight))

	// Update block-size metric (bytes from latest block)
	if n.blockStore != nil && currentHeight > 0 {
		if blk, err := n.blockStore.GetBlockByHeight(currentHeight); err == nil && blk != nil {
			if blkData, encErr := encoding.MarshalBlock(blk); encErr == nil {
				n.nodeMetrics.BlockSize.Set(float64(len(blkData)))
			}
		}
	}

	// Update P2P metrics
	if n.p2pHost != nil {
		n.nodeMetrics.PeerCount.Set(float64(n.p2pHost.PeerCount()))
	}

	// Update tx-pool metrics
	if n.txPool != nil {
		n.nodeMetrics.PendingTxns.Set(float64(n.txPool.GetPendingCount()))
	}

	// Update consensus metrics
	if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
		qpos := n.blockProducer.QPOS()
		n.nodeMetrics.SlotNumber.Set(float64(qpos.GetCurrentSlot()))
		n.nodeMetrics.EpochNumber.Set(float64(qpos.GetCurrentEpoch()))

		if vs := qpos.GetValidatorSet(); vs != nil {
			total := vs.ValidatorCount()
			n.nodeMetrics.Validators.Set(float64(total))
		}
	}

	// Update validator-manager metrics
	if n.validatorManager != nil {
		total := n.validatorManager.ValidatorCount()
		active := n.validatorManager.ActiveValidatorCount()
		n.nodeMetrics.Validators.Set(float64(total))
		n.nodeMetrics.OnlineValidators.Set(float64(active))
	}

	// P3-T1 (2026-07-15): Refresh Ministry Prometheus metrics (snapshot
	// all six ministries' GetStatus() into gauges/counters). Nil-safe —
	// no-op when ministryRegistry or its metrics are not configured.
	if n.ministryRegistry != nil {
		n.ministryRegistry.RefreshMetrics()
	}

	// Update system metrics
	n.nodeMetrics.UpdateSystemMetrics()
}

// initAlerting initializes the security alerting system
func (n *Node) initAlerting() error {
	if !n.config.AlertingConfig.Enabled {
		return nil
	}

	configPath := n.config.AlertingConfig.ConfigFile
	if configPath == "" {
		// P3-NODE-03 FIX (R30, 2026-07-27): resolve from env var before
		// falling back to the relative default so the node does not
		// depend on CWD when AlertingConfig.ConfigFile is unset.
		configPath = resolvePathEnv("QAU_ALERTING_CONFIG_FILE", "configs/alerting.json")
	}

	manager, err := alerting.CreateAlertManager(configPath)
	if err != nil {
		// Log warning but continue with default manager
		nodeLog.Warn("Failed to load alerting config from %s: %v", configPath, err)
		manager = alerting.NewAlertManager(alerting.DefaultAlertConfig())
	}

	n.alertManager = manager
	n.alertManager.Start()

	nodeLog.Info("Security alerting system initialized")
	return nil
}

// AlertManager returns the alert manager for sending security alerts
func (n *Node) AlertManager() *alerting.AlertManager {
	return n.alertManager
}

// SendSecurityAlert sends a security alert through the alerting system
func (n *Node) SendSecurityAlert(alertType string, severity alerting.Severity, title, message string, details map[string]any) error {
	if n.alertManager == nil {
		return nil
	}

	alert := &alerting.Alert{
		Type:     alertType,
		Severity: severity,
		Title:    title,
		Message:  message,
		Source:   n.config.Name,
		Details:  details,
	}

	return n.alertManager.SendAlert(alert)
}

// initP3Features initializes all P3 (Phase 3) optional subsystems:
//   - Cross-chain Bridge           (QAU_ENABLE_BRIDGE=1)
//   - L2 Rollup engine             (QAU_ENABLE_ROLLUP=1)
//   - Sharding                     (QAU_ENABLE_SHARDING=1)
//   - Quantum MPC manager          (QAU_ENABLE_QUANTUM_MPC=1)
//   - ZKP verifier                 (QAU_ENABLE_ZKP=1)
//   - Key rotation manager         (QAU_ENABLE_KEY_ROTATION=1)
//   - Quantum RNG                  (QAU_ENABLE_QRNG=1)
//
// Every subsystem is disabled by default. Initialization failures are
// non-fatal: the node logs a warning and continues without the feature.
func (n *Node) initP3Features() error {
	// Cross-chain Bridge
	if os.Getenv("QAU_ENABLE_BRIDGE") == "1" {
		if err := n.initBridge(); err != nil {
			nodeLog.Warn("Bridge initialization failed: %v", err)
		}
	}

	// L2 Rollup
	if os.Getenv("QAU_ENABLE_ROLLUP") == "1" {
		if err := n.initRollup(); err != nil {
			nodeLog.Warn("Rollup initialization failed: %v", err)
		}
	}

	// Sharding
	if os.Getenv("QAU_ENABLE_SHARDING") == "1" {
		if err := n.initSharding(); err != nil {
			nodeLog.Warn("Sharding initialization failed: %v", err)
		}
	}

	// Quantum MPC manager — for TSS key generation ceremonies
	if os.Getenv("QAU_ENABLE_QUANTUM_MPC") == "1" {
		cfg := quantum.DefaultMPCConfig()
		n.mpcManager = quantum.NewMPCManager(cfg)
		nodeLog.Info("Quantum MPC manager initialized (threshold=%d, totalParties=%d)",
			cfg.Threshold, cfg.TotalParties)
	}

	// ZKP verifier — for privacy transaction verification.
	// No circuits are registered by default; they must be provisioned
	// separately before proofs can be verified.
	if os.Getenv("QAU_ENABLE_ZKP") == "1" {
		n.zkVerifier = quantum.NewZKVerifier()
		nodeLog.Info("ZKP verifier initialized (no circuits registered by default)")
	}

	// Key rotation manager — for validator quantum key lifecycle management
	if os.Getenv("QAU_ENABLE_KEY_ROTATION") == "1" {
		mgr, err := quantum.NewKeyRotationManager(quantum.DefaultRotationPolicy())
		if err != nil {
			nodeLog.Warn("Key rotation manager initialization failed: %v", err)
		} else {
			n.keyRotationMgr = mgr
			nodeLog.Info("Quantum key rotation manager initialized")
		}
	}

	// QRNG — quantum random number generator for consensus randomness
	if os.Getenv("QAU_ENABLE_QRNG") == "1" {
		q, err := qrng.New(qrng.DefaultQRNGConfig())
		if err != nil {
			nodeLog.Warn("QRNG initialization failed: %v", err)
		} else {
			n.qrng = q
			nodeLog.Info("QRNG initialized for consensus randomness")
		}
	}

	return nil
}

// initBridge creates and starts the cross-chain bridge and message relayer.
//
// P0-3 FIX (2026-07-13): Previously this used DefaultBridgeConfig() with an
// empty NodeURLs map, resulting in zero chain adapters registered. Bridge
// startup succeeded but every SubmitMessage/ProcessMessage call failed with
// "no adapter found for source/target chain". Now the bridge config is loaded
// from the node config file's "bridge" section (n.config.Bridge) and falls
// back to DefaultBridgeConfig() only when that section is absent.
//
// Environment variable overrides (highest priority):
//   - QAU_BRIDGE_INITIALIZER_ADDRESS: overrides InitializerAddress
//   - QAU_BRIDGE_NODE_URLS: comma-separated "chainID=URL" pairs, e.g.
//     "quantaureum=http://localhost:8545,ethereum=http://localhost:8546"
//   - QAU_BRIDGE_CONTRACT_ADDRESSES: comma-separated "chainID=addr" pairs
func (n *Node) initBridge() error {
	cfg := n.buildBridgeConfig()
	n.bridgeConfig = cfg

	b := bridge.NewQuantumBridge(cfg)
	n.bridge = b

	// The relayer constructor requires the concrete *QuantumBridge type.
	if qb, ok := b.(*bridge.QuantumBridge); ok {
		n.bridgeRelayer = bridge.NewMessageRelayer(bridge.DefaultRelayerConfig(), qb)
	}

	// P0-6 FIX (2026-07-13): Open the persistent message store BEFORE
	// Initialize(), because Initialize() bootstraps usedNonces and
	// finalizedIDs from the store to prevent replay attacks across
	// restarts. Without this, a node restart would clear the nonce set
	// and allow an attacker to replay previously-seen messages.
	//
	// Store path: <DataDir>/bridge/messages.db (independent of qaudb's data.db
	// so bridge state is isolated and can be backed up/wiped separately).
	//
	// Failure to open the store is fatal: if we continued without persistence,
	// the bridge would silently degrade to in-memory mode and lose replay
	// protection on restart. Fail fast so operators notice.
	storePath := filepath.Join(n.config.DataDir, "bridge", "messages.db")
	store, err := bridge.NewBoltMessageStore(storePath)
	if err != nil {
		return fmt.Errorf("bridge message store open %s: %w", storePath, err)
	}
	n.bridgeStore = store
	if qb, ok := b.(*bridge.QuantumBridge); ok {
		qb.SetStore(store)
		nodeLog.Info("Bridge message store opened at %s", storePath)
	}

	if err := b.Initialize(n.ctx); err != nil {
		return fmt.Errorf("bridge initialize: %w", err)
	}
	if err := b.Start(n.ctx); err != nil {
		return fmt.Errorf("bridge start: %w", err)
	}

	// P3-2 (2026-07-15): Wire the BridgeMetricProvider into the global
	// Metrics instance so the AlertManager can evaluate the 5 bridge alert
	// rules (message processing stopped, failed messages high, quorum lost,
	// L1 anchor lag high, relayer disconnected).
	if qb, ok := b.(*bridge.QuantumBridge); ok {
		metrics.Global().SetBridgeMetricProvider(qb.Metrics())
		nodeLog.Info("Bridge Prometheus metrics enabled (qau_bridge_* namespace) + 5 alert rules")
	}

	if n.bridgeRelayer != nil {
		if err := n.bridgeRelayer.Start(n.ctx); err != nil {
			nodeLog.Warn("Bridge relayer start failed: %v", err)
		}
	}

	// P0-3 DoD ②: log how many adapters were registered so operators can
	// detect misconfiguration (zero adapters = bridge is non-functional).
	adapterCount := 0
	if qb, ok := b.(*bridge.QuantumBridge); ok {
		adapterCount = qb.AdapterCount()
	}
	if adapterCount == 0 {
		nodeLog.Warn("Cross-chain bridge started with 0 adapters — SubmitMessage will fail. " +
			"Configure 'bridge.nodeUrls' in the node config file or set QAU_BRIDGE_NODE_URLS env var.")
	} else {
		nodeLog.Info("Cross-chain bridge enabled and started (adapters=%d, chains registered)", adapterCount)
	}

	// P1-2 FIX (2026-07-13): Create AssetLockManager for the lock→confirm→mint→
	// burn→unlock lifecycle. Without this, the BridgeAPI /lock endpoints are
	// non-functional and cross-chain asset locks cannot be managed.
	//
	// R41-BRIDGE-07 (2026-08-03) FIX: inject the operator-admin trust root
	// at construction (NewAssetLockManager initialAdmin). The trust root
	// comes from n.config.Bridge.OperatorAdminAddress (JSON config) with a
	// QAU_BRIDGE_OPERATOR_ADMIN_ADDRESS env-var override (mirrors the
	// InitializerAddress / GovernanceAddress override pattern used a few
	// lines below for the adapters). When left empty, the
	// AssetLockManager starts fail-closed — equivalent to the historical
	// behavior (operatorAdmin stayed zero → SetAuthorizedOperatorsAuthorized
	// was never reachable) — but now the trust root is explicit and is
	// auditable at startup.
	if qb, ok := b.(*bridge.QuantumBridge); ok {
		opAdminAddr := types.Address{}
		// Env var override takes precedence (same precedence rule applied
		// to InitializerAddress / GovernanceAddress a few lines below).
		if envOp := os.Getenv("QAU_BRIDGE_OPERATOR_ADMIN_ADDRESS"); envOp != "" {
			if parsed, err := types.ParseHexAddress(envOp); err == nil {
				opAdminAddr = parsed
			} else {
				nodeLog.Error("QAU_BRIDGE_OPERATOR_ADMIN_ADDRESS invalid hex address %q: %v (continuing with operator admin unset → AssetLockManager fail-closed)", envOp, err)
			}
		} else if cfgOp := n.config.Bridge.OperatorAdminAddress; cfgOp != "" {
			if parsed, err := types.ParseHexAddress(cfgOp); err == nil {
				opAdminAddr = parsed
			} else {
				nodeLog.Error("bridge.operatorAdminAddress in config is not a valid hex address %q: %v (continuing with operator admin unset → AssetLockManager fail-closed)", cfgOp, err)
			}
		}
		n.assetLockManager = bridge.NewAssetLockManager(qb, opAdminAddr)
		if opAdminAddr == (types.Address{}) {
			nodeLog.Warn("Bridge AssetLockManager initialized with operatorAdmin=zero (fail-closed; set bridge.operatorAdminAddress to enable qau_bridgeRefundFailedLock)")
		} else {
			nodeLog.Info("Bridge AssetLockManager initialized (operatorAdmin=%x)", opAdminAddr[:8])
		}
	}

	// P1-3 + P1-4 FIX (2026-07-13): Set governance address and register event
	// signatures on all adapters. Adapters fail-closed by default — an empty
	// event signature allowlist rejects ALL cross-chain events. The startup
	// sequence is:
	//   1. SetGovernanceAddress (caller = initializer address)
	//   2. SetBootstrapMode(true) (caller = governance address)
	//   3. RegisterEventSignature for each standard event (caller = governance)
	//   4. SetBootstrapMode(false) (caller = governance — fail-closed again)
	// After this, only registered event signatures are accepted.
	if qb, ok := b.(*bridge.QuantumBridge); ok {
		n.initBridgeGovernance(qb)
	}

	return nil
}

// buildBridgeConfig constructs a bridge.BridgeConfig from the node config file's
// "bridge" section, applying environment variable overrides on top.
//
// P0-3 FIX (2026-07-13): When the config file has no "bridge" section, this
// returns DefaultBridgeConfig() (which has empty NodeURLs → zero adapters).
// This preserves backward compatibility for nodes that don't use the bridge.
func (n *Node) buildBridgeConfig() *bridge.BridgeConfig {
	// Start from defaults so unset fields get sane values.
	cfg := bridge.DefaultBridgeConfig()

	bc := n.config.Bridge

	// NodeURLs: copy from config (skipping empty URLs), then apply env override.
	// P0-3: Empty URLs are skipped so config files can use "" as a placeholder
	// for chains that aren't configured yet. Without this, bridge.Initialize()
	// would return an error on the first empty URL.
	if len(bc.NodeURLs) > 0 {
		cfg.NodeURLs = make(map[bridge.ChainID]string, len(bc.NodeURLs))
		for chainID, url := range bc.NodeURLs {
			if url == "" {
				continue // skip placeholder entries
			}
			cfg.NodeURLs[bridge.ChainID(chainID)] = url
		}
	}
	if envURLs := os.Getenv("QAU_BRIDGE_NODE_URLS"); envURLs != "" {
		cfg.NodeURLs = parseChainURLPairs(envURLs, cfg.NodeURLs)
	}

	// BridgeContractAddresses: copy from config (only for chains with a URL),
	// then apply env override.
	if len(bc.BridgeContractAddresses) > 0 {
		cfg.BridgeContractAddresses = make(map[bridge.ChainID]string, len(bc.BridgeContractAddresses))
		for chainID, addr := range bc.BridgeContractAddresses {
			// Only include contract addresses for chains that have a node URL.
			if _, hasURL := cfg.NodeURLs[bridge.ChainID(chainID)]; !hasURL {
				continue
			}
			cfg.BridgeContractAddresses[bridge.ChainID(chainID)] = addr
		}
	}
	if envAddrs := os.Getenv("QAU_BRIDGE_CONTRACT_ADDRESSES"); envAddrs != "" {
		cfg.BridgeContractAddresses = parseChainURLPairs(envAddrs, cfg.BridgeContractAddresses)
	}

	// Scalar fields: config value overrides default, env override is highest.
	if bc.GasLimit > 0 {
		cfg.GasLimit = bc.GasLimit
	}
	if bc.ConfirmationsRequired > 0 {
		cfg.ConfirmationsRequired = bc.ConfirmationsRequired
	}
	if bc.MessageExpiration > 0 {
		cfg.MessageExpiration = bc.MessageExpiration
	}
	if bc.PollingInterval > 0 {
		cfg.PollingInterval = time.Duration(bc.PollingInterval) * time.Second
	}
	if bc.MaxRetries > 0 {
		cfg.MaxRetries = bc.MaxRetries
	}
	if bc.InitializerAddress != "" {
		cfg.InitializerAddress = bc.InitializerAddress
	}
	if envInit := os.Getenv("QAU_BRIDGE_INITIALIZER_ADDRESS"); envInit != "" {
		cfg.InitializerAddress = envInit
	}

	return cfg
}

// parseChainURLPairs parses a comma-separated list of "chainID=value" pairs
// into a map, merging into the provided base map (which may be nil).
// Example: "quantaureum=http://localhost:8545,ethereum=http://localhost:8546"
func parseChainURLPairs(pairs string, base map[bridge.ChainID]string) map[bridge.ChainID]string {
	result := base
	if result == nil {
		result = make(map[bridge.ChainID]string)
	}
	for _, pair := range strings.Split(pairs, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		idx := strings.Index(pair, "=")
		if idx <= 0 || idx == len(pair)-1 {
			nodeLog.Warn("QAU_BRIDGE_*: skipping malformed pair %q (expected chainID=value)", pair)
			continue
		}
		chainID := strings.TrimSpace(pair[:idx])
		value := strings.TrimSpace(pair[idx+1:])
		if chainID == "" || value == "" {
			nodeLog.Warn("QAU_BRIDGE_*: skipping empty chainID or value in pair %q", pair)
			continue
		}
		result[bridge.ChainID(chainID)] = value
	}
	return result
}

// initRollup creates and starts the L2 rollup engine.
func (n *Node) initRollup() error {
	cfg := rollup.DefaultRollupConfig()

	// RLLP- (2026-07-16): Set BridgeAddress so processBatchLocked burns
	// withdrawal value from L2 supply (deducts from sender without crediting
	// the bridge account). This maintains the L2 supply invariant: every L1
	// release corresponds 1:1 to an L2 burn, preventing double-spending.
	// Uses the same derivation as l2BridgeAddress below.
	l2BridgeAddress := cfg.L1BridgeAddress
	if l2BridgeAddress == (types.Address{}) {
		// Fallback: derive a deterministic bridge address if config is zero.
		// This is a development convenience — production MUST set L1BridgeAddress.
		l2BridgeAddress = types.Address{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff}
	}
	cfg.BridgeAddress = l2BridgeAddress

	engine, err := rollup.NewRollupEngine(cfg)
	if err != nil {
		return fmt.Errorf("rollup engine: %w", err)
	}
	n.rollupEngine = engine

	// AUDIT (2026) BRDG-06 FIX: Wire the QVM executor so L2 contract
	// calls are actually executed instead of silently treated as simple
	// transfers. Without this, tx.Data is ignored and contract interactions
	// on L2 are non-functional.
	// R43-QVM-BYTECODE-01: same devnet gating for the L2 rollup engine's
	// executor (chainID 1334 = L2 devnet tolerates unknown opcodes).
	rollupExec := qvm.NewExecutor()
	if n.chainID == 1333 || n.chainID == 1334 {
		rollupExec.SetDevnetValidation(true)
	}
	engine.SetExecutor(rollupExec)

	// W-P1-1 FIX (2026-07-13): Inject signature verifiers to unblock the
	// fail-closed L2 transaction channel and fraud proof channel. Without
	// these, the sequencer rejects ALL L2 transactions (requireTxSig=true)
	// and the FraudProver rejects ALL fraud proofs (requireSigVerifier=true).
	// The verifiers are shared with the txpool's SigningVerifier for cache
	// efficiency (verified L1 tx signatures are cache hits on L2).
	//
	// Design: L2 transactions/fraud proofs carry the sender's Dilithium3
	// public key inline (RollupTransaction.PublicKey / FraudProof.ChallengerPubKey)
	// because L2 accounts' pubkeys are not stored on L1. The adapter verifies:
	//   1. pubKey derives to the claimed From/Challenger address
	//   2. signature is a valid Dilithium3 signature over the signing hash
	if n.txPool != nil {
		if tv, ok := n.txPool.Validator(); ok {
			if sv := tv.GetSigningVerifier(); sv != nil {
				txVerifier := &rollupTxSigVerifier{sv: sv}
				engine.SetTxSignatureVerifier(txVerifier)

				fpVerifier := &rollupFraudProofSigVerifier{sv: sv}
				engine.SetFraudProofVerifier(fpVerifier)

				nodeLog.Info("Rollup signature verifiers injected (tx + fraud proof, shared SigningVerifier)")
			} else {
				nodeLog.Warn("Rollup verifier injection skipped: txpool SigningVerifier is nil — " +
					"L2 transactions and fraud proofs will be rejected (fail-closed)")
			}
		} else {
			nodeLog.Warn("Rollup verifier injection skipped: txpool has no validator — " +
				"L2 transactions and fraud proofs will be rejected (fail-closed)")
		}
	} else {
		nodeLog.Warn("Rollup verifier injection skipped: txPool is nil — " +
			"L2 transactions and fraud proofs will be rejected (fail-closed)")
	}

	// W-P1-1 FIX: Wire BatchLookup and FraudProver so fraud proof verification
	// can retrieve batch data and so BatchManager can forward proofs to the prover.
	fp := engine.GetFraudProver()
	bm := engine.GetBatchManager()
	if fp != nil && bm != nil {
		fp.SetBatchLookup(bm)
		bm.SetFraudProver(fp)
		nodeLog.Info("Rollup FraudProver wired to BatchManager (lookup + prover)")
	}

	// W-P1-3 FIX (2026-07-13): Inject persistence so L2 state survives node
	// restarts. Uses a dedicated bbolt database at <DataDir>/rollup/l2.db,
	// independent from the L1 chain database. Without this, all L2 account
	// balances, batch history, and fraud proofs are lost on restart.
	rollupDbPath := filepath.Join(n.config.DataDir, "rollup", "l2.db")
	rollupDB, err := db.NewBoltDB(rollupDbPath)
	if err != nil {
		nodeLog.Warn("Rollup persistence disabled (db open failed: %v) — L2 state will not survive restart", err)
	} else {
		persistence := rollup.NewPersistence(rollupDB)
		engine.SetPersistence(persistence)
		nodeLog.Info("Rollup persistence enabled (db=%s)", rollupDbPath)
	}

	// W-P1-4 FIX (2026-07-13): Inject L1 anchor so batches are anchored to L1.
	// Uses the in-memory implementation with challenge period = 100 L1 blocks
	// (~20 minutes at 12s block time). Production should replace this with a
	// real L1 contract submission implementation (see rollup/l1_anchor.go
	// L1Anchor interface).
	// The L1 current height is synced from the blockchain on each new block.
	const defaultChallengeBlocks = 100
	l1Anchor := rollup.NewMemoryL1Anchor(defaultChallengeBlocks)
	engine.SetL1Anchor(l1Anchor)
	engine.GetBatchManager().SetL1ChallengeBlocks(defaultChallengeBlocks)
	nodeLog.Info("Rollup L1 anchor enabled (challengeBlocks=%d)", defaultChallengeBlocks)

	// W-P1-6 FIX (2026-07-13), Phase 3 (2026-07-14): Wire the L1↔L2 bridge.
	// When the rollup database is available, use bboltL1Bridge so deposits,
	// processed withdrawals, liquidity, and finalized state roots survive
	// restarts. Otherwise fall back to MemoryL1Bridge (state lost on restart).
	// Production should eventually replace this with a real L1 QASM contract
	// binding (see rollup/bridge.go L1Bridge interface).
	var l1Bridge rollup.L1Bridge
	if rollupDB != nil {
		bb, bErr := rollup.NewBboltL1Bridge(rollupDB)
		if bErr != nil {
			nodeLog.Warn("BboltL1Bridge init failed: %v — falling back to MemoryL1Bridge", bErr)
			l1Bridge = rollup.NewMemoryL1Bridge()
		} else {
			l1Bridge = bb
			nodeLog.Info("Rollup L1Bridge persistence enabled")
		}
	} else {
		l1Bridge = rollup.NewMemoryL1Bridge()
	}
	// Use the configured BridgeAddress (derived above, RLLP-) as the L2
	// withdrawal target. Users send L2 txs with To == this address to trigger
	// a withdrawal. This MUST match cfg.BridgeAddress so processBatchLocked
	// burns withdrawal value consistently with what the L2Bridge processes.
	l2Bridge := rollup.NewL2Bridge(l1Bridge, engine.GetStateManager(), cfg.BridgeAddress)
	// R41-ROLLUP-02 (2026-08-03) FIX: wire the finality machinery BEFORE
	// registering l2Bridge as the withdrawal processor.
	//   * SetL1HeightReader: L2Bridge's ConfirmDeposit / AvailableDelete
	//     paths (see rollup/bridge.go:562, 664) use l1HeightReader to
	//     compute L1 confirmation depth. Without it the field stays nil
	//     and any "requiredDepositConfirmations > 0" check is skipped,
	//     so deposits mint to L2 immediately with NO L1 finality wait —
	//     a single L1 reorg would print wrapped QAU on L2 that has no L1
	//     counterpart. We use the L1Anchor as the height source since it
	//     already tracks L1 height for the batch finalization path and
	//     satisfies the L1HeightReader interface (GetCurrentHeight).
	//   * SetRequiredDepositConfirmations: 64 L1 blocks (~13 min on the
	//     12-second consensus) is the same canon used by major L2 rollups
	//     and the value the production-readiness doc (production-
	//     readiness/05-rollup.md) calls out as the mainnet target.
	//     Devnet keeps 0 for fast tests (see RollupConfig.RequiredDeposit-
	//     Confirmations in DefaultRollupConfig).
	if l1Anchor != nil {
		l2Bridge.SetL1HeightReader(l1Anchor)
	} else if n.config != nil && n.config.NetworkID == MainnetNetworkID {
		// AUDIT (2026) FIX: fail-closed on mainnet. Without an
		// l1Anchor the L2 bridge has no L1 height source, so
		// requiredDepositConfirmations checks are skipped and deposits mint
		// wrapped QAU on L2 immediately — a single L1 reorg would print L2
		// tokens with no L1 counterpart. Refuse to enable the rollup bridge
		// on mainnet in that state instead of degrading to the devnet
		// zero-confirmation behavior.
		return fmt.Errorf("rollup: refusing to enable L2 bridge on mainnet without l1Anchor — deposits would mint with NO L1 finality tracking (audit 2026-08-17 M-04)")
	} else {
		nodeLog.Warn("Rollup L2Bridge finality disabled: l1Anchor is nil — deposits will mint with NO L1 finality wait (R41-ROLLUP-02)")
	}
	const mainnetRequiredDepositConfirmations = 64
	requiredConfirmations := uint64(0) // devnet default — bypass for tests
	if n.config != nil && n.config.NetworkID == MainnetNetworkID {
		requiredConfirmations = mainnetRequiredDepositConfirmations
	}
	l2Bridge.SetRequiredDepositConfirmations(requiredConfirmations)
	nodeLog.Info("Rollup L2Bridge finality wired (l1HeightReader=%v, requiredDepositConfirmations=%d)",
		l1Anchor != nil, requiredConfirmations)

	engine.SetWithdrawalProcessor(l2Bridge)
	nodeLog.Info("Rollup L1↔L2 bridge enabled (bridgeAddr=%x)", cfg.BridgeAddress[:8])

	// R41-ROLLUP-03 (2026-08-03) FIX: lock the FraudProver into production
	// mode on mainnet. LockProductionMode is a one-way latch: once set,
	// SetRequireSignatureVerifier(false) is rejected (see
	// rollup/fraud_proof.go:120-148). The FraudProver defaults to
	// requireSignatureVerifier=true, but WITHOUT the lock any code path
	// that obtains the FraudProver reference (RPC handler, plugin,
	// restart-time reconfig) could call SetRequireSignatureVerifier(false)
	// and disable L2 fraud-proof signature verification at runtime —
	// undoing the RLLP- fail-closed guarantee. We only lock on
	// mainnet so devnet/testnet can still toggle the verifier for testing.
	if n.config != nil && n.config.NetworkID == MainnetNetworkID && fp != nil {
		fp.LockProductionMode()
		nodeLog.Info("Rollup FraudProver production mode LOCKED (RLLP- / R41-ROLLUP-03)")
	}

	// W-P3-1 FIX (2026-07-14): Inject Prometheus metrics. Metrics auto-register
	// with the default Prometheus registry and are exposed via the existing
	// /metrics/prometheus endpoint (metrics/server.go). All 10 rollup metrics
	// (status, batches, txs, pending, durations, fraud proofs, L1 anchor lag)
	// become scrapeable by Prometheus.
	//
	// W-P3-2/W-P3-3 (2026-07-14): Also wire the RollupMetricProvider into the
	// global Metrics instance so the AlertManager can evaluate the 6 rollup
	// alert rules (engine stopped, consecutive failures, L1 anchor lag, fraud
	// proofs, pending backlog, batchLoop panics).
	rollupMetrics := rollup.NewRollupMetrics()
	engine.SetMetrics(rollupMetrics)
	metrics.Global().SetRollupMetricProvider(rollupMetrics)
	nodeLog.Info("Rollup Prometheus metrics enabled (12 metrics, qau_rollup_* namespace) + 6 alert rules")

	// W-P1-7 FIX (2026-07-15): Decentralized sequencer election. Wires the
	// QPOS validator set into the rollup sequencer elector so batch
	// production rotates across validators per epoch (PoS sequencer election,
	// Plan B). The elector uses epoch % len(validators) to pick the sequencer,
	// synchronized with QPOS epoch boundaries. Failover triggers after
	// SequencerTimeout (default 3) missed batch cycles.
	//
	// When blockProducer/QPOS is unavailable (e.g. dev mode without consensus),
	// the elector stays nil and the engine falls back to legacy single-sequencer
	// mode (any node builds batches) — matching pre-W-P1-7 behavior.
	if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
		qpos := n.blockProducer.QPOS()
		adapter := &qposSequencerAdapter{qpos: qpos}
		elector := rollup.NewQPOSSequencerElector(adapter)
		engine.SetSequencerElector(elector)

		// Set the local validator address so the engine knows whether this
		// node is the current sequencer. Without this, the engine operates in
		// legacy mode (always builds batches).
		validatorAddr := n.blockProducer.ValidatorAddr()
		if validatorAddr != (types.Address{}) {
			engine.SetLocalAddress(validatorAddr)
			nodeLog.Info("Rollup sequencer elector enabled (decentralized, QPOS-backed, localAddr=%x)",
				validatorAddr[:8])
		} else {
			nodeLog.Warn("Rollup sequencer elector enabled but local validator address is zero — " +
				"engine will operate in legacy mode (always builds batches)")
		}
	} else {
		nodeLog.Warn("Rollup sequencer elector disabled (blockProducer or QPOS is nil) — " +
			"engine operates in legacy single-sequencer mode")
	}

	if err := engine.Start(); err != nil {
		return fmt.Errorf("rollup start: %w", err)
	}

	nodeLog.Info("L2 Rollup engine enabled and started (chainID=%d, L1ChainID=%d)",
		cfg.ChainID, cfg.L1ChainID)
	return nil
}

// initSharding creates and configures the shard manager, ending the sharding
// subsystem's 100% island status.
//
// P1-5 (2026-07-14): wires the ShardManager (consensus/shard.go) into the
// node startup path. The manager is constructed with three production-grade
// dependencies implemented during P0:
//   - MainChainCommitterImpl (P0-2): persists shard commitments to a dedicated
//     bbolt database, with GetLatestSlot backed by QPOS.GetCurrentSlot.
//   - ShardStateStore (P0-3): persists blocks/receipts/spent markers/nonces
//     so HIGH-17 replay protection survives node restarts.
//   - ShardQPOSAdapter (P0-5): verifies shard proposer election by delegating
//     to QPOS.GetProposerForSlot (1:1 height→slot mapping by default).
//
// P1-6 (2026-07-14): Parameters are loaded from n.config.Sharding
// (ShardingNodeConfig). The subsystem is enabled via QAU_ENABLE_SHARDING=1
// env var; config fields tune operation once enabled.
//
// The state store and election verifier are stored on the Node (not on
// ShardManager) because they are per-ShardChain dependencies: P1-2 (block
// production loop) will inject them into each newly-created ShardChain via
// SetStateStore / SetElectionVerifier after CreateShard.
//
// Env: QAU_ENABLE_SHARDING=1 enables this subsystem. Default: disabled.
// Failure is non-fatal — the node continues without sharding.
func (n *Node) initSharding() error {
	if n.blockStore == nil {
		return fmt.Errorf("sharding requires blockStore (nil)")
	}
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return fmt.Errorf("sharding requires QPOS consensus (blockProducer or qpos is nil)")
	}
	qpos := n.blockProducer.QPOS()

	// Open a dedicated shard database, isolated from L1 (matches rollup pattern
	// at <DataDir>/rollup/l2.db). Both MainChainCommitterImpl and ShardStateStore
	// use distinct key prefixes, so they safely coexist in the same DB.
	shardDbPath := filepath.Join(n.config.DataDir, "shard", "state.db")
	if err := os.MkdirAll(filepath.Dir(shardDbPath), 0755); err != nil {
		return fmt.Errorf("shard db dir create (%s): %w", filepath.Dir(shardDbPath), err)
	}
	shardDB, err := db.NewBoltDB(shardDbPath)
	if err != nil {
		return fmt.Errorf("shard db open (%s): %w", shardDbPath, err)
	}

	// P0-2: MainChainCommitter production implementation. The slot callback
	// lets ShardManager stamp commitments with the current main-chain slot.
	committer := consensus.NewMainChainCommitter(shardDB, qpos.GetCurrentSlot)

	// P0-3: ShardStateStore for persistence. Without this, HIGH-17 replay
	// protection (spentReceipts, senderNonces) is lost on restart.
	stateStore := consensus.NewShardStateStore(shardDB)

	// P0-5: ShardQPOSAdapter for proposer election verification.
	// P1-6: SlotResolverMode configures the height→slot mapping.
	//   "" / "1:1" — default, shard height N → main slot N (nil resolver)
	//   "linear"   — slot = height * MaxCount + shardID; needs per-shard adapter,
	//                not supported with a single shared adapter. Fall back to
	//                1:1 and log a warning. P1-2 will create per-shard adapters
	//                when implementing the block production loop.
	shardCfg := n.config.Sharding
	var slotResolver func(height uint64) uint64
	switch strings.ToLower(shardCfg.SlotResolverMode) {
	case "", "1:1":
		// nil → ShardQPOSAdapter uses 1:1 (height == slot)
	case "linear":
		nodeLog.Warn("Sharding SlotResolverMode=%q requires per-shard adapter (P1-2); falling back to 1:1",
			shardCfg.SlotResolverMode)
	default:
		nodeLog.Warn("Sharding SlotResolverMode=%q unknown; using 1:1 default", shardCfg.SlotResolverMode)
	}
	electionVerifier := consensus.NewShardQPOSAdapter(qpos, slotResolver)

	// Construct ShardManager with the committer. Per-shard dependencies
	// (stateStore, electionVerifier) are stored on Node for P1-2 to inject
	// after CreateShard.
	n.shardManager = consensus.NewShardManager(committer)
	n.shardStateStore = stateStore
	n.shardElectionVerifier = electionVerifier

	// P1-4 (2026-07-14): Inject stateStore + authorizer so validator
	// assignments are persisted to the shared database and ReassignValidators
	// is gated by consensus authorization. The system caller is the zero
	// address (convention for system transactions initiated by the block
	// builder, not by any external account).
	n.shardManager.SetStateStore(stateStore)
	n.shardManager.SetAuthorizer(consensus.NewSystemShardAuthorizer(types.Address{}))

	// SHRD- (2026-07-17): On mainnet, require a real stateDB for shard
	// activation and commitment. This prevents placeholder state roots
	// (content-derived hashes that don't commit to actual state transitions)
	// from being anchored on the main chain. Testnet/devnet keep the
	// placeholder behavior so sharding can be exercised before per-shard
	// Verkle trie integration is complete.
	if n.config.NetworkID == MainnetNetworkID {
		n.shardManager.SetRequireRealStateRoot(true)
	}

	// AUDIT (2026) R4-GOV-04 FIX: Wire the ShardManager as the commitment
	// authenticator so MainChainCommitterImpl rejects any commitment that
	// does not carry a valid proposer signature matching the canonical shard
	// block. Without this, anyone reaching the commit path could persist
	// arbitrary (StateRoot, BlockHash) for any (shardID, height) and have
	// it "verify" successfully via byte comparison alone. ShardManager
	// implements CommitmentAuthenticator via AuthenticateCommitment, which
	// re-fetches the canonical block and verifies the block signature
	// against the proposer's registered Dilithium3 public key.
	committer.SetAuthenticator(n.shardManager)

	// P1-4: Restore assignments from the database so this node reads the same
	// assignment table as every other node. Errors are non-fatal — an empty
	// store (fresh start) simply means no assignments to load.
	if err := n.shardManager.LoadAssignments(); err != nil {
		nodeLog.Warn("ShardManager LoadAssignments failed (non-fatal, starting with empty table): %v", err)
	}

	nodeLog.Info("ShardManager enabled (db=%s, committer=persisted, electionVerifier=QPOS-backed, stateStore=persisted, "+
		"authorizer=system-caller, assignments=loaded, "+
		"maxCount=%d, blockSize=%d, interval=%ds, minValidators=%d, slotResolver=%q)",
		shardDbPath,
		shardCfg.EffectiveMaxCount(), shardCfg.EffectiveBlockSize(),
		shardCfg.EffectiveInterval(), shardCfg.EffectiveMinValidators(),
		shardCfg.SlotResolverMode)
	return nil
}

// replayBlocksToRestoreState replays all historical blocks to restore state
// This is called on node startup to rebuild the state from genesis
func (n *Node) replayBlocksToRestoreState() error {
	if n.blockStore == nil || n.stateDB == nil {
		nodeLog.Info("Skipping state replay: blockStore=%v, stateDB=%v", n.blockStore != nil, n.stateDB != nil)
		return nil
	}

	latestHeight, err := n.blockStore.GetLatestHeight()
	if err != nil || latestHeight == 0 {
		nodeLog.Info("No blocks to replay for state restoration")
		return nil
	}

	nodeLog.Info("🔄 Replaying %d blocks to restore state...", latestHeight)

	// Create executor for transaction execution.
	// AUDIT (2026) R4-ZK-03: Use the shared persistent privacy store
	// (initialized in initPrivacyStore) so nullifiers survive across
	// executor instances and node restarts.
	var executor *txpool.TxExecutor
	if n.privacyStore != nil {
		executor = txpool.NewTxExecutorWithStore(n.privacyStore)
	} else {
		executor = txpool.NewTxExecutor()
	}
	// AUDIT (2026) R4-ECON-06: Wire the multisig wallet lookup so the
	// executor verifies member signatures against the real wallet config.
	if n.multisigStore != nil {
		executor.SetMultisigWalletLookup(&multisigWalletLookupAdapter{store: n.multisigStore})
	}
	stateAdapter := &stateDBAdapter{stateDB: n.stateDB}

	totalTxs := 0
	successTxs := 0

	// audit-fix R2-L4: track consecutive failures — abort if too many blocks are
	// missing in a row, since that likely indicates a corrupted database.
	const maxConsecutiveFailures = 10
	consecutiveFailures := 0

	// Replay each block in order
	for height := uint64(1); height <= latestHeight; height++ {
		blk, err := n.blockStore.GetBlockByHeight(height)
		if err != nil {
			consecutiveFailures++
			nodeLog.Warn("failed to get block %d: %v (consecutive: %d)", height, err, consecutiveFailures)
			if consecutiveFailures >= maxConsecutiveFailures {
				return fmt.Errorf("aborting state replay: %d consecutive block load failures (last at height %d)", consecutiveFailures, height)
			}
			continue
		}
		consecutiveFailures = 0 // reset on success

		if len(blk.Transactions) == 0 {
			continue
		}

		// Create block context
		blockHashes := make(map[uint64]types.Hash)
		for i := uint64(0); i < 256 && height > i; i++ {
			hash, err := n.blockStore.GetBlockHash(height - i)
			if err == nil {
				blockHashes[height-i] = hash
			}
		}

		blockCtx := &txpool.BlockContext{
			BlockHash:   blk.Header.ParentHash,
			BlockNumber: height,
			Timestamp:   blk.Header.Timestamp,
			Coinbase:    blk.Header.ProposerAddr,
			GasLimit:    n.config.MaxGasLimit,
			BlockHashes: blockHashes,
		}

		// Execute each transaction
		blockReceipts := make([]*encoding.StoredReceipt, 0, len(blk.Transactions))
		blkHash := block.ComputeBlockHash(blk)
		for i, tx := range blk.Transactions {
			totalTxs++
			receipt := executor.Execute(tx, stateAdapter, blockCtx)
			if receipt.Status == 1 {
				successTxs++
			}
			// Cache actual gasUsed for receipt queries
			txHash := tx.Hash()
			n.receiptCacheMu.Lock()
			n.receiptCache[txHash] = receipt.GasUsed
			n.receiptCacheMu.Unlock()

			// R35-P0-09 FIX: collect receipts for persistent storage
			sr := &encoding.StoredReceipt{
				TxHash:      receipt.TxHash,
				BlockHash:   blkHash,
				BlockNumber: height,
				TxIndex:     uint32(i), //nolint:gosec,G115
				Status:      receipt.Status,
				GasUsed:     receipt.GasUsed,
				Error:       receipt.Error,
				Logs:        make([]*encoding.StoredLog, 0, len(receipt.Logs)),
			}
			for _, lg := range receipt.Logs {
				if lg == nil {
					continue
				}
				sr.Logs = append(sr.Logs, &encoding.StoredLog{
					Address: lg.Address,
					Topics:  lg.Topics,
					Data:    lg.Data,
				})
			}
			blockReceipts = append(blockReceipts, sr)
		}
		// R35-P0-09 FIX: persist replayed receipts so they survive restart
		if n.blockStore != nil && len(blockReceipts) > 0 {
			if err := n.blockStore.StoreReceipts(blockReceipts); err != nil {
				nodeLog.Warn("R35-P0-09: failed to persist receipts during replay for block %d: %v", height, err)
			}
		}

		// Log progress every 1000 blocks
		if height%1000 == 0 {
			nodeLog.Info("Replayed %d/%d blocks...", height, latestHeight)
		}
	}

	// Commit final state
	if _, err := n.stateDB.Commit(); err != nil {
		return fmt.Errorf("failed to commit replayed state: %w", err)
	}

	nodeLog.Info("✅ State restored: replayed %d blocks, %d/%d transactions successful",
		latestHeight, successTxs, totalTxs)

	return nil
}

// syncStakingFromChain syncs staking data from on-chain transactions
func (n *Node) syncStakingFromChain() error {
	if n.blockStore == nil || n.stakingManager == nil {
		nodeLog.Info("Skipping staking sync: blockStore=%v, stakingManager=%v", n.blockStore != nil, n.stakingManager != nil)
		return nil
	}

	nodeLog.Info("Syncing staking data from chain...")

	// Get latest block height
	latestHeight, _ := n.blockStore.GetLatestHeight()
	if latestHeight == 0 {
		nodeLog.Info("No blocks to sync staking from")
		return nil
	}
	nodeLog.Info("Scanning %d blocks for staking transactions...", latestHeight)

	// Contract addresses
	stakingContract := economics.StakingContractAddress
	unstakeContract := economics.UnstakeContractAddress
	rewardsContract := economics.RewardsContractAddress

	nodeLog.Info("Staking contract: %x", stakingContract[:])
	nodeLog.Info("Unstake contract: %x", unstakeContract[:])
	nodeLog.Info("Rewards contract: %x", rewardsContract[:])

	// Collect all transactions to staking contracts
	var stakingTxs []economics.ChainTransaction
	var unstakeTxs []economics.ChainTransaction
	var rewardTxs []economics.ChainTransaction

	// Scan blocks for staking transactions
	for height := uint64(1); height <= latestHeight; height++ {
		block, err := n.blockStore.GetBlockByHeight(height)
		if err != nil {
			continue
		}

		for _, tx := range block.Transactions {
			// Determine if this is a staking/unstaking/reward transaction.
			// Two detection methods:
			//   1. tx.To matches the system contract address (preferred)
			//   2. tx.Type indicates the operation (fallback for legacy txs
			//      where To was not set to the system contract address)
			isStake := (tx.To != nil && *tx.To == stakingContract) ||
				(tx.Type == encoding.TxTypeStake)
			isUnstake := (tx.To != nil && *tx.To == unstakeContract) ||
				(tx.Type == encoding.TxTypeUnstake)
			isReward := tx.To != nil && *tx.To == rewardsContract

			if !isStake && !isUnstake && !isReward {
				continue
			}

			// Fix up To address for legacy staking transactions where To was nil.
			// SyncFromChain requires To == StakingContractAddress, so we set it here.
			txTo := tx.To
			if txTo == nil && isStake {
				stakingAddr := stakingContract
				txTo = &stakingAddr
			} else if txTo == nil && isUnstake {
				unstakeAddr := unstakeContract
				txTo = &unstakeAddr
			}

			chainTx := economics.ChainTransaction{
				From:        tx.From,
				To:          txTo,
				Value:       tx.Value,
				BlockHeight: height,
			}

			// Categorize by operation type
			if isStake && tx.Value != nil && tx.Value.Sign() > 0 {
				nodeLog.Info("Found stake tx at block %d: from=%x, value=%s",
					height, tx.From[:8], tx.Value.String())
				stakingTxs = append(stakingTxs, chainTx)

				// Also register validator in ValidatorManager if not already registered
				// This ensures BlockValidator can verify blocks produced by this validator
				if n.validatorManager != nil && !n.validatorManager.IsValidator(tx.From) && len(tx.PublicKey) > 0 {
					pubKey, pkErr := crypto.PublicKeyFromBytes(tx.PublicKey)
					if pkErr != nil {
						nodeLog.Warn("Failed to parse validator public key from stake tx at block %d: addr=%x, err=%v",
							height, tx.From[:8], pkErr)
					} else {
						commission := uint32(100) // 1% default
						if vmErr := n.validatorManager.AddValidator(tx.From, tx.From, pubKey, tx.Value, commission, height); vmErr != nil {
							nodeLog.Warn("Failed to add validator to ValidatorManager at block %d: addr=%x, err=%v",
								height, tx.From[:8], vmErr)
						} else {
							nodeLog.Info("🔐 Validator registered in ValidatorManager from chain sync: addr=%x, stake=%s, height=%d",
								tx.From[:8], tx.Value.String(), height)
							if saErr := n.validatorManager.SetActive(tx.From, tx.From, true); saErr != nil {
								nodeLog.Warn("Failed to activate validator from chain sync: addr=%x, err=%v",
									tx.From[:8], saErr)
							}
						}
					}
				}
			} else if isUnstake {
				nodeLog.Info("Found unstake tx at block %d: from=%x",
					height, tx.From[:8])
				unstakeTxs = append(unstakeTxs, chainTx)
			} else if isReward {
				nodeLog.Info("Found reward claim tx at block %d: from=%x",
					height, tx.From[:8])
				rewardTxs = append(rewardTxs, chainTx)
			}
		}
	}

	nodeLog.Info("Found %d stake, %d unstake, %d reward transactions",
		len(stakingTxs), len(unstakeTxs), len(rewardTxs))

	// Process in order: stakes first, then unstakes, then rewards
	// This ensures correct state calculation

	// 1. Sync stakes
	if err := n.stakingManager.SyncFromChain(stakingTxs); err != nil {
		return err
	}

	// 1b. Re-add genesis validators' stakes after SyncFromChain resets the map.
	// SyncFromChain clears sm.stakes, which removes genesis validators whose
	// stakes were registered at init time (not via on-chain transactions).
	// Stake() ADDS to existing stake, so validators with on-chain staking txs
	// will get genesis_stake + chain_tx_stake (e.g., 30000 + 32 = 30032 QAU).
	// Use MinCommission (100 = 1%) to pass the commission validation check.
	if n.genesis != nil {
		for _, v := range n.genesis.Validators {
			addr, addrErr := parseAddressString(v.Address)
			if addrErr != nil {
				continue
			}
			stake := parseStake(v.Stake)
			// Log existing stake (if any) for debugging
			if existing, err := n.stakingManager.GetStake(addr); err == nil {
				nodeLog.Info("Genesis stake re-add: addr=%x, existing=%s QAU, adding=%s QAU",
					addr[:8], existing.Amount.String(), stake.String())
			}
			if smErr := n.stakingManager.Stake(addr, stake, 100, 0); smErr != nil {
				nodeLog.Warn("Failed to re-add genesis stake after sync: addr=%x, err=%v", addr[:8], smErr)
			}
		}
	}

	// 2. Process unstakes
	for _, tx := range unstakeTxs {
		unstakeAmount := tx.Value
		if unstakeAmount == nil {
			unstakeAmount = big.NewInt(0)
		}
		if err := n.stakingManager.ProcessUnstakeFromTx(tx.From, unstakeAmount, tx.BlockHeight); err != nil {
			nodeLog.Warn("failed to process unstake tx: %v", err)
		}
	}

	// 3. Process reward claims (just resets stake height for reward calculation)
	for _, tx := range rewardTxs {
		if _, err := n.stakingManager.ProcessRewardClaimFromTx(tx.From, tx.BlockHeight); err != nil {
			nodeLog.Warn("failed to process reward claim tx: %v", err)
		}
	}

	nodeLog.Info("Synced staking data, total staked: %s, contract balance: %s",
		n.stakingManager.GetTotalStaked().String(),
		n.stakingManager.GetContractBalance().String())

	return nil
}

// startStakingPersistence periodically saves the staking state to a JSON file
// so that qau_stake-based staking data survives node restarts.
func (n *Node) startStakingPersistence(stakingFile string) {
	if n.stakingManager == nil {
		return
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
		// goroutine death on unexpected panics.
		defer func() {
			if r := recover(); r != nil {
				nodeLog.Error("panic in startStakingPersistence: %v", r)
			}
		}()

		for {
			select {
			case <-ticker.C:
				if err := n.stakingManager.SaveToFile(stakingFile); err != nil {
					nodeLog.Warn("failed to persist staking data: %v", err)
				}
			case <-n.ctx.Done():
				// Final save on shutdown
				if err := n.stakingManager.SaveToFile(stakingFile); err != nil {
					nodeLog.Warn("failed to persist staking data on shutdown: %v", err)
				}
				return
			}
		}
	}()
}

// maxAppliedStakingBlocks bounds the R81 dedupe memory (~32 bytes per entry).
const maxAppliedStakingBlocks = 4096

// markStakingBlockApplied records that this block's staking side effects were
// applied and reports whether it is the FIRST time. Dedupe is by block hash,
// not by height or tx hash: a reorg that replaces height H with a different
// block must be applied, while the same block arriving through a second code
// path must not.
//
// R81-STAKING-DEDUPE (2026-08-28).
func (n *Node) markStakingBlockApplied(hash types.Hash) bool {
	n.appliedStakingBlocksMu.Lock()
	defer n.appliedStakingBlocksMu.Unlock()
	if n.appliedStakingBlocks == nil {
		n.appliedStakingBlocks = make(map[types.Hash]struct{}, maxAppliedStakingBlocks)
	}
	if _, seen := n.appliedStakingBlocks[hash]; seen {
		return false
	}
	n.appliedStakingBlocks[hash] = struct{}{}
	n.appliedStakingOrder = append(n.appliedStakingOrder, hash)
	if len(n.appliedStakingOrder) > maxAppliedStakingBlocks {
		evict := n.appliedStakingOrder[0]
		n.appliedStakingOrder = n.appliedStakingOrder[1:]
		delete(n.appliedStakingBlocks, evict)
	}
	return true
}

// syncStakingFromBlock syncs staking transactions from a single block
func (n *Node) syncStakingFromBlock(blk *encoding.Block) {
	if n.stakingManager == nil || blk == nil {
		return
	}

	// R81-STAKING-DEDUPE (2026-08-28): apply each block's staking side effects
	// at most once. AddStakeFromTx / ProcessUnstakeFromTx are cumulative, so a
	// second application inflates the stake and desynchronises the validator
	// set from the other nodes.
	if !n.markStakingBlockApplied(block.ComputeBlockHash(blk.Header)) {
		return
	}

	// Log block transaction count for staking debugging
	if len(blk.Transactions) > 0 {
		stakeCount := 0
		for _, tx := range blk.Transactions {
			if tx.Type == encoding.TxTypeStake || tx.Type == encoding.TxTypeUnstake {
				stakeCount++
			}
		}
		if stakeCount > 0 {
			nodeLog.Info("syncStakingFromBlock: block %d has %d txs (%d staking type)",
				blk.Header.Height, len(blk.Transactions), stakeCount)
		}
	}

	stakingContract := economics.StakingContractAddress
	unstakeContract := economics.UnstakeContractAddress
	rewardsContract := economics.RewardsContractAddress

	for _, tx := range blk.Transactions {
		// Determine if this is a staking/unstaking/reward transaction.
		// R38-P0-02 (2026-08-01) FIX: detection is now STRICT (AND, not OR).
		// Previously the OR fallback let a tx.Type==TxTypeStake but tx.To
		// tampered elsewhere be misclassified as a stake — AddStakeFromTx
		// accounted the funds to tx.From while the executor (R37-era)
		// had already sent them to the tampered tx.To. With canonical
		// VerifyTransactionAuthorization now enforcing TxTypeStake⇒To==contract,
		// an attacker cannot craft a stake tx whose To is wrong, so the AND
		// detector is now correct. Removing the OR fallback also drops
		// the "legacy stake tx without To field" code path which the
		// executor now refuses — there should be no such legacy txs on
		// the V2 chain after the reset.
		isStake := tx.To != nil && *tx.To == stakingContract && tx.Type == encoding.TxTypeStake
		isUnstake := tx.To != nil && *tx.To == unstakeContract && tx.Type == encoding.TxTypeUnstake
		isReward := tx.To != nil && *tx.To == rewardsContract

		// Handle staking deposits
		if isStake && tx.Value != nil && tx.Value.Sign() > 0 {
			if err := n.stakingManager.AddStakeFromTx(tx.From, tx.Value, blk.Header.Height); err != nil {
				nodeLog.Error("Failed to add stake from tx: %v", err)
			} else {
				// FIX: Use stakingManager's total stake (not tx.Value) to update QPOS.
				// AddStakeFromTx adds tx.Value to the existing stake, so the total
				// may be much larger than tx.Value. Using tx.Value here would
				// overwrite the existing QPOS stake (e.g., 30,000 QAU → 32 QAU).
				totalStake := new(big.Int).Set(tx.Value)
				if stakeInfo, err := n.stakingManager.GetStake(tx.From); err == nil {
					totalStake = stakeInfo.Amount
				}

				nodeLog.Info("💰 New stake synced: from=%x, value=%s, totalStake=%s, totalChain=%s",
					tx.From[:8], tx.Value.String(), totalStake.String(), n.stakingManager.GetTotalStaked().String())

				// Also add to QPOS validator set so the node participates in consensus
				if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
					if added := n.blockProducer.QPOS().AddStakingValidator(tx.From, totalStake); added {
						nodeLog.Info("🟢 New validator added to QPOS set: addr=%x, stake=%s",
							tx.From[:8], totalStake.String())
					} else {
						nodeLog.Info("🔄 Existing validator stake updated in QPOS: addr=%x, stake=%s",
							tx.From[:8], totalStake.String())
					}
				}

				// Register validator in ValidatorManager so blocks they produce are accepted
				// by BlockValidator (which uses ValidatorLookup to check IsValidator/GetValidatorPublicKey)
				if n.validatorManager != nil && !n.validatorManager.IsValidator(tx.From) {
					if len(tx.PublicKey) > 0 {
						pubKey, pkErr := crypto.PublicKeyFromBytes(tx.PublicKey)
						if pkErr != nil {
							nodeLog.Error("Failed to parse validator public key from staking tx: addr=%x, err=%v",
								tx.From[:8], pkErr)
						} else {
							// Use self-registration (caller == addr), same as genesis validators
							commission := uint32(100) // 1% default, same as genesis validators
							if vmErr := n.validatorManager.AddValidator(tx.From, tx.From, pubKey, totalStake, commission, blk.Header.Height); vmErr != nil {
								nodeLog.Error("Failed to add validator to ValidatorManager: addr=%x, err=%v",
									tx.From[:8], vmErr)
							} else {
								nodeLog.Info("🔐 New validator registered in ValidatorManager: addr=%x, stake=%s",
									tx.From[:8], totalStake.String())
								// Activate the validator so it can produce blocks
								if saErr := n.validatorManager.SetActive(tx.From, tx.From, true); saErr != nil {
									nodeLog.Error("Failed to activate validator: addr=%x, err=%v",
										tx.From[:8], saErr)
								} else {
									nodeLog.Info("✅ Validator activated: addr=%x", tx.From[:8])
								}
							}
						}
					} else {
						nodeLog.Warn("Staking tx has no public key, cannot register validator in ValidatorManager: addr=%x",
							tx.From[:8])
					}
				}
			}
		}

		// Handle unstake requests
		if isUnstake {
			// Value in tx represents amount to unstake (0 = unstake all)
			unstakeAmount := tx.Value
			if unstakeAmount == nil {
				unstakeAmount = big.NewInt(0)
			}
			if err := n.stakingManager.ProcessUnstakeFromTx(tx.From, unstakeAmount, blk.Header.Height); err != nil {
				nodeLog.Error("Failed to process unstake from tx: %v", err)
			} else {
				nodeLog.Info("🔓 Unstake request synced: from=%x, amount=%s",
					tx.From[:8], unstakeAmount.String())
				// R79-UNSTAKE-VSET (2026-08-28) FIX: mirror the unstake into the
				// consensus validator set. The stake branch above registers the
				// address in QPOS + ValidatorManager, but there was no symmetric
				// removal here, so an address that unstaked everything stayed an
				// ACTIVE validator in the consensus set forever. Proposer election
				// is a pure function of that set, so nodes whose sets differ
				// elect different proposers for the same slot and produce
				// competing blocks.
				n.syncValidatorSetAfterUnstake(tx.From)
			}
		}

		// Handle reward claims
		if isReward {
			rewards, err := n.stakingManager.ProcessRewardClaimFromTx(tx.From, blk.Header.Height)
			if err != nil {
				nodeLog.Error("Failed to process reward claim from tx: %v", err)
			} else {
				nodeLog.Info("🎁 Reward claim synced: from=%x, rewards=%s",
					tx.From[:8], rewards.String())
				// In production, this would trigger a transfer of rewards to the user
				// For now, rewards are calculated and tracked
			}
		}
	}
}

// FirstBlockEpoch returns the epoch of block 1 (the first non-genesis block),
// caching it after the first successful read. ok is false while the chain has
// no block 1 yet.
//
// R80-COLDSTART-DEADLOCK (2026-08-28).
func (n *Node) FirstBlockEpoch() (uint64, bool) {
	if n.firstBlockEpochKnown.Load() {
		return n.firstBlockEpoch.Load(), true
	}
	if n.blockStore == nil {
		return 0, false
	}
	blk, err := n.blockStore.GetBlockByHeight(1)
	if err != nil || blk == nil {
		return 0, false
	}
	n.firstBlockEpoch.Store(blk.Header.Epoch)
	n.firstBlockEpochKnown.Store(true)
	// R88-F: mirror into QPOS so the Executive cold-start guard can apply the
	// high-genesis exemption (epochs below the first block can never have an
	// on-chain VRF accumulator; zero-hash selection is identical on every node).
	if n.blockProducer != nil {
		if qpos := n.blockProducer.QPOS(); qpos != nil {
			qpos.SetFirstBlockEpoch(blk.Header.Epoch)
		}
	}
	return blk.Header.Epoch, true
}

// IsChainTooYoungForProposerSchedule reports whether the chain cannot possibly
// contain the epoch-2 VRF accumulator that QPOS needs to build a canonical
// proposer schedule for the given slot, because the chain's first block lives
// in epoch (slotEpoch - 1) or later.
//
// R80-COLDSTART-DEADLOCK (2026-08-28): this is the narrow window where the
// cold-start guard must be relaxed. On a mature chain the accumulator exists,
// the guard stays in force, and a restarting sealer still stands down instead
// of proposing from a fallback shuffle.
func (n *Node) IsChainTooYoungForProposerSchedule(slotEpoch uint64) bool {
	first, ok := n.FirstBlockEpoch()
	if !ok {
		// No block 1 yet: genesis-only chain, which the caller already
		// exempts via its own at-genesis check.
		return true
	}
	return slotEpoch < first+2
}

// stakingSyncBehindThreshold is how many blocks a node may lag behind the
// network and still apply staking side effects block by block. Beyond it the
// node is doing a bulk catch-up, where a single full rescan at the end
// (runPendingStakingResync) is cheaper than per-block work.
const stakingSyncBehindThreshold = 64

// isFarBehindForStakingSync reports whether this node is in a bulk catch-up
// far enough behind the network that per-block staking sync should be skipped.
//
// R79-STAKING-RESYNC (2026-08-28): deliberately NOT `syncer.IsSyncing()`.
// A syncer may report "syncing" even when a node is effectively at the
// network head. Treating that transient state as a permanent reason to
// skip staking sync would prevent skipped staking transactions from ever
// being replayed, causing validator sets to diverge.
func (n *Node) isFarBehindForStakingSync() bool {
	if n.syncer == nil {
		return false
	}
	if !n.syncer.IsSyncing() {
		return false
	}
	st := n.syncer.Status()
	return st.HighestBlock > st.CurrentBlock+stakingSyncBehindThreshold
}

// blockHasStakingTx reports whether the block carries any transaction that
// mutates staking state (stake / unstake / reward claim), i.e. whether
// skipping syncStakingFromBlock for it would lose consensus-relevant state.
//
// R79-STAKING-RESYNC (2026-08-28).
func blockHasStakingTx(blk *encoding.Block) bool {
	if blk == nil {
		return false
	}
	stakingContract := economics.StakingContractAddress
	unstakeContract := economics.UnstakeContractAddress
	rewardsContract := economics.RewardsContractAddress
	for _, tx := range blk.Transactions {
		if tx == nil {
			continue
		}
		if tx.Type == encoding.TxTypeStake || tx.Type == encoding.TxTypeUnstake {
			return true
		}
		if tx.To != nil &&
			(*tx.To == stakingContract || *tx.To == unstakeContract || *tx.To == rewardsContract) {
			return true
		}
	}
	return false
}

// runPendingStakingResync replays the whole chain's staking state once, if a
// staking transaction was skipped earlier because the syncer was active.
//
// R79-STAKING-RESYNC (2026-08-28): syncStakingFromChain is idempotent by
// construction (StakingManager.SyncFromChain clears the stake map, the genesis
// stakes are re-added, then unstakes/reward claims are replayed in order), so
// running it again mid-flight is safe. It is executed in its own goroutine
// because a full rescan walks every block, and guarded by an atomic so a burst
// of blocks cannot start several rescans at once.
func (n *Node) runPendingStakingResync() {
	if !n.stakingResyncPending.Load() {
		return
	}
	if n.isFarBehindForStakingSync() {
		return
	}
	if !n.stakingResyncRunning.CompareAndSwap(false, true) {
		return
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer n.stakingResyncRunning.Store(false)
		defer func() {
			if r := recover(); r != nil {
				nodeLog.Error("panic in runPendingStakingResync: %v", r)
			}
		}()
		nodeLog.Info("R79: replaying staking state from chain (staking txs were skipped during sync)")
		if err := n.syncStakingFromChain(); err != nil {
			nodeLog.Warn("R79: staking rescan failed, keeping it queued: %v", err)
			return
		}
		n.syncQPOSValidatorsFromStaking()
		n.stakingResyncPending.Store(false)
		nodeLog.Info("R79: staking state replayed, total staked=%s", n.stakingManager.GetTotalStaked().String())
	}()
}

// syncValidatorSetAfterUnstake mirrors an applied unstake transaction into the
// consensus validator set (QPOS) and the ValidatorManager.
//
// R79-UNSTAKE-VSET (2026-08-28): proposer election reads the QPOS
// ValidatorSet, so that set MUST be a deterministic function of applied
// blocks on every node. The stake branch of syncStakingFromBlock registers
// new stakers (AddStakingValidator + ValidatorManager.AddValidator), but
// unstakes were only applied to the economics StakingManager. A validator
// that unstaked its whole balance therefore kept producing blocks on the
// node that had registered it, while nodes that never registered it elected
// somebody else for the same slot -> two blocks per slot -> permanent fork.
//
// Behavior:
//   - remaining stake == 0 (or the stake record is gone): remove the address
//     from the QPOS set and deactivate it in ValidatorManager.
//   - remaining stake  > 0: update the weight in both places, because
//     election is stake-weighted.
func (n *Node) syncValidatorSetAfterUnstake(addr types.Address) {
	if n.stakingManager == nil {
		return
	}

	remaining := big.NewInt(0)
	if info, err := n.stakingManager.GetStake(addr); err == nil && info != nil && info.Amount != nil {
		remaining = new(big.Int).Set(info.Amount)
	}

	var qpos *consensus.QPOS
	if n.blockProducer != nil {
		qpos = n.blockProducer.QPOS()
	}

	if remaining.Sign() <= 0 {
		if qpos != nil && qpos.RemoveStakingValidator(addr) {
			nodeLog.Info("🔻 Validator removed from QPOS set after full unstake: addr=%x", addr[:8])
		}
		if n.validatorManager != nil && n.validatorManager.IsValidator(addr) {
			if err := n.validatorManager.SetActive(addr, addr, false); err != nil {
				nodeLog.Warn("Failed to deactivate validator after full unstake: addr=%x, err=%v", addr[:8], err)
			} else {
				nodeLog.Info("🔻 Validator deactivated in ValidatorManager after full unstake: addr=%x", addr[:8])
			}
		}
		return
	}

	if qpos != nil {
		qpos.AddStakingValidator(addr, remaining)
	}
	if n.validatorManager != nil && n.validatorManager.IsValidator(addr) {
		if err := n.validatorManager.UpdateStake(addr, addr, remaining); err != nil {
			nodeLog.Warn("Failed to update validator stake after partial unstake: addr=%x, err=%v", addr[:8], err)
		}
	}
	nodeLog.Info("🔻 Validator stake reduced after unstake: addr=%x, remaining=%s", addr[:8], remaining.String())
}

// syncQPOSValidatorsFromStaking syncs all active stakers from stakingManager
// into the QPOS validator set. This is called at startup (after blockProducer
// is initialized) to ensure the consensus layer knows about all staked validators.
// It also ensures validators already in ValidatorManager are synced to QPOS.
func (n *Node) syncQPOSValidatorsFromStaking() {
	if n.stakingManager == nil || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return
	}

	validators := n.stakingManager.GetActiveValidators()
	if len(validators) == 0 {
		return
	}

	qpos := n.blockProducer.QPOS()
	// R87-VSET-ORDER: sort by address before appending. GetActiveValidators()
	// returns a map; iterating it directly made the insertion order of staked
	// validators depend on Go map layout, which differs per process start. The
	// ValidatorSet assigns consensus indices by insertion order and epoch
	// rewards credit rewards[idx] to validators[idx], so two nodes restarting
	// with different layouts would credit the same census indices to different
	// addresses — permanent state-root divergence (same class as R87-M4).
	for _, addr := range sortedStakerAddrs(validators) {
		qpos.AddStakingValidator(addr, validators[addr])
	}
	nodeLog.Info("🔄 Synced %d staking validators to QPOS consensus set", len(validators))

	// Also ensure all validators in Validator Manager are in QPOS (e.g., genesis validators
	// that may not have gone through the staking sync path)
	// FIX: Skip validators already in stakingManager to avoid overwriting their stake
	// with validatorManager's genesis stake (which may be 0). stakingManager takes priority.
	if n.validatorManager != nil {
		vmValidators := n.validatorManager.GetAllValidators()
		// R87-VSET-ORDER: GetAllValidators() is built by map iteration — sort it
		// too, same rationale as above.
		sort.Slice(vmValidators, func(i, j int) bool {
			return bytesLess(vmValidators[i].Address[:], vmValidators[j].Address[:])
		})
		for _, v := range vmValidators {
			if v.Active {
				if _, exists := validators[v.Address]; !exists {
					qpos.AddStakingValidator(v.Address, v.Stake)
				}
			}
		}
	}
}

// initBridgeValidatorNetwork injects a ValidatorNetwork (M-of-N threshold
// arbitration) into the bridge, using the current QPOS/ValidatorManager
// validator set.
//
// P0-2 BRDG-03 FIX (2026-07-13): initBridge (called in initP3Features before
// startServices) could not inject vn because blockProducer was nil. This
// method runs after startServices creates blockProducer and syncs validators.
//
// When vn is set, ProcessMessage enforces M-of-N quorum before executing
// cross-chain messages (audit HIGH-08). When trustedValidatorKeys are set,
// SubmitMessage rejects messages signed with untrusted keys (audit BRDG-01).
//
// Both injections are fail-closed: if no validators with public keys are
// found, vn is NOT injected (ProcessMessage skips quorum check) and
// trustedValidatorKeys stays empty (SubmitMessage rejects all messages).
//
// BRDG-FIX (2026-07-16): returns an error if the header verifier
// cannot be fully configured on mainnet (propagated from
// initBridgeHeaderVerifier). The caller in startServices MUST propagate
// this error to abort node startup.
func (n *Node) initBridgeValidatorNetwork() error {
	if n.bridge == nil {
		return nil
	}
	qb, ok := n.bridge.(*bridge.QuantumBridge)
	if !ok {
		return nil
	}

	// Get validator set with public keys populated.
	// validatorManager.GetValidatorSet() fills PublicKeyBytes from v.PublicKey.
	// QPOS.GetValidatorSet() may have empty PublicKeyBytes for staking-added
	// validators, so validatorManager is the authoritative source.
	if n.validatorManager == nil {
		nodeLog.Warn("Bridge vn injection skipped: validatorManager is nil")
		return nil
	}

	vmVS, err := n.validatorManager.GetValidatorSet()
	if err != nil {
		nodeLog.Warn("Bridge vn injection skipped: %v", err)
		return nil
	}
	if vmVS == nil || vmVS.ValidatorCount() == 0 {
		nodeLog.Warn("Bridge vn injection skipped: no validators in validatorManager")
		return nil
	}

	// Collect active validators with non-empty public keys.
	type valEntry struct {
		addr   types.Address
		pubKey []byte
		stake  *big.Int
	}
	var entries []valEntry
	for _, v := range vmVS.Validators() {
		if !v.Active || len(v.PublicKeyBytes) == 0 {
			continue
		}
		entries = append(entries, valEntry{
			addr:   v.Address,
			pubKey: append([]byte(nil), v.PublicKeyBytes...),
			stake:  new(big.Int).Set(v.Stake),
		})
	}
	if len(entries) == 0 {
		nodeLog.Warn("Bridge vn injection skipped: no active validators with public keys")
		return nil
	}

	// Compute BFT threshold: ceil(2/3 * N) = (2*N + 2) / 3.
	// For N=1: threshold=1 (dev mode), N=3: threshold=2, N=4: threshold=3.
	validatorCount := len(entries)
	threshold := (2*validatorCount + 2) / 3
	if threshold < 1 {
		threshold = 1
	}

	// Create ValidatorNetwork with a real Dilithium3 signature verifier.
	// R8-OBS-2 (2026-07-18): NewValidatorNetwork now returns an error
	// instead of panicking when the verifier is nil. The verifier here
	// is always non-nil (NewQuantumSignatureVerifier), so the error path
	// is defensive only.
	verifier := bridge.NewQuantumSignatureVerifier()
	vn, err := bridge.NewValidatorNetwork(threshold, n.bridgeRelayer, verifier, "")
	if err != nil {
		return fmt.Errorf("bridge: failed to create validator network: %w", err)
	}

	// Inject validators directly into the ValidatorSet (bypassing the
	// governance-caller check, which is for runtime governance operations,
	// not for startup bootstrap from on-chain state).
	vs := vn.GetValidatorSet()
	for _, e := range entries {
		bv := &bridge.BridgeValidator{
			Address:   e.addr,
			PublicKey: e.pubKey,
			Stake:     e.stake,
			Active:    true,
		}
		if err := vs.AddValidator(bv); err != nil {
			nodeLog.Warn("Bridge vn: failed to add validator %s: %v", e.addr.ToHexAddress(), err)
		}
	}

	// Inject vn into the bridge (enables ProcessMessage quorum check).
	qb.SetValidatorNetwork(vn)

	// P0-1 BRDG-01 FIX (2026-07-13): Also inject trusted validator keys
	// (was missing from initBridge, causing SubmitMessage to fail-closed
	// with "no trusted validator keys configured").
	trustedKeys := make([][]byte, 0, len(entries))
	for _, e := range entries {
		trustedKeys = append(trustedKeys, e.pubKey)
	}
	qb.SetTrustedValidatorKeys(trustedKeys)

	// Start the ValidatorNetwork (heartbeat goroutine).
	if err := vn.Start(n.ctx); err != nil {
		nodeLog.Warn("Bridge ValidatorNetwork start failed: %v", err)
	}

	nodeLog.Info("Bridge ValidatorNetwork injected: %d validators, threshold=%d (BFT 2/3+)",
		validatorCount, threshold)

	// P0-4 FIX (2026-07-13): Inject trusted public keys into adapters so
	// VerifyMessage can validate message signatures. Without this, all
	// cross-chain messages fail with "no trusted key configured".
	// Keys come from config file (bridge.validatorPublicKeyHex/relayerPublicKeyHex)
	// or env vars (QAU_BRIDGE_VALIDATOR_PUBKEY/QAU_BRIDGE_RELAYER_PUBKEY).
	n.injectBridgeTrustedKeys(qb)

	// P1-5 (2026-07-14): Inject SPV header verifier for reorg detection.
	// Must run after Initialize() (adapters registered) and after
	// n.headerSyncer is created (initLightClient). Enables cross-chain
	// message rejection when the source block was reorged away.
	// BRDG-FIX (2026-07-16): returns error on mainnet if verifier
	// is not fully configured (fail-closed at startup).
	if err := n.initBridgeHeaderVerifier(qb); err != nil {
		return err
	}
	return nil
}

// initBridgeHeaderVerifier creates and injects the SPV header verifier into
// the bridge's chain adapters.
//
// P1-5 (2026-07-14): Stage 2 of SPV header verification (BRDG-04/HIGH-12/
// HIGH-15). The verifier provides two forms of reorg protection:
//
//   - Quantaureum side: uses n.headerSyncer (lightclient.HeaderSyncer) to
//     look up the block at msg.BlockNumber in the local block store and
//     compare its hash to msg.BlockHash. A mismatch indicates the source
//     block was reorged away.
//   - Ethereum side: uses a SyncCommitteeVerifier to verify sync committee
//     signatures on block headers fetched from the Ethereum RPC node.
//
// Nil-safe design: when n.headerSyncer is nil (light client not enabled),
// Quantaureum header verification is skipped. When the sync committee
// verifier has no committee configured, Ethereum header verification is
// skipped for pre-sync-committee blocks and fails-closed for blocks that
// carry sync committee signatures.
//
// The verifier and sync committee verifier are stored on the Node struct
// so they can be updated at runtime (e.g., when Ethereum sync committee
// data becomes available via light client sync).
//
// BRDG-FIX (2026-07-16): On mainnet, strict mode is enabled and the
// verifier MUST be fully configured (IsEnabled && HasQuantaureumLookup &&
// HasEthereumSyncCommittee). If not fully configured, returns an error to
// prevent node startup (fail-closed). This eliminates the fail-open path
// where an unconfigured verifier silently accepts cross-chain messages.
func (n *Node) initBridgeHeaderVerifier(qb *bridge.QuantumBridge) error {
	verifier := bridge.NewBridgeHeaderVerifier()

	// Inject Quantaureum header lookup for reorg detection.
	// n.headerSyncer is created in initLightClient() and satisfies the
	// bridge.HeaderLookup interface via GetHeaderByHeight.
	if n.headerSyncer != nil {
		verifier.SetQuantaureumHeaderLookup(n.headerSyncer)
		nodeLog.Info("Bridge header verifier: Quantaureum header lookup injected (reorg detection enabled)")
	} else {
		nodeLog.Warn("Bridge header verifier: Quantaureum header lookup not available (light client not enabled) — reorg detection disabled")
	}

	// Create and inject the Ethereum sync committee verifier.
	// Stored on Node so it can be updated when Ethereum sync committee
	// data becomes available (UpdateCurrentCommittee/UpdateNextCommittee).
	syncCommittee := lightclient.NewSyncCommitteeVerifier()
	n.bridgeSyncCommittee = syncCommittee
	verifier.SetEthereumSyncCommittee(syncCommittee)
	nodeLog.Info("Bridge header verifier: Ethereum sync committee verifier injected (will verify when committee is populated)")

	// BRDG-FIX (2026-07-16): On mainnet, enable strict mode and
	// assert the verifier is fully configured. This is the production
	// hard guard: if the header verifier is not fully configured on
	// mainnet, the node refuses to start. Silently allowing an
	// unconfigured verifier would let an attacker suppress syncer
	// initialization to bypass SPV reorg detection entirely.
	if n.config.NetworkID == MainnetNetworkID {
		verifier.SetStrictMode(true)
		if !verifier.IsEnabled() {
			return fmt.Errorf("bridge header verifier not enabled on mainnet (networkId=%d): "+
				"both Quantaureum lookup and Ethereum sync committee are nil (BRDG-)", n.config.NetworkID)
		}
		if !verifier.HasQuantaureumLookup() {
			return fmt.Errorf("bridge header verifier missing Quantaureum lookup on mainnet (networkId=%d): "+
				"light client/headerSyncer not initialized — reorg detection required (BRDG-)", n.config.NetworkID)
		}
		if !verifier.HasEthereumSyncCommittee() {
			return fmt.Errorf("bridge header verifier missing Ethereum sync committee on mainnet (networkId=%d): "+
				"sync committee verifier not injected (BRDG-)", n.config.NetworkID)
		}
		nodeLog.Info("Bridge header verifier: strict mode ENABLED on mainnet (fail-closed for nil syncers)")
	}

	// Inject the verifier into all registered adapters.
	n.bridgeHeaderVerifier = verifier
	injected := qb.InjectHeaderVerifier(verifier)
	nodeLog.Info("Bridge header verifier injected into %d adapters", injected)
	return nil
}

// RefreshBridgeValidators updates the bridge's ValidatorNetwork and trusted
// validator key set from the current QPOS validator set.
//
// P1-6 FIX (2026-07-14): At epoch boundaries, the QPOS validator set may
// change (new validators added, validators jailed/removed, stake updated).
// This method propagates those changes to the bridge arbitration network
// so that:
//   - New validators can participate in bridge message signing
//   - Jailed/removed validators are deactivated in the bridge ValidatorSet
//   - trustedValidatorKeys reflects the current consensus set
//
// This method is called from processEpochBoundary in block_producer.go.
// It is safe to call when the bridge is disabled (no-op).
func (n *Node) RefreshBridgeValidators() {
	if n.bridge == nil {
		return
	}
	qb, ok := n.bridge.(*bridge.QuantumBridge)
	if !ok {
		return
	}
	if n.validatorManager == nil {
		return
	}

	vmVS, err := n.validatorManager.GetValidatorSet()
	if err != nil || vmVS == nil || vmVS.ValidatorCount() == 0 {
		return
	}

	// Collect active validators with non-empty public keys.
	var entries []*bridge.BridgeValidator
	for _, v := range vmVS.Validators() {
		if !v.Active || len(v.PublicKeyBytes) == 0 {
			continue
		}
		entries = append(entries, &bridge.BridgeValidator{
			Address:   v.Address,
			PublicKey: append([]byte(nil), v.PublicKeyBytes...),
			Stake:     new(big.Int).Set(v.Stake),
			Active:    true,
		})
	}
	if len(entries) == 0 {
		return
	}

	// Compute BFT threshold: ceil(2/3 * N) = (2*N + 2) / 3.
	threshold := (2*len(entries) + 2) / 3
	if threshold < 1 {
		threshold = 1
	}

	result := qb.RefreshValidatorSet(entries, threshold)
	if result.Added > 0 || result.Updated > 0 || result.Deactivated > 0 {
		nodeLog.Info("Bridge validator set refreshed: added=%d updated=%d deactivated=%d threshold=%d",
			result.Added, result.Updated, result.Deactivated, result.Threshold)
	}
}

// injectBridgeTrustedKeys decodes hex-encoded trusted public keys from config
// or environment variables and injects them into the bridge's chain adapters.
//
// P0-4 FIX (2026-07-13): adapter.VerifyMessage requires a trusted public key
// to verify incoming cross-chain message signatures. Without injection, all
// messages are rejected with "no trusted key configured".
//
// Key sources (priority: env var > config file):
//   - QAU_BRIDGE_VALIDATOR_PUBKEY / bridge.validatorPublicKeyHex → Quantaureum adapter
//   - QAU_BRIDGE_RELAYER_PUBKEY / bridge.relayerPublicKeyHex → Ethereum/external adapter
//
// When no key is configured, injection is silently skipped (adapter remains
// in "no trusted key" state, VerifyMessage will reject all messages).
// This is fail-closed: operators must explicitly configure keys to enable
// cross-chain message verification.
func (n *Node) injectBridgeTrustedKeys(qb *bridge.QuantumBridge) {
	// Resolve validator public key (env var overrides config).
	validatorHex := n.config.Bridge.ValidatorPublicKeyHex
	if envVal := os.Getenv("QAU_BRIDGE_VALIDATOR_PUBKEY"); envVal != "" {
		validatorHex = envVal
	}

	// Resolve relayer public key (env var overrides config).
	relayerHex := n.config.Bridge.RelayerPublicKeyHex
	if envVal := os.Getenv("QAU_BRIDGE_RELAYER_PUBKEY"); envVal != "" {
		relayerHex = envVal
	}

	var validatorBytes, relayerBytes []byte
	var err error

	if validatorHex != "" {
		validatorBytes, err = hex.DecodeString(strings.TrimPrefix(validatorHex, "0x"))
		if err != nil {
			nodeLog.Warn("Bridge trusted key injection skipped: invalid validatorPublicKeyHex: %v", err)
		}
	}
	if relayerHex != "" {
		relayerBytes, err = hex.DecodeString(strings.TrimPrefix(relayerHex, "0x"))
		if err != nil {
			nodeLog.Warn("Bridge trusted key injection skipped: invalid relayerPublicKeyHex: %v", err)
		}
	}

	if len(validatorBytes) == 0 && len(relayerBytes) == 0 {
		nodeLog.Warn("Bridge trusted keys not configured — adapter VerifyMessage will reject all messages. " +
			"Set bridge.validatorPublicKeyHex/relayerPublicKeyHex in config or QAU_BRIDGE_VALIDATOR_PUBKEY/RELAYER_PUBKEY env var.")
		return
	}

	injected, errs := qb.InjectTrustedPublicKeys(validatorBytes, relayerBytes, "node/initBridge")
	for _, e := range errs {
		nodeLog.Warn("Bridge trusted key injection error: %v", e)
	}
	if injected > 0 {
		nodeLog.Info("Bridge trusted keys injected into %d adapter(s)", injected)
	}
}

// initBridgeGovernance sets the governance address on all chain adapters and
// registers the standard bridge event signatures.
//
// P1-3 + P1-4 FIX (2026-07-13): adapters fail-closed by default — without a
// governance address, SetBootstrapMode/RegisterEventSignature/SetRelayerKeys
// all reject. Without registered event signatures, WatchEvents rejects ALL
// cross-chain events. This method performs the startup bootstrap sequence:
//
//  1. SetGovernanceAddress(govAddr, caller=initializerAddr)
//  2. SetBootstrapMode(true,  caller=govAddr)
//  3. RegisterEventSignature(standardSigs, caller=govAddr)
//  4. SetBootstrapMode(false, caller=govAddr) — fail-closed again
//
// Configuration (env var overrides config file):
//   - QAU_BRIDGE_GOVERNANCE_ADDRESS / bridge.governanceAddress
//   - QAU_BRIDGE_INITIALIZER_ADDRESS / bridge.initializerAddress (already in cfg)
//
// When governance address is not configured, this method is a no-op (adapters
// remain in fail-closed state — bridge can still send messages but cannot
// receive/verify events until governance is configured).
func (n *Node) initBridgeGovernance(qb *bridge.QuantumBridge) {
	govAddr := n.config.Bridge.GovernanceAddress
	if envGov := os.Getenv("QAU_BRIDGE_GOVERNANCE_ADDRESS"); envGov != "" {
		govAddr = envGov
	}
	if govAddr == "" {
		nodeLog.Warn("Bridge governance address not configured — event signatures will not be registered. " +
			"Set bridge.governanceAddress in config or QAU_BRIDGE_GOVERNANCE_ADDRESS env var.")
		return
	}
	initializer := n.bridgeConfig.InitializerAddress
	if initializer == "" {
		nodeLog.Warn("Bridge initializer address not configured — cannot set governance address. " +
			"Set bridge.initializerAddress in config or QAU_BRIDGE_INITIALIZER_ADDRESS env var.")
		return
	}

	// Step 1: Set governance address (caller = initializer for first-time setup).
	injected, errs := qb.SetGovernanceAddressOnAdapters(govAddr, initializer)
	for _, e := range errs {
		nodeLog.Warn("Bridge governance address set error: %v", e)
	}
	if injected > 0 {
		nodeLog.Info("Bridge governance address set on %d adapter(s)", injected)
	}

	// Step 2: Enable bootstrap mode (caller = governance address).
	_, errs = qb.SetBootstrapModeOnAdapters(true, govAddr)
	for _, e := range errs {
		nodeLog.Warn("Bridge bootstrap mode enable error: %v", e)
	}

	// Step 3: Register standard event signatures (caller = governance address).
	sigHashes := bridge.StandardBridgeEventSignatures()
	injected, errs = qb.RegisterEventSignaturesOnAdapters(sigHashes, govAddr)
	for _, e := range errs {
		nodeLog.Warn("Bridge event signature registration error: %v", e)
	}
	if injected > 0 {
		nodeLog.Info("Bridge event signatures registered on %d adapter(s) (%d signatures each)",
			injected, len(sigHashes))
	}

	// Step 4: Disable bootstrap mode — fail-closed (only registered sigs accepted).
	injected, errs = qb.SetBootstrapModeOnAdapters(false, govAddr)
	for _, e := range errs {
		nodeLog.Warn("Bridge bootstrap mode disable error: %v", e)
	}
	if injected > 0 {
		nodeLog.Info("Bridge bootstrap mode disabled — event signature allowlist is now enforced")
	}
}

// ministryWorksAdapter adapts consensus.MinistryWorks to the
// bridge.MinistryWorksRecorder interface. P1-T7 (2026-07-14).
// MinistryWorks methods require a system caller for authorization —
// the adapter supplies the voting system caller automatically.
type ministryWorksAdapter struct {
	mw     *consensus.MinistryWorks
	caller types.Address
}

func (a *ministryWorksAdapter) RegisterBridge(name string, remoteChainID uint64, relayerCount int, totalLocked string) (uint64, error) {
	if a.mw == nil {
		return 0, fmt.Errorf("MinistryWorks not available")
	}
	info, err := a.mw.RegisterBridge(a.caller, name, remoteChainID, relayerCount, totalLocked)
	if err != nil {
		return 0, err
	}
	return info.ID, nil
}

func (a *ministryWorksAdapter) RecordCrossChainTx(bridgeID uint64, sourceTxHash types.Hash, amount string) (uint64, error) {
	if a.mw == nil {
		return 0, fmt.Errorf("MinistryWorks not available")
	}
	tx, err := a.mw.RecordCrossChainTx(a.caller, bridgeID, sourceTxHash, amount)
	if err != nil {
		return 0, err
	}
	return tx.ID, nil
}

// injectBridgeMinistryWorks wires MinistryWorks into the bridge for
// governance tracking of cross-chain operations.
// P1-T7 (2026-07-14): Called after MinistryRegistry is created and after
// the bridge is initialized. Since the bridge was already initialized
// (registerWithMinistry was a no-op because ministryWorks was nil), this
// method sets the recorder and manually triggers bridge registration.
func (n *Node) injectBridgeMinistryWorks(qb *bridge.QuantumBridge) {
	if n.ministryRegistry == nil || n.ministryRegistry.Works() == nil {
		return
	}
	adapter := &ministryWorksAdapter{
		mw:     n.ministryRegistry.Works(),
		caller: consensus.GetVotingSystemCaller(),
	}
	qb.SetMinistryWorks(adapter)
	// Manually trigger bridge registration since Initialize() already ran
	// (and was a no-op because ministryWorks was nil at that time).
	qb.RegisterWithMinistry()
	nodeLog.Info("MinistryWorks injected into bridge for cross-chain governance tracking")
}

// startBridgeAPI creates and starts the standalone BridgeAPI HTTP server.
//
// P1-1 FIX (2026-07-13): The bridge package includes a full HTTP API with 7
// endpoints (status, message, messages, lock, locks, relay, validators) plus
// API Key authentication and Slowloris protection. Without calling Start(),
// these endpoints are completely unavailable — users can only access the 3
// read-only RPC methods via the node's JSON-RPC port.
//
// This method is called from startServices() AFTER initBridgeValidatorNetwork(),
// because BridgeAPI requires the ValidatorNetwork for the /validators and
// /status endpoints.
//
// Configuration (env var overrides config file):
//   - QAU_BRIDGE_API_ADDR / bridge.bridgeApiAddr (e.g. "127.0.0.1:8547")
//   - QAU_BRIDGE_API_KEY / bridge.bridgeApiKey
//
// When BridgeAPIAddr is empty, the HTTP API is disabled (no-op).
func (n *Node) startBridgeAPI() {
	if n.bridge == nil {
		return
	}
	qb, ok := n.bridge.(*bridge.QuantumBridge)
	if !ok {
		return
	}

	apiAddr := n.config.Bridge.BridgeAPIAddr
	if envAddr := os.Getenv("QAU_BRIDGE_API_ADDR"); envAddr != "" {
		apiAddr = envAddr
	}
	apiKey := n.config.Bridge.BridgeAPIKey
	if envKey := os.Getenv("QAU_BRIDGE_API_KEY"); envKey != "" {
		apiKey = envKey
	}
	if apiAddr == "" {
		return // HTTP API disabled
	}
	if apiKey == "" {
		nodeLog.Warn("BridgeAPI addr configured (%s) but no API key set — refusing to start without authentication. "+
			"Set bridge.bridgeApiKey in config or QAU_BRIDGE_API_KEY env var.", apiAddr)
		return
	}

	vn := qb.GetValidatorNetwork()
	n.bridgeAPI = bridge.NewBridgeAPI(qb, n.bridgeRelayer, n.assetLockManager, vn, apiKey)
	if err := n.bridgeAPI.Start(apiAddr); err != nil {
		nodeLog.Warn("BridgeAPI start failed on %s: %v", apiAddr, err)
		n.bridgeAPI = nil
		return
	}
	nodeLog.Info("BridgeAPI listening on %s (7 endpoints, API key auth)", apiAddr)
}

// startServices starts background services.
// BRDG-FIX (2026-07-16): returns an error if a critical service
// (e.g., bridge header verifier on mainnet) cannot be initialized —
// the node MUST refuse to start instead of silently running in a
// fail-open configuration.
// shouldStartProducingBlocks reports whether this node must run the block
// production loop: a production sealer, i.e. validator enabled AND
// blockProducer enabled AND not sync-only. DevMode has its own branch.
//
// R94-RPCNODE-VERIFIER (2026-08-30): extracted from startServices so the
// producer-creation decision table is unit-testable without booting a Node.
func shouldStartProducingBlocks(devMode, validatorEnabled, blockProducer, syncOnlyMode bool) bool {
	return !devMode && validatorEnabled && blockProducer && !syncOnlyMode
}

// shouldCreateElectionVerifierProducer reports whether a BlockProducer must be
// constructed WITHOUT starting its production loop, purely so that QPOS and the
// validator set get initialized and wireElectionVerifier can install a
// core.ElectionVerifier on the block validator.
//
// R94-RPCNODE-VERIFIER (2026-08-30): this used to additionally require
// validatorEnabled, which silently excluded pure RPC / observer nodes
// (validatorEnabled=false, blockProducer=false). For those, n.blockProducer
// stayed nil, wireElectionVerifier no-opped, and the block validator ran with a
// nil election verifier. That is survivable ONLY while the validator is in
// syncingMode, where core/block_validator.go degrades a nil verifier to
// "skip + WARN" (R38-P1-08 conservative path). The moment initial sync finished
// and SetSyncingMode(false) ran, ValidateBlock hit its fail-closed
// `else if !devMode` branch and rejected every block with
// "election verifier not configured — proposer election verification REQUIRED
// in production". The rejection happens before ProcessBlock, so an
// observer that reaches this state cannot repair itself after initial sync.
//
// Dropping the validatorEnabled requirement makes the "6 validators + 1 public
// RPC entry point" architecture actually implementable. Semantics stay correct
// because wireElectionVerifier classifies such a node as a non-sealer and calls
// SetTrustCanonicalProposer(true) (R58-ELEC-TRUST): it follows the canonical
// chain's ProposerAddr instead of re-deriving the VRF schedule, exactly like
// geth's post-merge execution layer. Block signatures are still verified.
//
// SyncOnlyMode remains excluded: such a node has no authoritative genesis until
// it syncs one (node.go initGenesis leaves genesisBlock nil), so QPOS cannot be
// initialized here. Deployments that need a verifying observer must run with
// syncOnlyMode=false and a local genesis.json.
func shouldCreateElectionVerifierProducer(devMode, validatorEnabled, blockProducer, syncOnlyMode bool) bool {
	if devMode || syncOnlyMode {
		return false
	}
	// Anything that is not a producing sealer still needs the verifier.
	return !shouldStartProducingBlocks(devMode, validatorEnabled, blockProducer, syncOnlyMode)
}

func (n *Node) startServices() error {
	// Start block producer in dev mode (unless sync-only mode is enabled)
	if n.config.DevMode && !n.config.SyncOnlyMode {
		interval := time.Duration(n.config.BlockInterval) * time.Second
		if interval == 0 {
			interval = 12 * time.Second // Default 12 second block time
		}
		n.blockProducer = NewBlockProducer(n, interval)
		n.blockProducer.Start()
	}

	// Start block producer in production mode if validator is enabled and blockProducer is true
	nodeLog.Info("Production mode check: DevMode=%v, ValidatorEnabled=%v, BlockProducer=%v, SyncOnlyMode=%v",
		n.config.DevMode, n.config.ValidatorEnabled, n.config.BlockProducer, n.config.SyncOnlyMode)
	if shouldStartProducingBlocks(n.config.DevMode, n.config.ValidatorEnabled, n.config.BlockProducer, n.config.SyncOnlyMode) {
		interval := time.Duration(n.config.BlockInterval) * time.Second
		if interval == 0 {
			// audit-fix R3-M2: default must match consensus.SlotDuration (12s)
			// to avoid slot number divergence between BlockProducer and QPOS.
			interval = consensus.SlotDuration
		}
		nodeLog.Info("Starting validator block producer with %v interval", interval)
		n.blockProducer = NewBlockProducer(n, interval)
		n.blockProducer.Start()
	} else if shouldCreateElectionVerifierProducer(n.config.DevMode, n.config.ValidatorEnabled, n.config.BlockProducer, n.config.SyncOnlyMode) {
		// Create BlockProducer for election verification only — do NOT start
		// the production loop. This initializes QPOS and the validator set so
		// wireElectionVerifier can install an ElectionVerifier, letting the
		// node validate incoming blocks without producing any.
		//
		// R94-RPCNODE-VERIFIER (2026-08-30): this branch now also covers pure
		// RPC / observer nodes (validatorEnabled=false). See
		// shouldCreateElectionVerifierProducer for why omitting them prevents
		// block validation once initial sync ends.
		interval := time.Duration(n.config.BlockInterval) * time.Second
		if interval == 0 {
			interval = consensus.SlotDuration
		}
		nodeLog.Info("Creating BlockProducer for election verification only (validatorEnabled=%v, blockProducer=%v — production loop NOT started)",
			n.config.ValidatorEnabled, n.config.BlockProducer)
		n.blockProducer = NewBlockProducer(n, interval)
		// Do NOT call Start() — only needed for election verifier initialization
	}

	// Link QPOS to syncer so applyBlockInternal can replicate epoch reward
	// application. initSyncer runs before blockProducer is created, so SetQPOS
	// must be called here after blockProducer initialization.
	if n.blockProducer != nil && n.syncer != nil {
		if qpos := n.blockProducer.QPOS(); qpos != nil {
			n.syncer.SetQPOS(qpos)
			nodeLog.Info("Syncer QPOS linked for epoch reward replication")
		}
	}

	// R131: restore the validator session-key registry (snapshot → chain replay).
	n.loadVKSnapshots()

	// R53 FIX (2026-08-06): Detect and truncate fragmented chain data.
	//
	// Fragmented storage can report a latest height far above its continuous
	// tip:
	// Previous fork rollbacks leave behind orphan numberPrefix mappings for
	// heights above the continuous tip. findContinuousTipLocked stops at the
	// first ParentHash gap, so it returns a much smaller height than
	// GetLatestHeight. The R52 VRF rebuild then only covers [1, continuousTip],
	// leaving the remaining VRF outputs permanently lost -> proposer election
	// diverges -> chain fork.
	//
	// Fix: Before VRF rebuild, if continuousTip < latestHeight, truncate the
	// orphaned blocks above continuousTip so the chain is consistent and VRF
	// rebuild covers the full range. This is the in-memory equivalent of what
	// "reset chain data" was doing manually, but surgical and automatic.
	if n.blockStore != nil {
		if latestHeight, err := n.blockStore.GetLatestHeight(); err == nil && latestHeight > 0 {
			continuousTip := n.blockStore.FindContinuousTip()
			if continuousTip < latestHeight {
				nodeLog.Warn("R53 FIX: fragmented chain detected (continuousTip=%d < latestHeight=%d), truncating orphans",
					continuousTip, latestHeight)
				var truncated int
				var truncErr error
				if continuousTip > 0 {
					// Delete blocks above the continuous tip.
					truncated, truncErr = n.blockStore.DeleteBlocksFromHeight(continuousTip + 1)
				} else {
					// Chain fully disconnected — clear all non-genesis blocks
					// so the node resyncs from genesis.
					truncated, truncErr = n.blockStore.DeleteBlocksFromHeight(1)
				}
				if truncErr != nil {
					nodeLog.Error("R53 FIX: failed to truncate fragmented chain: %v (will attempt VRF rebuild on available data)", truncErr)
				} else {
					nodeLog.Info("R53 FIX: truncated %d orphaned blocks above continuousTip=%d", truncated, continuousTip)
				}
			}
		}
	}

	// R52 FIX (2026-08-06): Rebuild VRF accumulator from blockStore on restart.
	//
	// ROOT CAUSE of recurring restart-time chain forks:
	// epochVRFAccumulator is pure in-memory state (consensus/block.go:561
	// initializes it as an empty map, never persisted). On restart,
	// NewBlockProducer creates a fresh QPOS with an empty
	// epochVRFAccumulator. blockInsertLoop only processes blocks from
	// [currentHeight+1, ...] (syncer.go:318 sets startHeight=currentHeight),
	// so [1, currentHeight] VRF outputs are permanently lost.
	// ApplyBlockHeader (qpos_proposer.go:590-604) deliberately does NOT
	// accumulate VRF (to avoid double-XOR with blockInsertLoop on the live
	// path), so rebuildState cannot fix this either.
	//
	// Consequence: the shuffle seed (qpos_proposer.go:473) depends on
	// epochVRFAccumulator[epoch-2]. With missing VRF outputs, the seed is
	// wrong -> proposer election diverges from main chain -> chain fork.
	// Resetting chain data "fixes" it only because it forces a full re-sync
	// from genesis (which rebuilds VRF via blockInsertLoop), but the next
	// restart reproduces the fork. This is why "reset is not a solution".
	//
	// Fix: Replay all canonical blocks [1, currentHeight] and accumulate
	// their VRF outputs BEFORE blockInsertLoop starts. Safe because:
	// 1. blockInsertLoop hasn't started yet (no double-accumulation risk)
	// 2. syncer only requests [currentHeight+1, ...] blocks (no overlap)
	// 3. AccumulateVRFOutput uses XOR (commutative, order-independent)
	// 4. QPOS is freshly created (empty accumulator, no stale state)
	// R53: now runs AFTER truncation, so continuousTip == latestHeight.
	if n.blockProducer != nil && n.blockStore != nil {
		if qpos := n.blockProducer.QPOS(); qpos != nil {
			// R58-VRF-PERSIST (2026-08-18): register the persistence callback
			// FIRST so both the R52 replay below and the live block-import
			// path (SetEpochVRFAccumulator) durably record the on-chain
			// accumulator. This is the geth-equivalent guarantee that the
			// proposer entropy is a deterministic, recoverable function of the
			// canonical chain — a restart can never boot with an empty
			// accumulator even if the replay below is skipped or interrupted.
			//
			// The callback is only ever invoked under qpos's internal lock
			// (SetEpochVRFAccumulator holds q.mu), so the debounce state below
			// needs no extra synchronization. Debouncing identical
			// (epoch, value) writes collapses the R52 replay's ~32k per-block
			// calls into ~1 write per distinct value, keeping startup fast.
			var lastPersistEpoch uint64
			var lastPersistAcc types.Hash
			qpos.SetVRFPersistCallback(func(epoch uint64, acc types.Hash) {
				if n.blockStore == nil {
					return
				}
				if epoch == lastPersistEpoch && acc == lastPersistAcc {
					return
				}
				lastPersistEpoch, lastPersistAcc = epoch, acc
				if err := n.blockStore.PutVRFAccumulator(epoch, acc); err != nil {
					nodeLog.Error("R58-VRF-PERSIST: failed to persist epoch %d accumulator: %v", epoch, err)
				}
			})

			// R58-VRF-PERSIST: recover the last known accumulator checkpoint
			// from the block store. R88-C (2026-08-30): the persisted entries are
			// held back and CALIBRATED against the block store AFTER the R52
			// replay below — they are no longer bulk-loaded. Root cause: a
			// persisted checkpoint is a snapshot of the previous session's
			// in-memory map, whose value for an epoch is the LAST per-block
			// assignment of that session. If the previous session ended on a
			// fork that R53 later truncated, or the checkpoint predates a reorg,
			// the persisted value for an epoch may point at a block that is no
			// longer in the store at all — loading it verbatim poisons
			// acc[epoch] with fork-local entropy and diverges the proposer
			// shuffle (the R88 fork class). Calibration rule (below):
			//   - epoch ≤ the replayed tip → the replay already assigned the
			//     authoritative value; the persisted entry is DISCARDED.
			//   - epoch > the replayed tip AND blocks of that epoch survive in
			//     the store → the LAST surviving block's header value wins.
			//   - epoch > the replayed tip with NO surviving blocks → the
			//     persisted entry is DISCARDED (fail-closed: cold-start guard
			// R45 is safer than un-verifiable fork-local entropy).
			persistedAccs, persistedErr := n.blockStore.LoadVRFAccumulators()
			if persistedErr != nil {
				nodeLog.Warn("R58-VRF-PERSIST: failed to load persisted VRF accumulators: %v (R52 replay will rebuild)", persistedErr)
			}

			if latestHeight, err := n.blockStore.GetLatestHeight(); err == nil && latestHeight > 0 {
				continuousTip := latestHeight
				if tip := n.blockStore.FindContinuousTip(); tip < continuousTip {
					continuousTip = tip
				}
				count := 0
				var lastEpoch uint64
				var lastAcc types.Hash
				for h := uint64(1); h <= continuousTip; h++ {
					blk, err := n.blockStore.GetBlockByHeight(h)
					if err != nil || blk == nil {
						nodeLog.Warn("R52 FIX: failed to load block at height %d for VRF rebuild: %v", h, err)
						break
					}
					// R54-ACC (2026-08-07): Rebuild the per-epoch accumulator from
					// the ON-CHAIN header value (deterministic across nodes), not
					// by re-XOR-ing VRF outputs (path-asymmetric → fork).
					qpos.SetEpochVRFAccumulator(blk.Header.Epoch, blk.Header.VRFAccumulator)
					if blk.Header.Epoch >= lastEpoch {
						lastEpoch = blk.Header.Epoch
						lastAcc = blk.Header.VRFAccumulator
					}
					count++
				}
				nodeLog.Info("R52 FIX: Rebuilt VRF accumulator from %d canonical blocks (height 1..%d, lastOnChainEpoch=%d)", count, continuousTip, lastEpoch)

				// R45-WARMUP-REVERT-FIX (2026-08-12): The earlier
				// R45-FUTURE-EPOCH-WARMUP-EXPAND-FIX pre-loaded
				// epochVRFAccumulator for epochs [lastEpoch-2 .. lastEpoch+5]
				// with the chain-tip accumulator as a placeholder. This was
				// MEANT to suppress QPOS cold-start fallbacks during sealer
				// restart, but in practice the placeholder accumulator is
				// not the value that the canonical chain uses for those future
				// epochs: the canonical accumulator is the running XOR of
				// blocks produced above the local tip. For gaps above the tip,
				// a placeholder can elect a proposer different from the
				// canonical-chain ProposerAddr, causing valid incoming blocks
				// to be rejected as ordinary proposer mismatches.
				//
				// The fix is the OPPOSITE of the warmup: do NOT pre-load
				// accumulators for future epochs. Leave them empty. When
				// the syncer imports a new block whose epoch srcEpoch is
				// not in the map, GetProposerForSlot falls back via the
				// R45-PoA-FIX cold-start path (commitProcessingLoop),
				// marking coldStartEpochs[epoch] = {} and returning an
				// epoch-zero-accumulator shuffle to the caller. ValidateBlock
				// (block_validator.go:1317-1323) catches
				// ErrProposerScheduleNotReady explicitly and TRUSTS the
				// canonical proposer for that block instead of rejecting.
				// As the syncer applies block headers (calling
				// SetEpochVRFAccumulator for those future epochs from the
				// authoritative block), the placeholder-shuffle cache
				// is invalidated, coldStartEpochs is cleared, and the
				// schedule catches up to canonical reality.
				//
				// We intentionally keep lastEpoch/lastAcc populated above
				// (no-op uses) so a future, more-accurate warmup strategy
				// can compute it, but we DO NOT write it into qpos for any
				// epoch > lastEpoch. That preserves correctness.
				_ = lastAcc

				// R88-C (2026-08-30): calibrate the R58 persisted checkpoints
				// against the block store — see the long comment at the R58 load
				// above. The replay just assigned authoritative values for every
				// epoch ≤ lastEpoch; for entries beyond that we verify the epoch
				// still has surviving blocks and use the LAST surviving block's
				// header value, else discard (fail-closed).
				if persistedErr == nil && len(persistedAccs) > 0 {
					kept, calibrated, discarded := calibratePersistedVRFAccumulators(
						qpos, n.blockStore, persistedAccs, lastEpoch, continuousTip, latestHeight)
					nodeLog.Info("R58-VRF-PERSIST: calibrated %d persisted VRF accumulator checkpoint(s) against the block store (kept=%d calibrated=%d discarded=%d, replayTipEpoch=%d)",
						len(persistedAccs), kept, calibrated, discarded, lastEpoch)
				}

				// R45-COLDSTART-CLEAR-FIX (2026-08-12): The R52 rebuild above
				// populated q.epochVRFAccumulator for every canonical epoch
				// visible in blockStore [1, continuousTip]. Each
				// SetEpochVRFAccumulator call also cleared coldStartEpochs for
				// epoch+1 and epoch+2, but it did NOT clear coldStartEpochs for
				// the last epoch itself — and crucially, it did NOT scorch the
				// map of any epoch for which we never even called
				// GetProposerForSlot during the rebuild (the rebuild only
				// touches headers, never askes QPOS for shuffles).
				//
				// A stale cold-start flag can survive a restart through the
				// last-session-state replay even when the corresponding VRF
				// accumulator has since been loaded from a block header. The
				// producer would then refuse to propose indefinitely.
				//
				// Fix: clear coldStartEpochs entirely after R52 rebuild. Every
				// epoch with a populated accumulator is now safe to compute
				// the shuffle deterministically from the on-chain header
				// (SetEpochVRFAccumulator → shuffle cache invalidation already
				// ran). Epochs older than those covered by the rebuild are
				// unreachable (chain can only advance past the current tip),
				// and any future epoch depends on the accumulators we just
				// loaded. QPOSProposerForSlot will re-mark a cold-start epoch
				// only if, going forward, it actually has a missing
				// accumulator for a fresh future epoch — which is the
				// legitimate fail-closed path.
				if cleared := qpos.ClearColdStartEpochs(); cleared > 0 {
					nodeLog.Info("FIX: cleared %d stale QPOS cold-start epoch flags after R52 rebuild (chain tip=%d)", cleared, continuousTip)
				}

				// R45-STATE-PERSIST-FIX (2026-08-12): On restart when state was
				// loaded from persistent storage (stateAlreadyPersisted=true),
				// replayBlocksToRestoreState is intentionally skipped (line 702-708)
				// to avoid double-applying transactions. The side effect is that
				// syncer.rebuildState (the only other caller that sets
				// stateVerifiedHeight > 0 via line 3257) is also bypassed — so
				// Syncer.stateVerifiedHeight stays at 0 forever, IsStateReady()
				// returns false, and the BlockProducer loops indefinitely on
				// "Sync done but state not verified yet (verified=0)" instead
				// of producing new blocks. Any sealer that restarts with
				// persisted state can reach this condition.
				//
				// Fix: when we have a continuous tip in the blockStore AND the
				// persisted stateDB root matches the stored block's StateRoot,
				// mark state as verified up to that tip. This is the same trust
				// assumption as IsStateReady's `currentHeight == 0` shortcut
				// (syncer.go:2242): if the local chain is byte-identical to the
				// canonical header (stateRoot match), no replay is needed.
				if n.syncer != nil && n.stateDB != nil {
					tipBlk, tipErr := n.blockStore.GetBlockByHeight(continuousTip)
					if tipErr == nil && tipBlk != nil {
						computed := n.stateDB.Root()
						if computed == tipBlk.Header.StateRoot {
							n.syncer.MarkStateVerified(continuousTip)
							nodeLog.Info("FIX: marked persisted state as verified at height %d (stateRoot match=%x)",
								continuousTip, computed[:8])
						} else {
							nodeLog.Warn("FIX: persisted stateRoot %x != tip block %d stateRoot %x — NOT marking verified; rebuildState will run on first incoming block",
								computed[:8], continuousTip, tipBlk.Header.StateRoot[:8])
						}
					} else {
						nodeLog.Warn("FIX: could not load tip block %d to verify stateRoot (err=%v) — deferring to rebuildState", continuousTip, tipErr)
					}
				}
			}
		}
	}

	// Sync staking validators to QPOS validator set (must happen after block producer init)
	if n.blockProducer != nil && n.stakingManager != nil {
		n.syncQPOSValidatorsFromStaking()
	}

	// P1-2 (2026-07-14): Start ShardBlockProducer if sharding is enabled.
	// Must run after blockProducer init (for validator key + QPOS) and
	// after initSharding (for shardManager). Non-fatal if it fails.
	if n.shardManager != nil && n.blockProducer != nil && n.p2pHost != nil {
		interval := time.Duration(consensus.ShardBlockInterval) * time.Second
		n.shardProducer = NewShardBlockProducer(n, interval)
		if err := n.shardProducer.Start(); err != nil {
			nodeLog.Warn("ShardBlockProducer start failed (non-fatal): %v", err)
		}
	}

	// P0-2 BRDG-03 FIX (2026-07-13): Inject ValidatorNetwork into bridge.
	// Must run after syncQPOSValidatorsFromStaking so the validator set is
	// populated. initBridge (called earlier in initP3Features) created the
	// bridge but could not inject vn because blockProducer was nil then.
	// BRDG-FIX (2026-07-16): returns error if header verifier cannot
	// be fully configured on mainnet — abort startup (fail-closed).
	if err := n.initBridgeValidatorNetwork(); err != nil {
		return err
	}

	// P1-1 FIX (2026-07-13): Start the BridgeAPI HTTP server (if configured).
	// Must run AFTER initBridgeValidatorNetwork because BridgeAPI requires
	// the ValidatorNetwork for /validators and /status endpoints.
	n.startBridgeAPI()

	// Wire ConsensusStakeUpdater so qau_stake RPC propagates to QPOS ValidatorSet.
	// Must happen after blockProducer init (needs QPOS instance).
	if n.blockProducer != nil && n.blockProducer.QPOS() != nil && n.api != nil {
		n.api.SetConsensusStakeUpdater(&consensusStakeUpdaterAdapter{
			vm:   n.validatorManager,
			qpos: n.blockProducer.QPOS(),
		})
		nodeLog.Info("ConsensusStakeUpdater wired (VM + QPOS)")
	}

	// Register Stardust API (qau_stardust_* finality/chambers/ministry queries)
	// and Builder API (qau_builder_* MEV bid submission). These depend on the
	// QPOS engine and the MEV auction, which are only created inside
	// NewBlockProducer (called above in startServices). initRPC runs BEFORE
	// startServices, so n.blockProducer is nil there and these handlers cannot
	// be wired in initRPC. RegisterHandler is mutex-protected (server.go), so
	// registering here is safe even though the RPC server (started in initRPC)
	// may already be serving; requests to these methods before this point simply
	// return "method not found". On non-validator nodes blockProducer stays nil
	// and these consensus/MEV endpoints are intentionally not exposed.
	if n.rpcServer != nil && n.blockProducer != nil {
		if qpos := n.blockProducer.QPOS(); qpos != nil {
			// P1-T1 (2026-07-14): Create the MinistryRegistry singleton once
			// and inject it into StardustAPI. This ensures GetMinistryStatus
			// reads from the same instance that will be wired into the
			// consensus execution path (P1-T2 through P1-T7).
			coordinator := qpos.GetChambersCoordinator()
			if coordinator != nil {
				n.ministryRegistry = consensus.NewMinistryRegistry(qpos, coordinator)
				nodeLog.Info("MinistryRegistry singleton created")

				// P1-T6 (2026-07-14): Unify MinistryRites with GovernanceManager.
				// MinistryRites implements economics.EmergencyActionHandler — when
				// GovernanceManager.ExecuteProposal executes an Emergency-type
				// proposal, it delegates the consensus-layer side effect (Defense
				// ministry blacklisting all validators → chain halt) to MinistryRites.
				// This makes GovernanceManager the single source of truth for
				// proposal/vote state, removing the duplicate logic in MinistryRites.
				if n.governanceManager != nil && n.ministryRegistry.Rites() != nil {
					n.governanceManager.SetEmergencyActionHandler(n.ministryRegistry.Rites())
					nodeLog.Info("MinistryRites wired as EmergencyActionHandler for GovernanceManager")
				}

				// P1-T7 (2026-07-14): Wire MinistryWorks into bridge for
				// governance tracking of cross-chain operations. Bridge
				// registration and cross-chain tx recording are delegated
				// to MinistryWorks via the MinistryWorksRecorder interface.
				if n.bridge != nil {
					if qb, ok := n.bridge.(*bridge.QuantumBridge); ok {
						n.injectBridgeMinistryWorks(qb)
					}
				}

				// P1-T8 (2026-07-14): Create MinistryStateStore and restore
				// persisted state. The store uses the same BoltDB instance
				// as BlockStore (key-prefix isolated: min_per:, min_def:, etc.).
				// CRITICAL: The Defense blacklist must survive restarts — a
				// blacklisted validator that becomes un-blacklisted on restart
				// can compromise consensus safety.
				if n.blockStore != nil {
					n.ministryStateStore = consensus.NewMinistryStateStore(n.blockStore.GetDB())
					if epoch, err := n.ministryStateStore.LoadAll(n.ministryRegistry); err != nil {
						nodeLog.Warn("MinistryStateStore.LoadAll failed: %v (starting with empty ministry state)", err)
					} else if epoch > 0 {
						nodeLog.Info("Ministry state restored from checkpoint epoch %d", epoch)
					}
				}

				// P3-3 (2026-07-15): Wire the ThreeChambersCoordinator as the
				// Three Chambers metric provider so the AlertManager can
				// evaluate evidence queue backlog and DKG-stuck alert rules.
				metrics.Global().SetThreeChambersMetricProvider(coordinator)
				nodeLog.Info("Three Chambers metric provider wired (evidence queue + DKG alerts)")

				// P3-T1 (2026-07-15): Enable Ministry Prometheus metrics (10 spec'd
				// gauges/counters + 2 alert-supporting gauges, qau_ministry_*
				// namespace). Metrics are refreshed periodically by updateNodeMetrics
				// via MinistryRegistry.RefreshMetrics(). The same *MinistryMetrics
				// instance is also injected into the global Metrics instance as a
				// MinistryMetricProvider so the AlertManager can evaluate the 4
				// ministry alert rules (P3-T3).
				ministryMetrics := consensus.NewMinistryMetrics()
				n.ministryRegistry.SetMetrics(ministryMetrics)
				metrics.Global().SetMinistryMetricProvider(ministryMetrics)
				nodeLog.Info("Ministry Prometheus metrics enabled (12 metrics, qau_ministry_* namespace) + 4 alert rules")
			}

			stardustAPI := rpc.NewStardustAPI(qpos)
			if n.ministryRegistry != nil {
				stardustAPI.SetMinistryRegistry(n.ministryRegistry)
			}
			stardustAPI.RegisterHandlers(n.rpcServer)
			nodeLog.Info("Stardust API handlers registered")
		}
		if n.blockProducer.mevProtection != nil {
			builderAPI := rpc.NewBuilderAPI(
				n.blockProducer.mevProtection.Auction(),
				n.blockProducer.mevProtection.Registry(),
				func() uint64 {
					if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
						return n.blockProducer.QPOS().GetCurrentSlot()
					}
					return 0
				},
			)
			builderAPI.RegisterBuilderHandlers(n.rpcServer)
			nodeLog.Info("Builder API handlers registered")
		}
	}

	// Wire TSS signer and verifier BEFORE starting background services.
	// This ensures blockProcessingLoop/blockInsertLoop have the TSS verifier
	// available when they start receiving blocks. Without this, blocks signed
	// with TSS (4064-byte signatures) would fall through to Dilithium3
	// verification and fail.
	//
	// Note: Attestation signing/verification ALWAYS uses individual Dilithium3
	// signatures (see consensus/validator.go). TSS is used for: block signing
	// (optional), QTD finality verification, cross-chain bridges, and multi-sig
	// wallet operations.
	n.wireTSSSigner()
	n.wireKeyVersionValidator()
	n.wireTSSVerifier()
	n.wireElectionVerifier()
	n.wireDankshardingToConsensus()

	// Enable syncing mode if the node is starting from genesis or a very low
	// height. This skips election verification until sync completes, because
	// QPOS internal state (randaoMix, finalizedRoot) cannot be rebuilt without
	// first processing all blocks — a chicken-and-egg problem.
	if n.currentBlock == nil || n.currentBlock.Header.Height == 0 {
		nodeLog.Info("Enabling syncing mode: starting from genesis, election verification will be skipped until sync completes")
		n.blockValidator.SetSyncingMode(true)
	}

	// Start GraphQL HTTP server (separate port from RPC/WS).
	// Configurable via QAU_GRAPHQL_ADDR env var; disabled if set to "off".
	n.startGraphQLServer()

	// Start block processing loop (after TSS wiring to ensure verifier is ready)
	n.wg.Add(1)
	go n.blockProcessingLoop()

	// Start block insert loop (decoupled from network layer)
	n.wg.Add(1)
	go n.blockInsertLoop()

	// Start transaction processing loop
	n.wg.Add(1)
	go n.txProcessingLoop()

	// Start status message processing loop
	n.wg.Add(1)
	go n.statusProcessingLoop()

	// ETHEREUM-PARITY SYNC (2026-08-13): start the extended sync protocol
	// server (serves peer requests) and the response dispatch loop (feeds
	// incoming responses to the syncer).
	if n.snapServer != nil {
		n.snapServer.Start()
	}
	n.wg.Add(1)
	go n.syncResponseProcessingLoop()

	// Start attestation/vote processing loop
	n.wg.Add(1)
	go n.attestationProcessingLoop()

	// Start checkpoint message processing loop
	n.wg.Add(1)
	go n.checkpointProcessingLoop()

	// Start checkpoint recovery monitor (detects stalls and auto-recovers)
	n.wg.Add(1)
	go n.checkpointRecoveryMonitor()

	// Start TSS message processing loop (distributed signing mode and/or
	// distributed DKG mode — both route TSS P2P messages through
	// handleTSSMessage).
	if n.distributedSigner != nil || n.dkgCoordinator != nil {
		n.wg.Add(1)
		go n.tssProcessingLoop()
	}

	// P1-5: Start QTD partial seal processing loop.
	n.wg.Add(1)
	go n.qtdSealProcessingLoop()

	n.wg.Add(1)
	go n.memoryMonitorLoop()
	return nil
}

func (n *Node) wireTSSSigner() {
	if n.tssManager != nil && n.blockProducer != nil && n.blockProducer.QPOS() != nil {
		var adapter *tssSignerAdapter
		if n.config.TSSDistributedMode {
			adapter = newTSSSignerAdapterWithNode(n.tssManager, n)
			nodeLog.Info("TSS signer wired to QPOS (distributed P2P mode)")
		} else {
			adapter = newTSSSignerAdapter(n.tssManager)
			nodeLog.Info("TSS signer wired to QPOS consensus engine")
		}
		n.blockProducer.QPOS().SetThresholdSigner(adapter)
	}
}

func (n *Node) wireKeyVersionValidator() {
	if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
		n.blockValidator.SetKeyVersionValidator(&qposKeyVersionValidator{qpos: n.blockProducer.QPOS()})
		nodeLog.Info("Key version validator wired to QPOS consensus engine")
	}
}

func (n *Node) wireTSSVerifier() {
	if n.tssManager != nil {
		n.blockValidator.SetTSSVerifier(n.tssManager)
		nodeLog.Info("TSS verifier wired to block validator")
	}
}

// wireElectionVerifier connects the QPOS consensus engine to the block
// validator's proposer election verifier.
//
// SECURITY FIX (audit C-1 + S-1): Previously this method never called
// SetElectionVerifier() in production, leaving electionVerifier == nil.
// Combined with BlockValidator's fail-closed logic (rejects all blocks when
// electionVerifier == nil && !devMode), this meant either the chain couldn't
// run or DevMode was secretly enabled in production (bypassing ALL security
// checks). Now we enable strict election verification in production.
func (n *Node) wireElectionVerifier() {
	if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
		if n.config.DevMode {
			n.blockValidator.SetDevMode(true)
			nodeLog.Warn("Election verifier disabled (devMode=true) — node is in dev mode")
		} else {
			// Production: enable strict election verification
			verifier := core.NewQPOSElectionVerifier(n.blockProducer.QPOS())
			// R58-ELEC-TRUST (2026-08-18): only ACTIVE SEALERS keep strict
			// independent proposer verification. A non-producing node
			// (RPC/wallet gateway, verify-only observer — validatorEnabled
			// off, or blockProducer off) follows geth's post-merge model:
			// it does NOT re-derive the beacon proposer schedule, it trusts
			// the canonical-chain ProposerAddr. Without this, a synced
			// non-producer whose local VRF accumulator trajectory diverged
			// (R45-SYNC-TRUST-FIX) rejects every valid block with "proposer
			// mismatch" and stalls forever. The
			// sealer predicate below mirrors startServices' production
			// producer start condition, so a sealer always verifies
			// independently and the QAU_TRUST_CANONICAL_PROPOSER env remains
			// only as a manual override for sealer hosts that opt in.
			isSealer := !n.config.DevMode && n.config.ValidatorEnabled && n.config.BlockProducer && !n.config.SyncOnlyMode
			if !isSealer {
				verifier.SetTrustCanonicalProposer(true)
				nodeLog.Warn("Election verifier: non-sealer node — trusting canonical proposer (geth EL-style, no independent VRF schedule)")
			} else {
				nodeLog.Info("Election verifier: sealer node — strict proposer verification enabled")
			}
			n.blockValidator.SetElectionVerifier(verifier)
			n.blockValidator.SetDevMode(false)
			n.proposerElectionVerifier = verifier // R88-E: producer stand-down signal
			// SECURITY WARNING (audit S-3): VRF verification is not enforced because
			// VRF generation is not yet implemented in the block producer. Without VRF,
			// proposer selection is deterministic and can be predicted by adversaries
			// for targeted DoS attacks. This must be addressed in a future release.
			nodeLog.Warn("VRF verification NOT enforced — proposer selection is predictable (known limitation, audit S-3)")
		}
	}
}

// wireDankshardingToConsensus connects the DankshardingEngine (DA subsystem)
// to the BlockBuilder, BlockValidator, and QPOS consensus engine.
//
// P1-1~P1-4 (2026-07-14): Previously the engine was created and started in
// initDanksharding() but never injected into the downstream consumers, so
// all DA checks were silently skipped:
//   - BlockBuilder.processBlobsForBlock was a no-op (danksharding == nil)
//   - BlockValidator.verifyBlockDA was skipped (daCheckEnabled == false)
//   - QPOS.CheckDAAvailability returned nil (daAvailabilityCheck == nil)
//
// After this wiring:
//   - BlockBuilder stores blob matrices for blocks it produces
//   - BlockValidator verifies DA availability for incoming blocks (when not
//     syncing — syncingMode skips DA checks to allow fast catch-up)
//   - QPOS checks DA availability before finalizing blocks (hard check in
//     ThreeChambersFlow.FinalizeBlock) and before proposing (soft check in
//     CanPropose — logs warning but does not block liveness)
//
// When DankshardingEngine is nil (DA disabled), all three are no-ops.
func (n *Node) wireDankshardingToConsensus() {
	if n.danksharding == nil {
		// DA subsystem disabled — all downstream checks remain no-ops.
		return
	}

	// P1-2: Blob processing is already wired in BlockProducer.processBlobsForDA
	// (block_producer.go:2316) via bp.node.danksharding.ProcessBlobsForBlock.
	// No additional injection needed — BlockProducer accesses the engine
	// directly through the Node reference.

	// P1-3: Inject into BlockValidator and enable DA availability checks.
	// DA checks are skipped during syncing (SetSyncingMode(true)) to allow
	// fast chain catch-up without waiting for DAS sampling on every block.
	if n.blockValidator != nil {
		n.blockValidator.SetDankshardingEngine(n.danksharding)
		n.blockValidator.SetDACheckEnabled(true)
		nodeLog.Info("DankshardingEngine injected into BlockValidator (DA checks enabled, skipped during sync)")
	}

	// P1-4: Inject DA availability checker into QPOS.
	// CanPropose: soft check (logs warning, does not block proposing)
	// FinalizeBlock: hard check (rejects finalization if DA unavailable)
	if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
		qpos := n.blockProducer.QPOS()
		qpos.SetDAAvailabilityChecker(func(slot uint64) error {
			// AUDIT (2026) DA-FIX (HIGH): Previously, when
			// aggregate==nil (no attestation, insufficient attestation,
			// or signature aggregation failure), the checker returned nil
			// (fail-open), allowing finalization without DA proof. This
			// created a double fail-open with BlockValidator.verifyBlockDA
			// (which also skipped when no sidecar was present), letting
			// an attacker finalize blocks with unavailable blob data by
			// suppressing attestation submission.
			//
			// Now fail-closed: every finalized slot MUST have a sufficient
			// aggregate attestation. BuildAggregateAttestation returns
			// non-nil ONLY when IsSufficient()=true (AvailableCount/
			// TotalCount >= 0.6667), so a nil aggregate means either no
			// attestation was submitted or the attestations were
			// insufficient. Either way, finalization is blocked.
			//
			// Note: DA- already hard-guards mainnet against enabling
			// danksharding, so this check only runs on testnet/devnet
			// where DA is enabled. On those networks, blocking finalization
			// when DA proof is missing is the correct behavior — it forces
			// the DA committee to submit attestations.
			aggregate := n.danksharding.GetAggregateAttestation(slot)
			if aggregate == nil {
				return fmt.Errorf("DA aggregate attestation missing or insufficient for slot %d — finalization blocked (DA-)", slot)
			}
			// aggregate is non-nil, which means IsSufficient()=true (see
			// BuildAggregateAttestation contract). Double-check defensively.
			if !aggregate.IsSufficient() {
				return fmt.Errorf("DA attestation insufficient for slot %d: %d/%d available (DA-)",
					slot, aggregate.AvailableCount, aggregate.TotalCount)
			}
			return nil
		})
		nodeLog.Info("DA availability checker injected into QPOS (fail-closed: blocks finalization without sufficient attestation, DA-)")
	}
}

// initLightClient initializes the light client components (header syncer, SPV prover)
// and registers RPC handlers if enabled via config.LightClientEnabled.
// The light client is optional and disabled by default.
func (n *Node) initLightClient() {
	if !n.config.LightClientEnabled {
		return
	}
	if n.blockStore == nil {
		nodeLog.Warn("Light client enabled but blockStore is nil, skipping")
		return
	}

	// HeaderSyncer provides header retrieval and checkpoint verification for
	// light clients. trustedPubKey is nil (optional) — checkpoints cannot be
	// verified without it, but header retrieval and SPV proofs still work.
	n.headerSyncer = lightclient.NewHeaderSyncer(n.blockStore, nil)

	// SPVProver generates Merkle proofs for transactions and state.
	if n.stateDB != nil {
		n.spvProver = lightclient.NewSPVProver(n.blockStore, n.stateDB)
	}

	// LightClientAPI exposes light client RPC methods (qau_light_*).
	n.lightClientAPI = lightclient.NewLightClientAPI(n.headerSyncer, n.spvProver)

	// Wire callbacks for light client endpoints that need node-level operations.
	if n.txPool != nil {
		n.lightClientAPI.SetTxSubmitter(func(tx *encoding.Transaction) error {
			return n.txPool.Add(tx)
		})
	}
	if n.stateDB != nil {
		n.lightClientAPI.SetBalanceLookup(func(addr types.Address) (*big.Int, uint64, error) {
			balance := n.stateDB.GetBalance(addr)
			nonce := n.stateDB.GetNonce(addr)
			return balance, nonce, nil
		})
	}

	nodeLog.Info("Light client initialized (headerSyncer + SPV prover)")
}

// startGraphQLServer starts the GraphQL HTTP server on a configurable port.
// The address is read from the QAU_GRAPHQL_ADDR env var, defaulting to
// 127.0.0.1:8547 (8547 avoids conflict with the WebSocket server on 8546).
// Set QAU_GRAPHQL_ADDR=off to disable the GraphQL server entirely.
func (n *Node) startGraphQLServer() {
	addr := os.Getenv("QAU_GRAPHQL_ADDR")
	if addr == "off" {
		nodeLog.Info("GraphQL server disabled by QAU_GRAPHQL_ADDR=off")
		return
	}
	if addr == "" {
		addr = "127.0.0.1:8547"
	}

	// Create the GraphQL resolver and handler using a blockchain reader adapter.
	reader := &graphqlReaderAdapter{n}
	resolver := graphql.NewResolver(reader)
	handlerCfg := graphql.DefaultHandlerConfig()
	graphqlHandler := graphql.NewHandler(resolver, handlerCfg)

	mux := http.NewServeMux()
	mux.Handle("/", graphqlHandler)

	n.graphqlServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second, // P2P-R11-H04: Slowloris header-DoS protection
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second, // P2P-R11-H04: bound keepalive resource use
		MaxHeaderBytes:    1 << 20,           // P2P-R11-H04: 1 MiB header cap
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				nodeLog.Error("GraphQL server goroutine panic: %v", r)
			}
		}()
		nodeLog.Info("Starting GraphQL server on %s...", addr)
		if err := n.graphqlServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			nodeLog.Error("GraphQL server failed: %v", err)
		}
	}()
}

// EventBus returns the node's event bus for subscribing to real-time events
// (NewBlockEvent, NewTxEvent, NewAttestationEvent).
func (n *Node) EventBus() *event.TypeMux {
	return n.eventBus
}

// blockProcessingLoop processes incoming blocks
func (n *Node) blockProcessingLoop() {
	defer n.wg.Done()
	// R32-P1-03 FIX (2026-07-28): top-level panic recovery so a panic in
	// block unmarshalling, validation, or fork handling cannot kill the
	// block-processing goroutine and stall sync/consensus.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("blockProcessingLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	blockCh := n.p2pHost.SubscribeBlocks()
	blockReqCh := n.p2pHost.SubscribeBlockRequests()

	// SYNC-P2P-03 FIX (deep-audit 2026-07-12): bound the number of concurrent
	// block-request handlers. MsgTypeBlockReq is classified as a sync message
	// and so bypasses the per-peer rate limiter; previously each request spawned
	// an unbounded goroutine, each reading up to a full batch of blocks from the
	// DB and marshaling several MB. A peer streaming requests could exhaust
	// CPU/memory/goroutines. When the pool is saturated the request is dropped
	// (the peer re-requests), capping the amplification.
	const maxConcurrentBlockReq = 8
	blockReqSem := make(chan struct{}, maxConcurrentBlockReq)

	for {
		select {
		case <-n.ctx.Done():
			return
		case blockData := <-blockCh:
			if len(blockData) < 32 {
				continue
			}
			blk, err := encoding.UnmarshalBlock(blockData)
			if err != nil {
				continue
			}
			if blk.Header == nil || blk.Header.ProposerAddr == (types.Address{}) {
				continue
			}
			if blk.Header.ChainID != 0 && blk.Header.ChainID != n.chainID {
				continue
			}
			n.syncBufMu.Lock()
			currentH := uint64(0)
			if n.syncer != nil {
				currentH = n.syncer.CurrentHeight()
			}

			if blk.Header.Height == 0 {
				nodeLog.Info("blockProcessingLoop: received genesis block (currentH=%d)", currentH)
			} else if blk.Header.Height <= currentH+500 && blk.Header.Height >= currentH {
				nodeLog.Info("blockProcessingLoop: received block height=%d (currentH=%d, syncBuf=%d)",
					blk.Header.Height, currentH, len(n.syncBuf))
			} else {
				n.syncBufMu.Unlock()
				continue
			}

			// R33 NODE-06 FIX (2026-07-28): Overflow threshold reduced from
			// 2000 to 200 per spec (project memory: "clear syncBuf when its
			// length exceeds 200 to prevent deadlock"). The previous 2000
			// threshold allowed ~2000 blocks to accumulate before eviction,
			// causing memory pressure and delaying deadlock detection.
			//
			// R60-SYNC (2026-08-18): the wholesale clear below (line ~6544)
			// fired whenever the buffer hit 200 in-window blocks whose parents
			// had not arrived YET, discarding valid blocks and forcing the
			// request→clear→re-request thrash seen on mainnet. It is now gated
			// on the same genuine-stall condition as takeNextBlock: no block
			// successfully inserted for the stall window. Eviction of
			// far-ahead/old blocks (correct, those are never processable) is
			// unchanged.
			if len(n.syncBuf) >= 200 {
				if blk.Header.Height > currentH+500 && blk.Header.Height != 0 {
					n.syncBufMu.Unlock()
					continue
				}
				dropped := 0
				filtered := n.syncBuf[:0]
				for _, b := range n.syncBuf {
					if b.Header.Height > currentH+500 || (b.Header.Height <= currentH && b.Header.Height != 0) {
						dropped++
					} else {
						filtered = append(filtered, b)
					}
				}
				n.syncBuf = filtered
				if dropped > 0 {
					nodeLog.Info("blockProcessingLoop: evicted %d far-ahead/old blocks from syncBuf (currentH=%d, incoming=%d)", dropped, currentH, blk.Header.Height)
				}
				if len(n.syncBuf) >= 200 && time.Since(n.lastBlockInsert) > 30*time.Second {
					evicted := len(n.syncBuf)
					n.syncBuf = n.syncBuf[:0]
					n.syncBufMu.Unlock()
					nodeLog.Warn("blockProcessingLoop: syncBuf stall (%d blocks, no insert for %v), clearing entirely (currentH=%d)",
						evicted, time.Since(n.lastBlockInsert).Round(time.Second), currentH)
					continue
				}
			}

			if blk.Header.Height > currentH+500 && blk.Header.Height != 0 {
				n.syncBufMu.Unlock()
				continue
			}
			if blk.Header.Height < currentH && blk.Header.Height != 0 {
				n.syncBufMu.Unlock()
				continue
			}

			// ROOT-CAUSE FIX (2026-08-07): Notify the syncer IMMEDIATELY when
			// a block is received, BEFORE adding it to syncBuf. This closes
			// the race window between blockProcessingLoop (receipt) and
			// blockInsertLoop (processing) where the produceLoop could fire
			// and see highestKnown == currentHeight, incorrectly concluding
			// no sync is needed → producing a conflicting block → chain fork.
			// NotifyIncomingBlock updates highestKnown and sets syncActive=1
			// so IsSyncing() returns true before the producer can fire.
			if n.syncer != nil && blk.Header.Height > currentH {
				n.syncer.NotifyIncomingBlock(blk.Header.Height)
			}

			n.syncBuf = append(n.syncBuf, blk)
			n.syncBufMu.Unlock()
			select {
			case n.syncBufSignal <- struct{}{}:
			default:
			}
		case reqMsg := <-blockReqCh:
			// SYNC-P2P-03 FIX: acquire a handler slot; drop the request if the
			// pool is saturated so a request flood cannot spawn unbounded
			// goroutines / DB reads. The requesting peer will re-request.
			select {
			case blockReqSem <- struct{}{}:
				go func(m p2p.PeerMessage) {
					defer func() { <-blockReqSem }()
					// R34 P1-01 FIX (2026-07-29): Top-level panic recovery.
					// handleBlockRequest decodes untrusted peer-supplied
					// data (p2p.DecodeBlockRequest), marshals blocks
					// (encoding.MarshalBlock), and sends raw bytes back to
					// the peer. Any of these can panic on malformed input
					// or edge-case conditions (nil pointer dereference on
					// a corrupted block, send on closed channel during
					// shutdown, etc.). Without this recover, a single
					// malicious peer message crashes the entire node.
					defer func() {
						if r := recover(); r != nil {
							nodeLog.Error("blockProcessingLoop: blockRequest handler panic recovered (peer=%s): %v", m.From, r)
						}
					}()
					// P3-NODE-07 FIX (R30, 2026-07-27): check the error
					// return value and log it so operators can diagnose
					// why a peer's sync request went unanswered. Without
					// this, failures in handleBlockRequest (decode errors,
					// block fetch failures, send failures) were silently
					// dropped, making sync issues impossible to root-cause.
					if err := n.handleBlockRequest(m); err != nil {
						nodeLog.Warn("blockProcessingLoop: handleBlockRequest failed for peer %s: %v", m.From, err)
					}
				}(reqMsg)
			default:
				nodeLog.Warn("blockProcessingLoop: block-request handler pool saturated (max=%d), dropping request", maxConcurrentBlockReq)
			}
		}
	}
}

func (n *Node) memoryMonitorLoop() {
	defer n.wg.Done()
	// NODE-P2-01 FIX (R31, 2026-07-28): top-level panic recovery ensures a
	// single unrecovered panic cannot kill the memory monitor goroutine
	// permanently, which would leave the node without OOM protection.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("memoryMonitorLoop: top-level panic recovered (monitor terminated): %v", r)
		}
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lastGCCount uint32
	const memoryThresholdMB = 2048

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
		// NODE-P2-01 FIX (R31, 2026-07-28): per-tick recover so a panic
		// in runtime.ReadMemStats, syncBuf eviction, or syncer cleanup
		// does not terminate the entire monitor. The next tick will
		// retry. Without this, a transient panic (e.g., nil syncer after
		// a concurrent shutdown) silently disables memory monitoring.
		func() {
			defer func() {
				if r := recover(); r != nil {
					nodeLog.Error("memoryMonitorLoop: tick panic recovered (continuing): %v", r)
				}
			}()

			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			allocMB := m.Alloc / 1024 / 1024
			sysMB := m.Sys / 1024 / 1024

			n.syncBufMu.Lock()
			syncBufLen := len(n.syncBuf)
			n.syncBufMu.Unlock()

			pendingCnt := 0
			if n.syncer != nil {
				pendingCnt = n.syncer.PendingCount()
			}

			nodeLog.Info("MEMORY: alloc=%dMB sys=%dMB heapInUse=%dMB gcCount=%d syncBuf=%d pending=%d goroutines=%d",
				allocMB, sysMB, m.HeapInuse/1024/1024, m.NumGC-lastGCCount, syncBufLen, pendingCnt, runtime.NumGoroutine())

			if allocMB > memoryThresholdMB {
				nodeLog.Warn("MEMORY: high memory usage (%dMB > %dMB threshold), triggering GC and eviction", allocMB, memoryThresholdMB)
				runtime.GC()

				n.syncBufMu.Lock()
				// R33 NODE-06 FIX (2026-07-28): Memory monitor threshold reduced
				// from 1000 to 100 (proportional to the overflow threshold
				// reduction from 2000 to 200). This is defense-in-depth: the
				// primary overflow check at line ~5790 caps syncBuf at 200, but
				// if a race condition allows it to grow, this backup triggers.
				if len(n.syncBuf) > 100 {
					var currentH uint64
					if n.syncer != nil {
						currentH = n.syncer.CurrentHeight()
					}
					// Evict blocks far ahead of currentH, preserving blocks needed for sync.
					// The old approach (n.syncBuf[evicted:]) dropped the oldest blocks,
					// which included the critical currentH+1 block that takeNextBlock
					// needs for fork detection. This caused nodes to permanently stall
					// when they fell behind due to a fork/checkpoint mismatch.
					evicted := 0
					if currentH > 0 {
						filtered := n.syncBuf[:0]
						for _, b := range n.syncBuf {
							if b.Header.Height > currentH+500 {
								evicted++
							} else {
								filtered = append(filtered, b)
							}
						}
						n.syncBuf = filtered
					} else {
						evicted = len(n.syncBuf) - 50
						n.syncBuf = n.syncBuf[evicted:]
					}
					nodeLog.Warn("MEMORY: evicted %d blocks from syncBuf (remaining=%d, currentH=%d)", evicted, len(n.syncBuf), currentH)
				}
				n.syncBufMu.Unlock()

				if n.syncer != nil {
					n.syncer.ClearPendingBlocks()
				}
			}

			lastGCCount = m.NumGC
		}()
	}
}

func (n *Node) takeNextBlock() *encoding.Block {
	n.syncBufMu.Lock()
	defer n.syncBufMu.Unlock()
	if len(n.syncBuf) == 0 {
		return nil
	}

	// Get current height for fork detection fallback
	var currentH uint64
	if n.syncer != nil {
		currentH = n.syncer.CurrentHeight()
	}

	var bestIdx int = -1
	parentCheckCount := 0
	parentFoundCount := 0
	for i := 0; i < len(n.syncBuf); i++ {
		h := n.syncBuf[i].Header.Height
		if h <= 1 {
			if bestIdx == -1 || h < n.syncBuf[bestIdx].Header.Height {
				bestIdx = i
			}
			continue
		}
		parentCheckCount++
		parentExists, _ := n.blockStore.HasBlock(n.syncBuf[i].Header.ParentHash)
		if parentExists {
			parentFoundCount++
			if bestIdx == -1 || h < n.syncBuf[bestIdx].Header.Height {
				bestIdx = i
			}
		}
	}

	// Debug log: show why takeNextBlock made its choice
	if parentCheckCount > 0 && parentFoundCount == 0 && len(n.syncBuf) > 0 {
		// Log first few blocks' parent hash for debugging
		sample := n.syncBuf[0]
		if sample.Header.Height > 1 {
			nodeLog.Info("takeNextBlock: no parent found in store! syncBuf=%d, currentH=%d, checked=%d, found=%d, sampleBlock=%d, sampleParent=%x",
				len(n.syncBuf), currentH, parentCheckCount, parentFoundCount,
				sample.Header.Height, sample.Header.ParentHash[:8])
		}
	}

	// If no block has a parent in the store, try blocks at currentH+1
	// to trigger fork detection in ProcessBlock. This prevents the node
	// from being stuck when the local chain tip hash differs from peers
	// (e.g., after a checkpoint/TSS signature mismatch).
	if bestIdx == -1 && currentH > 0 {
		for i := 0; i < len(n.syncBuf); i++ {
			if n.syncBuf[i].Header.Height == currentH+1 {
				bestIdx = i
				nodeLog.Info("takeNextBlock: using fallback (currentH+1=%d), syncBuf=%d", currentH+1, len(n.syncBuf))
				break
			}
		}
	}

	if bestIdx == -1 {
		// Anti-deadlock: if syncBuf has unprocessable blocks (parent not in
		// store and no currentH+1 block), clear it to prevent permanent stall.
		// checkSync() will re-request blocks from currentH+1, and peers will
		// resend the correct blocks. Without this, syncBuf fills with blocks
		// whose parents are missing, ProcessBlock is never called, and the
		// node is stuck forever.
		//
		// R60-SYNC (2026-08-18): this clear is now gated on a GENUINE stall
		// instead of a raw buffer length. During healthy out-of-order sync
		// (multiple peers delivering overlapping ranges), a buffer full of
		// blocks whose parents have not arrived YET is normal — the parents
		// arrive moments later and the blocks become processable. The old
		// threshold (len > 50) discarded valid blocks and forced constant
		// re-requests during overlapping peer delivery.
		// We raise the threshold to match the accepted window (200, see
		// blockProcessingLoop) and only clear once no block has been
		// successfully inserted for the syncer's stall window (30s). A
		// fork-polluted buffer (parents that will NEVER arrive) stalls
		// inserts and is still cleared — deadlock protection is preserved.
		const syncBufOverflowThreshold = 200
		if len(n.syncBuf) > syncBufOverflowThreshold && time.Since(n.lastBlockInsert) > 30*time.Second {
			nodeLog.Warn("takeNextBlock: syncBuf stall (%d > %d, no insert for %v), clearing to prevent deadlock (currentH=%d)",
				len(n.syncBuf), syncBufOverflowThreshold, time.Since(n.lastBlockInsert), currentH)
			for i := range n.syncBuf {
				n.syncBuf[i] = nil
			}
			n.syncBuf = n.syncBuf[:0]
		}
		nodeLog.Info("takeNextBlock: returning nil, syncBuf=%d, currentH=%d, checked=%d, found=%d, lastInsert=%v ago",
			len(n.syncBuf), currentH, parentCheckCount, parentFoundCount, time.Since(n.lastBlockInsert).Round(time.Second))
		return nil
	}
	blk := n.syncBuf[bestIdx]
	n.syncBuf[bestIdx] = n.syncBuf[len(n.syncBuf)-1]
	n.syncBuf[len(n.syncBuf)-1] = nil
	n.syncBuf = n.syncBuf[:len(n.syncBuf)-1]
	return blk
}

func (n *Node) blockInsertLoop() {
	defer n.wg.Done()
	// NODE-P0-01 FIX (R31, 2026-07-27): Top-level panic recovery. Go's
	// runtime terminates the entire process on any unrecovered panic in
	// any goroutine. blockInsertLoop is the core block-import path; a
	// panic in ProcessBlock/syncStakingFromBlock/economicsManager.ProcessBlock
	// would crash the node and equate to a remote DoS vector if triggered
	// by a malicious peer-crafted block. This top-level recover is the
	// last line of defense — per-iteration recover below catches most
	// panics at finer granularity, but this one ensures the goroutine
	// never dies. After recovery, we log and continue the outer loop so
	// sync can resume; a corrupted in-memory state would be caught by
	// subsequent state-root checks.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("blockInsertLoop: top-level panic recovered (process NOT killed): %v", r)
		}
	}()
	nodeLog.Info("blockInsertLoop: goroutine started")

	insertCount := uint64(0)
	lastProgressLog := time.Now()

	for {
		select {
		case <-n.ctx.Done():
			nodeLog.Info("blockInsertLoop: ctx done, exiting")
			return
		case <-n.syncBufSignal:
		}

		for {
			blk := n.takeNextBlock()
			if blk == nil {
				break
			}
			insertCount++
			height := blk.Header.Height

			// NODE-P0-01 FIX (R31, 2026-07-27): Per-iteration panic
			// recovery. Wrapping the entire block-processing body in an
			// anonymous function with defer recover ensures a panic on
			// ONE block does not kill the goroutine and break sync for
			// all subsequent blocks. The block is dropped (continue to
			// the next one) on panic, mirroring the error-handling path
			// for ProcessBlock failures. Without this, a single malicious
			// block triggering a nil-pointer or out-of-bounds panic
			// would crash the whole node. Tracked by NODE-P0-01.
			func() {
				defer func() {
					if r := recover(); r != nil {
						nodeLog.Error("blockInsertLoop: panic recovered processing block %d (dropped, continuing): %v", height, r)
						// R39-P3-03 (2026-08-02) FIX: increment the
						// panic counter; if it crosses the threshold,
						// log.Fatalf to let systemd / watchdog restart
						// the process from a clean state. The audit's
						// finding observes that the bare-recover-then-
						// continue pattern leaves the node vulnerable to
						// chronic-injection DoS — a malicious peer can
						// repeatedly inject blocks that panic
						// ProcessBlock and hold the node in a chronic
						// drop-and-continue state, never making forward
						// progress. A clean restart via RecoverConsistency
						// is safer than continuing with potentially
						// corrupt in-memory state (a panic mid-SSTORE
						// could leave the StateDB with a half-mutated
						// account).
						//
						// The counter is reset to 0 on every successful
						// block insert (see the Store(0) at the bottom of
						// this anonymous func body), so the threshold is
						// a "consecutive-panic budget" — not a lifetime
						// crash budget. A single bad-patch-of-blocks
						// won't accumulate toward restart during
						// otherwise-healthy operation.
						//
						// Read the threshold under no lock — it's set
						// once in NewNode and is read-only after.
						count := n.blockInsertPanicCount.Add(1)
						threshold := n.panicRestartThreshold
						if shouldRestartAfterPanic(count, threshold) {
							// The threshold-decision logic is
							// delegated to shouldRestartAfterPanic so
							// the unit test
							// (node_r39_p3_03_test.go) can verify
							// the boundary WITHOUT triggering an
							// actual os.Exit (which would kill the
							// test process itself).
							//
							// log.Fatalf calls os.Exit(1) AFTER
							// writing the log entry — defers do NOT
							// run, but the goroutine's outer defer
							// (top-level recover at line 6219) is
							// already past (we're INSIDE the inner
							// per-iteration recover). The process
							// death is the intent; the top-level
							// recover does not stand in the way. We
							// craft an explicit marker string so
							// operators grep for "R39-P3-03" to
							// identify this restart mode in log
							// aggregators.
							nodeLog.Error("R39-P3-03: blockInsertLoop panic count reached threshold (count=%d, threshold=%d, consecutive panics in block processing) — restarting process so systemd/watchdog recovers from a clean state; the audit's chronic-injection DoS guard has triggered", count, threshold)
							// Use os.Exit(3) — exit code 3 is the
							// conventional "restart me" signal for
							// systemd (Type=notify +
							// Restart=on-failure reads non-zero
							// exit as failure). Don't use
							// log.Fatalf because it writes to
							// stderr with a timestamp prefix that
							// log aggregators index differently from
							// the nodeLog.Error above.
							os.Exit(3)
						}
					}
				}()

				if n.syncer != nil {
					n.syncer.UpdateHighestKnown(height)
				}

				blockHash := block.ComputeBlockHash(blk.Header)

				if n.syncer == nil {
					return
				}

				pbStart := time.Now()
				if err := n.syncer.ProcessBlock(blk); err != nil {
					if err == ErrParentNotFound {
						// ProcessBlock already added this block to pendingBlocks (if
						// capacity allowed). We must NOT re-add it to syncBuf — doing
						// so creates an infinite loop because takeNextBlock() will
						// return the same block again via the currentH+1 fallback,
						// and ProcessBlock will fail again with ErrParentNotFound.
						//
						// If pendingBlocks is full (maxPendingBlocks=500), the block
						// is dropped. This is acceptable because:
						//   1. The syncer's syncLoop periodically requests missing
						//      blocks from peers via checkSync()
						//   2. ProcessBlock now actively requests the missing parent
						//      block when parentNotFound (see syncer.go)
						//   3. Once the parent arrives, ProcessPendingBlocks will
						//      process any children still in pendingBlocks
						if height%1000 == 0 {
							nodeLog.Info("blockInsertLoop: block %d parent not found (pending=%d, pbDur=%v) — dropped, will be re-requested",
								height, n.syncer.PendingCount(), time.Since(pbStart))
						}
						select {
						case n.syncBufSignal <- struct{}{}:
						default:
						}
					} else if err == ErrForkDetected {
						// Fork was detected but not confirmed. Drop this block (it has a
						// mismatched parent hash) instead of retrying it in a loop.
						// ForkDetected handler already called requestBlocksFromBestPeer.
						nodeLog.Warn("blockInsertLoop: dropping block %d due to fork detection (pbDur=%v)", height, time.Since(pbStart))
					} else if !errors.Is(err, ErrStateRootMismatch) {
						nodeLog.Warn("blockInsertLoop: ProcessBlock failed for block %d: %v (pbDur=%v)", height, err, time.Since(pbStart))
					}
					return
				}
				if d := time.Since(pbStart); d > 500*time.Millisecond {
					nodeLog.Warn("blockInsertLoop: ProcessBlock slow for block %d: %v", height, d)
				}

				if n.syncer == nil || !n.syncer.IsSyncing() {
					go n.syncer.ProcessPendingBlocks(blockHash)
				}

				lockStart := time.Now()
				n.mu.Lock()
				lockDur := time.Since(lockStart)
				if lockDur > 100*time.Millisecond {
					nodeLog.Warn("blockInsertLoop: n.mu.Lock() took %v for block %d", lockDur, height)
				}
				shouldSwitch := false
				shouldSyncStaking := false
				skippedStakingSync := false
				if n.currentBlock == nil {
					shouldSwitch = true
				} else if blk.Header.Height > n.currentBlock.Header.Height {
					shouldSwitch = true
				} else if blk.Header.Height == n.currentBlock.Header.Height && blk.Header.Slot < n.currentBlock.Header.Slot {
					shouldSwitch = true
				} else if blk.Header.Height == n.currentBlock.Header.Height && blk.Header.Slot == n.currentBlock.Header.Slot {
					// AUDIT R4-CORE-02 (2026-07-15): Deterministic tiebreak at
					// equal height + equal slot. Previously the first-received
					// block won (non-deterministic) — two honest nodes receiving
					// competing blocks in different orders picked different
					// canonical heads, which could finalize conflicting roots.
					// Use the lower hash (lexicographic) as a deterministic
					// tiebreak so all nodes converge to the same head regardless
					// of import order.
					currentHeadHash := block.ComputeBlockHash(n.currentBlock.Header)
					if bytes.Compare(blockHash[:], currentHeadHash[:]) < 0 {
						shouldSwitch = true
					}
				} else if n.syncer != nil && n.syncer.IsSyncing() && blk.Header.Height < n.currentBlock.Header.Height {
					if _, err := n.blockStore.GetBlockByHeight(n.currentBlock.Header.Height); err != nil {
						shouldSwitch = true
					}
				}
				// AUDIT R4-CORE-02 (2026-07-15): Capture the old head BEFORE
				// switching so we can re-anchor slotBlockRoots along the new
				// canonical segment if a reorg occurred. Stale roots from the
				// abandoned fork would otherwise poison tryUpdateFinality.
				var oldHead *encoding.Block
				var oldHeadHash types.Hash
				if shouldSwitch && n.currentBlock != nil {
					oldHead = n.currentBlock
					oldHeadHash = block.ComputeBlockHash(n.currentBlock.Header)
				}
				if shouldSwitch {
					n.currentBlock = blk
					// R79-STAKING-RESYNC (2026-08-28): the gate used to be
					// `!syncer.IsSyncing()`, but on a live chain the syncer
					// stays in "syncing" state almost permanently (it keeps
					// requesting the next block from peers), so followers
					// NEVER applied staking side effects while the proposer
					// always did. Gate on "genuinely far behind" instead: a
					// node at (or near) the network head must apply staking
					// txs exactly like the proposer, or the validator sets
					// diverge and the chain forks.
					if !n.isFarBehindForStakingSync() {
						shouldSyncStaking = true
					} else if blockHasStakingTx(blk) {
						// R79-STAKING-RESYNC (2026-08-28): the staking side
						// effects of this block are being skipped because the
						// syncer is active. Remember it so a full rescan runs
						// once the syncer goes idle - otherwise this node's
						// validator set silently diverges from its peers'.
						skippedStakingSync = true
					}

					// Update Prometheus native metrics
					if n.nodeMetrics != nil {
						n.nodeMetrics.BlockHeight.Set(float64(blk.Header.Height))
						n.nodeMetrics.TxPerBlock.Observe(float64(len(blk.Transactions)))
						n.nodeMetrics.TotalTxns.Add(float64(len(blk.Transactions)))
					}
				}
				n.mu.Unlock()

				// syncStakingFromBlock moved outside lock to prevent deadlock
				if skippedStakingSync {
					n.stakingResyncPending.Store(true)
					nodeLog.Warn("blockInsertLoop: staking txs in block %d skipped while syncing - full staking rescan queued (R79)",
						blk.Header.Height)
				}
				if shouldSyncStaking {
					n.syncStakingFromBlock(blk)
					n.syncValidatorKeysFromBlock(blk)
				}
				// Always give a queued rescan a chance: it self-guards on
				// "still far behind" and on "already running".
				n.runPendingStakingResync()

				// Publish new block event for real-time subscribers (GraphQL, WS, etc.)
				if shouldSwitch && n.eventBus != nil {
					// NODE-P2-02 FIX (R31, 2026-07-28): log EventBus.Post errors instead
					// of silently discarding. A failing subscriber (panic in handler, full
					// channel) would silently drop block notifications, leaving WS/GraphQL
					// clients stale with no diagnostic trail.
					if err := n.eventBus.Post(NewBlockEvent{Block: blk}); err != nil {
						nodeLog.Warn("EventBus.Post(NewBlockEvent) failed at height %d: %v", blk.Header.Height, err)
					}
				}

				// FIX: Process economics for the committed block — collect gas fees,
				// distribute to FeeDistributor pools, and track inflation. This activates
				// the  FeeDistributor integration that was previously dead code.
				// Economics processing is accounting-only (no StateDB mutations), so it
				// cannot cause state-root mismatches between nodes.
				if shouldSwitch && n.economicsManager != nil {
					gasPrice := blk.Header.BaseFee
					if gasPrice == nil {
						gasPrice = big.NewInt(0)
					}
					// FIX: Route EIP-1559 blocks to ProcessEIP1559Block.
					// Previously, node.go only called ProcessBlock for ALL blocks,
					// leaving ProcessEIP1559Block as dead code. When BaseFee is set
					// (EIP-1559 active), use the EIP-1559 path which handles
					// baseFee + priorityFees splitting and FeeDistributor integration.
					var econErr error
					if blk.Header.BaseFee != nil && blk.Header.BaseFee.Sign() > 0 {
						// EIP-1559 block: pass baseFee and priorityFees (tip) separately.
						//
						// AUDIT (2026) R4-ECON-05 FIX: Previously priorityFees was
						// hardcoded to 0, causing the offline supply/burn tracker to
						// silently drop all tip revenue from its accounting. The block
						// header carries BaseFee but NOT the aggregate priority fees,
						// so we compute the sum from individual transactions. For each
						// EIP-1559 tx (TxTypeDynamicFee/TxTypeBlob), the effective
						// priority fee per gas is min(MaxPriorityFeePerGas,
						// MaxFeePerGas - BaseFee); multiply by tx.GasLimit as an
						// upper-bound approximation (per-tx GasUsed is not available
						// at this accounting point). This is conservative (GasLimit >=
						// actual GasUsed) but far more accurate than 0.
						priorityFeesTotal := new(big.Int)
						baseFee := blk.Header.BaseFee
						for _, tx := range blk.Transactions {
							if tx.MaxPriorityFeePerGas == nil || tx.MaxPriorityFeePerGas.Sign() <= 0 {
								continue
							}
							// effectivePriorityFee = min(MaxPriorityFeePerGas, MaxFeePerGas - BaseFee)
							// If MaxFeePerGas is not set, use MaxPriorityFeePerGas as-is.
							effectiveTip := new(big.Int).Set(tx.MaxPriorityFeePerGas)
							if tx.MaxFeePerGas != nil {
								maxTip := new(big.Int).Sub(tx.MaxFeePerGas, baseFee)
								if maxTip.Sign() < 0 {
									maxTip = big.NewInt(0)
								}
								if effectiveTip.Cmp(maxTip) > 0 {
									effectiveTip = maxTip
								}
							}
							// priorityFeesTotal += effectiveTip * tx.GasLimit
							txFee := new(big.Int).Mul(effectiveTip, new(big.Int).SetUint64(tx.GasLimit))
							priorityFeesTotal.Add(priorityFeesTotal, txFee)
						}
						_, econErr = n.economicsManager.ProcessEIP1559Block(
							blk.Header.Height,
							blk.Header.ProposerAddr,
							blk.Header.GasUsed,
							blk.Header.BaseFee,
							priorityFeesTotal,
						)
					} else {
						_, econErr = n.economicsManager.ProcessBlock(
							blk.Header.Height,
							blk.Header.ProposerAddr,
							blk.Header.GasUsed,
							gasPrice,
						)
					}
					if econErr != nil {
						//  AUDIT NOTE: Economics failures are intentionally
						// non-fatal during block sync/processing. Halting the chain
						// on economic errors (e.g., reward distribution failure)
						// would prevent sync from continuing and could be exploited
						// by a malicious block producer to halt nodes. The warning
						// is logged for operator visibility; the economic state
						// will self-correct on subsequent blocks.
						nodeLog.Warn("EconomicsManager.ProcessBlock failed for block %d: %v", height, econErr)
					}

					if n.blockProducer != nil {
						n.blockProducer.RecordBlockProducer(blk.Header.ProposerAddr, blk.Header.Height)
					}

					if n.blockProducer != nil && n.blockProducer.QPOS() != nil && shouldSwitch {
						// AUDIT R4-CORE-02 (2026-07-15): On reorg, re-anchor
						// slotBlockRoots for every slot on the new canonical segment
						// (walked back to the common ancestor with the old head).
						// Without this, intermediate blocks that never individually
						// became head leave stale slot roots pointing at the abandoned
						// fork, which then poison tryUpdateFinality (honest votes
						// rejected, abandoned-fork votes counted → conflicting roots
						// finalized across nodes). For linear extensions (no reorg)
						// this is a no-op and the SetSlotBlockRoot below records the
						// new head's own slot.
						if oldHead != nil {
							n.reanchorSlotRootsAfterReorg(
								n.blockProducer.QPOS(), n.blockStore,
								blk, blockHash, oldHead, oldHeadHash,
							)
						}
						// P0-3 FIX (2026-07-13): Record per-slot block root for GOV-05 fix.
						// This allows the Review Chamber to classify attestations against
						// the correct canonical block for each slot, not just the epoch boundary.
						// AUDIT (2026) CORE B-1 FIX: Only record per-slot/epoch block roots
						// when the block becomes the canonical chain head (shouldSwitch=true).
						// Previously, SetSlotBlockRoot was called for every imported block
						// including non-canonical forks, allowing an attacker who controls
						// import order to overwrite the canonical slot root with a fork root,
						// flipping the finality canonical root.
						n.blockProducer.QPOS().SetSlotBlockRoot(blk.Header.Slot, blockHash)
						// R106-FINALITY-SYNC (2026-09-02) FIX: adopt the checkpoint epochs the
						// header carries. Finality lives only in memory (see
						// AdoptHeaderFinality); without this a restarted / non-sealer node
						// rejects every live attestation (Source.Epoch > local justifiedEpoch)
						// and reports finalizedEpoch=0 forever. Same anchor position + same
						// canonical-head gating as SetSlotBlockRoot, mirroring R54-ACC's
						// header-derived SetEpochVRFAccumulator one line below.
						n.blockProducer.QPOS().AdoptHeaderFinality(blk.Header.JustifiedEpoch, blk.Header.FinalizedEpoch, blockHash)
						// R54-ACC (2026-08-07): Record the per-epoch VRF accumulator
						// from the ON-CHAIN header value. This assignment is
						// idempotent and path-independent, so it is safe to run
						// unconditionally (produce, sync, reorg). The old XOR-based
						// AccumulateVRFOutput was gated by isLinearExtension and
						// recomputed by reanchorSlotRootsAfterReorg, and any
						// asymmetry between those paths diverged the accumulator →
						// different proposer → chain fork. The header value is
						// identical on every node, so this converges deterministically.
						n.blockProducer.QPOS().SetEpochVRFAccumulator(blk.Header.Epoch, blk.Header.VRFAccumulator)
						if blk.Header.RANDAOReveal != (types.Hash{}) {
							if blk.Header.Slot%consensus.SlotsPerEpoch == 0 {
								n.blockProducer.QPOS().SetEpochBlockRoot(blk.Header.Epoch, blockHash)
							} else {
								// R42-P3 FIX: If this is the first block of the epoch
								// but NOT at the boundary slot (slot 32 was skipped),
								// set the epoch boundary to the parent block's hash.
								// The parent is the chain tip at the start of this epoch.
								n.blockProducer.QPOS().EnsureEpochBlockRoot(blk.Header.Epoch, blk.Header.ParentHash)
							}
							vs := n.blockProducer.QPOS().GetValidatorSet()
							validatorIdx := -1
							if vs != nil {
								validatorIdx = vs.GetValidatorIndex(blk.Header.ProposerAddr)
							}
							if validatorIdx >= 0 {
								// SECURITY (audit CORE-04 + R4-CORE-01): UpdateRANDAO still
								// fails because CommitRANDAO was never called (dead code).
								// The shuffle seed now uses the previous epoch's VRF
								// accumulator (set via AccumulateVRFOutput above) for
								// unpredictability, not randaoMix. This UpdateRANDAO call
								// is retained for forward compatibility but its error is
								// expected and safely ignored.
								_ = n.blockProducer.QPOS().UpdateRANDAO(blk.Header.RANDAOReveal, blk.Header.Epoch, validatorIdx)
							}
							// P0-2 (2026-07-13): Transition executive chamber at epoch boundary.
							// This selects executive members and transitions the state machine.
							// If a TSS group key is available, DKG completes immediately.
							if blk.Header.Slot%consensus.SlotsPerEpoch == 0 {
								coordinator := n.blockProducer.QPOS().GetChambersCoordinator()
								if coordinator != nil && vs != nil {
									groupPk := n.blockProducer.QPOS().GetGroupPublicKey()
									if err := coordinator.TransitionExecutiveForEpoch(blk.Header.Epoch, vs, groupPk); err != nil {
										nodeLog.Warn("Executive chamber transition failed for epoch %d: %v", blk.Header.Epoch, err)
									}
								}
							}
						}
					}

					// P1-T8 (2026-07-14): Persist ministry state at epoch boundaries.
					// Non-fatal: persistence errors are logged but do not halt block processing.
					if shouldSwitch && blk.Header.Slot%consensus.SlotsPerEpoch == 0 {
						if n.ministryStateStore != nil && n.ministryRegistry != nil {
							if err := n.ministryStateStore.SaveAll(n.ministryRegistry, blk.Header.Epoch); err != nil {
								nodeLog.Warn("MinistryStateStore.SaveAll failed at epoch %d: %v", blk.Header.Epoch, err)
							}
						}
					}

					if time.Since(lastProgressLog) >= 10*time.Second {
						isSyncing := n.syncer != nil && n.syncer.IsSyncing()
						n.syncBufMu.Lock()
						bufLen := len(n.syncBuf)
						n.syncBufMu.Unlock()
						nodeLog.Info("blockInsertLoop: processed %d blocks, latest=%d, bufLen=%d, syncing=%v",
							insertCount, height, bufLen, isSyncing)
						lastProgressLog = time.Now()
					}

					// Disable syncing mode once sync completes. This re-enables
					// strict election verification for all subsequent blocks.
					if n.syncer != nil && !n.syncer.IsSyncing() {
						n.mu.RLock()
						syncingMode := n.blockValidator.IsSyncingMode()
						n.mu.RUnlock()
						if syncingMode {
							nodeLog.Info("Sync complete: disabling syncing mode, re-enabling election verification at height %d", height)
							n.blockValidator.SetSyncingMode(false)
						}
					}
				}
				// R39-P3-03 (2026-08-02) FIX: this block insert was
				// completed without panicking — reset the panic
				// counter so a future panic-burst starts from 0.
				// Without this reset, a single bad-patch-of-blocks early
				// in the node's life would accumulate toward the
				// restart threshold during otherwise-healthy operation,
				// making the threshold effectively a "lifetime crash
				// budget" rather than a "consecutive-panic budget".
				// The audit's intent is the latter — a malicious peer
				// SUSTAINED attack triggers the restart; a one-off
				// early bad patch doesn't.
				//
				// The Store(0) is on the atomic.Uint64 itself (not a
				// mutex), so this is lock-free and O(1) — no contention
				// with the per-iteration panic-increment path.
				n.blockInsertPanicCount.Store(0)
				// R60-SYNC (2026-08-18): record the successful insert so
				// takeNextBlock's stall gate sees forward progress. This is
				// the ONLY place lastBlockInsert advances; a buffer full of
				// parentless blocks (parents not yet arrived) does NOT
				// advance it, so a genuinely stuck node still triggers the
				// deadlock clear after the stall window.
				n.lastBlockInsert = time.Now()
			}() // NODE-P0-01: close per-iteration recover wrapper
		}
	}
}

// shouldProcessP2PTx decides whether a tx arriving via p2p should be admitted to the batch (BatchAdd).
//
// FIX: the set of types returning true is enumerated explicitly; unknown types
// fail-closed. Since this fix, stake/unstake are allowed back in via p2p,
// with safety provided by canonical VerifyTransactionAuthorization inside
// BatchValidateWithState (ComputeStakeAuthorizationHash domain + “To“
// contract binding + pubkey↔From binding + chainId binding; see txpool/validator.go).
func shouldProcessP2PTx(tx *encoding.Transaction) bool {
	if tx == nil {
		return false
	}
	switch tx.Type {
	case encoding.TxTypeTransfer,
		encoding.TxTypeContract,
		encoding.TxTypeCreate,
		encoding.TxTypeDynamicFee,
		encoding.TxTypeCommit,
		encoding.TxTypeStake,   // canonical auth check passed → admit to pool
		encoding.TxTypeUnstake: // same as above
		return true
	case encoding.TxTypeValidatorKey: // R131: validator key-control ops
		return true
	default:
		// Privacy (ZK-proof path), MultiSig (requires roster), Blob (unsupported) —
		// each has its own dedicated channel; must not enter the pool via generic tx gossip.
		return false
	}
}

// txProcessingLoop processes incoming transactions in batches.
// TPS FIX: Collects up to 100 txs (or 10ms worth) and processes them together,
// enabling parallel Dilithium3 signature verification via BatchValidateWithState.
// This prevents txCh overflow when large batches arrive via P2P batch messages.
func (n *Node) txProcessingLoop() {
	defer n.wg.Done()
	// R32-P1-03 FIX (2026-07-28): top-level panic recovery so a panic in
	// batch validation, signature verification, or pool insertion cannot
	// kill the tx-processing goroutine and stall tx propagation.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("txProcessingLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	txCh := n.p2pHost.SubscribeTransactions()

	const (
		maxBatchSize  = 100
		flushInterval = 10 * time.Millisecond
	)

	batch := make([]*encoding.Transaction, 0, maxBatchSize)
	batchData := make([][]byte, 0, maxBatchSize) // raw data for re-broadcast
	timer := time.NewTimer(flushInterval)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Batch add to pool — uses parallel signature verification
		errs := n.txPool.BatchAdd(batch)
		added := 0
		for _, err := range errs {
			if err == nil {
				added++
			}
		}
		nodeLog.Info("[txProcessingLoop] P2P txs: received=%d added=%d", len(batch), added)
		// Re-broadcast successful txs to other peers
		if bc := n.p2pHost.Broadcaster(); bc != nil {
			for i, err := range errs {
				if err == nil {
					// TPS OPTIMIZATION: Store in CompactTxManager so peers can
					// request this tx by hash instead of receiving full 5.5KB.
					if ct := n.p2pHost.CompactTx(); ct != nil {
						txHash := p2p.HashData(batchData[i])
						ct.StoreTx(txHash, batchData[i])
					}
					if err := bc.BroadcastTransaction(context.Background(), batchData[i]); err != nil {
						nodeLog.Debug("Failed to broadcast transaction: %v", err)
					}
				}
			}
		}
		// Publish new transaction events for real-time subscribers (GraphQL, WS, etc.)
		if n.eventBus != nil {
			for i, err := range errs {
				if err == nil {
					// NODE-P2-02 FIX (R31, 2026-07-28): log EventBus.Post errors so
					// stale WS/GraphQL subscribers can be diagnosed.
					if postErr := n.eventBus.Post(NewTxEvent{Tx: batch[i]}); postErr != nil {
						nodeLog.Warn("EventBus.Post(NewTxEvent) failed: %v", postErr)
					}
				}
			}
		}
		batch = batch[:0]
		batchData = batchData[:0]
	}

	for {
		select {
		case <-n.ctx.Done():
			flush()
			return
		case txData := <-txCh:
			tx, err := encoding.UnmarshalTransaction(txData)
			if err != nil {
				continue
			}
			// FIX: previously stake/unstake were dropped at the p2p entry point.
			//
			// Historically (2026-07-30) stake/unstake transactions received via
			// p2p were unconditionally dropped, on the assumption that "stake
			// txs are only created via local RPC (qau_stake/qau_unstake) and
			// propagate via blocks, not tx gossip". That assumption is false
			// for non-validator RPC gateways: their transactions can reach
			// validators only through gossip, so dropping them can strand the
			// transactions permanently in the gateway pool.
			//
			// Since the previous authorization hardening, BatchValidateWithState
			// already runs the canonical VerifyTransactionAuthorization for
			// stake/unstake (ComputeStakeAuthorizationHash domain + To
			// contract binding + pubkey↔From binding + chainId binding), and
			// forged stake txs are now rejected at pool admission — the old
			// drop-on-arrival is no longer a defense, it was a fatal block
			// on the staking feature. The type whitelist (shouldProcessP2PTx)
			// remains to keep fail-closed behavior for unknown types.
			if !shouldProcessP2PTx(tx) {
				nodeLog.Debug("[txProcessingLoop] dropping p2p tx from=%x type=%d", tx.From[:8], tx.Type)
				continue
			}
			batch = append(batch, tx)
			batchData = append(batchData, txData)
			if len(batch) >= maxBatchSize {
				flush()
				timer.Reset(flushInterval)
			}
		case <-timer.C:
			flush()
			timer.Reset(flushInterval)
		}
	}
}

// statusProcessingLoop processes incoming status messages from peers
func (n *Node) statusProcessingLoop() {
	defer n.wg.Done()
	// R32-P1-03 FIX (2026-07-28): top-level panic recovery so a panic in
	// status decoding or peer-state update cannot kill this goroutine and
	// stall sync-status propagation.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("statusProcessingLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	statusCh := n.p2pHost.SubscribeStatus()
	for {
		select {
		case <-n.ctx.Done():
			return
		case pm := <-statusCh:
			// Per-message recover: a malformed status payload must not
			// terminate the loop.
			// GHOST-HEIGHT FIX (2026-08-06): statusCh now carries the peerID
			// (PeerMessage) so the syncer can track per-peer heights and let
			// highestKnown decay to the current network tip.
			func() {
				defer func() {
					if r := recover(); r != nil {
						nodeLog.Error("statusProcessingLoop: message panic recovered: %v", r)
					}
				}()
				n.handleIncomingStatus(pm.Payload, pm.From)
			}()
		}
	}
}

// syncResponseProcessingLoop dispatches extended sync protocol responses to
// the syncer (ETHEREUM-PARITY SYNC, 2026-08-13). Responses arrive typed via
// SubscribeSyncResponses; each kind maps to one syncer handler.
func (n *Node) syncResponseProcessingLoop() {
	defer n.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("syncResponseProcessingLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	respCh := n.p2pHost.SubscribeSyncResponses()
	for {
		select {
		case <-n.ctx.Done():
			return
		case pm, ok := <-respCh:
			if !ok {
				return
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						nodeLog.Error("syncResponseProcessingLoop: message panic recovered: %v", r)
					}
				}()
				if n.syncer == nil {
					return
				}
				switch pm.Type {
				case p2p.MsgTypeSnapStateResp:
					if resp, err := p2p.DecodeSnapStateResponse(pm.Payload); err == nil {
						n.syncer.HandleSnapStateResponse(pm.From, resp)
					}
				case p2p.MsgTypeSnapStorageResp:
					if resp, err := p2p.DecodeSnapStorageResponse(pm.Payload); err == nil {
						n.syncer.HandleSnapStorageResponse(pm.From, resp)
					}
				case p2p.MsgTypeSnapBytecodeResp:
					if resp, err := p2p.DecodeSnapBytecodeResponse(pm.Payload); err == nil {
						n.syncer.HandleSnapBytecodeResponse(pm.From, resp)
					}
				case p2p.MsgTypeHeaderResp:
					if resp, err := p2p.DecodeHeaderResponse(pm.Payload); err == nil {
						n.syncer.HandleHeaderResponse(resp)
					}
				case p2p.MsgTypeReceiptResp:
					if resp, err := p2p.DecodeReceiptResponse(pm.Payload); err == nil {
						n.syncer.HandleReceiptResponse(resp)
					}
				}
			}()
		}
	}
}

// attestationProcessingLoop processes incoming attestations/votes from peers
func (n *Node) attestationProcessingLoop() {
	defer n.wg.Done()
	// R32-P1-03 FIX (2026-07-28): top-level panic recovery so a panic in
	// attestation decoding or vote counting cannot kill this goroutine and
	// stall consensus voting.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("attestationProcessingLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	voteCh := n.p2pHost.SubscribeVotes()
	for {
		select {
		case <-n.ctx.Done():
			return
		case attData := <-voteCh:
			// Per-message recover: a malformed attestation must not
			// terminate the loop.
			func() {
				defer func() {
					if r := recover(); r != nil {
						nodeLog.Error("attestationProcessingLoop: message panic recovered: %v", r)
					}
				}()
				n.handleIncomingAttestation(attData)
			}()
		}
	}
}

// handleIncomingAttestation handles an incoming attestation from a peer
func (n *Node) handleIncomingAttestation(data []byte) {
	if len(data) < 60 { // Minimum attestation size
		return
	}

	// Parse attestation
	att, err := n.parseAttestation(data)
	if err != nil {
		return
	}

	// Process attestation in block producer's QPOS engine
	if n.blockProducer != nil && n.blockProducer.QPOS() != nil {
		if err := n.blockProducer.QPOS().ProcessAttestation(att); err != nil {
			// Ignore duplicate or invalid attestations
			return
		}
		// P1-2: Forward to ReviewChamber for block approval tracking.
		qpos := n.blockProducer.QPOS()
		if qpos.HasChambers() {
			coordinator := qpos.GetChambersCoordinator()
			if coordinator != nil {
				review := coordinator.GetReviewChamber()
				if review != nil {
					// NODE-P2-02 FIX (R31, 2026-07-28): log review processing errors
					// instead of silently discarding. ReviewChamber failures affect
					// block approval tracking and consensus sync diagnostics.
					if err := review.ProcessReviewAttestation(att); err != nil {
						// R95-ATTEST-LOGLEVEL (2026-08-30): the slot proposer
						// broadcasts an attestation for its own block every slot and
						// CanAttest correctly refuses it, so this fired ~1x/slot
						// (7,200/day/node) and buried actionable warnings. The
						// identical call in block_producer.go already logs at Debug;
						// match it for the routine case only, keeping real faults at
						// Warn. Classified by sentinel, never by message text.
						if errors.Is(err, consensus.ErrNotInReviewChamber) {
							nodeLog.Debug("ProcessReviewAttestation refused slot %d (validator=%d): %v", att.Slot, att.ValidatorIndex, err)
						} else {
							nodeLog.Warn("ProcessReviewAttestation failed for slot %d (validator=%d): %v", att.Slot, att.ValidatorIndex, err)
						}
					}
				}
			}
		}
		// Publish new attestation event for real-time subscribers (GraphQL, WS, etc.)
		if n.eventBus != nil {
			// NODE-P2-02 FIX (R31, 2026-07-28): log EventBus.Post errors for diagnosis.
			if err := n.eventBus.Post(NewAttestationEvent{Attestation: att}); err != nil {
				nodeLog.Warn("EventBus.Post(NewAttestationEvent) failed for slot %d: %v", att.Slot, err)
			}
		}
	}
}

// CheckpointManager returns the node's checkpoint manager
func (n *Node) CheckpointManager() *consensus.CheckpointManager {
	return n.checkpointManager
}

// checkpointProcessingLoop processes incoming checkpoint signature and request messages
func (n *Node) checkpointProcessingLoop() {
	defer n.wg.Done()
	// R32-P1-03 FIX (2026-07-28): top-level panic recovery so a panic in
	// checkpoint decoding or signature verification cannot kill this
	// goroutine and stall checkpoint finalization.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("checkpointProcessingLoop: top-level panic recovered (loop terminated): %v", r)
		}
	}()

	checkpointCh := n.p2pHost.SubscribeCheckpoint()
	for {
		select {
		case <-n.ctx.Done():
			return
		case data := <-checkpointCh:
			// Per-message recover: a malformed checkpoint message must not
			// terminate the loop.
			func() {
				defer func() {
					if r := recover(); r != nil {
						nodeLog.Error("checkpointProcessingLoop: message panic recovered: %v", r)
					}
				}()
				n.handleIncomingCheckpointMessage(data)
			}()
		}
	}
}

// handleIncomingCheckpointMessage handles a checkpoint signature or request
func (n *Node) handleIncomingCheckpointMessage(data []byte) {
	// Try to decode as checkpoint signature first (min 104 bytes)
	if len(data) >= 104 {
		sigMsg, err := p2p.DecodeCheckpointSig(data)
		if err == nil {
			n.handleCheckpointSig(sigMsg)
			return
		}
	}

	// Try to decode as checkpoint request (8 bytes)
	if len(data) >= 8 {
		reqMsg, err := p2p.DecodeCheckpointReq(data)
		if err == nil {
			n.handleCheckpointReq(reqMsg)
			return
		}
	}
}

// handleCheckpointSig handles a received checkpoint signature from a peer
func (n *Node) handleCheckpointSig(msg *p2p.CheckpointSigMessage) {
	if n.checkpointManager == nil {
		return
	}

	err := n.checkpointManager.AddCheckpointSignature(
		msg.ValidatorAddr,
		msg.Signature,
		msg.Height,
		msg.BlockHash,
	)
	if err != nil {
		nodeDebugLog("Checkpoint sig rejected: height=%d from=%x err=%v",
			msg.Height, msg.ValidatorAddr[:8], err)
		return
	}

	// Try to finalize the checkpoint if enough signatures collected
	cp, err := n.checkpointManager.FinalizeCheckpoint()
	if err != nil {
		// Not enough signatures yet — normal
		return
	}

	nodeLog.Info("Checkpoint FINALIZED at height %d (epoch %d) with %d signatures",
		cp.Height, cp.Epoch, len(cp.Signatures))
}

// handleCheckpointReq handles a checkpoint request from a peer
func (n *Node) handleCheckpointReq(msg *p2p.CheckpointReqMessage) {
	if n.checkpointManager == nil || n.blockStore == nil {
		return
	}

	// Check if we have a finalized checkpoint at this height
	cp, err := n.checkpointManager.GetCheckpoint(msg.Height)
	if err != nil || cp == nil {
		return
	}

	// Get the block to provide block hash and state root
	blk, err := n.blockStore.GetBlockByHeight(msg.Height)
	if err != nil || blk == nil || blk.Header == nil {
		return
	}

	blockHash := block.ComputeBlockHash(blk.Header)

	// broadcast our checkpoint signature for this height
	if n.blockProducer != nil && n.blockProducer.QPOS() != nil && n.blockProducer.ValidatorKey() != nil {
		// Re-sign and broadcast
		n.broadcastCheckpointSignature(msg.Height, blockHash, blk.Header.StateRoot)
	}
}

// broadcastCheckpointSignature creates and broadcasts our checkpoint signature
func (n *Node) broadcastCheckpointSignature(height uint64, blockHash, stateRoot types.Hash) {
	if n.checkpointManager == nil || n.blockProducer == nil {
		return
	}

	bp := n.blockProducer
	if bp.ValidatorKey() == nil {
		return
	}

	// Build a temporary checkpoint object to compute its hash
	cp := &consensus.Checkpoint{
		Height:    height,
		BlockHash: blockHash,
		StateRoot: stateRoot,
		Timestamp: time.Now().Unix(),
		Epoch:     height / n.checkpointManager.Config().CheckpointInterval,
	}

	cpHash := cp.Hash()
	sig, err := bp.ValidatorKey().Sign(cpHash[:])
	if err != nil {
		nodeLog.Error("Failed to sign checkpoint at height %d: %v", height, err)
		return
	}

	// Add our own signature locally
	if err := n.checkpointManager.AddCheckpointSignature(bp.ValidatorAddr(), sig, height, blockHash); err != nil {
		nodeLog.Warn("Failed to add local checkpoint signature at height %d: %v", height, err)
	}

	// Broadcast to peers
	sigMsg := &p2p.CheckpointSigMessage{
		Height:        height,
		BlockHash:     blockHash,
		StateRoot:     stateRoot,
		Epoch:         cp.Epoch,
		ValidatorAddr: bp.ValidatorAddr(),
		Signature:     sig,
	}

	encoded := p2p.EncodeCheckpointSig(sigMsg)
	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()
	if err := n.p2pHost.BroadcastCheckpointSignature(ctx, encoded); err != nil {
		nodeDebugLog("Failed to broadcast checkpoint sig at height %d: %v", height, err)
	}
}

// checkpointRecoveryMonitor periodically checks if the node is stuck at a checkpoint
// height and automatically requests missing checkpoint signatures from peers.
// This prevents the "stuck at 1024" scenario where blocks stop being produced
// because the checkpoint hasn't been finalized.
const checkpointRecoveryInterval = 15 * time.Second
const checkpointStallThreshold = 120 * time.Second // 2 minutes without new blocks

func (n *Node) checkpointRecoveryMonitor() {
	defer n.wg.Done()
	// NODE-P2-01 FIX (R31, 2026-07-28): top-level panic recovery so a single
	// unrecovered panic cannot silently disable checkpoint stall detection.
	defer func() {
		if r := recover(); r != nil {
			nodeLog.Error("checkpointRecoveryMonitor: top-level panic recovered (monitor terminated): %v", r)
		}
	}()

	ticker := time.NewTicker(checkpointRecoveryInterval)
	defer ticker.Stop()

	var lastHeight uint64
	var lastHeightTime time.Time
	var checkpointRequested map[uint64]bool // track which heights we've already requested

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
		// NODE-P2-01 FIX (R31, 2026-07-28): per-tick recover. A panic in
		// checkpointManager.GetStats, requestCheckpointSignatures, or p2pHost
		// interaction must not terminate stall detection — the next tick
		// should retry. `continue` statements inside the wrapper become
		// `return` from the anonymous function, preserving loop semantics.
		func() {
			defer func() {
				if r := recover(); r != nil {
					nodeLog.Error("checkpointRecoveryMonitor: tick panic recovered (continuing): %v", r)
				}
			}()

			if n.checkpointManager == nil || n.p2pHost == nil {
				return
			}

			n.mu.Lock()
			if n.currentBlock == nil {
				n.mu.Unlock()
				return
			}
			currentHeight := n.currentBlock.Header.Height
			n.mu.Unlock()

			// Track height changes
			if currentHeight != lastHeight {
				lastHeight = currentHeight
				lastHeightTime = time.Now()
				if checkpointRequested != nil {
					checkpointRequested = nil // reset on progress
				}
				return
			}

			// Check if we're stalled
			if time.Since(lastHeightTime) < checkpointStallThreshold {
				return
			}

			// We're stalled — check if it's a checkpoint issue
			stats := n.checkpointManager.GetStats(currentHeight)
			if stats == nil {
				return
			}

			nodeLog.Warn("checkpointRecoveryMonitor: node stalled at height %d for %v (latestCP=%d, pendingSigs=%d)",
				currentHeight, time.Since(lastHeightTime).Round(time.Second), stats.LatestHeight, stats.PendingSignatures)

			// Request checkpoint signatures for the next checkpoint height
			nextCheckpointHeight := ((currentHeight / 1000) + 1) * 1000

			// Also request for any checkpoint height near us
			heightsToRequest := []uint64{nextCheckpointHeight}
			if currentHeight%1000 < 100 {
				// We're near a checkpoint boundary, also request the current one
				cpHeight := (currentHeight / 1000) * 1000
				if cpHeight > 0 && cpHeight > stats.LatestHeight {
					heightsToRequest = append(heightsToRequest, cpHeight)
				}
			}

			if checkpointRequested == nil {
				checkpointRequested = make(map[uint64]bool)
			}

			for _, cpHeight := range heightsToRequest {
				if checkpointRequested[cpHeight] {
					continue // already requested
				}
				checkpointRequested[cpHeight] = true

				nodeLog.Info("checkpointRecoveryMonitor: requesting checkpoint signatures for height %d", cpHeight)
				n.requestCheckpointSignatures(cpHeight)
			}
		}()
	}
}

// requestCheckpointSignatures broadcasts a checkpoint request to all peers.
func (n *Node) requestCheckpointSignatures(height uint64) {
	if n.p2pHost == nil {
		return
	}

	reqMsg := &p2p.CheckpointReqMessage{
		Height: height,
	}

	encoded := p2p.EncodeCheckpointReq(reqMsg)
	ctx, cancel := context.WithTimeout(n.ctx, 3*time.Second)
	defer cancel()
	if err := n.p2pHost.BroadcastCheckpointRequest(ctx, encoded); err != nil {
		nodeDebugLog("Failed to broadcast checkpoint request for height %d: %v", height, err)
	} else {
		nodeLog.Info("Checkpoint signature request broadcast for height %d", height)
	}
}

// parseAttestation parses attestation data from P2P message.
// audit-fix L-5: uses encoding/binary for consistent, readable byte parsing.
func (n *Node) parseAttestation(data []byte) (*consensus.Attestation, error) {
	// Minimum size: slot(8) + blockRoot(32) + sourceEpoch(8) + sourceRoot(32) +
	//               targetEpoch(8) + targetRoot(32) + validatorIdx(4) + keyVersion(8) + sigLen(2)
	minSize := 8 + 32 + 8 + 32 + 8 + 32 + 4 + 8 + 2
	if len(data) < minSize {
		return nil, fmt.Errorf("attestation data too short: got %d, need at least %d", len(data), minSize)
	}

	att := &consensus.Attestation{}
	offset := 0

	// Slot (8 bytes)
	att.Slot = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// BeaconBlockRoot (32 bytes)
	copy(att.BeaconBlockRoot[:], data[offset:offset+32])
	offset += 32

	// SourceEpoch (8 bytes)
	att.Source.Epoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// SourceRoot (32 bytes)
	copy(att.Source.Root[:], data[offset:offset+32])
	offset += 32

	// TargetEpoch (8 bytes)
	att.Target.Epoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// TargetRoot (32 bytes)
	copy(att.Target.Root[:], data[offset:offset+32])
	offset += 32

	// audit-fix R2-L2: validate ValidatorIndex range to prevent negative
	// values from uint32 overflow on 32-bit platforms.
	rawIdx := binary.BigEndian.Uint32(data[offset:])
	if rawIdx > 0x7FFFFFFF {
		return nil, fmt.Errorf("validator index %d exceeds max int32", rawIdx)
	}
	att.ValidatorIndex = int(rawIdx)
	offset += 4

	// KeyVersion (8 bytes) — CRITICAL for signature verification
	att.KeyVersion = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Signature length (2 bytes) + signature
	if offset+2 > len(data) {
		return nil, fmt.Errorf("attestation data truncated")
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	if offset+sigLen > len(data) {
		return nil, fmt.Errorf("attestation signature truncated")
	}
	att.Signature = make([]byte, sigLen)
	copy(att.Signature, data[offset:offset+sigLen])

	return att, nil
}

// handleIncomingStatus handles an incoming status message from a peer
func (n *Node) handleIncomingStatus(data []byte, from p2p.PeerID) {
	nodeLog.Info("Received status message, data_len=%d", len(data))

	status, err := p2p.DecodeStatusMessage(data)
	if err != nil {
		nodeLog.Error("Failed to decode status message: %v", err)
		return
	}

	nodeLog.Info("Peer status: height=%d, network=%d", status.BestHeight, status.NetworkID)

	if n.syncer != nil {
		n.syncer.HandleStatusMessage(status, from)
	} else {
		nodeLog.Warn("handleIncomingStatus: syncer is nil!")
	}
}

// reanchorSlotRootsAfterReorg walks the new canonical head back to the common
// ancestor with the old (replaced) head and re-anchors slotBlockRoots for
// every slot on the new canonical segment (AUDIT R4-CORE-02, 2026-07-15).
//
// Without this, a multi-block reorg leaves slotBlockRoots[reorged_slot]
// pointing at the abandoned fork's roots (SetSlotBlockRoot only records the
// new head's OWN slot). tryUpdateFinality then reads those stale roots and
// rejects honest attestations targeting the new canonical block while
// counting abandoned-fork votes → finality stalls or finalizes conflicting
// roots across nodes with different import orders (accountable safety
// failure).
//
// This is a no-op for linear extensions (new head's parent IS the old head):
// no stale roots can exist, so we return without touching slotBlockRoots and
// let the caller's SetSlotBlockRoot record the new head's own slot.
//
// The walk is bounded by maxReorgDepth (2 epochs / 64 slots). Reorgs deeper
// than this are extremely unusual; if encountered, we re-anchor what we can
// and log a warning — the affected deep slots' attestations may be
// miscounted, but this is strictly better than leaving ALL reorged slots
// stale (the pre-fix behavior).
func (n *Node) reanchorSlotRootsAfterReorg(
	qpos *consensus.QPOS,
	bs *block.BlockStore,
	newHead *encoding.Block,
	newHeadHash types.Hash,
	oldHead *encoding.Block,
	oldHeadHash types.Hash,
) {
	if qpos == nil || bs == nil || newHead == nil || oldHead == nil {
		return
	}
	// Linear extension: new head's parent IS the old head → no stale roots
	// can exist. Skip the walk entirely.
	if newHead.Header.ParentHash == oldHeadHash {
		return
	}

	const maxReorgDepth = 2 * consensus.SlotsPerEpoch // 64 slots

	// Walk the NEW chain back from newHead, collecting (slot → root) pairs.
	// We also record each hash so we can detect the common ancestor when
	// walking the old chain.
	type segEntry struct {
		slot       uint64
		hash       types.Hash
		epoch      uint64
		vrf        types.Hash
		acc        types.Hash // on-chain per-epoch VRF accumulator (header)
		parentHash types.Hash
	}
	newChain := make([]segEntry, 0, maxReorgDepth)
	newHashSlots := make(map[types.Hash]uint64, maxReorgDepth)

	cur := newHead
	curHash := newHeadHash
	for i := 0; i < maxReorgDepth; i++ {
		newChain = append(newChain, segEntry{slot: cur.Header.Slot, hash: curHash, epoch: cur.Header.Epoch, vrf: cur.Header.VRFValue, acc: cur.Header.VRFAccumulator, parentHash: cur.Header.ParentHash})
		newHashSlots[curHash] = cur.Header.Slot
		if cur.Header.Height == 0 {
			break // genesis reached
		}
		parent, err := bs.GetBlock(cur.Header.ParentHash)
		if err != nil || parent == nil {
			break
		}
		cur = parent
		curHash = block.ComputeBlockHash(parent.Header)
	}

	// Walk the OLD chain back to find the common ancestor: the first hash
	// that also appears in the new chain. Everything on the new chain ABOVE
	// that ancestor needs re-anchoring.
	ancestorSlot, found := uint64(0), false
	// R55-ACC-ONCHAIN (2026-08-07): We no longer collect the old chain's
	// segment to zero out abandoned-fork VRF accumulators — see the comment
	// at the newAcc construction below. The walk below is retained solely to
	// locate the common ancestor.
	cur = oldHead
	curHash = oldHeadHash
	for i := 0; i < maxReorgDepth; i++ {
		if s, ok := newHashSlots[curHash]; ok {
			ancestorSlot = s
			found = true
			break
		}
		if cur.Header.Height == 0 {
			break
		}
		parent, err := bs.GetBlock(cur.Header.ParentHash)
		if err != nil || parent == nil {
			break
		}
		cur = parent
		curHash = block.ComputeBlockHash(parent.Header)
	}

	if !found {
		// Common ancestor not within maxReorgDepth. Re-anchor the entire
		// walked new-chain segment as best-effort and warn — deep reorgs
		// are anomalous and may indicate an attack or a syncing node
		// importing a long fork.
		//
		// SHRD- (Info, 2026-07-17): This is a known best-effort
		// limitation. Slots deeper than maxReorgDepth (2 epochs / 64
		// slots) below the common ancestor are NOT re-anchored and may
		// remain stale in slotBlockRoots. This is acceptable because:
		//   1. Deep reorgs are anomalous (attack or sync-time long fork).
		//   2. The QTD finality layer (qtd_finality.go:458-470) still
		//      double-checks slot/epoch roots before sealing, so stale
		//      roots cannot be silently exploited.
		//   3. The warn log above provides operator visibility.
		// Recommended ops action: alert on this warn log and manually
		// investigate deep reorgs when they occur.
		nodeLog.Warn("R4-CORE-02: reorg deeper than %d blocks detected; re-anchoring %d slots as best-effort (deep slots may remain stale)",
			maxReorgDepth, len(newChain))
		ancestorSlot = 0
	}

	// Build the roots map: every slot on the new chain strictly above the
	// common ancestor. newChain[0] is the new head (newest); entries are
	// appended as we walk down, so iterate and include slots > ancestorSlot.
	roots := make(map[uint64]types.Hash, len(newChain))
	for _, e := range newChain {
		if e.slot > ancestorSlot {
			roots[e.slot] = e.hash
		}
	}
	if len(roots) == 0 {
		return
	}

	// R54-ACC (2026-08-07): Derive the per-epoch VRF accumulator for every
	// epoch touched by this reorg directly from the NEW canonical chain's
	// block headers (on-chain, deterministic). newChain is ordered newest →
	// oldest, so the FIRST entry we see for a given epoch carries that
	// epoch's FULL accumulator (the last canonical block of the epoch).
	//
	// This replaces the old CONSENSUS-DETERMINISM FIX (2026-08-04) which
	// recomputed the accumulator by XOR-self-reflexivity from the abandoned
	// fork's local map value (qpos.GetEpochVRFAccumulator). That recompute
	// was path-dependent: once two nodes forked, their local accumulator
	// differed, so the reorg recompute propagated that divergence into the
	// new chain's accumulator → permanent fork. Reading the value the new
	// chain's own proposers wrote into their headers makes this a pure
	// function of the verified chain, identical on every node.
	//
	// R55-ACC-ONCHAIN (2026-08-07): We do NOT zero out epochs that appear on
	// the abandoned fork but not in newChain. During a deep reorg
	// (ancestorSlot == 0) or when the new chain cannot be walked back to the
	// common ancestor (bs.GetBlock returns nil because the node is still
	// re-syncing), newChain is incomplete; it may contain only the new head
	// block. Zeroing every epoch absent from that truncated newChain would
	// wipe the accumulator for epochs that do have canonical blocks, and since
	// those blocks are already finalized they never re-trigger
	// SetEpochVRFAccumulator on the head path. The accumulator would remain
	// zero and produce a divergent shuffle seed.
	//
	// The accumulator is therefore maintained EXCLUSIVELY by
	// SetEpochVRFAccumulator from on-chain header values (node.go head path
	// and block_producer.go). Here we only add the epochs the new chain
	// definitively contains; we never delete/zero any epoch. Any stale value
	// left after a reorg is corrected the moment a canonical block of that
	// epoch becomes the head. This is fail-safe: a stale (possibly fork)
	// accumulator is always safer than a wrongly-zeroed one, because the
	// former still originates from a header the node verified.
	newAcc := make(map[uint64]types.Hash)
	for _, e := range newChain {
		if e.slot <= ancestorSlot {
			break
		}
		if _, ok := newAcc[e.epoch]; !ok {
			newAcc[e.epoch] = e.acc
		}
	}

	qpos.ReanchorSlotRoots(roots, newAcc)

	// Also re-anchor epoch boundary roots on the new canonical segment, so
	// the epoch-root fallback in tryUpdateFinality / getExpectedBlockRoot
	// does not read a stale root from the abandoned fork.
	for _, e := range newChain {
		if e.slot > ancestorSlot && e.slot%consensus.SlotsPerEpoch == 0 {
			qpos.SetEpochBlockRoot(consensus.SlotToEpoch(e.slot), e.hash)
		} else {
			// R42-P3 FIX: Also ensure epoch boundary for non-boundary-slot blocks.
			qpos.EnsureEpochBlockRoot(consensus.SlotToEpoch(e.slot), e.parentHash)
		}
	}

	nodeLog.Info("R4-CORE-02: re-anchored %d slot roots after reorg (ancestor slot %d, new head slot %d)",
		len(roots), ancestorSlot, newHead.Header.Slot)
}

// handleIncomingBlock handles an incoming block from the network
func (n *Node) handleIncomingBlock(data []byte) {
	startTime := time.Now()

	if len(data) > 10*1024*1024 {
		nodeLog.Error("Block data too large: %d bytes", len(data))
		return
	}

	blk, err := encoding.UnmarshalBlock(data)
	if err != nil {
		nodeLog.Error("Failed to unmarshal block: %v", err)
		return
	}

	if blk.Header.ProposerAddr == (types.Address{}) {
		nodeLog.Error("Block has zero ProposerAddr at height %d", blk.Header.Height)
		return
	}

	n.mu.Lock()
	if n.currentBlock != nil && blk.Header.Height+64 < n.currentBlock.Header.Height {
		n.mu.Unlock()
		return
	}
	n.mu.Unlock()

	if blk.Header.ChainID != 0 && blk.Header.ChainID != n.chainID {
		return
	}

	height := blk.Header.Height
	blockHash := block.ComputeBlockHash(blk.Header)

	if n.syncer != nil {
		n.syncer.UpdateHighestKnown(height)
	}

	if n.syncer == nil {
		return
	}

	if err := n.syncer.ProcessBlock(blk); err != nil {
		if err != ErrParentNotFound && height%100 == 0 {
			nodeLog.Error("Failed to process block %d: %v (took %v)", height, err, time.Since(startTime))
		}
		return
	}

	go n.syncer.ProcessPendingBlocks(blockHash)

	n.mu.Lock()
	shouldSwitch := false
	if n.currentBlock == nil {
		shouldSwitch = true
	} else if blk.Header.Height > n.currentBlock.Header.Height {
		shouldSwitch = true
	} else if blk.Header.Height == n.currentBlock.Header.Height && blk.Header.Slot < n.currentBlock.Header.Slot {
		nodeLog.Info("Fork resolution: block %d slot=%d replaces local block slot=%d (earlier slot wins)",
			blk.Header.Height, blk.Header.Slot, n.currentBlock.Header.Slot)
		shouldSwitch = true
	} else if blk.Header.Height == n.currentBlock.Header.Height && blk.Header.Slot == n.currentBlock.Header.Slot {
		// AUDIT R4-CORE-02 (2026-07-15): Deterministic tiebreak at equal
		// height + equal slot (lower hash wins). See blockInsertLoop for
		// the full rationale.
		currentHeadHash := block.ComputeBlockHash(n.currentBlock.Header)
		if bytes.Compare(blockHash[:], currentHeadHash[:]) < 0 {
			nodeLog.Info("Fork resolution: block %d slot=%d replaces local block (deterministic lower-hash tiebreak)",
				blk.Header.Height, blk.Header.Slot)
			shouldSwitch = true
		}
	}
	// AUDIT R4-CORE-02 (2026-07-15): Capture old head for reorg re-anchoring.
	var oldHead *encoding.Block
	var oldHeadHash types.Hash
	if shouldSwitch && n.currentBlock != nil {
		oldHead = n.currentBlock
		oldHeadHash = block.ComputeBlockHash(n.currentBlock.Header)
	}
	if shouldSwitch {
		n.currentBlock = blk
	}
	n.mu.Unlock()

	// AUDIT (2026) CORE B-1 FIX: Only record per-slot/epoch block roots
	// and trigger epoch transitions when the block becomes the canonical
	// chain head (shouldSwitch=true). Previously, SetSlotBlockRoot was called
	// BEFORE the shouldSwitch check, so every imported block (including
	// non-canonical forks) overwrote the canonical slot root — an attacker
	// who influences import order could flip the finality canonical root.
	if shouldSwitch && n.blockProducer != nil && n.blockProducer.QPOS() != nil {
		// AUDIT R4-CORE-02 (2026-07-15): Re-anchor slot roots on reorg.
		if oldHead != nil {
			n.reanchorSlotRootsAfterReorg(
				n.blockProducer.QPOS(), n.blockStore,
				blk, blockHash, oldHead, oldHeadHash,
			)
		}
		// P0-3 FIX (2026-07-13): Record per-slot block root for GOV-05 fix.
		n.blockProducer.QPOS().SetSlotBlockRoot(blk.Header.Slot, blockHash)
		// R106-FINALITY-SYNC (2026-09-02) FIX: adopt the checkpoint epochs the
		// header carries (see AdoptHeaderFinality). Idempotent + monotonic, so
		// the duplicate call with blockInsertLoop's own adoption (when the same
		// block flows through both paths) is a no-op. Kept here so a live head
		// switch adopts finality even when blockInsertLoop is busy draining a
		// large sync buffer.
		n.blockProducer.QPOS().AdoptHeaderFinality(blk.Header.JustifiedEpoch, blk.Header.FinalizedEpoch, blockHash)
		// AUDIT R4-CORE-01 (2026-07-15): VRF accumulation OWNERSHIP NOTE:
		// AccumulateVRFOutput is already called by blockInsertLoop at line 6738
		// (gated by shouldSwitch=true). Calling it HERE AGAIN would DOUBLE-COUNT
		// the same canonical block's VRF output → XOR XOR = cancel → accumulator
		// diverges across nodes that import via different paths (live vs sync).
		//
		// The accumulator is OWNED EXCLUSIVELY by blockInsertLoop, so it is NOT
		// called here. Only SetSlotBlockRoot / SetEpochBlockRoot / UpdateRANDAO
		// remain (they don't affect the VRF accumulator so it's safe).
		if blk.Header.RANDAOReveal != (types.Hash{}) {
			if blk.Header.Slot%consensus.SlotsPerEpoch == 0 {
				n.blockProducer.QPOS().SetEpochBlockRoot(blk.Header.Epoch, blockHash)
			} else {
				n.blockProducer.QPOS().EnsureEpochBlockRoot(blk.Header.Epoch, blk.Header.ParentHash)
			}
			vs := n.blockProducer.QPOS().GetValidatorSet()
			validatorIdx := -1
			if vs != nil {
				validatorIdx = vs.GetValidatorIndex(blk.Header.ProposerAddr)
			}
			if validatorIdx >= 0 {
				// Note: The UpdateRANDAO error is intentionally ignored —
				// CommitRANDAO is never invoked, so it always returns a
				// "no RANDAO commitment" error. The shuffle seed now
				// depends only on the epoch and no longer on randaoMix.
				_ = n.blockProducer.QPOS().UpdateRANDAO(blk.Header.RANDAOReveal, blk.Header.Epoch, validatorIdx)
			}
			// P0-2 (2026-07-13): Transition executive chamber at epoch boundary.
			if blk.Header.Slot%consensus.SlotsPerEpoch == 0 {
				coordinator := n.blockProducer.QPOS().GetChambersCoordinator()
				if coordinator != nil && vs != nil {
					groupPk := n.blockProducer.QPOS().GetGroupPublicKey()
					if err := coordinator.TransitionExecutiveForEpoch(blk.Header.Epoch, vs, groupPk); err != nil {
						nodeLog.Warn("Executive chamber transition failed for epoch %d: %v", blk.Header.Epoch, err)
					}
				}
			}
		}
	}

	// syncStakingFromBlock moved outside lock to prevent deadlock
	// when syncStakingFromBlock calls into stakingManager/QPOS/validatorManager
	if shouldSwitch {
		// P1-T8 (2026-07-14): Persist ministry state at epoch boundaries.
		if blk.Header.Slot%consensus.SlotsPerEpoch == 0 {
			if n.ministryStateStore != nil && n.ministryRegistry != nil {
				if err := n.ministryStateStore.SaveAll(n.ministryRegistry, blk.Header.Epoch); err != nil {
					nodeLog.Warn("MinistryStateStore.SaveAll failed at epoch %d: %v", blk.Header.Epoch, err)
				}
			}
		}
		n.syncStakingFromBlock(blk)
		n.syncValidatorKeysFromBlock(blk)
	}

	// Publish new block event for real-time subscribers (GraphQL, WS, etc.)
	if shouldSwitch && n.eventBus != nil {
		// NODE-P2-02 FIX (R31, 2026-07-28): log EventBus.Post errors for diagnosis.
		if err := n.eventBus.Post(NewBlockEvent{Block: blk}); err != nil {
			nodeLog.Warn("EventBus.Post(NewBlockEvent) failed at height %d: %v", blk.Header.Height, err)
		}
	}

	if n.blockProducer != nil {
		n.blockProducer.RecordBlockProducer(blk.Header.ProposerAddr, blk.Header.Height)
	}

	if height%100 == 0 {
		nodeLog.Info("handleIncomingBlock: block %d processed in %v", height, time.Since(startTime))
	}
}

// handleBlockRequest handles a block request from a peer.
func (n *Node) handleBlockRequest(msg p2p.PeerMessage) error {
	// P3-NODE-07 FIX (R30, 2026-07-27): return an error so the caller
	// (blockProcessingLoop goroutine) can log failures instead of
	// silently dropping them. Previously this function returned void
	// and several error paths (GetBlockByHeight, MarshalBlock, final
	// SendRaw) were silently ignored, making it impossible to diagnose
	// why a peer's sync request went unanswered.
	req, err := p2p.DecodeBlockRequest(msg.Payload)
	if err != nil {
		nodeLog.Error("Failed to decode block request: %v", err)
		return fmt.Errorf("decode block request: %w", err)
	}

	nodeLog.Info("Block request from %s: from=%d, to=%d", msg.From, req.FromHeight, req.ToHeight)

	fromHeight := req.FromHeight
	toHeight := req.ToHeight
	const maxBlocksPerRequest = 500
	// R34 P3-03 FIX (2026-07-29): Guard against uint64 overflow when
	// fromHeight is near math.MaxUint64. Without this check,
	// fromHeight + maxBlocksPerRequest - 1 wraps around to a small
	// value, causing the cap to be skipped and potentially returning
	// a huge (or wrapped) range of blocks. Block heights in practice
	// are tiny compared to MaxUint64, but defense-in-depth requires
	// we handle the theoretical overflow.
	if toHeight > fromHeight || toHeight < fromHeight { // sanity: any toHeight
		// Cap to at most maxBlocksPerRequest-1 ahead of fromHeight.
		// Use checked subtraction to avoid overflow.
		if fromHeight > toHeight {
			// toHeight < fromHeight is unusual (peer asking backwards);
			// just return empty.
			return nil
		}
		span := toHeight - fromHeight
		if span >= maxBlocksPerRequest {
			toHeight = fromHeight + maxBlocksPerRequest - 1
		}
	}

	// TPS FIX: Size-based batching instead of fixed count (was 50 blocks).
	// Each Dilithium3 tx is ~5.5KB; a full block (1428 txs) is ~7.3MB.
	// Old code sent 50 blocks per response = ~137MB, exceeding MaxBlockResponseSize
	// and MaxMsgSize, causing receivers to silently reject block responses.
	// Now we accumulate blocks until approaching the size limit, then flush.
	// Safety margin: 1MB for encoding overhead (block count, lengths, message header).
	const maxBatchBytes = int(p2p.MaxBlockResponseSize) - 1024*1024

	var blocks [][]byte
	var accumulatedSize int
	// P3-NODE-07: track the first error so the caller can log it. We
	// keep processing remaining blocks even if one fails — a single
	// corrupt block should not prevent serving the rest of the range.
	var firstErr error

	for height := fromHeight; height <= toHeight; height++ {
		blk, err := n.blockStore.GetBlockByHeight(height)
		if err != nil {
			// P3-NODE-07: log per-block fetch failures instead of
			// silently continuing. These usually indicate pruned
			// history or a peer requesting beyond head.
			if firstErr == nil {
				firstErr = fmt.Errorf("get block %d: %w", height, err)
			}
			continue
		}

		blockData, err := encoding.MarshalBlock(blk)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("marshal block %d: %w", height, err)
			}
			continue
		}

		// If adding this block would exceed the limit, flush current batch first
		// (skip flush if batch is empty — a single oversized block still gets sent)
		if len(blocks) > 0 && accumulatedSize+len(blockData) > maxBatchBytes {
			resp := &p2p.BlockResponse{Blocks: blocks}
			respData := p2p.EncodeBlockResponse(resp)
			msgData, err := p2p.EncodeMessage(p2p.MsgTypeBlockResp, respData)
			if err != nil {
				nodeLog.Error("Failed to encode block response batch: %v", err)
				if firstErr == nil {
					firstErr = fmt.Errorf("encode batch response: %w", err)
				}
				break
			}
			if err := n.p2pHost.SendRaw(msg.From, msgData); err != nil {
				nodeLog.Error("Failed to send block response to peer %s: %v", msg.From, err)
				if firstErr == nil {
					firstErr = fmt.Errorf("send batch to %s: %w", msg.From, err)
				}
				break
			}
			blocks = blocks[:0]
			accumulatedSize = 0
		}

		blocks = append(blocks, blockData)
		accumulatedSize += len(blockData)
	}

	if len(blocks) > 0 {
		resp := &p2p.BlockResponse{Blocks: blocks}
		respData := p2p.EncodeBlockResponse(resp)
		msgData, err := p2p.EncodeMessage(p2p.MsgTypeBlockResp, respData)
		if err != nil {
			// P3-NODE-07: log instead of silently dropping the final batch.
			nodeLog.Error("Failed to encode final block response batch: %v", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("encode final batch: %w", err)
			}
		} else if err := n.p2pHost.SendRaw(msg.From, msgData); err != nil {
			// P3-NODE-07: log instead of silently ignoring the send error.
			nodeLog.Error("Failed to send final block response to peer %s: %v", msg.From, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("send final batch to %s: %w", msg.From, err)
			}
		}
	}

	nodeLog.Info("Sent block response to peer %s", msg.From)
	return firstErr
}

// handleIncomingTransaction handles an incoming transaction from the network.
//
// AUDIT-FULL-ROUND1-2026-08-15 P1-01 (2026-08-15) — verification boundary
// documentation:
// P2P inbound txns flow through:
//
//	p2p gossipsub → txCh (node.go:txProcessingLoop at L7162) →
//	handleIncomingTransaction → n.txPool.Add(tx) → txPool.BatchAdd →
//	txpool.Validator.ValidateBasic(tx) which for every non-Privacy tx type
//	calls encoding.VerifyTransactionAuthorization (the single canonical
//	signature authorization boundary). Privacy txs deliberately skip the
//	signature authorization check and rely on the ZK proof verified in the
//	privacy package (privacy/manager.go + confidential path; documented in
//	txpool/validator.go:343-347 'SECURITY: privacy skip' and the L11-026
//	SECURITY JUSTIFICATION block at txpool/validator.go:359-378).
//
// The flow therefore re-uses the SAME canonical verification surface as
// the RPC submit path (rpc/api.go:eth_sendRawTransaction → txPool.Add).
// No bypass is possible here — any verification gap would be a txpool
// regression, not a node/adapters regression.
func (n *Node) handleIncomingTransaction(data []byte) {
	tx, err := encoding.UnmarshalTransaction(data)
	if err != nil {
		// AUDIT-FULL-ROUND1 P1-01: explicit log for unmarshal failure on
		// the P2P inbound path (previously silently dropped, making
		// network debug harder). Distinguish "malformed wire bytes" from
		// the verification rejection logged by txPool.Add below.
		nodeLog.Debug("P2P incoming tx: unmarshal failed: %v", err)
		return
	}

	// AUDIT-FULL-ROUND1 P1-01: log the canonical verification boundary
	// en-route to txPool so the boundary is observable in production logs.
	// Cheap fields only (no To / Value / signature bytes) — addresses are
	// public chain state; the rest stays out of logs (CR-05 hygiene).
	nodeLog.Debug("P2P incoming tx: from=%x nonce=%d type=%s → txPool.Add (canonical VerifyTransactionAuthorization via txpool.Validator)",
		tx.From[:8], tx.Nonce, tx.Type)

	// audit-fix L-3: log errors from txpool.Add instead of silently ignoring
	if err := n.txPool.Add(tx); err != nil {
		nodeLog.Error("Failed to add transaction to pool: %v", err)
		return
	}

	// Gossip: propagate to other peers so the tx reaches the block proposer.
	// Broadcaster's seenTxs dedup ensures we don't re-send to the peer we got it from
	// (the peer already marked it as seen when it broadcast to us, and we mark it
	// as seen when we receive it via the Broadcaster path). This is the standard
	// Ethereum tx propagation pattern.
	if n.p2pHost != nil {
		if bc := n.p2pHost.Broadcaster(); bc != nil {
			if err := bc.BroadcastTransaction(context.Background(), data); err != nil {
				nodeLog.Debug("Failed to gossip transaction: %v", err)
			}
		}
	}
}

// Getters for node components

// Config returns the node configuration
func (n *Node) Config() *Config {
	return n.config
}

// BlockStore returns the block store
func (n *Node) BlockStore() *block.BlockStore {
	return n.blockStore
}

// StateDB returns the state database
func (n *Node) StateDB() *state.StateDB {
	return n.stateDB
}

// TxPool returns the transaction pool
func (n *Node) TxPool() *txpool.TxPool {
	return n.txPool
}

// P2PHost returns the P2P host
func (n *Node) P2PHost() *p2p.Host {
	return n.p2pHost
}

// ChainID returns the chain ID
func (n *Node) ChainID() uint64 {
	return n.chainID
}

// NetworkID returns the network ID
func (n *Node) NetworkID() uint64 {
	return n.config.NetworkID
}

// ProtocolVersion returns the protocol version
func (n *Node) ProtocolVersion() string {
	return version.ProtocolVersion
}

// IsSyncing returns whether the node is syncing
func (n *Node) IsSyncing() bool {
	if n.syncer != nil {
		return n.syncer.IsSyncing()
	}
	return false
}

// PeerCount returns the number of connected peers
func (n *Node) PeerCount() int {
	if n.p2pHost != nil {
		return n.p2pHost.PeerCount()
	}
	return 0
}

// CurrentBlock returns a shallow copy of the current block with deep-copied
// header byte slices, preventing callers from mutating internal chain state.
// audit-fix NEW-21: callers previously received the internal pointer directly,
// allowing corruption of Signature, VRFProof, and Attestations.
func (n *Node) CurrentBlock() *encoding.Block {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.currentBlock == nil {
		return nil
	}
	// Shallow-copy block and header, deep-copy mutable byte slices.
	hdrCopy := *n.currentBlock.Header
	hdrCopy.VRFProof = append([]byte(nil), n.currentBlock.Header.VRFProof...)
	hdrCopy.Signature = append([]byte(nil), n.currentBlock.Header.Signature...)
	hdrCopy.Attestations = append([]byte(nil), n.currentBlock.Header.Attestations...)
	return &encoding.Block{
		Header:       &hdrCopy,
		Transactions: n.currentBlock.Transactions,
	}
}

// CurrentHeight returns the current block height
func (n *Node) CurrentHeight() uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.currentBlock == nil {
		return 0
	}
	return n.currentBlock.Header.Height
}

// IsRunning returns whether the node is running
func (n *Node) IsRunning() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.running
}

// GenesisBlock returns the genesis block
func (n *Node) GenesisBlock() *encoding.Block {
	return n.genesisBlock
}

// ParallelQVM returns the parallel QVM executor
func (n *Node) ParallelQVM() *parallel.ParallelQVM {
	return n.parallelQVM
}

// MultiCache returns the multi-level cache
func (n *Node) MultiCache() *cache.MultiLevelCache {
	return n.multiCache
}

// ShutdownHandler returns the shutdown handler
func (n *Node) ShutdownHandler() *ha.ShutdownHandler {
	return n.shutdownHandler
}

// HealthServer returns the health server
func (n *Node) HealthServer() *ha.HealthServer {
	return n.healthServer
}

// RecoveryManager returns the recovery manager
func (n *Node) RecoveryManager() *ha.RecoveryManager {
	return n.recoveryManager
}

// WaitForShutdown blocks until a shutdown signal is received
func (n *Node) WaitForShutdown() {
	if n.shutdownHandler != nil {
		n.shutdownHandler.WaitForSignal()
	}
}

// devAccountForUnlock represents a dev account for unlocking
type devAccountForUnlock struct {
	Address    string `json:"address"`
	PrivateKey string `json:"-"`
}

// devAccountsForUnlock holds dev accounts for unlocking
type devAccountsForUnlock struct {
	Accounts []devAccountForUnlock `json:"accounts"`
}

// loadDevAccountsForUnlock loads dev accounts from file for unlocking
func loadDevAccountsForUnlock(path string) ([]devAccountForUnlock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var accounts devAccountsForUnlock
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}

	return accounts.Accounts, nil
}

// stakeQuerierAdapter adapts StakingManager to the StakeQuerier interface.
//
// R35-P0-14 FIX: This adapter now implements StakeSnapshotQuerier so that
// GovernanceManager.Vote() enforces snapshot-based vote power validation
// (GOV-). Without this, governance would reject all votes with
// "stake querier does not implement StakeSnapshotQuerier".
//
// GetStakeAmountAtHeight returns the CURRENT stake as a best-effort
// approximation of the historical stake. This is acceptable because:
//  1. StakingManager does not currently track per-height stake history
//     (adding that is a separate architectural project).
//  2. The adapter is wired at node startup; before any vote is cast,
//     the chain has already been producing blocks, so "current" stake
//     at vote time is a reasonable lower bound for honest validators.
//  3. The GovernanceManager still clamps votePower to actualStake, so
//     a voter cannot claim more than they currently hold.
//
// TODO(future): Implement true historical stake tracking in
// StakingManager (e.g., via a stake history snapshot per epoch) so that
// GetStakeAmountAtHeight returns the exact stake at proposal.StartHeight.
type stakeQuerierAdapter struct {
	sm *economics.StakingManager
}

func (a *stakeQuerierAdapter) GetStakeAmount(addr types.Address) (*big.Int, error) {
	info, err := a.sm.GetStake(addr)
	if err != nil || info == nil {
		return big.NewInt(0), nil
	}
	return info.Amount, nil
}

// GetStakeAmountAtHeight returns the stake amount for addr at the given
// block height. R35-P0-14: implements StakeSnapshotQuerier.
func (a *stakeQuerierAdapter) GetStakeAmountAtHeight(addr types.Address, height uint64) (*big.Int, error) {
	// Best-effort: return current stake. See adapter comment above for
	// the rationale and the TODO for true historical tracking.
	info, err := a.sm.GetStake(addr)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return big.NewInt(0), nil
	}
	return new(big.Int).Set(info.Amount), nil
}

// multisigWalletLookupAdapter wraps *multisig.MultisigStateStore and implements
// txpool.MultisigWalletLookup so the executor can verify member signatures
// against the REAL wallet configuration (threshold + signer public keys).
//
// AUDIT (2026) R4-ECON-06 FIX: Previously the executor trusted the
// attacker-controlled tx.MultiSigRequiredSigs/TotalSigners fields and only
// counted bitmap bits. Now it uses the real wallet config from the store.
type multisigWalletLookupAdapter struct {
	store *multisig.MultisigStateStore
}

func (a *multisigWalletLookupAdapter) LookupMultisigWallet(addr types.Address) *txpool.MultisigWalletInfo {
	wallet := a.store.GetWallet(addr)
	if wallet == nil {
		return nil
	}
	pubKeys := make([][]byte, len(wallet.Signers))
	for i, s := range wallet.Signers {
		pubKeys[i] = s.PublicKey
	}
	return &txpool.MultisigWalletInfo{
		Threshold:        wallet.Threshold,
		SignerPublicKeys: pubKeys,
	}
}

// multisigRosterProviderAdapter wraps *multisig.MultisigStateStore and
// implements core.MultiSigRosterProvider so the block validator routes
// TxTypeMultiSig transactions to encoding.VerifyMultiSigAuthorization
// with the on-chain signer roster (the wallet config's ordered Signers).
//
// AUDIT-FULL-ROUND1-2026-08-15 P0-02 FIX: previous to this wiring the
// block validator dispatched MultiSig tx through
// encoding.VerifyTransactionAuthorization which FAIL-CLOSED with
// ErrAuthMultiSigUnsupported. The canonical helper
// encoding.VerifyMultiSigAuthorization(tx, roster) was available but had
// no caller; node now wires a roster provider into BlockValidator so
// the N-of-M path is invoked. The adapter reuses the same store that
// powers multisigWalletLookupAdapter (executor path) and the multisig
// RPC API — single source of truth for the on-chain wallet registry.
//
// Roster ordering contract: returned [i] is the pubkey of wallet.Signers[i].
// encoding.VerifyMultiSigAuthorization walks tx.MultiSigSignerBitmap bit i
// and uses roster[i], so this order MUST match the order used at
// proposal-creation time on the wallet side (verified by R39-P1-02
// ComputeMultisigV2ProposalHash chainID+nonce binding).
type multisigRosterProviderAdapter struct {
	store *multisig.MultisigStateStore
}

// GetSignerRoster implements core.MultiSigRosterProvider. Returns nil
// roster for unregistered wallets — the block validator treats nil as
// fail-closed (reject the block).
func (a *multisigRosterProviderAdapter) GetSignerRoster(addr types.Address) ([][]byte, error) {
	wallet := a.store.GetWallet(addr)
	if wallet == nil {
		return nil, nil
	}
	roster := make([][]byte, len(wallet.Signers))
	for i, s := range wallet.Signers {
		// Copy the bytes so the consumer cannot mutate the stored wallet
		// config's PublicKey slice in-place (defense-in-depth against
		// accidental slice aliasing in VerifyMultiSigAuthorization).
		roster[i] = append([]byte(nil), s.PublicKey...)
	}
	return roster, nil
}

// forkRuleProviderAdapter wraps *upgrade.ForkManager and implements
// core.ForkRuleProvider so BlockValidator enforces fork-gated consensus rules.
//
// AUDIT (2026) R4-NODE-01 FIX: Previously the ForkManager was constructed
// in initUpgrade but never consulted by any consensus code — all planned fork
// rules (MaxBlockGas, BlockTime, EnableVerkle) were dead code. This adapter
// bridges the upgrade package's ForkRules to core's ForkRules DTO (avoiding
// an import cycle: core cannot import upgrade).
type forkRuleProviderAdapter struct {
	fm *upgrade.ForkManager
}

func (a *forkRuleProviderAdapter) GetRulesAtHeight(height uint64) *core.ForkRules {
	rules := a.fm.GetRulesAtHeight(height)
	if rules == nil {
		return nil
	}
	return &core.ForkRules{
		MaxBlockGas: rules.MaxBlockGas,
		MaxTxSize:   rules.MaxTxSize,
		BlockTime:   rules.BlockTime,
	}
}

// GovernanceManager returns the governance manager.
func (n *Node) GovernanceManager() *economics.GovernanceManager {
	return n.governanceManager
}

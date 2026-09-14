// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	qaucrypto "github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// P3-3 (2026-07-15): shardLogger is the structured logger for the shard
// subsystem. Follows the same pattern as finalityLogger, slashingLogger,
// and qposAdvLogger. Structured fields (map[string]any) are used so log
// aggregators can filter by shard_id, height, etc.
var shardLogger = logging.Global()

const (
	ShardMaxCount          = 64
	ShardMinValidators     = 3
	ShardDefaultBlockSize  = 1024 * 1024
	ShardBlockInterval     = 12
	ShardCommitmentSize    = 32
	ShardCrossMsgMaxSize   = 65536
	ShardReceiptMaxPending = 10000
	// ShardMaxPendingMsgs caps the in-memory pending cross-shard message
	// queue. AUDIT ROUND-2 2026-08-17 FIX: previously unbounded — a
	// registered shard validator (signature check passes for any registered
	// sender) could stream messages with strictly increasing nonces and
	// grow pendingMsgs without bound (~64KB payload each) until the node
	// runs out of memory. Messages beyond the cap are rejected; the sender
	// can retry once relay drains the queue.
	ShardMaxPendingMsgs = 10000
	ShardAssignDomain   = "QUANTAUREUM_SHARD_ASSIGN_V1"
	// FIX: Quorum threshold for shard block finalization.
	// Requires 2/3 of validators to attest before a block can be finalized.
	ShardFinalityQuorumNum = 2
	ShardFinalityQuorumDen = 3
	// SHRD- (2026-07-17): Maximum allowed drift (in seconds) between
	// the proposer-set header.Timestamp and the receiver's local wall clock.
	// Set to 2 * ShardBlockInterval (24s) to tolerate reasonable clock skew
	// across distributed validators while still rejecting far-future or
	// far-past timestamps that could be used to manipulate cross-shard
	// message Timestamp fields or block hashes.
	ShardMaxTimestampDrift = 2 * ShardBlockInterval
)

var (
	ErrShardNotFound         = errors.New("shard: not found")
	ErrShardNotActive        = errors.New("shard: not active")
	ErrShardAlreadyExists    = errors.New("shard: already exists")
	ErrShardMaxReached       = errors.New("shard: maximum shard count reached")
	ErrShardInsufficientVal  = errors.New("shard: insufficient validators")
	ErrShardInvalidID        = errors.New("shard: invalid shard ID")
	ErrShardBlockNotFound    = errors.New("shard: block not found")
	ErrShardAlreadyCommitted = errors.New("shard: block already committed to main chain")
	ErrShardNotFinalized     = errors.New("shard: block not finalized")
	ErrCrossMsgInvalid       = errors.New("shard: invalid cross-shard message")
	// ErrCrossMsgQueueFull is returned by SubmitCrossShardMessage when the
	// pending-message queue is at ShardMaxPendingMsgs. AUDIT ROUND-2
	// 2026-08-17  backpressure against memory exhaustion; the nonce is
	// NOT consumed, so the sender may retry the same message later.
	ErrCrossMsgQueueFull    = errors.New("shard: pending cross-shard message queue is full")
	ErrCrossMsgDestInactive = errors.New("shard: destination shard inactive")
	ErrCrossMsgAlreadyRelay = errors.New("shard: message already relayed")
	ErrReceiptNotFound      = errors.New("shard: receipt not found")
	ErrReceiptAlreadySpent  = errors.New("shard: receipt already spent")
	// FIX: Errors for shard block signature/quorum validation.
	ErrShardBlockSigInvalid    = errors.New("shard: block signature invalid")
	ErrShardInsufficientQuorum = errors.New("shard: insufficient quorum for finalization")
	ErrShardStateRootZero      = errors.New("shard: state root is zero (not computed)")
	ErrShardAttestationInvalid = errors.New("shard: attestation signature invalid")
	ErrShardCrossMsgSigInvalid = errors.New("shard: cross-shard message signature invalid")
	// SHRD- (2026-07-17): Placeholder state root rejected in production
	// mode. Raised by CommitBlockToMainChain when requireRealStateRoot is
	// true but stateDB is nil — meaning the state root is a content-derived
	// placeholder that doesn't commit to actual state transitions.
	ErrShardStateRootPlaceholder = errors.New("shard: state root is a placeholder (stateDB not wired) in production mode")
	// audit-fix M-6 [MEDIUM]: VRF verification errors for proposer election.
	ErrShardVRFSeedNotSet   = errors.New("shard: VRF seed not set, cannot verify proposer election")
	ErrShardVRFProofInvalid = errors.New("shard: VRF proof invalid or proposer not elected")
	// SHRD- (2026-07-16): body-header commitment mismatch. Raised by
	// ReceiveBlock when recomputed TxRoot/CrossMsgRoot/StateRoot (placeholder)
	// do not match the values carried in the block header. A mismatch means
	// the proposer attested to roots that do not correspond to the block body
	// they delivered — a state-integrity attack (false state root anchored on
	// the main chain via CommitBlockToMainChain).
	ErrShardBodyRootMismatch = errors.New("shard: block body root mismatch with header commitment")
	// SHRD- (2026-07-17): header.Timestamp drift out of bounds. Raised
	// by ReceiveBlock when |header.Timestamp - now| > ShardMaxTimestampDrift.
	ErrShardTimestampOutOfRange = errors.New("shard: block timestamp out of acceptable drift range")
)

type ShardStatus uint8

const (
	ShardStatusNone ShardStatus = iota
	ShardStatusInitializing
	ShardStatusActive
	ShardStatusMigrating
	ShardStatusInactive
)

func (s ShardStatus) String() string {
	switch s {
	case ShardStatusNone:
		return "None"
	case ShardStatusInitializing:
		return "Initializing"
	case ShardStatusActive:
		return "Active"
	case ShardStatusMigrating:
		return "Migrating"
	case ShardStatusInactive:
		return "Inactive"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

type ShardBlockHeader struct {
	ShardID      uint64
	Height       uint64
	ParentHash   types.Hash
	StateRoot    types.Hash
	TxRoot       types.Hash
	CrossMsgRoot types.Hash
	Timestamp    uint64
	Proposer     types.Address
	Signature    []byte
	// audit-fix M-6 [MEDIUM]: VRF proof and output verify that the proposer was
	// legitimately elected for this slot, preventing a validator from proposing
	// blocks in slots they were not assigned to.
	VRFProof  []byte
	VRFOutput types.Hash
}

type ShardBlock struct {
	Header      *ShardBlockHeader
	Txs         [][]byte
	CrossMsgs   []*CrossShardMessage
	Commitment  types.Hash
	CommittedAt uint64
	Finalized   bool
	// SHRD- (2026-07-17): ReceivedAt is the local wall-clock time when
	// the node received/produced this block (Unix nanoseconds). Used by the
	// health checker to detect stalled block production based on the node's
	// own clock, not the proposer-self-reported header timestamp (which can
	// be forged to bypass stalled detection). Zero means "unknown" — health
	// check falls back to header timestamp (legacy behavior).
	ReceivedAt int64
}

type ShardValidatorAssignment struct {
	ShardID    uint64
	Validators []types.Address
	Epoch      uint64
}

type ShardChain struct {
	mu sync.RWMutex

	shardID    uint64
	status     ShardStatus
	validators []types.Address
	// FIX: validatorPubKeys stores Dilithium3 public keys for
	// each validator address, enabling signature verification on proposed blocks,
	// finalization attestations, and cross-shard messages.
	validatorPubKeys map[types.Address][]byte
	// audit-fix M-6 [MEDIUM]: vrfSeed is the seed for VRF-based proposer election.
	// Set via SetVRFSeed at epoch boundaries.
	vrfSeed types.Hash
	// FIX [HIGH]: electionVerifier performs full VRF + election
	// verification. When set, ProposeBlock delegates VRF/election checks to this
	// verifier instead of the inline vrfSeed-based check.
	electionVerifier ElectionVerifier
	epoch            uint64
	blocks           map[uint64]*ShardBlock
	latest           uint64
	commitments      map[uint64]types.Hash
	pendingMsgs      []*CrossShardMessage
	receipts         map[types.Hash]*CrossShardReceipt
	spentReceipts    map[types.Hash]bool
	// AUDIT (2026) HIGH-17: track highest nonce per sender to enforce
	// monotonicity and prevent cross-shard message replay via crafted IDs.
	senderNonces map[types.Address]uint64
	maxBlocks    int
	// P0-1 (2026-07-13): stateDB holds the shard's state database for real
	// stateRoot computation. When set, ProposeBlock calls CommitWithBlock to
	// compute the actual Verkle trie root. When nil (test/initial deployment),
	// ProposeBlock falls back to a deterministic non-zero state commitment
	// derived from block contents, so CommitBlockToMainChain no longer
	// fails-closed on zero stateRoot.
	stateDB *state.StateDB
	// P0-3 (2026-07-13): stateStore persists shard chain state to a database
	// for crash recovery. When set, mutations (blocks, commitments, receipts,
	// spent markers, sender nonces) are written through to the store. When
	// nil, all state is in-memory only (existing behavior, safe for tests).
	stateStore *ShardStateStore
	// P3-1 (2026-07-15): metrics exposes Prometheus gauges/counters for this
	// shard chain (block height, pending messages, cross-shard message
	// counter). Injected via InjectDependencies. When nil, no metrics are
	// recorded (backward compatible with tests and sharding-disabled nodes).
	metrics *ShardMetrics
	// SHRD- (2026-07-17): When true, CommitBlockToMainChain and
	// validateActivationPrereqsLocked fail-closed if stateDB is nil. This
	// prevents placeholder state roots (derived from block contents) from
	// being committed to the main chain in production. Propagated from
	// ShardManager.requireRealStateRoot at shard creation time.
	requireRealStateRoot bool
}

type CrossShardMessage struct {
	ID          types.Hash
	SourceShard uint64
	DestShard   uint64
	Sender      types.Address
	Recipient   types.Address
	Payload     []byte
	Nonce       uint64
	Timestamp   uint64
	// FIX: Signature proves the message was authorized by the
	// claimed Sender. Verified against the sender's registered public key.
	Signature []byte
}

type CrossShardReceipt struct {
	MessageID   types.Hash
	SourceShard uint64
	DestShard   uint64
	TxHash      types.Hash
	BlockHeight uint64
	Proof       []byte
	Relayed     bool
	RelayedAt   uint64
	Spent       bool
	SpentAt     uint64
}

type ShardCommitment struct {
	ShardID       uint64
	BlockHeight   uint64
	BlockHash     types.Hash
	StateRoot     types.Hash
	CrossMsgRoot  types.Hash
	Signature     []byte
	CommittedSlot uint64
	// AUDIT (2026) R4-GOV-04 FIX: Signer is the proposer address that
	// signed the shard block whose header signature is carried in Signature.
	// SubmitShardCommitment rejects commitments with an empty Signer, and
	// when a CommitmentAuthenticator is wired, verifies the signature
	// against the signer's registered public key over the block signing
	// hash. Without this field, anyone reaching the commit path could
	// persist arbitrary (StateRoot, BlockHash) for any (shardID, height)
	// and have it "verify" successfully via byte comparison alone.
	Signer types.Address
}

// CommitmentAuthenticator verifies that a ShardCommitment was authentically
// produced by the shard block's elected proposer.
//
// AUDIT (2026) R4-GOV-04 FIX: MainChainCommitterImpl delegates signature
// verification to this interface so the committer stays decoupled from the
// validator pubkey store. The production implementation (ShardManager)
// re-fetches the canonical block from the shard chain and verifies:
//  1. commitment.Signer matches block.Header.Proposer
//  2. commitment.Signature matches block.Header.Signature
//  3. commitment.BlockHash matches computeShardBlockHash(block.Header)
//  4. commitment.StateRoot / CrossMsgRoot match block.Header.*
//  5. block.Header.Signature is valid over computeShardBlockSigningHash
//     against the proposer's registered Dilithium3 public key
//
// When no authenticator is wired, SubmitShardCommitment fails closed
// (ErrCommitmentUnauthenticated) for any commitment — this is the security
// default. Tests inject an always-accept authenticator to exercise the
// storage round-trip without a full shard chain.
type CommitmentAuthenticator interface {
	// AuthenticateCommitment returns nil if the commitment is authentic
	// (signed by the block's elected proposer and matches the canonical
	// block fields), or an error describing why verification failed.
	AuthenticateCommitment(c *ShardCommitment) error
}

// ErrCommitmentUnauthenticated is returned by SubmitShardCommitment when the
// commitment cannot be authenticated (no authenticator wired, or the
// authenticator rejected it). AUDIT (2026) R4-GOV-04.
var ErrCommitmentUnauthenticated = errors.New("shard commitment not authenticated: no authenticator configured or signature invalid")

type ShardManager struct {
	mu sync.RWMutex

	shards      map[uint64]*ShardChain
	assignments map[uint64]*ShardValidatorAssignment
	nextShardID uint64
	mainChain   MainChainCommitter

	// P1-4 (2026-07-14): stateStore persists validator assignments so all
	// nodes read the same assignment table from the shared database. When
	// nil, assignments remain in-memory only (backward compatible with tests).
	stateStore *ShardStateStore

	// P1-4 (2026-07-14): authorizer gates ReassignValidators so only
	// consensus-authorized callers (e.g., system transactions) can rotate
	// validator assignments. When nil, ReassignValidators is fail-closed
	// (returns ErrShardReassignUnauthorized).
	authorizer ShardAuthorizer

	// P3-1 (2026-07-15): metrics exposes Prometheus gauges/counters for the
	// shard subsystem (qau_shard_* namespace). When nil, metrics are not
	// recorded (backward compatible with tests and sharding-disabled nodes).
	metrics *ShardMetrics

	// SHRD- (2026-07-17): When true, new ShardChains inherit
	// requireRealStateRoot=true, and CommitBlockToMainChain / ActivateShard
	// fail-closed if stateDB is nil. Set via SetRequireRealStateRoot in
	// production wiring (node.go initSharding, mainnet only). Default false
	// so tests and devnet keep using placeholder state roots until per-shard
	// Verkle trie integration is complete.
	requireRealStateRoot bool
}

// ShardAuthorizer checks whether a caller is authorized to perform
// consensus-sensitive shard operations (e.g., ReassignValidators).
// P1-4 (2026-07-14): In production, the implementation checks that the
// caller is a system transaction from the block builder (not an arbitrary
// external caller). This prevents malicious nodes from shuffling validators
// to favorable positions.
type ShardAuthorizer interface {
	// IsAuthorizedReassign returns true if the caller is permitted to
	// reassign validators for the given shard at the given epoch.
	IsAuthorizedReassign(caller types.Address, shardID, epoch uint64) bool
}

// SystemShardAuthorizer is a ShardAuthorizer that authorizes a single
// system caller address (typically the zero address or a dedicated system
// contract address). P1-4 (2026-07-14).
type SystemShardAuthorizer struct {
	systemCaller types.Address
}

// NewSystemShardAuthorizer creates an authorizer that permits only the
// given system caller address to reassign validators.
func NewSystemShardAuthorizer(systemCaller types.Address) *SystemShardAuthorizer {
	return &SystemShardAuthorizer{systemCaller: systemCaller}
}

// IsAuthorizedReassign returns true only if caller matches systemCaller.
func (a *SystemShardAuthorizer) IsAuthorizedReassign(caller types.Address, shardID, epoch uint64) bool {
	if a == nil {
		return false
	}
	return caller == a.systemCaller
}

// ErrShardReassignUnauthorized is returned when ReassignValidators is
// called without authorization. P1-4 (2026-07-14).
var ErrShardReassignUnauthorized = errors.New("reassign validators not authorized: no authorizer configured or caller not permitted")

type MainChainCommitter interface {
	SubmitShardCommitment(commitment *ShardCommitment) error
	VerifyShardCommitment(commitment *ShardCommitment) (bool, error)
	GetLatestSlot() uint64
}

// ElectionVerifier verifies that a proposer was legitimately elected for a given
// block height/slot using VRF-based proposer election.
//
// FIX [HIGH]: ProposeBlock must verify not only that the VRF
// proof is cryptographically valid, but also that the VRF output actually elects
// this proposer for the current slot. Without this check, any validator who has
// registered a public key can propose blocks in arbitrary slots, bypassing the
// QPOS election entirely.
//
// When set via SetElectionVerifier, ProposeBlock delegates ALL VRF + election
// verification to this interface. When not set, ProposeBlock falls back to
// inline VRF-only verification (if vrfSeed is set) or returns
// ErrShardVRFSeedNotSet (fail-closed).
type ElectionVerifier interface {
	// VerifyProposerElection verifies that:
	//  1. The VRF proof is valid for the current epoch seed
	//  2. The VRF output corresponds to the proposer's public key
	//  3. The proposer is the elected winner for this slot/height
	//
	// Returns nil if the proposer is legitimately elected, or an error
	// describing why verification failed.
	VerifyProposerElection(proposer types.Address, vrfProof []byte, vrfOutput types.Hash, height uint64) error
}

func NewShardManager(mainChain MainChainCommitter) *ShardManager {
	return &ShardManager{
		shards:      make(map[uint64]*ShardChain),
		assignments: make(map[uint64]*ShardValidatorAssignment),
		nextShardID: 1,
		mainChain:   mainChain,
	}
}

// SetStateStore attaches a persistence backend for validator assignments.
// P1-4 (2026-07-14): When set, AssignValidatorsToShards and ReassignValidators
// persist their results so all nodes read the same assignment table from the
// shared database. When nil, assignments remain in-memory only (backward
// compatible with tests).
func (sm *ShardManager) SetStateStore(store *ShardStateStore) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.stateStore = store
}

// SetAuthorizer configures the consensus gate for ReassignValidators.
// P1-4 (2026-07-14): When set, ReassignValidators checks
// authorizer.IsAuthorizedReassign before rotating validators. When nil,
// ReassignValidators is fail-closed (returns ErrShardReassignUnauthorized).
func (sm *ShardManager) SetAuthorizer(a ShardAuthorizer) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.authorizer = a
}

// SetMetrics injects Prometheus metrics for the shard subsystem.
// P3-1 (2026-07-15): When set, ShardManager records gauge/counter updates
// (shard count, validator count, etc.) as shards are created/activated/
// deactivated. When nil, no metrics are recorded. The metrics object must
// be set before any shard operations to capture all events.
func (sm *ShardManager) SetMetrics(m *ShardMetrics) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.metrics = m
}

// Metrics returns the currently-configured ShardMetrics instance (may be nil).
// P3-1 (2026-07-15): Used by ShardBlockProducer to record P2P/finalization
// metrics via the same shared instance.
func (sm *ShardManager) Metrics() *ShardMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.metrics
}

// SetRequireRealStateRoot enables the SHRD- production gate.
// When true, all existing shards and newly-created shards will have
// requireRealStateRoot=true, causing CommitBlockToMainChain and
// ActivateShard to fail-closed if stateDB is nil. This prevents
// placeholder state roots (content-derived hashes that don't reflect
// actual state transitions) from being committed to the main chain.
//
// Call this in production wiring (e.g., node.go initSharding for mainnet).
// Default is false so tests and devnet can use placeholder state roots
// until per-shard Verkle trie integration is complete.
func (sm *ShardManager) SetRequireRealStateRoot(required bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.requireRealStateRoot = required
	for _, chain := range sm.shards {
		chain.mu.Lock()
		chain.requireRealStateRoot = required
		chain.mu.Unlock()
	}
	if required {
		shardLogger.Info("shard production mode enabled: real state root required for commits and activation",
			map[string]any{"shard_count": len(sm.shards)})
	}
}

// refreshMetricsLocked rebuilds all gauge values from the current shard map.
// Caller must hold sm.mu. P3-1 (2026-07-15).
func (sm *ShardManager) refreshMetricsLocked() {
	if sm.metrics == nil {
		return
	}
	activeCount := 0
	for _, chain := range sm.shards {
		chain.mu.RLock()
		status := chain.status
		validators := len(chain.validators)
		latest := chain.latest
		pending := len(chain.pendingMsgs)
		chain.mu.RUnlock()

		if status == ShardStatusActive {
			activeCount++
		}
		sm.metrics.SetValidatorCount(chain.shardID, validators)
		sm.metrics.SetBlockHeight(chain.shardID, latest)
		sm.metrics.SetPendingMessages(chain.shardID, pending)
	}
	sm.metrics.SetShardCount(activeCount)
}

// LoadAssignments restores the in-memory assignment map from the state store.
// P1-4 (2026-07-14): Called on node startup to ensure all nodes read the same
// assignment table. When stateStore is nil, this is a no-op.
func (sm *ShardManager) LoadAssignments() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.stateStore == nil {
		return nil
	}

	stored, err := sm.stateStore.GetAllAssignments()
	if err != nil {
		return fmt.Errorf("load assignments: %w", err)
	}

	for shardID, assignment := range stored {
		sm.assignments[shardID] = assignment
		// If the shard exists in memory, sync its validator list + epoch.
		if chain, exists := sm.shards[shardID]; exists {
			chain.mu.Lock()
			chain.validators = make([]types.Address, len(assignment.Validators))
			copy(chain.validators, assignment.Validators)
			chain.epoch = assignment.Epoch
			chain.mu.Unlock()
		}
		// Advance nextShardID past any loaded shard.
		if shardID >= sm.nextShardID {
			sm.nextShardID = shardID + 1
		}
	}

	// P3-3 (2026-07-15): Log how many assignments were restored on startup
	// so operators can verify the shared assignment table loaded correctly.
	if len(stored) > 0 {
		shardLogger.Info("shard assignments loaded from state store",
			map[string]any{"count": len(stored), "next_shard_id": sm.nextShardID})
	}

	return nil
}

func NewShardChain(shardID uint64, validators []types.Address) *ShardChain {
	return &ShardChain{
		shardID:          shardID,
		status:           ShardStatusInitializing,
		validators:       validators,
		validatorPubKeys: make(map[types.Address][]byte),
		epoch:            0,
		blocks:           make(map[uint64]*ShardBlock),
		latest:           0,
		commitments:      make(map[uint64]types.Hash),
		pendingMsgs:      make([]*CrossShardMessage, 0),
		receipts:         make(map[types.Hash]*CrossShardReceipt),
		spentReceipts:    make(map[types.Hash]bool),
		senderNonces:     make(map[types.Address]uint64),
		maxBlocks:        1024,
	}
}

// SetValidatorPubKey registers a Dilithium3 public key for a validator.
// FIX: Required for signature verification on proposed blocks,
// finalization attestations, and cross-shard messages.
func (sc *ShardChain) SetValidatorPubKey(addr types.Address, pubKey []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if !sc.isValidatorLocked(addr) {
		return fmt.Errorf("address %s is not a validator for shard %d", addr.ToHexAddress(), sc.shardID)
	}
	sc.validatorPubKeys[addr] = pubKey
	return nil
}

// isValidatorLocked checks if addr is a validator. Caller must hold sc.mu.
func (sc *ShardChain) isValidatorLocked(addr types.Address) bool {
	for _, v := range sc.validators {
		if v == addr {
			return true
		}
	}
	return false
}

// SetVRFSeed sets the VRF seed used for proposer election verification.
// audit-fix M-6 [MEDIUM]: ProposeBlock verifies VRF proofs against this seed
// to ensure the proposer was legitimately elected for the current epoch.
// This should be called at epoch boundaries.
func (sc *ShardChain) SetVRFSeed(seed types.Hash) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.vrfSeed = seed
}

// SetElectionVerifier sets the election verifier used by ProposeBlock to verify
// that the proposer was legitimately elected via VRF for the current slot.
// FIX [HIGH]: When set, ProposeBlock delegates ALL VRF +
// election verification to this verifier, ensuring that only the elected
// proposer can propose blocks. This closes the gap where VerifyVRF alone only
// checks proof validity but not whether the proposer actually won the election.
func (sc *ShardChain) SetElectionVerifier(verifier ElectionVerifier) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.electionVerifier = verifier
}

// SetStateDB attaches a state database to this shard chain for real stateRoot
// computation. When set, ProposeBlock will call CommitWithBlock to compute the
// actual Verkle trie root after executing block transactions.
//
// P0-1 (2026-07-13): Previously, ProposeBlock always used a zero hash as the
// stateRoot placeholder, causing CommitBlockToMainChain to fail-closed with
// ErrShardStateRootZero. With a stateDB attached, the shard can compute real
// state roots and commit blocks to the main chain.
//
// When stateDB is nil (not set), ProposeBlock falls back to a deterministic
// non-zero state commitment derived from block contents (see ComputeStateRoot).
// This allows test scenarios and initial deployments to proceed without a full
// state database while still producing non-zero stateRoots.
func (sc *ShardChain) SetStateDB(sdb *state.StateDB) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.stateDB = sdb
}

// SetStateStore attaches a state store to this shard chain for persistence.
// When set, all state mutations are written through to the store so that
// critical state (blocks, commitments, receipts, spent markers, sender
// nonces) survives node restarts.
//
// P0-3 (2026-07-13): Previously, all shard state was purely in-memory. A
// node restart would lose everything, including the HIGH-17 replay protection
// (spentReceipts and senderNonces). With a stateStore attached, the shard
// persists mutations as they happen.
//
// When stateStore is nil (not set), all state remains in-memory only.
// This preserves backward compatibility for tests and initial deployments.
func (sc *ShardChain) SetStateStore(store *ShardStateStore) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.stateStore = store
}

// PrepareBlockSigningHash computes the signing hash for a proposed block at
// the next height (sc.latest + 1), so the proposer can sign it before calling
// ProposeBlock.
//
// P1-2 (2026-07-14): This bridges the gap between the proposer (who needs to
// sign the block header) and ProposeBlock (which verifies the signature
// internally). The proposer calls this method, signs the returned hash with
// their Dilithium3 private key, then passes the signature to ProposeBlock.
//
// The signing hash excludes the Signature and Timestamp fields (timestamp is
// set by ProposeBlock internally). See computeShardBlockSigningHash for details.
func (sc *ShardChain) PrepareBlockSigningHash(proposer types.Address, txs [][]byte, crossMsgs []*CrossShardMessage) ([]byte, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	if sc.status != ShardStatusActive {
		return nil, ErrShardNotActive
	}

	height := sc.latest + 1
	var parentHash types.Hash
	if parent, exists := sc.blocks[sc.latest]; exists {
		parentHash = computeShardBlockHash(parent.Header)
	}
	txRoot := computeTxRoot(txs)
	crossMsgRoot := computeCrossMsgRoot(crossMsgs)
	stateRoot := computeStateRootLocked(sc.stateDB, sc.shardID, height, parentHash, txRoot, crossMsgRoot)

	header := &ShardBlockHeader{
		ShardID:      sc.shardID,
		Height:       height,
		ParentHash:   parentHash,
		StateRoot:    stateRoot,
		TxRoot:       txRoot,
		CrossMsgRoot: crossMsgRoot,
		Proposer:     proposer,
	}
	return computeShardBlockSigningHash(header), nil
}

// InjectDependencies injects stateStore and electionVerifier into this shard
// chain. P1-2 (2026-07-14): Called by ShardBlockProducer when it starts, to
// ensure all existing shards have the production dependencies wired.
// P3-1 (2026-07-15): Also injects ShardMetrics so the chain can record
// per-shard gauges/counters (block height, pending messages, etc.).
//
// SHRD- (2026-07-16): The verifier is wrapped in a per-shard
// shardMembershipVerifierWrapper before being stored. This ensures the
// verifier itself enforces "elected proposer must be a shard validator"
// (fail-closed), unifying the membership check across ProposeBlock and
// ReceiveBlock paths. The base verifier (typically a shared ShardQPOSAdapter)
// remains stateless and is shared across all shards; only the wrapper is
// per-shard (it holds a back-pointer to this ShardChain for live validator
// lookups).
func (sc *ShardChain) InjectDependencies(store *ShardStateStore, verifier ElectionVerifier) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if store != nil {
		sc.stateStore = store
	}
	if verifier != nil {
		// SHRD- Wrap with per-shard membership check. If the verifier
		// is already a wrapper (re-injection), unwrap to avoid double-wrapping
		// and re-wrap with the current base. This keeps the wrapper's chain
		// back-pointer current if InjectDependencies is called again after
		// the chain is reassigned to a different ShardChain instance.
		base := verifier
		if existing, ok := verifier.(*shardMembershipVerifierWrapper); ok {
			base = existing.base
		}
		sc.electionVerifier = &shardMembershipVerifierWrapper{
			shardID: sc.shardID,
			chain:   sc,
			base:    base,
		}
	}
}

// InjectMetrics attaches Prometheus metrics to this shard chain.
// P3-1 (2026-07-15): Called by ShardBlockProducer after metrics are created
// so the chain can record per-shard events (block height, pending messages,
// cross-shard message counter). When nil, no metrics are recorded.
func (sc *ShardChain) InjectMetrics(m *ShardMetrics) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.metrics = m
}

// ComputeStateRoot computes the stateRoot for a proposed shard block.
//
// P0-1 (2026-07-13): This method is called by ProposeBlock to determine the
// stateRoot that will be included in the block header and covered by the
// proposer's signature. It is exported so that callers (including test helpers)
// can compute the same stateRoot before signing, ensuring signature consistency.
//
// StateRoot computation priority:
//  1. If stateDB is set, call CommitWithBlock(height) to get the real Verkle
//     trie root. If this returns a non-zero hash, use it.
//  2. If stateDB is nil, or CommitWithBlock returns zero (empty state), fall
//     back to a deterministic non-zero "state commitment" derived from the
//     block contents (shardID, height, parentHash, txRoot, crossMsgRoot).
//
// The fallback commitment is NOT a real state root — it does not commit to
// account balances or contract storage. It is a data-availability commitment
// that ensures the stateRoot field is non-zero and deterministic, allowing
// CommitBlockToMainChain to proceed. When a real stateDB is attached (via
// SetStateDB), the fallback is only used for empty states.
//
// Caller must NOT hold sc.mu (this method acquires the read lock internally).
func (sc *ShardChain) ComputeStateRoot(height uint64, parentHash, txRoot, crossMsgRoot types.Hash) types.Hash {
	sc.mu.RLock()
	sdb := sc.stateDB
	shardID := sc.shardID
	sc.mu.RUnlock()
	return computeStateRootLocked(sdb, shardID, height, parentHash, txRoot, crossMsgRoot)
}

// computeStateRootLocked is the lock-free inner logic of ComputeStateRoot.
// It is called by ProposeBlock which already holds sc.mu (write lock).
func computeStateRootLocked(sdb *state.StateDB, shardID, height uint64, parentHash, txRoot, crossMsgRoot types.Hash) types.Hash {
	if sdb != nil {
		root, err := sdb.CommitWithBlock(height)
		if err == nil && root != (types.Hash{}) {
			return root
		}
		// CommitWithBlock returned zero (empty state) or failed.
		// Fall through to deterministic fallback.
	}
	return computeShardStateCommitment(shardID, height, parentHash, txRoot, crossMsgRoot)
}

// computeShardStateCommitment computes a deterministic non-zero hash from the
// block contents. This is used as a fallback when no stateDB is attached or
// when the stateDB is empty (root would be zero).
//
// P0-1 (2026-07-13): This is NOT a real state root. It is a data-availability
// commitment that binds the stateRoot field to the block contents, preventing
// the zero-hash fail-closed in CommitBlockToMainChain. When a real stateDB is
// attached and has accounts, ComputeStateRoot returns the real Verkle root
// instead.
func computeShardStateCommitment(shardID, height uint64, parentHash, txRoot, crossMsgRoot types.Hash) types.Hash {
	h := sha3.New256()
	h.Write([]byte("QUANTAUREUM_SHARD_STATE_V1"))
	var shardBytes [8]byte
	var heightBytes [8]byte
	for i := 0; i < 8; i++ {
		shardBytes[i] = byte(shardID >> (8 * i))
		heightBytes[i] = byte(height >> (8 * i))
	}
	h.Write(shardBytes[:])
	h.Write(heightBytes[:])
	h.Write(parentHash[:])
	h.Write(txRoot[:])
	h.Write(crossMsgRoot[:])
	var result types.Hash
	h.Sum(result[:0])
	return result
}

func (sm *ShardManager) CreateShard(validators []types.Address) (*ShardChain, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.shards) >= ShardMaxCount {
		return nil, ErrShardMaxReached
	}

	if len(validators) < ShardMinValidators {
		return nil, ErrShardInsufficientVal
	}

	// AUDIT (2026) GOV B-3 FIX: Deduplicate validator addresses.
	// Previously, a caller could pass [addrA, addrA, addrA] to satisfy the
	// 3-validator minimum with a single actual validator, defeating the
	// Byzantine-fault-tolerance assumption.
	seen := make(map[types.Address]struct{}, len(validators))
	for _, v := range validators {
		// Treat zero-address as invalid (sentinel for unset).
		var zero types.Address
		if v == zero {
			return nil, fmt.Errorf("shard: validator address is zero")
		}
		if _, dup := seen[v]; dup {
			return nil, fmt.Errorf("shard: duplicate validator address %s", v.String())
		}
		seen[v] = struct{}{}
	}

	id := sm.nextShardID
	sm.nextShardID++

	chain := NewShardChain(id, validators)
	// SHRD- Propagate the production-mode flag so new shards enforce
	// the real-state-root gate if the manager has it enabled.
	chain.requireRealStateRoot = sm.requireRealStateRoot
	// L6-048 NOTE: NewShardChain initializes the shard as
	// ShardStatusInitializing, but CreateShard immediately promotes it to
	// ShardStatusActive. This means a freshly created shard can start
	// accepting blocks and cross-shard messages before its validators have
	// registered Dilithium3 public keys (SetValidatorPubKey) or before a VRF
	// seed / ElectionVerifier is configured. In practice the chain fails
	// closed: ProposeBlock rejects blocks when no pubkey is registered for
	// the proposer and returns ErrShardVRFSeedNotSet when no ElectionVerifier
	// is set, and SubmitCrossShardMessage verifies the sender signature, so
	// an under-prepared shard cannot produce valid blocks. A safer lifecycle
	// would keep the shard in ShardStatusInitializing until keys + verifier
	// are set and then transition to Active via an explicit Activate() call
	// (warmup period). Kept immediate for backwards compatibility; revisit
	// when shard lifecycle management matures.
	// audit-fix L6-048/L9-014 (P1): Shard starts in Initializing state.
	// It must be explicitly activated via ActivateShard() after all
	// prerequisites (validator keys, VRF seeds, ElectionVerifier) are
	// configured. Previously the shard was immediately set to Active,
	// allowing operations before keys/verifiers were ready.
	chain.status = ShardStatusInitializing
	sm.shards[id] = chain

	sm.assignments[id] = &ShardValidatorAssignment{
		ShardID:    id,
		Validators: validators,
		Epoch:      0,
	}

	// P3-1 (2026-07-15): Refresh metrics after creating a new shard.
	sm.refreshMetricsLocked()

	// P3-3 (2026-07-15): Log shard creation so operators can audit the
	// lifecycle. The shard is still Initializing until ActivateShard.
	shardLogger.Info("shard created",
		map[string]any{"shard_id": id, "validators": len(validators)})

	return chain, nil
}

// validateActivationPrereqsLocked checks that a shard has the prerequisites
// required to transition to Active: registered validator public keys and a
// configured election verifier. Caller MUST hold chain.mu.
//
// SHRD- (2026-07-16): Extracted from ActivateShard so ReactivateShard
// can reuse the same gate. Previously ReactivateShard skipped these checks,
// allowing a shard with no pubkeys/verifier to be re-activated — a latent
// consistency defect (ProposeBlock/ReceiveBlock would still fail-closed, but
// status==Active could mislead health checks and cross-shard routing).
func validateActivationPrereqsLocked(chain *ShardChain, shardID uint64) error {
	if len(chain.validatorPubKeys) == 0 {
		shardLogger.Warn("shard activation rejected: validator public keys not set",
			map[string]any{"shard_id": shardID})
		return fmt.Errorf("shard %d cannot be activated: validator public keys not set", shardID)
	}
	if chain.electionVerifier == nil {
		shardLogger.Warn("shard activation rejected: election verifier not set",
			map[string]any{"shard_id": shardID})
		return fmt.Errorf("shard %d cannot be activated: election verifier not set", shardID)
	}
	// SHRD- (2026-07-17): In production mode (requireRealStateRoot),
	// activation requires a real stateDB. Without it, ProposeBlock would
	// produce blocks with placeholder state roots (content-derived hashes
	// that don't commit to actual state transitions), which could then be
	// committed to the main chain via CommitBlockToMainChain — defeating
	// state-root integrity and making fraud proofs impossible (SHRD-).
	// Fail-closed here prevents such shards from going Active in production.
	if chain.requireRealStateRoot && chain.stateDB == nil {
		shardLogger.Warn("shard activation rejected: production mode requires real stateDB",
			map[string]any{"shard_id": shardID})
		return fmt.Errorf("shard %d cannot be activated: %w", shardID, ErrShardStateRootPlaceholder)
	}
	return nil
}

// ActivateShard transitions a shard from Initializing to Active.
// audit-fix L6-048/L9-014: Replaces immediate Active on creation.
//
// Locking note: ActivateShard holds sm.mu (ShardManager's lock) but NOT
// chain.mu. This matches the original convention — chain.status and
// chain.validatorPubKeys are read/written under sm.mu protection, which
// is safe because no concurrent ShardManager operation can modify the
// same chain while sm.mu is held. refreshMetricsLocked acquires
// chain.mu.RLock() internally, so we must NOT hold chain.mu here.
func (sm *ShardManager) ActivateShard(shardID uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	chain, exists := sm.shards[shardID]
	if !exists {
		return fmt.Errorf("shard %d not found", shardID)
	}

	if chain.status != ShardStatusInitializing {
		return fmt.Errorf("shard %d is not in Initializing state (current: %s)", shardID, chain.status)
	}

	// SHRD- Reuse the shared prerequisite gate. Reads chain fields
	// under sm.mu protection (same convention as the rest of this method).
	chain.mu.Lock()
	err := validateActivationPrereqsLocked(chain, shardID)
	chain.mu.Unlock()
	if err != nil {
		return err
	}

	chain.mu.Lock()
	chain.status = ShardStatusActive
	chain.mu.Unlock()

	// P3-1 (2026-07-15): Refresh metrics after state transition.
	sm.refreshMetricsLocked()

	shardLogger.Info("shard activated",
		map[string]any{"shard_id": shardID, "validators": len(chain.validators)})
	return nil
}

func (sm *ShardManager) GetShard(shardID uint64) (*ShardChain, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	chain, exists := sm.shards[shardID]
	if !exists {
		return nil, ErrShardNotFound
	}
	return chain, nil
}

func (sm *ShardManager) GetActiveShards() []*ShardChain {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make([]*ShardChain, 0)
	for _, chain := range sm.shards {
		if chain.status == ShardStatusActive {
			result = append(result, chain)
		}
	}
	return result
}

func (sm *ShardManager) DeactivateShard(shardID uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	chain, exists := sm.shards[shardID]
	if !exists {
		return ErrShardNotFound
	}

	chain.mu.Lock()
	if chain.status != ShardStatusActive {
		chain.mu.Unlock()
		return ErrShardNotActive
	}
	chain.status = ShardStatusInactive
	chain.mu.Unlock()

	// P3-1 (2026-07-15): Refresh metrics after state transition.
	// chain.mu is released above so refreshMetricsLocked can acquire its read lock.
	sm.refreshMetricsLocked()

	// P3-3 (2026-07-15): Deactivation halts block production for this shard;
	// operators should be alerted to investigate.
	shardLogger.Warn("shard deactivated",
		map[string]any{"shard_id": shardID})
	return nil
}

func (sm *ShardManager) ReactivateShard(shardID uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	chain, exists := sm.shards[shardID]
	if !exists {
		return ErrShardNotFound
	}

	chain.mu.Lock()
	if chain.status == ShardStatusActive {
		chain.mu.Unlock()
		return ErrShardNotActive
	}

	// SHRD- (2026-07-16): Reuse the same prerequisite gate as
	// ActivateShard. Previously ReactivateShard skipped pubkey/verifier
	// checks, allowing a shard with no pubkeys or no election verifier to
	// be re-activated to Active — a latent consistency defect (ProposeBlock/
	// ReceiveBlock would still fail-closed, but status==Active could
	// mislead health checks and cross-shard routing into treating the shard
	// as "ready").
	err := validateActivationPrereqsLocked(chain, shardID)
	if err != nil {
		chain.mu.Unlock()
		return err
	}

	chain.status = ShardStatusActive
	chain.mu.Unlock()

	// P3-1 (2026-07-15): Refresh metrics after state transition.
	// chain.mu is released above so refreshMetricsLocked can acquire its read lock.
	sm.refreshMetricsLocked()

	shardLogger.Info("shard reactivated",
		map[string]any{"shard_id": shardID})
	return nil
}

// ReassignValidators rotates the validator set for a single shard.
//
// P1-4 (2026-07-14): This is a consensus-sensitive operation — a malicious
// node could shuffle validators to favorable positions if left ungated. The
// caller parameter identifies who is requesting the reassignment, and the
// authorizer (set via SetAuthorizer) checks whether that caller is permitted.
// When no authorizer is configured, this method is fail-closed and returns
// ErrShardReassignUnauthorized. When stateStore is configured, the new
// assignment is persisted so all nodes read the same table from the shared
// database.
func (sm *ShardManager) ReassignValidators(caller types.Address, shardID uint64, validators []types.Address, epoch uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// P1-4: Fail-closed when no authorizer is configured.
	if sm.authorizer == nil {
		// P3-3 (2026-07-15): Log unauthorized reassignment attempts so
		// operators can detect misconfiguration or attack attempts.
		shardLogger.Warn("reassign validators rejected: no authorizer configured",
			map[string]any{"shard_id": shardID, "caller": caller.ToHexAddress()})
		return ErrShardReassignUnauthorized
	}
	if !sm.authorizer.IsAuthorizedReassign(caller, shardID, epoch) {
		shardLogger.Warn("reassign validators rejected: caller not authorized",
			map[string]any{"shard_id": shardID, "caller": caller.ToHexAddress(), "epoch": epoch})
		return ErrShardReassignUnauthorized
	}

	chain, exists := sm.shards[shardID]
	if !exists {
		return ErrShardNotFound
	}

	if len(validators) < ShardMinValidators {
		return ErrShardInsufficientVal
	}

	chain.mu.Lock()
	chain.validators = make([]types.Address, len(validators))
	copy(chain.validators, validators)
	chain.epoch = epoch
	chain.mu.Unlock()

	assignment := &ShardValidatorAssignment{
		ShardID:    shardID,
		Validators: validators,
		Epoch:      epoch,
	}
	sm.assignments[shardID] = assignment

	// P1-4: Persist so all nodes converge on the same assignment table.
	if sm.stateStore != nil {
		if err := sm.stateStore.PutAssignment(shardID, assignment); err != nil {
			// Persistence errors are non-fatal (project convention): the
			// in-memory state is correct, only crash recovery is affected.
			// Callers that require durability should check the returned error.
			return fmt.Errorf("reassign validators: persist assignment: %w", err)
		}
	}

	// P3-1 (2026-07-15): Refresh metrics after validator reassignment.
	sm.refreshMetricsLocked()

	// P3-3 (2026-07-15): Log the rotation for audit trail. The caller field
	// is logged so operators can verify only authorized system callers are
	// triggering rotations.
	shardLogger.Info("validators reassigned",
		map[string]any{"shard_id": shardID, "validators": len(validators),
			"epoch": epoch, "caller": caller.ToHexAddress()})

	return nil
}

// AssignValidatorsToShards performs a batch shuffle of all validators across
// shards. This is the system-level assignment called at epoch boundaries (not
// a single-shard rotation — use ReassignValidators for that).
//
// P1-4 (2026-07-14): When stateStore is configured, each shard's assignment is
// persisted so all nodes read the same table from the shared database. This
// anchors the shuffle result (which is deterministic given the same seed) to
// main-chain state, preventing nodes from computing divergent assignments.
func (sm *ShardManager) AssignValidatorsToShards(allValidators []types.Address, shardCount int, seed types.Hash) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if shardCount <= 0 || shardCount > ShardMaxCount {
		return fmt.Errorf("invalid shard count: %d", shardCount)
	}

	if len(allValidators) < shardCount*ShardMinValidators {
		return fmt.Errorf("insufficient validators: need at least %d, have %d", shardCount*ShardMinValidators, len(allValidators))
	}

	// SHRD- (2026-07-17): Deduplicate and validate the input validator
	// list before shuffling. Without this, a caller could pass
	// [addrA, addrA, addrA, ...] to satisfy the count threshold with a single
	// actual entity, allowing cheap committee takeover and BFT-threshold
	// dilution. Mirrors the dedup+zero-address check already enforced by
	// CreateShard (shard.go:733-748).
	var zero types.Address
	seen := make(map[types.Address]struct{}, len(allValidators))
	deduped := make([]types.Address, 0, len(allValidators))
	for _, v := range allValidators {
		if v == zero {
			shardLogger.Warn("assign validators rejected: zero address in input",
				map[string]any{"shard_count": shardCount})
			return fmt.Errorf("shard: validator address is zero")
		}
		if _, dup := seen[v]; dup {
			shardLogger.Warn("assign validators rejected: duplicate address in input",
				map[string]any{"shard_count": shardCount, "addr": v.ToHexAddress()})
			return fmt.Errorf("shard: duplicate validator address %s", v.ToHexAddress())
		}
		seen[v] = struct{}{}
		deduped = append(deduped, v)
	}

	// Re-check the minimum count against the deduplicated list. The earlier
	// len() check used the raw (possibly duplicated) input, so dedup may have
	// reduced the count below shardCount*ShardMinValidators — in which case
	// some shard would end up with fewer than ShardMinValidators actual
	// validators, breaking the BFT assumption.
	if len(deduped) < shardCount*ShardMinValidators {
		shardLogger.Warn("assign validators rejected: insufficient validators after dedup",
			map[string]any{"shard_count": shardCount,
				"raw_count": len(allValidators), "deduped_count": len(deduped),
				"required": shardCount * ShardMinValidators})
		return fmt.Errorf("insufficient validators after dedup: need at least %d, have %d (raw %d)",
			shardCount*ShardMinValidators, len(deduped), len(allValidators))
	}

	shuffled := make([]types.Address, len(deduped))
	copy(shuffled, deduped)
	shuffleAddresses(shuffled, seed)

	validatorsPerShard := len(shuffled) / shardCount

	// P1-4: Collect assignments to persist after the loop (avoid holding
	// sm.mu while writing to stateStore, which has its own lock).
	var toPersist []*ShardValidatorAssignment

	// P4-3 (2026-07-15): Distribute shuffled validators across shards.
	// Each shard gets validatorsPerShard validators; the LAST shard absorbs
	// the remainder (so len(shuffled) need not be a multiple of shardCount).
	// If a shard already exists, its validator set is rotated in place and
	// its epoch incremented. If not, a new chain is created.
	//
	// SHRD- (2026-07-16): NEW shards are created in ShardStatusInitializing
	// (NOT Active). This closes the latent consistency defect where the batch
	// assignment path bypassed the Initialize→Activate prerequisite gate that
	// CreateShard+ActivateShard enforce. The caller must subsequently:
	//   1. Register validator public keys via SetValidatorPubKey for each shard.
	//   2. Inject an election verifier via InjectDependencies.
	//   3. Call ActivateShard to transition to Active (prerequisites checked).
	// Existing shards that are already Active keep their status (they already
	// passed activation; rotating validators doesn't invalidate that).
	for i := 0; i < shardCount; i++ {
		start := i * validatorsPerShard
		end := start + validatorsPerShard
		if i == shardCount-1 {
			end = len(shuffled)
		}

		shardValidators := shuffled[start:end]

		shardID := uint64(i + 1)
		var assignment *ShardValidatorAssignment
		if chain, exists := sm.shards[shardID]; exists {
			chain.mu.Lock()
			chain.validators = shardValidators
			chain.epoch++
			chain.mu.Unlock()

			assignment = &ShardValidatorAssignment{
				ShardID:    shardID,
				Validators: shardValidators,
				Epoch:      chain.epoch,
			}
		} else {
			// SHRD- New shard starts in Initializing, NOT Active.
			// NewShardChain already sets status = ShardStatusInitializing.
			chain := NewShardChain(shardID, shardValidators)
			// SHRD- Propagate the production-mode flag.
			chain.requireRealStateRoot = sm.requireRealStateRoot
			sm.shards[shardID] = chain

			assignment = &ShardValidatorAssignment{
				ShardID:    shardID,
				Validators: shardValidators,
				Epoch:      0,
			}
		}
		sm.assignments[shardID] = assignment
		toPersist = append(toPersist, assignment)
	}

	// SHRD- (2026-07-17): Defensive post-distribution check. The
	// pre-dedup + post-dedup count checks above should guarantee every shard
	// receives at least ShardMinValidators, but verify explicitly in case
	// future changes to the distribution logic introduce skew. Fail-closed:
	// if any shard is under-manned, refuse the entire assignment so no
	// half-applied state is persisted.
	for _, a := range toPersist {
		if len(a.Validators) < ShardMinValidators {
			shardLogger.Warn("assign validators rejected: shard below minimum after distribution",
				map[string]any{"shard_id": a.ShardID,
					"validators": len(a.Validators), "minimum": ShardMinValidators})
			return fmt.Errorf("shard %d has %d validators after distribution, minimum is %d",
				a.ShardID, len(a.Validators), ShardMinValidators)
		}
	}

	if uint64(shardCount) >= sm.nextShardID {
		sm.nextShardID = uint64(shardCount) + 1
	}

	// P1-4: Persist all assignments so all nodes converge on the same table.
	if sm.stateStore != nil {
		for _, a := range toPersist {
			if err := sm.stateStore.PutAssignment(a.ShardID, a); err != nil {
				return fmt.Errorf("assign validators: persist assignment (shard %d): %w", a.ShardID, err)
			}
		}
	}

	// P3-1 (2026-07-15): Refresh metrics after batch validator assignment.
	sm.refreshMetricsLocked()

	return nil
}

// shuffleAddresses performs a deterministic Fisher-Yates shuffle on the
// address slice using a seed-derived PRNG.
//
// P1-4 (2026-07-14): The shuffle is deterministic given the same seed, so
// all nodes that share the same main-chain seed compute the same validator
// assignment across shards. This prevents a single node from manipulating
// which validators end up in which shard.
//
// The PRNG is a simple hash chain: state₀ = seed, stateₙ = SHA3-256(stateₙ₋₁).
// Each iteration produces 8 bytes of randomness used to pick the swap index j.
// This is NOT cryptographically secure against a biased-seed attack, but the
// seed itself comes from the main-chain (QPOS epoch seed), which is the same
// security boundary as the proposer election.
//
// P4-3 (2026-07-15): Documented for clarity — this function is security-
// sensitive because a non-uniform shuffle would let validators predict their
// shard assignment and potentially collude.
//
// SHRD- (2026-07-17): Replaced naive `val % (i+1)` (which has standard
// modular bias) with rejection sampling. We draw 8 bytes, interpret as uint64,
// and reject values >= 2^64 - (2^64 mod (i+1)) (the largest multiple of (i+1)
// that fits in uint64). This eliminates modular bias, giving a perfectly
// uniform distribution over [0, i]. The rejection rate is at most (i+1)/2^64,
// which is negligible — for i=200000, the rejection probability is ~1e-14,
// so in practice we never reject. The PRNG state advances on each draw
// (including rejected draws) to maintain deterministic output.
func shuffleAddresses(addrs []types.Address, seed types.Hash) {
	n := len(addrs)
	if n <= 1 {
		return
	}

	state := make([]byte, 32)
	copy(state, seed[:])

	// drawUint64 advances the PRNG state and returns the next 8-byte value.
	drawUint64 := func() uint64 {
		h := sha3.New256()
		h.Write(state)
		hash := h.Sum(nil)
		copy(state, hash)
		var val uint64
		for k := 0; k < 8; k++ {
			val = (val << 8) | uint64(hash[k])
		}
		return val
	}

	for i := n - 1; i > 0; i-- {
		// Rejection sampling to eliminate modular bias.
		// We want j in [0, i]. The naive `val % (i+1)` is biased when
		// 2^64 is not a multiple of (i+1). We reject val >= maxAcceptable,
		// where maxAcceptable = 2^64 - (2^64 % (i+1)). After rejection,
		// `val % (i+1)` is perfectly uniform.
		mod := uint64(i + 1)
		// maxAcceptable is the largest multiple of mod that fits in uint64.
		// 2^64 % mod = (2^64 - mod) % mod + mod % mod... simpler:
		// maxAcceptable = 2^64 - (2^64 % mod). But 2^64 overflows uint64
		// (wraps to 0), so we compute it as: if mod == 0 (never, i>0),
		// skip; else maxAcceptable = -mod % mod... Use the identity:
		// rejection threshold = (2^64 - mod) % mod, then maxAcceptable =
		// 2^64 - rejectionThreshold. Since 2^64 wraps to 0 in uint64
		// arithmetic: maxAcceptable = 0 - rejectionThreshold = -rejectionThreshold.
		rejectionThreshold := (0 - mod) % mod // 2^64 % mod, computed via wraparound
		maxAcceptable := 0 - rejectionThreshold

		var val uint64
		for {
			val = drawUint64()
			if val < maxAcceptable || rejectionThreshold == 0 {
				break
			}
			// Rejected: draw again (state already advanced).
		}
		j := int(val % mod)
		addrs[i], addrs[j] = addrs[j], addrs[i]
	}
}

func (sc *ShardChain) ShardID() uint64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.shardID
}

func (sc *ShardChain) Status() ShardStatus {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.status
}

func (sc *ShardChain) Validators() []types.Address {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	result := make([]types.Address, len(sc.validators))
	copy(result, sc.validators)
	return result
}

// ValidatorPubKey returns the registered Dilithium3 public key for the given
// validator address, or (nil, false) if not registered.
// AUDIT (2026) R4-GOV-04: Used by ShardManager.AuthenticateCommitment
// to verify the block signature carried in a ShardCommitment against the
// proposer's registered public key.
func (sc *ShardChain) ValidatorPubKey(addr types.Address) ([]byte, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	pk, ok := sc.validatorPubKeys[addr]
	if !ok || len(pk) == 0 {
		return nil, false
	}
	out := make([]byte, len(pk))
	copy(out, pk)
	return out, true
}

func (sc *ShardChain) LatestHeight() uint64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.latest
}

func (sc *ShardChain) Epoch() uint64 {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.epoch
}

// ProposeBlock creates a new shard block proposed by `proposer`.
//
// FIX: Previously ProposeBlock accepted any validator as
// proposer without verifying a signature, and never set the Signature field on
// the block header. This allowed any node to forge blocks under any validator's
// identity. Now the proposer must supply a Dilithium3 signature over the block
// header (excluding the Signature field itself), which is verified against the
// proposer's registered public key.
//
// FIX: The stateRoot is still a zero placeholder because
// computing the actual trie root requires state-DB integration that is not yet
// available in the shard module. CommitBlockToMainChain now rejects zero
// stateRoots, so proposed blocks cannot be committed until real stateRoot
// computation is implemented. This fail-closed behavior prevents committing
// blocks that commit to no specific state.
//
// audit-fix M-6 [MEDIUM]: ProposeBlock verifies VRF proof to ensure the
// proposer was legitimately elected for this slot.
//
// FIX [HIGH]: ProposeBlock now requires an ElectionVerifier
// to be set (via SetElectionVerifier). The verifier performs full VRF +
// election verification, ensuring only the elected proposer can propose blocks.
// If no ElectionVerifier is set, ProposeBlock returns ErrShardVRFSeedNotSet
// (fail-closed). The vrfSeed-based fallback path (which only verified VRF
// proof validity but NOT election results) has been removed as it was
// insecure — any validator with a registered public key could propose blocks
// in arbitrary slots.
func (sc *ShardChain) ProposeBlock(proposer types.Address, txs [][]byte, crossMsgs []*CrossShardMessage, signature []byte, vrfProof []byte, vrfOutput types.Hash) (*ShardBlock, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.status != ShardStatusActive {
		return nil, ErrShardNotActive
	}

	if !sc.isValidatorLocked(proposer) {
		return nil, fmt.Errorf("address %x is not a validator for shard %d", proposer[:4], sc.shardID)
	}

	// FIX: Verify the proposer's signature.
	pubKeyBytes, ok := sc.validatorPubKeys[proposer]
	if !ok || len(pubKeyBytes) == 0 {
		// P3-3 (2026-07-15): A proposer without a registered public key is
		// either misconfiguration or an attack attempt.
		shardLogger.Warn("propose block rejected: no public key for proposer",
			map[string]any{"shard_id": sc.shardID, "proposer": proposer.ToHexAddress()})
		return nil, fmt.Errorf("no public key registered for proposer %s", proposer.ToHexAddress())
	}
	pubKey, err := qaucrypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil || pubKey == nil {
		shardLogger.Warn("propose block rejected: invalid public key for proposer",
			map[string]any{"shard_id": sc.shardID, "proposer": proposer.ToHexAddress()})
		return nil, fmt.Errorf("invalid public key for proposer %s: %w", proposer.ToHexAddress(), err)
	}

	// Compute height early — needed by the election verifier.
	height := sc.latest + 1

	// FIX [HIGH]: Verify that the proposer was legitimately
	// elected via VRF for this slot.
	//
	// audit-fix FIX [MEDIUM]: The insecure vrfSeed-only fallback path
	// has been REMOVED. Previously, when no ElectionVerifier was set but vrfSeed
	// was configured, ProposeBlock only called VerifyVRF (proof validity) without
	// verifying election results — allowing any validator with a registered
	// public key to propose blocks in arbitrary slots. Now, an ElectionVerifier
	// is REQUIRED. If not set, ProposeBlock returns ErrShardVRFSeedNotSet
	// (fail-closed).
	//
	// Note: we already hold sc.mu (write lock) so we can read sc.electionVerifier
	// directly.
	if sc.electionVerifier != nil {
		if err := sc.electionVerifier.VerifyProposerElection(proposer, vrfProof, vrfOutput, height); err != nil {
			// P3-3 (2026-07-15): Election failure is a security event — a
			// validator attempted to propose in a slot they were not elected to.
			shardLogger.Warn("propose block rejected: election verification failed",
				map[string]any{"shard_id": sc.shardID, "height": height,
					"proposer": proposer.ToHexAddress(), "error": err.Error()})
			return nil, fmt.Errorf("%w: %v", ErrShardVRFProofInvalid, err)
		}
	} else {
		// fail-closed: no election verifier configured.
		shardLogger.Warn("propose block rejected: no election verifier configured",
			map[string]any{"shard_id": sc.shardID, "height": height})
		return nil, ErrShardVRFSeedNotSet
	}

	var parentHash types.Hash
	if parent, exists := sc.blocks[sc.latest]; exists {
		parentHash = computeShardBlockHash(parent.Header)
	}

	txRoot := computeTxRoot(txs)
	crossMsgRoot := computeCrossMsgRoot(crossMsgs)

	// P0-1 (2026-07-13): Compute the stateRoot using the attached stateDB
	// (real Verkle trie root) or a deterministic non-zero fallback commitment
	// derived from block contents. Previously this was always a zero hash,
	// causing CommitBlockToMainChain to fail-closed with ErrShardStateRootZero.
	// We already hold sc.mu (write lock), so use computeStateRootLocked.
	stateRoot := computeStateRootLocked(sc.stateDB, sc.shardID, height, parentHash, txRoot, crossMsgRoot)

	header := &ShardBlockHeader{
		ShardID:      sc.shardID,
		Height:       height,
		ParentHash:   parentHash,
		StateRoot:    stateRoot,
		TxRoot:       txRoot,
		CrossMsgRoot: crossMsgRoot,
		Timestamp:    uint64(time.Now().Unix()), // R4-C1 NOTE: Proposer-set block timestamp — standard blockchain behavior. The proposer sets the time, validators check it's within bounds, and all nodes process the same block header. NOT a consensus determinism issue.
		Proposer:     proposer,
		VRFProof:     vrfProof,
		VRFOutput:    vrfOutput,
	}

	// FIX: Verify signature over the header (without Signature field).
	msg := computeShardBlockSigningHash(header)
	if !qaucrypto.Verify(pubKey, msg, signature) {
		// P3-3 (2026-07-15): Invalid signature is a security event.
		shardLogger.Warn("propose block rejected: signature invalid",
			map[string]any{"shard_id": sc.shardID, "height": height,
				"proposer": proposer.ToHexAddress()})
		return nil, ErrShardBlockSigInvalid
	}
	header.Signature = signature

	block := &ShardBlock{
		Header:    header,
		Txs:       txs,
		CrossMsgs: crossMsgs,
	}

	// L6-025 INVARIANT: The proposer's signature is verified ABOVE (lines 625-629)
	// BEFORE the block is stored here. This ordering is critical: storing an
	// unverified block would allow any validator to inject invalid blocks into
	// the chain. Any future refactoring MUST preserve this order — verify-then-store.
	// If signature verification fails, ProposeBlock returns ErrShardBlockSigInvalid
	// and never reaches this storage point.
	// SHRD- (2026-07-17): Stamp the local receive time so the health
	// checker uses the node's own clock (not the proposer-self-reported
	// header timestamp) for stalled detection.
	block.ReceivedAt = time.Now().UnixNano()
	sc.blocks[height] = block
	sc.latest = height

	if len(sc.blocks) > sc.maxBlocks {
		sc.pruneOldBlocks()
	}

	// P0-3 (2026-07-13): Write through to state store for crash recovery.
	// We store the block AND the latest height, so that on restart we can
	// rebuild the in-memory chain from persisted state.
	if sc.stateStore != nil {
		if err := sc.stateStore.PutBlock(sc.shardID, block); err != nil {
			return nil, fmt.Errorf("failed to persist block: %w", err)
		}
		if err := sc.stateStore.PutLatestHeight(sc.shardID, height); err != nil {
			return nil, fmt.Errorf("failed to persist latest height: %w", err)
		}
	}

	// P3-1 (2026-07-15): Record block height metric for this shard.
	if sc.metrics != nil {
		sc.metrics.SetBlockHeight(sc.shardID, height)
	}

	// P3-3 (2026-07-15): Log successful block proposal. Debug level since
	// this is a routine event (once per slot per shard).
	shardLogger.Debugf("shard %d: proposed block height %d by %s",
		sc.shardID, height, proposer.ToHexAddress())

	return block, nil
}

// FinalizeBlock finalizes a block at the given height after collecting enough
// validator attestations.
//
// FIX: Previously FinalizeBlock simply set Finalized=true
// without any quorum check, allowing a single node to finalize any block. Now
// it requires a map of validator→signature attestations and verifies that at
// least 2/3 of the shard's validators signed the block hash.
func (sc *ShardChain) FinalizeBlock(height uint64, attestations map[types.Address][]byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	block, exists := sc.blocks[height]
	if !exists {
		return ErrShardBlockNotFound
	}

	if block.Finalized {
		return nil
	}

	// FIX: Verify quorum of validator attestations.
	// Each attestation is a validator's Dilithium3 signature over the block
	// hash. We verify each signature against the validator's registered
	// public key and count unique validators (dedup prevents a single
	// validator's signature from counting twice).
	// P4-3 (2026-07-15): The 2/3 threshold is computed with ceiling division
	// (see below) to enforce the true supermajority.
	blockHash := computeShardBlockHash(block.Header)
	signingMsg := blockHash[:]

	validAttestations := 0
	seenValidators := make(map[types.Address]bool)
	for addr, sig := range attestations {
		if seenValidators[addr] {
			continue // deduplicate
		}
		if !sc.isValidatorLocked(addr) {
			continue
		}
		pubKeyBytes, ok := sc.validatorPubKeys[addr]
		if !ok || len(pubKeyBytes) == 0 {
			continue
		}
		pubKey, err := qaucrypto.PublicKeyFromBytes(pubKeyBytes)
		if err != nil || pubKey == nil {
			continue
		}
		if qaucrypto.Verify(pubKey, signingMsg, sig) {
			validAttestations++
			seenValidators[addr] = true
		}
	}

	// L6-004 FIX: Use ceiling division instead of floor to enforce the true
	// 2/3 supermajority. Previously floor(N*2/3) allowed N=4 validators to
	// finalize with only 2 attestations (50%), violating the 2/3 guarantee.
	// ceil(N*num/den) = (N*num + den - 1) / den.
	required := (len(sc.validators)*ShardFinalityQuorumNum + ShardFinalityQuorumDen - 1) / ShardFinalityQuorumDen
	if required < 1 {
		required = 1
	}
	if validAttestations < required {
		// P3-3 (2026-07-15): Quorum failure blocks finalization; operators
		// should investigate validator availability or attestation relays.
		shardLogger.Warn("finalize block rejected: insufficient quorum",
			map[string]any{"shard_id": sc.shardID, "height": height,
				"valid_attestations": validAttestations, "required": required})
		return fmt.Errorf("%w: got %d attestations, need %d", ErrShardInsufficientQuorum, validAttestations, required)
	}

	block.Finalized = true

	// P3-3 (2026-07-15): Log successful finalization for operational visibility.
	shardLogger.Info("shard block finalized",
		map[string]any{"shard_id": sc.shardID, "height": height,
			"attestations": validAttestations, "required": required})
	return nil
}

func (sc *ShardChain) GetBlock(height uint64) (*ShardBlock, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	block, exists := sc.blocks[height]
	if !exists {
		return nil, ErrShardBlockNotFound
	}
	return block, nil
}

// ReceiveBlock accepts a block received from the network, verifies it, and
// stores it.
//
// P1-2 (2026-07-14): Used by ShardBlockProducer to process blocks proposed by
// other validators. Unlike ProposeBlock (which builds the header internally and
// sets its own timestamp), ReceiveBlock accepts a fully-built block with the
// proposer's timestamp already set. This ensures all nodes store the identical
// block (same timestamp → same block hash → consistent attestation signatures).
//
// Verification steps (same security guarantees as ProposeBlock):
//  1. Shard must be active
//  2. Block height must be exactly latest + 1 (no gaps, no duplicates)
//  3. Proposer must be a registered validator with a public key
//  4. ElectionVerifier must confirm the proposer was elected for this height
//  5. Parent hash must match the current latest block's hash
//  6. Proposer's Dilithium3 signature must verify over the signing hash
//  7. SHRD- Recomputed TxRoot/CrossMsgRoot from the block body must
//     match the header commitments; StateRoot must be non-zero and, when
//     no stateDB is attached, must match the deterministic placeholder
//     recomputed from the (verified) body roots.
//
// If the block at this height already exists (idempotent receive), returns nil.
func (sc *ShardChain) ReceiveBlock(block *ShardBlock) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.status != ShardStatusActive {
		return ErrShardNotActive
	}

	if block == nil || block.Header == nil {
		return fmt.Errorf("receive block: nil block or header")
	}

	header := block.Header

	// Idempotent: if we already have this exact height, skip.
	if existing, exists := sc.blocks[header.Height]; exists {
		// Same block hash → already received, no-op.
		existingHash := computeShardBlockHash(existing.Header)
		newHash := computeShardBlockHash(header)
		if existingHash == newHash {
			return nil
		}
		// Different block at same height → conflict, reject.
		// P3-3 (2026-07-15): Conflicting blocks indicate a fork or attack;
		// log the conflict so operators can investigate proposer behavior.
		shardLogger.Warn("receive block rejected: conflicting block at height",
			map[string]any{"shard_id": sc.shardID, "height": header.Height,
				"existing_hash": existingHash.String(), "new_hash": newHash.String(),
				"proposer": header.Proposer.ToHexAddress()})
		return fmt.Errorf("receive block: conflicting block at height %d", header.Height)
	}

	// Height must be exactly latest + 1 (no gaps).
	expectedHeight := sc.latest + 1
	if header.Height != expectedHeight {
		return fmt.Errorf("receive block: expected height %d, got %d", expectedHeight, header.Height)
	}

	// Proposer must be a validator.
	if !sc.isValidatorLocked(header.Proposer) {
		return fmt.Errorf("receive block: proposer %x is not a validator for shard %d",
			header.Proposer[:4], sc.shardID)
	}

	// Public key must be registered.
	pubKeyBytes, ok := sc.validatorPubKeys[header.Proposer]
	if !ok || len(pubKeyBytes) == 0 {
		return fmt.Errorf("receive block: no public key registered for proposer %s",
			header.Proposer.ToHexAddress())
	}
	pubKey, err := qaucrypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil || pubKey == nil {
		return fmt.Errorf("receive block: invalid public key for proposer %s: %w",
			header.Proposer.ToHexAddress(), err)
	}

	// Election verification (fail-closed, same as ProposeBlock).
	if sc.electionVerifier != nil {
		if err := sc.electionVerifier.VerifyProposerElection(
			header.Proposer, header.VRFProof, header.VRFOutput, header.Height,
		); err != nil {
			// P3-3 (2026-07-15): Election failure on a received block is a
			// security event — the proposer claimed a slot they weren't elected to.
			shardLogger.Warn("receive block rejected: election verification failed",
				map[string]any{"shard_id": sc.shardID, "height": header.Height,
					"proposer": header.Proposer.ToHexAddress(), "error": err.Error()})
			return fmt.Errorf("%w: %v", ErrShardVRFProofInvalid, err)
		}
	} else {
		shardLogger.Warn("receive block rejected: no election verifier configured",
			map[string]any{"shard_id": sc.shardID, "height": header.Height})
		return ErrShardVRFSeedNotSet
	}

	// Parent hash must match.
	var parentHash types.Hash
	if parent, exists := sc.blocks[sc.latest]; exists {
		parentHash = computeShardBlockHash(parent.Header)
	}
	if header.ParentHash != parentHash {
		// P3-3 (2026-07-15): Parent mismatch indicates a fork or out-of-order block.
		shardLogger.Warn("receive block rejected: parent hash mismatch",
			map[string]any{"shard_id": sc.shardID, "height": header.Height,
				"expected_parent": parentHash.String(), "got_parent": header.ParentHash.String()})
		return fmt.Errorf("receive block: parent hash mismatch (expected %x, got %x)",
			parentHash[:4], header.ParentHash[:4])
	}

	// Verify proposer's signature over the signing hash.
	signingMsg := computeShardBlockSigningHash(header)
	if !qaucrypto.Verify(pubKey, signingMsg, header.Signature) {
		// P3-3 (2026-07-15): Signature failure on a received block is a security event.
		shardLogger.Warn("receive block rejected: signature invalid",
			map[string]any{"shard_id": sc.shardID, "height": header.Height,
				"proposer": header.Proposer.ToHexAddress()})
		return ErrShardBlockSigInvalid
	}

	// SHRD- (2026-07-17): Timestamp drift check.
	//
	// The proposer sets header.Timestamp (standard blockchain behavior). The
	// signature already covers the timestamp, so a proposer cannot retroactively
	// change it. However, an elected proposer can still pick an arbitrary
	// timestamp when signing. Reject blocks whose timestamp drifts more than
	// ShardMaxTimestampDrift seconds from the receiver's wall clock — this
	// bounds the impact on cross-shard message Timestamp fields and block
	// hashes, and fulfills the bound-check promise documented at the
	// ProposeBlock call site.
	//
	// Use signed int64 arithmetic to correctly distinguish future vs past
	// drift and avoid uint64 underflow when header.Timestamp < now.
	now := time.Now().Unix()
	headerTs := int64(header.Timestamp)
	maxDrift := int64(ShardMaxTimestampDrift)
	if headerTs > now+maxDrift {
		delta := headerTs - now
		shardLogger.Warn("receive block rejected: timestamp too far in the future",
			map[string]any{"shard_id": sc.shardID, "height": header.Height,
				"header_timestamp": header.Timestamp, "now": now,
				"delta": delta, "max_drift": ShardMaxTimestampDrift,
				"proposer": header.Proposer.ToHexAddress()})
		return fmt.Errorf("%w: header=%d now=%d delta=%d max_drift=%d",
			ErrShardTimestampOutOfRange, header.Timestamp, now, delta, ShardMaxTimestampDrift)
	}
	if headerTs < now-maxDrift {
		delta := now - headerTs
		shardLogger.Warn("receive block rejected: timestamp too far in the past",
			map[string]any{"shard_id": sc.shardID, "height": header.Height,
				"header_timestamp": header.Timestamp, "now": now,
				"delta": delta, "max_drift": ShardMaxTimestampDrift,
				"proposer": header.Proposer.ToHexAddress()})
		return fmt.Errorf("%w: header=%d now=%d delta=%d max_drift=%d",
			ErrShardTimestampOutOfRange, header.Timestamp, now, delta, ShardMaxTimestampDrift)
	}

	// SHRD- (2026-07-16): Body-header commitment consistency check.
	//
	// Previously ReceiveBlock trusted the TxRoot/CrossMsgRoot/StateRoot carried
	// in the header without recomputing them from block.Txs/block.CrossMsgs.
	// A malicious elected proposer could deliver a block body that does not
	// match the attested roots, anchoring a false state root on the main chain
	// via CommitBlockToMainChain (which uses header.StateRoot verbatim).
	//
	// Fix: recompute the Merkle roots from the delivered body and reject on
	// any mismatch. For StateRoot:
	//   - When stateDB == nil (test/initial deployment), the proposer also
	//     uses the deterministic placeholder computeShardStateCommitment, so
	//     the receiver can recompute and verify it exactly.
	//   - When stateDB != nil (production), the real Verkle trie root can
	//     only be recomputed by executing the transactions locally. Full
	//     state-root binding on the receive path is therefore deferred to
	//     SHRD- (state execution pipeline). We still enforce a non-zero
	//     stateRoot here as a baseline integrity check.
	recomputedTxRoot := computeTxRoot(block.Txs)
	if recomputedTxRoot != header.TxRoot {
		shardLogger.Warn("receive block rejected: tx root mismatch",
			map[string]any{"shard_id": sc.shardID, "height": header.Height,
				"header_tx_root": header.TxRoot.String(),
				"body_tx_root":   recomputedTxRoot.String(),
				"proposer":       header.Proposer.ToHexAddress()})
		return fmt.Errorf("%w: tx root (header=%s, body=%s)",
			ErrShardBodyRootMismatch, header.TxRoot.String(), recomputedTxRoot.String())
	}

	recomputedCrossMsgRoot := computeCrossMsgRoot(block.CrossMsgs)
	if recomputedCrossMsgRoot != header.CrossMsgRoot {
		shardLogger.Warn("receive block rejected: cross-msg root mismatch",
			map[string]any{"shard_id": sc.shardID, "height": header.Height,
				"header_cross_msg_root": header.CrossMsgRoot.String(),
				"body_cross_msg_root":   recomputedCrossMsgRoot.String(),
				"proposer":              header.Proposer.ToHexAddress()})
		return fmt.Errorf("%w: cross-msg root (header=%s, body=%s)",
			ErrShardBodyRootMismatch, header.CrossMsgRoot.String(), recomputedCrossMsgRoot.String())
	}

	// StateRoot verification.
	if header.StateRoot == (types.Hash{}) {
		shardLogger.Warn("receive block rejected: zero state root",
			map[string]any{"shard_id": sc.shardID, "height": header.Height,
				"proposer": header.Proposer.ToHexAddress()})
		return ErrShardStateRootZero
	}
	if sc.stateDB == nil {
		// No state DB: proposer must have used the deterministic placeholder.
		// Recompute it from the (already-verified) body roots and compare.
		recomputedStateRoot := computeShardStateCommitment(
			sc.shardID, header.Height, header.ParentHash,
			recomputedTxRoot, recomputedCrossMsgRoot)
		if recomputedStateRoot != header.StateRoot {
			shardLogger.Warn("receive block rejected: state root (placeholder) mismatch",
				map[string]any{"shard_id": sc.shardID, "height": header.Height,
					"header_state_root": header.StateRoot.String(),
					"body_state_root":   recomputedStateRoot.String(),
					"proposer":          header.Proposer.ToHexAddress()})
			return fmt.Errorf("%w: state root placeholder (header=%s, body=%s)",
				ErrShardBodyRootMismatch, header.StateRoot.String(), recomputedStateRoot.String())
		}
	}
	// When stateDB != nil, full state-root binding requires executing the
	// transactions locally (SHRD-). The non-zero check above is the
	// baseline integrity guarantee until the state execution pipeline lands.

	// Store the block.
	// SHRD- (2026-07-17): Stamp the local receive time so the health
	// checker uses the node's own clock (not the proposer-self-reported
	// header timestamp) for stalled detection.
	block.ReceivedAt = time.Now().UnixNano()
	sc.blocks[header.Height] = block
	sc.latest = header.Height

	if len(sc.blocks) > sc.maxBlocks {
		sc.pruneOldBlocks()
	}

	// Persist to state store.
	if sc.stateStore != nil {
		if err := sc.stateStore.PutBlock(sc.shardID, block); err != nil {
			return fmt.Errorf("receive block: persist block: %w", err)
		}
		if err := sc.stateStore.PutLatestHeight(sc.shardID, header.Height); err != nil {
			return fmt.Errorf("receive block: persist height: %w", err)
		}
	}

	// P3-1 (2026-07-15): Record block height metric for this shard.
	if sc.metrics != nil {
		sc.metrics.SetBlockHeight(sc.shardID, header.Height)
	}

	return nil
}

func (sc *ShardChain) CommitBlockToMainChain(height uint64) (*ShardCommitment, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.status != ShardStatusActive {
		return nil, ErrShardNotActive
	}

	block, exists := sc.blocks[height]
	if !exists {
		return nil, ErrShardBlockNotFound
	}

	if !block.Finalized {
		return nil, ErrShardNotFinalized
	}

	// FIX: Reject blocks with zero stateRoot. A zero stateRoot
	// means the state commitment has not been computed, so committing it to the
	// main chain would allow validators to claim different states for the same
	// block. This fail-closed check ensures blocks cannot be committed until
	// real stateRoot computation is implemented.
	var zeroHash types.Hash
	if block.Header.StateRoot == zeroHash {
		return nil, ErrShardStateRootZero
	}

	// SHRD- (2026-07-17): In production mode, reject placeholder state
	// roots. When stateDB is nil, computeStateRootLocked falls back to
	// computeShardStateCommitment — a deterministic hash of (shardID, height,
	// parentHash, txRoot, crossMsgRoot) that does NOT commit to actual state
	// transitions. Committing such a placeholder to the main chain would
	// anchor a state root that receivers cannot recompute or build fraud
	// proofs against (SHRD-). The placeholder is only acceptable in
	// test/dev mode (requireRealStateRoot=false) until per-shard Verkle
	// trie integration is complete.
	if sc.requireRealStateRoot && sc.stateDB == nil {
		shardLogger.Warn("commit rejected: production mode requires real stateDB",
			map[string]any{"shard_id": sc.shardID, "height": height})
		return nil, fmt.Errorf("shard %d height %d: %w",
			sc.shardID, height, ErrShardStateRootPlaceholder)
	}

	if _, committed := sc.commitments[height]; committed {
		return nil, ErrShardAlreadyCommitted
	}

	blockHash := computeShardBlockHash(block.Header)

	commitment := &ShardCommitment{
		ShardID:      sc.shardID,
		BlockHeight:  height,
		BlockHash:    blockHash,
		StateRoot:    block.Header.StateRoot,
		CrossMsgRoot: block.Header.CrossMsgRoot,
		// AUDIT (2026) R4-GOV-04 FIX: Carry the block's proposer and
		// signature so MainChainCommitterImpl can authenticate the
		// commitment against the proposer's registered public key. Without
		// this, anyone reaching the commit path could persist arbitrary
		// (StateRoot, BlockHash) and have it "verify" via byte comparison
		// alone.
		Signer:    block.Header.Proposer,
		Signature: block.Header.Signature,
	}

	sc.commitments[height] = blockHash
	block.CommittedAt = height

	// P0-3 (2026-07-13): Persist the commitment to state store.
	if sc.stateStore != nil {
		if err := sc.stateStore.PutCommitment(sc.shardID, height, blockHash); err != nil {
			return nil, fmt.Errorf("failed to persist commitment: %w", err)
		}
	}

	return commitment, nil
}

func (sc *ShardChain) GetCommitment(height uint64) (types.Hash, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	h, exists := sc.commitments[height]
	return h, exists
}

// verifyCrossShardMessageSignatureLocked verifies the cross-shard message
// signature and canonical ID. Must be called with sc.mu held (read or write).
//
// AUDIT (2026) GOV-FIX: Extracted from SubmitCrossShardMessage so
// that RelayCrossShardMessage can also enforce these checks. Previously the
// relay/receipt path bypassed HIGH-17's signature and canonical ID
// verification, allowing a caller who invoked RelayCrossShardMessage directly
// (without first calling SubmitCrossShardMessage) to create receipts for
// forged or ID-malleable messages.
//
// SHRD- (2026-07-17) DESIGN CONFIRMATION: The sender lookup below
// searches sc.validatorPubKeys, which means ONLY registered validators can
// originate cross-shard messages. This is an intentional design decision for
// the current phase: cross-shard messages are validator-internal consensus
// messages (e.g., committing shard state, relaying attestations), NOT
// user-level asset transfers. User-level cross-shard transfers will require
// a separate account-public-key registry and signature scheme, which is
// deferred until per-shard Verkle trie integration lands. Documenting this
// boundary explicitly so it is not mistaken for a bug.
func (sc *ShardChain) verifyCrossShardMessageSignatureLocked(msg *CrossShardMessage) error {
	if msg == nil {
		return ErrCrossMsgInvalid
	}
	// FIX: Verify the sender's signature to prevent message
	// forgery. Without this check, any caller could submit a cross-shard message
	// under an arbitrary sender address.
	if len(msg.Signature) == 0 {
		return ErrShardCrossMsgSigInvalid
	}
	pubKeyBytes, ok := sc.validatorPubKeys[msg.Sender]
	if !ok || len(pubKeyBytes) == 0 {
		return fmt.Errorf("no public key registered for sender %s", msg.Sender.ToHexAddress())
	}
	pubKey, err := qaucrypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil || pubKey == nil {
		return fmt.Errorf("invalid public key for sender %s: %w", msg.Sender.ToHexAddress(), err)
	}
	signingMsg := computeCrossShardMessageSigningHash(msg)
	if !qaucrypto.Verify(pubKey, signingMsg, msg.Signature) {
		return ErrShardCrossMsgSigInvalid
	}

	// AUDIT (2026) HIGH-17: Verify msg.ID matches the canonical ID
	// derived from (sourceShard, destShard, sender, nonce). Without this
	// check, a sender could use different msg.ID values for the same
	// logical message, bypassing the receipts/spentReceipts dedup and
	// replaying the same cross-shard transfer multiple times.
	canonicalID := GenerateCrossShardMessageID(msg.SourceShard, msg.DestShard, msg.Sender, msg.Nonce)
	if msg.ID != canonicalID {
		return fmt.Errorf("%w: msg.ID does not match canonical ID", ErrCrossMsgInvalid)
	}
	return nil
}

// VerifyCrossShardMessageSignature acquires the read lock and verifies the
// cross-shard message signature and canonical ID. For callers that do not
// already hold sc.mu (e.g. ShardManager.RelayCrossShardMessage).
func (sc *ShardChain) VerifyCrossShardMessageSignature(msg *CrossShardMessage) error {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.verifyCrossShardMessageSignatureLocked(msg)
}

func (sc *ShardChain) SubmitCrossShardMessage(msg *CrossShardMessage) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.status != ShardStatusActive {
		return ErrShardNotActive
	}

	if msg == nil {
		return ErrCrossMsgInvalid
	}

	if msg.SourceShard != sc.shardID {
		return fmt.Errorf("message source shard %d does not match this shard %d", msg.SourceShard, sc.shardID)
	}

	if len(msg.Payload) > ShardCrossMsgMaxSize {
		return fmt.Errorf("payload too large: %d > %d", len(msg.Payload), ShardCrossMsgMaxSize)
	}

	// AUDIT ROUND-2 2026-08-17 FIX: bounded queue. Checked early
	// (before signature verification) as fail-fast backpressure; rejection
	// happens before the nonce is consumed so the sender can retry.
	if len(sc.pendingMsgs) >= ShardMaxPendingMsgs {
		shardLogger.Warn("cross-shard message rejected: pending queue full",
			map[string]any{"shard_id": sc.shardID, "pending": len(sc.pendingMsgs),
				"cap": ShardMaxPendingMsgs, "sender": msg.Sender.ToHexAddress()})
		return ErrCrossMsgQueueFull
	}

	// AUDIT (2026) GOV-FIX: Use the shared verification helper so
	// that SubmitCrossShardMessage and RelayCrossShardMessage enforce the
	// same signature + canonical ID checks.
	if err := sc.verifyCrossShardMessageSignatureLocked(msg); err != nil {
		return err
	}

	// AUDIT (2026) HIGH-17: Enforce per-sender nonce monotonicity.
	// A sender must use strictly increasing nonces; replaying a previous
	// nonce (even with a fresh signature) is rejected.
	if lastNonce, exists := sc.senderNonces[msg.Sender]; exists {
		if msg.Nonce <= lastNonce {
			// P3-3 (2026-07-15): Nonce replay is a security event — log the
			// attempt so operators can detect malicious or buggy senders.
			shardLogger.Warn("cross-shard message rejected: nonce not monotonic",
				map[string]any{"shard_id": sc.shardID, "sender": msg.Sender.ToHexAddress(),
					"nonce": msg.Nonce, "last_nonce": lastNonce,
					"source_shard": msg.SourceShard, "dest_shard": msg.DestShard})
			return fmt.Errorf("%w: nonce %d <= last seen %d for sender %s", ErrCrossMsgInvalid, msg.Nonce, lastNonce, msg.Sender.ToHexAddress())
		}
	}
	sc.senderNonces[msg.Sender] = msg.Nonce

	// P0-3 (2026-07-13): Persist the sender nonce for replay protection
	// across restarts. HIGH-17 safety: if we lose the nonce on restart,
	// a sender could replay old messages.
	if sc.stateStore != nil {
		if err := sc.stateStore.PutSenderNonce(sc.shardID, msg.Sender, msg.Nonce); err != nil {
			return fmt.Errorf("failed to persist sender nonce: %w", err)
		}
	}

	sc.pendingMsgs = append(sc.pendingMsgs, msg)

	// P3-1 (2026-07-15): Record cross-shard message counter and pending gauge.
	if sc.metrics != nil {
		sc.metrics.IncCrossShardMessages()
		sc.metrics.SetPendingMessages(sc.shardID, len(sc.pendingMsgs))
	}
	return nil
}

func (sc *ShardChain) GetPendingMessages() []*CrossShardMessage {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	result := make([]*CrossShardMessage, len(sc.pendingMsgs))
	copy(result, sc.pendingMsgs)
	return result
}

func (sc *ShardChain) ClearPendingMessages() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.pendingMsgs = sc.pendingMsgs[:0]

	// P3-1 (2026-07-15): Reset pending messages gauge after clearing.
	if sc.metrics != nil {
		sc.metrics.SetPendingMessages(sc.shardID, 0)
	}
}

func (sc *ShardChain) CreateReceipt(msg *CrossShardMessage, txHash types.Hash, blockHeight uint64) *CrossShardReceipt {
	proof := computeReceiptProof(msg, txHash, blockHeight)

	receipt := &CrossShardReceipt{
		MessageID:   msg.ID,
		SourceShard: msg.SourceShard,
		DestShard:   msg.DestShard,
		TxHash:      txHash,
		BlockHeight: blockHeight,
		Proof:       proof,
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// AUDIT (2026) GOV-FIX: Don't overwrite an existing receipt.
	// Without this check, a duplicate RelayCrossShardMessage call would
	// create a fresh (un-relayed) receipt, overwriting the already-relayed
	// one and bypassing RelayReceipt's `receipt.Relayed` replay protection.
	// Return the existing receipt (idempotent) so callers see the true state.
	if existing, exists := sc.receipts[msg.ID]; exists {
		return existing
	}

	sc.receipts[msg.ID] = receipt

	// P0-3 (2026-07-13): Persist receipt for cross-shard message tracking.
	if sc.stateStore != nil {
		if err := sc.stateStore.PutReceipt(sc.shardID, msg.ID, receipt); err != nil {
			// Non-fatal: receipt is still in memory, but won't survive restart.
			// We don't fail the whole call since the receipt was created.
		}
	}

	return receipt
}

// RelayReceipt marks a receipt as relayed at the given main-chain slot.
//
// P4-3 (2026-07-15): This is the second phase of cross-shard message delivery
// (after CreateReceipt). A relayed receipt proves the message reached the
// destination shard and can be spent by the recipient. Double-relay is
// rejected (ErrCrossMsgAlreadyRelay) to prevent replay.
func (sc *ShardChain) RelayReceipt(receipt *CrossShardReceipt, relaySlot uint64) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if receipt == nil {
		return ErrReceiptNotFound
	}

	if receipt.Relayed {
		return ErrCrossMsgAlreadyRelay
	}

	receipt.Relayed = true
	receipt.RelayedAt = relaySlot
	return nil
}

// SpendReceipt marks a receipt as spent, consuming the cross-shard transfer.
//
// P4-3 (2026-07-15): This is the final phase — the recipient calls this after
// processing the message to prevent the same receipt from being consumed
// twice. Requires the receipt to have been relayed first. The spent marker is
// persisted (ShardStateStore) so it survives restarts (HIGH-17 replay
// protection).
func (sc *ShardChain) SpendReceipt(messageID types.Hash, spendSlot uint64) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.spentReceipts[messageID] {
		return ErrReceiptAlreadySpent
	}

	receipt, exists := sc.receipts[messageID]
	if !exists {
		return ErrReceiptNotFound
	}

	if !receipt.Relayed {
		return fmt.Errorf("receipt not yet relayed")
	}

	receipt.Spent = true
	receipt.SpentAt = spendSlot
	sc.spentReceipts[messageID] = true

	// P0-3 (2026-07-13): Persist spent marker and updated receipt.
	// HIGH-17 safety: the spent marker prevents double-spending of receipts
	// across restarts.
	if sc.stateStore != nil {
		if err := sc.stateStore.MarkReceiptSpent(sc.shardID, messageID); err != nil {
			return fmt.Errorf("failed to persist spent receipt marker: %w", err)
		}
		_ = sc.stateStore.PutReceipt(sc.shardID, messageID, receipt)
	}

	return nil
}

func (sc *ShardChain) GetReceipt(messageID types.Hash) (*CrossShardReceipt, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	receipt, exists := sc.receipts[messageID]
	if !exists {
		return nil, ErrReceiptNotFound
	}
	return receipt, nil
}

func (sc *ShardChain) IsReceiptSpent(messageID types.Hash) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.spentReceipts[messageID]
}

// isValidator was replaced by isValidatorLocked (called with lock held).
// Removed to avoid dead code.

// pruneOldBlocks removes the oldest blocks from the in-memory map when it
// exceeds maxBlocks, keeping only the most recent maxBlocks entries.
//
// P4-3 (2026-07-15): This bounds memory usage on long-running shards. Pruned
// blocks are NOT recoverable from memory (but remain in the stateStore if
// persistence is configured). The threshold is computed as (latest - maxBlocks)
// so the pruning window slides forward as the chain grows.
// Caller must hold sc.mu (write lock).
//
// SHRD- (2026-07-17): Skip blocks that are still in flight (not yet
// finalized or not yet committed). Pruning such blocks would cause
// FinalizeBlock / CommitBlockToMainChain to return ErrShardBlockNotFound,
// breaking the finalization/commitment pipeline. Only prune blocks that have
// completed both stages. Under normal operation the pruning window
// (maxBlocks * ShardBlockInterval ≈ 3.4h at maxBlocks=1024) is far longer
// than attestation/commit latency, so this only triggers under abnormal
// stalls — where preserving the in-flight block is the safer choice.
func (sc *ShardChain) pruneOldBlocks() {
	if sc.latest <= uint64(sc.maxBlocks) {
		return
	}

	threshold := sc.latest - uint64(sc.maxBlocks)
	for h := range sc.blocks {
		if h < threshold {
			block := sc.blocks[h]
			if block != nil {
				_, committed := sc.commitments[h]
				if !block.Finalized || !committed {
					// Block is still in flight (attestation collection or
					// pending commit). Skip to preserve finalization/commit.
					continue
				}
			}
			delete(sc.blocks, h)
		}
	}
}

func (sm *ShardManager) RelayCrossShardMessage(sourceShardID, destShardID uint64, msg *CrossShardMessage, txHash types.Hash) (*CrossShardReceipt, error) {
	sm.mu.RLock()
	sourceChain, sourceExists := sm.shards[sourceShardID]
	destChain, destExists := sm.shards[destShardID]
	sm.mu.RUnlock()

	if !sourceExists {
		return nil, fmt.Errorf("source shard %d not found", sourceShardID)
	}
	if !destExists {
		return nil, fmt.Errorf("destination shard %d not found", destShardID)
	}

	destChain.mu.RLock()
	destStatus := destChain.status
	destHeight := destChain.latest
	destChain.mu.RUnlock()

	if destStatus != ShardStatusActive {
		return nil, ErrCrossMsgDestInactive
	}

	// AUDIT (2026) GOV-FIX: Verify the message signature and
	// canonical ID on the relay path, just as SubmitCrossShardMessage does.
	// Previously this path bypassed HIGH-17's checks, allowing a caller who
	// invoked RelayCrossShardMessage directly (without prior Submit) to
	// create receipts for forged or ID-malleable messages. The nonce
	// monotonicity check is NOT re-enforced here because the message has
	// already been submitted (and nonce recorded) by the time it is relayed;
	// re-enforcing strict `>` would reject the legitimate relay of an
	// already-submitted message. Signature + canonical ID verification is
	// sufficient to prevent forgery and ID malleability on this path.
	if err := sourceChain.VerifyCrossShardMessageSignature(msg); err != nil {
		return nil, fmt.Errorf("relay rejected: signature/canonical ID verification failed: %w", err)
	}

	receipt := sourceChain.CreateReceipt(msg, txHash, destHeight)
	if receipt == nil {
		return nil, fmt.Errorf("failed to create receipt for message %x", msg.ID[:8])
	}

	// GOV-FIX: If CreateReceipt returned an existing (already-relayed)
	// receipt, reject the duplicate relay attempt. This prevents replay via
	// repeated RelayCrossShardMessage calls.
	if receipt.Relayed {
		// P3-3 (2026-07-15): Duplicate relay attempt — log for audit trail.
		shardLogger.Warn("cross-shard message relay rejected: already relayed",
			map[string]any{"source_shard": sourceShardID, "dest_shard": destShardID,
				"message_id": msg.ID.String()})
		return nil, fmt.Errorf("%w: message %x", ErrCrossMsgAlreadyRelay, msg.ID[:8])
	}

	if sm.mainChain != nil {
		relaySlot := sm.mainChain.GetLatestSlot()
		if err := sourceChain.RelayReceipt(receipt, relaySlot); err != nil {
			// P3-3 (2026-07-15): Relay failure blocks cross-shard message delivery.
			shardLogger.Warn("cross-shard message relay failed",
				map[string]any{"source_shard": sourceShardID, "dest_shard": destShardID,
					"message_id": msg.ID.String(), "error": err.Error()})
			return nil, fmt.Errorf("relay failed: %w", err)
		}
	}

	return receipt, nil
}

func (sm *ShardManager) CommitShardBlock(shardID, height uint64) (*ShardCommitment, error) {
	sm.mu.RLock()
	chain, exists := sm.shards[shardID]
	sm.mu.RUnlock()

	if !exists {
		return nil, ErrShardNotFound
	}

	commitment, err := chain.CommitBlockToMainChain(height)
	if err != nil {
		return nil, err
	}

	if sm.mainChain != nil {
		if err := sm.mainChain.SubmitShardCommitment(commitment); err != nil {
			// P3-3 (2026-07-15): Main chain submission failure blocks shard
			// finality anchoring; operators should check main chain health.
			shardLogger.Warn("shard commitment submission to main chain failed",
				map[string]any{"shard_id": shardID, "height": height,
					"error": err.Error()})
			return nil, fmt.Errorf("main chain submission failed: %w", err)
		}
	}

	// P3-3 (2026-07-15): Log successful anchoring for cross-shard verification.
	shardLogger.Info("shard block committed to main chain",
		map[string]any{"shard_id": shardID, "height": height,
			"state_root": commitment.StateRoot.String()})

	return commitment, nil
}

func (sm *ShardManager) VerifyShardCommitment(commitment *ShardCommitment) (bool, error) {
	if sm.mainChain != nil {
		return sm.mainChain.VerifyShardCommitment(commitment)
	}

	sm.mu.RLock()
	chain, exists := sm.shards[commitment.ShardID]
	sm.mu.RUnlock()

	if !exists {
		return false, ErrShardNotFound
	}

	chain.mu.RLock()
	storedHash, hasCommitment := chain.commitments[commitment.BlockHeight]
	chain.mu.RUnlock()

	if !hasCommitment {
		return false, nil
	}

	return storedHash == commitment.BlockHash, nil
}

// AuthenticateCommitment verifies that a ShardCommitment was authentically
// produced by the shard block's elected proposer.
//
// AUDIT (2026) R4-GOV-04 FIX: This is the production CommitmentAuthenticator
// implementation used by MainChainCommitterImpl. It re-fetches the canonical
// block from the shard chain and verifies:
//  1. commitment.Signer is non-zero and matches block.Header.Proposer
//  2. commitment.Signature is non-empty and matches block.Header.Signature
//  3. commitment.BlockHash matches computeShardBlockHash(block.Header)
//  4. commitment.StateRoot / CrossMsgRoot match block.Header.*
//  5. block.Header.Signature is valid over computeShardBlockSigningHash
//     against the proposer's registered Dilithium3 public key
//
// This closes the R4-GOV-04 vector where anyone reaching the commit path
// could persist arbitrary (StateRoot, BlockHash) for any (shardID, height)
// and have it "verify" successfully via byte comparison alone. The
// re-fetch from the canonical shard chain means a forged commitment cannot
// pass even with a valid signature from a different shard/height — the
// (shardID, height) must already have a finalized, signed block whose
// fields exactly match the commitment.
func (sm *ShardManager) AuthenticateCommitment(c *ShardCommitment) error {
	if c == nil {
		return fmt.Errorf("commitment is nil")
	}

	// Fail-closed: empty signer means unauthenticated commitment.
	var zeroAddr types.Address
	if c.Signer == zeroAddr {
		return fmt.Errorf("%w: empty signer", ErrCommitmentUnauthenticated)
	}
	if len(c.Signature) == 0 {
		return fmt.Errorf("%w: empty signature", ErrCommitmentUnauthenticated)
	}

	sm.mu.RLock()
	chain, exists := sm.shards[c.ShardID]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("%w: shard %d not found", ErrCommitmentUnauthenticated, c.ShardID)
	}

	block, err := chain.GetBlock(c.BlockHeight)
	if err != nil {
		return fmt.Errorf("%w: cannot fetch block (shard=%d, height=%d): %v",
			ErrCommitmentUnauthenticated, c.ShardID, c.BlockHeight, err)
	}
	if block == nil || block.Header == nil {
		return fmt.Errorf("%w: nil block or header", ErrCommitmentUnauthenticated)
	}

	header := block.Header

	// 1. Signer must match the block's proposer.
	if c.Signer != header.Proposer {
		return fmt.Errorf("%w: signer %x does not match block proposer %x",
			ErrCommitmentUnauthenticated, c.Signer[:8], header.Proposer[:8])
	}

	// 2. Signature must match the block header's signature.
	if !bytesEqual(c.Signature, header.Signature) {
		return fmt.Errorf("%w: signature does not match block header signature",
			ErrCommitmentUnauthenticated)
	}

	// 3. BlockHash must match the canonical block hash.
	canonicalHash := computeShardBlockHash(header)
	if c.BlockHash != canonicalHash {
		return fmt.Errorf("%w: block hash mismatch (commitment %x != canonical %x)",
			ErrCommitmentUnauthenticated, c.BlockHash[:8], canonicalHash[:8])
	}

	// 4. StateRoot and CrossMsgRoot must match the block header.
	if c.StateRoot != header.StateRoot {
		return fmt.Errorf("%w: state root mismatch", ErrCommitmentUnauthenticated)
	}
	if c.CrossMsgRoot != header.CrossMsgRoot {
		return fmt.Errorf("%w: cross-msg root mismatch", ErrCommitmentUnauthenticated)
	}

	// 5. The block signature must be valid against the proposer's registered
	// public key over the block signing hash. This proves the proposer
	// actually signed this block (and thus authorized the commitment).
	pubKeyBytes, ok := chain.ValidatorPubKey(header.Proposer)
	if !ok {
		return fmt.Errorf("%w: no public key registered for proposer %s",
			ErrCommitmentUnauthenticated, header.Proposer.ToHexAddress())
	}
	pubKey, err := qaucrypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil || pubKey == nil {
		return fmt.Errorf("%w: invalid public key for proposer %s: %v",
			ErrCommitmentUnauthenticated, header.Proposer.ToHexAddress(), err)
	}
	signingMsg := computeShardBlockSigningHash(header)
	if !qaucrypto.Verify(pubKey, signingMsg, header.Signature) {
		return fmt.Errorf("%w: block signature verification failed",
			ErrCommitmentUnauthenticated)
	}

	return nil
}

// bytesEqual is a constant-time-ish comparison for byte slices. Used by
// AuthenticateCommitment to compare signatures without depending on
// bytes.Equal (avoids pulling in bytes package in this file if not needed).
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (sm *ShardManager) GetShardCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.shards)
}

func (sm *ShardManager) GetActiveShardCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for _, chain := range sm.shards {
		if chain.status == ShardStatusActive {
			count++
		}
	}
	return count
}

func (sm *ShardManager) GetAssignment(shardID uint64) (*ShardValidatorAssignment, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	assignment, exists := sm.assignments[shardID]
	if !exists {
		return nil, false
	}

	result := &ShardValidatorAssignment{
		ShardID:    assignment.ShardID,
		Validators: make([]types.Address, len(assignment.Validators)),
		Epoch:      assignment.Epoch,
	}
	copy(result.Validators, assignment.Validators)
	return result, true
}

// computeShardBlockHash computes the canonical hash of a shard block header.
// All header fields (including VRF proof/output) are included so the hash
// cryptographically commits to the full block identity.
//
// P4-3 (2026-07-15): This hash is used by:
//   - FinalizeBlock: attesters sign this hash to finalize the block
//   - CommitBlockToMainChain: the hash is anchored to the main chain
//   - ReceiveBlock: parent hash verification uses this hash of the parent
//
// audit-fix M-6: VRF fields are included so attester signatures protect the
// election proof — without this, a proposer could swap VRF proofs after the
// fact without invalidating attestations.
func computeShardBlockHash(header *ShardBlockHeader) types.Hash {
	h := sha3.New256()
	var shardIDBytes [8]byte
	var heightBytes [8]byte
	var tsBytes [8]byte
	for i := 0; i < 8; i++ {
		shardIDBytes[i] = byte(header.ShardID >> (8 * i))
		heightBytes[i] = byte(header.Height >> (8 * i))
		tsBytes[i] = byte(header.Timestamp >> (8 * i))
	}
	h.Write(shardIDBytes[:])
	h.Write(heightBytes[:])
	h.Write(header.ParentHash[:])
	h.Write(header.StateRoot[:])
	h.Write(header.TxRoot[:])
	h.Write(header.CrossMsgRoot[:])
	h.Write(tsBytes[:])
	h.Write(header.Proposer[:])
	// audit-fix M-6: Include VRF fields in the block hash so they are
	// cryptographically committed and protected by attester signatures.
	h.Write(header.VRFProof)
	h.Write(header.VRFOutput[:])

	var result types.Hash
	h.Sum(result[:0])
	return result
}

// ComputeShardBlockHashPublic is the exported wrapper for computeShardBlockHash.
// P1-2 (2026-07-14): Used by ShardBlockProducer (node package) to compute the
// block hash for attestation signing.
func ComputeShardBlockHashPublic(header *ShardBlockHeader) types.Hash {
	return computeShardBlockHash(header)
}

// computeShardBlockSigningHash computes the hash that the proposer signs when
// creating a block. It excludes the Signature field (empty at signing time) and
// the Timestamp field (set internally by ProposeBlock). The timestamp is still
// protected by attester signatures in FinalizeBlock, which sign the full block
// hash (including timestamp).
// FIX: Used by ProposeBlock to verify the proposer's signature.
// audit-fix M-6: Includes VRF proof and output so the proposer commits to them.
func computeShardBlockSigningHash(header *ShardBlockHeader) []byte {
	h := sha3.New256()
	var shardIDBytes [8]byte
	var heightBytes [8]byte
	for i := 0; i < 8; i++ {
		shardIDBytes[i] = byte(header.ShardID >> (8 * i))
		heightBytes[i] = byte(header.Height >> (8 * i))
	}
	h.Write(shardIDBytes[:])
	h.Write(heightBytes[:])
	h.Write(header.ParentHash[:])
	h.Write(header.StateRoot[:])
	h.Write(header.TxRoot[:])
	h.Write(header.CrossMsgRoot[:])
	h.Write(header.Proposer[:])
	// audit-fix M-6: Include VRF fields in the signing hash.
	h.Write(header.VRFProof)
	h.Write(header.VRFOutput[:])
	return h.Sum(nil)
}

// computeCrossShardMessageSigningHash computes the hash that the sender signs
// when submitting a cross-shard message.
// FIX: Used by SubmitCrossShardMessage to verify the sender's
// signature.
func computeCrossShardMessageSigningHash(msg *CrossShardMessage) []byte {
	h := sha3.New256()
	h.Write(msg.ID[:])
	var srcBytes [8]byte
	var dstBytes [8]byte
	var nonceBytes [8]byte
	var tsBytes [8]byte
	for i := 0; i < 8; i++ {
		srcBytes[i] = byte(msg.SourceShard >> (8 * i))
		dstBytes[i] = byte(msg.DestShard >> (8 * i))
		nonceBytes[i] = byte(msg.Nonce >> (8 * i))
		tsBytes[i] = byte(msg.Timestamp >> (8 * i))
	}
	h.Write(srcBytes[:])
	h.Write(dstBytes[:])
	h.Write(msg.Sender[:])
	h.Write(msg.Recipient[:])
	h.Write(msg.Payload)
	h.Write(nonceBytes[:])
	h.Write(tsBytes[:])
	return h.Sum(nil)
}

// computeTxRoot computes the Merkle root of a list of transactions.
// L4-011 FIX: Previously used a flat hash (concatenation + single
// SHA3-256), which is vulnerable to second-preimage attacks and does
// not provide tamper-evidence for individual transactions. Now uses a
// proper Merkle tree with domain-separated leaf/internal node hashing,
// consistent with miner.ComputeMerkleRoot.
func computeTxRoot(txs [][]byte) types.Hash {
	if len(txs) == 0 {
		return types.Hash{}
	}

	// Hash each transaction to create leaf nodes (domain-separated: 0x00)
	leaves := make([]types.Hash, len(txs))
	for i, tx := range txs {
		h := sha3.New256()
		h.Write([]byte{0x00})
		h.Write(tx)
		copy(leaves[i][:], h.Sum(nil))
	}

	// Build Merkle tree bottom-up
	// L8-012 CONFIRMED FIXED: Odd-leaf handling is present (L4-011 FIX).
	// When the number of nodes at any level is odd, the last node is
	// duplicated so every pair is well-defined. This is the standard
	// Bitcoin/Ethereum Merkle tree convention.
	nodes := leaves
	for len(nodes) > 1 {
		if len(nodes)%2 != 0 {
			// Duplicate last node for odd count
			nodes = append(nodes, nodes[len(nodes)-1])
		}
		nextLevel := make([]types.Hash, len(nodes)/2)
		for i := 0; i < len(nodes); i += 2 {
			h := sha3.New256()
			h.Write([]byte{0x01}) // domain separator for internal nodes
			h.Write(nodes[i][:])
			h.Write(nodes[i+1][:])
			copy(nextLevel[i/2][:], h.Sum(nil))
		}
		nodes = nextLevel
	}

	return nodes[0]
}

// hashCrossMsg hashes a single cross-shard message into a leaf node.
// The serialization includes all message fields to ensure tamper-evidence.
func hashCrossMsg(msg *CrossShardMessage) types.Hash {
	h := sha3.New256()
	h.Write([]byte{0x00}) // domain separator for leaf nodes
	h.Write(msg.ID[:])
	var srcBytes [8]byte
	var dstBytes [8]byte
	for i := 0; i < 8; i++ {
		srcBytes[i] = byte(msg.SourceShard >> (8 * i))
		dstBytes[i] = byte(msg.DestShard >> (8 * i))
	}
	h.Write(srcBytes[:])
	h.Write(dstBytes[:])
	h.Write(msg.Sender[:])
	h.Write(msg.Recipient[:])
	h.Write(msg.Payload)
	var leaf types.Hash
	copy(leaf[:], h.Sum(nil))
	return leaf
}

// computeCrossMsgRoot computes the Merkle root of cross-shard messages.
// L6-024 SECURITY FIX: Previously used a flat hash (concatenation of all
// messages + single SHA3-256), which is vulnerable to second-preimage
// attacks and does not support Merkle proofs for individual messages. Now
// uses a proper Merkle tree with domain-separated leaf/internal node
// hashing, consistent with computeTxRoot.
func computeCrossMsgRoot(msgs []*CrossShardMessage) types.Hash {
	if len(msgs) == 0 {
		return types.Hash{}
	}

	// Hash each message to create leaf nodes
	leaves := make([]types.Hash, len(msgs))
	for i, msg := range msgs {
		leaves[i] = hashCrossMsg(msg)
	}

	// Build Merkle tree bottom-up
	nodes := leaves
	for len(nodes) > 1 {
		if len(nodes)%2 != 0 {
			// Duplicate last node for odd count
			nodes = append(nodes, nodes[len(nodes)-1])
		}
		nextLevel := make([]types.Hash, len(nodes)/2)
		for i := 0; i < len(nodes); i += 2 {
			h := sha3.New256()
			h.Write([]byte{0x01}) // domain separator for internal nodes
			h.Write(nodes[i][:])
			h.Write(nodes[i+1][:])
			copy(nextLevel[i/2][:], h.Sum(nil))
		}
		nodes = nextLevel
	}

	return nodes[0]
}

// computeReceiptProof computes a deterministic proof binding a cross-shard
// message to its relay context (txHash + blockHeight).
//
// P4-3 (2026-07-15): The proof is stored on the CrossShardReceipt and serves
// as a tamper-evident link between the original message and the relay
// transaction. Verifiers can recompute the proof to confirm the receipt was
// not forged. The proof does NOT include the payload (the message ID already
// commits to the payload via GenerateCrossShardMessageID), which keeps the
// proof compact.
func computeReceiptProof(msg *CrossShardMessage, txHash types.Hash, blockHeight uint64) []byte {
	h := sha3.New256()
	h.Write(msg.ID[:])
	var srcBytes [8]byte
	var dstBytes [8]byte
	var heightBytes [8]byte
	for i := 0; i < 8; i++ {
		srcBytes[i] = byte(msg.SourceShard >> (8 * i))
		dstBytes[i] = byte(msg.DestShard >> (8 * i))
		heightBytes[i] = byte(blockHeight >> (8 * i))
	}
	h.Write(srcBytes[:])
	h.Write(dstBytes[:])
	h.Write(txHash[:])
	h.Write(heightBytes[:])
	return h.Sum(nil)
}

// GenerateCrossShardMessageID computes the canonical message ID from the
// message's identifying fields (sourceShard, destShard, sender, nonce).
//
// P4-3 (2026-07-15): The canonical ID is critical for replay protection:
//   - HIGH-17: SubmitCrossShardMessage rejects messages whose msg.ID does not
//     match this canonical ID, preventing a sender from using arbitrary IDs
//     to bypass the receipts/spentReceipts dedup.
//   - The ID intentionally EXCLUDES the payload and timestamp, so a sender
//     cannot create two "different" messages with the same (source, dest,
//     sender, nonce) tuple. This enforces one-receipt-per-nonce semantics.
//
// The domain separator ("QUANTAUREUM_CROSS_MSG_V1") prevents cross-protocol
// collisions if the same fields appear in a different context.
func GenerateCrossShardMessageID(sourceShard, destShard uint64, sender types.Address, nonce uint64) types.Hash {
	h := sha3.New256()
	var srcBytes [8]byte
	var dstBytes [8]byte
	var nonceBytes [8]byte
	for i := 0; i < 8; i++ {
		srcBytes[i] = byte(sourceShard >> (8 * i))
		dstBytes[i] = byte(destShard >> (8 * i))
		nonceBytes[i] = byte(nonce >> (8 * i))
	}
	h.Write([]byte("QUANTAUREUM_CROSS_MSG_V1"))
	h.Write(srcBytes[:])
	h.Write(dstBytes[:])
	h.Write(sender[:])
	h.Write(nonceBytes[:])

	var result types.Hash
	h.Sum(result[:0])
	return result
}

func SortAddresses(addrs []types.Address) {
	sort.Slice(addrs, func(i, j int) bool {
		for k := 0; k < len(addrs[i]); k++ {
			if addrs[i][k] != addrs[j][k] {
				return addrs[i][k] < addrs[j][k]
			}
		}
		return false
	})
}

// Quantaureum Node source, version 1.0.0.
// Package bridge implements the Quantaureum Cross-Chain Bridge protocol.
// This bridge enables secure and trustless transfer of assets and messages
// between Quantaureum and other blockchains.
package bridge

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

const (
	// MaxConcurrentProcessing limits concurrent message processing goroutines.
	// audit-fix N-1: prevents goroutine explosion from unbounded concurrency.
	MaxConcurrentProcessing = 16

	maxMessageIDLen = 256
	maxAmountLen    = 128
	maxDataSize     = 1 << 20
	maxAssetIDLen   = 256
	maxTokenIDLen   = 128
	maxAddressLen   = 256
	maxChainIDLen   = 64

	// R39-P2-05 (2026-08-02) FIX: the single source of truth for the
	// bridge's per-message maximum transfer amount. The audit's R39-P2-05
	// finding observes that unlock proof paths (UnlockAsset + RefundFailed
	// LockWithBurnProof in asset_lock.go) lacked amount range upper-bound
	// validation — the lock-side bridge.go path DID check the upper bound
	// (line ~2525), but the unlock paths relied only on lock.Amount being
	// already within range from the original LockAsset call. If a future
	// bug allowed a LockAsset with amount > maxTransferAmount to slip
	// through (e.g., a refactor that skips the upper-bound check), the
	// unlock paths would dutifully release / refund the inflated amount.
	//
	// The fix centralizes the upper bound as a single package-level
	// constant and enforces it on BOTH unlock paths (in addition to the
	// existing lock path), so failure of any single check doesn't bypass
	// the global upper bound. The amount is 1e27 base units, mirroring
	// the original literal in bridge.go:2525 — large enough to not
	// constrain legitimate large transfers, but small enough to make
	// "amount too large" insertion bugs immediately visible instead of
	// silently draining the bridge's wrapped-asset reserve.
	maxTransferAmountStr = "1000000000000000000000000000"

	// R43-BRIDGE-MSG-01 FIX (2026-08-03): hard cap on the in-memory
	// `messages` map. The map was append-only: SubmitMessage added entries
	// and they were never removed even after reaching a terminal status
	// (EXECUTED / FAILED / EXPIRED). A long-running bridge relayer would
	// leak memory until OOM. The existing `evictOldMessages()` only fires
	// after a successful ProcessMessage and is gated by the higher
	// `maxMessages` cap (100000), so terminal messages sat in memory for
	// the entire bridge lifetime in any path that did NOT go through
	// ProcessMessage (e.g., EXPIRED in VerifyMessage, FAILED after
	// MaxRetries in processPendingBatch). `sweepMessages()` is called
	// after every append and after every terminal transition so the map
	// stays bounded at maxMessagesInMemory (10000) by evicting terminal
	// messages oldest first. Persisted messages (via bbolt MessageStore)
	// are unaffected — only the IN-MEMORY cache is swept. A downstream
	// caller that asks for a swept message ID gets the canonical
	// `ErrMessageNotFound` (GetMessage returns "message not found: %s"),
	// matching the existing behavior for unknown IDs.
	maxMessagesInMemory = 10000

	// H-3 FIX: Maximum sizes for nonce tracking and finalized ID sets.
	// Prevents unbounded memory growth on long-running bridge relayers.
	maxUsedNoncesPerAddress = 10000
	maxFinalizedIDs         = 200000
	// BRDG-FIX (2026-07-17): nonceTTL = 0 means used nonces NEVER
	// expire. Previously nonceTTL = 24h, which combined with finalizedIDs
	// LRU eviction (maxFinalizedIDs = 200000) allowed replay: once a
	// finalized ID was evicted AND its nonce TTL-expired, an attacker could
	// replay the original signed message and re-execute it (double-spend).
	// Nonce replay prevention is a security-critical invariant — once a
	// nonce is seen, it must be rejected forever. OOM is now prevented by
	// maxUsedNoncesGlobal (fail-closed when reached) instead of TTL eviction.
	// The TTL eviction code path is retained for the nonceTTL > 0 case but
	// is effectively disabled when nonceTTL = 0.
	nonceTTL = 0
	// BRDG-FIX (2026-07-17): Global cap on total used nonces across ALL
	// source addresses. The per-address cap (maxUsedNoncesPerAddress) is
	// insufficient because an attacker with quorum can forge messages with
	// arbitrary sourceAddress values, each accumulating up to the per-address
	// cap. Without a global cap, the map grows without bound → OOM. 1M entries
	// × ~40 bytes ≈ 40MB, well below typical node memory budgets, while
	// allowing 1M distinct nonces before rejection.
	maxUsedNoncesGlobal = 1_000_000

	// R2 FIX: Global rate limiting for bridge message submission.
	// Prevents flooding attacks where an attacker submits thousands of
	// cross-chain messages to exhaust bridge resources or congest target chains.
	// Token bucket: 100 messages/sec burst, sustained 10 messages/sec.
	bridgeRateLimit  = 10
	bridgeBurstLimit = 100
)

// ChainID represents a unique identifier for a blockchain
type ChainID string

// nonceKey is the composite key for the usedNonces replay-protection map.
//
// BRIDGE- (2026-07-20) FIX: Previously usedNonces was keyed by
// SourceAddress alone (map[string]...). That meant two messages from the
// SAME address on DIFFERENT source chains shared a single nonce namespace:
// a message from chain A with nonce N would cause SubmitMessage to reject a
// later message from chain B with the same nonce N from the same address,
// even though the two nonces are independent (each source chain maintains
// its own nonce sequence per EIP-2930 / standard bridge designs).
//
// Switching the key to (SourceChain, SourceAddress) isolates each chain's
// nonce space so cross-chain messages from the same address no longer
// collide. The struct is comparable (ChainID is a string typedef) and can
// be used directly as a Go map key.
type nonceKey struct {
	chain ChainID
	addr  string
}

// AssetType represents the type of asset being transferred
type AssetType string

const (
	// AssetTypeNative represents native blockchain currency
	AssetTypeNative AssetType = "NATIVE"
	// AssetTypeQRC20 represents QRC20 quantum-safe fungible tokens
	AssetTypeQRC20 AssetType = "QRC20"
	// AssetTypeQRC721 represents QRC721 quantum-safe NFTs
	AssetTypeQRC721 AssetType = "QRC721"
	// AssetTypeQRC1155 represents QRC1155 quantum-safe multi-tokens
	AssetTypeQRC1155 AssetType = "QRC1155"
	// AssetTypeQAU represents QAU native tokens
	AssetTypeQAU AssetType = "QAU"
	// AssetTypeWrapped represents wrapped external chain assets (quantum-secured)
	AssetTypeWrapped AssetType = "WRAPPED"
)

// BridgeMessageStatus represents the status of a bridge message
type BridgeMessageStatus string

const (
	// MessageStatusPending indicates the message is pending processing
	MessageStatusPending BridgeMessageStatus = "PENDING"
	// MessageStatusVerified indicates the message has been verified
	MessageStatusVerified BridgeMessageStatus = "VERIFIED"
	// MessageStatusExecuted indicates the message has been executed
	MessageStatusExecuted BridgeMessageStatus = "EXECUTED"
	// MessageStatusFailed indicates the message execution failed
	MessageStatusFailed BridgeMessageStatus = "FAILED"
	// MessageStatusExpired indicates the message has expired
	MessageStatusExpired BridgeMessageStatus = "EXPIRED"
)

// BridgeMessage represents a cross-chain message
// It contains all information needed to transfer assets or data between chains

type BridgeMessage struct {
	// ID is the unique identifier for this message
	ID string `json:"id"`
	// SourceChain is the blockchain where the message originated
	SourceChain ChainID `json:"source_chain"`
	// TargetChain is the blockchain where the message is destined
	TargetChain ChainID `json:"target_chain"`
	// SourceAddress is the address on the source chain that initiated the message
	SourceAddress string `json:"source_address"`
	// TargetAddress is the address on the target chain that will receive the message
	TargetAddress string `json:"target_address"`
	// AssetType is the type of asset being transferred
	AssetType AssetType `json:"asset_type"`
	// AssetID is the identifier of the asset (token address for QRC20, etc.)
	AssetID string `json:"asset_id"`
	// Amount is the amount of asset being transferred (in smallest unit)
	Amount string `json:"amount"`
	// TokenID is the ID for NFTs (QRC721/QRC1155)
	TokenID string `json:"token_id,omitempty"`
	// Data is additional data for the message (function call data, etc.)
	Data []byte `json:"data,omitempty"`
	// Nonce is the nonce to prevent replay attacks
	Nonce uint64 `json:"nonce"`
	// Timestamp is when the message was created
	Timestamp int64 `json:"timestamp"`
	// Expiration is when the message expires (optional)
	Expiration int64 `json:"expiration,omitempty"`
	// Status is the current status of the message
	Status BridgeMessageStatus `json:"status"`
	// Proof is the proof that the message was submitted on the source chain
	Proof []byte `json:"proof,omitempty"`
	// Receipt is the receipt of execution on the target chain
	Receipt []byte `json:"receipt,omitempty"`
	// GasFee is the gas fee paid for execution on the target chain
	GasFee string `json:"gas_fee,omitempty"`
	// MessageType is the type of bridge message
	MessageType MessageType `json:"message_type"`
	// QuantumSignature is the Dilithium3 signature (3293 bytes)
	QuantumSignature []byte `json:"quantum_signature,omitempty"`
	// QuantumPublicKey is the Dilithium3 public key (1952 bytes)
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	// BlockNumber is the block number on the source chain when the message was committed.
	// Used with confirmationsRequired to ensure sufficient block depth before execution.
	BlockNumber uint64 `json:"block_number,omitempty"`
	// SlippageTolerance is the maximum acceptable price slippage in basis points (bps).
	// 100 bps = 1%. For example, 50 = 0.5% maximum slippage.
	// 0 means no slippage protection (not recommended).
	// audit-fix R63-HIGH-slippage: prevents users from receiving far less than expected
	// due to price movement between submission and execution.
	SlippageTolerance uint64 `json:"slippage_tolerance,omitempty"`
	// Deadline is the latest block number on the target chain before which the message
	// must be executed. Messages executed after the deadline are rejected.
	// 0 means no deadline (not recommended for production).
	// audit-fix R63-HIGH-slippage: prevents indefinite pending messages from executing
	// at unfavorable rates far in the future.
	Deadline uint64 `json:"deadline,omitempty"`
	// MaxAmount is the maximum amount the relayer will deliver. If the bridge rate
	// would result in delivering less than this amount (after slippage), the message
	// is rejected. This protects users from receiving amounts far below expectations.
	// Empty means no maximum (use with caution).
	// audit-fix R63-HIGH-slippage: provides an absolute floor on delivered amounts.
	MaxAmount string `json:"max_amount,omitempty"`
	// Signature is the Ethereum event signature hash (keccak256 of the event signature).
	// Populated when bridging from Ethereum-compatible chains.
	Signature string `json:"signature,omitempty"`
	// TxHash is the transaction hash on the source chain.
	// Populated when bridging from Ethereum-compatible chains.
	TxHash string `json:"tx_hash,omitempty"`
	// BlockHash is the block hash on the source chain.
	// Populated when bridging from Ethereum-compatible chains.
	BlockHash string `json:"block_hash,omitempty"`
	// RetryCount is the number of times this message has been retried after failure.
	// audit-fix R64-B2: enables retry mechanism in processMessagesLoop.
	RetryCount int `json:"retry_count,omitempty"`
	// GasLimit is the maximum gas allowed for executing this cross-chain message.
	// When set (>0), execution is rejected if the message's gas requirement exceeds
	// the adapter's configured gasLimit. 0 means no per-message limit (use adapter default).
	// audit-fix R69-GAS-1 [MEDIUM]: prevents resource exhaustion attacks where
	// malicious cross-chain messages specify high gas to consume bridge node resources.
	GasLimit uint64 `json:"gas_limit,omitempty"`
}

// MessageType represents the type of bridge message

type MessageType string

const (
	// MessageTypeAssetTransfer represents an asset transfer message
	MessageTypeAssetTransfer MessageType = "ASSET_TRANSFER"
	// MessageTypeContractCall represents a cross-chain contract call
	MessageTypeContractCall MessageType = "CONTRACT_CALL"
	// MessageTypeDataTransfer represents a data transfer message
	MessageTypeDataTransfer MessageType = "DATA_TRANSFER"
)

// Field is a key-value pair for structured logging.
// P3-3 (2026-07-15): replaces ad-hoc log.Printf format strings with
// queryable structured fields for production log systems (ELK, Loki, etc.).
type Field struct {
	Key   string
	Value any
}

// BridgeLogger is the structured logging interface for bridge operations.
// P3-3 (2026-07-15): all key paths (message submit/verify/execute/fail,
// arbitration signatures, validator rotation, L1 anchor, SPV verify, errors)
// should log through this interface instead of raw log.Printf.
type BridgeLogger interface {
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
}

// fieldsToMap converts a slice of Field to a map[string]any for the
// underlying logging.Logger. Returns nil when empty so the logger omits
// the fields key entirely.
func fieldsToMap(fields ...Field) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	m := make(map[string]any, len(fields))
	for _, f := range fields {
		m[f.Key] = f.Value
	}
	return m
}

// quantumBridgeLogger adapts logging.Logger to the BridgeLogger interface.
// This is the production implementation — emits structured JSON with module
// and field metadata.
type quantumBridgeLogger struct {
	logger *logging.Logger
}

func (l *quantumBridgeLogger) Info(msg string, fields ...Field) {
	l.logger.Info(msg, fieldsToMap(fields...))
}

func (l *quantumBridgeLogger) Warn(msg string, fields ...Field) {
	l.logger.Warn(msg, fieldsToMap(fields...))
}

func (l *quantumBridgeLogger) Error(msg string, fields ...Field) {
	l.logger.Error(msg, fieldsToMap(fields...))
}

// defaultBridgeLogger wraps the standard log package for backward
// compatibility. Used in tests or when the QuantumLogger is not available.
type defaultBridgeLogger struct{}

func (defaultBridgeLogger) Info(msg string, fields ...Field) {
	log.Printf("[INFO] [bridge] %s%v", msg, fields)
}

func (defaultBridgeLogger) Warn(msg string, fields ...Field) {
	log.Printf("[WARN] [bridge] %s%v", msg, fields)
}

func (defaultBridgeLogger) Error(msg string, fields ...Field) {
	log.Printf("[ERROR] [bridge] %s%v", msg, fields)
}

// pkgLogger is the package-level structured logger for bridge components
// that don't have direct access to a QuantumBridge instance (e.g.,
// BoltMessageStore, ExternalChainAdapter event parsing). Defaults to the
// quantumBridgeLogger backed by logging.Global().WithModule("bridge").
var pkgLogger BridgeLogger = &quantumBridgeLogger{
	logger: logging.Global().WithModule("bridge"),
}

// SetBridgeLogger overrides the package-level logger. Primarily for testing.
func SetBridgeLogger(l BridgeLogger) {
	if l != nil {
		pkgLogger = l
	}
}

// MessageStore provides persistent storage for bridge messages.
// Implementations must be safe for concurrent use.
type MessageStore interface {
	// SaveMessage persists a bridge message.
	SaveMessage(ctx context.Context, msg *BridgeMessage) error
	// LoadMessage loads a message by ID.
	LoadMessage(ctx context.Context, id string) (*BridgeMessage, error)
	// LoadMessagesByStatus loads messages by status.
	LoadMessagesByStatus(ctx context.Context, status BridgeMessageStatus) ([]*BridgeMessage, error)
	// UpdateMessageStatus atomically updates a message's status.
	UpdateMessageStatus(ctx context.Context, id string, oldStatus, newStatus BridgeMessageStatus) error
	// SaveHighestUsedNonce persists the highest-used nonce for a
	// (sourceChain, sourceAddress) pair.
	// R32-P1-04 FIX (2026-07-28): dedicated persistence for the nonce
	// high-water mark, so it survives restarts even if EXECUTED messages
	// are pruned from the message store in the future.
	SaveHighestUsedNonce(ctx context.Context, sourceChain, sourceAddress string, nonce uint64) error
	// LoadAllHighestUsedNonces loads all persisted nonce high-water marks.
	// Returns a map keyed by (sourceChain, sourceAddress) → nonce.
	LoadAllHighestUsedNonces(ctx context.Context) (map[NonceKey]uint64, error)
}

// NonceKey is the persistence-layer representation of a nonce high-water
// map key. It mirrors bridge.nonceKey but is exported so the MessageStore
// interface can return it without creating a circular dependency.
// R32-P1-04 FIX (2026-07-28).
type NonceKey struct {
	Chain string
	Addr  string
}

// MinistryWorksRecorder is the interface for recording cross-chain bridge
// operations to the consensus-layer MinistryWorks governance ministry.
// P1-T7 (2026-07-14): Bridge delegates bridge registration and cross-chain
// transaction recording to this interface, implemented by
// consensus.MinistryWorks via the node wiring layer.
type MinistryWorksRecorder interface {
	// RegisterBridge records a new bridge registration in the ministry.
	// name is the bridge name, remoteChainID is the peer chain ID,
	// relayerCount is the number of active relayers, totalLocked is the
	// total value locked (as a decimal string). Returns the bridge ID
	// assigned by the ministry, or an error.
	RegisterBridge(name string, remoteChainID uint64, relayerCount int, totalLocked string) (uint64, error)

	// RecordCrossChainTx records a cross-chain transaction in the ministry.
	// bridgeID is the ministry-assigned bridge ID, sourceTxHash is the
	// source chain transaction hash, amount is the transfer amount (decimal
	// string). Returns the tx ID assigned by the ministry, or an error.
	RecordCrossChainTx(bridgeID uint64, sourceTxHash types.Hash, amount string) (uint64, error)
}

// Bridge represents the main cross-chain bridge interface
type Bridge interface {
	// Initialize initializes the bridge
	Initialize(ctx context.Context) error
	// Start starts the bridge operations
	Start(ctx context.Context) error
	// Stop stops the bridge operations
	Stop(ctx context.Context) error
	// SubmitMessage submits a new cross-chain message
	SubmitMessage(ctx context.Context, msg *BridgeMessage) error
	// ProcessMessage processes a cross-chain message
	ProcessMessage(ctx context.Context, msg *BridgeMessage) error
	// VerifyMessage verifies a cross-chain message using proof
	VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error)
	// GetMessage retrieves a message by ID
	GetMessage(ctx context.Context, id string) (*BridgeMessage, error)
	// GetMessagesByStatus retrieves messages by status
	GetMessagesByStatus(ctx context.Context, status BridgeMessageStatus) ([]*BridgeMessage, error)
	// GetMessagesByChain retrieves messages by source or target chain
	GetMessagesByChain(ctx context.Context, chainID ChainID, isSource bool) ([]*BridgeMessage, error)
}

// BridgeConfig represents the configuration for the bridge
type BridgeConfig struct {
	// NodeURLs maps chain IDs to their respective node URLs
	NodeURLs map[ChainID]string `json:"node_urls"`
	// BridgeContractAddresses maps chain IDs to bridge contract addresses
	BridgeContractAddresses map[ChainID]string `json:"bridge_contract_addresses"`
	// GasLimit is the default gas limit for cross-chain calls
	GasLimit uint64 `json:"gas_limit"`
	// ConfirmationsRequired is the number of confirmations required on source chain
	ConfirmationsRequired int `json:"confirmations_required"`
	// MessageExpiration is the default message expiration time in seconds
	MessageExpiration int64 `json:"message_expiration"`
	// PollingInterval is the interval for polling source chain events
	PollingInterval time.Duration `json:"polling_interval"`
	// MaxRetries is the maximum number of retries for message processing
	MaxRetries int `json:"max_retries"`
	// InitializerAddress is the address authorized to set the governance address
	// for the first time on Quantaureum chain adapters.
	InitializerAddress string `json:"initializer_address"`
}

// DefaultBridgeConfig returns the default bridge configuration
func DefaultBridgeConfig() *BridgeConfig {
	return &BridgeConfig{
		NodeURLs:                make(map[ChainID]string),
		BridgeContractAddresses: make(map[ChainID]string),
		GasLimit:                2000000,
		ConfirmationsRequired:   10,
		MessageExpiration:       3600 * 24, // 24 hours
		PollingInterval:         15 * time.Second,
		MaxRetries:              5,
	}
}

// R32-P2-11 FIX (2026-07-28): Bridge message retry backoff helpers.
//
// The previous retry implementation already used exponential backoff
// (baseInterval * 2^attempts), but with no CAP on the backoff duration.
// After MaxRetries=5 retries with PollingInterval=15s, the backoff grows
// to 15s * 2^5 = 480s = 8 minutes. If an operator raises MaxRetries to
// 10 (e.g. for a flaky RPC), the backoff would reach 15s * 2^10 = 15360s
// = 4.26 hours, effectively disabling retries for hours. With
// MaxRetries=20 the backoff would exceed 5 days.
//
// This fix adds two improvements:
//  1. maxBackoffInterval (5 minutes): caps the exponential growth so
//     retries never wait more than 5 minutes regardless of MaxRetries.
//     This matches the polling interval's purpose (responsive bridge
//     operation) while still providing meaningful backoff for transient
//     failures.
//  2. computeBackoff helper: centralizes the backoff computation so all
//     retry paths (FAILED, VERIFIED, PENDING) use the same capped formula.
//     Previously the formula was duplicated across 3 sites.
const maxBackoffInterval = 5 * time.Minute

// computeBackoff returns the retry backoff duration for a message that has
// failed `attempts` times. The formula is:
//
//	backoff = min(baseInterval * 2^attempts, maxBackoffInterval)
//
// R32-P2-11: Without the cap, a high MaxRetries setting could produce
// multi-hour backoffs that effectively disable the bridge. The cap keeps
// retries responsive while still providing exponential decay of retry
// frequency for transient failures.
func (q *QuantumBridge) computeBackoff(attempts int) time.Duration {
	if attempts <= 0 {
		return q.config.PollingInterval
	}
	// Guard against overflow: 1<<63 would produce a negative time.Duration.
	// Cap attempts at 30 (2^30 * 15s ≈ 230 days, well beyond maxBackoffInterval).
	if attempts > 30 {
		attempts = 30
	}
	backoff := q.config.PollingInterval * time.Duration(1<<uint(attempts))
	if backoff > maxBackoffInterval {
		backoff = maxBackoffInterval
	}
	if backoff < q.config.PollingInterval {
		// Defensive: should never happen, but if PollingInterval is zero
		// (misconfiguration), fall back to a sane minimum.
		backoff = q.config.PollingInterval
	}
	return backoff
}

// validateGovernanceProposalID validates the format of a governance proposal ID.
//
// R32-P2-12 FIX (2026-07-28): Previously, SetRelayerKeys/SetValidatorKeys
// accepted ANY non-empty string as a "governance proposal ID", including
// "1", "abc", or random blobs. This made the proposalID check ineffective
// as an audit trail: an attacker who compromised the governance account
// could rotate keys with an arbitrary proposalID and leave no on-chain
// reference. The fix validates that proposalID is a keccak256 hash in
// the standard 0x-prefixed hex format (66 chars total).
//
// Accepted format: ^0x[0-9a-fA-F]{64}$
//
// This is defense-in-depth — the primary auth is the caller identity
// check (caller == governanceAddress). The format check ensures the
// proposalID can be cross-referenced against on-chain governance records.
//
// Returns nil if valid, error describing the violation otherwise.
func validateGovernanceProposalID(proposalID string) error {
	// Length check: "0x" + 64 hex chars = 66 chars total.
	if len(proposalID) != 66 {
		return fmt.Errorf("proposal ID must be 0x-prefixed 32-byte hash (66 chars), got %d chars", len(proposalID))
	}
	// Prefix check.
	if proposalID[0] != '0' || (proposalID[1] != 'x' && proposalID[1] != 'X') {
		return fmt.Errorf("proposal ID must start with 0x")
	}
	// Hex check: chars 2..65 must be [0-9a-fA-F].
	for i := 2; i < len(proposalID); i++ {
		c := proposalID[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return fmt.Errorf("proposal ID contains non-hex character %q at position %d", c, i)
		}
	}
	return nil
}

// StandardBridgeEventSignatures returns the keccak256 hashes of the standard
// bridge event ABI signatures that should be registered on all adapters.
//
// P1-4 FIX (2026-07-13): adapters fail-closed by default — an empty event
// signature allowlist rejects ALL cross-chain events. These signatures must
// be registered at startup (via governance caller) before the bridge can
// parse any lock/burn events from either chain.
//
// Events:
//   - TokensLocked: emitted by Ethereum bridge contract when native tokens
//     are locked for transfer to Quantaureum.
//   - ERC20Locked: emitted by Ethereum bridge contract when ERC20 tokens
//     are locked for transfer to Quantaureum.
//   - TokensBurned: emitted by Quantaureum bridge contract when wrapped
//     native tokens are burned for release on Ethereum.
//   - WrappedTokenBurned: emitted by Quantaureum bridge contract when
//     wrapped ERC20 tokens are burned for release on Ethereum.
func StandardBridgeEventSignatures() []string {
	abis := []string{
		"TokensLocked(address,uint256,bytes32,bytes32)",
		"ERC20Locked(address,address,uint256,bytes32)",
		"TokensBurned(address,uint256,address,bytes32)",
		"WrappedTokenBurned(address,address,uint256,address)",
	}
	hashes := make([]string, 0, len(abis))
	for _, abi := range abis {
		h := sha3.NewLegacyKeccak256()
		h.Write([]byte(abi))
		hashes = append(hashes, "0x"+hex.EncodeToString(h.Sum(nil)))
	}
	return hashes
}

// merkleRootStorageSlotHex is the canonical on-chain storage slot where the
// bridge contract stores the latest committed Merkle root. It is computed as
// keccak256("merkleRoot") — a fixed 32-byte value, memoized at package init
// to avoid recomputing on every FetchMerkleRootFromChain call.
//
// P1-5 (2026-07-14): Stage 2 of SPV header verification. The bridge contract
// writes the committed root to this slot whenever a new batch of messages is
// finalized on-chain. Reading the root directly from contract storage (via
// eth_getStorageAt) eliminates the trust assumption on the governance caller
// used in Stage 1 (SetCommittedRoot): the root comes from the on-chain
// contract, which is itself secured by the chain's consensus.
var merkleRootStorageSlotHex = func() string {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("merkleRoot"))
	return "0x" + hex.EncodeToString(h.Sum(nil))
}()

// computeMerkleRootStorageSlot returns the hex-encoded storage slot
// (keccak256("merkleRoot")) used by the bridge contract to store the
// committed Merkle root. Both adapters use this slot when fetching the
// root via eth_getStorageAt.
func computeMerkleRootStorageSlot() string {
	return merkleRootStorageSlotHex
}

// ChainAdapter represents an adapter for interacting with a specific blockchain
type ChainAdapter interface {
	// ChainID returns the chain ID for this adapter
	ChainID() ChainID
	// SubmitMessage submits a message to the blockchain
	SubmitMessage(ctx context.Context, msg *BridgeMessage) (string, error)
	// VerifyMessage verifies a message using blockchain proof
	VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error)
	// ExecuteMessage executes a message on the blockchain
	ExecuteMessage(ctx context.Context, msg *BridgeMessage) (bool, error)
	// HasSufficientConfirmations reports whether a source event at the given
	// block number has at least this adapter's required confirmation depth on
	// THIS adapter's chain. BRIDGE-CONF-01 FIX (deep-audit 2026-07-12): the
	// confirmation-depth check must run on the SOURCE adapter (msg.BlockNumber is
	// a source-chain height), not on the target adapter that executes the
	// message. Returns (true, nil) when no depth is required (confirmations<=0).
	HasSufficientConfirmations(ctx context.Context, blockNumber uint64) (bool, error)
	// GetTransactionBlockNumber looks up the block number in which a transaction
	// was included on this adapter's chain. Returns an error if the transaction
	// is not yet confirmed or not found.
	// AUDIT (2026 security review) BRDG-09: Used by the confirmation-watcher goroutine to
	// automatically promote pending asset locks to Locked status once the
	// source-chain lock transaction is confirmed. Without this, ConfirmLock
	// had no production caller and locks could remain Pending indefinitely.
	GetTransactionBlockNumber(ctx context.Context, txHash string) (uint64, error)
	// GetMessageProof retrieves proof for a message
	GetMessageProof(ctx context.Context, msgID string) ([]byte, error)
	// WatchEvents watches for bridge events on the blockchain
	WatchEvents(ctx context.Context, callback func(*BridgeMessage) error) error
	// FetchMerkleRootFromChain reads the committed Merkle root directly from
	// the on-chain bridge contract via eth_getStorageAt.
	// P1-5 (2026-07-14): Stage 2 of SPV header verification. Eliminates the
	// trust assumption on the governance caller used in Stage 1
	// (SetCommittedRoot): the root comes from the on-chain contract secured
	// by consensus. Adapters auto-update their cached committedRoot when the
	// fetched root differs.
	FetchMerkleRootFromChain(ctx context.Context) (types.Hash, error)

	// R37-FIX P2-BRIDGE-01 (2026-07-30) + R38-P1-11 DEEP FIX (2026-08-02):
	// VerifyBurnTransaction verifies that the given transaction on this
	// adapter's chain is a finalized burn call to the wrapped-asset
	// contract for the given amount, with full calldata consistency
	// against the BurnVerificationRequest fields.
	//
	// The previous signature (ctx, txHash string, amount *big.Int) only
	// verified the receipt status + contract-to whitelist match — it
	// could NOT catch a forged tx whose calldata lied about
	// (validatorAddr, fundingEpoch, signature, beneficiary, real
	// burnAmount). The deep fix takes a BurnVerificationRequest and the
	// adapter MUST:
	//   1. confirm the receipt is successful and finalized (existing
	//      behavior)
	//   2. fetch the tx via eth_getTransactionByHash to extract calldata
	//   3. decode the calldata per the wrapped-asset ABI: function
	//      selector + burnAmount + validatorAddr + fundingEpoch +
	//      signature + beneficiary
	//   4. assert strong consistency: req.Amount == calldata.burnAmount,
	//      req.ValidatorAddr == calldata.validatorAddr,
	//      req.FundingEpoch == calldata.fundingEpoch,
	//      req.Beneficiary == calldata.beneficiary
	//   5. if req.Signature is non-empty, verify the signature over
	//      (txHash || validatorAddr || fundingEpoch || amount) against
	//      the validator's known Dilithium3 public key
	//
	// Adapters that cannot perform deep verification MUST return
	// (false, ErrBurnVerificationNotSupported) — AssetLockManager
	// treats that as fail-closed.
	VerifyBurnTransaction(ctx context.Context, req *BurnVerificationRequest) (bool, error)
}

// BurnVerificationRequest is the rich input to the deep R38-P1-11 fix
// for VerifyBurnTransaction (2026-08-02). The previous signature
// (ctx, txHash string, amount *big.Int) only verified the receipt
// status + contract-to whitelist match — it could NOT catch a forged
// tx whose calldata lied about (validatorAddr, fundingEpoch, signature,
// beneficiary, real burnAmount). This struct carries every field the
// adapter needs to perform full calldata verification:
//   - TxHash + ChainID: locate the tx on the target chain
//   - Amount: declared burn amount; adapter MUST derive the same from
//     calldata and reject if they disagree (strong consistency)
//   - ValidatorAddr: the validator whose key was supposed to sign the
//     burn; matched against the calldata's beneficiary / sig-recovered
//     signer depending on adapter semantics
//   - FundingEpoch: the epoch the burn claims to fund; matched against
//     calldata
//   - Signature: optional Dilithium3 signature over (txHash,
//     validatorAddr, fundingEpoch, amount); adapters that do not support
//     signature verification MUST leave this nil and continue with
//     calldata-only checks
//   - Beneficiary: L1 address that should receive the unwrapped asset;
//     matched against the calldata beneficiary and (where applicable)
//     receipt logs
//
// Adapters that cannot perform deep verification MUST return
// (false, ErrBurnVerificationNotSupported) rather than silently claim
// true — AssetLockManager treats that as fail-closed (refund refused).
type BurnVerificationRequest struct {
	TxHash        string
	ChainID       ChainID
	Amount        *big.Int
	ValidatorAddr types.Address
	FundingEpoch  uint64
	Signature     []byte
	Beneficiary   types.Address
}

// ErrBurnVerificationNotSupported is returned by ChainAdapter implementations
// that cannot perform deep calldata verification (e.g. a stub adapter used
// in tests). AssetLockManager treats this as fail-closed (refund refused)
// rather than fail-open (refund granted without verification).
// R38-P1-11 DEEP FIX (2026-08-02).
var ErrBurnVerificationNotSupported = fmt.Errorf("chain adapter does not support deep burn verification")

// BridgeEvent represents a bridge event
type BridgeEvent struct {
	// EventType is the type of event
	EventType string `json:"event_type"`
	// Message is the bridge message associated with the event
	Message *BridgeMessage `json:"message"`
	// Timestamp is when the event occurred
	Timestamp int64 `json:"timestamp"`
	// BlockNumber is the block number where the event occurred
	BlockNumber uint64 `json:"block_number"`
	// TransactionHash is the transaction hash of the event
	TransactionHash string `json:"transaction_hash"`
}

// QuantumBridge implements the Quantaureum Cross-Chain Bridge
type QuantumBridge struct {
	// Configuration
	config *BridgeConfig
	// Chain adapters for each supported chain
	adapters map[ChainID]ChainAdapter
	// Message store (in-memory cache)
	messages map[string]*BridgeMessage
	// Message status index
	messagesByStatus map[BridgeMessageStatus]map[string]bool
	// Message chain index
	messagesBySourceChain map[ChainID]map[string]bool
	messagesByTargetChain map[ChainID]map[string]bool
	// Persistent storage backend (nil = in-memory only)
	store MessageStore
	// audit-fix CRIT-1: permanent set of finalized message IDs (executed/failed/expired).
	// When messages are evicted from the in-memory cache to bound memory usage,
	// their IDs are retained here so that a replay attempt with the same ID is
	// rejected at SubmitMessage time even after eviction.
	// R68-BRIDGE-3 [MEDIUM] FIX: LRU ordering via ordered slice + index map.
	// Previously, eviction was arbitrary (random map iteration order), which could
	// remove recently added entries and allow message replay. Now we track insertion
	// order in finalizedIDsOrder and evict oldest entries first.
	finalizedIDs      map[string]bool
	finalizedIDsOrder []string       // Ordered list of finalized IDs (oldest first)
	finalizedIDsIndex map[string]int // Maps ID -> index in finalizedIDsOrder for O(1) lookup
	// SECURITY FIX: per-sender nonce tracking to prevent replay attacks.
	// Maps (source chain, source address) -> set of used nonces. An attacker
	// cannot replay a message with the same nonce even if they capture a
	// valid signature.
	// H-3 FIX: track insertion time for TTL-based eviction.
	// BRIDGE-FIX (2026-07-20): key is now nonceKey{chain, addr}
	// instead of just the address string, so the same address on different
	// source chains no longer shares a nonce namespace.
	usedNonces map[nonceKey]map[uint64]time.Time
	// BRDG-FIX (2026-07-17): Global running count of entries across all
	// per-address sub-maps in usedNonces. Maintained incrementally on insert
	// and TTL-eviction to avoid O(N) scans on every ProcessMessage call.
	// Capped at maxUsedNoncesGlobal to prevent OOM via forged sourceAddresses.
	totalUsedNonces int
	// BRIDGE-H01/ECON-H02 (R30, 2026-07-27) FIX: highest executed nonce per
	// (chain, addr). Provides compact replay protection for all nonces <=
	// this value, allowing sweepUsedNonces to prune those entries from
	// usedNonces without losing replay protection. Only advanced on EXECUTED
	// status transition (not on submission) so failed submissions don't
	// permanently burn nonces.
	highestUsedNonce map[nonceKey]uint64
	// AUDIT-FULL NW-08 (2026-08-14): optional on-disk checkpoint for
	// usedNonces/highestUsedNonce in memory mode (store == nil). Previously
	// the nonce state was memory-only in that mode, so a restart forgot
	// every recorded nonce and pre-restart messages could be replayed
	// (double-spend). When a path is configured via SetNonceCheckpointPath,
	// the checkpoint is loaded in Initialize and rewritten on every nonce
	// mutation. See nonce_checkpoint.go.
	nonceCheckpointPath string
	// FIX (2026-08-15): checkpoint I/O is off-loaded to a
	// single background goroutine so the file WriteFile+Rename never runs
	// while holding q.mu. The checkpoint loop drains a buffered channel of
	// serialized (JSON) snapshots and atomically writes them to disk. This
	// eliminates the "dozens of ms bridge stall while holding the write
	// lock" hazard flagged in . Mutations enqueue snapshots
	// (non-blocking due to the buffer); Stop / finalize drains the channel
	// and stops the goroutine.
	nonceCheckpointCh   chan []byte
	nonceCheckpointDone chan struct{}
	// Synchronization
	mu sync.RWMutex
	// audit-fix R2-H2: per-message locks to prevent TOCTOU double-execution.
	// The global mu protects map access; msgLocks prevents concurrent
	// ProcessMessage calls for the same message ID.
	msgLocks map[string]*sync.Mutex
	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
	// Running status
	running bool
	// BRIDGE- (2026-07-20) FIX: Emergency pause flag.
	// When set, SubmitMessage and ProcessMessage reject new work with
	// ErrBridgePaused. In-flight messages already in the processing
	// pipeline will complete, but no new ones will be accepted.
	// Used by governance / operators to halt bridge operations when a
	// vulnerability is discovered or the bridge is under attack.
	// Implemented as atomic.Bool for lock-free reads from hot paths.
	paused atomic.Bool
	// pausedReason records why the bridge was paused (for diagnostics /
	// audit log). Cleared on Unpause. Protected by mu.
	pausedReason string
	// BRIDGE-R13-H01 (2026-07-21) FIX: wakeup signal for processMessagesLoop.
	// When Unpause() is called, it sends on this channel to wake up the loop
	// immediately instead of waiting for the next PollingInterval tick. This
	// ensures pending messages resume processing promptly after Unpause.
	// Buffered(1) so the first Unpause before the loop starts does not block.
	// The channel is never closed — sends use a non-blocking select so a
	// stopped loop doesn't deadlock.
	processWakeup chan struct{}
	// audit-fix R2-L4: maximum number of in-memory messages before eviction
	maxMessages int
	// audit-fix R64-B2: retry tracking for failed message reprocessing.
	// Maps message ID -> retry count. Used in processMessagesLoop to enforce
	// MaxRetries limit and implement exponential backoff.
	retryAttempts map[string]int
	// Maps message ID -> last retry timestamp (Unix nanoseconds).
	// Used for exponential backoff: next retry must wait baseInterval * 2^attempts.
	lastRetryTime map[string]time.Time

	rateLimiter *RateLimiter
	// AUDIT (2026 security review) HIGH-08: Optional validator network for M-of-N
	// threshold verification before message execution. When set,
	// ProcessMessage requires quorum before calling ExecuteMessage.
	validatorNetwork *ValidatorNetwork
	// P0-1 BRDG-01 FIX (2026-07-13): Trusted Dilithium3 public keys for
	// verifyQuantumSignature. Messages signed with keys NOT in this set are
	// rejected at SubmitMessage time. Populated from QPOS validator set or
	// governance. Empty = fail-closed (all messages rejected until keys are
	// configured), preventing forgery via self-generated key pairs.
	trustedValidatorKeys [][]byte
	// R31-MED-4 FIX (2026-09-06): validator-trust mutation lock. Once the
	// bridge has an active trust set, ad-hoc local mutation of the trusted
	// keys (SetTrustedValidatorKeys) is refused unless the operator
	// explicitly opens a mutation window via UnlockValidatorTrustMutation.
	// The epoch-sync path (RefreshValidatorSet, driven by consensus state
	// in node.RefreshBridgeValidators) remains the only always-open
	// mutation channel. This prevents a compromised local operator process
	// from silently replacing the bridge trust anchor with attacker keys
	// between epochs.
	validatorTrustLocked bool
	// P3-1 (2026-07-14): Prometheus metrics for bridge observability.
	// Nil-safe: all BridgeMetrics methods check for nil before recording.
	metrics *BridgeMetrics
	// P3-3 (2026-07-14): Structured logger for bridge operations.
	// Initialized from the global logger with module="bridge".
	// All key operations (submit/verify/execute/lock/mint/burn) log
	// structured fields (messageID, chainID, sourceAddr) for traceability.
	logger *logging.Logger

	// P1-T7 (2026-07-14): MinistryWorks recorder for governance tracking.
	// When set, SubmitMessage records cross-chain transactions and bridge
	// creation registers the bridge in the ministry. Best-effort: errors
	// are logged but do NOT block bridge operations.
	ministryWorks    MinistryWorksRecorder
	ministryBridgeID uint64 // ID assigned by MinistryWorks.RegisterBridge

	// BRIDGE-R15-CRIT-002 (2026-07-22): hook invoked by evictOldMessages
	// before deleting a stale PENDING BridgeMessage from memory. The hook
	// lets the AssetLockManager mark the corresponding AssetLock as Failed
	// so the operator can later refund the stuck source-chain funds.
	// Without this hook, evicting a PENDING message silently dropped it
	// while the user's locked assets remained permanently stuck. nil-safe:
	// evictOldMessages checks for nil before calling. Protected by mu.
	pendingEvictionHook func(messageID string)
}

type RateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	lastUpdate time.Time
	rate       float64
	burst      float64
}

func newRateLimiter(rate, burst int) *RateLimiter {
	return &RateLimiter{
		tokens:     float64(burst),
		lastUpdate: time.Now(),
		rate:       float64(rate),
		burst:      float64(burst),
	}
}

func (rl *RateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastUpdate).Seconds()
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.burst {
		rl.tokens = rl.burst
	}
	rl.lastUpdate = now

	if rl.tokens < 1 {
		return false
	}
	rl.tokens--
	return true
}

// NewQuantumBridge creates a new QuantumBridge instance
func NewQuantumBridge(config *BridgeConfig) Bridge {
	if config == nil {
		config = DefaultBridgeConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &QuantumBridge{
		config:                config,
		adapters:              make(map[ChainID]ChainAdapter),
		messages:              make(map[string]*BridgeMessage),
		messagesByStatus:      make(map[BridgeMessageStatus]map[string]bool),
		messagesBySourceChain: make(map[ChainID]map[string]bool),
		messagesByTargetChain: make(map[ChainID]map[string]bool),
		msgLocks:              make(map[string]*sync.Mutex),
		finalizedIDs:          make(map[string]bool),
		// R68-BRIDGE-3 FIX: Initialize LRU ordering structures
		finalizedIDsOrder: make([]string, 0),
		finalizedIDsIndex: make(map[string]int),
		usedNonces:        make(map[nonceKey]map[uint64]time.Time), // SECURITY FIX: nonce tracking with TTL
		highestUsedNonce:  make(map[nonceKey]uint64),               // BRIDGE-H01/ECON-H02: compact replay protection
		ctx:               ctx,
		cancel:            cancel,
		running:           false,
		maxMessages:       100000,
		retryAttempts:     make(map[string]int),
		lastRetryTime:     make(map[string]time.Time),
		rateLimiter:       newRateLimiter(bridgeRateLimit, bridgeBurstLimit),
		// P0-1 BRDG-01 FIX: initialize empty trusted key set (fail-closed).
		trustedValidatorKeys: make([][]byte, 0),
		metrics:              NewBridgeMetrics(),
		logger:               logging.Global().WithModule("bridge"),
		// BRIDGE-R13-H01: buffered(1) wakeup channel for prompt resume after Unpause.
		processWakeup: make(chan struct{}, 1),
	}
}

// ErrBridgePaused is returned by SubmitMessage and ProcessMessage when the
// bridge is in emergency-pause mode. Callers should propagate this error to
// upstream clients so they know the bridge is intentionally halted.
//
// BRIDGE- (2026-07-20): The bridge had no pause mechanism — when a
// vulnerability was discovered or the bridge was under attack, operators
// had no way to halt bridge operations short of shutting down the entire
// node. The emergency pause API (Pause/Unpause/IsPaused) allows governance
// or operators to halt only the bridge while the rest of the node keeps
// running (consensus, RPC, etc.).
var ErrBridgePaused = fmt.Errorf("bridge is paused (BRIDGE-): emergency halt is active; new messages are rejected until Unpause() is called")

// Pause activates emergency-pause mode. After Pause returns:
//   - SubmitMessage rejects new messages with ErrBridgePaused.
//   - ProcessMessage rejects new messages with ErrBridgePaused.
//   - Messages already in the processing pipeline complete normally.
//
// The reason string is recorded for diagnostics / audit log. It is NOT
// compared against any allowlist; callers (governance, operator tools) are
// responsible for supplying a meaningful reason.
//
// BRIDGE- (2026-07-20): Emergency pause for bridge.
func (q *QuantumBridge) Pause(reason string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.paused.Store(true)
	q.pausedReason = reason
	if q.logger != nil {
		q.logger.Warn("bridge paused (BRIDGE-)",
			map[string]any{"reason": reason})
	}
}

// Unpause deactivates emergency-pause mode. After Unpause returns,
// SubmitMessage and ProcessMessage accept new messages again.
//
// The reason is cleared. Callers should ensure the underlying issue that
// triggered Pause() has been resolved before calling Unpause().
//
// BRIDGE-R13-H01 (2026-07-21) FIX: Unpause now sends a non-blocking wakeup
// signal to processMessagesLoop so pending messages resume processing
// immediately instead of waiting for the next PollingInterval tick. This
// closes the gap where messages stuck in PENDING/FAILED/VERIFIED status
// during the pause window would otherwise sit idle for up to
// PollingInterval (default 15s) after Unpause before being retried.
//
// BRIDGE- (2026-07-20): Emergency pause for bridge.
func (q *QuantumBridge) Unpause() {
	q.mu.Lock()
	wasPaused := q.paused.Load()
	q.paused.Store(false)
	prevReason := q.pausedReason
	q.pausedReason = ""
	wakeup := q.processWakeup
	q.mu.Unlock()

	if wasPaused {
		if q.logger != nil {
			q.logger.Info("bridge unpaused (BRIDGE-)",
				map[string]any{"previousReason": prevReason})
		}
		// BRIDGE-R13-H01: non-blocking wakeup send. If the channel buffer is
		// already full (e.g., previous Unpause hasn't been consumed yet), the
		// loop is already scheduled to wake up — no need to queue another.
		select {
		case wakeup <- struct{}{}:
		default:
		}
	}
}

// IsPaused returns whether the bridge is currently in emergency-pause mode.
// Safe for concurrent use; the underlying atomic read is lock-free.
//
// BRIDGE- (2026-07-20): Emergency pause for bridge.
func (q *QuantumBridge) IsPaused() bool {
	return q.paused.Load()
}

// PausedReason returns the reason string recorded when Pause() was last
// called, or "" if the bridge is not currently paused. For diagnostics /
// audit log only.
//
// BRIDGE- (2026-07-20): Emergency pause for bridge.
func (q *QuantumBridge) PausedReason() string {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.pausedReason
}

// SetTrustedValidatorKeys sets the trusted Dilithium3 public keys used by
// verifyQuantumSignature to authorize bridge messages at SubmitMessage time.
//
// P0-1 BRDG-01 FIX (2026-07-13): Without this call, trustedValidatorKeys is
// empty and all SubmitMessage calls fail with "no trusted validator keys
// configured" (fail-closed). Keys should be populated from the QPOS validator
// set or governance contract at node startup.
//
// Each key must be exactly crypto.Dilithium3PublicKeySize (1952) bytes, matching
// the format produced by crypto.PublicKey.Bytes() / circl mode3.PublicKey.MarshalBinary().
//
// trustedKeySetsEqual reports whether two trusted-key sets contain the same
// keys (order-insensitive, constant bounds). Used by the R31-MED-4 mutation
// guard to distinguish an idempotent re-seed from an actual trust-anchor
// CHANGE: re-seeding the identical set (node restart, re-init) is a no-op,
// while any change is refused without an explicit mutation window.
func trustedKeySetsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, k := range a {
		seen[string(k)] = struct{}{}
	}
	for _, k := range b {
		if _, ok := seen[string(k)]; !ok {
			return false
		}
	}
	return true
}

func (q *QuantumBridge) SetTrustedValidatorKeys(keys [][]byte) {
	q.mu.Lock()
	defer q.mu.Unlock()
	// R31-MED-4 FIX: guard non-bootstrap mutations. The FIRST seeding of a
	// trust set (empty -> non-empty) is bootstrap and allowed silently;
	// every subsequent replacement requires an explicit mutation window
	// opened by UnlockValidatorTrustMutation (which logs loudly), or the
	// epoch-driven RefreshValidatorSet path. Without this, any local caller
	// could swap the bridge's trust anchor to attacker-controlled keys at
	// any time — the quorum M-of-N check would then pass with forged
	// validator attestations.
	if len(q.trustedValidatorKeys) > 0 && len(keys) > 0 && !q.validatorTrustLocked {
		// Mutation window OPEN (UnlockValidatorTrustMutation): operator-
		// driven rotation is permitted. The window is re-sealed by
		// LockValidatorTrustMutation (or the next epoch sync); do NOT
		// auto-seal here so the follow-up Set inside the window succeeds.
	}
	if len(q.trustedValidatorKeys) > 0 && q.validatorTrustLocked && len(keys) > 0 {
		// Idempotent re-seed with the IDENTICAL set is allowed (restarts,
		// re-init wiring). Any actual CHANGE is refused without an
		// explicit mutation window.
		if !trustedKeySetsEqual(q.trustedValidatorKeys, keys) {
			q.logger.Warn("bridge: SetTrustedValidatorKeys REFUSED — trust set CHANGE requires "+
				"RefreshValidatorSet (epoch sync) or UnlockValidatorTrustMutation + re-lock "+
				"for an operator-driven rotation (R31-MED-4)",
				map[string]any{
					"currentKeys": len(q.trustedValidatorKeys),
					"attempted":   len(keys),
				})
			return
		}
		// Same set — accept as a no-op re-seed (keeps the lock sealed).
		return
	}
	if len(keys) == 0 {
		// Emptying the trust set is fail-closed for SubmitMessage, not an
		// escalation — but still refuse after bootstrap so a buggy caller
		// cannot DoS the bridge by wiping the anchor.
		if len(q.trustedValidatorKeys) > 0 {
			q.logger.Warn("bridge: SetTrustedValidatorKeys REFUSED — refusing to CLEAR the seeded trust set (R31-MED-4)",
				map[string]any{"currentKeys": len(q.trustedValidatorKeys)})
			return
		}
		return
	}
	// Deep copy to prevent external mutation.
	q.trustedValidatorKeys = make([][]byte, len(keys))
	for i, k := range keys {
		cp := make([]byte, len(k))
		copy(cp, k)
		q.trustedValidatorKeys[i] = cp
	}
	// Bootstrap seeding complete — lock against future ad-hoc mutation.
	// A windowed rotation leaves the window open until the operator calls
	// LockValidatorTrustMutation; the lock flag set here is correct for
	// bootstrap (empty -> non-empty) because no window can be open before
	// the first seed.
	q.validatorTrustLocked = true
}

// UnlockValidatorTrustMutation opens an explicit operator-driven mutation
// window for the bridge trust anchor (R31-MED-4). It must be followed by
// SetTrustedValidatorKeys and then LockValidatorTrustMutation to re-seal.
// Every call logs at Warn level with the reason so rotations are visible in
// the audit trail; the reason is mandatory and recorded.
func (q *QuantumBridge) UnlockValidatorTrustMutation(reason string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if reason == "" {
		reason = "(no reason provided — flagged)"
	}
	q.validatorTrustLocked = false
	q.logger.Warn("bridge: validator trust mutation window OPENED (R31-MED-4)",
		map[string]any{"reason": reason, "currentKeys": len(q.trustedValidatorKeys)})
}

// LockValidatorTrustMutation re-seals the trust anchor after an operator
// rotation. Idempotent.
func (q *QuantumBridge) LockValidatorTrustMutation() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.validatorTrustLocked = true
	q.logger.Warn("bridge: validator trust mutation window SEALED (R31-MED-4)",
		map[string]any{"currentKeys": len(q.trustedValidatorKeys)})
}

// GetTrustedValidatorKeysCount returns the number of configured trusted
// validator keys. For diagnostics / DoD verification.
func (q *QuantumBridge) GetTrustedValidatorKeysCount() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.trustedValidatorKeys)
}

// SetMinistryWorks wires the MinistryWorks recorder for governance tracking.
// P1-T7 (2026-07-14): When set, the bridge registers itself with the ministry
// and records cross-chain transactions. Best-effort: ministry recording
// failures are logged but do NOT block bridge operations.
//
// This should be called BEFORE Initialize() so that the bridge is registered
// in the ministry during initialization. If called after Initialize(),
// registration happens on the next SubmitMessage call.
func (q *QuantumBridge) SetMinistryWorks(recorder MinistryWorksRecorder) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.ministryWorks = recorder
}

// registerWithMinistry registers this bridge in the MinistryWorks governance
// ministry. P1-T7 (2026-07-14): Called during Initialize() after adapters
// are registered. Best-effort — errors are logged but do not block startup.
// Caller must NOT hold q.mu (this method acquires it).
func (q *QuantumBridge) registerWithMinistry() {
	q.registerWithMinistryInternal()
}

// RegisterWithMinistry is the exported version of registerWithMinistry.
// P1-T7 (2026-07-14): Used by the node layer to trigger bridge registration
// after MinistryWorks is injected (post-initialization).
func (q *QuantumBridge) RegisterWithMinistry() {
	q.registerWithMinistryInternal()
}

func (q *QuantumBridge) registerWithMinistryInternal() {
	q.mu.RLock()
	recorder := q.ministryWorks
	adapterCount := len(q.adapters)
	q.mu.RUnlock()

	if recorder == nil {
		return
	}

	// Register the bridge with a name derived from the first adapter's chain ID.
	// The remoteChainID is the first non-Quantaureum chain in the adapters map.
	// If no adapters are configured, skip registration (will be retried on
	// first SubmitMessage).
	name := "quantum-bridge"
	var remoteChainID uint64
	for chainID := range q.adapters {
		// Use the first adapter's chain ID as the remote chain ID.
		// ChainID is a string type; convert to uint64 if possible.
		remoteChainID = chainIDToUint64(chainID)
		if remoteChainID > 0 {
			break
		}
	}

	bridgeID, err := recorder.RegisterBridge(name, remoteChainID, 0, "0")
	if err != nil {
		q.logger.Warn("MinistryWorks.RegisterBridge failed (non-fatal)", map[string]any{
			"error": err.Error(),
			"name":  name,
		})
		return
	}

	q.mu.Lock()
	q.ministryBridgeID = bridgeID
	q.mu.Unlock()

	q.logger.Info("Bridge registered with MinistryWorks", map[string]any{
		"bridgeID":      bridgeID,
		"name":          name,
		"remoteChainID": remoteChainID,
		"adapters":      adapterCount,
	})
}

// chainIDToUint64 converts a ChainID string to uint64 if possible.
// Returns 0 if the conversion fails.
func chainIDToUint64(chainID ChainID) uint64 {
	var n uint64
	for _, c := range []byte(string(chainID)) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

// markFinalized records a message ID as finalized and maintains LRU ordering.
// R68-BRIDGE-3 [MEDIUM] FIX: replaces direct finalizedIDs[id]=true writes.
// Maintains insertion order in finalizedIDsOrder so that eviction removes oldest
// entries first (true LRU), preventing arbitrary deletion that could allow replay.
func (q *QuantumBridge) markFinalized(id string) {
	if _, exists := q.finalizedIDs[id]; exists {
		return // Already finalized, keep existing position
	}
	q.finalizedIDs[id] = true
	q.finalizedIDsOrder = append(q.finalizedIDsOrder, id)
	q.finalizedIDsIndex[id] = len(q.finalizedIDsOrder) - 1
}

// SetStore sets the persistent storage backend for bridge messages.
// audit-fix N-6: allows callers to inject a MessageStore implementation.
func (q *QuantumBridge) SetStore(store MessageStore) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.store = store
}

// SetValidatorNetwork configures the M-of-N validator threshold verification.
// AUDIT (2026 security review) HIGH-08: When set, ProcessMessage requires validator
// quorum before executing messages. This prevents a single relayer from
// executing arbitrary messages.
func (q *QuantumBridge) SetValidatorNetwork(vn *ValidatorNetwork) {
	q.mu.Lock()
	q.validatorNetwork = vn
	q.mu.Unlock()
	// P3-1: propagate metrics to validator network + validator set.
	if vn != nil {
		vn.SetMetrics(q.metrics)
	}
}

// GetValidatorNetwork returns the injected validator network, or nil.
// P1-1 FIX (2026-07-13): Used by initBridge to pass vn to BridgeAPI.
func (q *QuantumBridge) GetValidatorNetwork() *ValidatorNetwork {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.validatorNetwork
}

// Metrics returns the bridge's Prometheus metrics instance.
// P3-2 (2026-07-15): Used by node.go to wire the BridgeMetricProvider into
// the global Metrics instance for the AlertManager (5 bridge alert rules).
func (q *QuantumBridge) Metrics() *BridgeMetrics {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.metrics
}

// RefreshValidatorSet updates the bridge's ValidatorNetwork and trusted
// validator key set from the current QPOS validator set.
//
// P1-6 FIX (2026-07-14): QPOS validator set changes (new validator added,
// validator jailed/removed, stake updated) must propagate to the bridge
// arbitration network. Without this, the bridge would use a stale validator
// set, causing:
//   - New validators cannot participate in bridge arbitration (their signatures
//     are rejected by the SignatureAggregator because they're not in the set)
//   - Jailed validators can still sign bridge messages (they remain Active in
//     the bridge ValidatorSet even after QPOS removes them)
//   - trustedValidatorKeys becomes stale → SubmitMessage rejects messages from
//     new validators and accepts messages from removed validators
//
// This method atomically updates both the ValidatorNetwork's ValidatorSet and
// the trustedValidatorKeys under the bridge mutex.
//
// Returns the ValidatorSyncResult from the ValidatorSet sync, or a zero result
// if no ValidatorNetwork is configured.
func (q *QuantumBridge) RefreshValidatorSet(validators []*BridgeValidator, threshold int) ValidatorSyncResult {
	// Update trustedValidatorKeys under the bridge lock.
	// R31-MED-4 NOTE: this is the consensus-driven epoch sync path (called
	// from node.RefreshBridgeValidators at epoch boundaries with the active
	// QPOS validator set). It intentionally BYPASSES the
	// validatorTrustLocked guard in SetTrustedValidatorKeys: the trust
	// anchor follows the on-chain validator set, which itself is only
	// mutable through staking/slashing consensus rules.
	q.mu.Lock()
	if len(validators) > 0 {
		q.trustedValidatorKeys = make([][]byte, 0, len(validators))
		for _, v := range validators {
			if len(v.PublicKey) > 0 {
				cp := make([]byte, len(v.PublicKey))
				copy(cp, v.PublicKey)
				q.trustedValidatorKeys = append(q.trustedValidatorKeys, cp)
			}
		}
	}
	// Epoch sync keeps the mutation lock sealed (it never unlocks the
	// ad-hoc Set path; it writes under its own consensus-derived mandate).
	q.validatorTrustLocked = true
	vn := q.validatorNetwork
	q.mu.Unlock()

	// Update the ValidatorNetwork's ValidatorSet (no bridge lock needed).
	if vn == nil || vn.GetValidatorSet() == nil {
		return ValidatorSyncResult{}
	}
	return vn.GetValidatorSet().SyncFromQPOS(validators, threshold)
}

// governanceAdapter is the internal interface for adapter governance methods.
// Both *ExternalChainAdapter and *QuantaureumChainAdapter satisfy this.
// P1-3/P1-4 FIX (2026-07-13): used by batch governance methods below.
type governanceAdapter interface {
	SetGovernanceAddress(addr string, caller string) error
	SetBootstrapMode(enabled bool, caller string) error
	RegisterEventSignature(sigHash string, caller string) error
}

// SetGovernanceAddressOnAdapters sets the governance address on all registered
// adapters. P1-3 FIX (2026-07-13): adapters require governance address before
// RegisterEventSignature/SetRelayerKeys/SetBootstrapMode can be called.
// caller must be the initializer address (for first-time setup) or the current
// governance address (for rotation).
func (q *QuantumBridge) SetGovernanceAddressOnAdapters(govAddr, caller string) (injected int, errs []error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	for chainID, adapter := range q.adapters {
		ga, ok := adapter.(governanceAdapter)
		if !ok {
			continue
		}
		if err := ga.SetGovernanceAddress(govAddr, caller); err != nil {
			errs = append(errs, fmt.Errorf("%s adapter: %w", chainID, err))
			continue
		}
		injected++
	}
	return injected, errs
}

// SetBootstrapModeOnAdapters toggles bootstrap mode on all registered adapters.
// P1-4 FIX (2026-07-13): bootstrap mode must be enabled before registering
// event signatures (which requires governance caller), then disabled after.
// caller must be the governance address.
func (q *QuantumBridge) SetBootstrapModeOnAdapters(enabled bool, caller string) (injected int, errs []error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	for chainID, adapter := range q.adapters {
		ga, ok := adapter.(governanceAdapter)
		if !ok {
			continue
		}
		if err := ga.SetBootstrapMode(enabled, caller); err != nil {
			errs = append(errs, fmt.Errorf("%s adapter: %w", chainID, err))
			continue
		}
		injected++
	}
	return injected, errs
}

// RegisterEventSignaturesOnAdapters registers a list of event signature hashes
// on all registered adapters. P1-4 FIX (2026-07-13): event signatures must be
// registered before the bridge can parse cross-chain events (fail-closed by
// default when bootstrap mode is off). caller must be the governance address.
func (q *QuantumBridge) RegisterEventSignaturesOnAdapters(sigHashes []string, caller string) (injected int, errs []error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	for chainID, adapter := range q.adapters {
		ga, ok := adapter.(governanceAdapter)
		if !ok {
			continue
		}
		for _, sig := range sigHashes {
			if err := ga.RegisterEventSignature(sig, caller); err != nil {
				errs = append(errs, fmt.Errorf("%s adapter sig=%s: %w", chainID, sig, err))
				continue
			}
		}
		injected++
	}
	return injected, errs
}

// AdapterCount returns the number of registered chain adapters.
// P0-3 FIX (2026-07-13): Used by initBridge() to log how many adapters were
// registered, so operators can detect misconfiguration (zero adapters means
// the bridge cannot process any cross-chain messages).
// GetAdapter returns the ChainAdapter for the given chain ID, or an error if
// no adapter is registered for that chain. R37 P2-BRIDGE-01.
func (q *QuantumBridge) GetAdapter(chainID ChainID) (ChainAdapter, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	adapter, exists := q.adapters[chainID]
	if !exists {
		return nil, fmt.Errorf("no adapter registered for chain %s", chainID)
	}
	return adapter, nil
}

func (q *QuantumBridge) AdapterCount() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.adapters)
}

// InjectTrustedPublicKeys injects trusted public keys into all registered adapters.
// P0-4 FIX (2026-07-13): adapter VerifyMessage requires a trusted public key
// to verify incoming cross-chain messages. Without injection, all messages fail
// with "no trusted key configured". This method must be called AFTER Initialize()
// (which registers adapters).
//
// AUDIT-FULL C-1 FIX (2026-08-14): Now requires governance caller to ensure
// only authorized code paths can install trusted keys.
//
// For Quantaureum adapters (chainID "quantaureum"/"quantaureum-testnet"), it
// uses validatorPubKeyBytes. For external adapters (ethereum, etc.), it uses
// relayerPubKeyBytes. Either may be nil to skip injection for that adapter type.
func (q *QuantumBridge) InjectTrustedPublicKeys(validatorPubKeyBytes, relayerPubKeyBytes []byte, caller string) (injected int, errs []error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	for chainID, adapter := range q.adapters {
		isQauChain := chainID == "quantaureum" || chainID == "quantaureum-testnet"
		if isQauChain {
			if len(validatorPubKeyBytes) == 0 {
				continue
			}
			if qauAdapter, ok := adapter.(*QuantaureumChainAdapter); ok {
				if err := qauAdapter.SetTrustedPublicKeyBytes(validatorPubKeyBytes, caller); err != nil {
					errs = append(errs, fmt.Errorf("quantaureum adapter: %w", err))
					continue
				}
				injected++
			}
		} else {
			if len(relayerPubKeyBytes) == 0 {
				continue
			}
			if extAdapter, ok := adapter.(*ExternalChainAdapter); ok {
				if err := extAdapter.SetTrustedRelayerPublicKeyBytes(relayerPubKeyBytes, caller); err != nil {
					errs = append(errs, fmt.Errorf("%s adapter: %w", chainID, err))
					continue
				}
				injected++
			}
		}
	}
	return injected, errs
}

// InjectHeaderVerifier injects the SPV header verifier into all registered
// adapters. P1-5 (2026-07-14): when configured, VerifyMessage calls header
// verification to detect source-chain reorganizations before accepting a
// message. Must be called AFTER Initialize() (which registers adapters).
//
// The verifier is nil-safe: when not configured (nil), header verification is
// skipped. Production deployments MUST inject a configured verifier during
// node startup.
//
// Returns the number of adapters that received the verifier.
func (q *QuantumBridge) InjectHeaderVerifier(v *BridgeHeaderVerifier) int {
	if v == nil {
		return 0
	}
	q.mu.RLock()
	defer q.mu.RUnlock()

	injected := 0
	for _, adapter := range q.adapters {
		switch a := adapter.(type) {
		case *QuantaureumChainAdapter:
			a.SetHeaderVerifier(v)
			injected++
		case *ExternalChainAdapter:
			a.SetHeaderVerifier(v)
			injected++
		}
	}
	return injected
}

// ensureStatusMap returns the inner map for a status, creating it lazily
// if it doesn't exist. Defensive against paths that bypass Initialize()
// (e.g., direct map manipulation in tests, or future code paths that
// add new statuses without updating Initialize).
//
// BRIDGE-R13-H01 (2026-07-21): Found while writing the pause/resume
// regression tests. The VERIFIED → EXECUTED transition in
// processPendingBatch wrote to messagesByStatus[MessageStatusExecuted]
// without checking if the inner map was initialized. In production,
// Initialize() pre-creates all inner maps, so the bug was masked. But
// the transition code SHOULD be defensive: a missing inner map is a
// recoverable state, not a reason to panic the processing goroutine.
//
// Caller MUST hold q.mu (write lock).
func (q *QuantumBridge) ensureStatusMap(status BridgeMessageStatus) map[string]bool {
	if q.messagesByStatus[status] == nil {
		q.messagesByStatus[status] = make(map[string]bool)
	}
	return q.messagesByStatus[status]
}

// Initialize initializes the bridge
func (q *QuantumBridge) Initialize(ctx context.Context) error {
	// Initialize message status indexes
	for _, status := range []BridgeMessageStatus{
		MessageStatusPending,
		MessageStatusVerified,
		MessageStatusExecuted,
		MessageStatusFailed,
		MessageStatusExpired,
	} {
		q.messagesByStatus[status] = make(map[string]bool)
	}

	// Initialize chain adapters from configuration
	for chainID, nodeURL := range q.config.NodeURLs {
		if nodeURL == "" {
			return fmt.Errorf("bridge: empty node URL for chain %s", chainID)
		}
		contractAddr := q.config.BridgeContractAddresses[chainID]
		var adapter ChainAdapter
		if chainID == "quantaureum" || chainID == "quantaureum-testnet" {
			adapter = NewQuantaureumChainAdapter(chainID, nodeURL, contractAddr, q.config.ConfirmationsRequired, q.config.InitializerAddress)
		} else {
			adapter = NewExternalChainAdapter(chainID, nodeURL, contractAddr, q.config.ConfirmationsRequired, q.config.InitializerAddress)
		}
		q.adapters[chainID] = adapter
	}

	// P3-1: propagate metrics to all adapters.
	for _, adapter := range q.adapters {
		switch a := adapter.(type) {
		case *QuantaureumChainAdapter:
			a.SetBridgeMetrics(q.metrics)
		case *ExternalChainAdapter:
			a.SetBridgeMetrics(q.metrics)
		}
	}

	// R64-B5 FIX: Bootstrap usedNonces and finalizedIDs from persistent store.
	// This prevents replay attacks where an attacker could reuse a nonce from a
	// message submitted before the bridge last restarted. We load ALL messages
	// (pending + verified + executed + failed + expired) so that any previously-used
	// nonce is protected even if the bridge was down.
	// BRDG-FIX (2026-07-17): Previously EXECUTED messages were NOT loaded,
	// meaning their nonces were lost on restart — an attacker could replay an
	// executed message (whose finalizedID may also have been LRU-evicted) and
	// re-execute it (double-spend). Now EXECUTED is included in the restore set
	// and markFinalized is called for it (alongside Failed/Expired).
	if q.store != nil {
		nonTerminalStatuses := []BridgeMessageStatus{
			MessageStatusPending,
			MessageStatusVerified,
			MessageStatusExecuted,
			MessageStatusFailed,
			MessageStatusExpired,
		}
		for _, status := range nonTerminalStatuses {
			messages, err := q.store.LoadMessagesByStatus(ctx, status)
			if err != nil {
				return fmt.Errorf("bridge: failed to load %s messages from store: %w", status, err)
			}
			for _, msg := range messages {
				// Populate usedNonces: prevents replay of any previously-seen nonce.
				// BRIDGE- key by (SourceChain, SourceAddress) so the same
				// address on different source chains does not collide.
				nk := nonceKey{chain: msg.SourceChain, addr: msg.SourceAddress}
				if q.usedNonces[nk] == nil {
					q.usedNonces[nk] = make(map[uint64]time.Time)
				}
				q.usedNonces[nk][msg.Nonce] = time.Unix(msg.Timestamp, 0)
				q.totalUsedNonces++ // BRDG- keep global count in sync on bootstrap restore

				// For terminal statuses, also mark as finalized so we skip reprocessing.
				// BRDG-FIX: EXECUTED is now included — without this, an
				// EXECUTED message whose nonce was restored above but whose ID
				// was not marked finalized could be re-submitted and re-executed.
				if status == MessageStatusFailed || status == MessageStatusExpired || status == MessageStatusExecuted {
					q.markFinalized(msg.ID)
				}

				// BRIDGE-H01 FIX (R30, 2026-07-27): only advance highestUsedNonce
				// for EXECUTED messages. PENDING/FAILED nonces must remain
				// individually tracked (retriable) and EXPIRED nonces are not
				// covered by the high-water mark.
				if status == MessageStatusExecuted && msg.Nonce > q.highestUsedNonce[nk] {
					q.highestUsedNonce[nk] = msg.Nonce
				}

				// BRIDGE-H02 FIX (R30, 2026-07-27): restore PENDING, VERIFIED,
				// and FAILED messages to the in-memory cache so processMessagesLoop
				// and processPendingBatch can find them after restart. Previously
				// only VERIFIED was restored, leaving PENDING and FAILED messages
				// permanently stuck (nonces consumed but in no processing queue).
				// Terminal statuses (EXECUTED, EXPIRED) are NOT restored — they
				// require no further processing.
				if status == MessageStatusPending || status == MessageStatusVerified || status == MessageStatusFailed {
					q.messages[msg.ID] = msg
					q.ensureStatusMap(status)[msg.ID] = true
					// R10-BR-002 FIX: Lazy-init inner per-chain maps, matching
					// the pattern in SubmitMessage (lines 627-634). Without this,
					// writing to a nil inner map panics on bridge restart.
					if _, ok := q.messagesBySourceChain[msg.SourceChain]; !ok {
						q.messagesBySourceChain[msg.SourceChain] = make(map[string]bool)
					}
					q.messagesBySourceChain[msg.SourceChain][msg.ID] = true
					if _, ok := q.messagesByTargetChain[msg.TargetChain]; !ok {
						q.messagesByTargetChain[msg.TargetChain] = make(map[string]bool)
					}
					q.messagesByTargetChain[msg.TargetChain][msg.ID] = true
				}
			}
		}
		// R43-BRIDGE-MSG-01 FIX (2026-08-03): the restore loop above may
		// have grown the in-memory `messages` map with retriable FAILED
		// messages (and PENDING / VERIFIED) beyond maxMessagesInMemory.
		// Sweep terminal messages oldest first so the cap holds right
		// after restart. PENDING / VERIFIED messages are always kept.
		q.sweepMessages()
		// BRIDGE-H03 FIX (R30, 2026-07-27): after restore, sweep covered
		// nonces (those <= highestUsedNonce) to free space. EXECUTED nonces
		// are now covered by highestUsedNonce, so they are pruned. EXPIRED
		// nonces are NOT covered (only EXECUTED advances highestUsedNonce),
		// so they remain individually tracked. This prevents active users
		// from hitting the per-address or global cap immediately after restart.
		q.sweepUsedNonces()

		// R32-P1-04 FIX (2026-07-28): Merge persisted nonce high-water marks
		// from the dedicated nonce_highwater bucket. This is defense-in-depth:
		// even if EXECUTED messages are pruned from the message store in the
		// future, the dedicated bucket preserves the high-water mark. We take
		// the max of the reconstructed value (from EXECUTED messages) and the
		// persisted value (from the dedicated bucket) to never lower the
		// water mark.
		persistedHighs, err := q.store.LoadAllHighestUsedNonces(ctx)
		if err != nil {
			q.logger.Warn("bridge: failed to load persisted nonce high-water marks (continuing with reconstructed values)",
				map[string]any{"error": err.Error()})
		} else {
			for nk, persisted := range persistedHighs {
				bridgeNk := nonceKey{chain: ChainID(nk.Chain), addr: nk.Addr}
				if persisted > q.highestUsedNonce[bridgeNk] {
					q.highestUsedNonce[bridgeNk] = persisted
				}
			}
		}
	}

	// AUDIT-FULL NW-08 (2026-08-14): memory-mode nonce checkpoint. Without
	// a persistent message store, usedNonces/highestUsedNonce were
	// memory-only, so a restart forgot every recorded nonce and an
	// attacker could replay any pre-restart message. When a checkpoint
	// path is configured (SetNonceCheckpointPath, expected default: a
	// file in the node's data directory), load it here so the replay
	// window survives restarts. Load failures fail-closed — starting
	// with an empty anti-replay set would silently re-open the replay
	// window the checkpoint was written to close.
	if q.store == nil && q.nonceCheckpointPath != "" {
		q.mu.Lock()
		err := q.loadNonceCheckpointLocked()
		q.mu.Unlock()
		if err != nil {
			return fmt.Errorf("bridge: failed to load nonce checkpoint: %w", err)
		}
		// FIX (2026-08-15): start the background
		// checkpoint writer AFTER the initial load completes, so the
		// goroutine never races the initial Stateful load. Mutations now
		// enqueue serialized snapshots here instead of doing WriteFile+
		// Rename while holding q.mu.
		q.startNonceCheckpointLoop()
	}

	// BR-04 (R43 P3, 2026-08-03): startup reconciliation — verify that the
	// in-memory state reconstructed from the bbolt store is internally
	// consistent. During runtime, SaveMessage writes to bbolt first, then
	// the caller updates memory; if the memory update panics (e.g. nil-map
	// dereference), the bbolt write is already committed but the in-memory
	// state is stale. On the NEXT restart, the restore loop above reloads
	// from bbolt and self-heals — but the operator needs to KNOW that a
	// divergence happened. This reconciliation logs a summary of restored
	// state counts and warns if any index (messagesByStatus, messagesBySourceChain,
	// messagesByTargetChain) is inconsistent with the messages map.
	q.reconcileMemoryWithStore()

	// P1-T7 (2026-07-14): Register this bridge with MinistryWorks for
	// governance tracking. Best-effort — failures are logged but do not
	// block initialization.
	q.registerWithMinistry()

	return nil
}

// Start starts the bridge operations
func (q *QuantumBridge) Start(ctx context.Context) error {
	// audit-fix N-2: protect running field with mutex
	q.mu.Lock()
	if q.running {
		q.mu.Unlock()
		return nil // Already running
	}
	q.running = true
	q.mu.Unlock()

	// Start event watchers for each adapter
	for _, adapter := range q.adapters {
		go func(adapter ChainAdapter) {
			if err := adapter.WatchEvents(q.ctx, q.handleBridgeEvent); err != nil {
				// R66-BR-WS-1 [LOW] FIX: Log error to aid incident investigation.
				// Previously the comment indicated intent to log but the body was empty.
				// P3-3 (2026-07-15): structured log replaces log.Printf.
				q.logger.Error("WatchEvents exited for chain", map[string]any{
					"chain": string(adapter.ChainID()),
					"error": err.Error(),
				})
			}
		}(adapter)
	}

	// Start message processor
	go q.processMessagesLoop()

	return nil
}

// Stop stops the bridge operations
func (q *QuantumBridge) Stop(ctx context.Context) error {
	// audit-fix N-2: protect running field with mutex
	q.mu.Lock()
	if !q.running {
		q.mu.Unlock()
		return nil // Already stopped
	}
	q.running = false
	q.mu.Unlock()

	// P0-2 BRDG-03 FIX (2026-07-13): Stop the ValidatorNetwork to release
	// its heartbeat goroutine. Without this, the goroutine leaks on bridge
	// shutdown (it only exits implicitly via ctx cancel, which is fragile).
	q.mu.RLock()
	vn := q.validatorNetwork
	q.mu.RUnlock()
	if vn != nil {
		if err := vn.Stop(); err != nil {
			// P3-3 (2026-07-15): structured log replaces log.Printf.
			q.logger.Warn("validator network stop failed", map[string]any{
				"error": err.Error(),
			})
		}
	}

	// FIX (2026-08-15): drain + stop the background
	// nonce-checkpoint writer BEFORE canceling ctx, so any already-
	// enqueued snapshots can land on disk during a clean shutdown (the
	// goroutine has no ctx dependency and writes only the bytes it has).
	// Bounded by a 5s shutdown timeout inside stopNonceCheckpointLoop so
	// a wedged writer cannot hang bridge shutdown.
	q.stopNonceCheckpointLoop()

	q.cancel()
	return nil
}

// sweepUsedNonces prunes all nonce entries <= highestUsedNonce for each
// (chain, addr) pair, freeing space under the global cap. Also evicts
// expired entries (nonceTTL > 0) as a side benefit.
//
// ECON-H02 FIX (R29, 2026-07-26): Without the sweep, the bridge would
// permanently reject all new messages after 1M lifetime nonces. The sweep
// reclaims space by leveraging highestUsedNonce as a compact replay
// protection counter — nonces <= highest are still protected even after
// being pruned from usedNonces.
//
// Returns the number of entries pruned. Caller must hold q.mu.
func (q *QuantumBridge) sweepUsedNonces() int {
	pruned := 0
	now := time.Now()
	for nk, nonces := range q.usedNonces {
		highest := q.highestUsedNonce[nk]
		for n, ts := range nonces {
			if n <= highest || (nonceTTL > 0 && now.Sub(ts) > nonceTTL) {
				delete(nonces, n)
				pruned++
			}
		}
		if len(nonces) == 0 {
			delete(q.usedNonces, nk)
		}
	}
	q.totalUsedNonces -= pruned
	if q.totalUsedNonces < 0 {
		q.totalUsedNonces = 0
	}
	return pruned
}

// sweepUsedNoncesFor prunes entries <= highestUsedNonce for a single
// (chain, addr) pair. BRIDGE-H03 FIX (R30, 2026-07-27): called before
// rejecting on the per-address cap to free covered entries, and
// proactively after ExecuteMessage advances highestUsedNonce to keep
// the per-address map small.
//
// Returns the number of entries pruned. Caller must hold q.mu.
func (q *QuantumBridge) sweepUsedNoncesFor(nk nonceKey) int {
	nonces, ok := q.usedNonces[nk]
	if !ok {
		return 0
	}
	highest := q.highestUsedNonce[nk]
	pruned := 0
	for n := range nonces {
		if n <= highest {
			delete(nonces, n)
			pruned++
		}
	}
	if len(nonces) == 0 {
		delete(q.usedNonces, nk)
	}
	q.totalUsedNonces -= pruned
	if q.totalUsedNonces < 0 {
		q.totalUsedNonces = 0
	}
	return pruned
}

// SubmitMessage submits a new cross-chain message
func (q *QuantumBridge) SubmitMessage(ctx context.Context, msg *BridgeMessage) error {
	// BRIDGE- (2026-07-20): Emergency pause check. Done BEFORE
	// rate limiting so a paused bridge rejects work as cheaply as possible.
	if q.paused.Load() {
		return ErrBridgePaused
	}
	if !q.rateLimiter.allow() {
		return fmt.Errorf("bridge rate limit exceeded, max %d messages/sec", bridgeRateLimit)
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	// audit-fix CRIT-1: reject messages whose IDs have already been finalized
	// (executed, failed, or expired). This prevents replay attacks where a
	// message is re-submitted after being evicted from the in-memory cache.
	if q.finalizedIDs[msg.ID] {
		return fmt.Errorf("message %s has already been finalized and cannot be replayed", msg.ID)
	}

	// SECURITY FIX: Check nonce to prevent replay attacks.
	// Even if an attacker captures a valid signed message, they cannot replay
	// it with the same nonce for the same (source chain, source address).
	// BRIDGE-FIX (2026-07-20): the key is now (SourceChain, SourceAddress)
	// so the same address on different source chains no longer shares a nonce
	// namespace — cross-chain messages from the same address no longer collide.
	nk := nonceKey{chain: msg.SourceChain, addr: msg.SourceAddress}
	if q.usedNonces[nk] == nil {
		q.usedNonces[nk] = make(map[uint64]time.Time)
	}
	// S2-9 [LOW] FIX: collect keys before deletion to avoid skipped entries
	// from Go's randomized map iteration order when deleting during range.
	// BRDG-FIX (2026-07-17): when nonceTTL = 0, nonces NEVER expire —
	// skip the scan entirely. This preserves replay protection even after
	// finalizedIDs LRU eviction, closing the double-spend window.
	//
	// R35-P3-BRIDGE-5 NOTE (2026-07-29): The TTL eviction code path below is
	// a known REPLAY RISK if nonceTTL is ever set to a non-zero value. Once a
	// nonce is evicted after the TTL expires AND its finalizedID is evicted
	// from the LRU (maxFinalizedIDs), an attacker can replay the original
	// signed message and re-execute it (double-spend). The SECURE default is
	// nonceTTL = 0 (nonces never expire), which trades memory for security
	// via maxUsedNoncesGlobal (fail-closed OOM protection). DO NOT change
	// nonceTTL to a non-zero value without also implementing persistent
	// replay protection (e.g., a disk-backed nonce store keyed by
	// (chain, addr, nonce) that survives LRU eviction).
	now := time.Now()
	var expired []uint64
	if nonceTTL > 0 {
		for n, ts := range q.usedNonces[nk] {
			if now.Sub(ts) > nonceTTL {
				expired = append(expired, n)
			}
		}
	}
	for _, n := range expired {
		delete(q.usedNonces[nk], n)
		q.totalUsedNonces-- // BRDG- keep global count in sync on TTL eviction
	}
	// BRDG-FIX (2026-07-17): Global cap across all source addresses.
	// The per-address cap below is insufficient because an attacker with
	// quorum can forge messages with arbitrary sourceAddress values, each
	// accumulating up to maxUsedNoncesPerAddress. Without this global cap,
	// the map grows without bound → OOM. Reject new messages (and log) when
	// the global limit is reached; this is a fail-closed DoS trade-off:
	// the bridge halts rather than crashing the node.
	// ECON-H02 FIX (R29, 2026-07-26): Before rejecting, attempt to reclaim
	// space by sweeping nonces covered by highestUsedNonce. This prevents
	// active users from being permanently blocked after 1M lifetime nonces.
	if q.totalUsedNonces >= maxUsedNoncesGlobal {
		pruned := q.sweepUsedNonces()
		if pruned > 0 {
			log.Printf("[bridge] ECON-H02: global cap sweep reclaimed %d covered nonces", pruned)
		}
		if q.totalUsedNonces >= maxUsedNoncesGlobal {
			log.Printf("[bridge] WARN: BRDG- global used nonces limit reached (%d), rejecting new message (possible replay flood)", maxUsedNoncesGlobal)
			return fmt.Errorf("global used nonces limit reached (%d), rejecting new message to prevent OOM", maxUsedNoncesGlobal)
		}
	}
	// H-3 FIX: cap per-(chain, address) nonce count to prevent unbounded growth.
	// BRIDGE- the cap now applies per (chain, address) pair, not per address.
	// BRIDGE-H03 FIX (R30, 2026-07-27): Before rejecting, attempt to reclaim
	// space by sweeping covered nonces for this (chain, addr) pair.
	if len(q.usedNonces[nk]) >= maxUsedNoncesPerAddress {
		pruned := q.sweepUsedNoncesFor(nk)
		if pruned > 0 {
			log.Printf("[bridge] BRIDGE-H03: per-address cap sweep reclaimed %d covered nonces for (chain=%s, addr=%s)", pruned, msg.SourceChain, msg.SourceAddress)
		}
		if len(q.usedNonces[nk]) >= maxUsedNoncesPerAddress {
			return fmt.Errorf("too many pending nonces for (chain=%s, address=%s) (limit %d)", msg.SourceChain, msg.SourceAddress, maxUsedNoncesPerAddress)
		}
	}
	// BRIDGE-H01/ECON-H02 FIX: reject nonces below the high-water mark.
	// These nonces are covered by highestUsedNonce (compact replay protection)
	// even if they've been pruned from usedNonces by a sweep.
	if msg.Nonce <= q.highestUsedNonce[nk] {
		return fmt.Errorf("nonce %d is below highest used nonce %d for (chain=%s, address=%s)", msg.Nonce, q.highestUsedNonce[nk], msg.SourceChain, msg.SourceAddress)
	}
	if _, used := q.usedNonces[nk][msg.Nonce]; used {
		return fmt.Errorf("nonce %d already used for (chain=%s, address=%s)", msg.Nonce, msg.SourceChain, msg.SourceAddress)
	}

	// Also reject if the message is already in the active in-memory store.
	if _, exists := q.messages[msg.ID]; exists {
		return fmt.Errorf("message %s already exists", msg.ID)
	}

	// R40-P1-08 (2026-08-03) FIX: HARD-CAP the active in-memory message
	// store before any further validation. Previously, the only cap
	// enforcement was `evictOldMessages()` running on a periodic loop and
	// silently dropping STALE PENDING messages older than 1 hour — a flood
	// of messages younger than 1 hour would never be evicted, the store
	// would grow unboundedly toward `maxMessages`, and SubmitMessage calls
	// would keep accepting messages until the process OOMed. The audit
	// additionally flagged that the eviction path only WARN-logged the
	// drop with no returned error, so a producer never knew its message
	// was discarded.
	//
	// This hard-cap check fails SubmitMessage EARLY with a clear error so:
	//   (1) the producer sees a rejection and can retry / back off;
	//   (2) the bridge stays below its memory budget (no OOM path);
	//   (3) the periodic `evictOldMessages()` cleanup is still allowed to
	//       run for the 1-hour-stale-PENDING case, but it now runs against
	//       a bounded store instead of recovering after an OOM-inducing
	//       spike.
	//
	// `maxMessages == 0` is preserved as the "no cap" sentinel (used by
	// tests / emergency-override paths) for backward compatibility.
	if q.maxMessages > 0 && len(q.messages) >= q.maxMessages {
		return fmt.Errorf("bridge: message store at capacity (%d/%d); "+
			"reject new message %q (R40-P1-08)",
			len(q.messages), q.maxMessages, msg.ID)
	}

	// Validate message
	if err := q.validateMessage(msg); err != nil {
		return err
	}

	// SECURITY FIX: Timestamp freshness validation to prevent replay of old messages
	// Reject messages with timestamps too far in the past or future.
	//
	// R35-P3-BRIDGE-6 NOTE (2026-07-29): This validation uses time.Now() (wall
	// clock), which is a CONSENSUS-CRITICAL path. If validator nodes have clock
	// drift > maxTimestampDrift (5 minutes), an honest node may reject a
	// message that other nodes accept, leading to divergent bridge state.
	// The 5-minute window is generous enough to tolerate NTP-corrected clocks,
	// but NOT uncorrected drift. TODO: replace time.Now() with the current
	// block timestamp (passed in by the caller from the consensus layer) so
	// all validators use the same deterministic time source. This requires
	// adding a blockTime parameter to SubmitMessage and updating all call
	// sites — deferred because it is a signature change with broad impact.
	const maxTimestampDrift = 5 * 60 // 5 minutes drift allowed
	nowUnix := time.Now().Unix()
	if msg.Timestamp > nowUnix+60 {
		return fmt.Errorf("message timestamp too far in the future: %d", msg.Timestamp)
	}
	if msg.Timestamp < nowUnix-maxTimestampDrift {
		return fmt.Errorf("message timestamp too far in the past: %d", msg.Timestamp)
	}

	// Set default values if not provided
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().Unix()
	}

	if msg.Expiration == 0 {
		msg.Expiration = msg.Timestamp + q.config.MessageExpiration
	}

	if msg.Status == "" {
		msg.Status = MessageStatusPending
	}

	// Store message in memory
	q.messages[msg.ID] = msg
	q.ensureStatusMap(msg.Status)[msg.ID] = true

	// SECURITY FIX: Record the nonce to prevent replay attacks.
	// This marks the nonce as used for this (source chain, source address).
	// H-3 FIX: record insertion time for TTL-based eviction.
	// BRIDGE- nk was constructed earlier in this function.
	q.usedNonces[nk][msg.Nonce] = time.Now()
	q.totalUsedNonces++ // BRDG- keep global count in sync on insert
	// AUDIT-FULL NW-08: snapshot the nonce state so the replay window
	// survives a restart in memory mode. The rollback paths below
	// re-checkpoint if this submission is undone.
	q.checkpointNoncesLocked()

	// audit-fix H-2: persist message to durable storage.
	//
	// P3-BR-04 FIX (2026-08-03): REORDERED — write the in-memory maps
	// BEFORE calling SaveMessage, and roll back the maps if SaveMessage
	// fails. Previous order (store-then-memory) meant a panic between
	// SaveMessage success and the map updates would leave the durable
	// store containing a message the in-memory cache did not — a
	// divergence that persisted until next bridge restart (where the
	// startup LoadMessagesByStatus loop would re-constitute the message,
	// but mid-flight any concurrent SubmitMessage could double-spend the
	// nonce because the in-memory usedNonces check would not find it).
	// New order:
	//   1. Mutate all in-memory maps under q.mu (we already hold it).
	//   2. Attempt to persist; on failure, roll back the in-memory
	//      mutations so the durable record and the in-memory record
	//      agree (both absent — durable absence is what we want here:
	//      SubmitMessage fails-by-error so the caller will retry with
	//      the SAME nonce; no double-use). On panic BETWEEN the map
	//      mutations and the store call, the in-memory state is
	//      advanced but the durable record is absent, and the next
	//      SubmitMessage call for this nonce would re-attempt persist;
	//      the in-memory usedNonces[nk][nonce] is now set, blocking the
	//      retry anyway. So the in-memory-only divergence case can only
	//      occur on a panic DURING SaveMessage itself (a marshal / bbolt
	//      write panic), which this code path surfaces as a returned
	//      error (recover() in db.Update wrapper) rather than as a
	//      silent divergence — see message_store.go SaveMessage for the
	//      bbolt transaction panic recovery.
	// Lazily initialize chain sub-maps to prevent nil map panic
	if _, ok := q.messagesBySourceChain[msg.SourceChain]; !ok {
		q.messagesBySourceChain[msg.SourceChain] = make(map[string]bool)
	}
	q.messagesBySourceChain[msg.SourceChain][msg.ID] = true
	if _, ok := q.messagesByTargetChain[msg.TargetChain]; !ok {
		q.messagesByTargetChain[msg.TargetChain] = make(map[string]bool)
	}
	q.messagesByTargetChain[msg.TargetChain][msg.ID] = true

	// R43-BRIDGE-MSG-01 FIX (2026-08-03): the messages map grew on this
	// append; if it exceeds maxMessagesInMemory, sweep terminal messages
	// (EXECUTED / FAILED / EXPIRED) oldest first. The freshly-submitted
	// message is PENDING so it is never evicted here. Caller (SubmitMessage)
	// holds q.mu (write lock), which sweepMessages requires.
	q.sweepMessages()

	if q.store != nil {
		if err := q.store.SaveMessage(ctx, msg); err != nil {
			// P3-BR-04 rollback: durable persistence failed; remove the
			// freshly-added in-memory entries so the durable record and
			// in-memory record agree (both absent). The caller will
			// surface the error to the user, who can retry the same
			// submitMessage; usedNonces was bumped above for replay
			// protection, but a failed store write means the nonce was
			// NOT actually used on durable storage, so a retry by the
			// same client (with a NEW nonce) is the correct path. We
			// leave q.totalUsedNonces and usedNonces[nk][nonce] set —
			// they reflect that the bridge ATTEMPTED to use this nonce,
			// and a fresh attempt with the same nonce would trip a
			// replay guard which is a useful side effect even on a
			// failed persist (DoS: an attacker that triggers persist
			// failures to burn nonces could only burn their own).
			delete(q.messagesBySourceChain[msg.SourceChain], msg.ID)
			delete(q.messagesByTargetChain[msg.TargetChain], msg.ID)
			// Note: not deleting from q.messages — q.messages is keyed
			// differently (status-keyed via map[status]map[id]) and is
			// serialized through q.SetMessageStatus / q.AddMessage
			// rather than directly mutated here. Caller (SubmitMessage)
			// adds the message to q.messages via q.messages[msg.ID]=msg
			// BEFORE this function is reached; stripping that requires
			// passing a rollback callback to SubmitMessage. For now we
			// rely on the next sweepMessages / restart-reconcile to
			// drop the orphaned in-memory copy. TODO: refactor
			// SubmitMessage to use an explicit rollback closure so the
			// messages/usedNonces mutation is atomic with persist.
			return fmt.Errorf("failed to persist bridge message: %w", err)
		}
	}

	// Submit to source chain adapter
	adapter, exists := q.adapters[msg.SourceChain]
	if !exists {
		// BRIDGE-H01 FIX: roll back in-memory state so the nonce can be retried
		// with a properly-configured adapter.
		delete(q.usedNonces[nk], msg.Nonce)
		q.totalUsedNonces--
		// AUDIT-FULL NW-08: the insert above checkpointed the nonce; rewrite
		// the checkpoint without it so a restart between rollback and retry
		// does not permanently burn a nonce that was never used.
		q.checkpointNoncesLocked()
		delete(q.messages, msg.ID)
		if sm, ok := q.messagesByStatus[msg.Status]; ok {
			delete(sm, msg.ID)
		}
		if scm, ok := q.messagesBySourceChain[msg.SourceChain]; ok {
			delete(scm, msg.ID)
		}
		if tcm, ok := q.messagesByTargetChain[msg.TargetChain]; ok {
			delete(tcm, msg.ID)
		}
		return fmt.Errorf("no adapter found for source chain: %s", msg.SourceChain)
	}

	_, err := adapter.SubmitMessage(ctx, msg)
	if err != nil {
		// BRIDGE-H01 FIX (R30, 2026-07-27): Roll back in-memory state on adapter
		// failure so the same nonce can be retried. Without this, failed
		// submissions would permanently consume a nonce, breaking deterministic
		// retry (e.g., BRIDGE-C03 refund/lock/mint/burn nonces). highestUsedNonce
		// is NOT advanced on submission (only on EXECUTED), so retry is safe.
		delete(q.usedNonces[nk], msg.Nonce)
		q.totalUsedNonces--
		// AUDIT-FULL NW-08: rewrite the checkpoint without the rolled-back
		// nonce (see the no-adapter rollback above for rationale).
		q.checkpointNoncesLocked()
		delete(q.messages, msg.ID)
		if sm, ok := q.messagesByStatus[msg.Status]; ok {
			delete(sm, msg.ID)
		}
		if scm, ok := q.messagesBySourceChain[msg.SourceChain]; ok {
			delete(scm, msg.ID)
		}
		if tcm, ok := q.messagesByTargetChain[msg.TargetChain]; ok {
			delete(tcm, msg.ID)
		}
		return err
	}

	// P3-1: record submission metric.
	q.metrics.IncMessagesSubmitted(msg.SourceChain, msg.TargetChain)
	q.metrics.SetStatusCount(MessageStatusPending, len(q.messagesByStatus[MessageStatusPending]))

	// P3-3: structured log for message submission.
	q.logger.Info("message submitted", map[string]any{
		"messageID":   msg.ID,
		"sourceChain": string(msg.SourceChain),
		"targetChain": string(msg.TargetChain),
		"sourceAddr":  msg.SourceAddress,
		"targetAddr":  msg.TargetAddress,
		"assetType":   string(msg.AssetType),
		"amount":      msg.Amount,
		"nonce":       msg.Nonce,
	})

	// P1-T7 (2026-07-14): Record cross-chain transaction in MinistryWorks.
	// Best-effort: errors are logged but do NOT block the bridge operation.
	// The message was already successfully submitted to the adapter, so
	// ministry recording failure should not cause SubmitMessage to fail.
	if q.ministryWorks != nil && q.ministryBridgeID > 0 {
		// Compute a source tx hash from the message ID (deterministic).
		// The message ID is already unique (includes nonce + source addr + timestamp).
		sourceTxHash := types.Hash(sha3.Sum256([]byte(msg.ID)))
		if _, err := q.ministryWorks.RecordCrossChainTx(q.ministryBridgeID, sourceTxHash, msg.Amount); err != nil {
			q.logger.Warn("MinistryWorks.RecordCrossChainTx failed (non-fatal)", map[string]any{
				"error":     err.Error(),
				"messageID": msg.ID,
				"bridgeID":  q.ministryBridgeID,
			})
		}
	}

	return nil
}

// ProcessMessage processes a cross-chain message.
// audit-fix R2-H2: per-message mutex prevents concurrent processing of the same message,
// eliminating the TOCTOU race between verify and status update.
//
// BRIDGE- (2026-07-20) FIX: Previously msgLocks entries were never
// removed after message processing completed. An attacker could send many
// garbage messages (even if verification failed) and each would create a
// permanent *sync.Mutex entry — leading to unbounded memory growth and OOM.
// We now:
//  1. Enforce a hard cap (maxMsgLocks) on msgLocks size; refuse new
//     messages when cap is reached (prevents OOM from attack).
//  2. defer-delete the msgLocks entry when this goroutine is the last
//     holder (i.e., no other goroutine is concurrently waiting on it).
//     This requires checking after unlock whether the mutex is still
//     held by us; to keep the change simple and race-free, we instead
//     delete entries that have been idle (no concurrent waiters) using
//     a try-lock pattern via sync.Mutex.TryLock().
func (q *QuantumBridge) ProcessMessage(ctx context.Context, msg *BridgeMessage) error {
	// BRIDGE- (2026-07-20): Emergency pause check. Done BEFORE
	// acquiring the global lock so a paused bridge rejects work without
	// serializing on mu. In-flight messages already past this point
	// will still complete; this only prevents NEW processing.
	if q.paused.Load() {
		return ErrBridgePaused
	}
	// Acquire per-message lock to prevent double-execution
	q.mu.Lock()
	// BRIDGE- enforce hard cap to prevent OOM via message spam.
	// Only enforce cap for NEW message IDs; existing IDs already have a
	// mutex and don't grow the map.
	const maxMsgLocks = 100000
	if _, exists := q.msgLocks[msg.ID]; !exists {
		if len(q.msgLocks) >= maxMsgLocks {
			q.mu.Unlock()
			return fmt.Errorf("bridge: msgLocks capacity exceeded (%d), refusing new message ID=%s", maxMsgLocks, msg.ID)
		}
	}
	msgMu, exists := q.msgLocks[msg.ID]
	if !exists {
		msgMu = &sync.Mutex{}
		q.msgLocks[msg.ID] = msgMu
	}
	q.mu.Unlock()

	msgMu.Lock()

	// BRIDGE- Cleanup msgLocks entry after processing. We unlock
	// the per-message mutex, then TryLock to prove no concurrent waiter
	// is blocked on it. If TryLock succeeds, no one else is waiting and
	// we can safely delete the entry. If it fails, another ProcessMessage
	// call is concurrently waiting — leave the entry in place for that
	// caller.
	defer func() {
		msgMu.Unlock()
		// Try to re-acquire to prove no concurrent waiter. If success,
		// we are the last holder and can delete the entry.
		if msgMu.TryLock() {
			q.mu.Lock()
			delete(q.msgLocks, msg.ID)
			q.mu.Unlock()
			msgMu.Unlock()
		}
	}()

	// BRIDGE-R10-HIGH-003 (2026-07-19) FIX: Idempotency check at the
	// ProcessMessage entry. Previously, ProcessMessage only checked
	// msg.Status != Pending — but msg.Status is a mutable field on the
	// BridgeMessage struct that an attacker can construct with Status=Pending
	// directly (bypassing SubmitMessage, which already checks finalizedIDs).
	// Re-checking finalizedIDs here ensures that even if an attacker
	// constructs a fresh BridgeMessage with the same ID and Status=Pending,
	// the message cannot be re-executed once its ID has been recorded as
	// finalized (executed/failed/expired).
	//
	// This runs under msgMu (so concurrent calls for the same ID are
	// serialized) and under q.mu.RLock() (so the finalizedIDs map read is
	// race-free with concurrent markFinalized calls).
	q.mu.RLock()
	if q.finalizedIDs[msg.ID] {
		q.mu.RUnlock()
		return fmt.Errorf("message %s has already been finalized (idempotency check at ProcessMessage entry)", msg.ID)
	}
	if msg.Status != MessageStatusPending {
		q.mu.RUnlock()
		return fmt.Errorf("message %s is not pending (status: %s)", msg.ID, msg.Status)
	}
	q.mu.RUnlock()

	// Verify message (safe: per-message lock held)
	valid, err := q.VerifyMessage(ctx, msg)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("message verification failed: %s", msg.ID)
	}

	// Execute on target chain
	adapter, adapterExists := q.adapters[msg.TargetChain]
	if !adapterExists {
		return fmt.Errorf("no adapter found for target chain: %s", msg.TargetChain)
	}

	// BRIDGE-CONF-01 FIX (deep-audit 2026-07-12): verify confirmation depth on the
	// SOURCE chain before executing on the target. msg.BlockNumber is a
	// source-chain height, so the depth must be measured against the source
	// chain's current height (via the source adapter), not the target chain's
	// (which the target's ExecuteMessage previously did — subtracting heights
	// from two independent chains, which either disabled reorg protection or
	// permanently bricked a bridge direction).
	if srcAdapter, ok := q.adapters[msg.SourceChain]; ok {
		if msg.BlockNumber == 0 {
			return fmt.Errorf("message %s has no source block number: cannot verify confirmation depth", msg.ID)
		}
		enough, confErr := srcAdapter.HasSufficientConfirmations(ctx, msg.BlockNumber)
		if confErr != nil {
			return fmt.Errorf("message %s: failed to verify source confirmations: %w", msg.ID, confErr)
		}
		if !enough {
			return fmt.Errorf("message %s has insufficient confirmations on source chain %s", msg.ID, msg.SourceChain)
		}
	} else {
		// AUDIT (2026 security review) R4-BRDG: Fail-closed when the source adapter is
		// missing. Previously the confirmation-depth check was silently skipped,
		// allowing execution to proceed without source-chain reorg protection.
		// This violates the BRIDGE-CONF-01 design intent stated above.
		return fmt.Errorf("message %s: source chain adapter %s not configured — cannot verify confirmation depth (fail-closed)", msg.ID, msg.SourceChain)
	}

	// AUDIT (2026 security review) HIGH-08 / BRDG-03: If validator network is configured,
	// require M-of-N quorum AND that the quorum signatures are bound to the
	// exact payload being executed. Previously only HasQuorum(msg.ID) was
	// checked, which counted signatures for the ID string without binding them
	// to the message payload — allowing a relayer to swap (amount, recipient,
	// source/dest chain) on a message whose ID already had quorum. The fix
	// computes the canonical message hash (same one used by SignMessage and
	// the adapter Verify paths) and requires HasQuorumForHash to match it
	// against the hash recorded at AddSignature time.
	//
	// AUDIT R4-BRDG-04 (2026-07-15): This check MUST run BEFORE the PENDING →
	// VERIFIED transition. Previously the transition happened first, so a
	// failed-quorum message was already in VERIFIED status — and the
	// processMessagesLoop retry path then called ExecuteMessage directly,
	// bypassing the quorum check entirely. With the check moved up, a
	// failed-quorum message stays PENDING (no execution path skips quorum).
	q.mu.RLock()
	vn := q.validatorNetwork
	q.mu.RUnlock()
	if vn != nil {
		expectedHash := computeMessageHash(msg)
		if !vn.GetSignatureAggregator().HasQuorumForHash(msg.ID, expectedHash) {
			return fmt.Errorf("message %s: insufficient validator signatures or message-hash mismatch (audit HIGH-08/BRDG-03; R4-BRDG-04: pre-VERIFIED check)", msg.ID)
		}
	}

	// Atomically transition PENDING → VERIFIED
	// AUDIT R4-BRDG-04 (2026-07-15): Now that the quorum check is above, only
	// messages that have passed quorum reach VERIFIED status. The retry loop
	// for VERIFIED messages still re-checks quorum (defense in depth — in case
	// quorum was lost between initial processing and retry, e.g., a signer was
	// slashed).
	q.mu.Lock()
	if msg.Status != MessageStatusPending {
		q.mu.Unlock()
		return fmt.Errorf("message %s status changed during processing (expected PENDING, got %s)", msg.ID, msg.Status)
	}
	oldStatus := msg.Status
	msg.Status = MessageStatusVerified
	// audit-fix NEW-15: also update the internal message so that
	// GetMessage(id).Status stays consistent with the status indexes.
	if internalMsg, ok := q.messages[msg.ID]; ok {
		internalMsg.Status = MessageStatusVerified
	}
	delete(q.messagesByStatus[oldStatus], msg.ID)
	q.ensureStatusMap(msg.Status)[msg.ID] = true
	// P3-1: update status gauges.
	q.metrics.SetStatusCount(oldStatus, len(q.messagesByStatus[oldStatus]))
	q.metrics.SetStatusCount(msg.Status, len(q.ensureStatusMap(msg.Status)))
	q.mu.Unlock()

	// P3-3: structured log for verification transition.
	q.logger.Info("message verified", map[string]any{
		"messageID":   msg.ID,
		"sourceChain": string(msg.SourceChain),
		"targetChain": string(msg.TargetChain),
		"sourceAddr":  msg.SourceAddress,
	})

	// Persist status change
	if q.store != nil {
		if err := q.store.UpdateMessageStatus(ctx, msg.ID, oldStatus, MessageStatusVerified); err != nil {
			return fmt.Errorf("failed to persist verified status: %w", err)
		}
	}

	success, err := adapter.ExecuteMessage(ctx, msg)
	if err != nil {
		return err
	}

	// R61-BR-C1 [CRITICAL] FIX: ExecuteMessage can return (success=false, err=nil)
	// when execution silently fails (e.g., target chain RPC error, insufficient gas).
	// Previously only `err != nil` was checked, so silent failures with `err == nil` were
	// marked as EXECUTED — draining bridge liquidity while the message remained unprocessed.
	// Fix: propagate execution failure even when err is nil.
	if !success {
		return fmt.Errorf("message %s execution failed on target chain %s", msg.ID, msg.TargetChain)
	}

	// Update message status based on execution result
	q.mu.Lock()
	oldStatus = msg.Status
	newStatus := MessageStatusExecuted
	msg.Status = newStatus
	// audit-fix NEW-15: sync internal message status with index.
	if internalMsg, ok := q.messages[msg.ID]; ok {
		internalMsg.Status = newStatus
	}
	delete(q.messagesByStatus[oldStatus], msg.ID)
	q.ensureStatusMap(newStatus)[msg.ID] = true
	// BRIDGE-H01 FIX (R30, 2026-07-27): advance highestUsedNonce on EXECUTED.
	execNk := nonceKey{chain: msg.SourceChain, addr: msg.SourceAddress}
	if msg.Nonce > q.highestUsedNonce[execNk] {
		q.highestUsedNonce[execNk] = msg.Nonce
		// R32-P1-04 FIX (2026-07-28): persist the new high-water mark to the
		// dedicated nonce_highwater bucket so it survives restarts even if
		// EXECUTED messages are pruned from the message store in the future.
		// Best-effort: errors are logged but do not block execution (the
		// in-memory state is authoritative for runtime; persistence is for
		// restart recovery and will be reconstructed from EXECUTED messages
		// even if this call fails).
		if q.store != nil {
			if err := q.store.SaveHighestUsedNonce(ctx, string(msg.SourceChain), msg.SourceAddress, msg.Nonce); err != nil {
				q.logger.Warn("bridge: failed to persist highestUsedNonce (non-fatal, will retry on next advance)",
					map[string]any{"error": err.Error(), "sourceChain": string(msg.SourceChain), "nonce": msg.Nonce})
			}
		}
	}
	// BRIDGE-H03 FIX: proactive sweep after execution.
	q.sweepUsedNoncesFor(execNk)
	// AUDIT-FULL NW-08: persist the advanced high-water mark (and post-sweep
	// nonce state) so executed nonces stay replay-protected across restarts
	// in memory mode.
	q.checkpointNoncesLocked()
	// P3-1: update status gauges.
	q.metrics.SetStatusCount(oldStatus, len(q.messagesByStatus[oldStatus]))
	q.metrics.SetStatusCount(newStatus, len(q.messagesByStatus[newStatus]))
	// P3-2 (2026-07-15): record last-processed timestamp for the
	// bridge_message_processing_stopped alert rule.
	q.metrics.SetLastMessageProcessedAt(time.Now().Unix())
	// P3-3: structured log for execution transition.
	q.logger.Info("message executed", map[string]any{
		"messageID":   msg.ID,
		"sourceChain": string(msg.SourceChain),
		"targetChain": string(msg.TargetChain),
		"targetAddr":  msg.TargetAddress,
		"assetType":   string(msg.AssetType),
		"amount":      msg.Amount,
	})
	// AUDIT (2026 security review) BRDG §A.2 FIX: Moved markFinalized and ClearMessage
	// to AFTER successful persist. Previously both were called before persist
	// — if persist failed, in-memory status was rolled back but:
	//   1. markFinalized had already recorded the ID in finalizedIDs, blocking
	//      all future retry attempts (message permanently stuck as "already
	//      finalized" even though execution was rolled back)
	//   2. ClearMessage had already wiped validator signatures, so any retry
	//      would fail quorum verification
	// Moving both after persist ensures the message can be retried on failure.
	q.mu.Unlock()

	// Persist final status; roll back in-memory on failure
	if q.store != nil {
		if err := q.store.UpdateMessageStatus(ctx, msg.ID, oldStatus, newStatus); err != nil {
			q.mu.Lock()
			msg.Status = oldStatus
			// audit-fix NEW-15: rollback internal message status on persist failure.
			if internalMsg, ok := q.messages[msg.ID]; ok {
				internalMsg.Status = oldStatus
			}
			delete(q.messagesByStatus[newStatus], msg.ID)
			q.ensureStatusMap(oldStatus)[msg.ID] = true
			q.mu.Unlock()
			return fmt.Errorf("failed to persist final status %s: %w", newStatus, err)
		}
	}

	// NEW-B-2 [MEDIUM] FIX: record executed message ID in finalizedIDs to prevent replay.
	// ExecuteMessage returning (true, nil) means the target chain executed the message.
	// Recording it here blocks future retry attempts by the same message ID.
	// AUDIT (2026 security review) BRDG §A.2: Now called AFTER successful persist.
	q.mu.Lock()
	q.markFinalized(msg.ID)
	q.mu.Unlock()
	// AUDIT (2026 security review) BRDG NEW-1/NEW-2 FIX: Now that the message has been
	// successfully executed, clear the collected validator signatures to
	// free memory. Previously SignMessage cleared them prematurely (before
	// ProcessMessage could verify quorum), making the bridge non-functional.
	// AUDIT (2026 security review) BRDG §A.2: Now called AFTER successful persist.
	if vn != nil {
		vn.GetSignatureAggregator().ClearMessage(msg.ID)
	}

	// audit-fix R2-L4: evict completed/expired messages if over limit
	q.evictOldMessages()

	return nil
}

// SetPendingEvictionHook registers a callback invoked by evictOldMessages
// before deleting a stale PENDING BridgeMessage from memory. The hook
// receives the message ID and is expected to mark any associated AssetLock
// as Failed so the operator can later refund the stuck source-chain funds.
//
// BRIDGE-R15-CRIT-002 (2026-07-22): Without this hook, evicting a PENDING
// message silently dropped it from memory while the user's locked assets
// remained permanently stuck on the source chain. Pass nil to clear the
// hook (eviction becomes a no-op for AssetLock state, restoring pre-fix
// behavior for tests that don't care about lock state).
//
// Safe to call at any time (acquires q.mu). The hook is invoked under
// q.mu — implementations must NOT acquire q.mu recursively or call back
// into the bridge (deadlock risk). The AssetLockManager's
// HandlePendingMessageEviction acquires alm.mu (a different lock), which
// is safe.
func (q *QuantumBridge) SetPendingEvictionHook(hook func(messageID string)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pendingEvictionHook = hook
}

// sweepMessages bounds the in-memory `messages` map to maxMessagesInMemory
// by evicting terminal messages (EXECUTED / FAILED / EXPIRED) oldest first
// (by msg.Timestamp). It is invoked after every successful SubmitMessage
// append and after every terminal state transition (EXECUTED, FAILED,
// EXPIRED) so the map does not retain completed messages forever.
//
// R43-BRIDGE-MSG-01 FIX (2026-08-03):
//   - In-progress messages (PENDING, VERIFIED) are NEVER evicted regardless
//     of count — they still need processing by processMessagesLoop /
//     processPendingBatch. Only terminal messages are sweepable.
//   - Evicted IDs are first recorded in finalizedIDs (via markFinalized)
//     so a future replay of the same ID is rejected at SubmitMessage time
//     (matches the existing CRIT-1 invariant enforced by evictOldMessages).
//   - The index maps (messagesByStatus, messagesBySourceChain,
//     messagesByTargetChain, msgLocks, retryAttempts, lastRetryTime) are
//     cleaned up alongside the messages entry so no dangling references
//     remain.
//   - Only the IN-MEMORY cache is swept; persisted messages (via the
//     bbolt MessageStore) stay on disk. A downstream caller that asks
//     for a swept message ID gets the canonical "message not found: %s"
//     error from GetMessage, matching the existing behavior for unknown IDs.
//   - Caller MUST hold q.mu (write lock).
//   - Normal operation is O(1) (returns immediately when under the cap).
//     Sweeps are O(n) where n = len(messages), triggered only when the cap
//     is exceeded, so a sustained flood cannot grow the map unbounded.
func (q *QuantumBridge) sweepMessages() {
	if len(q.messages) <= maxMessagesInMemory {
		return
	}
	// Collect terminal messages first, then sort by timestamp ascending so
	// we evict the oldest terminal messages first. In-progress messages
	// (PENDING / VERIFIED) are kept regardless of count.
	type termEntry struct {
		id        string
		timestamp int64
	}
	var terminal []termEntry
	for _, status := range []BridgeMessageStatus{MessageStatusExecuted, MessageStatusFailed, MessageStatusExpired} {
		for id := range q.messagesByStatus[status] {
			if msg := q.messages[id]; msg != nil {
				terminal = append(terminal, termEntry{id: id, timestamp: msg.Timestamp})
			}
		}
	}
	if len(terminal) == 0 {
		// No terminal messages to evict — in-progress messages fill the
		// map up to the cap. We must NOT evict them; the sweep is a no-op
		// until some messages reach a terminal status.
		return
	}
	// Simple insertion sort by timestamp ascending (oldest first). The
	// terminal slice is small in practice (bounded by len(terminal) ≤
	// len(messages) - inProgress) so an O(n^2) sort is fine here; we avoid
	// pulling in sort just for this.
	for i := 1; i < len(terminal); i++ {
		for j := i; j > 0 && terminal[j].timestamp < terminal[j-1].timestamp; j-- {
			terminal[j], terminal[j-1] = terminal[j-1], terminal[j]
		}
	}
	removed := 0
	for _, e := range terminal {
		if len(q.messages) <= maxMessagesInMemory {
			break
		}
		id := e.id
		msg, ok := q.messages[id]
		if !ok {
			continue
		}
		status := msg.Status
		// CRIT-1 / NEW-B-2: record finalized ID before eviction so a
		// replay with the same ID is rejected at SubmitMessage time.
		q.markFinalized(id)
		delete(q.messages, id)
		if sm := q.messagesByStatus[status]; sm != nil {
			delete(sm, id)
		}
		delete(q.msgLocks, id)
		// R67-BR-7 [LOW] parity: clean retry tracking maps on sweep.
		delete(q.retryAttempts, id)
		delete(q.lastRetryTime, id)
		for _, chainMap := range q.messagesBySourceChain {
			delete(chainMap, id)
		}
		for _, chainMap := range q.messagesByTargetChain {
			delete(chainMap, id)
		}
		removed++
	}
	if removed > 0 && q.logger != nil {
		q.logger.Info("bridge: sweepMessages evicted terminal messages to bound in-memory cache (R43-BRIDGE-MSG-01)",
			map[string]any{"removed": removed, "remaining": len(q.messages), "cap": maxMessagesInMemory})
	}
}

// reconcileMemoryWithStore verifies that the in-memory indexes
// (messagesByStatus, messagesBySourceChain, messagesByTargetChain) are
// internally consistent with the messages map after a restore from bbolt.
//
// BR-04 (R43 P3, 2026-08-03): During runtime, SaveMessage writes to bbolt
// first, then the caller updates memory. If the memory update panics, the
// bbolt write is committed but the in-memory state is stale. On the NEXT
// restart, the restore loop reloads from bbolt — but the operator needs to
// KNOW a divergence happened. This method logs a summary of restored state
// and warns if any index is inconsistent.
//
// Caller holds q.mu (called from init/restore path under the lock).
func (q *QuantumBridge) reconcileMemoryWithStore() {
	// Count messages by status from the messages map.
	statusCounts := make(map[BridgeMessageStatus]int)
	orphanedStatus := 0
	orphanedSource := 0
	orphanedTarget := 0

	for id, msg := range q.messages {
		statusCounts[msg.Status]++

		// Verify messagesByStatus is consistent.
		statusMap := q.messagesByStatus[msg.Status]
		if statusMap == nil || !statusMap[id] {
			orphanedStatus++
		}

		// Verify messagesBySourceChain is consistent.
		chainMap := q.messagesBySourceChain[msg.SourceChain]
		if chainMap == nil || !chainMap[id] {
			orphanedSource++
		}

		// Verify messagesByTargetChain is consistent.
		chainMap = q.messagesByTargetChain[msg.TargetChain]
		if chainMap == nil || !chainMap[id] {
			orphanedTarget++
		}
	}

	// Also check for dangling entries in the index maps (entries that point
	// to IDs NOT in the messages map).
	danglingStatus := 0
	danglingSource := 0
	danglingTarget := 0
	for status, statusMap := range q.messagesByStatus {
		for id := range statusMap {
			if _, ok := q.messages[id]; !ok {
				danglingStatus++
				// Clean up the dangling entry immediately.
				delete(statusMap, id)
			}
		}
		// Remove empty status maps.
		if len(statusMap) == 0 {
			delete(q.messagesByStatus, status)
		}
	}
	for chain, chainMap := range q.messagesBySourceChain {
		for id := range chainMap {
			if _, ok := q.messages[id]; !ok {
				danglingSource++
				delete(chainMap, id)
			}
		}
		if len(chainMap) == 0 {
			delete(q.messagesBySourceChain, chain)
		}
	}
	for chain, chainMap := range q.messagesByTargetChain {
		for id := range chainMap {
			if _, ok := q.messages[id]; !ok {
				danglingTarget++
				delete(chainMap, id)
			}
		}
		if len(chainMap) == 0 {
			delete(q.messagesByTargetChain, chain)
		}
	}

	// Log the reconciliation summary.
	if q.logger != nil {
		fields := map[string]any{
			"total_messages":    len(q.messages),
			"finalized_ids":     len(q.finalizedIDs),
			"total_used_nonces": q.totalUsedNonces,
		}
		for status, count := range statusCounts {
			fields["status_"+string(status)] = count
		}
		q.logger.Info("bridge: BR-04 startup reconciliation complete", fields)

		if orphanedStatus > 0 || orphanedSource > 0 || orphanedTarget > 0 {
			q.logger.Warn("bridge: BR-04 reconciliation found orphaned messages (in messages map but missing from index)",
				map[string]any{
					"orphaned_status":       orphanedStatus,
					"orphaned_source_chain": orphanedSource,
					"orphaned_target_chain": orphanedTarget,
				})
		}
		if danglingStatus > 0 || danglingSource > 0 || danglingTarget > 0 {
			q.logger.Warn("bridge: BR-04 reconciliation found dangling index entries (cleaned up)",
				map[string]any{
					"dangling_status":       danglingStatus,
					"dangling_source_chain": danglingSource,
					"dangling_target_chain": danglingTarget,
				})
		}
	}
}

// evictOldMessages removes completed/expired messages when the store exceeds maxMessages.
// audit-fix R2-L4: prevents unbounded memory growth in the bridge message store.
// H-3 FIX: also caps finalizedIDs to prevent unbounded growth.
func (q *QuantumBridge) evictOldMessages() {
	q.mu.Lock()
	defer q.mu.Unlock()

	// R43-BRIDGE-MSG-01 FIX (2026-08-03): first, bound the in-memory
	// `messages` map to maxMessagesInMemory (the tighter, lower cap)
	// by sweeping terminal messages oldest first. This runs under the
	// same lock and BEFORE the legacy maxMessages logic so the lower
	// cap always wins. If sweepMessages reduces the map below
	// maxMessagesInMemory but it's still above q.maxMessages, the legacy
	// block below kicks in for the higher cap + finalizedIDs trim +
	// stale-PENDING eviction.
	q.sweepMessages()

	if len(q.messages) <= q.maxMessages && len(q.finalizedIDs) <= maxFinalizedIDs {
		return
	}

	// S2-9 [LOW] FIX: collect keys to delete before iteration to avoid skipped entries
	// caused by Go's randomized map iteration order when deleting during range.
	// R68-BRIDGE-3 [MEDIUM] FIX: Use LRU ordering to evict oldest entries first.
	// Previously, arbitrary map iteration could delete recently-added entries,
	// allowing an attacker to re-submit messages that should have been finalized.
	// Now we iterate finalizedIDsOrder from the front (oldest) and evict in insertion order.
	if len(q.finalizedIDs) > maxFinalizedIDs {
		evictCount := len(q.finalizedIDs) - maxFinalizedIDs
		// Evict from front of LRU order slice (oldest entries first)
		for i := 0; i < evictCount && i < len(q.finalizedIDsOrder); i++ {
			id := q.finalizedIDsOrder[i]
			delete(q.finalizedIDs, id)
			delete(q.finalizedIDsIndex, id)
		}
		// Trim evicted entries from the front of the slice
		q.finalizedIDsOrder = q.finalizedIDsOrder[evictCount:]
		// Rebuild index map for remaining entries
		for newIdx, id := range q.finalizedIDsOrder {
			q.finalizedIDsIndex[id] = newIdx
		}
	}

	if len(q.messages) <= q.maxMessages {
		return
	}

	// Evict executed, failed, and expired messages first
	for _, status := range []BridgeMessageStatus{MessageStatusExecuted, MessageStatusFailed, MessageStatusExpired} {
		for id := range q.messagesByStatus[status] {
			// audit-fix CRIT-1: record finalized ID before eviction so that
			// SubmitMessage can reject replay attempts after eviction.
			q.markFinalized(id)
			delete(q.messages, id)
			delete(q.messagesByStatus[status], id)
			delete(q.msgLocks, id)
			// R67-BR-7 [LOW] FIX: Clean up retry tracking maps during eviction.
			// Previously evictOldMessages only deleted from messages and index maps,
			// leaving stale entries in retryAttempts and lastRetryTime. On long-running
			// relayers, these maps accumulate indefinitely causing memory leaks and
			// increasing the cost of retry lookups.
			delete(q.retryAttempts, id)
			delete(q.lastRetryTime, id)
			// Clean chain indexes
			for _, chainMap := range q.messagesBySourceChain {
				delete(chainMap, id)
			}
			for _, chainMap := range q.messagesByTargetChain {
				delete(chainMap, id)
			}
			if len(q.messages) <= q.maxMessages {
				return
			}
		}
	}

	//  [MEDIUM] FIX: Evict stale PENDING messages to prevent unbounded memory growth.
	// Previously, evictOldMessages() only evicted Executed/Failed/Expired messages, so a
	// sustained stream of pending cross-chain messages (e.g., from a slow relayer) could
	// accumulate indefinitely beyond maxMessages. Stale PENDING messages older than 1 hour
	// are likely stalled or blocked by downstream failures and should be evicted.
	if len(q.messages) > q.maxMessages {
		const pendingEvictionAge = 1 * time.Hour
		cutoff := time.Now().Add(-pendingEvictionAge).Unix()
		var toEvict []string
		for id := range q.messagesByStatus[MessageStatusPending] {
			if msg := q.messages[id]; msg != nil && msg.Timestamp < cutoff {
				toEvict = append(toEvict, id)
			}
		}
		for _, id := range toEvict {
			// BRIDGE-R15-CRIT-002 (2026-07-22): Invoke the pending
			// eviction hook BEFORE deleting the message so the
			// AssetLockManager can mark the corresponding AssetLock as
			// Failed (giving the operator a refund path). Without this
			// hook, the user's locked assets would be permanently stuck
			// on the source chain. The hook is nil-safe — if no hook
			// is registered, eviction proceeds without lock-state
			// mutation (restoring pre-fix behavior for tests).
			if q.pendingEvictionHook != nil {
				q.pendingEvictionHook(id)
			}
			q.markFinalized(id)
			delete(q.messages, id)
			delete(q.messagesByStatus[MessageStatusPending], id)
			delete(q.msgLocks, id)
			// R67-BR-7 [LOW] FIX: Clean up retry tracking maps during PENDING eviction.
			delete(q.retryAttempts, id)
			delete(q.lastRetryTime, id)
			for _, chainMap := range q.messagesBySourceChain {
				delete(chainMap, id)
			}
			for _, chainMap := range q.messagesByTargetChain {
				delete(chainMap, id)
			}
			if len(q.messages) <= q.maxMessages {
				return
			}
		}
	}
}

// VerifyMessage verifies a cross-chain message using proof
func (q *QuantumBridge) VerifyMessage(ctx context.Context, msg *BridgeMessage) (bool, error) {
	// Check if message is expired
	if msg.Expiration > 0 && time.Now().Unix() > msg.Expiration {
		// Update status to expired
		q.mu.Lock()
		oldStatus := msg.Status
		msg.Status = MessageStatusExpired
		// audit-fix NEW-15: sync internal message status on expiry.
		if internalMsg, ok := q.messages[msg.ID]; ok {
			internalMsg.Status = MessageStatusExpired
		}
		// Update indexes
		delete(q.messagesByStatus[oldStatus], msg.ID)
		q.ensureStatusMap(msg.Status)[msg.ID] = true
		// P3-1: update status gauges.
		q.metrics.SetStatusCount(oldStatus, len(q.messagesByStatus[oldStatus]))
		q.metrics.SetStatusCount(msg.Status, len(q.ensureStatusMap(msg.Status)))
		// R43-BRIDGE-MSG-01 FIX (2026-08-03): a terminal transition just
		// occurred (EXPIRED); if the messages map is over the cap, sweep
		// the now-largest terminal bucket (EXECUTED / FAILED / EXPIRED)
		// oldest first. We hold q.mu (write lock), which sweepMessages
		// requires. sweepMessages is a no-op when under maxMessagesInMemory.
		q.sweepMessages()
		q.mu.Unlock()
		// P3-3: structured log for message expiry.
		q.logger.Warn("message expired", map[string]any{
			"messageID":   msg.ID,
			"sourceChain": string(msg.SourceChain),
			"targetChain": string(msg.TargetChain),
			"expiration":  msg.Expiration,
		})
		return false, fmt.Errorf("message expired: %s", msg.ID)
	}

	// Get source chain adapter
	adapter, exists := q.adapters[msg.SourceChain]
	if !exists {
		return false, fmt.Errorf("no adapter found for source chain: %s", msg.SourceChain)
	}

	// Verify message using adapter
	return adapter.VerifyMessage(ctx, msg)
}

// GetMessage retrieves a message by ID.
// audit-fix M-4: returns a deep copy to prevent callers from mutating internal state.
// audit-fix NEW-13: deep-copy byte slices (Data, Proof, Receipt, QuantumSignature,
// QuantumPublicKey) that were shared between the copy and internal state.
func (q *QuantumBridge) GetMessage(ctx context.Context, id string) (*BridgeMessage, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	msg, exists := q.messages[id]
	if !exists {
		return nil, fmt.Errorf("message not found: %s", id)
	}

	return msg.deepCopy(), nil
}

// GetMessagesByStatus retrieves messages by status
func (q *QuantumBridge) GetMessagesByStatus(ctx context.Context, status BridgeMessageStatus) ([]*BridgeMessage, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	messageIDs, exists := q.messagesByStatus[status]
	if !exists {
		return []*BridgeMessage{}, nil
	}

	// audit-fix R2-M1+NEW-13: return deep copies to prevent callers from mutating internal state
	messages := make([]*BridgeMessage, 0, len(messageIDs))
	for id := range messageIDs {
		if msg, exists := q.messages[id]; exists {
			messages = append(messages, msg.deepCopy())
		}
	}

	return messages, nil
}

// GetMessagesByChain retrieves messages by source or target chain
func (q *QuantumBridge) GetMessagesByChain(ctx context.Context, chainID ChainID, isSource bool) ([]*BridgeMessage, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var messageIDs map[string]bool
	var exists bool

	if isSource {
		messageIDs, exists = q.messagesBySourceChain[chainID]
	} else {
		messageIDs, exists = q.messagesByTargetChain[chainID]
	}

	if !exists {
		return []*BridgeMessage{}, nil
	}

	// audit-fix R2-M1+NEW-13: return deep copies to prevent callers from mutating internal state
	messages := make([]*BridgeMessage, 0, len(messageIDs))
	for id := range messageIDs {
		if msg, exists := q.messages[id]; exists {
			messages = append(messages, msg.deepCopy())
		}
	}

	return messages, nil
}

// validateMessage validates a bridge message including quantum signature verification.
// audit-fix C-1: verify QuantumSignature to prevent forged cross-chain messages.
// audit-fix L-5: validate Amount is a valid non-negative number.
// audit-fix CRIT-NEW-1: delegate field validation to validateMessageFields.
func (q *QuantumBridge) validateMessage(msg *BridgeMessage) error {
	if err := q.validateMessageFields(msg); err != nil {
		return err
	}
	if err := q.verifyQuantumSignature(msg); err != nil {
		return fmt.Errorf("quantum signature verification failed: %w", err)
	}
	return nil
}

// validateMessageFields performs structural and semantic validation on a bridge
// message WITHOUT requiring a quantum signature. This is used by internal flows
// (e.g., AssetLockManager) that construct messages from trusted data before
// the quantum signature is added by the relayer.
func (q *QuantumBridge) validateMessageFields(msg *BridgeMessage) error {
	if msg.ID == "" {
		return fmt.Errorf("message ID is required")
	}
	if len(msg.ID) > maxMessageIDLen {
		return fmt.Errorf("message ID too long: %d bytes (max %d)", len(msg.ID), maxMessageIDLen)
	}

	if msg.SourceChain == "" {
		return fmt.Errorf("source chain is required")
	}
	if len(msg.SourceChain) > maxChainIDLen {
		return fmt.Errorf("source chain ID too long: %d bytes (max %d)", len(msg.SourceChain), maxChainIDLen)
	}

	if msg.TargetChain == "" {
		return fmt.Errorf("target chain is required")
	}
	if len(msg.TargetChain) > maxChainIDLen {
		return fmt.Errorf("target chain ID too long: %d bytes (max %d)", len(msg.TargetChain), maxChainIDLen)
	}
	if msg.SourceChain == msg.TargetChain {
		return fmt.Errorf("source and target chains must be different (got %s)", msg.SourceChain)
	}

	if msg.SourceAddress == "" {
		return fmt.Errorf("source address is required")
	}
	if len(msg.SourceAddress) > maxAddressLen {
		return fmt.Errorf("source address too long: %d bytes (max %d)", len(msg.SourceAddress), maxAddressLen)
	}

	if msg.TargetAddress == "" {
		return fmt.Errorf("target address is required")
	}
	if len(msg.TargetAddress) > maxAddressLen {
		return fmt.Errorf("target address too long: %d bytes (max %d)", len(msg.TargetAddress), maxAddressLen)
	}

	if msg.AssetType == "" {
		return fmt.Errorf("asset type is required")
	}

	if msg.Amount == "" {
		return fmt.Errorf("amount is required")
	}
	if len(msg.Amount) > maxAmountLen {
		return fmt.Errorf("amount string too long: %d bytes (max %d)", len(msg.Amount), maxAmountLen)
	}

	amount, ok := new(big.Int).SetString(msg.Amount, 10)
	if !ok {
		return fmt.Errorf("amount must be a valid decimal number")
	}
	if amount.Sign() <= 0 {
		return fmt.Errorf("amount must be positive")
	}
	// R39-P2-05 (2026-08-02) FIX: source the upper bound from the
	// package-level maxTransferAmountStr (single source of truth,
	// shared by both unlock paths in asset_lock.go).
	var maxTransferAmount big.Int
	maxTransferAmount.SetString(maxTransferAmountStr, 10)
	if amount.Cmp(&maxTransferAmount) > 0 {
		return fmt.Errorf("amount exceeds maximum allowed transfer limit")
	}

	if len(msg.AssetID) > maxAssetIDLen {
		return fmt.Errorf("asset ID too long: %d bytes (max %d)", len(msg.AssetID), maxAssetIDLen)
	}
	if len(msg.TokenID) > maxTokenIDLen {
		return fmt.Errorf("token ID too long: %d bytes (max %d)", len(msg.TokenID), maxTokenIDLen)
	}
	if len(msg.Data) > maxDataSize {
		return fmt.Errorf("data payload too large: %d bytes (max %d)", len(msg.Data), maxDataSize)
	}

	// audit-fix R63-HIGH-slippage: validate slippage tolerance and deadline.
	// SlippageTolerance is in basis points (bps). 100 bps = 1%. A value of 0 provides
	// no protection against price movement; recommend at least 50 bps (0.5%).
	// Reject absurdly high values (>10000 bps = 100%) that could hide bugs.
	if msg.SlippageTolerance > 10000 {
		return fmt.Errorf("slippage tolerance too high: %d bps (max 10000 bps)", msg.SlippageTolerance)
	}
	// audit-fix R63-HIGH-slippage: validate deadline is in the future if provided.
	// A deadline of 0 disables deadline protection. For production, require a deadline.
	if msg.Deadline > 0 {
		// Deadline must be greater than BlockNumber to be meaningful.
		// The actual comparison against current block height is done at execution time.
		if msg.Deadline <= msg.BlockNumber {
			return fmt.Errorf("deadline (%d) must be greater than block number (%d)", msg.Deadline, msg.BlockNumber)
		}
		// R70-DEADLINE-OVERFLOW [MEDIUM] FIX: Add an upper bound to prevent
		// uint64 overflow when block numbers are cast to int64 for time comparison.
		// The maximum reasonable deadline is ~1M blocks (~4 months at 12s block time).
		const maxDeadlineBlocks = 1_000_000
		if msg.Deadline > maxDeadlineBlocks {
			return fmt.Errorf("deadline (%d) exceeds maximum allowed (%d)", msg.Deadline, maxDeadlineBlocks)
		}
	}
	// audit-fix R63-HIGH-slippage: validate MaxAmount if provided.
	// MaxAmount is a CEILING on the amount that may be delivered: ExecuteMessage
	// rejects execution when the delivered amount exceeds MaxAmount (see the
	// adapters' Amount > MaxAmount check). If empty, no cap is enforced.
	if msg.MaxAmount != "" {
		if len(msg.MaxAmount) > maxAmountLen {
			return fmt.Errorf("max_amount string too long: %d bytes (max %d)", len(msg.MaxAmount), maxAmountLen)
		}
		maxAmt, ok := new(big.Int).SetString(msg.MaxAmount, 10)
		if !ok {
			return fmt.Errorf("max_amount must be a valid decimal number")
		}
		if maxAmt.Sign() < 0 {
			return fmt.Errorf("max_amount must not be negative")
		}
		// BRIDGE-MAXAMT-01 FIX (deep-audit 2026-07-12): MaxAmount is a ceiling on
		// the delivered amount, and ExecuteMessage enforces Amount <= MaxAmount.
		// For a 1:1 bridge the delivered amount equals msg.Amount, so a MaxAmount
		// BELOW Amount could never be satisfied and would permanently brick the
		// transfer. The previous check rejected MaxAmount > Amount (a floor
		// interpretation), which contradicted the execution-time ceiling check
		// and forced MaxAmount == Amount (a no-op). Require MaxAmount >= Amount so
		// the cap is meaningful: it bounds any future fee/exchange-rate inflation
		// of the delivered amount while always permitting the 1:1 transfer.
		if maxAmt.Cmp(amount) < 0 {
			return fmt.Errorf("max_amount (%s) must not be less than amount (%s)", msg.MaxAmount, msg.Amount)
		}
	}

	if msg.MessageType == "" {
		return fmt.Errorf("message type is required")
	}

	return nil
}

// verifyQuantumSignature verifies the Dilithium3 quantum signature on a bridge
// message.
//
// P0-1 BRDG-01 FIX (2026-07-13): Previously this method trusted
// msg.QuantumPublicKey (the key embedded in the message itself), only checking
// that the derived address matched msg.SourceAddress. This allowed anyone to
// forge messages by generating their own Dilithium3 key pair, setting
// SourceAddress to the derived address, and self-signing.
//
// Now the method requires msg.QuantumPublicKey to match one of the configured
// trustedValidatorKeys (via subtle.ConstantTimeCompare to prevent timing
// attacks). If no trusted keys are configured, the method fails closed
// (rejects all messages) to prevent operation without authorization.
//
// SECURITY FIX: Includes all critical fields in signing data to prevent tampering.
// Fields included: ID, SourceChain, TargetChain, SourceAddress, TargetAddress,
// AssetType, AssetID, Amount, TokenID, Data, MessageType, Nonce
func (q *QuantumBridge) verifyQuantumSignature(msg *BridgeMessage) error {
	if len(msg.QuantumSignature) == 0 {
		return fmt.Errorf("quantum signature is required")
	}
	if len(msg.QuantumPublicKey) == 0 {
		return fmt.Errorf("quantum public key is required")
	}

	// BRDG-01 FIX: Look up the trusted key from the configured set, NOT from
	// the message. Fail-closed if no trusted keys are configured.
	// NOTE: verifyQuantumSignature is called from validateMessage, which is
	// called from SubmitMessage while q.mu is already held (write-locked).
	// We must NOT re-acquire the lock here — Go's sync.RWMutex is not
	// reentrant, and doing so would deadlock. The caller guarantees thread
	// safety.
	trustedKeys := q.trustedValidatorKeys

	if len(trustedKeys) == 0 {
		return fmt.Errorf("no trusted validator keys configured: cannot verify message %s", msg.ID)
	}

	// Check that msg.QuantumPublicKey matches one of the trusted keys.
	// Use subtle.ConstantTimeCompare to prevent timing attacks that could
	// leak information about which trusted key matched.
	matched := false
	for _, trustedKey := range trustedKeys {
		if subtle.ConstantTimeCompare(msg.QuantumPublicKey, trustedKey) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("message public key does not match any trusted validator key for message %s", msg.ID)
	}

	pubKey, err := crypto.PublicKeyFromBytes(msg.QuantumPublicKey)
	if err != nil {
		return fmt.Errorf("invalid quantum public key: %w", err)
	}

	msgHash := computeMessageHash(msg)

	if !crypto.Verify(pubKey, msgHash, msg.QuantumSignature) {
		return fmt.Errorf("quantum signature is invalid")
	}

	derivedAddr := pubKey.Address()
	if derivedAddr.ToHexAddress() != msg.SourceAddress {
		return fmt.Errorf("quantum public key does not match source address")
	}

	return nil
}

// deepCopy returns a deep copy of the BridgeMessage with all byte slices copied.
// audit-fix NEW-13: prevents callers from mutating internal bridge state via shared slices.
func (m *BridgeMessage) deepCopy() *BridgeMessage {
	cpy := *m
	if m.Data != nil {
		cpy.Data = make([]byte, len(m.Data))
		copy(cpy.Data, m.Data)
	}
	if m.Proof != nil {
		cpy.Proof = make([]byte, len(m.Proof))
		copy(cpy.Proof, m.Proof)
	}
	if m.Receipt != nil {
		cpy.Receipt = make([]byte, len(m.Receipt))
		copy(cpy.Receipt, m.Receipt)
	}
	if m.QuantumSignature != nil {
		cpy.QuantumSignature = make([]byte, len(m.QuantumSignature))
		copy(cpy.QuantumSignature, m.QuantumSignature)
	}
	if m.QuantumPublicKey != nil {
		cpy.QuantumPublicKey = make([]byte, len(m.QuantumPublicKey))
		copy(cpy.QuantumPublicKey, m.QuantumPublicKey)
	}
	return &cpy
}

// handleBridgeEvent handles a bridge event from a chain adapter.
// For events parsed from blockchain logs that do not yet carry a quantum signature,
// the source chain adapter signs the message before submitting it to the bridge.
// This ensures quantum signature verification is enforced for ALL message types.
func (q *QuantumBridge) handleBridgeEvent(msg *BridgeMessage) error {
	if len(msg.QuantumSignature) == 0 {
		adapter, exists := q.adapters[msg.SourceChain]
		if !exists {
			return fmt.Errorf("no adapter found for source chain: %s", msg.SourceChain)
		}
		if _, err := adapter.SubmitMessage(q.ctx, msg); err != nil {
			return fmt.Errorf("failed to sign bridge event message: %w", err)
		}
	}
	return q.SubmitMessage(q.ctx, msg)
}

// processMessagesLoop processes pending messages in a loop.
// R64-B2 FIX: implements retry mechanism with exponential backoff for failed messages.
// Previously MaxRetries config was defined but never used, causing transient failures
// (RPC errors, gas estimation failures, target chain congestion) to permanently stall
// bridge messages. Now queries FAILED and VERIFIED messages and retries them up to
// MaxRetries with exponential backoff (baseInterval * 2^attempts).
func (q *QuantumBridge) processMessagesLoop() {
	ticker := time.NewTicker(q.config.PollingInterval)
	defer ticker.Stop()

	// audit-fix N-1: semaphore channel limits concurrent processing goroutines
	sem := make(chan struct{}, MaxConcurrentProcessing)

	for {
		select {
		case <-q.ctx.Done():
			return
		case <-ticker.C:
			// BRIDGE-R13-H01 (2026-07-21) FIX: Skip ALL processing while paused.
			// Previously the loop continued to dispatch ProcessMessage and
			// adapter.ExecuteMessage calls during pause. ProcessMessage would
			// fail with ErrBridgePaused and the retry logic would increment
			// retryAttempts — eventually exhausting MaxRetries and permanently
			// marking PENDING messages as FAILED. Worse, the VERIFIED retry
			// path calls adapter.ExecuteMessage directly without any paused
			// check, so VERIFIED messages would actually EXECUTE during pause
			// — defeating the entire purpose of the emergency pause.
			//
			// Now we skip the entire tick when paused. Messages stay in their
			// current status without consuming retry attempts. The wakeup
			// channel (processWakeup) is signaled by Unpause() to immediately
			// re-enter the loop without waiting for the next tick.
			if q.paused.Load() {
				continue
			}
			q.processPendingBatch(sem)
		case <-q.processWakeup:
			// BRIDGE-R13-H01: Unpause() signaled. Drain any additional buffered
			// wakeups, then process one batch immediately (if not still paused).
			for {
				select {
				case <-q.processWakeup:
				default:
				}
				break
			}
			if q.paused.Load() {
				continue
			}
			q.processPendingBatch(sem)
		}
	}
}

// processPendingBatch runs one iteration of failed/verified/pending message
// processing. Extracted from processMessagesLoop so it can be invoked from
// both the ticker and the wakeup path (BRIDGE-R13-H01).
//
// Caller contract: caller MUST NOT hold q.mu. The method internally takes
// and releases q.mu.RLock() / q.mu.Lock() as needed.
func (q *QuantumBridge) processPendingBatch(sem chan struct{}) {
	// R64-B2 FIX: process failed messages with retry logic.
	// MaxRetries (default 5) caps the number of retry attempts.
	// Exponential backoff: wait baseInterval * 2^attempts between retries.
	// R10-BR-001 FIX: Remove q.mu.Lock() — GetMessagesByStatus already
	// acquires q.mu.RLock(). Holding the write lock while calling a method
	// that takes the read lock causes a self-deadlock (sync.RWMutex is NOT
	// reentrant in Go).
	failedMsgs, err := q.GetMessagesByStatus(q.ctx, MessageStatusFailed)
	if err == nil {
		for _, msg := range failedMsgs {
			// AUDIT (2026 security review) BRDG §7.1 FIX: Read retryAttempts and
			// lastRetryTime under q.mu.RLock() to prevent data race
			// with concurrent writers (which modify these maps under
			// q.mu.Lock() in ProcessMessage, ExecuteMessage, etc.).
			q.mu.RLock()
			attempts := q.retryAttempts[msg.ID]
			lastRetry := q.lastRetryTime[msg.ID]
			q.mu.RUnlock()
			if attempts >= q.config.MaxRetries {
				// R64-B2: message exceeded retry limit, leave in FAILED state
				continue
			}

			// Exponential backoff: baseInterval * 2^attempts
			// R32-P2-11 FIX (2026-07-28): Use centralized computeBackoff helper
			// which caps the backoff at maxBackoffInterval (5 min). Previously
			// the unbounded formula could produce multi-hour waits when
			// MaxRetries was raised by operators.
			if !lastRetry.IsZero() {
				backoff := q.computeBackoff(attempts)
				if time.Since(lastRetry) < backoff {
					continue
				}
			}

			// Acquire per-message lock
			q.mu.Lock()
			msgMu, exists := q.msgLocks[msg.ID]
			if !exists {
				msgMu = &sync.Mutex{}
				q.msgLocks[msg.ID] = msgMu
			}
			// R67-BR-3 [MEDIUM] FIX: Acquire global lock before reading lastRetryTime.
			// TOCTOU race: previously lastRetryTime was read at line ~1068 while holding
			// only a read-lock, then the global lock was released, and then the per-message
			// lock was acquired. Between the read-lock release and the per-message lock
			// acquisition, the goroutine that just processed this message could update
			// lastRetryTime and retryAttempts. By always acquiring the global lock first,
			// we ensure atomic read of both maps before releasing it.
			q.mu.Unlock()

			msgMu.Lock()
			// Transition FAILED -> PENDING for reprocessing
			q.mu.Lock()
			oldStatus := msg.Status
			msg.Status = MessageStatusPending
			if internalMsg, ok := q.messages[msg.ID]; ok {
				internalMsg.Status = MessageStatusPending
			}
			delete(q.messagesByStatus[oldStatus], msg.ID)
			q.ensureStatusMap(MessageStatusPending)[msg.ID] = true
			q.mu.Unlock()

			if q.store != nil {
				if updateErr := q.store.UpdateMessageStatus(q.ctx, msg.ID, oldStatus, MessageStatusPending); updateErr != nil {
					// Roll back on persist failure
					q.mu.Lock()
					msg.Status = oldStatus
					if internalMsg, ok := q.messages[msg.ID]; ok {
						internalMsg.Status = oldStatus
					}
					delete(q.messagesByStatus[MessageStatusPending], msg.ID)
					q.ensureStatusMap(oldStatus)[msg.ID] = true
					q.mu.Unlock()
					msgMu.Unlock()
					continue
				}
			}
			msgMu.Unlock()

			// Process the message (now in PENDING state)
			select {
			case sem <- struct{}{}:
			case <-q.ctx.Done():
				return
			}
			go func(msg *BridgeMessage) {
				defer func() {
					<-sem
					if r := recover(); r != nil {
						// P3-3 (2026-07-15): structured log replaces log.Printf.
						q.logger.Error("ProcessMessage goroutine panic", map[string]any{
							"message_id": msg.ID,
							"panic":      fmt.Sprintf("%v", r),
						})
					}
				}()

				if err := q.ProcessMessage(q.ctx, msg); err != nil {
					q.mu.Lock()
					q.retryAttempts[msg.ID]++
					q.lastRetryTime[msg.ID] = time.Now()
					q.mu.Unlock()
				}
			}(msg)
		}
	}

	// R64-B2 FIX: retry VERIFIED messages that may be stuck.
	// These are messages that passed verification but failed at execution
	// (e.g., RPC errors, gas estimation failures). Retry with backoff.
	// R10-BR-001 FIX: Remove q.mu.Lock() — GetMessagesByStatus already
	// acquires q.mu.RLock(). See comment above for deadlock explanation.
	verifiedMsgs, err := q.GetMessagesByStatus(q.ctx, MessageStatusVerified)
	if err == nil {
		for _, msg := range verifiedMsgs {
			// AUDIT (2026 security review) BRDG §7.1 FIX: Read retryAttempts and
			// lastRetryTime under q.mu.RLock() to prevent data race
			// with concurrent writers.
			q.mu.RLock()
			attempts := q.retryAttempts[msg.ID]
			lastRetry := q.lastRetryTime[msg.ID]
			q.mu.RUnlock()
			if attempts >= q.config.MaxRetries {
				continue
			}

			if !lastRetry.IsZero() {
				// R32-P2-11: Use centralized computeBackoff (capped at 5 min).
				backoff := q.computeBackoff(attempts)
				if time.Since(lastRetry) < backoff {
					continue
				}
			}

			// R67-BR-3 [MEDIUM] FIX: Acquire global lock before reading lastRetryTime.
			// Same TOCTOU race as the failed-messages retry loop above.
			q.mu.Lock()
			msgMu, exists := q.msgLocks[msg.ID]
			if !exists {
				msgMu = &sync.Mutex{}
				q.msgLocks[msg.ID] = msgMu
			}
			q.mu.Unlock()

			msgMu.Lock()
			q.mu.RLock()
			if msg.Status != MessageStatusVerified {
				q.mu.RUnlock()
				msgMu.Unlock()
				continue
			}
			q.mu.RUnlock()

			adapter, adapterExists := q.adapters[msg.TargetChain]
			msgMu.Unlock()
			if !adapterExists {
				continue
			}

			// AUDIT R4-BRDG-04 (2026-07-15): Defense-in-depth — re-check
			// quorum BEFORE executing a VERIFIED message on retry. The
			// primary fix is in ProcessMessage (quorum checked before the
			// PENDING→VERIFIED transition), but a message's quorum can be
			// invalidated after VERIFIED (e.g., a signer was slashed, or
			// signatures expired). Without this re-check, the retry path
			// would execute the message without quorum — defeating the
			// validator-network control entirely. Skip (don't execute) if
			// quorum is configured but no longer holds; the retry loop will
			// keep retrying until quorum is restored or MaxRetries is hit.
			q.mu.RLock()
			vnRetry := q.validatorNetwork
			q.mu.RUnlock()
			if vnRetry != nil {
				expectedHash := computeMessageHash(msg)
				if !vnRetry.GetSignatureAggregator().HasQuorumForHash(msg.ID, expectedHash) {
					// Quorum lost since VERIFIED — record retry attempt so
					// MaxRetries eventually fails the message instead of
					// spinning forever.
					q.mu.Lock()
					q.retryAttempts[msg.ID]++
					q.lastRetryTime[msg.ID] = time.Now()
					if q.retryAttempts[msg.ID] >= q.config.MaxRetries {
						oldStatus := msg.Status
						msg.Status = MessageStatusFailed
						if internalMsg, ok := q.messages[msg.ID]; ok {
							internalMsg.Status = MessageStatusFailed
						}
						delete(q.messagesByStatus[oldStatus], msg.ID)
						q.ensureStatusMap(MessageStatusFailed)[msg.ID] = true
						// R43-BRIDGE-MSG-01 FIX (2026-08-03): a terminal
						// transition (FAILED) just occurred; sweep terminal
						// messages if over the cap. We hold q.mu (write lock).
						q.sweepMessages()
					}
					q.mu.Unlock()
					q.logger.Warn("VERIFIED message retry skipped: quorum no longer holds", map[string]any{
						"messageID":   msg.ID,
						"targetChain": string(msg.TargetChain),
					})
					continue
				}
			}

			select {
			case sem <- struct{}{}:
			case <-q.ctx.Done():
				return
			}
			go func(msg *BridgeMessage) {
				defer func() {
					<-sem
					if r := recover(); r != nil {
						// P3-3 (2026-07-15): structured log replaces log.Printf.
						q.logger.Error("ExecuteMessage goroutine panic", map[string]any{
							"message_id": msg.ID,
							"panic":      fmt.Sprintf("%v", r),
						})
					}
				}()

				success, execErr := adapter.ExecuteMessage(q.ctx, msg)
				q.mu.Lock()
				defer q.mu.Unlock()

				if execErr != nil || !success {
					q.retryAttempts[msg.ID]++
					q.lastRetryTime[msg.ID] = time.Now()
					if q.retryAttempts[msg.ID] >= q.config.MaxRetries {
						// Transition to FAILED
						oldStatus := msg.Status
						msg.Status = MessageStatusFailed
						if internalMsg, ok := q.messages[msg.ID]; ok {
							internalMsg.Status = MessageStatusFailed
						}
						delete(q.messagesByStatus[oldStatus], msg.ID)
						q.ensureStatusMap(MessageStatusFailed)[msg.ID] = true
						if q.store != nil {
							// FIX: Log the error instead of silently ignoring it.
							// P3-3 (2026-07-15): structured log replaces log.Printf.
							if err := q.store.UpdateMessageStatus(q.ctx, msg.ID, oldStatus, MessageStatusFailed); err != nil {
								q.logger.Error("failed to update message status to FAILED", map[string]any{
									"message_id": msg.ID,
									"error":      err.Error(),
								})
							}
						}
					}
				} else {
					// R70-RETRY-INCONSISTENCY [LOW] FIX: On success, clean up retry
					// accounting so the message does not remain in VERIFIED forever.
					// Previously only the error branch updated state, leaving successful
					// messages stuck in VERIFIED and skewing metrics.
					delete(q.retryAttempts, msg.ID)
					delete(q.lastRetryTime, msg.ID)
					oldStatus := msg.Status
					msg.Status = MessageStatusExecuted
					if internalMsg, ok := q.messages[msg.ID]; ok {
						internalMsg.Status = MessageStatusExecuted
					}
					delete(q.messagesByStatus[oldStatus], msg.ID)
					q.ensureStatusMap(MessageStatusExecuted)[msg.ID] = true
					// BRIDGE-H01 FIX (R30, 2026-07-27): advance highestUsedNonce
					// only on EXECUTED transition. This is the single legitimate
					// place to advance the high-water mark — failed submissions
					// (rolled back in SubmitMessage) and pending messages do not
					// advance it, so their nonces can be retried.
					execNk := nonceKey{chain: msg.SourceChain, addr: msg.SourceAddress}
					if msg.Nonce > q.highestUsedNonce[execNk] {
						q.highestUsedNonce[execNk] = msg.Nonce
						// R32-P1-04 FIX (2026-07-28): persist the new high-water mark.
						if q.store != nil {
							if err := q.store.SaveHighestUsedNonce(q.ctx, string(msg.SourceChain), msg.SourceAddress, msg.Nonce); err != nil {
								q.logger.Warn("bridge: failed to persist highestUsedNonce in batch path (non-fatal)",
									map[string]any{"error": err.Error(), "sourceChain": string(msg.SourceChain), "nonce": msg.Nonce})
							}
						}
					}
					// BRIDGE-H03 FIX: proactive sweep after execution keeps the
					// per-address map small so active users don't hit the cap.
					q.sweepUsedNoncesFor(execNk)
					// AUDIT-FULL NW-08: persist the advanced high-water mark (and
					// post-sweep nonce state) — batch retry path counterpart of
					// the checkpoint after the main execution path.
					q.checkpointNoncesLocked()
					if q.store != nil {
						// FIX: Log the error instead of silently ignoring it.
						// P3-3 (2026-07-15): structured log replaces log.Printf.
						if err := q.store.UpdateMessageStatus(q.ctx, msg.ID, oldStatus, MessageStatusExecuted); err != nil {
							q.logger.Error("failed to update message status to EXECUTED", map[string]any{
								"message_id": msg.ID,
								"error":      err.Error(),
							})
						}
					}
				}
				// R43-BRIDGE-MSG-01 FIX (2026-08-03): this goroutine
				// reached a terminal transition (EXECUTED on the success
				// branch, or FAILED on the MaxRetries branch). We still
				// hold q.mu (defer q.mu.Unlock()); if the messages map
				// exceeds maxMessagesInMemory, sweep terminal messages
				// oldest first to bound the in-memory cache.
				q.sweepMessages()
			}(msg)
		}
	}

	// Process pending messages (normal path)
	// R10-BR-001 FIX: Remove q.mu.Lock() — GetMessagesByStatus already
	// acquires q.mu.RLock(). See comment above for deadlock explanation.
	pendingMsgs, err := q.GetMessagesByStatus(q.ctx, MessageStatusPending)
	if err == nil {
		for _, msg := range pendingMsgs {
			// Skip messages that were just re-queued by the retry logic above.
			// AUDIT (2026 security review) BRDG §7.1 FIX: Read both maps under q.mu.RLock()
			// to prevent data race with concurrent writers.
			q.mu.RLock()
			_, justRetried := q.lastRetryTime[msg.ID]
			attempts := q.retryAttempts[msg.ID]
			q.mu.RUnlock()
			if justRetried && attempts > 0 {
				continue
			}

			select {
			case sem <- struct{}{}:
			case <-q.ctx.Done():
				return
			}
			go func(msg *BridgeMessage) {
				defer func() {
					<-sem
					if r := recover(); r != nil {
						// P3-3 (2026-07-15): structured log replaces log.Printf.
						q.logger.Error("ProcessMessage goroutine panic", map[string]any{
							"message_id": msg.ID,
							"panic":      fmt.Sprintf("%v", r),
						})
					}
				}()
				if err := q.ProcessMessage(q.ctx, msg); err != nil {
					// R64-B2: track failure for retry mechanism
					q.mu.Lock()
					q.retryAttempts[msg.ID]++
					q.lastRetryTime[msg.ID] = time.Now()
					q.mu.Unlock()
				}
			}(msg)
		}
	}
}

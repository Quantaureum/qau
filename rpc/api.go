// Quantaureum Node source, version 1.0.0.
package rpc

// L14-029 SECURITY NOTE: Gas estimation (eth_estimateGas) provides an
// approximation, not an exact value. The estimation runs the transaction
// against the current state and adds a safety margin (typically 10-20%).
// However, the actual gas cost may differ if the state changes between
// estimation and execution (e.g., another transaction modifies storage
// that the estimation assumed). Callers should always set a gas limit
// with adequate margin above the estimate to avoid out-of-gas failures.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/privacy"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/txpool"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// ErrProofNotSupported is returned by a StateReader that cannot produce a
// real Verkle proof. The RPC layer falls back to the Unverified path
// honestly rather than fabricating a pseudo-proof.
// R38-P2-04 DEEP FIX (2026-08-02).
var ErrProofNotSupported = fmt.Errorf("state reader does not support stateRoot-aware proofs")

// maxStakingNoncesPerAddress is the maximum number of tracked nonces per address.
// audit-fix NEW-18: bounded to prevent unbounded memory growth.
const maxStakingNoncesPerAddress = 10000

// maxStakingTrackedAddresses is the maximum number of addresses tracked for staking nonces.
const maxStakingTrackedAddresses = 100000

// slotsPerEpoch is the number of slots per QPOS epoch.
// This MUST match consensus.SlotsPerEpoch (currently 32). If consensus
// changes this value, update here accordingly.
// L19-004 FIX: Extracted from hardcoded magic number to a named constant
// for maintainability and clarity.
const slotsPerEpoch = 32

// FIX: Define DefaultGasPriceWei as a named constant instead of
// scattering the magic number 1_000_000_000 across 4 locations. This makes
// it easy to find and update when the gas price policy changes.
const DefaultGasPriceWei = 1_000_000_000 // 1 Gwei = 10^9 wei

// API provides the core RPC API methods
type API struct {
	// Backend interfaces (to be injected)
	stateReader     StateReader
	blockReader     BlockReader
	txPool          TxPool
	chainInfo       ChainInfo
	accountManager  AccountManager
	stakingManager  StakingManager
	contractCaller  ContractCaller
	snapshotManager SnapshotManager

	// consensusStakeUpdater propagates staking changes to the consensus layer
	// (ValidatorManager). Without this, qau_stake only updates the economics
	// StakingManager but QPOS still sees stake=0, resulting in low participation
	// rate and no finality.
	consensusStakeUpdater ConsensusStakeUpdater

	// R45-FORKRECOVERY-API (2026-08-12): injected backend for
	// debug_rollbackChainToHeight. nil = endpoint disabled.
	forkRecoveryMgr ForkRecoveryManager

	// audit-fix NEW-18: nonce tracking for replay protection on signed staking operations.
	stakingNonceMu    sync.Mutex
	stakingUsedNonces map[types.Address]map[string]time.Time

	// R131: optional backend for the validator-key registry status RPC.
	// Injected by node startup; nil → endpoint reports "unavailable".
	validatorKeyStatusFn func(addr types.Address) (map[string]any, error)

	devMode bool

	// Privacy manager for privacy transaction operations
	privacyMgr *privacy.PrivacyManager

	// FIX: configurable default gas price (was hardcoded inline as 1 Gwei).
	// Used as fallback when dynamic gas price from recent blocks is unavailable.
	defaultGasPrice *big.Int

	// FIX: optional admin allowlist for state-mutating staking operations.
	// When non-empty, only addresses in this set may perform admin-gated
	// operations. When empty, no restriction is enforced (backward-compatible).
	adminAddrs map[types.Address]bool

	// FIX: enforceAdminAuth enables fail-closed admin checks.
	// When true (production mode), requireAdmin returns an error if the admin
	// allowlist is nil/empty, blocking all state-mutating staking operations
	// until admin addresses are configured. When false (default, test/dev mode),
	// the allowlist is optional (backward-compatible).
	enforceAdminAuth bool
}

// StateReader provides state reading capabilities.
//
// R38-P2-04 DEEP FIX (2026-08-02): Add three stateRoot-aware methods so
// eth_getProof can return proofs cryptographically bound to the canonical
// chain state root, not pseudo-proofs against a freshly-built synthetic
// singleton tree.
//
//   - StateRoot() returns the canonical chain state root the proofs
//     below bind to. Callers compare this to the block's StateRoot to
//     confirm the proof is for the canonical state they expect.
//   - ProveAccount(addr) returns a VerkleProof for the account at addr.
//   - ProveStorage(addr, key) returns a VerkleProof for one storage slot.
//
// Implementations SHOULD delegate to StateDB.stateTrie.Prove (real
// Verkle path) — NOT to GetAccountWithProof, which returns a
// "Simplified" placeholder proof. Adapters whose backend cannot produce
// real Verkle proofs MUST return ErrProofNotSupported so the RPC layer
// falls back to the Unverified path honestly rather than fabricating a
// pseudo-proof and silently turning Unverified=false.
//
// Refer to qaudb/trie/verkle.go for the VerkleProof struct layout
// (Path []types.Hash, Siblings [][]SiblingWithIdx, ExtensionStems ...).
type StateReader interface {
	GetBalance(addr types.Address) *big.Int
	GetNonce(addr types.Address) uint64
	GetCode(addr types.Address) []byte
	GetState(addr types.Address, key types.Hash) types.Hash
	IterateAccounts(fn func(addr types.Address, code []byte, balance *big.Int) bool)

	// R38-P2-04 DEEP FIX (2026-08-02): StateRoot-aware proof methods.
	// See the long comment above for rationale. Adapters whose backend
	// cannot produce real Verkle proofs MUST return ErrProofNotSupported.
	StateRoot() types.Hash
	ProveAccount(addr types.Address) (*trie.VerkleProof, error)
	ProveStorage(addr types.Address, key types.Hash) (*trie.VerkleProof, error)
}

// ContractCallRequest represents a contract call request
type ContractCallRequest struct {
	From  types.Address
	To    types.Address
	Value *big.Int
	Data  []byte
	Gas   uint64
}

// ContractCallResult represents the result of a contract call
type ContractCallResult struct {
	ReturnData []byte
	GasUsed    uint64
	Error      error
}

// ContractCaller provides contract call capabilities for eth_call
type ContractCaller interface {
	Call(req *ContractCallRequest) (*ContractCallResult, error)
}

// BlockReader provides block reading capabilities
type BlockReader interface {
	GetBlockByHash(hash types.Hash) (any, error)
	GetBlockByHeight(height uint64) (any, error)
	GetLatestHeight() uint64
	GetTransaction(hash types.Hash) (any, error)
	GetTransactionReceipt(hash types.Hash) (any, error)
	GetBlockByHeightRange(from, to uint64) ([]any, error)
	GetGasLimit() uint64
}

// SnapshotManager provides snapshot creation and restoration capabilities
type SnapshotManager interface {
	CreateSnapshot(blockHeight uint64) (map[string]any, error)
	RestoreSnapshot(blockHeight uint64) (map[string]any, error)
}

// ForkRecoveryManager provides fork-recovery operations that combine block-store
// truncation with state rollback. Used by the debug_rollbackChainToHeight RPC
// (R45-FORKRECOVERY-API, 2026-08-12) to manually resolve persistent chain
// forks produced by a buggy sealer schedule (the earlier R45-WARMUP-EXPAND-FIX
// pre-filled epochVRFAccumulator with chain-tip placeholder values, which
// diverged from the canonical chain's accumulated VRF and produced blocks with
// different proposer addresses and irreconcilable branches).
type ForkRecoveryManager interface {
	// RollbackToFork deletes all blocks at or above forkHeight from the
	// block store and rewinds stateDB to the same height. Returns the
	// number of blocks deleted. After rollback, the syncer resumes from
	// peers starting at forkHeight, accepting only canonical (peer-signed)
	// blocks — eliminating the locally-poisoned branch.
	RollbackToFork(forkHeight uint64) (int, error)
}

// TxPool provides transaction pool capabilities
type TxPool interface {
	AddTransaction(tx []byte) (types.Hash, error)
	// AddVerifiedTransaction adds a pre-verified transaction (signature already
	// checked by caller, e.g. qau_stake verified via staking signature) to the
	// pool without re-running Dilithium3 signature verification. The transaction
	// is packed into blocks and propagates to all nodes through block sync.
	AddVerifiedTransaction(tx *encoding.Transaction) (types.Hash, error)
	GetPendingTransactions() []any
	GetPendingCount() int
	GetQueuedCount() int
	GetPendingNonce(addr types.Address) uint64
	AddUserOperation(uo *encoding.UserOperation) error
	GetUserOperation(hash types.Hash) *encoding.UserOperation
	PendingUserOps() []*encoding.UserOperation
}

// ChainInfo provides chain information
type ChainInfo interface {
	ChainID() uint64
	NetworkID() uint64
	ProtocolVersion() string
	IsSyncing() bool
	HighestBlock() uint64 // audit-fix R6-L1: highest known block from syncer
	PeerCount() int
	GetPeers() []PeerInfo
	GetQPOSStatus() map[string]any
	GetEnodeURL() string
	// FIX: Expose configured listen address and advertised IP
	// so AdminNodeInfo can report the actual bind address instead of
	// parsing it from the enode URL.
	GetListenAddr() string
	GetAdvertisedIP() string
}

// PeerInfo represents information about a connected peer
type PeerInfo struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Caps      []string `json:"caps"`
	Network   Network  `json:"network"`
	Protocols Protocol `json:"protocols"`
}

// Network represents peer network information
type Network struct {
	LocalAddress  string `json:"localAddress"`
	RemoteAddress string `json:"remoteAddress"`
}

// Protocol represents peer protocol information
type Protocol struct {
	Qau *QauProtocol `json:"qau,omitempty"`
}

// QauProtocol represents QAU protocol info
type QauProtocol struct {
	Version    int    `json:"version"`
	Difficulty string `json:"difficulty"`
	Head       string `json:"head"`
}

// AccountManager provides account management for sendTransaction
type AccountManager interface {
	SignTransaction(from types.Address, tx any) ([]byte, error)
	UnlockAccountDirect(addr types.Address, password string) error
	IsUnlocked(addr types.Address) bool
}

// StakingManager provides staking capabilities
type StakingManager interface {
	Stake(addr types.Address, amount *big.Int, commission uint32, blockHeight uint64) error
	RequestUnstake(addr types.Address, amount *big.Int, blockHeight uint64) error
	CompleteUnstake(addr types.Address, currentHeight uint64) (*big.Int, error)
	GetStake(addr types.Address) (*StakeInfo, error)
	GetUnstakeRequest(addr types.Address) (*UnstakeRequest, error)
	GetTotalStaked() *big.Int
	GetAllStakes() []*StakeInfo
	GetActiveValidators() map[types.Address]*big.Int
	ValidatorCount() int
	ActiveValidatorCount() int
	GetConfig() *StakingConfig
	GetRewardPoolStatus() map[string]any
	GetTotalRewardsClaimed() *big.Int
	UpdateCommission(caller, addr types.Address, commission uint32) error
	SaveState() error
}

// StakeInfo represents a validator's stake information (RPC version)
type StakeInfo struct {
	Address     types.Address
	Amount      *big.Int
	Commission  uint32
	StakeHeight uint64
	Active      bool
}

// UnstakeRequest represents a pending unstake request (RPC version)
type UnstakeRequest struct {
	Address       types.Address
	Amount        *big.Int
	RequestHeight uint64
	UnlockHeight  uint64
}

// ConsensusStakeUpdater bridges RPC staking operations to the consensus layer.
// When qau_stake/qau_unstake update the economics StakingManager, this interface
// propagates the change to the consensus ValidatorManager so QPOS sees the
// updated stake for proposer selection and finality.
type ConsensusStakeUpdater interface {
	// UpdateValidatorStake sets the validator's stake in the consensus layer.
	// If the validator doesn't exist, it should be added first.
	UpdateValidatorStake(addr types.Address, stake *big.Int, commission uint32, blockHeight uint64) error
	// IsKnownValidator checks if the address is registered in the validator manager.
	IsKnownValidator(addr types.Address) bool
}

// StakingConfig represents staking configuration (RPC version)
type StakingConfig struct {
	MinStakeAmount  *big.Int
	MaxStakeAmount  *big.Int
	UnbondingPeriod uint64
	MaxValidators   uint32
	MinCommission   uint32
	MaxCommission   uint32
}

// NewAPI creates a new API instance
func NewAPI(state StateReader, blocks BlockReader, pool TxPool, chain ChainInfo, accMgr AccountManager) *API {
	return &API{
		stateReader:       state,
		blockReader:       blocks,
		txPool:            pool,
		chainInfo:         chain,
		accountManager:    accMgr,
		stakingUsedNonces: make(map[types.Address]map[string]time.Time),
		privacyMgr:        privacy.NewPrivacyManager(privacy.DefaultPrivacyConfig()),
		// FIX: default gas price is now configurable (was hardcoded 1 Gwei).
		// FIX: Use named constant instead of magic number.
		defaultGasPrice: big.NewInt(DefaultGasPriceWei),

		enforceAdminAuth: true, //  fail-closed by default
	}
}

// SetDefaultGasPrice sets the default gas price used as fallback when dynamic
// gas price from recent blocks is unavailable.
// FIX: allows configuration of gas price from config files instead of
// hardcoding 1 Gwei inline.
func (api *API) SetDefaultGasPrice(price *big.Int) {
	if price == nil || price.Sign() <= 0 {
		return
	}
	api.defaultGasPrice = new(big.Int).Set(price)
}

// SetDevMode enables or disables dev-mode-only RPC methods.
// audit-fix WS-H3: must be called explicitly to enable SignQuantumTransaction.
func (api *API) SetDevMode(enabled bool) {
	if DEV_MODE_ENABLED != "true" {
		api.devMode = false
		return
	}
	api.devMode = enabled
}

// SetStakingManager sets the staking manager for the API
func (api *API) SetStakingManager(sm StakingManager) {
	if sm == nil {
		return
	}
	api.stakingManager = sm
}

// SetConsensusStakeUpdater injects the consensus-layer stake updater.
// Called by node.go during initialization to bridge RPC staking operations
// to the ValidatorManager.
func (api *API) SetConsensusStakeUpdater(csu ConsensusStakeUpdater) {
	if csu == nil {
		return
	}
	api.consensusStakeUpdater = csu
}

func (api *API) SetPrivacyManager(pm *privacy.PrivacyManager) {
	if pm == nil {
		return
	}
	api.privacyMgr = pm
}

// SetContractCaller sets the contract caller for the API (for eth_call operations)
func (api *API) SetContractCaller(cc ContractCaller) {
	if cc == nil {
		return
	}
	api.contractCaller = cc
}

// SetSnapshotManager sets the snapshot manager for the API (for qau_createSnapshot/qau_restoreSnapshot)
func (api *API) SetSnapshotManager(sm SnapshotManager) {
	if sm == nil {
		return
	}
	api.snapshotManager = sm
}

// SetForkRecoveryManager sets the backend for debug_rollbackChainToHeight
// (R45-FORKRECOVERY-API, 2026-08-12). When not set, the endpoint returns
// "fork recovery manager not available".
func (api *API) SetForkRecoveryManager(frm ForkRecoveryManager) {
	if frm == nil {
		return
	}
	api.forkRecoveryMgr = frm
}

func (api *API) requireStakingManager() *Error {
	if api.stakingManager == nil {
		return NewError(ErrCodeInternal, "staking manager not available")
	}
	return nil
}

func (api *API) requireTxPool() *Error {
	if api.txPool == nil {
		return NewError(ErrCodeInternal, "transaction pool not available")
	}
	return nil
}

// maxPaginationOffset is the absolute upper bound on the offset parameter
// accepted by any paginated RPC endpoint. P2P-R10-M2 (2026-07-19) FIX:
// previously, endpoints only clamped offset to be non-negative, but a
// caller could supply math.MaxInt64 which (when added to limit) could
// overflow on 32-bit builds and produced confusing empty responses. We
// cap offset at a generous 1<<31-1 (same as MaxInt32) which is well
// above any realistic page count.
const maxPaginationOffset = 1<<31 - 1

// sanitizePagination clamps limit/offset pagination parameters to safe,
// consistent bounds. P2P-R10-M2 (2026-07-19) FIX.
//
// Rules:
//   - limit <= 0 or limit > maxLimit → defaultLimit
//   - offset < 0 → 0
//   - offset > maxPaginationOffset → maxPaginationOffset
//
// defaultLimit MUST be <= maxLimit; otherwise defaultLimit is used as-is
// (a programming bug callers should not trigger).
func sanitizePagination(limit, offset, defaultLimit, maxLimit int) (int, int) {
	if defaultLimit <= 0 || defaultLimit > maxLimit {
		defaultLimit = maxLimit
	}
	if limit <= 0 || limit > maxLimit {
		limit = defaultLimit
	}
	if offset < 0 {
		offset = 0
	}
	if offset > maxPaginationOffset {
		offset = maxPaginationOffset
	}
	return limit, offset
}

// SetAdminAddresses configures the admin allowlist for state-mutating staking operations.
// FIX: when non-empty, only these addresses may perform admin-gated staking operations.
func (api *API) SetAdminAddresses(addrs []types.Address) {
	api.adminAddrs = make(map[types.Address]bool, len(addrs))
	for _, a := range addrs {
		api.adminAddrs[a] = true
	}
}

// SetEnforceAdminAuth enables fail-closed admin authentication.
// FIX: when enabled (production mode), requireAdmin rejects all
// state-mutating staking operations if no admin allowlist has been configured,
// preventing unauthorized access when the admin list is empty.
// When disabled (default), the allowlist is optional (backward-compatible).
func (api *API) SetEnforceAdminAuth(enabled bool) {
	api.enforceAdminAuth = enabled
}

// requireAuthorizedUser returns an error when an allowlist is configured and
// the given address is not in it.
//
// AUDIT (2026) API-07 FIX: Renamed from requireAdmin to clarify semantics.
// This is a USER ALLOWLIST check (authorized-user gating), NOT an admin
// privilege check. The adminAddrs field is a per-user allowlist that controls
// who can call state-mutating staking operations — it is not the same as the
// server-level admin authorization in ValidateAdminRequest. The old name
// caused confusion about what security boundary was being enforced.
//
// FIX: when enforceAdminAuth is true (production mode) and the
// allowlist is nil/empty, this fails-closed, returning an error instead of
// allowing unauthenticated access. When enforceAdminAuth is false (default,
// test/dev mode), an empty allowlist means no restriction (backward-compatible).
func (api *API) requireAuthorizedUser(addr types.Address) error {
	if api.enforceAdminAuth && len(api.adminAddrs) == 0 {
		return fmt.Errorf("authorized-user allowlist not configured: state-mutating staking operations are blocked until authorized addresses are set")
	}
	if len(api.adminAddrs) == 0 {
		return nil
	}
	if !api.adminAddrs[addr] {
		return fmt.Errorf("address %s is not in the authorized-user allowlist for staking operations", addr.ToHexAddress())
	}
	return nil
}

// verifyStakingSignature verifies a Dilithium3 signature for a staking operation.
// audit-fix NEW-18: all state-mutating staking RPC calls must include a signature
// proving ownership of the address being operated on.
// The signature should be over: method || userAddress || nonce || params...
func (api *API) verifyStakingSignature(method string, userAddr types.Address, nonce, params string, signature, pubKeyHex string) error {
	// FIX: enforce admin allowlist when configured for state-mutating staking operations.
	if err := api.requireAuthorizedUser(userAddr); err != nil {
		return err
	}
	if signature == "" || pubKeyHex == "" {
		return fmt.Errorf("signature and publicKey are required for state-mutating staking operations")
	}
	if nonce == "" {
		return fmt.Errorf("nonce is required for replay protection")
	}

	// Check nonce hasn't been used before
	api.stakingNonceMu.Lock()
	// R48-H-H1 FIX: Restructured to check limits BEFORE inserting.
	// 1. Check if this address would exceed the global address limit
	// 2. Check if this nonce was already used
	// 3. Evict oldest nonces for this address if at per-address limit, BEFORE inserting
	// Previously: global limit used `>` (off-by-one), and eviction happened after insertion.
	if api.stakingUsedNonces[userAddr] == nil {
		// New address: check global address count limit
		// R48-H-H1 FIX: Use >= to enforce strict limit (was >, allowed N+1)
		if len(api.stakingUsedNonces) >= maxStakingTrackedAddresses {
			api.stakingNonceMu.Unlock()
			return fmt.Errorf("too many tracked addresses (memory limit)")
		}
		api.stakingUsedNonces[userAddr] = make(map[string]time.Time)
	}
	// M-NEW-1 FIX: Evict nonces older than 10 minutes for time-based expiration.
	// This ensures replay protection works even after the in-memory limit eviction
	// removes old entries, and provides bounded temporal protection.
	const stakingNonceTTL = 10 * time.Minute
	now := time.Now()
	for k, ts := range api.stakingUsedNonces[userAddr] {
		if now.Sub(ts) > stakingNonceTTL {
			delete(api.stakingUsedNonces[userAddr], k)
		}
	}
	// Check replay
	if _, used := api.stakingUsedNonces[userAddr][nonce]; used {
		api.stakingNonceMu.Unlock()
		return fmt.Errorf("nonce already used (replay detected)")
	}
	// Evict oldest nonces BEFORE inserting if at limit
	if len(api.stakingUsedNonces[userAddr]) >= maxStakingNoncesPerAddress {
		type nonceEntry struct {
			nonce string
			ts    time.Time
		}
		entries := make([]nonceEntry, 0, len(api.stakingUsedNonces[userAddr]))
		for k, ts := range api.stakingUsedNonces[userAddr] {
			entries = append(entries, nonceEntry{k, ts})
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].ts.Before(entries[j].ts)
		})
		// R48-H-H1 FIX: Evict oldest half BEFORE insert to keep count bounded
		for i := 0; i < len(entries)/2; i++ {
			delete(api.stakingUsedNonces[userAddr], entries[i].nonce)
		}
	}
	// LOW-2 FIX: Reserve nonce with pending marker (zero time) instead of confirmed time.
	// This blocks concurrent requests for the same nonce, but allows rollback if
	// signature verification fails, preventing nonce consumption by invalid requests.
	api.stakingUsedNonces[userAddr][nonce] = time.Time{} // zero Time = pending
	api.stakingNonceMu.Unlock()

	// Parse signature
	// R32-P2-02 FIX (2026-07-28): Defense-in-depth — reject signatures
	// and public keys with wrong length at the RPC boundary, before
	// reaching crypto.PublicKeyFromBytes. Aligns with multisig_api.go:462
	// and governance_api.go:224.
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		api.rollbackStakingNonce(userAddr, nonce)
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sigBytes) != crypto.Dilithium3SignatureSize {
		api.rollbackStakingNonce(userAddr, nonce)
		return fmt.Errorf("invalid signature length: got %d, want %d", len(sigBytes), crypto.Dilithium3SignatureSize)
	}

	// Parse public key
	pubKeyBytes, err := hex.DecodeString(strings.TrimPrefix(pubKeyHex, "0x"))
	if err != nil {
		api.rollbackStakingNonce(userAddr, nonce)
		return fmt.Errorf("invalid publicKey hex: %w", err)
	}
	if len(pubKeyBytes) != crypto.Dilithium3PublicKeySize {
		api.rollbackStakingNonce(userAddr, nonce)
		return fmt.Errorf("invalid publicKey length: got %d, want %d", len(pubKeyBytes), crypto.Dilithium3PublicKeySize)
	}

	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		api.rollbackStakingNonce(userAddr, nonce)
		return fmt.Errorf("invalid Dilithium3 public key: %w", err)
	}

	// Verify the public key corresponds to the claimed address
	derivedAddr := pubKey.Address()
	if derivedAddr != userAddr {
		api.rollbackStakingNonce(userAddr, nonce)
		return fmt.Errorf("public key does not match claimed address")
	}

	// Construct message with nonce: method || chainID || address || nonce || params
	// audit-fix R11-M: Use delimiter to prevent field collision attacks
	// AUDIT (2026) KEYS-08: Include ChainID in the signed message to
	// prevent cross-chain replay (same signature reused on mainnet/testnet).
	// Previously the message was `method|address|nonce|params` with no
	// ChainID binding, so a staking signature from testnet could be replayed
	// on mainnet and vice versa.
	chainID := uint64(1)
	if api.chainInfo != nil {
		chainID = api.chainInfo.ChainID()
	}

	// R38-P0-02 (2026-08-01) FIX: route stake/unstake through the
	// canonical ComputeStakeAuthorizationHash domain. The legacy string
	// domain ("method|chainID|addr|nonce|params") did not cover tx.To,
	// tx.Value (in encoded form), or txType as a typed byte — so a relay
	// could tamper with tx.To (pointing funds at an attacker address)
	// while keeping the legacy string signature valid. The canonical
	// hash binds every consensus-affecting field, and the block
	// validator (VerifyTransactionAuthorization) re-derives the same
	// hash to verify. RPC is now just a relay that PRE-parses the
	// fields to the same format the block validator will use.
	if method == "stake" || method == "unstake" {
		// Parse the amount / commission out of params.
		// stake params layout: "amount|commission" (commission is uint32)
		// unstake params layout: "amount"
		var amountStr, commissionStr string
		parts := strings.Split(params, "|")
		amountStr = parts[0]
		if method == "stake" {
			if len(parts) < 2 {
				api.rollbackStakingNonce(userAddr, nonce)
				return fmt.Errorf("stake canonical verify: missing commission in params")
			}
			commissionStr = parts[1]
		}

		amount, ok := new(big.Int).SetString(amountStr, 10)
		if !ok {
			// fall back to hex (consistent with RPC entry parsing)
			amount, ok = new(big.Int).SetString(strings.TrimPrefix(strings.TrimPrefix(amountStr, "0x"), "0X"), 16)
			if !ok {
				api.rollbackStakingNonce(userAddr, nonce)
				return fmt.Errorf("stake canonical verify: cannot parse amount %q", amountStr)
			}
		}
		var commission uint64
		if method == "stake" {
			c, err2 := strconv.ParseUint(commissionStr, 10, 32)
			if err2 != nil {
				api.rollbackStakingNonce(userAddr, nonce)
				return fmt.Errorf("stake canonical verify: invalid commission %q: %w", commissionStr, err2)
			}
			commission = c
		}

		// Recipient + txType per method.
		var recipient types.Address
		var authType types.StakeAuthTxType
		if method == "stake" {
			recipient[18] = 0x10
			recipient[19] = 0x01
			authType = types.StakeAuthTypeStake
		} else {
			recipient[18] = 0x10
			recipient[19] = 0x02
			authType = types.StakeAuthTypeUnstake
			commission = 0 // unstake has no commission; canonical hash treats it as 0
		}

		canonical, err := types.ComputeStakeAuthorizationHash(
			chainID, userAddr, recipient, authType,
			amount, uint32(commission), nonce,
		)
		if err != nil {
			api.rollbackStakingNonce(userAddr, nonce)
			return fmt.Errorf("stake canonical verify: %w", err)
		}
		// R43-RPC-LEGACY-01 (2026-08-03): route through the canonical
		// encoding.VerifyStakeAuthorizationDigest helper rather than
		// hand-rolled `crypto.Verify(pubKey, canonical[:], sigBytes)`.
		// The helper applies the SAME pubkey/from address-binding check
		// (R38-P0-02) + canonical-hash computation + signature verify
		// that the L1 block validator's encoding.VerifyTransactionAuthorization
		// TxTypeStake branch performs, eliminating duplicate logic that
		// could drift from canonical. We keep the canonical-hash call
		// above for back-compat with the caller-provided error message
		// (helper returns false/nil on binding mismatch with no err
		// string — but the err path here is the hash computation). The
		// pre-computed canonical variable is also kept for the legacy
		// call sites that compare against it; this keeps the diff
		// minimal so we don't ship a behavior change beyond signature
		// verification path unification. On any binding mismatch /
		// verify-failure we return the same `"signature verification
		// failed (canonical)"` message; a future PR can split that
		// into distinct messages now that we know it's the canonical
		// entry point we'd be re-checking.
		_ = canonical // computed earlier; helper re-computes for verify
		verified, _ := encoding.VerifyStakeAuthorizationDigest(
			chainID, userAddr, recipient, authType, amount,
			uint32(commission), nonce, pubKeyBytes, sigBytes,
		)
		if !verified {
			api.rollbackStakingNonce(userAddr, nonce)
			return fmt.Errorf("signature verification failed (canonical)")
		}
		// LOW-2 FIX: Confirm the nonce.
		api.stakingNonceMu.Lock()
		if nonces, ok := api.stakingUsedNonces[userAddr]; ok {
			nonces[nonce] = time.Now()
		}
		api.stakingNonceMu.Unlock()
		return nil
	}

	// Legacy string-domain path — still used by claimRewards, which has
	// no canonical stake-authorization semantics (it targets the rewards
	// contract, not the staking/unstaking contract). Will be migrated in
	// a separate batch once the rewards RPC API is unified with the
	// canonical auth helper.
	message := []byte(method + "|" + strconv.FormatUint(chainID, 10) + "|" + userAddr.ToHexAddress() + "|" + nonce + "|" + params)

	// Verify Dilithium3 signature
	if !crypto.Verify(pubKey, message, sigBytes) {
		api.rollbackStakingNonce(userAddr, nonce)
		return fmt.Errorf("signature verification failed")
	}

	// LOW-2 FIX: Confirm the nonce by updating from pending (zero) to actual timestamp
	api.stakingNonceMu.Lock()
	if nonces, ok := api.stakingUsedNonces[userAddr]; ok {
		nonces[nonce] = time.Now()
	}
	api.stakingNonceMu.Unlock()

	return nil
}

// rollbackStakingNonce removes a pending nonce reservation when signature verification fails.
// LOW-2 FIX: prevents nonces from being permanently consumed by failed requests.
func (api *API) rollbackStakingNonce(userAddr types.Address, nonce string) {
	api.stakingNonceMu.Lock()
	defer api.stakingNonceMu.Unlock()
	if nonces, ok := api.stakingUsedNonces[userAddr]; ok {
		// Only delete if still in pending state (zero time)
		if ts, exists := nonces[nonce]; exists && ts.IsZero() {
			delete(nonces, nonce)
		}
	}
}

// extractStakingAuth extracts nonce, signature and publicKey from args for authenticated staking operations.
// audit-fix NEW-18: staking operations now require Dilithium3 signature verification.
// Auth fields are at the end: [...params, nonce, signature, publicKey]
func extractStakingAuth(args []any, minArgs int) ([]any, string, string, string, *Error) {
	if len(args) < minArgs+3 {
		return nil, "", "", "", NewErrorWithData(ErrCodeInvalidParams, "missing authentication",
			"state-mutating staking operations require nonce, signature, and publicKey parameters")
	}

	nonce, ok := args[len(args)-3].(string)
	if !ok {
		return nil, "", "", "", NewErrorWithData(ErrCodeInvalidParams, "invalid nonce", "nonce must be a string")
	}

	sig, ok := args[len(args)-2].(string)
	if !ok {
		return nil, "", "", "", NewErrorWithData(ErrCodeInvalidParams, "invalid signature", "signature must be a hex string")
	}

	pubKey, ok := args[len(args)-1].(string)
	if !ok {
		return nil, "", "", "", NewErrorWithData(ErrCodeInvalidParams, "invalid publicKey", "publicKey must be a hex string")
	}

	return args[:len(args)-3], nonce, sig, pubKey, nil
}

// RegisterHandlers registers all API handlers with the server
func (api *API) RegisterHandlers(server *Server) {
	// Chain methods — standard JSON-RPC namespace (eth_*)
	server.RegisterHandler("eth_chainId", api.ChainID)
	server.RegisterHandler("eth_protocolVersion", api.ProtocolVersion)
	server.RegisterHandler("eth_blockNumber", api.BlockNumber)
	server.RegisterHandler("eth_gasPrice", api.GasPrice)
	server.RegisterHandler("eth_syncing", api.Syncing)

	// Account methods
	server.RegisterHandler("eth_getBalance", api.GetBalance)
	server.RegisterHandler("eth_getTransactionCount", api.GetTransactionCount)
	server.RegisterHandler("eth_getCode", api.GetCode)
	server.RegisterHandler("eth_getStorageAt", api.GetStorageAt)

	// Block methods
	server.RegisterHandler("eth_getBlockByHash", api.GetBlockByHash)
	server.RegisterHandler("eth_getBlockByNumber", api.GetBlockByNumber)
	server.RegisterHandler("eth_getBlockTransactionCountByHash", api.GetBlockTransactionCountByHash)
	server.RegisterHandler("eth_getBlockTransactionCountByNumber", api.GetBlockTransactionCountByNumber)
	server.RegisterHandler("eth_getTransactionByBlockHashAndIndex", api.GetTransactionByBlockHashAndIndex)
	server.RegisterHandler("eth_getTransactionByBlockNumberAndIndex", api.GetTransactionByBlockNumberAndIndex)

	// Transaction methods
	// R7-H1 FIX: eth_sendTransaction signs with locally-unlocked keys. Like geth,
	// it is gated as admin (IPC-style) and not exposed on HTTP/WS without elevated
	// credentials; raw submission (eth_sendRawTransaction) remains public.
	server.RegisterAdminMethod("eth_sendTransaction")
	server.RegisterHandler("eth_sendTransaction", api.SendTransaction)
	server.RegisterHandler("eth_sendRawTransaction", api.SendRawTransaction)
	server.RegisterHandler("eth_getTransactionByHash", api.GetTransactionByHash)
	server.RegisterHandler("eth_getTransactionReceipt", api.GetTransactionReceipt)
	server.RegisterHandler("eth_estimateGas", api.EstimateGas)
	server.RegisterHandler("eth_call", api.Call)

	// Quantaureum-unique methods (qau_ namespace)

	// Filter methods
	server.RegisterHandler("eth_newFilter", api.NewFilter)
	server.RegisterHandler("eth_newBlockFilter", api.NewBlockFilter)
	server.RegisterHandler("eth_newPendingTransactionFilter", api.NewPendingTransactionFilter)
	server.RegisterHandler("eth_uninstallFilter", api.UninstallFilter)
	server.RegisterHandler("eth_getFilterChanges", api.GetFilterChanges)
	server.RegisterHandler("eth_getFilterLogs", api.GetFilterLogs)
	server.RegisterHandler("eth_getLogs", api.GetLogs)

	// Net methods (standard)
	server.RegisterHandler("net_version", api.NetVersion)
	server.RegisterHandler("net_peerCount", api.NetPeerCount)
	server.RegisterHandler("net_listening", api.NetListening)

	// TxPool methods (standard)
	server.RegisterHandler("txpool_status", api.TxPoolStatus)
	// RP-04 FIX: txpool_content leaks all pending transaction details (from,
	// to, value, gas, data). Register it as an admin method (matching geth,
	// where txpool_content is a debug/admin namespace) so it requires elevated
	// credentials instead of being callable by any authenticated caller.
	server.RegisterAdminMethod("txpool_content")
	server.RegisterHandler("txpool_content", api.TxPoolContent)
	// AUDIT (2026) API-FIX: txpool_inspect and eth_pendingTransactions
	// also leak full pending transaction details (from, to, value, gas, data) —
	// same as txpool_content. Previously they were removed from the public
	// allowlist (auth.go) but NOT registered as admin methods, so any API key
	// holder could still call them. Now register as admin methods so they
	// require elevated credentials, consistent with txpool_content.
	server.RegisterAdminMethod("txpool_inspect")
	server.RegisterHandler("txpool_inspect", api.TxPoolInspect)
	server.RegisterAdminMethod("eth_pendingTransactions")
	server.RegisterHandler("eth_pendingTransactions", api.PendingTransactions)

	// Web3 methods
	server.RegisterHandler("web3_clientVersion", api.Web3ClientVersion)
	server.RegisterHandler("web3_sha3", api.Web3Sha3)

	// Admin methods - H-21 FIX: register as admin methods requiring special permission
	server.RegisterAdminMethod("admin_peers")
	server.RegisterAdminMethod("admin_nodeInfo")
	server.RegisterHandler("admin_peers", api.AdminPeers)
	server.RegisterHandler("admin_nodeInfo", api.AdminNodeInfo)

	// C-4 FIX: Personal account methods require admin authentication.
	server.RegisterAdminMethod("personal_newAccount")
	server.RegisterAdminMethod("personal_unlockAccount")
	server.RegisterAdminMethod("personal_importRawKey")
	server.RegisterAdminMethod("personal_sendTransaction")
	server.RegisterAdminMethod("personal_sign")
	server.RegisterAdminMethod("personal_lockAccount")
	// RP-05 FIX: personal_listAccounts leaks account addresses stored on the
	// node, so it must be admin-gated (reverts the L18-039 change that left it
	// as a plain authenticated method). It is NOT in PublicMethods. Note: auth.go
	// has no static AdminMethods list — admin gating is done via these
	// RegisterAdminMethod calls, so the registration belongs here.
	server.RegisterAdminMethod("personal_listAccounts")

	// QPOS Consensus methods
	server.RegisterHandler("qau_qposStatus", api.QPOSStatus)

	// R131 Validator key sovereignty
	server.RegisterHandler("qau_validatorKeyStatus", api.ValidatorKeyStatus)

	// Staking methods
	server.RegisterHandler("qau_stake", api.Stake)
	server.RegisterHandler("qau_unstake", api.Unstake)
	server.RegisterHandler("qau_getStake", api.GetStake)
	server.RegisterHandler("qau_getStakingPools", api.GetStakingPools)
	server.RegisterHandler("qau_getStakingStats", api.GetStakingStats)
	server.RegisterHandler("qau_getUserStakes", api.GetUserStakes)
	server.RegisterHandler("qau_claimRewards", api.ClaimRewards)
	server.RegisterHandler("qau_compoundRewards", api.CompoundRewards)
	server.RegisterHandler("qau_getStakingContracts", api.GetStakingContracts)
	server.RegisterHandler("qau_getPendingRewards", api.GetPendingRewards)
	server.RegisterHandler("qau_getUnstakeStatus", api.GetUnstakeStatus)
	server.RegisterHandler("qau_getContractBalance", api.GetContractBalance)
	server.RegisterHandler("qau_getContractList", api.GetContractList)
	server.RegisterHandler("qau_getRewardPoolStatus", api.GetRewardPoolStatus)
	server.RegisterHandler("qau_getTotalRewardsClaimed", api.GetTotalRewardsClaimed)
	server.RegisterHandler("qau_updateCommission", api.UpdateCommission)

	// Quantum transaction methods
	// RP-04 FIX: qau_signQuantumTransaction signs with the node's private key
	// (like eth_sendTransaction), so it must be admin-gated, not public. It is
	// intentionally absent from PublicMethods in auth.go.
	server.RegisterAdminMethod("qau_signQuantumTransaction")
	server.RegisterHandler("qau_signQuantumTransaction", api.SignQuantumTransaction)
	server.RegisterHandler("qau_verifyQuantumTransaction", api.VerifyQuantumTransaction)

	// Privacy transaction methods
	// P2-PRIVACY-ADMIN FIX (R29, 2026-07-26): qau_sendPrivacyTransaction
	// takes (from, to, amount) without a user-provided signature, so the
	// node signs on behalf of the user (like eth_sendTransaction) — this is
	// an admin-only operation. RegisterAdminMethod gates it behind admin
	// auth, and the method is intentionally absent from PublicMethods in
	// auth.go so the admin gate cannot be bypassed by unauthenticated
	// callers.
	server.RegisterAdminMethod("qau_sendPrivacyTransaction")
	server.RegisterHandler("qau_sendPrivacyTransaction", api.SendPrivacyTransaction)
	server.RegisterHandler("qau_scanPrivacy", api.ScanPrivacy)
	server.RegisterHandler("qau_getPrivacyBalance", api.GetPrivacyBalance)
	server.RegisterHandler("qau_generateStealthAddress", api.GenerateStealthAddress)

	// EIP-4337 Account Abstraction methods
	// RPC-P1-02 FIX (R31, 2026-07-27): Register BOTH eth_* and qau_* aliases.
	// ERC-4337 specifies these as standard eth_* JSON-RPC methods (see
	// https://eips.ethereum.org/EIPS/eip-4337#rpc-methods-eth-namespace).
	// Standard wallets/SDKs (MetaMask Snap for Account Abstraction,
	// @account-abstraction/sdk, Stackup bundler, etc.) call eth_*
	// exclusively and cannot reach a node that only exposes qau_*.
	// The qau_* aliases are retained for backward compatibility with
	// existing Quantaureum integrations and are scheduled for deprecation
	// once the wallet whitelist is fully migrated to eth_*.
	server.RegisterHandler("eth_sendUserOperation", api.SendUserOperation)
	server.RegisterHandler("eth_estimateUserOperationGas", api.EstimateUserOperationGas)
	server.RegisterHandler("eth_getUserOperationByHash", api.GetUserOperationByHash)
	server.RegisterHandler("eth_getUserOperationReceipt", api.GetUserOperationReceipt)
	server.RegisterHandler("eth_supportedEntryPoints", api.SupportedEntryPoints)
	server.RegisterHandler("qau_sendUserOperation", api.SendUserOperation)
	server.RegisterHandler("qau_estimateUserOperationGas", api.EstimateUserOperationGas)
	server.RegisterHandler("qau_getUserOperationByHash", api.GetUserOperationByHash)
	server.RegisterHandler("qau_getUserOperationReceipt", api.GetUserOperationReceipt)
	server.RegisterHandler("qau_supportedEntryPoints", api.SupportedEntryPoints)

	// Snapshot methods (Geth-standard evm_* namespace)
	// R7-C2 FIX: Snapshot create/restore are destructive state operations. They
	// roll the chain DB back to an arbitrary height (restore) and must never be
	// reachable by non-admin callers. Admin-gate both.
	server.RegisterAdminMethod("evm_snapshot")
	server.RegisterAdminMethod("evm_revert")
	server.RegisterHandler("evm_snapshot", api.CreateSnapshot)
	server.RegisterHandler("evm_revert", api.RestoreSnapshot)

	// R45-FORKRECOVERY-API (2026-08-12): manual chain-fork recovery.
	// Admin-gated to prevent unauthorized chain manipulation. See
	// node.ForkRecoveryBackend for the implementation.
	server.RegisterAdminMethod("debug_rollbackChainToHeight")
	server.RegisterHandler("debug_rollbackChainToHeight", api.RollbackChainToFork)
}

// ChainID returns the chain ID
// L-NEW-1 FIX: Default to Quantaureum MainnetChainID instead of Ethereum's 0x1
func (api *API) ChainID(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.chainInfo == nil {
		return formatHexUint64(1668), nil // Default to Quantaureum MainnetChainID
	}
	return formatHexUint64(api.chainInfo.ChainID()), nil
}

// NetworkID returns the network ID
func (api *API) NetworkID(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.chainInfo == nil {
		return "1", nil // Default network ID
	}
	return formatUint64(api.chainInfo.NetworkID()), nil
}

// ProtocolVersion returns the protocol version
func (api *API) ProtocolVersion(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.chainInfo == nil {
		return "1.0.0", nil
	}
	return api.chainInfo.ProtocolVersion(), nil
}

// BlockNumber returns the latest block number
func (api *API) BlockNumber(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.blockReader == nil {
		return "0x0", nil
	}
	return formatHexUint64(api.blockReader.GetLatestHeight()), nil
}

// GetBalance returns the balance of an account
func (api *API) GetBalance(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	// audit-fix: support blockTag in second argument
	var blockTag string
	if len(args) > 1 {
		blockTag = args[1]
	} else {
		blockTag = "latest"
	}

	if api.stateReader == nil {
		return "0x0", nil
	}

	// Only "latest" is truly supported currently, but we allow current height
	if blockTag != "latest" && blockTag != "" {
		height, err := parseBlockNumber(blockTag, api.blockReader)
		if err == nil && api.blockReader != nil {
			if height != api.blockReader.GetLatestHeight() {
				// Historical state not yet implemented in stateReader
				return nil, NewError(ErrCodeInvalidParams, "historical state not supported")
			}
		}
	}
	balance := api.stateReader.GetBalance(addr)
	return formatHexBigInt(balance), nil
}

// GetTransactionCount returns the nonce of an account
// Supports optional second parameter: "pending" (default) returns on-chain + pending nonce,
// "latest" returns only the on-chain nonce.
func (api *API) GetTransactionCount(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	// Default to "pending" for compatibility with Ethereum's behavior
	blockTag := "pending"
	if len(args) > 1 && args[1] != "" {
		blockTag = args[1]
	}

	if blockTag == "pending" && api.txPool != nil {
		nonce := api.txPool.GetPendingNonce(addr)
		return formatHexUint64(nonce), nil
	}

	if api.stateReader == nil {
		return "0x0", nil
	}

	nonce := api.stateReader.GetNonce(addr)
	return formatHexUint64(nonce), nil
}

// GetCode returns the code at an address
func (api *API) GetCode(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	if api.stateReader == nil {
		return "0x", nil
	}

	code := api.stateReader.GetCode(addr)
	return formatHexBytes(code), nil
}

// GetStorageAt returns the storage value at a position
func (api *API) GetStorageAt(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	key, err := parseHash(args[1])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid storage key", err.Error())
	}

	if api.stateReader == nil {
		return formatHexHash(types.Hash{}), nil
	}

	value := api.stateReader.GetState(addr, key)
	return formatHexHash(value), nil
}

// GetBlockByHash returns a block by its hash
func (api *API) GetBlockByHash(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	hashStr, ok := args[0].(string)
	if !ok {
		return nil, ErrInvalidParams
	}

	fullTx := false
	if len(args) >= 2 {
		if ft, ok := args[1].(bool); ok {
			fullTx = ft
		}
	}

	hash, err := parseHash(hashStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash", err.Error())
	}

	if api.blockReader == nil {
		return nil, NewError(ErrCodeNotFound, "block not found")
	}

	block, err := api.blockReader.GetBlockByHash(hash)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, "block not found")
	}

	// If fullTx=false, replace transaction objects with hash strings
	if !fullTx {
		if blockResp, ok := block.(*BlockResponse); ok {
			blockResp.Transactions = txHashesOnly(blockResp.Transactions)
		}
	}

	// M-4: response body length is capped, preventing oversized blocks from causing DoS
	data, err := json.Marshal(block)
	if err != nil {
		//  err.Error() in Data is stripped by sanitizeError in production
		return nil, NewErrorWithData(ErrCodeInternal, "failed to marshal block", err.Error())
	}
	if len(data) > MaxResponseBodySize {
		return nil, NewError(ErrCodeInternal, "block response too large")
	}
	return block, nil
}

// GetBlockByNumber returns a block by its number
func (api *API) GetBlockByNumber(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	heightStr, ok := args[0].(string)
	if !ok {
		return nil, ErrInvalidParams
	}

	// audit-fix R7-L3: resolve "safe" and "finalized" block tags using actual
	// QPOS finality data instead of mapping them to "latest".
	// "finalized" — highest block in the finalized epoch (irreversible).
	// "safe"      — highest block in the justified epoch (one step before finalized).
	// Falls back to "latest" when QPOS status is unavailable.
	switch heightStr {
	case "finalized":
		if api.chainInfo != nil {
			status := api.chainInfo.GetQPOSStatus()
			if fe, ok := status["finalizedEpoch"].(uint64); ok && fe > 0 {
				// Conservative: use last slot of finalized epoch (slotsPerEpoch slots/epoch)
				heightStr = formatHexUint64(fe*slotsPerEpoch + (slotsPerEpoch - 1))
			} else {
				heightStr = "latest"
			}
		} else {
			heightStr = "latest"
		}
	case "safe":
		if api.chainInfo != nil {
			status := api.chainInfo.GetQPOSStatus()
			if je, ok := status["justifiedEpoch"].(uint64); ok && je > 0 {
				heightStr = formatHexUint64(je*slotsPerEpoch + (slotsPerEpoch - 1))
			} else {
				heightStr = "latest"
			}
		} else {
			heightStr = "latest"
		}
	}

	height, err := parseBlockNumber(heightStr, api.blockReader)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid block number", err.Error())
	}

	fullTx := false
	if len(args) >= 2 {
		if ft, ok := args[1].(bool); ok {
			fullTx = ft
		}
	}

	if api.blockReader == nil {
		return nil, NewError(ErrCodeNotFound, "block not found")
	}

	block, err := api.blockReader.GetBlockByHeight(height)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, "block not found")
	}

	// If fullTx=false, replace transaction objects with hash strings
	if !fullTx {
		if blockResp, ok := block.(*BlockResponse); ok {
			blockResp.Transactions = txHashesOnly(blockResp.Transactions)
		}
	}

	// M-4: response body length is capped, preventing oversized blocks from causing DoS
	data, err := json.Marshal(block)
	if err != nil {
		//  err.Error() in Data is stripped by sanitizeError in production
		return nil, NewErrorWithData(ErrCodeInternal, "failed to marshal block", err.Error())
	}
	if len(data) > MaxResponseBodySize {
		return nil, NewError(ErrCodeInternal, "block response too large")
	}
	return block, nil
}

// SendRawTransaction sends a raw transaction
func (api *API) SendRawTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	txData, err := parseHexBytes(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid transaction data", err.Error())
	}

	if len(txData) == 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "empty transaction data", "")
	}

	if err := api.requireTxPool(); err != nil {
		return nil, err
	}

	// Only accept protobuf format with Dilithium3 quantum signatures
	hash, err := api.txPool.AddTransaction(txData)
	if err != nil {
		return nil, NewError(ErrCodeInvalidTx, "transaction validation failed") // FIX: generic message, err details logged internally
	}

	return formatHexHash(hash), nil
}

func (api *API) SendUserOperation(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []map[string]any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	uoParams := args[0]
	uo, err := parseUserOperation(uoParams)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user operation", err.Error())
	}

	if err := api.requireTxPool(); err != nil {
		return nil, err
	}

	if err := api.txPool.AddUserOperation(uo); err != nil {
		return nil, NewError(ErrCodeInvalidTx, "transaction validation failed") // FIX: generic message, err details logged internally
	}

	uoHash := uo.Hash(qvm.EntryPointAddress, api.chainInfo.ChainID())
	return formatHexHash(uoHash), nil
}

func (api *API) EstimateUserOperationGas(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []map[string]any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	uoParams := args[0]
	uo, err := parseUserOperation(uoParams)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user operation", err.Error())
	}

	preVerificationGas := estimatePreVerificationGas(uo)
	verificationGasLimit := estimateVerificationGas(uo)
	callGasLimit := estimateCallGas(uo)

	return map[string]any{
		"preVerificationGas": fmt.Sprintf("0x%x", preVerificationGas),
		"verificationGas":    fmt.Sprintf("0x%x", verificationGasLimit),
		"callGasLimit":       fmt.Sprintf("0x%x", callGasLimit),
	}, nil
}

func (api *API) GetUserOperationByHash(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	hash, err := parseHash(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash", err.Error())
	}

	if err := api.requireTxPool(); err != nil {
		return nil, err
	}

	uo := api.txPool.GetUserOperation(hash)
	if uo == nil {
		return nil, nil
	}

	return formatUserOperation(uo), nil
}

func (api *API) GetUserOperationReceipt(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	hash, err := parseHash(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash", err.Error())
	}

	receipt := api.getUserOpReceiptFromChain(hash)
	if receipt == nil {
		return nil, nil
	}

	return receipt, nil
}

func (api *API) SupportedEntryPoints(ctx context.Context, params json.RawMessage) (any, *Error) {
	return []string{qvm.EntryPointAddressHex}, nil
}

func parseUserOperation(params map[string]any) (*encoding.UserOperation, error) {
	uo := &encoding.UserOperation{}

	if senderStr, ok := params["sender"].(string); ok {
		sender, err := parseAddress(senderStr)
		if err != nil {
			return nil, fmt.Errorf("invalid sender: %w", err)
		}
		uo.Sender = sender
	}

	if nonceStr, ok := params["nonce"].(string); ok {
		nonce, err := parseUint64(nonceStr)
		if err != nil {
			return nil, fmt.Errorf("invalid nonce: %w", err)
		}
		uo.Nonce = nonce
	}

	if initCodeStr, ok := params["initCode"].(string); ok {
		initCode, err := parseHexBytes(initCodeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid initCode: %w", err)
		}
		uo.InitCode = initCode
	}

	if callDataStr, ok := params["callData"].(string); ok {
		callData, err := parseHexBytes(callDataStr)
		if err != nil {
			return nil, fmt.Errorf("invalid callData: %w", err)
		}
		uo.CallData = callData
	}

	if callGasStr, ok := params["callGasLimit"].(string); ok {
		callGas, err := parseUint64(callGasStr)
		if err != nil {
			return nil, fmt.Errorf("invalid callGasLimit: %w", err)
		}
		uo.CallGasLimit = callGas
	}

	if verifGasStr, ok := params["verificationGasLimit"].(string); ok {
		verifGas, err := parseUint64(verifGasStr)
		if err != nil {
			return nil, fmt.Errorf("invalid verificationGasLimit: %w", err)
		}
		uo.VerificationGasLimit = verifGas
	}

	if preVerifGasStr, ok := params["preVerificationGas"].(string); ok {
		preVerifGas, err := parseUint64(preVerifGasStr)
		if err != nil {
			return nil, fmt.Errorf("invalid preVerificationGas: %w", err)
		}
		uo.PreVerificationGas = preVerifGas
	}

	if maxFeeStr, ok := params["maxFeePerGas"].(string); ok {
		maxFee, err := parseBigInt(maxFeeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid maxFeePerGas: %w", err)
		}
		uo.MaxFeePerGas = maxFee
	}

	if maxPriorityFeeStr, ok := params["maxPriorityFeePerGas"].(string); ok {
		maxPriorityFee, err := parseBigInt(maxPriorityFeeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid maxPriorityFeePerGas: %w", err)
		}
		uo.MaxPriorityFeePerGas = maxPriorityFee
	}

	if paymasterStr, ok := params["paymaster"].(string); ok && paymasterStr != "" && paymasterStr != "0x" {
		paymaster, err := parseAddress(paymasterStr)
		if err != nil {
			return nil, fmt.Errorf("invalid paymaster: %w", err)
		}
		uo.Paymaster = &paymaster
	}

	if paymasterDataStr, ok := params["paymasterData"].(string); ok {
		paymasterData, err := parseHexBytes(paymasterDataStr)
		if err != nil {
			return nil, fmt.Errorf("invalid paymasterData: %w", err)
		}
		uo.PaymasterData = paymasterData
	}

	if sigStr, ok := params["signature"].(string); ok {
		sig, err := parseHexBytes(sigStr)
		if err != nil {
			return nil, fmt.Errorf("invalid signature: %w", err)
		}
		uo.Signature = sig
	}

	return uo, nil
}

func formatUserOperation(uo *encoding.UserOperation) map[string]any {
	result := map[string]any{
		"sender":               uo.Sender.ToHexAddress(),
		"nonce":                fmt.Sprintf("0x%x", uo.Nonce),
		"initCode":             formatHexBytes(uo.InitCode),
		"callData":             formatHexBytes(uo.CallData),
		"callGasLimit":         fmt.Sprintf("0x%x", uo.CallGasLimit),
		"verificationGasLimit": fmt.Sprintf("0x%x", uo.VerificationGasLimit),
		"preVerificationGas":   fmt.Sprintf("0x%x", uo.PreVerificationGas),
		"maxFeePerGas":         formatHexBig(uo.MaxFeePerGas),
		"maxPriorityFeePerGas": formatHexBig(uo.MaxPriorityFeePerGas),
		"signature":            formatHexBytes(uo.Signature),
	}
	if uo.Paymaster != nil {
		result["paymaster"] = uo.Paymaster.ToHexAddress()
		result["paymasterData"] = formatHexBytes(uo.PaymasterData)
	}
	return result
}

func estimatePreVerificationGas(uo *encoding.UserOperation) uint64 {
	base := uint64(21000)
	dataGas := uint64(len(uo.CallData)) * 16
	if len(uo.InitCode) > 0 {
		dataGas += uint64(len(uo.InitCode)) * 16
	}
	if uo.Paymaster != nil {
		dataGas += uint64(len(uo.PaymasterData)) * 16
	}
	return base + dataGas
}

func estimateVerificationGas(uo *encoding.UserOperation) uint64 {
	base := uint64(50000)
	if len(uo.InitCode) > 0 {
		base += uint64(len(uo.InitCode)) * 200
	}
	return base
}

func estimateCallGas(uo *encoding.UserOperation) uint64 {
	base := uint64(21000)
	dataGas := uint64(len(uo.CallData)) * 16
	return base + dataGas
}

func (api *API) getUserOpReceiptFromChain(hash types.Hash) map[string]any {
	return nil
}

func parseUint64(hexStr string) (uint64, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if hexStr == "" {
		return 0, nil
	}
	val, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return 0, err
	}
	return val, nil
}

func parseBigInt(hexStr string) (*big.Int, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if hexStr == "" {
		return big.NewInt(0), nil
	}
	val := new(big.Int)
	val.SetString(hexStr, 16)
	return val, nil
}

func formatHexBig(val *big.Int) string {
	if val == nil {
		return "0x0"
	}
	return fmt.Sprintf("0x%x", val)
}

// GetTransactionByHash returns a transaction by its hash
func (api *API) GetTransactionByHash(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	hash, err := parseHash(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash", err.Error())
	}

	if api.blockReader == nil {
		return nil, nil // Return null for non-existent transaction (Ethereum standard)
	}

	tx, err := api.blockReader.GetTransaction(hash)
	if err != nil {
		return nil, nil // Return null for non-existent transaction (Ethereum standard)
	}

	return tx, nil
}

// GetTransactionReceipt returns a transaction receipt
func (api *API) GetTransactionReceipt(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	hashStr, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash", "expected string")
	}

	hash, err := parseHash(hashStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hash", err.Error())
	}

	if api.blockReader == nil {
		return nil, nil // Return null instead of error for pending transactions
	}

	// P2P-R11-M06 (2026-07-20) FIX: previously the adapter conflated "not
	// found" and "storage error" into the same (nil, nil) return. Now the
	// adapter returns (nil, nil) only for legitimate not-found (tx pending
	// or block reorged) and (nil, err) for actual I/O/decode failures.
	//
	// For Ethereum JSON-RPC spec compliance, eth_getTransactionReceipt
	// returns null when a tx is pending — so we still return (nil, nil) to
	// clients in that case. But we now log the storage error so operators
	// can diagnose data-corruption or I/O issues that would otherwise be
	// silently swallowed.
	receipt, err := api.blockReader.GetTransactionReceipt(hash)
	if err != nil {
		// Log the actual error; the comment "Return null instead of error
		// for pending transactions" was masking real storage failures.
		log.Printf("[WARN] rpc: GetTransactionReceipt storage error for hash %x: %v",
			hash, err)
		// Return null per eth_* spec (clients expect null for pending txs,
		// not internal-error objects). Operators diagnose via the log line.
		return nil, nil
	}

	return receipt, nil
}

// Helper functions

func parseAddress(s string) (types.Address, error) {
	// Support QAU-prefixed addresses (Base32)
	if strings.HasPrefix(s, "QAU") {
		return types.ParseAddress(s)
	}
	// Support 0x-prefixed addresses (Hex)
	s = stripHexPrefix(s)
	if len(s) != 40 {
		return types.Address{}, ErrInvalidParams
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return types.Address{}, err
	}
	return types.BytesToAddress(bytes), nil
}

func parseHash(s string) (types.Hash, error) {
	s = stripHexPrefix(s)
	// Pad short hashes with leading zeros (for storage keys like "0x0")
	if len(s) < 64 {
		s = fmt.Sprintf("%064s", s)
		// Replace spaces with zeros
		s = strings.ReplaceAll(s, " ", "0")
	}
	if len(s) != 64 {
		return types.Hash{}, ErrInvalidParams
	}
	bytes, err := hex.DecodeString(s)
	if err != nil {
		return types.Hash{}, err
	}
	return types.BytesToHash(bytes), nil
}

// maxParseHexBytesLen is the maximum number of hex characters accepted by
// parseHexBytes. 2 MiB of hex chars decodes to 1 MiB of bytes, aligning with
// server.MaxRequestBodySize. This is a defense-in-depth measure: even though
// server.go already caps the entire request body at 1 MiB, an explicit
// per-field limit prevents a single hex field from consuming the entire
// budget and gives callers a clearer error than a generic "request too
// large".
//
// R32-P2-02 FIX (2026-07-28): Previously parseHexBytes had no length limit,
// relying solely on the global MaxParamsLength (64 KiB) for protection. This
// fix closes the defense-in-depth gap for the 9 call sites that use
// parseHexBytes (eth_sendRawTransaction, eth_estimateGas, AA UserOp fields,
// personal_sign, personal_buildTransaction, etc.).
const maxParseHexBytesLen = 2 << 20 // 2 MiB hex chars = 1 MiB decoded

func parseHexBytes(s string) ([]byte, error) {
	s = stripHexPrefix(s)
	// Pad odd-length hex strings with leading zero (e.g. "abc" → "0abc")
	// Without this, hex.DecodeString returns an error for odd-length strings,
	// which causes buildTransaction to silently drop the data field.
	if len(s)%2 != 0 {
		s = "0" + s
	}
	// R32-P2-02: Reject oversized hex inputs before decoding. Without this,
	// an attacker could submit a multi-MB hex string that consumes memory
	// and CPU during hex.DecodeString even though the global params limit
	// would eventually reject the overall request.
	if len(s) > maxParseHexBytesLen {
		return nil, fmt.Errorf("hex input too large: %d chars exceeds limit %d", len(s), maxParseHexBytesLen)
	}
	return hex.DecodeString(s)
}

func parseBlockNumber(s string, reader BlockReader) (uint64, error) {
	switch s {
	case "latest", "pending":
		if reader != nil {
			return reader.GetLatestHeight(), nil
		}
		return 0, nil
	case "earliest":
		return 0, nil
	default:
		s = stripHexPrefix(s)
		// Pad odd-length hex strings with leading zero
		if len(s)%2 != 0 {
			s = "0" + s
		}
		bytes, err := hex.DecodeString(s)
		if err != nil {
			return 0, err
		}
		// L10-008: Prevent uint64 overflow from excessively long hex strings.
		// Without this check, a hex string longer than 8 bytes would silently
		// wrap around in the shift-or loop below, potentially bypassing the
		// maxReasonableHeight guard and yielding an unintended small height.
		if len(bytes) > 8 {
			return 0, fmt.Errorf("block number hex too large: %d bytes", len(bytes))
		}
		var height uint64
		for _, b := range bytes {
			height = height<<8 | uint64(b)
		}
		const maxReasonableHeight = 1000000000 // 1 billion
		if height > maxReasonableHeight {
			return 0, fmt.Errorf("block number %d exceeds maximum reasonable height", height)
		}
		return height, nil
	}
}

func stripHexPrefix(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

func formatHexUint64(n uint64) string {
	if n == 0 {
		return "0x0"
	}
	return fmt.Sprintf("0x%x", n)
}

// txHashesOnly converts transaction objects to hash-only strings for fullTx=false responses
func txHashesOnly(txs []any) []any {
	hashes := make([]any, len(txs))
	for i, tx := range txs {
		switch v := tx.(type) {
		case *TransactionResponse:
			hashes[i] = v.Hash
		case map[string]any:
			if h, ok := v["hash"].(string); ok {
				hashes[i] = h
			} else {
				hashes[i] = tx
			}
		case string:
			hashes[i] = v
		default:
			hashes[i] = tx
		}
	}
	return hashes
}

// audit-fix R5-Info-1: return a decimal string instead of hex-encoded raw bytes.
func formatUint64(n uint64) string {
	return fmt.Sprintf("%d", n)
}

func formatHexBigInt(n *big.Int) string {
	if n == nil {
		return "0x0"
	}
	return "0x" + n.Text(16)
}

func formatHexBytes(b []byte) string {
	if len(b) == 0 {
		return "0x"
	}
	return "0x" + hex.EncodeToString(b)
}

func formatHexHash(h types.Hash) string {
	return "0x" + hex.EncodeToString(h[:])
}

// GasPrice returns the current gas price.
// FIX: Previously returned a hardcoded "0x3b9aca00" (1 Gwei) regardless
// of network congestion. Now attempts to compute a dynamic price from the
// latest block's BaseFeePerGas. If block data is unavailable (nil blockReader,
// nil block, or no base fee field), falls back to the configured default
// (api.defaultGasPrice, initialized to 1 Gwei but overridable via
// SetDefaultGasPrice for production config-based configuration).
func (api *API) GasPrice(ctx context.Context, params json.RawMessage) (any, *Error) {
	// Try to get dynamic gas price from the latest block's base fee
	if api.blockReader != nil {
		latestHeight := api.blockReader.GetLatestHeight()
		if latestHeight > 0 {
			block, err := api.blockReader.GetBlockByHeight(latestHeight)
			if err == nil && block != nil {
				if blockResp, ok := block.(*BlockResponse); ok && blockResp.BaseFeePerGas != "" {
					baseFee := new(big.Int)
					// Parse hex string (with or without 0x prefix)
					hexStr := blockResp.BaseFeePerGas
					if len(hexStr) >= 2 && hexStr[:2] == "0x" {
						hexStr = hexStr[2:]
					}
					if _, ok := baseFee.SetString(hexStr, 16); ok && baseFee.Sign() > 0 {
						return formatHexBigInt(baseFee), nil
					}
				}
			}
		}
	}
	// Fall back to configured default gas price
	if api.defaultGasPrice != nil && api.defaultGasPrice.Sign() > 0 {
		return formatHexBigInt(api.defaultGasPrice), nil
	}
	// Ultimate fallback: 1 Gwei (should not normally be reached)
	//  Use hex of DefaultGasPriceWei constant.
	return fmt.Sprintf("0x%x", DefaultGasPriceWei), nil
}

// Syncing returns the sync status
// audit-fix R6-L1: use chainInfo.HighestBlock() for highestBlock so clients
// can observe sync progress (previously both values used GetLatestHeight()).
func (api *API) Syncing(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.chainInfo == nil {
		return false, nil
	}
	if api.chainInfo.IsSyncing() {
		// audit-fix R7-M1: guard against nil blockReader to prevent panic
		var currentBlock uint64
		if api.blockReader != nil {
			currentBlock = api.blockReader.GetLatestHeight()
		}
		return map[string]any{
			"startingBlock": "0x0",
			"currentBlock":  formatHexUint64(currentBlock),
			"highestBlock":  formatHexUint64(api.chainInfo.HighestBlock()),
		}, nil
	}
	return false, nil
}

// EstimateGas estimates the gas needed for a transaction
// SECURITY FIX: Implement actual gas estimation instead of hardcoded value.
// The previous implementation always returned 21000 (0x5208), which is only
// correct for simple ETH transfers. This is a security issue because:
// 1. It could cause transactions to run out of gas if more complex
// 2. It misleads callers about actual gas consumption
// 3. It breaks EVM gas accounting integrity
//
// FIX: Documented the limitations of this heuristic-based
// estimation more thoroughly and added a 20% safety margin to reduce the
// risk of out-of-gas errors. The estimation now:
// - Uses 21000 base gas for simple transfers (correct)
// - Adds 68 gas per byte of data (approximate, EIP-2028 uses 16 for non-zero)
// - Adds 32000 gas for contract creation
// - Applies a 20% safety margin on top of the computed estimate
// - Caps at the block gas limit
// TODO: Implement actual EVM simulation (binary search over gas limits)
// similar to go-ethereum's EstimateGas for accurate estimation. The current
// heuristic may over- or under-estimate gas for complex contract calls,
// which can cause transactions to fail or waste gas fees.
func (api *API) EstimateGas(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []json.RawMessage
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	var txObj struct {
		From  string `json:"from"`
		To    any    `json:"to"`
		Value string `json:"value"`
		Data  string `json:"data"`
	}
	if err := json.Unmarshal(args[0], &txObj); err != nil {
		return nil, ErrInvalidParams
	}

	// FIX: Try actual QVM simulation if ContractCaller is available.
	// This provides accurate gas estimation by executing the transaction in a
	// read-only context and measuring actual gas consumed. Falls back to the
	// heuristic estimation below if simulation is unavailable or fails.
	if api.contractCaller != nil {
		if toStr, ok := txObj.To.(string); ok && toStr != "" && toStr != "0x" && toStr != "0x0" {
			to, addrErr := parseAddress(toStr)
			if addrErr == nil {
				// Parse call data
				var data []byte
				if txObj.Data != "" {
					if parsedData, dErr := parseHexBytes(txObj.Data); dErr == nil {
						data = parsedData
					}
				}
				// Parse value
				value := big.NewInt(0)
				if txObj.Value != "" {
					vStr := stripHexPrefix(txObj.Value)
					if _, ok := value.SetString(vStr, 16); !ok {
						value.SetString(vStr, 10)
					}
				}
				// Parse from address (optional)
				var from types.Address
				if txObj.From != "" {
					from, _ = parseAddress(txObj.From)
				}
				// Use a generous gas limit for the simulation
				const simulationGas uint64 = 50_000_000
				req := &ContractCallRequest{
					From:  from,
					To:    to,
					Value: value,
					Data:  data,
					Gas:   simulationGas,
				}
				result, callErr := api.contractCaller.Call(req)
				if callErr == nil && result != nil && result.Error == nil && result.GasUsed > 0 {
					simGas := result.GasUsed
					if simGas < 21000 {
						simGas = 21000
					}
					// Apply 20% safety margin on top of simulated gas
					simGas += simGas / 5
					// Cap at block gas limit
					if api.blockReader != nil && simGas > api.blockReader.GetGasLimit() {
						simGas = api.blockReader.GetGasLimit()
					}
					return formatHexUint64(simGas), nil
				}
			}
		}
	}

	// --- Heuristic fallback (when ContractCaller is not available) ---
	// TODO(): The heuristic below is an approximation, not an exact gas
	// estimate. When ContractCaller is not available, this provides a rough
	// estimate based on static analysis of the transaction payload. A proper
	// implementation should use binary search over gas limits (similar to
	// go-ethereum's EstimateGas) to find the minimum gas that allows the
	// transaction to succeed. The current heuristic may over- or under-estimate
	// gas for complex contract calls, which can cause transactions to fail or
	// waste gas fees. The QVM simulation path above addresses this when
	// ContractCaller is configured, but contract creation gas estimation
	// (when 'to' is empty) still requires the heuristic.

	// Base gas for a simple transfer
	gas := uint64(21000)

	// Add gas for data payload using QVM's actual gas model:
	// 16 gas per non-zero byte (GasTxDataNonZero), 4 gas per zero byte (GasTxDataZero).
	// FIX: Previously used a flat 68 gas/byte (pre-EIP-2028 Ethereum value),
	// which over-estimated gas for data-heavy transactions. Now matches qvm/gas.go
	// constants for more accurate heuristic estimates.
	if txObj.Data != "" {
		if dataBytes, dErr := parseHexBytes(txObj.Data); dErr == nil {
			for _, b := range dataBytes {
				if b == 0 {
					gas += 4 // GasTxDataZero (qvm/gas.go:71)
				} else {
					gas += 16 // GasTxDataNonZero (qvm/gas.go:72)
				}
			}
		}
	}

	// Add gas for contract creation (if 'to' is empty/null)
	if txObj.To == nil || txObj.To == "" || txObj.To == "0x" || txObj.To == "0x0" {
		gas += 32000 // contract creation overhead
	}

	// Apply a 20% safety margin to the computed gas estimate.
	// This reduces the likelihood of out-of-gas errors for contract calls
	// where the heuristic underestimates the actual gas needed. The margin
	// is capped so it does not push simple transfers far above 21000.
	if gas > 21000 {
		gas += gas / 5 // 20% safety margin
	}

	// R43-H-H3 FIX: Add nil check for blockReader to prevent panic when
	// EstimateGas is called before the block reader is initialized.
	if api.blockReader != nil && gas > api.blockReader.GetGasLimit() {
		gas = api.blockReader.GetGasLimit()
	}

	return formatHexUint64(gas), nil
}

// SendTransaction sends a transaction (requires unlocked account)
func (api *API) SendTransaction(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []map[string]any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	txParams := args[0]

	// Extract from address
	fromStr, ok := txParams["from"].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "missing from address", "from is required")
	}

	from, err := parseAddress(fromStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid from address", err.Error())
	}

	// Check if account manager is available
	if api.accountManager == nil {
		return nil, NewError(ErrCodeInternal, "account manager not available, use eth_sendRawTransaction instead")
	}

	// Check if account is unlocked
	if !api.accountManager.IsUnlocked(from) {
		return nil, NewError(ErrCodeUnauthorized, "account is locked, unlock it first or use eth_sendRawTransaction")
	}

	// Sign and send transaction
	signedTx, err := api.accountManager.SignTransaction(from, txParams)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	if err := api.requireTxPool(); err != nil {
		return nil, err
	}

	hash, err := api.txPool.AddTransaction(signedTx)
	if err != nil {
		return nil, NewError(ErrCodeInvalidTx, "transaction validation failed") // FIX: generic message, err details logged internally
	}

	return formatHexHash(hash), nil
}

// NetVersion returns the network ID
func (api *API) NetVersion(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.chainInfo == nil {
		return "1", nil
	}
	return fmt.Sprintf("%d", api.chainInfo.NetworkID()), nil
}

// NetPeerCount returns the number of connected peers
func (api *API) NetPeerCount(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.chainInfo == nil {
		return "0x0", nil
	}
	return formatHexUint64(uint64(api.chainInfo.PeerCount())), nil // #nosec G115 -- PeerCount is always non-negative
}

// NetListening returns whether the node is listening for connections
func (api *API) NetListening(ctx context.Context, params json.RawMessage) (any, *Error) {
	return true, nil
}

// TxPoolStatus returns the transaction pool status
func (api *API) TxPoolStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.txPool == nil {
		return map[string]string{
			"pending": "0x0",
			"queued":  "0x0",
		}, nil
	}
	return map[string]string{
		"pending": formatHexUint64(uint64(api.txPool.GetPendingCount())), // #nosec G115 -- count is always non-negative
		"queued":  formatHexUint64(uint64(api.txPool.GetQueuedCount())),  // #nosec G115 -- count is always non-negative
	}, nil
}

// TxPoolContent returns the transaction pool content
func (api *API) TxPoolContent(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.txPool == nil {
		return map[string]any{
			"pending": map[string]any{},
			"queued":  map[string]any{},
		}, nil
	}
	return map[string]any{
		"pending": api.txPool.GetPendingTransactions(),
		"queued":  map[string]any{},
	}, nil
}

// TxPoolInspect returns a human-readable summary of the transaction pool
// content, grouped by sender and nonce. RP-03 FIX: this standard txpool method
// was previously missing. It mirrors geth's txpool_inspect, returning a
// "from -> to: value + gas" summary per pending transaction instead of the full
// transaction objects exposed by txpool_content.
func (api *API) TxPoolInspect(ctx context.Context, params json.RawMessage) (any, *Error) {
	pendingSummary := map[string]map[string]string{}
	if api.txPool != nil {
		for _, tx := range api.txPool.GetPendingTransactions() {
			// R37-P3-36 FIX (2026-07-31): GetPendingTransactions returns
			// txpool.SafePendingTx structs, NOT map[string]any. The previous
			// type assertion silently skipped every transaction, causing
			// txpool_inspect to always return empty pending in production.
			var from, to, value, gas, gasPrice, nonce string
			switch v := tx.(type) {
			case txpool.SafePendingTx:
				from = v.From.String()
				if v.To != nil {
					to = v.To.String()
				}
				if v.Value != nil {
					value = v.Value.String()
				}
				gas = fmt.Sprintf("0x%x", v.GasLimit)
				if v.GasPrice != nil {
					gasPrice = v.GasPrice.String()
				}
				nonce = fmt.Sprintf("0x%x", v.Nonce)
			case *txpool.SafePendingTx:
				if v == nil {
					continue
				}
				from = v.From.String()
				if v.To != nil {
					to = v.To.String()
				}
				if v.Value != nil {
					value = v.Value.String()
				}
				gas = fmt.Sprintf("0x%x", v.GasLimit)
				if v.GasPrice != nil {
					gasPrice = v.GasPrice.String()
				}
				nonce = fmt.Sprintf("0x%x", v.Nonce)
			default:
				continue
			}
			if from == "" {
				from = "0x0"
			}
			if nonce == "" {
				nonce = "0x0"
			}
			if _, ok := pendingSummary[from]; !ok {
				pendingSummary[from] = map[string]string{}
			}
			pendingSummary[from][nonce] = fmt.Sprintf("%s -> %s: %s wei + %s gas × %s", from, to, value, gas, gasPrice)
		}
	}
	return map[string]any{
		"pending": pendingSummary,
		"queued":  map[string]any{},
	}, nil
}

// PendingTransactions returns all pending transactions
func (api *API) PendingTransactions(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.txPool == nil {
		return []any{}, nil
	}
	return api.txPool.GetPendingTransactions(), nil
}

// Web3ClientVersion returns the client version
func (api *API) Web3ClientVersion(ctx context.Context, params json.RawMessage) (any, *Error) {
	return "Quantaureum/v1.0.0/go", nil
}

// Web3Sha3 returns the Keccak-256 hash of the input
func (api *API) Web3Sha3(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	data, err := parseHexBytes(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid hex data", err.Error())
	}

	// Use SHA3-256 (Keccak)
	hash := sha3Hash(data)
	return formatHexBytes(hash), nil
}

// sha3Hash computes Keccak-256 hash (Ethereum-compatible SHA3)
func sha3Hash(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hasher.Sum(nil)
}

// AdminPeers returns information about connected peers
func (api *API) AdminPeers(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.chainInfo == nil {
		return []PeerInfo{}, nil
	}
	return api.chainInfo.GetPeers(), nil
}

// AdminNodeInfo returns information about the local node.
//
//	SECURITY NOTE: This endpoint exposes the node's listen address,
//
// advertised IP, and P2P ports. It is registered as an admin method
// (RegisterAdminMethod) requiring authentication. Operators should ensure:
//  1. The admin RPC endpoint is only accessible from localhost or a
//     trusted management network (never exposed to the public internet).
//  2. Admin credentials are rotated regularly.
//  3. In production, consider setting RPC listen address to 127.0.0.1 only.
func (api *API) AdminNodeInfo(ctx context.Context, params json.RawMessage) (any, *Error) {
	var networkID uint64
	var enodeURL string
	var listenAddr string
	var discoveryPort, listenerPort int

	if api.chainInfo != nil {
		networkID = api.chainInfo.NetworkID()
		enodeURL = api.chainInfo.GetEnodeURL()
	}

	// /FIX: Extract IP, port, and listen address from enodeURL
	// instead of leaving them as zero values. Falls back to "127.0.0.1" only
	// when enodeURL is unavailable or unparseable.
	// FIX: Use GetListenAddr()/GetAdvertisedIP() as primary source
	// instead of parsing enodeURL. Falls back to enodeURL parsing when the
	// configured values are empty (e.g. during testing).
	reportedIP := "127.0.0.1"
	if api.chainInfo != nil {
		if ip := api.chainInfo.GetAdvertisedIP(); ip != "" {
			reportedIP = ip
		}
		if la := api.chainInfo.GetListenAddr(); la != "" {
			listenAddr = la
		}
	}
	if enodeURL != "" && (reportedIP == "127.0.0.1" || listenAddr == "") {
		// Best-effort: extract host:port from enode://<pubkey>@<host>:<port>
		if atIdx := indexOf(enodeURL, '@'); atIdx >= 0 {
			rest := enodeURL[atIdx+1:]
			if colonIdx := indexOf(rest, ':'); colonIdx > 0 {
				if reportedIP == "127.0.0.1" {
					reportedIP = rest[:colonIdx]
				}
				// FIX: Extract port and populate listen address/ports
				// that were previously left as zero values.
				portStr := rest[colonIdx+1:]
				// Strip any query parameters (e.g. ?discport=0)
				if qIdx := indexOf(portStr, '?'); qIdx >= 0 {
					portStr = portStr[:qIdx]
				}
				if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
					listenerPort = p
					discoveryPort = p
					if listenAddr == "" {
						listenAddr = fmt.Sprintf("%s:%d", reportedIP, p)
					}
				}
			}
		}
	}

	// FIX: Redact the public key from the enode URL to prevent leaking
	// the node's cryptographic identity through admin_nodeInfo. Replace the
	// full pubkey with a truncated hash (first 16 chars) for identification.
	redactedEnode := enodeURL
	if len(enodeURL) > 22 { // "enode://" = 7 chars + "@" at minimum
		atIdx := indexOf(enodeURL, '@')
		if atIdx > 7 { // "enode://" is 7 chars
			pubkeyPart := enodeURL[7:atIdx]
			if len(pubkeyPart) > 16 {
				redactedEnode = "enode://" + pubkeyPart[:16] + "…REDACTED@" + enodeURL[atIdx+1:]
			}
		}
	}

	nodeInfo := map[string]any{
		"id":    "qau-node",
		"name":  "Quantaureum/v1.0.0/go",
		"enode": redactedEnode,
		"ip":    reportedIP,
		"ports": map[string]int{
			"discovery": discoveryPort,
			"listener":  listenerPort,
		},
		"listenAddr": listenAddr,
		"protocols": map[string]any{
			"qau": map[string]any{
				"network":    networkID,
				"difficulty": "0x0",
				"genesis":    "0x0",
				"head":       "0x0",
			},
		},
	}
	return nodeInfo, nil
}

// indexOf returns the byte index of the first occurrence of c in s, or -1 if
// not found. Used by AdminNodeInfo for best-effort enode URL parsing.
func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// QPOSStatus returns the current QPOS consensus status
func (api *API) QPOSStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.chainInfo == nil {
		return map[string]any{}, nil
	}
	return api.chainInfo.GetQPOSStatus(), nil
}

// ============================================================================
// Staking RPC Methods
// ============================================================================

// Stake handles staking requests
// audit-fix NEW-18: requires Dilithium3 signature to prove caller owns the address.
// Parameters: [address, amount, commission?, nonce, signature, publicKey]
func (api *API) Stake(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	// audit-fix NEW-18: extract authentication fields
	coreArgs, nonce, sig, pubKeyHex, rpcErr := extractStakingAuth(args, 2)
	if rpcErr != nil {
		return nil, rpcErr
	}

	// Parse address
	addrStr, ok := coreArgs[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", "address must be a string")
	}
	addr, err := parseAddress(addrStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	// Parse amount
	amountStr, ok := coreArgs[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "amount must be a string")
	}
	// Parse amount: if it has "0x" prefix, treat as hex; otherwise try decimal first.
	// This prevents decimal strings like "30000000000000000000000" (which contains
	// only hex-valid digits 0-9) from being misinterpreted as hex.
	var amount *big.Int
	if strings.HasPrefix(amountStr, "0x") || strings.HasPrefix(amountStr, "0X") {
		amount, ok = new(big.Int).SetString(stripHexPrefix(amountStr), 16)
		if !ok {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse hex amount")
		}
	} else {
		amount, ok = new(big.Int).SetString(amountStr, 10)
		if !ok {
			// Try hex without prefix as fallback
			amount, ok = new(big.Int).SetString(amountStr, 16)
			if !ok {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse amount")
			}
		}
	}

	// Parse optional commission (default 0)
	commission := uint32(0)
	if len(coreArgs) > 2 {
		if commFloat, ok := coreArgs[2].(float64); ok {
			commission = uint32(commFloat)
		}
	}

	// H-NEW-3 FIX: Validate minimum stake amount at RPC layer BEFORE expensive
	// Dilithium3 signature verification. This saves CPU on invalid requests and
	// provides clear error messages to users.
	// R64 FIX: Only enforce MinStakeAmount for NEW stakers. Existing validators
	// can top-up any amount > 0 (matches Stake() behavior in staking.go which
	// only checks MinStakeAmount for new stakes, not top-ups).
	if api.stakingManager != nil {
		config := api.stakingManager.GetConfig()
		if config != nil && config.MinStakeAmount != nil && amount.Cmp(config.MinStakeAmount) < 0 {
			existingStake, stakeErr := api.stakingManager.GetStake(addr)
			if stakeErr != nil || existingStake == nil {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "insufficient stake amount",
					fmt.Sprintf("minimum stake is %s, got %s", config.MinStakeAmount.String(), amount.String()))
			}
		}
	}

	// audit-fix NEW-18: verify Dilithium3 signature proves caller owns the address
	// AUDIT (2026) KEYS-08: Include commission in the signed params to
	// prevent a relay from tampering with the commission value after signing.
	// Previously commission was outside the signed message, so an attacker
	// could intercept a valid staking request and change the commission
	// without invalidating the signature.
	if verifyErr := api.verifyStakingSignature("stake", addr, nonce, amountStr+"|"+strconv.FormatUint(uint64(commission), 10), sig, pubKeyHex); verifyErr != nil {
		return nil, NewError(ErrCodeUnauthorized, verifyErr.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	// ── On-chain staking transaction (Ethereum-style deposit contract) ──
	// Instead of directly mutating stakingManager memory (which doesn't propagate
	// to other nodes), create a real TxTypeStake transaction that gets packed
	// into a block. The block processing pipeline (syncStakingFromBlock) then
	// updates stakingManager + QPOS + ValidatorManager on ALL nodes through
	// block synchronization — exactly like Ethereum's deposit contract.

	// Get nonce from state
	txNonce := uint64(0)
	if api.stateReader != nil {
		txNonce = api.stateReader.GetNonce(addr)
	}

	// Get chain ID
	chainID := uint64(1)
	if api.chainInfo != nil {
		chainID = api.chainInfo.ChainID()
	}

	// Check balance (stake amount + gas cost must be available)
	if api.stateReader != nil {
		balance := api.stateReader.GetBalance(addr)
		gasCost := new(big.Int).Mul(big.NewInt(100000), big.NewInt(1)) // GasLimit * GasPrice
		totalCost := new(big.Int).Add(amount, gasCost)
		if balance.Cmp(totalCost) < 0 {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "insufficient balance",
				fmt.Sprintf("need %s (stake + gas), have %s", totalCost.String(), balance.String()))
		}
	}

	// Decode public key and signature from hex
	pubKeyBytes, err := parseHexBytes(pubKeyHex)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid publicKey", err.Error())
	}
	sigBytes, err := parseHexBytes(sig)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid signature", err.Error())
	}

	// Encode commission into 4 bytes big-endian (same as types.NewQuantumStake)
	commissionData := make([]byte, 4)
	commissionData[0] = byte(commission >> 24)
	commissionData[1] = byte(commission >> 16)
	commissionData[2] = byte(commission >> 8)
	commissionData[3] = byte(commission)

	// R38-P0-02 (2026-08-01) FIX: Append the staking nonce to tx.Data so
	// the block validator can reconstruct the staking signature message
	// and verify it. Format: commission(4) + nonceLen(2) + nonce(nonceLen).
	// The nonce is the RPC-layer replay-protection nonce (NOT tx.Nonce which
	// is the on-chain account nonce). Without this, the block validator
	// cannot verify the staking signature and must skip signature verification
	// entirely — allowing a malicious proposer to forge stake/unstake txs.
	nonceBytes := []byte(nonce)
	stakingNonceData := make([]byte, 2+len(nonceBytes))
	stakingNonceData[0] = byte(len(nonceBytes) >> 8)
	stakingNonceData[1] = byte(len(nonceBytes))
	copy(stakingNonceData[2:], nonceBytes)
	txData := append(commissionData, stakingNonceData...)

	// Staking contract address: 0x0000000000000000000000000000000000001001
	// (same as economics.StakingContractAddress)
	var stakingContract types.Address
	stakingContract[18] = 0x10
	stakingContract[19] = 0x01

	// Create on-chain TxTypeStake transaction
	stakeTx := &encoding.Transaction{
		Type:      encoding.TxTypeStake,
		Nonce:     txNonce,
		ChainID:   chainID,
		From:      addr,
		To:        &stakingContract,
		Value:     amount,
		Data:      txData, // R38-P0-02: commission + staking nonce for validator verification
		GasLimit:  100000,
		GasPrice:  big.NewInt(1),
		PublicKey: pubKeyBytes,
		Signature: sigBytes, // staking signature (authorization proven by verifyStakingSignature above)
	}

	// Add to transaction pool (skips Dilithium3 tx-signature verification since
	// we already verified the staking signature). The transaction will be packed
	// into the next block and propagate to all nodes through block sync.
	if api.txPool == nil {
		return nil, NewError(ErrCodeInternal, "transaction pool not available")
	}
	txHash, poolErr := api.txPool.AddVerifiedTransaction(stakeTx)
	if poolErr != nil {
		return nil, NewError(ErrCodeInternal, fmt.Sprintf("failed to submit staking transaction: %v", poolErr))
	}

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash[:]),
		"address":   addrStr,
		"amount":    amount.String(),
		"timestamp": time.Now().Unix(),
		"onChain":   true, // indicates this is a real on-chain transaction
	}, nil
}

// Unstake handles unstaking requests
// audit-fix NEW-18: requires Dilithium3 signature to prove caller owns the address.
// Parameters: [address, amount, nonce, signature, publicKey]
func (api *API) Unstake(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	// audit-fix NEW-18: extract authentication fields
	coreArgs, nonce, sig, pubKeyHex, rpcErr := extractStakingAuth(args, 2)
	if rpcErr != nil {
		return nil, rpcErr
	}

	// Parse address
	addrStr, ok := coreArgs[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", "address must be a string")
	}
	addr, err := parseAddress(addrStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	// Parse amount
	amountStr, ok := coreArgs[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "amount must be a string")
	}
	// Parse amount: if it has "0x" prefix, treat as hex; otherwise try decimal first.
	// This prevents decimal strings like "30000000000000000000000" (which contains
	// only hex-valid digits 0-9) from being misinterpreted as hex.
	// (Consistent with Stake() amount parsing above.)
	var amount *big.Int
	if strings.HasPrefix(amountStr, "0x") || strings.HasPrefix(amountStr, "0X") {
		amount, ok = new(big.Int).SetString(stripHexPrefix(amountStr), 16)
		if !ok {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse hex amount")
		}
	} else {
		amount, ok = new(big.Int).SetString(amountStr, 10)
		if !ok {
			// Try hex without prefix as fallback
			amount, ok = new(big.Int).SetString(amountStr, 16)
			if !ok {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse amount")
			}
		}
	}

	// audit-fix NEW-18: verify Dilithium3 signature proves caller owns the address
	if verifyErr := api.verifyStakingSignature("unstake", addr, nonce, amountStr, sig, pubKeyHex); verifyErr != nil {
		return nil, NewError(ErrCodeUnauthorized, verifyErr.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	// Get current block height for unlock height estimation
	currentHeight := uint64(0)
	if api.blockReader != nil {
		currentHeight = api.blockReader.GetLatestHeight()
	}

	// ── On-chain unstaking transaction (like Ethereum withdrawal) ──
	// Create a real TxTypeUnstake transaction that gets packed into a block.
	// The block processing pipeline (syncStakingFromBlock) handles the actual
	// unstake on ALL nodes through block synchronization.

	// Get nonce from state
	txNonce := uint64(0)
	if api.stateReader != nil {
		txNonce = api.stateReader.GetNonce(addr)
	}

	// Get chain ID
	chainID := uint64(1)
	if api.chainInfo != nil {
		chainID = api.chainInfo.ChainID()
	}

	// Decode public key and signature from hex
	pubKeyBytes, err := parseHexBytes(pubKeyHex)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid publicKey", err.Error())
	}
	sigBytes, err := parseHexBytes(sig)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid signature", err.Error())
	}

	// Unstaking contract address: 0x0000000000000000000000000000000000001002
	var unstakeContract types.Address
	unstakeContract[18] = 0x10
	unstakeContract[19] = 0x02

	// R38-P0-02 (2026-08-01) FIX: Encode the staking nonce into tx.Data so
	// the block validator can reconstruct the staking signature message.
	//
	// R78-UNSTAKE-DATA (2026-08-28) FIX: the layout MUST be the canonical
	// commission(4 BE) + nonceLen(2 BE) + nonce(nonceLen) that
	// encoding.decodeStakeAuthData (reached from the canonical
	// VerifyTransactionAuthorization) parses for BOTH TxTypeStake and
	// TxTypeUnstake. This function previously emitted only
	// nonceLen(2) + nonce, so every unstake tx failed the block validator
	// with ErrAuthStakeBadData. The txpool admits it anyway through
	// AddVerifiedTransaction (signature already checked at the RPC
	// boundary), so the proposer packed the tx while every other
	// validator rejected the whole block and followers stalled at the
	// parent height.
	// Unstake carries no commission, so the canonical hash uses 0 (see
	// verifyStakingSignature, unstake branch) and the 4 leading bytes
	// stay zero here too.
	nonceBytes := []byte(nonce)
	unstakeTxData := make([]byte, 4+2+len(nonceBytes))
	// unstakeTxData[0:4] left zero = commission 0.
	unstakeTxData[4] = byte(len(nonceBytes) >> 8)
	unstakeTxData[5] = byte(len(nonceBytes))
	copy(unstakeTxData[6:], nonceBytes)

	// Create on-chain TxTypeUnstake transaction
	unstakeTx := &encoding.Transaction{
		Type:      encoding.TxTypeUnstake,
		Nonce:     txNonce,
		ChainID:   chainID,
		From:      addr,
		To:        &unstakeContract,
		Value:     amount,
		Data:      unstakeTxData, // R38-P0-02: staking nonce for validator verification
		GasLimit:  100000,
		GasPrice:  big.NewInt(1),
		PublicKey: pubKeyBytes,
		Signature: sigBytes,
	}

	// Add to transaction pool
	if api.txPool == nil {
		return nil, NewError(ErrCodeInternal, "transaction pool not available")
	}
	txHash, poolErr := api.txPool.AddVerifiedTransaction(unstakeTx)
	if poolErr != nil {
		return nil, NewError(ErrCodeInternal, fmt.Sprintf("failed to submit unstaking transaction: %v", poolErr))
	}

	// Estimate unlock height (will be finalized when block is processed)
	unlockHeight := currentHeight + 100 // approximate unlock period

	return map[string]any{
		"success":      true,
		"txHash":       formatHexBytes(txHash[:]),
		"address":      addrStr,
		"amount":       amount.String(),
		"unlockHeight": unlockHeight,
		"timestamp":    time.Now().Unix(),
		"onChain":      true,
	}, nil
}

// GetStake returns stake info for an address
func (api *API) GetStake(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	stake, err := api.stakingManager.GetStake(addr)
	if err != nil {
		return map[string]any{
			"found":  false,
			"amount": "0",
		}, nil
	}

	// Check for pending unstake
	var pendingUnstake any
	if unstakeReq, err := api.stakingManager.GetUnstakeRequest(addr); err == nil {
		pendingUnstake = map[string]any{
			"amount":        unstakeReq.Amount.String(),
			"requestHeight": unstakeReq.RequestHeight,
			"unlockHeight":  unstakeReq.UnlockHeight,
		}
	}

	return map[string]any{
		"found":          true,
		"address":        formatHexBytes(stake.Address[:]),
		"amount":         stake.Amount.String(),
		"commission":     stake.Commission,
		"stakeHeight":    stake.StakeHeight,
		"active":         stake.Active,
		"pendingUnstake": pendingUnstake,
	}, nil
}

// GetStakingPools returns available staking pools
func (api *API) GetStakingPools(ctx context.Context, params json.RawMessage) (any, *Error) {
	limit := 100
	offset := 0

	if len(params) > 0 {
		var args []any
		if err := json.Unmarshal(params, &args); err != nil {
			// FIX: Return error instead of silently using defaults.
			// Previously, parse failure was logged but execution continued
			// with default limit=100, offset=0, causing callers to receive
			// a seemingly successful response with ignored parameters.
			return nil, NewError(ErrCodeInvalidParams, "invalid staking pools parameters")
		}
		if len(args) >= 1 {
			if l, ok := args[0].(float64); ok {
				limit = int(l)
			}
		}
		if len(args) >= 2 {
			if o, ok := args[1].(float64); ok {
				offset = int(o)
			}
		}
	}

	// P2P-R10-M2 (2026-07-19) FIX: Unified pagination bounds check.
	// Previously used inline `limit <= 0 || limit > 100` / `offset < 0`
	// with no upper bound on offset, allowing MaxInt64 to reach the
	// slicing path. Now uses sanitizePagination for consistency with
	// other paginated endpoints.
	limit, offset = sanitizePagination(limit, offset, 100, 100)

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	config := api.stakingManager.GetConfig()
	totalStaked := api.stakingManager.GetTotalStaked()
	validatorCount := api.stakingManager.ValidatorCount()

	//  NOTE: "reward_rate" and "apy" use float64 for display purposes.
	// float64 has limited precision (IEEE 754 double) and should not be used
	// for exact financial calculations. The actual reward computation in
	// GetUserStakes uses big.Int integer arithmetic (amount * apy * blocks / year / 100).
	// For production, consider returning these as scaled integer strings (e.g.
	// basis points: 500 = 5.00%) to avoid float64 precision loss in JSON clients.
	pools := []map[string]any{
		{
			"pool_id":          "STAKE-QAU-30",
			"token":            "QAU",
			"reward_token":     "QAU",
			"total_staked":     totalStaked.String(),
			"reward_rate":      0.05,
			"duration_days":    30,
			"min_stake_amount": config.MinStakeAmount.String(),
			"apy":              0.0, //  StakingAPY disabled (consensus rewards only)
			"validators":       validatorCount,
		},
		{
			"pool_id":      "STAKE-QAU-90",
			"token":        "QAU",
			"reward_token": "QAU",
			// LOW-3 FIX: Previously this returned totalStaked*2, a fabricated
			// multiplier that inflated the reported stake. Use the real
			// totalStaked value; per-pool breakdown should come from on-chain
			// state when available, not from a hard-coded multiplier.
			"total_staked":     totalStaked.String(),
			"reward_rate":      0.05,
			"duration_days":    90,
			"min_stake_amount": new(big.Int).Mul(config.MinStakeAmount, big.NewInt(0)).String(),
			"apy":              0.0, //  StakingAPY disabled (consensus rewards only)
			"validators":       validatorCount,
		},
		{
			"pool_id":      "STAKE-QAU-365",
			"token":        "QAU",
			"reward_token": "QAU",
			// LOW-3 FIX: Previously this returned totalStaked*3, a fabricated
			// multiplier. Use the real totalStaked value.
			"total_staked":     totalStaked.String(),
			"reward_rate":      0.05,
			"duration_days":    365,
			"min_stake_amount": config.MinStakeAmount.String(),
			"apy":              0.0, //  StakingAPY disabled (consensus rewards only)
			"validators":       validatorCount,
		},
	}

	if offset > len(pools) {
		offset = len(pools)
	}
	end := offset + limit
	if end > len(pools) {
		end = len(pools)
	}

	return map[string]any{
		"pools":     pools[offset:end],
		"total":     len(pools),
		"limit":     limit,
		"offset":    offset,
		"timestamp": time.Now().Unix(),
	}, nil
}

// GetStakingStats returns staking statistics
func (api *API) GetStakingStats(ctx context.Context, params json.RawMessage) (any, *Error) {
	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	totalStaked := api.stakingManager.GetTotalStaked()
	validatorCount := api.stakingManager.ValidatorCount()
	activeValidatorCount := api.stakingManager.ActiveValidatorCount()

	// Calculate estimated rewards (5% APY on total staked)
	annualRewards := new(big.Int).Mul(totalStaked, big.NewInt(0))
	annualRewards.Div(annualRewards, big.NewInt(100))

	return map[string]any{
		"totalValueLocked":           totalStaked.String(),
		"totalValueLockedUSD":        0, // Would need price oracle
		"totalRewardsDistributed":    annualRewards.String(),
		"totalRewardsDistributedUSD": 0,
		"averageAPY":                 0.0, // StakingAPY disabled (consensus rewards only); audit-fix R8-Info-1
		"totalStakers":               validatorCount,
		"activeStakers":              activeValidatorCount,
		"activePools":                3,
		"timestamp":                  time.Now().Unix(),
	}, nil
}

// GetUserStakes returns all stakes for a user
func (api *API) GetUserStakes(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	stake, err := api.stakingManager.GetStake(addr)
	if err != nil {
		return map[string]any{
			"stakes":    []any{},
			"timestamp": time.Now().Unix(),
		}, nil
	}

	// Calculate rewards (simplified: 5% APY prorated)
	currentHeight := uint64(0)
	if api.blockReader != nil {
		currentHeight = api.blockReader.GetLatestHeight()
	}

	// audit-fix  guard against uint64 underflow when currentHeight < stake.StakeHeight
	var blocksStaked uint64
	if currentHeight > stake.StakeHeight {
		blocksStaked = currentHeight - stake.StakeHeight
	}
	// Assuming 12 second blocks
	blocksPerDay := uint64(7200) // 24 * 60 * 60 / 12
	blocksPerYear := blocksPerDay * 365
	apy := big.NewInt(0) // StakingAPY disabled

	rewards := new(big.Int).Mul(stake.Amount, apy)
	// FIX: Use SetUint64 instead of int64() conversion to avoid
	// overflow when blocksStaked or blocksPerYear exceeds MaxInt64.
	rewards.Mul(rewards, new(big.Int).SetUint64(blocksStaked))
	rewards.Div(rewards, new(big.Int).SetUint64(blocksPerYear))
	rewards.Div(rewards, big.NewInt(100))

	// Lock period: 30 days = 30 * 7200 = 216000 blocks
	lockPeriodBlocks := uint64(30 * 7200)
	unlockBlock := stake.StakeHeight + lockPeriodBlocks

	stakes := []map[string]any{
		{
			"pool_id":     "STAKE-QAU-30",
			"amount":      stake.Amount.String(),
			"rewards":     rewards.String(),
			"start_time":  stake.StakeHeight,
			"unlock_time": unlockBlock,
			"status":      "active",
			"apy":         0.0, //  StakingAPY disabled (consensus rewards only)
		},
	}

	return map[string]any{
		"stakes":    stakes,
		"timestamp": time.Now().Unix(),
	}, nil
}

// ClaimRewards handles reward claiming
// audit-fix NEW-18: requires Dilithium3 signature to prove caller owns the address.
// Parameters: [address, nonce, signature, publicKey]
func (api *API) ClaimRewards(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	// audit-fix NEW-18: extract authentication fields
	coreArgs, nonce, sig, pubKeyHex, rpcErr := extractStakingAuth(args, 1)
	if rpcErr != nil {
		return nil, rpcErr
	}

	addrStr, ok := coreArgs[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", "address must be a string")
	}
	addr, err := parseAddress(addrStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	stake, err := api.stakingManager.GetStake(addr)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, "no stake found for address")
	}

	currentHeight := uint64(0)
	if api.blockReader != nil {
		currentHeight = api.blockReader.GetLatestHeight()
	}

	var blocksStaked uint64
	if currentHeight > stake.StakeHeight {
		blocksStaked = currentHeight - stake.StakeHeight
	}
	blocksPerYear := uint64(2628000)
	apy := big.NewInt(0)

	rewards := new(big.Int).Mul(stake.Amount, apy)
	// FIX: Use SetUint64 instead of int64() conversion to avoid overflow.
	rewards.Mul(rewards, new(big.Int).SetUint64(blocksStaked))
	rewards.Div(rewards, new(big.Int).SetUint64(blocksPerYear))
	rewards.Div(rewards, big.NewInt(100))

	if rewards.Sign() <= 0 {
		return nil, NewError(ErrCodeInvalidParams, "no rewards to claim")
	}

	if verifyErr := api.verifyStakingSignature("claimRewards", addr, nonce, "", sig, pubKeyHex); verifyErr != nil {
		return nil, NewError(ErrCodeUnauthorized, verifyErr.Error())
	}

	nowUnix := time.Now().Unix()
	txHash := keccak256(append(addr[:], append(rewards.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"address":   addrStr,
		"amount":    rewards.String(),
		"timestamp": nowUnix,
	}, nil
}

func (api *API) CompoundRewards(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	// audit-fix NEW-18: extract authentication fields
	coreArgs, nonce, sig, pubKeyHex, rpcErr := extractStakingAuth(args, 1)
	if rpcErr != nil {
		return nil, rpcErr
	}

	addrStr, ok := coreArgs[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", "address must be a string")
	}
	addr, err := parseAddress(addrStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	stake, err := api.stakingManager.GetStake(addr)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, "no stake found for address")
	}

	// Calculate rewards
	currentHeight := uint64(0)
	if api.blockReader != nil {
		currentHeight = api.blockReader.GetLatestHeight()
	}

	// audit-fix  guard against uint64 underflow when currentHeight < stake.StakeHeight
	// Without this check, blocksStaked wraps to ~1.8e19, producing astronomical rewards
	// that get written as real stake via Stake() below — enabling infinite token creation.
	var blocksStaked uint64
	if currentHeight > stake.StakeHeight {
		blocksStaked = currentHeight - stake.StakeHeight
	}
	// audit-fix R8-M1: use 2,628,000 (12s blocks) consistent with GetUserStakes/GetPendingRewards.
	// Previously 10,512,000 (3s blocks) which understated compounded rewards by 4x.
	blocksPerYear := uint64(2628000)
	apy := big.NewInt(0)

	rewards := new(big.Int).Mul(stake.Amount, apy)
	rewards.Mul(rewards, big.NewInt(int64(blocksStaked))) //nolint:gosec,G115
	rewards.Div(rewards, big.NewInt(int64(blocksPerYear)))
	rewards.Div(rewards, big.NewInt(100))

	// audit-fix R9-L2: skip staking if rewards are zero to avoid resetting StakeHeight
	// without adding any value (e.g. when CompoundRewards is called immediately after staking).
	if rewards.Sign() <= 0 {
		return nil, NewError(ErrCodeInvalidParams, "no rewards to compound")
	}

	if verifyErr := api.verifyStakingSignature("compoundRewards", addr, nonce, "", sig, pubKeyHex); verifyErr != nil {
		return nil, NewError(ErrCodeUnauthorized, verifyErr.Error())
	}

	if api.stateReader != nil {
		accountBalance := api.stateReader.GetBalance(addr)
		if accountBalance.Cmp(rewards) < 0 {
			return nil, NewError(ErrCodeInvalidParams,
				fmt.Sprintf("insufficient balance to compound rewards: have %s, need %s", accountBalance.String(), rewards.String()))
		}
	}

	// Add rewards to stake
	if err := api.stakingManager.Stake(addr, rewards, stake.Commission, currentHeight); err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R8-L3: include timestamp so identical address+amount compounds produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(addr[:], append(rewards.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"address":   addrStr,
		"amount":    rewards.String(),
		"newTotal":  new(big.Int).Add(stake.Amount, rewards).String(),
		"timestamp": nowUnix,
	}, nil
}

// GetStakingContracts returns all staking contract addresses
func (api *API) GetStakingContracts(ctx context.Context, params json.RawMessage) (any, *Error) {
	return map[string]any{
		"staking": "0x0000000000000000000000000000000000001001",
		"unstake": "0x0000000000000000000000000000000000001002",
		"rewards": "0x0000000000000000000000000000000000001003",
		"description": map[string]string{
			"staking": "Send QAU to this address to stake. Amount sent = stake amount.",
			"unstake": "Send a transaction to this address to request unstake. Value = amount to unstake (0 = all).",
			"rewards": "Send a transaction to this address to claim pending rewards.",
		},
		"lockPeriod": map[string]any{
			"blocks":      216000,
			"days":        30,
			"description": "Unstaked tokens are locked for 30 days before withdrawal.",
		},
	}, nil
}

// GetPendingRewards returns pending rewards for an address
func (api *API) GetPendingRewards(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	currentHeight := uint64(0)
	if api.blockReader != nil {
		currentHeight = api.blockReader.GetLatestHeight()
	}

	// Get stake info
	stake, err := api.stakingManager.GetStake(addr)
	if err != nil {
		return map[string]any{
			"address":        args[0],
			"pendingRewards": "0",
			"hasStake":       false,
		}, nil
	}

	// audit-fix R9-M1: use 5% APY consistent with ClaimRewards/CompoundRewards/GetUserStakes.
	// Previously 18.5% — users saw ~3.7x more pending rewards than they could actually claim.
	blocksPerYear := uint64(2628000)
	// audit-fix  guard against uint64 underflow when currentHeight < stake.StakeHeight
	var blocksStaked uint64
	if currentHeight > stake.StakeHeight {
		blocksStaked = currentHeight - stake.StakeHeight
	}
	apy := big.NewInt(0) // StakingAPY disabled

	rewards := new(big.Int).Mul(stake.Amount, apy)
	rewards.Mul(rewards, big.NewInt(int64(blocksStaked))) //nolint:gosec,G115
	rewards.Div(rewards, big.NewInt(int64(blocksPerYear)))
	rewards.Div(rewards, big.NewInt(100))

	return map[string]any{
		"address":        args[0],
		"pendingRewards": rewards.String(),
		"stakedAmount":   stake.Amount.String(),
		"blocksStaked":   blocksStaked,
		"apy":            0.0, //  StakingAPY disabled (consensus rewards only)
		"hasStake":       true,
	}, nil
}

// GetUnstakeStatus returns the status of an unstake request
func (api *API) GetUnstakeStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	addr, err := parseAddress(args[0])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	currentHeight := uint64(0)
	if api.blockReader != nil {
		currentHeight = api.blockReader.GetLatestHeight()
	}

	unstakeReq, err := api.stakingManager.GetUnstakeRequest(addr)
	if err != nil {
		return map[string]any{
			"address":    args[0],
			"hasRequest": false,
		}, nil
	}

	// Calculate time remaining
	blocksRemaining := uint64(0)
	if unstakeReq.UnlockHeight > currentHeight {
		blocksRemaining = unstakeReq.UnlockHeight - currentHeight
	}

	// 12 seconds per block
	secondsRemaining := blocksRemaining * 12
	canWithdraw := currentHeight >= unstakeReq.UnlockHeight

	return map[string]any{
		"address":          args[0],
		"hasRequest":       true,
		"amount":           unstakeReq.Amount.String(),
		"requestHeight":    unstakeReq.RequestHeight,
		"unlockHeight":     unstakeReq.UnlockHeight,
		"currentHeight":    currentHeight,
		"blocksRemaining":  blocksRemaining,
		"secondsRemaining": secondsRemaining,
		"canWithdraw":      canWithdraw,
	}, nil
}

// GetContractBalance returns the expected balance of the staking contract
func (api *API) GetContractBalance(ctx context.Context, params json.RawMessage) (any, *Error) {
	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	totalStaked := api.stakingManager.GetTotalStaked()

	// Get actual contract balance from state
	actualBalanceStr := "0"
	if api.stateReader != nil {
		// Staking contract address
		var stakingAddr [20]byte
		stakingAddr[18] = 0x10
		stakingAddr[19] = 0x01
		actualBalance := api.stateReader.GetBalance(stakingAddr)
		if actualBalance != nil {
			actualBalanceStr = actualBalance.String()
		}
	}

	return map[string]any{
		"totalStaked":     totalStaked.String(),
		"actualBalance":   actualBalanceStr,
		"stakingContract": "0x0000000000000000000000000000000000001001",
	}, nil
}

// keccak256 computes the Keccak-256 hash
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// GetContractList returns all contracts on the chain (accounts with code)
func (api *API) GetContractList(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []map[string]any
	if err := json.Unmarshal(params, &args); err != nil || len(args) > 1 {
		return nil, ErrInvalidParams
	}

	limit := 100
	offset := 0
	includeZeroBalance := false

	if len(args) > 0 {
		if l, ok := args[0]["limit"]; ok {
			if lf, ok := l.(float64); ok {
				limit = int(lf)
			}
		}
		if o, ok := args[0]["offset"]; ok {
			if of, ok := o.(float64); ok {
				offset = int(of)
			}
		}
		if izb, ok := args[0]["includeZeroBalance"]; ok {
			if b, ok := izb.(bool); ok {
				includeZeroBalance = b
			}
		}
	}

	// P2P-R10-M2 (2026-07-19) FIX: Unified pagination bounds check.
	// Previously used inline `limit < 1 → 1; limit > 500 → 500; offset < 0 → 0`
	// with no upper bound on offset, inconsistent with GetStakingPools (max 100)
	// and GetPendingTransfers (max 100). Now uses sanitizePagination for
	// consistency; maxLimit=500 retained for this endpoint since the contract
	// list can legitimately be large.
	limit, offset = sanitizePagination(limit, offset, 100, 500)

	if api.stateReader == nil {
		return nil, NewError(ErrCodeInternal, "state reader not available")
	}

	type contractInfo struct {
		Address  string `json:"address"`
		Balance  string `json:"balance"`
		CodeSize int    `json:"codeSize"`
	}

	var allContracts []contractInfo

	api.stateReader.IterateAccounts(func(addr types.Address, code []byte, balance *big.Int) bool {
		// Only include accounts with code (contracts)
		if len(code) == 0 {
			return true // continue iterating
		}

		// Filter zero-balance contracts unless requested
		if !includeZeroBalance && balance.Sign() == 0 {
			return true
		}

		allContracts = append(allContracts, contractInfo{
			Address:  "0x" + hex.EncodeToString(addr[:]),
			Balance:  "0x" + balance.Text(16),
			CodeSize: len(code),
		})
		return true
	})

	// Sort by balance descending
	sort.Slice(allContracts, func(i, j int) bool {
		// FIX: Check SetString return value instead of silently ignoring it.
		// If parsing fails (malformed hex), default to 0 for stable sort ordering.
		bi, ok1 := new(big.Int).SetString(allContracts[i].Balance[2:], 16)
		if !ok1 || bi == nil {
			bi = big.NewInt(0)
		}
		bj, ok2 := new(big.Int).SetString(allContracts[j].Balance[2:], 16)
		if !ok2 || bj == nil {
			bj = big.NewInt(0)
		}
		return bj.Cmp(bi) < 0
	})

	// Apply offset and limit
	total := len(allContracts)
	if offset >= total {
		return map[string]any{
			"contracts": []contractInfo{},
			"total":     total,
		}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return map[string]any{
		"contracts": allContracts[offset:end],
		"total":     total,
	}, nil
}

// GetRewardPoolStatus returns the reward pool status for audit.
// This is a read-only method that exposes reward pool accounting.
func (api *API) GetRewardPoolStatus(ctx context.Context, params json.RawMessage) (any, *Error) {
	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	status := api.stakingManager.GetRewardPoolStatus()

	// Convert *big.Int values to strings for JSON serialization
	result := make(map[string]any)
	for k, v := range status {
		if bi, ok := v.(*big.Int); ok {
			result[k] = bi.String()
		} else {
			result[k] = v
		}
	}

	return map[string]any{
		"reward_pool": result,
		"timestamp":   time.Now().Unix(),
	}, nil
}

// GetTotalRewardsClaimed returns the total rewards claimed across all stakers.
// This is a read-only audit method.
func (api *API) GetTotalRewardsClaimed(ctx context.Context, params json.RawMessage) (any, *Error) {
	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	total := api.stakingManager.GetTotalRewardsClaimed()

	return map[string]any{
		"total_rewards_claimed": total.String(),
		"timestamp":             time.Now().Unix(),
	}, nil
}

// UpdateCommission updates a validator's commission rate.
// audit-fix NEW-18: requires Dilithium3 signature to prove caller owns the address.
// Only the validator themselves can update their commission (caller == addr).
// Parameters: [address, commission, nonce, signature, publicKey]
func (api *API) UpdateCommission(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	// audit-fix NEW-18: extract authentication fields
	coreArgs, nonce, sig, pubKeyHex, rpcErr := extractStakingAuth(args, 2)
	if rpcErr != nil {
		return nil, rpcErr
	}

	addrStr, ok := coreArgs[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", "address must be a string")
	}
	addr, err := parseAddress(addrStr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	// Parse commission (JSON number comes as float64)
	var commission uint32
	switch v := coreArgs[1].(type) {
	case float64:
		commission = uint32(v) //nolint:gosec
	case string:
		parsed, parseErr := strconv.Atoi(v)
		if parseErr != nil {
			return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid commission", "commission must be a number")
		}
		commission = uint32(parsed) //nolint:gosec
	default:
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid commission", "commission must be a number")
	}

	// audit-fix NEW-18: verify Dilithium3 signature proves caller owns the address
	if verifyErr := api.verifyStakingSignature("updateCommission", addr, nonce, fmt.Sprintf("%d", commission), sig, pubKeyHex); verifyErr != nil {
		return nil, NewError(ErrCodeUnauthorized, verifyErr.Error())
	}

	if err := api.requireStakingManager(); err != nil {
		return nil, err
	}

	// caller == addr: only the validator themselves can update their commission
	if err := api.stakingManager.UpdateCommission(addr, addr, commission); err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R8-L3: include timestamp for unique txHash.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(addr[:], append([]byte{byte(commission)}, big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":    true,
		"txHash":     formatHexBytes(txHash),
		"address":    addrStr,
		"commission": commission,
		"timestamp":  nowUnix,
	}, nil
}

// CreateSnapshot creates a state snapshot at the specified block height
func (api *API) CreateSnapshot(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.snapshotManager == nil {
		return nil, NewError(ErrCodeInternal, "snapshot manager not available")
	}

	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		// No params = snapshot at latest height
	}

	var height uint64
	if len(args) > 0 {
		switch v := args[0].(type) {
		case float64:
			height = uint64(v)
		case string:
			h, err := parseBlockNumber(v, api.blockReader)
			if err != nil {
				return nil, NewError(ErrCodeInvalidParams, "invalid block height")
			}
			height = h
		}
	} else {
		// Default to latest block
		if api.blockReader != nil {
			height = api.blockReader.GetLatestHeight()
		}
	}

	result, err := api.snapshotManager.CreateSnapshot(height)
	if err != nil {
		//  err.Error() in Data is stripped by sanitizeError in production
		return nil, NewErrorWithData(ErrCodeInternal, "failed to create snapshot", err.Error())
	}

	return result, nil
}

// RestoreSnapshot restores state from a snapshot at the specified block height
func (api *API) RestoreSnapshot(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.snapshotManager == nil {
		return nil, NewError(ErrCodeInternal, "snapshot manager not available")
	}

	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	var height uint64
	switch v := args[0].(type) {
	case float64:
		height = uint64(v)
	case string:
		h, err := parseBlockNumber(v, api.blockReader)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid block height")
		}
		height = h
	}

	result, err := api.snapshotManager.RestoreSnapshot(height)
	if err != nil {
		//  err.Error() in Data is stripped by sanitizeError in production
		return nil, NewErrorWithData(ErrCodeInternal, "failed to restore snapshot", err.Error())
	}

	return result, nil
}

// RollbackChainToFork is the handler for debug_rollbackChainToHeight
// (R45-FORKRECOVERY-API, 2026-08-12). It deletes all blocks at or above
// the given forkHeight from the local block store and rewinds the
// stateDB to that height, allowing the syncer to re-import the canonical
// branch from peers without persisting a locally-poisoned fork.
//
// Returns map{"forkHeight": N, "deletedBlocks": M}.
func (api *API) RollbackChainToFork(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.forkRecoveryMgr == nil {
		return nil, NewError(ErrCodeInternal, "fork recovery manager not available")
	}

	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	var forkHeight uint64
	switch v := args[0].(type) {
	case float64:
		forkHeight = uint64(v)
	case string:
		h, err := parseBlockNumber(v, api.blockReader)
		if err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid fork height")
		}
		forkHeight = h
	default:
		return nil, NewError(ErrCodeInvalidParams, "fork height must be number or block-tag string")
	}

	if forkHeight == 0 {
		return nil, NewError(ErrCodeInvalidParams, "refusing to rollback to genesis height 0 — peer re-seeding protection")
	}

	deleted, err := api.forkRecoveryMgr.RollbackToFork(forkHeight)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInternal, "fork rollback failed", err.Error())
	}
	return map[string]any{
		"forkHeight":    forkHeight,
		"deletedBlocks": deleted,
	}, nil
}

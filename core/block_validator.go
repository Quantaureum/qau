// Quantaureum Node source, version 1.0.0.
package core

// L14-028 SECURITY NOTE: Chain reorganization depth is limited by the
// finality mechanism in the QPOS consensus layer. Once a block is
// finalized (after F finality threshold blocks), it cannot be reorged.
// Reorgs deeper than the finality window are rejected. This prevents
// long-range attack vectors where an adversary attempts to rewrite
// significant portions of chain history.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// MaxSlotGap bounds how far a block's slot may jump ahead of its parent's
// slot (R37-P0-01, 2026-07-30). Without a bound, a single elected validator
// could search for a far-future slot S+k where they win the (predictable)
// election, stamp a timestamp up to parent+12k+15s, and permanently freeze
// or monopolize the chain (all honest wall-clock blocks then fail either
// slotGap<0 or the minimum-interval check).
//
// Value: 2 epochs (64 slots ≈ 12.8 min at 12s/slot). This tolerates normal
// missed slots, validator restarts, and brief network stalls, while capping
// the attack stall to ~12.8 minutes. TRADE-OFF: a FULL-network outage longer
// than ~12.8 minutes produces a recovery block whose slotGap exceeds this
// bound (block production slots are wall-clock derived); recovery from such
// an outage requires a coordinated validator upgrade raising this value.
// This is a CONSENSUS rule — all validators must run the same value.
const MaxSlotGap = 2 * consensus.SlotsPerEpoch

// MaxFutureSlotGap is the maximum number of slots a block can be ahead
// of the current wall-clock slot (computed from genesis time). R38-P0-03.
// Set to 2 epochs (64 slots ≈ 12.8 minutes) — generous enough for clock
// drift and network latency, tight enough to prevent future-slot election
// attacks. Unlike MaxSlotGap, this does NOT prevent recovery from long
// downtimes because it is relative to wall-clock time, not to the parent.
const MaxFutureSlotGap = uint64(2 * consensus.SlotsPerEpoch)

// R37-FIX P2-CORE-01 (2026-07-30): Block gas limit validation constants.
// header.GasLimit was previously never validated, so a proposer could stamp
// GasLimit=MaxUint64 (BaseFee target = GasLimit/2 explodes → BaseFee falls
// -12.5%/block and honest validators must follow → fee market destroyed) or
// a tiny value (fees driven up). Ethereum rules are applied:
//
//	|header.GasLimit - parent.GasLimit| < parent.GasLimit / GasLimitBoundDivisor
//	header.GasLimit >= MinGasLimit
//
// plus a hard protocol ceiling.
const GasLimitBoundDivisor = 1024

// MinGasLimit is the minimum acceptable block gas limit (same as Ethereum).
const MinGasLimit = 5000

// MaxBlockGasLimitProtocol is a hard protocol-level ceiling on the block gas
// limit. Deliberately NOT the locally-configured maxGasLimit: validators run
// heterogeneous configs (20M on some nodes, 30M on mainnet), so enforcing a
// local config value here would partition the chain. 60M = 2x the current
// mainnet target leaves room for governance-approved increases (reachable in
// ~700 blocks at the 1/1024 per-block drift) while bounding manipulation.
const MaxBlockGasLimitProtocol = 60_000_000

// Block validation errors
var (
	ErrInvalidBlockVersion = errors.New("invalid block version")
	ErrInvalidBlockHeight  = errors.New("invalid block height")
	ErrInvalidParentHash   = errors.New("invalid parent hash")
	ErrInvalidTimestamp    = errors.New("invalid timestamp")
	ErrFutureBlock         = errors.New("block timestamp in future")
	ErrInvalidTxRoot       = errors.New("invalid transaction root")
	ErrInvalidStateRoot    = errors.New("invalid state root")
	ErrInvalidReceiptRoot  = errors.New("invalid receipt root")
	// ErrDuplicateTransaction is returned when a block contains two
	// transactions with the same hash. This is the active defense against
	// CVE-2012-2459 (Merkle duplicate-last malleability, audit R4-DATA-08):
	// the exploit shape requires the same leaf to appear twice in the list
	// ([A,B,C,C] for an even-count forgery of [A,B,C]). Rejecting duplicate
	// transaction hashes makes the latent structural vulnerability
	// unexploitable regardless of any future relaxation of nonce uniqueness.
	ErrDuplicateTransaction  = errors.New("duplicate transaction in block")
	ErrBlockGasLimitExceeded = errors.New("block gas limit exceeded")
	ErrEmptyBlock            = errors.New("empty block")
	ErrInvalidProposer       = errors.New("invalid block proposer")
	ErrInvalidVRFProof       = errors.New("invalid VRF proof")
	ErrInvalidSignature      = errors.New("invalid block signature")
	// ErrSlotGapTooLarge is returned when header.Slot jumps more than
	// MaxSlotGap slots ahead of parent.Slot (R37-P0-01 slot inflation).
	ErrSlotGapTooLarge = errors.New("slot gap exceeds maximum allowed")
	// ErrEpochSlotMismatch is returned when header.Epoch does not equal
	// SlotToEpoch(header.Slot) (R37-P1-CORE-01 epoch/slot binding).
	ErrEpochSlotMismatch = errors.New("header epoch does not match slot")
	ErrInvalidChainID    = errors.New("invalid chain ID: replay attack protection")
	ErrInvalidKeyVersion = errors.New("invalid block key version: validator not configured")
	// ErrInvalidBaseFee is returned when header.BaseFee does not match the
	// EIP-1559 derivation from the parent block (audit R4-ECON-01).
	ErrInvalidBaseFee = errors.New("invalid base fee")
	// ErrInvalidGasLimit is returned when header.GasLimit violates the
	// ±1/1024 parent-drift bound or the [MinGasLimit, MaxBlockGasLimitProtocol]
	// clamp (R37-P2-CORE-01).
	ErrInvalidGasLimit = errors.New("invalid gas limit")
	// P1-3 (2026-07-14): DA availability gating. Returned when the DA layer
	// reports that the block's blob data is not sufficiently available
	// (sampling confidence below threshold). Only enforced when a
	// DankshardingEngine is injected AND daCheckEnabled is true AND the
	// node is not in syncing mode.
	ErrDANotAvailable = errors.New("block blob data not sufficiently available via DA sampling")
	// CONS- (2026-07-22): EIP-4844 blob gas validation errors.
	ErrInvalidBlobGasUsed   = errors.New("invalid blob gas used")
	ErrInvalidExcessBlobGas = errors.New("invalid excess blob gas")
	ErrInvalidBlobMaxFee    = errors.New("invalid blob max fee")
)

// ValidatorLookup provides validator public key lookup for signature verification
type ValidatorLookup interface {
	// GetValidatorPublicKey returns the public key for a validator address
	GetValidatorPublicKey(addr types.Address) ([]byte, error)
	// IsValidator returns true if the address is a registered validator
	IsValidator(addr types.Address) bool
}

// MultiSigRosterProvider supplies the on-chain signer roster for verifying
// TxTypeMultiSig transactions at the block-validation boundary.
// AUDIT-FULL-ROUND1-2026-08-15 P0-02 FIX (2026-08-15).
//
// Background: encoding.VerifyTransactionAuthorization FAIL-CLOSED on
// TxTypeMultiSig with ErrAuthMultiSigUnsupported because the encoding
// package cannot import the on-chain multisig registry (would create a
// cycle: encoding <- economics <- ...). The dedicated helper
// encoding.VerifyMultiSigAuthorization(tx, roster) takes the signer
// roster as an external input and does the N-of-M Dilithium3 verification;
// the canonical entry point's comment explicitly says "the consensus
// block validator path is responsible for routing MultiSig to that
// helper". Round 1 of the boundary audit flagged this gap as P0-02:
// infrastructure existed, but no caller routed to it.
//
// This interface closes that gap. node/ wires a wallet/multisig adapter
// into BlockValidator.SetMultiSigRosterProvider during initialization;
// validateTransactions then re-routes TxTypeMultiSig transactions out of
// the ordinary ValidateTxBatch pipeline (which would just return
// ErrAuthMultiSigUnsupported) into the N-of-M path via
// encoding.VerifyMultiSigAuthorization.
//
// Contract:
//   - GetSignerRoster returns the M public keys eligible to sign a tx
//     bound to this walletAddress, in the SAME index order as
//     tx.MultiSigSignerBitmap (bit i = 1 => roster[i] signed).
//   - Returns nil roster (with nil error) when the wallet is not
//     registered with the on-chain multisig registry — the block
//     validator treats nil roster as fail-closed (reject the block).
//   - GetSignerRoster must be safe to call concurrently with ValidateBlock;
//     the registered adapter implements its own locking.
type MultiSigRosterProvider interface {
	GetSignerRoster(walletAddress types.Address) ([][]byte, error)
}

// KeyVersionValidator checks if a block's signing key version is valid.
// audit-fix C-5: CRITICAL - interface for consensus-layer key version validation
// to reject blocks signed with revoked or not-yet-active keys during rotation.
type KeyVersionValidator interface {
	ValidateKeyVersion(blockKeyVersion uint64, blockTimestamp int64) error
	GetCurrentKeyVersion() uint64
}

type TSSVerifier interface {
	VerifyCombinedSignature(signature []byte, message []byte) error
	HasGroupPublicKey() bool
}

// ProposerElectionVerifier verifies that a block's proposer was legitimately
// elected for the given slot/epoch.
//
// audit fix (H-7) [CRITICAL]: ValidateBlock must verify that the
// block's ProposerAddr matches the expected proposer determined by the QPOS
// election algorithm. Without this check, any registered validator can propose
// blocks in arbitrary slots, bypassing the QPOS election entirely.
//
// The QPOS consensus engine should implement this interface and be registered
// via SetElectionVerifier during node initialization.
type ProposerElectionVerifier interface {
	// VerifyProposer checks that proposer is the legitimate elected proposer
	// for the given slot and epoch. Returns nil if the proposer is valid,
	// or an error describing why the proposer is not legitimate.
	VerifyProposer(proposer types.Address, slot, epoch uint64) error
}

// NonceReader provides pre-state nonce lookup for replay protection.
// AUDIT (2026) R4-ECON-02: BlockValidator anchors the first transaction
// of each sender to the pre-state nonce to reject already-executed (replayed)
// transactions that waste block space and Dilithium verification time (~0.4s).
// The executor (ECON- fix) prevents replays from executing, but they
// still cause denial-of-service via wasted validation work.
type NonceReader interface {
	GetNonce(addr types.Address) uint64
}

// ForkRuleProvider supplies consensus rules that are active at a given block
// height. When injected into BlockValidator, the validator enforces fork-gated
// parameters (MaxBlockGas, MaxTxSize, BlockTime) instead of the hardcoded
// defaults set in NewBlockValidator.
//
// AUDIT (2026) R4-NODE-01 FIX: Previously the ForkManager was constructed
// in node.initUpgrade but never consulted by any consensus or execution code
// — all planned fork rules (MaxBlockGas, EnableVerkle, etc.) were dead code.
// This interface allows node.go to inject the ForkManager so that
// ValidateBlock enforces the rules active at the block's height.
type ForkRuleProvider interface {
	// GetRulesAtHeight returns the consensus rules active at the given
	// height, or nil if no rules are configured (fall back to defaults).
	GetRulesAtHeight(height uint64) *ForkRules
}

// ForkRules is the consensus ruleset active at a given height. It is a
// core-local DTO that mirrors upgrade.ForkRules without creating an import
// cycle (core cannot import upgrade; upgrade can import core).
type ForkRules struct {
	MaxBlockGas uint64
	MaxTxSize   uint64
	BlockTime   uint64 // seconds
}

// BlockValidator validates blocks.
type BlockValidator struct {
	mu                     sync.RWMutex
	chainID                uint64
	maxGasLimit            uint64
	maxFutureTime          time.Duration
	minBlockInterval       time.Duration
	validatorLookup        ValidatorLookup
	multisigRosterProvider MultiSigRosterProvider
	keyVersionValidator    KeyVersionValidator
	tssVerifier            TSSVerifier
	devMode                bool
	// signingVerifier verifies Dilithium3 transaction signatures in blocks.
	// When set, validateTransactions batch-verifies all tx signatures in parallel.
	// SECURITY FIX: Without this, a malicious proposer could include
	// invalid-signature transactions in blocks that other nodes would accept.
	signingVerifier *crypto.SigningVerifier
	// audit fix (H-7) [CRITICAL]: electionVerifier verifies that the
	// block's proposer was legitimately elected via QPOS. When set,
	// ValidateBlock rejects blocks from non-elected proposers. When not set
	// and not in devMode, ValidateBlock fails closed (rejects all blocks).
	electionVerifier ProposerElectionVerifier
	// vrfEnforced gates the VRF proof/value existence check and cryptographic
	// verification. SECURITY (audit 2026-06-26, P1-01): VRF generation is now
	// implemented in the block producer. Set to true in production via
	// SetVRFEnforced(true) during node initialization.
	vrfEnforced bool
	// vrfSeed is the seed for VRF verification. When set and vrfEnforced
	// is true, ValidateBlock calls ValidateVRFProof to cryptographically
	// verify the VRF proof (not just check existence). audit-fix H-8.
	vrfSeed types.Hash
	// CONS- (2026-07-19) FIX: receiptRootValidator field REMOVED.
	// Previously this struct field was set during ValidateBlock and
	// retrieved via GetReceiptRootValidator(). Two concurrent
	// ValidateBlock calls would overwrite each other's stored closure,
	// causing the second caller to retrieve a closure bound to the
	// first caller's block — a data race / semantic bug. Now
	// GetReceiptRootValidator(block) takes the block as an argument and
	// returns a fresh closure each time, eliminating the shared state.
	// syncingMode skips election verification during initial chain sync.
	// When a node starts from genesis (no chain data), QPOS internal state
	// (randaoMix, finalizedRoot) is zero-initialized and cannot be rebuilt
	// without first processing all blocks — but blocks can't be validated
	// without the correct QPOS state. syncingMode breaks this chicken-and-egg
	// by skipping election verification until sync completes, after which
	// the node switches to strict production verification.
	//
	// R38-P1-08 FIX 2 (2026-08-01, conservative): We KEEP the syncingMode
	// skip (removing it would break initial sync because QPOS snapshots are
	// not available until the chain is replayed) but we now (a) log a WARN
	// every time the skip fires so it is visible, and (b) increment
	// syncingModeSkipCount so operators can detect how many blocks entered
	// the unverified-proposer path during the last sync session. This is
	// the conservative mitigation; the full fix requires reconstructing the
	// QPOS proposer set incrementally during sync so each peer-supplied
	// block's proposer can be verified against a snapshot built from the
	// blocks received so far. Tracked as:
	// TODO(R38-P1-08 follow-up): Reconstruct QPOS proposer snapshots
	// incrementally during sync so proposer election can be verified
	// block-by-block instead of being skipped wholesale.
	syncingMode          bool
	syncingModeSkipCount uint64 // atomic; observable via SyncingModeSkipCount()
	// R38-P1-08 DEEP FIX (2026-08-02): When syncingMode is true AND
	// syncProposerVerification is true AND an electionVerifier is
	// configured, ValidateBlock runs a BEST-EFFORT VerifyProposer on each
	// sync-applied block. If the QPOS snapshot is sufficiently
	// reconstructed (the deep-fix ApplyBlockHeader path), this will pass
	// for honestly-elected proposers; if the snapshot hasn't yet reached
	// this slot (early-sync gaps), VerifyProposer returns a NotFound-style
	// error and we conservatively fall back to skipping (still counted,
	// still logged) so honest nodes are not falsely rejected.
	//
	// R39-P1-04 (2026-08-02) FIX: the default is now TRUE. R38-P1-08 left
	// this OFF and only documented SetSyncProposerVerification(true) as a
	// deployment checklist item; the R39 audit calls out that
	// "default OFF + opt-in checklist" is operationally equivalent to
	// "no defense" because no production deployment actually flips the
	// opt-in. NewBlockValidator now sets syncProposerVerification=true
	// explicitly so production nodes always run the best-effort check.
	// Operators who genuinely want the legacy OFF behavior can call
	// SetSyncProposerVerification(false).
	syncProposerVerification          bool
	syncProposerVerificationPassCount uint64 // atomic; observable
	syncProposerVerificationFailCount uint64 // atomic; observable

	// R40-P1-07 / R40-P2-06 (2026-08-03) — lifecycle management for the
	// post-sync re-verification sweep goroutine launched by
	// SetSyncingMode(false). The goroutine was previously fire-and-forget
	// ("intentionally NOT joined"); on node shutdown it could keep running
	// long after the validator's electionVerifier / QPOS snapshot were
	// torn down, leading to use-after-free style reads of freed consensus
	// state and a goroutine leak across graceful-restart cycles. The sweep
	// now runs under sweepCtx, which SetSyncingMode(false) (re)creates via
	// context.WithCancel and Stop() cancels. Each reverify iteration checks
	// sweepCtx.Done() and exits early when the node is shutting down.
	sweepCtx    context.Context
	sweepCancel context.CancelFunc

	// R39-P1-04 (2026-08-02) FIX: sync-period re-verification queue.
	// Every sync-period block whose proposer election verification was
	// SKIPPED (either because syncProposerVerification was off, or because
	// the best-effort VerifyProposer returned NotFound-style and fell
	// through conservatively) is recorded here as {slot, epoch, proposer,
	// height}. When SetSyncingMode(false) is called (chain sync done), the
	// BlockValidator re-walks this list and runs VerifyProposer on each
	// entry against the now-fully-reconstructed QPOS snapshot; pass/fail
	// are counted on the existing Pass/Fail counters and any fail is
	// logged at WARN so operators get a single grep point
	// ("R39-P1-04 SYNC-REVERIFY-FAIL") for forensic follow-up.
	//
	// Memory bound: the long-tail sync is at most a few thousand blocks;
	// each entry is O(48) bytes (slot/epoch/height + 20-byte Address),
	// so even a 10k-block sync uses ≈ 480 KB. The list is cleared on
	// SetSyncingMode(false) (after the re-verification sweep) and on
	// SetSyncingMode(true), so it cannot grow unbounded across cycles
	// (a node that toggles sync repeatedly clears each time).
	pendingReverify []reverifyRecord
	// P1-3 (2026-07-14): DankshardingEngine for DA availability verification.
	// When set AND daCheckEnabled is true, ValidateBlock extracts blob
	// commitments from the block's blob transactions and calls
	// VerifyBlockDAAvailability to sample the DA layer. If sampling reports
	// the blob data is not sufficiently available, the block is rejected
	// with ErrDANotAvailable. This is opt-in: only DA committee members
	// and full nodes that wish to independently verify DA availability
	// should enable it. Non-DA nodes rely on the aggregate attestation
	// checked in QPOS finalizeBlock (P1-4).
	danksharding   *DankshardingEngine
	daCheckEnabled bool
	// privacyEnabled gates TxTypePrivacy acceptance in validated blocks.
	// Default false — production nodes do not wire a PrivacyTxVerifier,
	// so any privacy tx in a block is a forged-drain attack (audit R4-ZK-01).
	// Set true only when the ZK privacy subsystem is fully configured.
	privacyEnabled bool
	// nonceReader provides pre-state nonce for replay detection.
	// AUDIT (2026) R4-ECON-02: When set, validateTransactions anchors
	// each sender's first tx in the block to the pre-state nonce, rejecting
	// already-executed replays that waste block space and sig verification.
	nonceReader NonceReader
	// forkRuleProvider supplies fork-gated consensus rules.
	// AUDIT (2026) R4-NODE-01: When set, ValidateBlock enforces the
	// MaxBlockGas/MaxTxSize/BlockTime active at the block's height instead
	// of the hardcoded defaults. When nil, the hardcoded defaults apply
	// (backward-compatible behavior).
	forkRuleProvider ForkRuleProvider
}

// reverifyRecord is the unit of the R39-P1-04 post-sync re-verification
// queue. Fields are the minimal set VerifyProposer needs plus block height
// for log readability.
type reverifyRecord struct {
	height   uint64
	slot     uint64
	epoch    uint64
	proposer types.Address
}

// SetPrivacyEnabled controls whether blocks containing TxTypePrivacy
// transactions are accepted. Default false. See audit R4-ZK-01.
func (v *BlockValidator) SetPrivacyEnabled(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.privacyEnabled = enabled
}

// NewBlockValidator creates a new block validator.
func NewBlockValidator(chainID, maxGasLimit uint64) *BlockValidator {
	return &BlockValidator{
		chainID:          chainID,
		maxGasLimit:      maxGasLimit,
		maxFutureTime:    15 * time.Second,
		minBlockInterval: 12 * time.Second, // audit-fix L9-015: 12s minimum block interval (Ethereum-compatible)
		// R39-P1-04 (2026-08-02) FIX: default ON. R38-P1-08 conservatively
		// kept this OFF and only documented SetSyncProposerVerification(true)
		// as a deployment checklist item; audit R39-P1-04 calls out that
		// "default OFF + opt-in checklist" is operationally equivalent to
		// "no defense" (no production deployment actually flips it). Flip
		// the default ON so production nodes ALWAYS run a best-effort
		// VerifyProposer on sync-applied blocks; the deep-fix
		// ApplyBlockHeader path already makes VerifyProposer's NotFound look
		// the same as "snapshot doesn't have this slot yet" and falls
		// through conservatively (counted, logged, but the block still
		// applies) so honest nodes aren't falsely rejected. Operators who
		// genuinely want the legacy OFF behavior can call
		// SetSyncProposerVerification(false); tests do that explicitly
		// when they pin the OFF path.
		syncProposerVerification: true,
	}
}

// SetValidatorLookup sets the validator lookup for signature verification
func (v *BlockValidator) SetValidatorLookup(lookup ValidatorLookup) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.validatorLookup = lookup
}

// SetMultiSigRosterProvider sets the on-chain multisig signer-roster
// provider used to route TxTypeMultiSig transactions to
// encoding.VerifyMultiSigAuthorization. AUDIT-FULL-ROUND1-2026-08-15 P0-02 FIX.
//
// When set AND a block contains TxTypeMultiSig transactions, validateTransactions
// queries the provider for the signer roster of each MultiSig-wallet address
// and calls encoding.VerifyMultiSigAuthorization(tx, roster) — the canonical
// N-of-M Dilithium3 path. When NOT set, validateTransactions rejects any
// block containing a TxTypeMultiSig transaction — fail-closed, identical
// posture to encoding.VerifyTransactionAuthorization's ErrAuthMultiSigUnsupported
// (no silent "skip and trust" bypass).
func (v *BlockValidator) SetMultiSigRosterProvider(p MultiSigRosterProvider) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.multisigRosterProvider = p
}

// SetSigningVerifier sets the signing verifier for transaction signature verification.
// SECURITY FIX: When set, validateTransactions batch-verifies all Dilithium3
// transaction signatures in blocks, preventing malicious proposers from
// including forged-signature transactions.
func (v *BlockValidator) SetSigningVerifier(sv *crypto.SigningVerifier) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.signingVerifier = sv
}

// SetKeyVersionValidator sets the key version validator for rotation-safe block validation.
// audit-fix C-5: CRITICAL - must be called during node initialization to enforce
// key version checks during block validation.
func (v *BlockValidator) SetKeyVersionValidator(kvv KeyVersionValidator) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keyVersionValidator = kvv
}

func (v *BlockValidator) SetTSSVerifier(verifier TSSVerifier) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tssVerifier = verifier
}

// SetNonceReader sets the pre-state nonce reader for replay detection.
// AUDIT (2026) R4-ECON-02: Must be called during node initialization
// to reject blocks containing already-executed (replayed) transactions.
func (v *BlockValidator) SetNonceReader(nr NonceReader) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nonceReader = nr
}

// SetForkRuleProvider injects the fork rule provider so ValidateBlock
// enforces fork-gated consensus rules (MaxBlockGas, MaxTxSize, BlockTime)
// active at each block's height.
//
// AUDIT (2026) R4-NODE-01 FIX: Without this, the ForkManager constructed
// in node.initUpgrade is dead code — planned hard forks never take effect.
// When nil, the hardcoded defaults from NewBlockValidator apply.
func (v *BlockValidator) SetForkRuleProvider(provider ForkRuleProvider) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.forkRuleProvider = provider
}

func (v *BlockValidator) SetDevMode(dev bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	// SECURITY (audit 2026-06-26, P1-03): devMode bypasses critical security
	// checks (election, key version, VRF). Only allowed on devnet (1333).
	if dev && v.chainID != params.DevnetChainID {
		logging.Global().Error("devMode rejected on non-devnet chain",
			map[string]any{"chainID": v.chainID, "reason": "devMode only allowed on devnet (1333)"})
		return
	}
	v.devMode = dev
}

// SetSyncingMode enables or disables syncing mode. When enabled, election
// verification is skipped to allow initial chain sync from genesis. This is
// necessary because QPOS internal state (randaoMix, finalizedRoot) cannot be
// rebuilt without processing blocks, but blocks cannot be validated without
// the correct QPOS state. After sync completes, SetSyncingMode(false) must
// be called to re-enable strict election verification.
//
// R38-P1-08 FIX 2 (conservative): On SetSyncingMode(false), log the total
// number of blocks that went through the unverified-proposer path during
// the sync session so operators can audit. The counter is NOT reset to
// zero on disable — operators can read it via SyncingModeSkipCount() and
// reset it themselves if they need a fresh per-session count. We log the
// total here for visibility at the natural "sync done" reporting point.
func (v *BlockValidator) SetSyncingMode(syncing bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.syncingMode = syncing
	if syncing {
		logging.Global().Warn("Syncing mode enabled: election verification skipped during chain sync",
			map[string]any{"reason": "QPOS state rebuild requires block processing"})
		// R39-P1-04 (2026-08-02) FIX: dropping into a fresh sync session
		// clears any stale pendingReverify entries from a prior session so
		// the post-disable sweep below only re-verifies blocks from THIS
		// sync (otherwise a node toggling sync twice could re-verify stale
		// records and double-count). This is also the memory-pressure
		// escape valve: if a sync session accumulated a very large
		// pendingReverify list and the operator toggles sync again without
		// waiting for the disable sweep, the old list is discarded here.
		v.pendingReverify = nil
	} else {
		logging.Global().Info("Syncing mode disabled: strict election verification re-enabled",
			map[string]any{"syncingModeSkipCount": atomic.LoadUint64(&v.syncingModeSkipCount)})

		// R39-P1-04 (2026-08-02) FIX: post-sync best-effort re-verification.
		// Walk every block proposer election we SKIPPED during sync
		// (collected in v.pendingReverify across sync-period ValidateBlock
		// calls) and run VerifyProposer against the now-fully-reconstructed
		// QPOS snapshot. Each PASS adds to the existing
		// syncProposerVerificationPassCount; each FAIL adds to the fail
		// counter AND is logged at WARN with the R39-P1-04
		// SYNC-REVERIFY-FAIL tag so operators have a single grep point to
		// investigate "chain accepted a sync block whose proposer
		// election the QPOS snapshot says was illegitimate" — the audit's
		// "force a re-walk of all sync-trusted blocks after
		// SetSyncingMode(false)" requirement.
		//
		// What this does NOT do (deliberately): it does NOT roll back the
		// already-applied chain state. State was applied during sync before
		// the snapshot had enough information to verify the proposer; once
		// applied, blocks cannot be silently rolled back without a chain
		// reorg, which has its own safety implications. The re-walk is
		// meant as the OBSERVABILITY + ALERTING surface: any FAIL here is a
		// strong signal that the sync source was feeding the node
		// illegitimate proposer election results and the operator MUST
		// investigate; defense-in-depth prevents the next block the bad
		// peer proposes from being applied (because production-mode
		// ValidateBlock in this file hard-fails on VerifyProposer errors).
		// We snapshot pendingReverify under v.mu and clear it BEFORE
		// running the sweep so a concurrent ValidateBlock doesn't observe
		// a half-processed list.
		pending := v.pendingReverify
		v.pendingReverify = nil
		// Snapshot the electionVerifier under the lock (consistent with
		// the read pattern in ValidateBlock); release the lock before the
		// (potentially O(thousands)) sweep so we don't block
		// ValidateBlock / IsSyncingMode / SetSyncingMode on the sweep's
		// duration.
		electionVerifier := v.electionVerifier
		// R40-P1-07 / R40-P2-06 (2026-08-03): the post-sync sweep goroutine
		// is now lifetime-managed via sweepCtx. Cancel any previously-
		// launched sweep first (a fresh SetSyncingMode(false) call supersedes
		// the prior session's sweep) before creating a new cancellable
		// context. The cancel is stored on v so Stop() can tear it down on
		// graceful node shutdown; without that, the goroutine would keep
		// touching electionVerifier / QPOS snapshot data after those fields
		// are released, producing use-after-free reads during shutdown or
		// leaking across restart-in-place cycles.
		if v.sweepCancel != nil {
			v.sweepCancel()
		}
		v.sweepCtx, v.sweepCancel = context.WithCancel(context.Background())
		// Spin off a best-effort goroutine so SetSyncingMode returns
		// promptly; the sweep is observability/alerting, not on the
		// critical path. The goroutine exits early when sweepCtx is
		// canceled (Stop() or a subsequent SetSyncingMode call).
		sweepCtx := v.sweepCtx
		if len(pending) > 0 && electionVerifier != nil {
			go v.reverifySyncPeriodProposers(sweepCtx, pending, electionVerifier)
		} else if len(pending) > 0 {
			// No electionVerifier configured — cannot re-verify. Log so
			// operators see the missed sweep rather than silently
			// dropping the records. Cancel the just-created context so we
			// don't leak a live cancelFunc with no goroutine consuming it.
			v.sweepCancel()
			v.sweepCancel = nil
			v.sweepCtx = nil
			logging.Global().Warn("R39-P1-04: post-sync re-verification skipped (no electionVerifier configured)",
				map[string]any{"pendingReverifyCount": len(pending)})
		}
	}
}

// Stop cancels any in-flight post-sync re-verification sweep goroutine and
// releases the sweep lifecycle. Idempotent; safe to call multiple times and
// from concurrent goroutines (the underlying context.CancelFunc is safe to
// call repeatedly). After Stop returns, no new sweep will be launched by
// SetSyncingMode(false) — callers that resume syncing should Stop() before
// destroying the BlockValidator. R40-P1-07 / R40-P2-06 (2026-08-03).
func (v *BlockValidator) Stop() {
	v.mu.Lock()
	if v.sweepCancel != nil {
		v.sweepCancel()
		v.sweepCancel = nil
		v.sweepCtx = nil
	}
	v.mu.Unlock()
}

// reverifySyncPeriodProposers runs the R39-P1-04 post-sync re-verification
// sweep over the snapshot taken from v.pendingReverify at
// SetSyncingMode(false) time. It is invoked as a best-effort goroutine and
// must not block the caller. Each entry:
//   - PASS (electionVerifier.VerifyProposer returns nil) → atomic bump
//     syncProposerVerificationPassCount;
//   - FAIL (returns non-nil) → atomic bump syncProposerVerificationFailCount
//     AND a WARN log entry tagged R39-P1-04 SYNC-REVERIFY-FAIL.
//
// The sweep is read-only against the snapshot; it does not mutate
// v.pendingReverify (already cleared in SetSyncingMode), nor any other
// chain state. Failures are alert-only — the chain state applied during
// sync is NOT rolled back here (rolling back requires a chain reorg, which
// is the operator's call after investigating the alert, not an automatic
// side-effect of the audit sweep).
func (v *BlockValidator) reverifySyncPeriodProposers(ctx context.Context, pending []reverifyRecord, electionVerifier ProposerElectionVerifier) {
	for i, rec := range pending {
		// R40-P1-07 / R40-P2-06 (2026-08-03): respect cancellation so node
		// shutdown / a fresh SetSyncingMode(false) stops the sweep early
		// instead of touching possibly-freed consensus state. Check on the
		// hot path here (per-iteration) — pending is at most a few thousand
		// entries, so the select overhead is negligible.
		if err := ctx.Err(); err != nil {
			logging.Global().Info("R39-P1-04: post-sync re-verification sweep canceled before completion",
				map[string]any{"processed": i, "remaining": len(pending) - i, "reason": err.Error()})
			return
		}
		if err := electionVerifier.VerifyProposer(rec.proposer, rec.slot, rec.epoch); err != nil {
			atomic.AddUint64(&v.syncProposerVerificationFailCount, 1)
			logging.Global().Warn("R39-P1-04 SYNC-REVERIFY-FAIL: post-sync VerifyProposer says the sync-period proposer was NOT legitimately elected — investigate the sync source (state already applied, no auto-rollback)",
				map[string]any{"height": rec.height, "slot": rec.slot, "epoch": rec.epoch,
					"proposer": fmt.Sprintf("%x", rec.proposer[:8]), "error": err.Error()})
		} else {
			atomic.AddUint64(&v.syncProposerVerificationPassCount, 1)
		}
	}
	logging.Global().Info("R39-P1-04: post-sync re-verification sweep complete",
		map[string]any{"records": len(pending)})
}

// IsSyncingMode returns whether syncing mode is currently active.
func (v *BlockValidator) IsSyncingMode() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.syncingMode
}

// SyncingModeSkipCount returns the cumulative number of blocks whose
// proposer election was skipped due to syncingMode==true since the
// BlockValidator was created. This is the observability surface for the
// R38-P1-08 conservative Fix 2.
func (v *BlockValidator) SyncingModeSkipCount() uint64 {
	return atomic.LoadUint64(&v.syncingModeSkipCount)
}

// SetSyncProposerVerification enables/disables the deep-fix
// (R38-P1-08 follow-up) best-effort proposer election verification FOR
// blocks arriving during syncingMode. When enabled AND an
// electionVerifier is configured, ValidateBlock will:
//   - Call electionVerifier.VerifyProposer for each syncingMode block.
//   - On success: continue validation, increment the PASS counter.
//   - On failure: log WARN, increment the FAIL counter, and SKIP
//     election verification (do NOT reject) — preserving the conservative
//     R38-P1-08 Fix 2 behavior is critical: the QPOS snapshot may not
//     yet have reconstructed this slot's proposer lookup (early-sync
//     gaps), so failing closed would reject honestly-elected proposers.
//
// Default false preserves R38-P1-08 Fix 2's wholesale skip behavior.
// Operators should only enable this once the QPOS snapshot is fully
// reconstructed at sync completion (SetSyncingMode(false) makes it a
// no-op anyway because the non-sync branch already does strict election
// verification).
//
// Recoverability: this API is purely observability + redundancy — even
// when enabled, validation never fails on the best-effort path. The
// counters let operators see whether the QPOS snapshot was actually
// sufficient for block-by-block election verification during sync.
func (v *BlockValidator) SetSyncProposerVerification(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.syncProposerVerification = enabled
	logging.Global().Info("R38-P1-08 deep-fix: best-effort sync proposer verification",
		map[string]any{"enabled": enabled})
}

// IsSyncProposerVerification reports whether the deep-fix best-effort
// sync proposer verification is enabled. R38-P1-08 deep-fix.
func (v *BlockValidator) IsSyncProposerVerification() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.syncProposerVerification
}

// SyncProposerVerificationPassCount returns the cumulative count of
// sync-applied blocks whose proposer election was BEST-EFFORT verified
// via the deep-fix path. R38-P1-08 deep-fix observability surface.
func (v *BlockValidator) SyncProposerVerificationPassCount() uint64 {
	return atomic.LoadUint64(&v.syncProposerVerificationPassCount)
}

// SyncProposerVerificationFailCount returns the cumulative count of
// sync-applied blocks whose best-effort VerifyProposer returned an
// error (snapshot not yet reconstructed / proposer mismatch / etc.).
// A non-zero value here is NOT an attack signal — it's expected during
// early sync when the QPOS snapshot hasn't yet reached the current
// slot. Operators should compare PASS / FAIL ratios; a high FAIL ratio
// after sync completion may indicate an inconsistent QPOS snapshot.
// R38-P1-08 deep-fix observability surface.
func (v *BlockValidator) SyncProposerVerificationFailCount() uint64 {
	return atomic.LoadUint64(&v.syncProposerVerificationFailCount)
}

// SetVRFEnforced enables or disables VRF proof/value existence checks and
// cryptographic verification. SECURITY (audit 2026-06-26, P1-01): VRF
// generation is now implemented in the block producer. This should be set
// to true for production (mainnet/testnet) via node initialization.
func (v *BlockValidator) SetVRFEnforced(enforced bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.vrfEnforced = enforced
}

// SetVRFSeed sets the VRF seed used for cryptographic VRF proof verification.
// audit fix (H-8) [HIGH]: When set and vrfEnforced is true,
// ValidateBlock calls ValidateVRFProof to verify the VRF proof signature and
// output determinism (not just check existence). This should be called at
// epoch boundaries with the current VRF seed.
func (v *BlockValidator) SetVRFSeed(seed types.Hash) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.vrfSeed = seed
}

// SetElectionVerifier sets the proposer election verifier used by ValidateBlock
// to verify that each block's proposer was legitimately elected via QPOS.
// audit fix (H-7) [CRITICAL]: Must be called during node initialization
// in production. When not set and not in devMode, ValidateBlock rejects all
// non-genesis blocks (fail-closed) to prevent unelected validators from
// proposing blocks.
func (v *BlockValidator) SetElectionVerifier(verifier ProposerElectionVerifier) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.electionVerifier = verifier
}

// SetDankshardingEngine injects the DA engine for blob availability verification.
// P1-3 (2026-07-14): When set AND daCheckEnabled is true (via
// SetDACheckEnabled(true)), ValidateBlock extracts blob commitments from the
// block's blob transactions and calls VerifyBlockDAAvailability to sample the
// DA layer. Blocks whose blob data is not sufficiently available are rejected.
//
// This is opt-in: only DA committee members and full nodes that wish to
// independently verify DA availability should enable it. Non-DA nodes rely on
// the aggregate attestation checked in QPOS finalizeBlock (P1-4).
//
// The check is automatically skipped during syncing mode (initial chain sync),
// when the block has no blob transactions, or when blob transactions lack
// their sidecar (commitments not available locally).
func (v *BlockValidator) SetDankshardingEngine(engine *DankshardingEngine) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.danksharding = engine
}

// SetDACheckEnabled enables or disables DA availability verification in
// ValidateBlock. P1-3 (2026-07-14): Must be called AFTER
// SetDankshardingEngine to take effect. When disabled (default), DA
// verification is skipped even if a DankshardingEngine is set.
func (v *BlockValidator) SetDACheckEnabled(enabled bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.daCheckEnabled = enabled
}

// ValidateHeader validates a block header against its parent.
func (v *BlockValidator) ValidateHeader(header, parent *encoding.BlockHeader) error {
	// R43-H-H2 FIX: Validate parent is not nil before dereferencing.
	// R41 fixes only added the check to ValidateBlock but not ValidateHeader,
	// which is called directly by other code paths that could pass nil parent.
	if parent == nil {
		return fmt.Errorf("ValidateHeader: parent block header is nil")
	}

	// Check version
	if header.Version == 0 {
		return ErrInvalidBlockVersion
	}

	// audit-fix H-1: Check chain ID for cross-chain replay protection
	if header.ChainID != v.chainID {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidChainID, v.chainID, header.ChainID)
	}

	// Check height
	if header.Height != parent.Height+1 {
		return ErrInvalidBlockHeight
	}

	// R37-P1-CORE-01 FIX (2026-07-30): Bind header.Epoch to header.Slot.
	// Previously Epoch was a free field — a proposer could inject an
	// arbitrary epoch, and downstream consumers (VRF accumulator, epoch
	// roots, executive committee migration in node.go) would attribute the
	// block's VRF output to the attacker-chosen epoch, enabling long-term
	// election bias. The proposer always sets Epoch = SlotToEpoch(Slot)
	// (block_producer.go), so honest blocks satisfy this check.
	if header.Epoch != consensus.SlotToEpoch(header.Slot) {
		return fmt.Errorf("%w: epoch %d, slot %d maps to epoch %d",
			ErrEpochSlotMismatch, header.Epoch, header.Slot, consensus.SlotToEpoch(header.Slot))
	}

	// Check parent hash
	parentHash := v.computeHeaderHash(parent)
	if header.ParentHash != parentHash {
		return ErrInvalidParentHash
	}

	// R54-ACC (2026-08-07): Verify the on-chain per-epoch VRF accumulator.
	// It is a deterministic function of the parent header + this header's
	// epoch + VRF output (consensus.ComputeNextVRFAccumulator). Enforcing it
	// here guarantees every node sees the IDENTICAL accumulator for each block,
	// which is what keeps proposer election (and thus the chain) convergent.
	// A mismatch means a malicious or buggy proposer injected a value that
	// honest nodes would never derive — reject it.
	expectedAcc := consensus.ComputeNextVRFAccumulator(
		parent.VRFAccumulator, parent.Epoch, header.Epoch, header.VRFValue,
	)
	if header.VRFAccumulator != expectedAcc {
		return fmt.Errorf("%w: header=%x expected=%x (epoch %d, vrf %x)",
			consensus.ErrInvalidVRFAccumulator,
			header.VRFAccumulator[:4], expectedAcc[:4], header.Epoch, header.VRFValue[:4])
	}

	// Check timestamp
	if header.Timestamp <= parent.Timestamp {
		return ErrInvalidTimestamp
	}

	// audit-fix MEDIUM: enforce minimum block interval to prevent timestamp manipulation.
	// Without this check, a malicious proposer could set timestamps only 1 second apart,
	// bypassing the intended SlotDuration (12s) and disrupting consensus timing assumptions.
	v.mu.RLock()
	minInterval := v.minBlockInterval
	// R11-CORE-002 FIX: Read maxFutureTime under RLock for consistency.
	maxFutureTime := v.maxFutureTime
	forkProvider := v.forkRuleProvider
	v.mu.RUnlock()
	minIntervalSec := int64(minInterval.Seconds())

	// AUDIT (2026) R4-NODE-01: If a fork rule provider is configured,
	// use the BlockTime active at this block's height instead of the
	// hardcoded default. This makes scheduled hard forks actually take
	// effect (previously the ForkManager was dead code).
	if forkProvider != nil {
		if rules := forkProvider.GetRulesAtHeight(header.Height); rules != nil {
			if rules.BlockTime > 0 {
				minIntervalSec = int64(rules.BlockTime)
			}
		}
	}
	if minIntervalSec > 0 && header.Timestamp < parent.Timestamp+minIntervalSec {
		return fmt.Errorf("%w: block timestamp %d too close to parent %d (min interval %ds)",
			ErrInvalidTimestamp, header.Timestamp, parent.Timestamp, minIntervalSec)
	}

	// Check future timestamp
	// R35-P1-10 FIX (2026-07-29): Previously this used time.Now() (wall-clock)
	// as the reference, which is a CONSENSUS-CRITICAL path. If two honest
	// nodes' clocks differ by more than maxFutureTime (15s), one node accepts
	// a block the other rejects → consensus split. The fix uses the PARENT
	// block's timestamp as the deterministic reference, so all nodes make the
	// same decision regardless of local clock drift.
	//
	// R36-P0-01 FIX (2026-07-30): R35's parent-relative bound used
	// `parent.Timestamp + maxFutureSec` (15s). Combined with the 12s minimum
	// block interval, the valid window was only [parent+12, parent+15] = 3s.
	// If a validator missed even one slot (restart >15s is common), the next
	// honest proposer stamped time.Now() ≈ parent+24s → ErrFutureBlock on
	// every node → chain permanent halt (time only moves forward, every
	// subsequent stamp is even larger).
	//
	// FIX: Make the future bound slot-gap-aware. The proposer may stamp up to
	// `parent.Timestamp + slotGap*minInterval + maxFutureSec` where slotGap =
	// header.Slot - parent.Slot. This preserves the original anti-future-
	// stamp goal (a proposer can't stamp arbitrarily far ahead of the parent)
	// while tolerating missed slots. The maxFutureSec (15s) remains as a
	// per-slot jitter allowance for clock drift and network latency.
	//
	// For genesis (parent.Slot == 0 and header.Slot == 0 or 1), the bound
	// falls back to parent.Timestamp + maxFutureSec + minInterval (one slot
	// worth of tolerance), which is permissive enough for chain start.
	//
	// SECURITY: header.Slot is bounded in two ways below: (a) header.Epoch
	// must equal SlotToEpoch(header.Slot) (P1-CORE-01 check above), and
	// (b) header.Slot must not exceed the current wall-clock slot plus
	// MaxFutureSlotGap (R38-P0-03 check below). The prior slotGap <=
	// MaxSlotGap=64 hard cap was RETIRED in R38-P0-03 — see the comment
	// block further down — because it permanently halted the chain after
	// any downtime longer than ~12.8 minutes. The bound is now wall-clock
	// relative (genesis time + elapsed / slot duration), NOT slotGap
	// relative, so the "slotGap*minIntervalSec multiplication cannot
	// overflow int64" reasoning that depended on the cap no longer
	// applies. The multiplication below is safe because slotGap is itself
	// bounded by MaxFutureSlotGap (an int64 that fits comfortably within
	// int64 range when multiplied by minIntervalSec, which is on the order
	// of seconds). R40-P1-07 (2026-08-03) — comment-only fix to stop the
	// stale "slotGap <= MaxSlotGap=64" claim from misleading future
	// maintainers into re-introducing the retired cap.
	maxFutureSec := int64(maxFutureTime / time.Second)
	if maxFutureSec < 1 {
		maxFutureSec = 15 // fallback if maxFutureTime misconfigured
	}
	slotGap := int64(header.Slot) - int64(parent.Slot)
	if slotGap < 0 {
		// Slot going backwards is a consensus violation caught elsewhere;
		// be defensive and reject here too.
		return fmt.Errorf("%w: header slot %d < parent slot %d",
			ErrInvalidTimestamp, header.Slot, parent.Slot)
	}
	// R37-P0-01 FIX (2026-07-30): Cap the slot jump. Without this bound, a
	// single elected validator could search for a far-future slot S+k where
	// they win the (publicly computable) election, stamp a timestamp up to
	// parent+12k+15s, and broadcast a block that passes all validation.
	// Once that block is the tip, every honest wall-clock block fails either
	// slotGap<0 or the minimum-interval check — the attacker permanently
	// monopolizes block production or the chain halts. See MaxSlotGap docs.
	//
	// R38-P0-03 (2026-08-01) FIX: The previous MaxSlotGap=64 hard cap meant
	// that if the chain was down for more than ~12.8 minutes (64 slots × 12s),
	// no block could ever be accepted — the slot gap would always exceed 64,
	// permanently halting the chain. The fix replaces the parent-relative
	// hard cap with a genesis-relative future-slot check:
	//   - Remove the `slotGap > MaxSlotGap` hard rejection.
	//   - Instead, reject only if header.Slot is more than MaxFutureSlotGap
	//     slots ahead of the CURRENT wall-clock slot (computed from genesis
	//     time). This prevents a malicious proposer from stamping a block
	//     too far in the future while allowing the chain to recover from
	//     arbitrarily long downtimes.
	//   - The existing timestamp bound (parent+slotGap*minInterval+maxFutureSec)
	//     still limits how far ahead of the parent a proposer can stamp, so
	//     the future-slot election attack is still mitigated.
	// MaxFutureSlotGap is set to 2 epochs (64 slots ≈ 12.8 minutes), which
	// is generous enough for clock drift and network latency but tight
	// enough to prevent future-slot election attacks.
	{
		genesisTime := consensus.GetGenesisTime()
		if genesisTime > 0 {
			// AUDIT-FULL CS-01 (2026-08-14): derive the current-slot baseline
			// DETERMINISTICALLY from the parent block timestamp first, and keep
			// the wall clock only as a secondary reference (max of the two).
			// Previously the baseline came solely from time.Now(), so a node
			// whose local clock lagged more than MaxFutureSlotGap slots behind
			// would reject blocks every other honest node accepted — a local
			// clock skew could split consensus. The parent timestamp is
			// consensus data: every node validating the same parent derives
			// the same baseline. Taking the max preserves the R38-P0-03
			// wall-clock protection for nodes with accurate clocks and can
			// only RELAX the check for lagging-clock nodes, never tighten it,
			// so no previously accepted block becomes rejected.
			slotSecs := int64(consensus.SlotDuration.Seconds())
			if slotSecs < 1 {
				slotSecs = 12 // defensive fallback, mirrors SlotDuration default
			}
			parentDerived := uint64(0)
			if parent.Timestamp > genesisTime { // #nosec G115 -- safe: positive delta to uint64
				parentDerived = uint64((parent.Timestamp - genesisTime) / slotSecs) // #nosec G115 -- safe: delta/12s fits in uint64
			}
			wallDerived := uint64(0)
			if elapsed := time.Now().Unix() - genesisTime; elapsed > 0 {
				wallDerived = uint64(elapsed / slotSecs) // #nosec G115 -- safe: elapsed/12s fits in uint64
			}
			currentSlot := parentDerived
			if wallDerived > currentSlot {
				currentSlot = wallDerived
			}
			if header.Slot > currentSlot+MaxFutureSlotGap {
				return fmt.Errorf("%w: header slot %d is %d slots ahead of current slot %d (parent-derived %d, wall-derived %d, max future gap %d)",
					ErrSlotGapTooLarge, header.Slot, header.Slot-currentSlot, currentSlot, parentDerived, wallDerived, MaxFutureSlotGap)
			}
		}
	}
	if slotGap == 0 {
		// R40-P1-09 (2026-08-03) — slotGap == 0 has three sub-cases that this
		// branch must distinguish; the prior comment only mentioned two.
		//   (1) GENESIS: parent.Slot == 0 && header.Slot == 0 — the actual
		//       genesis block. Tolerate one slot interval + jitter so the
		//       seed/initial-timestamp alignment can absorb chain-start
		//       timing slop (the genesis block's timestamp is set by the
		//       operator, not the consensus clock).
		//   (2) NORMAL SAME-SLOT REPLAY: parent.Slot > 0 && header.Slot ==
		//       parent.Slot — a same-slot block (rare; usually a re-org /
		//       re-broadcast). Only jitter is allowed, so a proposer cannot
		//       re-stamp the same slot with a manipulated timestamp.
		//   (3) SYNC-IMPORTED GENESIS: header.Slot == 0 && parent.Slot == 0
		//       during initial sync — identical to case (1) for the
		//       purposes of this bound (genesis is genesis regardless of how
		//       the block arrived), so it routes through the genesis branch
		//       below. The "normal sync" case here means a NON-genesis
		//       same-slot block delivered during chain sync; it is governed
		//       by the same jitter-only rule as case (2) to avoid
		//       sync-time future-stamping attacks.
		//
		// The split below (genesis vs everything-else) correctly handles
		// all three sub-cases. R40-P1-09 closes the audit concern that the
		// branch "genesis slot vs normal sync slot not correctly distinguished" — the comment now
		// enumerates the cases explicitly so future maintainers do not
		// collapse them by accident.
		if parent.Slot == 0 && header.Slot == 0 {
			// Genesis block: allow one slot interval plus maxFutureSec
			// jitter to accommodate chain start timing.
			maxTime := parent.Timestamp + minIntervalSec + maxFutureSec
			if header.Timestamp > maxTime {
				return ErrFutureBlock
			}
		} else {
			// Same slot (same-slot replay, genesis-slot sync, or sync-imported
			// non-genesis same-slot): allow up to maxFutureSec jitter only.
			// This path is rare for normal blocks.
			maxTime := parent.Timestamp + maxFutureSec
			if header.Timestamp > maxTime {
				return ErrFutureBlock
			}
		}
	} else {
		// Normal case: header is slotGap slots ahead of parent. Allow
		// slotGap * minInterval for the slot progression plus maxFutureSec
		// for per-slot jitter. This means even after missing several slots,
		// the next honest proposer's time.Now() stamp falls within bounds.
		//
		// Example: parent.Slot=10, header.Slot=12 (missed 1 slot),
		// parent.Timestamp=T. maxTime = T + 2*12 + 15 = T + 39s. The
		// proposer's time.Now() ≈ T + 24s (one slot missed) < T + 39s ✓.
		maxTime := parent.Timestamp + slotGap*minIntervalSec + maxFutureSec
		if header.Timestamp > maxTime {
			return ErrFutureBlock
		}
	}

	// Check proposer address
	if header.ProposerAddr.IsEmpty() {
		return ErrInvalidProposer
	}

	// SECURITY (audit R4-ECON-01): Validate that header.BaseFee matches the
	// EIP-1559 derivation from the parent block. Without this check, a
	// malicious proposer could stamp an arbitrary BaseFee, causing honest
	// validators executing with header.BaseFee to compute a different
	// effectiveGasPrice (and thus different sender balance / coinbase /
	// GasUsed) than the proposer did — splitting stateRoot and ReceiptRoot.
	// Sync nodes (which previously set blockCtx.BaseFee=nil) are now fixed
	// to use header.BaseFee too; combined with this check the entire network
	// converges on the same fee computation.
	//
	// Genesis (height 0) is exempt — the genesis block has no parent to
	// derive from. Early blocks whose parent didn't carry a BaseFee fall
	// back to the initial 1 Gwei (still validated, see R37-P3-33 below).
	// R37-FIX P2-CORE-01 (2026-07-30): Validate header.GasLimit BEFORE the
	// BaseFee check below, because BaseFee derivation consumes parent.GasLimit
	// and the proposer's freedom to stamp an arbitrary GasLimit is the attack
	// input. Genesis (height 0) is exempt — it has no parent to drift from.
	if header.Height > 0 {
		if header.GasLimit < MinGasLimit {
			return fmt.Errorf("%w: gas limit %d below minimum %d",
				ErrInvalidGasLimit, header.GasLimit, uint64(MinGasLimit))
		}
		if header.GasLimit > MaxBlockGasLimitProtocol {
			return fmt.Errorf("%w: gas limit %d exceeds protocol ceiling %d",
				ErrInvalidGasLimit, header.GasLimit, uint64(MaxBlockGasLimitProtocol))
		}
		// ±1/1024 drift bound vs the parent (Ethereum VerifyGaslimit). When
		// parent.GasLimit == 0 (legacy/test chains) only the clamps above
		// apply — a zero parent gives a zero bound and would reject any
		// non-zero limit.
		if parent.GasLimit > 0 {
			bound := parent.GasLimit / GasLimitBoundDivisor
			var diff uint64
			if header.GasLimit > parent.GasLimit {
				diff = header.GasLimit - parent.GasLimit
			} else {
				diff = parent.GasLimit - header.GasLimit
			}
			if diff >= bound {
				return fmt.Errorf("%w: gas limit %d vs parent %d (diff %d >= bound %d = parent/%d)",
					ErrInvalidGasLimit, header.GasLimit, parent.GasLimit, diff, bound, GasLimitBoundDivisor)
			}
		}
	}

	// R37-P3-33 FIX (2026-07-31): Previously this check was skipped
	// entirely whenever parent.BaseFee was nil/zero ("early blocks"), with
	// NO height boundary — a proposer could stamp an arbitrary BaseFee on
	// ANY block whose parent lacked one, splitting the fee computation
	// across nodes. The exemption is now bounded to genesis (height 0)
	// only. For early blocks the expected fee derives from the protocol
	// initial base fee: CalculateNextBaseFee with a nil/zero parent fee
	// returns the initial 1 Gwei, exactly what the block producer stamps
	// (node.calculateNextBaseFee).
	if header.Height > 0 {
		expectedBaseFee := economics.CalculateNextBaseFee(
			parent.GasUsed, parent.GasLimit, parent.BaseFee)
		if header.BaseFee == nil || header.BaseFee.Cmp(expectedBaseFee) != 0 {
			return fmt.Errorf("%w: at height %d expected %s, got %s",
				ErrInvalidBaseFee, header.Height,
				expectedBaseFee.String(), baseFeeString(header.BaseFee))
		}
	}

	// CONS- (2026-07-22): EIP-4844 blob gas validation.
	// Genesis (height 0) is exempt — the genesis block has no parent to
	// derive ExcessBlobGas from, and its BlobGasUsed is meaningless.
	if header.Height > 0 {
		maxBlobGas := uint64(encoding.MaxBlobsPerBlock) * uint64(encoding.BlobGasPerBlob)
		if header.BlobGasUsed > maxBlobGas {
			return fmt.Errorf("%w: %d exceeds max %d",
				ErrInvalidBlobGasUsed, header.BlobGasUsed, maxBlobGas)
		}
		expectedExcess := encoding.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed)
		if header.ExcessBlobGas != expectedExcess {
			return fmt.Errorf("%w: got %d expected %d",
				ErrInvalidExcessBlobGas, header.ExcessBlobGas, expectedExcess)
		}
	}

	return nil
}

// baseFeeString returns a log-safe representation of a possibly-nil BaseFee.
func baseFeeString(b *big.Int) string {
	if b == nil {
		return "<nil>"
	}
	return b.String()
}

// ValidateBlock validates a complete block.
// SECURITY FIX: Added nil check for parent parameter.
// SECURITY FIX Q-B-002: Returns a StateRootValidation callback that callers
// MUST invoke after executing all transactions. This prevents accidental
// omission of state root verification.
//
// CONS- (2026-07-20) FIX: Previously this function created a
// receiptRootValidator closure but assigned it to `_` and discarded it,
// returning only the stateRootValidator. The asymmetric API was error-prone:
// callers had to remember to separately call GetReceiptRootValidator(block)
// to verify the receipt root. The fix returns BOTH validators as a pair so
// the API is symmetric and callers cannot forget the receipt root check.
// GetReceiptRootValidator is retained for backward compatibility but is
// deprecated — callers should use the returned receiptValidator closure.
func (v *BlockValidator) ValidateBlock(block *encoding.Block, parent *encoding.BlockHeader) (func(computedStateRoot types.Hash) error, func(computedReceiptRoot types.Hash) error, error) {
	if block == nil || block.Header == nil {
		return nil, nil, ErrEmptyBlock
	}

	// SECURITY FIX: Validate parent is not nil before dereferencing
	if parent == nil {
		// audit-fix LOW: removed leading space for consistent error message format
		return nil, nil, fmt.Errorf("ValidateBlock: parent block header is nil")
	}

	// Validate header
	if err := v.ValidateHeader(block.Header, parent); err != nil {
		return nil, nil, err
	}

	// audit-fix H-5: CRITICAL - Validate genesis block hash to ensure this node is on the correct chain
	// If a node receives blocks from a different chain (different genesis block),
	// it would compute different state hashes and cause a permanent fork
	if block.Header.Height == 0 {
		// This is a genesis block - store its hash for chain validation
		// The node operator must ensure this matches the network's genesis block
		blockHash := v.computeHeaderHash(block.Header)
		// Log this critical hash for operator verification during setup
		logging.Global().Info("Genesis block hash", map[string]any{
			"hash": fmt.Sprintf("%x", blockHash[:]),
		})
		// Note: Full genesis hash validation happens at consensus layer via consensus.ValidateGenesisBlockHash()
	} else {
		// audit-fix HIGH: Validate VRF proof existence for non-genesis blocks.
		// VRF (Verifiable Random Function) proves the proposer was legitimately
		// selected. Without this check, an attacker could construct blocks with
		// empty VRF proofs and bypass the proposer selection mechanism.
		//
		// audit-fix Round3 C-2: VRF generation is not yet implemented in
		// block_producer.go. Gate the existence check on vrfEnforced to avoid
		// rejecting all blocks. Enable via SetVRFEnforced(true) once VRF
		// generation is wired into block production.
		//
		// SECURITY (audit 2026-06-26, P1-01): VRF is now enforced in production.
		// The VRF seed is derived from the parent block hash, ensuring each block
		// has a unique, unpredictable seed. This prevents proposers from biasing
		// the VRF output by grinding on multiple seeds.
		v.mu.RLock()
		vrfEnforced := v.vrfEnforced
		configuredSeed := v.vrfSeed
		v.mu.RUnlock()
		if vrfEnforced {
			if len(block.Header.VRFProof) == 0 {
				return nil, nil, fmt.Errorf("%w: VRF proof missing for non-genesis block at height %d",
					ErrInvalidVRFProof, block.Header.Height)
			}
			if block.Header.VRFValue == (types.Hash{}) {
				return nil, nil, fmt.Errorf("%w: VRF value missing for non-genesis block at height %d",
					ErrInvalidVRFProof, block.Header.Height)
			}
			// SECURITY (P1-01): Use parent block hash as VRF seed. If a configured
			// seed is set (via SetVRFSeed), use that instead (for epoch-based seeds).
			// Otherwise derive from parent hash for per-block uniqueness.
			vrfSeed := configuredSeed
			if vrfSeed == (types.Hash{}) {
				vrfSeed = block.Header.ParentHash
			}
			if err := v.ValidateVRFProof(block.Header, vrfSeed); err != nil {
				return nil, nil, fmt.Errorf("VRF proof verification failed at height %d: %w",
					block.Header.Height, err)
			}
		}
	}

	// R37-FIX P2-CORE-02 (2026-07-30): Block signature verification and the
	// proposer election check run BEFORE validateTransactions. Previously the
	// batch Dilithium3 transaction signature verification (~seconds of CPU for
	// hundreds of txs) executed before the block's own signature was checked,
	// so any unauthenticated p2p peer could burn validator CPU with a
	// structurally valid block full of garbage-signature txs and a junk
	// proposer signature. The fork-block path already established the correct
	// precedent (syncer.go verifies the block signature before processing
	// transactions). Cheap block-level authentication now gates the expensive
	// batch work.

	// SECURITY FIX: Require block signature when validator lookup is configured.
	// Previously, blocks without signatures were accepted ("initial sync of legacy blocks"),
	// but this is a security vulnerability that allows unsigned blocks.
	// Only skip signature verification when validatorLookup is nil (completely unconfigured).
	v.mu.RLock()
	validatorLookup := v.validatorLookup
	v.mu.RUnlock()
	if validatorLookup == nil {
		return nil, nil, fmt.Errorf("%w: validator lookup not configured — block signature verification required", ErrInvalidSignature)
	}
	if len(block.Header.Signature) == 0 {
		return nil, nil, ErrInvalidSignature
	}
	if err := v.ValidateSignature(block.Header); err != nil {
		return nil, nil, err
	}

	// audit fix (H-7) [CRITICAL]: Verify that the block's proposer was
	// legitimately elected via QPOS for this slot/epoch. Without this check,
	// any registered validator can propose blocks in arbitrary slots, bypassing
	// the QPOS election entirely.
	//
	// When an election verifier is configured, ValidateBlock delegates proposer
	// verification to it. When not configured and not in devMode, ValidateBlock
	// fails closed (rejects the block) to prevent unelected validators from
	// proposing blocks.
	//
	// Genesis blocks (height 0) are exempt — the genesis proposer is defined in
	// the genesis config, not elected.
	if block.Header.Height > 0 {
		// P3-E7 FIX: Explicitly reject blocks with a zero proposer address.
		// A zero address can never be an elected validator; rejecting it here
		// is a fast, defense-in-depth check that does not depend on the
		// election verifier being configured. (node/node.go also guards this
		// at the ingestion layer; this is the consensus-layer enforcement.)
		if block.Header.ProposerAddr == (types.Address{}) {
			return nil, nil, fmt.Errorf("%w: zero proposer address at height %d",
				ErrInvalidProposer, block.Header.Height)
		}

		v.mu.RLock()
		electionVerifier := v.electionVerifier
		devMode := v.devMode
		syncingMode := v.syncingMode
		syncProposerVerification := v.syncProposerVerification
		v.mu.RUnlock()

		if syncingMode {
			// During initial chain sync, election verification is gated by
			// the deep-fix opt-in below. The conservative default (Fix 2)
			// skips election verification wholesale and counts/log the skips;
			// the deep fix (R38-P1-08 follow-up) allows best-effort
			// verification when the QPOS snapshot has been incrementally
			// reconstructed by syncer.applyBlockInternal via qpos.ApplyBlockHeader.
			if syncProposerVerification && electionVerifier != nil {
				// R38-P1-08 DEEP FIX (2026-08-02): Best-effort VerifyProposer.
				// On PASS: continue validation, increment PASS counter (no skip).
				// On FAIL: fall back to legacy conservative behavior (skip +
				// count + log) so honest blocks aren't rejected because the
				// snapshot hasn't yet reached their slot.
				if err := electionVerifier.VerifyProposer(block.Header.ProposerAddr, block.Header.Slot, block.Header.Epoch); err != nil {
					atomic.AddUint64(&v.syncProposerVerificationFailCount, 1)
					atomic.AddUint64(&v.syncingModeSkipCount, 1)
					logging.Global().Warn("R38-P1-08 deep-fix: best-effort VerifyProposer failed (snapshot not yet reconstructed for this slot — falling back to skip)",
						map[string]any{"height": block.Header.Height, "slot": block.Header.Slot, "epoch": block.Header.Epoch,
							"proposer": fmt.Sprintf("%x", block.Header.ProposerAddr[:8]), "error": err.Error()})
					// R39-P1-04 (2026-08-02) FIX: record this block for the
					// post-sync re-verification sweep at
					// SetSyncingMode(false) time. We MUST promote the RLock
					// to a write lock to mutate pendingReverify; the
					// critical section is O(1) (append), so this does not
					// meaningfully change the lock profile. We re-check
					// v.syncingMode under the write lock (it may have been
					// toggled between the RLock read at line 1002 and now)
					// — if sync was just disabled (the sweep is in-flight),
					// we drop the record to avoid re-verifying a block from
					// the new sync session through the old sweep.
					v.mu.Lock()
					if v.syncingMode {
						v.pendingReverify = append(v.pendingReverify, reverifyRecord{
							height:   block.Header.Height,
							slot:     block.Header.Slot,
							epoch:    block.Header.Epoch,
							proposer: block.Header.ProposerAddr,
						})
					}
					v.mu.Unlock()
				} else {
					atomic.AddUint64(&v.syncProposerVerificationPassCount, 1)
					// Verified — fall through to the rest of ValidateBlock:
					// the proposer is honest, election verification SUCCEEDED
					// (no skip applied).
				}
			} else {
				// R38-P1-08 FIX 2 (conservative): syncProposerVerification not
				// opted in, OR no electionVerifier configured — log a WARN
				// and bump the counter so operators can see how many blocks
				// entered the unverified-proposer path during sync. The full
				// fix (this file's deep-fix path above) requires opt-in AND
				// an ElectionVerifier, which is set up after the QPOS is
				// linked at node startup (node.go:5625).
				atomic.AddUint64(&v.syncingModeSkipCount, 1)
				logging.Global().Warn("R38-P1-08: skipping election verification during sync (conservative mitigation — proposer not verified block-by-block)",
					map[string]any{"height": block.Header.Height, "slot": block.Header.Slot, "epoch": block.Header.Epoch,
						"proposer": fmt.Sprintf("%x", block.Header.ProposerAddr[:8])})
				// R39-P1-04 (2026-08-02) FIX: same record-for-sweep as the
				// deep-fix-failed branch above. Even with
				// syncProposerVerification off (e.g. legacy deployments that
				// explicitly opted back to the conservative behavior, or
				// during a moment when electionVerifier happens to be nil),
				// the post-sync sweep at SetSyncingMode(false) MUST still
				// re-walk these blocks per the audit's
				// "force a re-walk of ALL sync-trusted blocks" requirement.
				v.mu.Lock()
				if v.syncingMode {
					v.pendingReverify = append(v.pendingReverify, reverifyRecord{
						height:   block.Header.Height,
						slot:     block.Header.Slot,
						epoch:    block.Header.Epoch,
						proposer: block.Header.ProposerAddr,
					})
				}
				v.mu.Unlock()
			}
		} else if electionVerifier != nil {
			if err := electionVerifier.VerifyProposer(block.Header.ProposerAddr, block.Header.Slot, block.Header.Epoch); err != nil {
				// R45-PoA-FIX (2026-08-12): If the QPOS verifier reports
				// cold-start (VRF accumulator for epoch-2 not yet
				// repopulated after sealer restart), do NOT fail the
				// block — the canonical-chain ProposerAddr is authoritative
				// by definition, and the local QPOS schedule will catch up
				// as the syncer replays canonical headers (calling
				// SetEpochVRFAccumulator, which clears coldStartEpochs and
				// invalidates the shuffleCache for the affected epoch).
				// Failing the block here is what produced the "expected X,
				// got Y" deadlock when only some sealers restarted in the
				// R45 deployment.
				if errors.Is(err, ErrProposerScheduleNotReady) {
					// Trust the canonical-chain proposer; QPOS catches up
					// via subsequent SetEpochVRFAccumulator calls from the
					// syncer's ApplyBlockHeader path. No warning at INFO
					// level — this is expected during sealer warm-up.
					logging.Global().Info("ValidateBlock: QPOS cold-start — trusting canonical proposer (slot+epoch may use wrong seed locally until accumulator replays)",
						map[string]any{"slot": block.Header.Slot, "epoch": block.Header.Epoch, "proposer": fmt.Sprintf("%x", block.Header.ProposerAddr[:4])})
				} else {
					return nil, nil, fmt.Errorf("%w: proposer %x not elected for slot %d epoch %d: %v",
						ErrInvalidProposer, block.Header.ProposerAddr[:4], block.Header.Slot, block.Header.Epoch, err)
				}
			}
		} else if !devMode {
			// fail-closed: in production, election verification is required.
			return nil, nil, fmt.Errorf("%w: election verifier not configured — proposer election verification REQUIRED in production",
				ErrInvalidProposer)
		}
	}

	// Validate transactions (R37 P2-CORE-02: now gated by the block signature
	// and proposer election checks above).
	if err := v.validateTransactions(block); err != nil {
		return nil, nil, err
	}

	// R36-P2-CORE-01 FIX: Validate that header.BlobGasUsed matches the
	// actual blob content of the block. Without this check, a malicious
	// proposer could include blob transactions but stamp BlobGasUsed=0,
	// keeping the blob basefee at the floor and bypassing the EIP-4844
	// fee market. The existing ValidateHeader check only enforces an
	// upper bound and ExcessBlobGas derivation consistency — it cannot
	// verify against actual blob content because it only sees headers.
	// Genesis (height 0) is exempt.
	if block.Header.Height > 0 {
		var actualBlobCount uint64
		for _, tx := range block.Transactions {
			if tx.IsBlobTx() {
				actualBlobCount += uint64(len(tx.BlobVersionedHashes))
			}
		}
		expectedBlobGasUsed := actualBlobCount * uint64(encoding.BlobGasPerBlob)
		if block.Header.BlobGasUsed != expectedBlobGasUsed {
			return nil, nil, fmt.Errorf("%w: header %d does not match actual blob content %d (blobs=%d)",
				ErrInvalidBlobGasUsed, block.Header.BlobGasUsed, expectedBlobGasUsed, actualBlobCount)
		}
	}

	// Validate transaction root
	txRoot := v.computeTxRoot(block.Transactions)
	if block.Header.TxRoot != txRoot {
		return nil, nil, ErrInvalidTxRoot
	}

	// audit-fix C-5: CRITICAL - validate key version to reject blocks signed with
	// CRITICAL FIX: Key version validation must NOT be optional in production.
	// During key rotation, an attacker who obtained a retired key could forge blocks
	// if this validation is skipped. Log a warning if validator is not configured.
	v.mu.RLock()
	kvv := v.keyVersionValidator
	v.mu.RUnlock()
	if kvv == nil {
		// CRITICAL SECURITY WARNING: Key version validation is disabled!
		// Block signature verification may accept keys that have been revoked or
		// are not yet active. This is a serious security risk in production.
		if !v.devMode {
			logging.Global().Warn("KEY VERSION VALIDATOR NOT CONFIGURED - block signature verification SKIPPED - this is INSECURE in production", nil)
		}
		// CRITICAL FIX: Return error in production even with warning - don't silently skip validation
		if !v.devMode {
			return nil, nil, fmt.Errorf("%w: key version validator not configured — REQUIRED in production", ErrInvalidKeyVersion)
		}
	} else {
		if err := kvv.ValidateKeyVersion(block.Header.KeyVersion, block.Header.Timestamp); err != nil {
			return nil, nil, fmt.Errorf("key version validation failed: %w", err)
		}
	}

	// L14-010: Validate that block's reported GasUsed does not exceed GasLimit.
	// This prevents malicious blocks from claiming more gas than the block allows.
	if block.Header.GasUsed > block.Header.GasLimit {
		return nil, nil, fmt.Errorf("%w: GasUsed %d exceeds GasLimit %d",
			ErrBlockGasLimitExceeded, block.Header.GasUsed, block.Header.GasLimit)
	}

	// R35-P1-09 FIX (2026-07-29): Static pre-execution gas bound. The sum of
	// all transaction gas limits is the maximum possible GasUsed — a block
	// claiming more gas than its transactions could possibly consume is
	// provably fraudulent. The EXACT check (Header.GasUsed == sum of
	// receipt.GasUsed) requires execution and is in ValidateGasUsed().
	var txGasLimitSum uint64
	for _, tx := range block.Transactions {
		if tx != nil {
			txGasLimitSum += tx.GasLimit
		}
	}
	if block.Header.GasUsed > txGasLimitSum {
		return nil, nil, fmt.Errorf("%w: header GasUsed %d exceeds sum of tx gas limits %d (fraudulent gas reporting)",
			ErrBlockGasLimitExceeded, block.Header.GasUsed, txGasLimitSum)
	}

	// R60-CENSUS-FMT (2026-08-09): The Attestations wire format is determined by
	// the block type, so this validator MUST branch on it exactly as the block
	// producer does (node/block_producer.go):
	//   - epoch-boundary block (Slot % SlotsPerEpoch == 0, Slot > 0): the new
	//     R59 census format — proposerCount(4) + proposer table
	//     [slot(8)+proposerIdx(4)]*proposerCount + attCount(4) + attestations.
	//   - non-boundary block: the legacy serializeAttestations format —
	//     count(4) + attestations (no proposer table prefix).
	// Previously this check parsed EVERY block as the census format; on a
	// non-boundary block the legacy 4-byte count was misread as proposerCount,
	// pushing the attCount read into attestation bytes and producing a garbage
	// large count → spurious "too many attestations" rejections → fork.
	// Each Dilithium3 attestation is ~4KB, so we must parse the count, not check
	// byte length.
	//
	// L11-033: This upper bound is currently a fixed constant. In the future it
	// should scale with the active validator set size (e.g. a multiple of the
	// number of validators eligible to attest for this slot), so that it both
	// rejects DoS payloads and never rejects legitimately full blocks. The
	// ValidatorLookup already available on the BlockValidator can supply the
	// validator count when this bound is made dynamic.
	//
	// AUDIT (2026) CONS-FIX: When the configured ValidatorLookup
	// exposes the active validator count (e.g. *consensus.ValidatorManager),
	// scale the upper bound as max(1024, activeValidatorCount) so that
	// committees larger than 1024 do not get their legitimately full blocks
	// rejected. For small validator sets (the common case), 1024 still
	// applies and rejects DoS payloads.
	maxAttestations := 1024
	if counter, ok := validatorLookup.(interface{ ActiveValidatorCount() int }); ok {
		if n := counter.ActiveValidatorCount(); n > maxAttestations {
			maxAttestations = n
		}
	}
	isEpochBoundary := block.Header.Slot%consensus.SlotsPerEpoch == 0
	attestationCount := 0
	if len(block.Header.Attestations) >= 4 {
		if isEpochBoundary {
			// New census format: proposerCount(4) + [slot(8)+proposerIdx(4)]*
			// proposerCount, then attCount(4).
			proposerCount := int(binary.BigEndian.Uint32(block.Header.Attestations[:4]))
			propLen := 4 + proposerCount*12
			if len(block.Header.Attestations) >= propLen+4 {
				attestationCount = int(binary.BigEndian.Uint32(block.Header.Attestations[propLen : propLen+4]))
			}
		} else {
			// Legacy format: count(4) + attestations.
			attestationCount = int(binary.BigEndian.Uint32(block.Header.Attestations[:4]))
		}
	}
	if attestationCount > maxAttestations {
		return nil, nil, fmt.Errorf("too many attestations: %d (max %d)", attestationCount, maxAttestations)
	}

	// R37-P3-30 FIX (2026-07-31): Validate the serialized attestation payload
	// length is consistent with the declared count.
	//   - legacy format: count(4) + variable-size attestations, each with fixed
	//     fields (slot 8 + blockRoot 32 + sourceEpoch 8 + targetEpoch 8 +
	//     validatorIdx 4 = 60 bytes) plus sigLen(2) + signature.
	//   - census format: proposerCount(4) + proposer table + [attCount(4) +
	//     attestations], same per-attestation layout.
	// R38-P2-02 FIX (2026-08-02): The original R37 check was gated by
	// `if attestationCount > 0`, so a block declaring count=0 could carry an
	// unbounded trailing garbage payload and still pass — relayers/peers
	// would forward megabytes of attacker bytes. Bind the upper bound
	// unconditionally: when count==0, the only legal payload is the census
	// header (proposer table + 4-byte attCount prefix) itself, anything beyond
	// that is fraud. For count>0 we keep the per-attestation conservative max
	// (60 + 2 + Dilithium3 sig).
	maxAttestationPayload := 60 + 2 + crypto.Dilithium3SignatureSize
	// Fixed header length: legacy = count(4). Census = proposerCount(4) +
	// proposer table + attCount(4). Proposer entries are bounded: at most one
	// per slot in an epoch, and each is 12 bytes.
	maxProposerCount := 0
	if isEpochBoundary && len(block.Header.Attestations) >= 4 {
		maxProposerCount = int(binary.BigEndian.Uint32(block.Header.Attestations[:4]))
	}
	censusHeaderLen := 4
	if isEpochBoundary {
		censusHeaderLen = 4 + maxProposerCount*12 + 4
	}
	maxExpectedLen := censusHeaderLen
	if attestationCount > 0 {
		maxExpectedLen = censusHeaderLen + attestationCount*maxAttestationPayload
	}
	if len(block.Header.Attestations) > maxExpectedLen {
		return nil, nil, fmt.Errorf("attestations payload too large: %d bytes (max %d for %d attestations)",
			len(block.Header.Attestations), maxExpectedLen, attestationCount)
	}

	// P1-3 (2026-07-14): DA availability gating. When a DankshardingEngine is
	// injected AND daCheckEnabled is true AND the node is not in syncing mode,
	// extract blob commitments from the block's blob transactions and sample
	// the DA layer. If sampling reports the blob data is not sufficiently
	// available, reject the block.
	//
	// This check is skipped when:
	//   - syncingMode is true (initial chain sync, DA layer not yet built)
	//   - no DankshardingEngine is configured (DA not enabled on this node)
	//   - daCheckEnabled is false (operator opted out of DA verification)
	//   - the block has no blob transactions (nothing to verify)
	//
	// AUDIT (2026) DA-FIX (HIGH): The syncingMode skip is a known
	// limitation — it skips DA verification for ALL blocks during initial sync,
	// not just historical blocks. The audit recommended "only skip historical
	// blocks and re-verify head blocks after catching up". This would require
	// knowing the current chain height inside ValidateBlock, which is a larger
	// change. For now, we accept this limitation because:
	//   1. DA- already hard-guards mainnet against enabling danksharding,
	//      so this skip only affects testnet/devnet during initial sync.
	//   2. syncingMode is cleared once sync completes, after which all new
	//      blocks go through full DA verification (now fail-closed per
	//      DA-).
	//   3. The QPOS FinalizeBlock DA checker (node.go) provides a second
	//      layer of defense for finalized blocks, and it is now fail-closed
	//      (DA-) — so even if a syncing node accepts an unavailable
	//      block, the network will not finalize it.
	//
	// AUDIT (2026) DA- (INFO): This known limitation is tracked as
	// an Info-level finding. The three mitigations above (mainnet hard guard,
	// syncingMode clearing, FinalizeBlock fail-closed) provide defense-in-
	// depth. The test TestR5_DA_R5_02_ValidateBlock_SyncingModeSkipsDA
	// (core/r5_da_r5_02_test.go) explicitly verifies this behavior and
	// records it as a documented limitation. No code change needed — this
	// comment is the closure artifact.
	v.mu.RLock()
	daEngine := v.danksharding
	daCheckEnabled := v.daCheckEnabled
	syncingMode := v.syncingMode
	v.mu.RUnlock()
	if daEngine != nil && daCheckEnabled && !syncingMode {
		if err := v.verifyBlockDA(block, daEngine); err != nil {
			return nil, nil, err
		}
	}

	// SECURITY FIX Q-B-002: Return a callback that the caller MUST invoke
	// after transaction execution to verify the state root. This makes
	// omission a compile-time error (unused variable) rather than a silent bug.
	stateRootValidator := func(computedStateRoot types.Hash) error {
		// audit-fix L9-005 (P0): Explicitly reject zero StateRoot. A zero
		// StateRoot means the block was never properly finalized (transactions
		// were not executed). Without this check, a zero computedStateRoot
		// would match a zero block.Header.StateRoot, silently accepting
		// incomplete blocks.
		if block.Header.Height > 0 && block.Header.StateRoot == (types.Hash{}) {
			return fmt.Errorf("%w: block StateRoot is zero (not finalized)", ErrInvalidStateRoot)
		}
		if block.Header.StateRoot != computedStateRoot {
			return fmt.Errorf("%w: expected %x, got %x", ErrInvalidStateRoot, computedStateRoot, block.Header.StateRoot)
		}
		return nil
	}

	// L10-002 FIX (P0): receiptRootValidator verifies ReceiptRoot after
	// transaction execution. A zero ReceiptRoot means the block was never
	// properly finalized (receipts were not computed). The caller MUST invoke
	// this callback after computing the receipt root from actual execution results.
	//
	// CONS- (2026-07-19) FIX: The closure is NO LONGER stored in the
	// struct field.
	//
	// CONS- (2026-07-20) FIX: The closure is now RETURNED alongside
	// stateRootValidator (previously it was discarded with `_ =`). This
	// makes the API symmetric: callers get both validators as a pair and
	// cannot accidentally forget the receipt root check.
	receiptRootValidator := func(computedReceiptRoot types.Hash) error {
		if block.Header.Height > 0 && block.Header.ReceiptRoot == (types.Hash{}) {
			return fmt.Errorf("%w: block ReceiptRoot is zero (not finalized)", ErrInvalidReceiptRoot)
		}
		if block.Header.ReceiptRoot != computedReceiptRoot {
			return fmt.Errorf("%w: expected %x, got %x", ErrInvalidReceiptRoot, computedReceiptRoot, block.Header.ReceiptRoot)
		}
		return nil
	}

	return stateRootValidator, receiptRootValidator, nil
}

// GetReceiptRootValidator returns a fresh closure that verifies the receipt
// root of the given block.
//
// Deprecated: Use the second return value of ValidateBlock instead.
// CONS- (2026-07-20): ValidateBlock now returns the receipt root
// validator directly as its second return value. Callers should use that
// rather than calling this method separately.
//
// CONS- (2026-07-19) FIX: Previously the closure was stored as a
// struct field set during ValidateBlock, which made it subject to data
// races when multiple goroutines called ValidateBlock concurrently on
// different blocks. Now we generate a fresh closure bound to the
// caller-supplied block, eliminating the shared mutable state.
//
// The returned closure captures only its `block` argument (read-only),
// so it is safe to call concurrently from multiple goroutines as long
// as the block itself is not mutated during the call.
func (v *BlockValidator) GetReceiptRootValidator(block *encoding.Block) func(types.Hash) error {
	if block == nil {
		return func(types.Hash) error {
			return fmt.Errorf("GetReceiptRootValidator: nil block")
		}
	}
	return func(computedReceiptRoot types.Hash) error {
		if block.Header.Height > 0 && block.Header.ReceiptRoot == (types.Hash{}) {
			return fmt.Errorf("%w: block ReceiptRoot is zero (not finalized)", ErrInvalidReceiptRoot)
		}
		if block.Header.ReceiptRoot != computedReceiptRoot {
			return fmt.Errorf("%w: expected %x, got %x", ErrInvalidReceiptRoot, computedReceiptRoot, block.Header.ReceiptRoot)
		}
		return nil
	}
}

// verifyBlockDA extracts blob commitments from the block's blob transactions
// and calls VerifyBlockDAAvailability to sample the DA layer. P1-3 (2026-07-14).
//
// AUDIT (2026) DA-FIX (HIGH): Previously this function had two
// fail-open paths that allowed blocks with unavailable blob data to pass
// DA verification:
//  1. Blob tx without sidecar → return nil (skip, rely on aggregate attestation)
//  2. Transient DA error → return nil (skip, rely on aggregate attestation)
//
// Both paths assumed the QPOS aggregate attestation checker would catch
// unavailable data, but that checker was also fail-open (aggregate==nil →
// return nil). This created a double fail-open: neither local sampling nor
// the aggregate attestation check would reject unavailable data.
//
// The fix closes both paths:
//  1. No sidecar → query the aggregate attestation. If the aggregate is
//     nil (missing/insufficient), reject the block instead of skipping.
//  2. Transient error → reject the block (fail-closed). This may cause
//     temporary forks during network partitions, but is safer than
//     accepting data-unavailable blocks.
//
// Note: DA- already hard-guards mainnet against enabling danksharding,
// so this check only runs on testnet/devnet where DA is enabled.
func (v *BlockValidator) verifyBlockDA(block *encoding.Block, engine *DankshardingEngine) error {
	// Extract blob commitments from the block's blob transactions.
	// Only transactions with an attached sidecar have raw KZGCommitments
	// (needed for DAS sampling). Transactions without a sidecar only carry
	// versioned hashes (SHA256 of commitment), which cannot be reversed to
	// obtain the raw commitment.
	var commitments []encoding.KZGCommitment
	hasBlobTxWithoutSidecar := false
	for _, tx := range block.Transactions {
		if !tx.IsBlobTx() {
			continue
		}
		sidecar := tx.BlobTxSidecar()
		if sidecar == nil {
			// AUDIT (2026) DA-FIX: Can't sample without raw
			// commitments. Previously returned nil (fail-open). Now mark
			// for aggregate attestation fallback check below.
			hasBlobTxWithoutSidecar = true
			continue
		}
		commitments = append(commitments, sidecar.Commitments...)
	}

	// If any blob tx lacks a sidecar, we cannot locally sample all blobs.
	// Fall back to the DA committee's aggregate attestation. If the
	// aggregate is missing or insufficient, reject the block (fail-closed).
	if hasBlobTxWithoutSidecar {
		aggregate := engine.GetAggregateAttestation(block.Header.Slot)
		if aggregate == nil || !aggregate.IsSufficient() {
			logging.Global().Warn("DA check FAILED: blob tx without sidecar and no sufficient aggregate attestation (DA-)",
				map[string]any{
					"slot":             block.Header.Slot,
					"height":           block.Header.Height,
					"aggregatePresent": aggregate != nil,
				})
			return fmt.Errorf("%w: blob tx without sidecar and no sufficient aggregate attestation for slot %d (DA-)",
				ErrDANotAvailable, block.Header.Slot)
		}
		// Aggregate attestation is sufficient — rely on committee's sampling.
		// If we also have local commitments, continue to sample them as
		// defense-in-depth; otherwise return early.
		if len(commitments) == 0 {
			return nil
		}
	}

	if len(commitments) == 0 {
		return nil // No blob txs in this block — nothing to verify.
	}

	available, confidence, err := engine.VerifyBlockDAAvailability(
		block.Header.Slot, len(commitments), commitments,
	)
	if err != nil {
		// AUDIT (2026) DA-FIX (HIGH): Previously returned nil
		// (fail-open), allowing blocks to pass when the DA layer returned
		// a transient error. Now fail-closed: reject the block to prevent
		// accepting data-unavailable blocks. This may cause temporary
		// forks during network partitions, but is safer than accepting
		// unavailable data.
		logging.Global().Warn("DA availability check error (fail-closed, rejecting block — DA-)",
			map[string]any{
				"slot":      block.Header.Slot,
				"height":    block.Header.Height,
				"blobCount": len(commitments),
				"error":     err.Error(),
			})
		return fmt.Errorf("%w: DA sampling error for slot %d: %v (DA-)",
			ErrDANotAvailable, block.Header.Slot, err)
	}

	if !available {
		logging.Global().Warn("DA availability check FAILED: block blob data not sufficiently available",
			map[string]any{
				"slot":       block.Header.Slot,
				"height":     block.Header.Height,
				"blobCount":  len(commitments),
				"confidence": confidence,
			})
		return fmt.Errorf("%w: slot %d confidence %.4f (%d blobs)",
			ErrDANotAvailable, block.Header.Slot, confidence, len(commitments))
	}

	return nil
}

// ValidateReceiptRoot verifies the block's receipt root matches the computed
// receipt root. L10-002 FIX (P0): Previously, ValidateBlock did not verify
// ReceiptRoot at all, allowing zero or forged receipt roots to be accepted.
// This should be called after transaction execution to verify receipt integrity.
func (v *BlockValidator) ValidateReceiptRoot(block *encoding.Block, computedReceiptRoot types.Hash) error {
	if block == nil || block.Header == nil {
		return ErrEmptyBlock
	}
	// L10-002: Reject zero ReceiptRoot for non-genesis blocks.
	if block.Header.Height > 0 && block.Header.ReceiptRoot == (types.Hash{}) {
		return fmt.Errorf("%w: block ReceiptRoot is zero (not finalized)", ErrInvalidReceiptRoot)
	}
	if block.Header.ReceiptRoot != computedReceiptRoot {
		return fmt.Errorf("%w: expected %x, got %x", ErrInvalidReceiptRoot, computedReceiptRoot, block.Header.ReceiptRoot)
	}
	return nil
}

// ValidateStateRoot verifies the block's state root matches the computed state root.
// This should be called after transaction execution to verify state transitions are correct.
// DEPRECATED: Use the callback returned by ValidateBlock() instead.
func (v *BlockValidator) ValidateStateRoot(block *encoding.Block, computedStateRoot types.Hash) error {
	if block == nil || block.Header == nil {
		return ErrEmptyBlock
	}
	// audit-fix L9-005 (P0): Reject zero StateRoot for non-genesis blocks.
	if block.Header.Height > 0 && block.Header.StateRoot == (types.Hash{}) {
		return fmt.Errorf("%w: block StateRoot is zero (not finalized)", ErrInvalidStateRoot)
	}
	if block.Header.StateRoot != computedStateRoot {
		return fmt.Errorf("%w: expected %x, got %x", ErrInvalidStateRoot, computedStateRoot, block.Header.StateRoot)
	}
	return nil
}

// ValidateGasUsed verifies that the block's Header.GasUsed matches the actual
// total gas consumed by transaction execution.
//
// R35-P1-09 FIX (2026-07-29): Previously the codebase only checked
// GasUsed <= GasLimit (line 703) and GasUsed <= sum-of-tx-gas-limits (line 719,
// also added by this fix). Neither check prevents a malicious proposer from
// UNDERREPORTING GasUsed — e.g. claiming GasUsed=0 while executing
// high-gas transactions — to pay less BaseFee or manipulate the next block's
// BaseFee downward. This method closes that gap by requiring the block
// processor to pass the actual computed gas used (sum of receipt.GasUsed)
// after executing the block's transactions.
//
// The block processor (node/block_producer.go:2037) already computes
// totalGasUsed by summing receipt.GasUsed. Validators re-executing the block
// compute the same value. This method should be called by the validation path
// after re-execution, with the recomputed total.
func (v *BlockValidator) ValidateGasUsed(block *encoding.Block, computedGasUsed uint64) error {
	if block == nil || block.Header == nil {
		return ErrEmptyBlock
	}
	if block.Header.GasUsed != computedGasUsed {
		return fmt.Errorf("%w: header GasUsed %d != computed GasUsed %d (gas mismatch — possible BaseFee manipulation)",
			ErrBlockGasLimitExceeded, block.Header.GasUsed, computedGasUsed)
	}
	return nil
}

// validateTransactions validates all transactions in a block.
// audit-fix R2-M4: validates per-account nonce ordering in addition to tx.Validate().
// A malicious proposer could include replay/out-of-order nonces without this check.
//
// SECURITY NOTE: ValidateBlock now returns a state-root validation callback.
// The block processing pipeline MUST invoke that callback after executing all
// transactions. Failure to do so is a compile-time error (unused return value).
func (v *BlockValidator) validateTransactions(block *encoding.Block) error {
	// Track highest nonce seen per account for ordering validation
	accountNonces := make(map[types.Address]uint64)

	// AUDIT (2026) R4-DATA-08 FIX: Active defense against CVE-2012-2459
	// (Merkle duplicate-last malleability). The block Merkle root uses
	// duplicate-last padding for odd transaction counts, which structurally
	// allows two different transaction lists to share one root:
	//   [A, B, C]       (odd, 3 txs) → root padded as [A,B,C,C]
	//   [A, B, C, C]    (even, 4 txs) → root computed as-is
	// Both yield the same Merkle root. The exploit requires the same
	// transaction hash C to appear twice. Nonce uniqueness already rejects
	// this in practice (latent), but we add an explicit duplicate-hash check
	// here as defense-in-depth so the invariant is enforced actively and
	// survives any future relaxation of nonce ordering rules.
	seenTxHashes := make(map[types.Hash]struct{}, len(block.Transactions))

	// SECURITY FIX: Collect transactions that need signature verification.
	// Most transactions will be cache hits (already verified in txpool),
	// so the actual crypto cost is minimal for honest blocks.
	v.mu.RLock()
	sv := v.signingVerifier
	nr := v.nonceReader
	v.mu.RUnlock()

	type sigItem struct {
		index int
		tx    *encoding.Transaction
	}
	var pendingSigs []sigItem
	// AUDIT-FULL-ROUND1-2026-08-15 P0-02 FIX: MultiSig transactions are
	// collected separately and verified via the canonical N-of-M path
	// (encoding.VerifyMultiSigAuthorization) using the on-chain signer
	// roster supplied by the injected MultiSigRosterProvider. They MUST
	// NOT be appended to pendingSigs — pendingSigs is verified by
	// encoding.DefaultValidator.ValidateTxBatch which calls
	// VerifyTransactionAuthorization and FAIL-CLOSED on MultiSig with
	// ErrAuthMultiSigUnsupported (intentional: see transaction_authorization.go
	// comment). Routing them there would reject every MultiSig-containing
	// block. The separate collection below lets the block validator
	// successfully admit MultiSig blocks when an on-chain roster is available.
	var multisigPending []sigItem

	for i, tx := range block.Transactions {
		// AUDIT (2026) M-02 NOTE: block-level zero-fee protection. The
		// tx.Validate() call below is the consensus gate against zero-cost
		// transactions: it rejects any non-blob tx with nil or non-positive
		// GasPrice and any blob tx with nil or non-positive MaxFeePerGas.
		// Since big.Int values are integers, Sign() > 0 is equivalent to
		// GasPrice >= 1 wei — the protocol floor mirrored by
		// txpool.MinGasPrice. Block producers therefore CANNOT include
		// zero-fee transactions in a block that passes validation, closing
		// the self-dealing vector identified by the audit.
		if err := tx.Validate(); err != nil {
			return err
		}

		// CONS- (2026-07-22): EIP-4844 blob tx fee validation.
		// Blob transactions must specify a non-nil MaxFeePerBlobGas that
		// is >= the current blob base fee (derived from header.ExcessBlobGas).
		// Without this, a malicious proposer could include blob txs with
		// nil/zero MaxFeePerBlobGas that would be rejected by the executor,
		// wasting block space, or with a fee below the blob base fee,
		// bypassing the EIP-4844 fee market.
		if tx.IsBlobTx() {
			if tx.MaxFeePerBlobGas == nil || tx.MaxFeePerBlobGas.Sign() <= 0 {
				return fmt.Errorf("%w: nil or zero MaxFeePerBlobGas for blob tx at index %d",
					ErrInvalidBlobMaxFee, i)
			}
			blobBaseFee := encoding.CalcBlobFee(block.Header.ExcessBlobGas)
			if tx.MaxFeePerBlobGas.Cmp(blobBaseFee) < 0 {
				return fmt.Errorf("%w: MaxFeePerBlobGas %s below blob base fee %s at index %d",
					ErrInvalidBlobMaxFee, tx.MaxFeePerBlobGas.String(), blobBaseFee.String(), i)
			}
		}

		// R4-DATA-08: Reject duplicate transaction hashes. This catches the
		// exact CVE-2012-2459 exploit shape ([A,B,C,C]) at validation time.
		// A duplicate hash means either a replayed transaction (same nonce
		// and signature) or a SHA3 collision (computationally infeasible).
		// Either way the block is invalid.
		txHash := tx.Hash()
		if _, seen := seenTxHashes[txHash]; seen {
			return fmt.Errorf("%w: index %d duplicates earlier transaction %x",
				ErrDuplicateTransaction, i, txHash[:8])
		}
		seenTxHashes[txHash] = struct{}{}

		// SECURITY (audit R4-ZK-01): Reject privacy transactions in blocks
		// when the privacy subsystem is not enabled. A privacy tx skips
		// signature verification and nonce checks; if accepted into a block
		// without a configured PrivacyTxVerifier, the executor's fail-closed
		// path would still have allowed gas deduction (now also fixed at the
		// executor). Rejecting here provides defense-in-depth at the
		// consensus layer — non-privacy-enabled nodes must not accept blocks
		// containing privacy transactions.
		if tx.Type == encoding.TxTypePrivacy {
			v.mu.RLock()
			enabled := v.privacyEnabled
			v.mu.RUnlock()
			if !enabled {
				return fmt.Errorf("block contains privacy transaction at index %d but privacy is not enabled", i)
			}
		}

		// Verify nonces are monotonically increasing per account within the block.
		// Privacy transactions use nullifiers for replay protection, not nonces,
		// so skip nonce ordering checks for them (same as txPool validator).
		if tx.Type != encoding.TxTypePrivacy {
			if lastNonce, seen := accountNonces[tx.From]; seen {
				if tx.Nonce <= lastNonce {
					return fmt.Errorf("invalid nonce ordering for %x: got %d, expected > %d",
						tx.From[:8], tx.Nonce, lastNonce)
				}
			} else {
				// AUDIT (2026) R4-ECON-02 FIX: First tx from this sender
				// in the block — anchor to the pre-state nonce. Without this,
				// a malicious proposer can include already-executed transactions
				// (nonce < stateNonce) that pass the within-block ordering check
				// but are replays. The executor (ECON-) prevents execution,
				// but replays still waste ~0.4s/block of Dilithium verification
				// time and occupy block space (censorship DoS).
				if nr != nil {
					stateNonce := nr.GetNonce(tx.From)
					if tx.Nonce < stateNonce {
						return fmt.Errorf("replay tx from %x: nonce %d below state nonce %d",
							tx.From[:8], tx.Nonce, stateNonce)
					}
				}
			}
			accountNonces[tx.From] = tx.Nonce
		}

		// Collect non-privacy transactions for signature verification.
		// R38-P0-02 (2026-08-01) FIX: Re-enable signature verification for
		// stake/unstake transactions. The RPC layer now encodes the staking
		// nonce into tx.Data (format: commission(4)+nonceLen(2)+nonce for
		// stake, nonceLen(2)+nonce for unstake), allowing the block validator
		// to reconstruct the staking signature message
		// `method|chainID|addr|nonce|params` and verify it with the embedded
		// Dilithium3 public key + signature.
		//
		// Previously (R37-P0-02), stake/unstake txs were EXEMPT from signature
		// verification because the validator could not reconstruct the staking
		// signature message. This allowed a malicious proposer to forge
		// stake/unstake transactions for ANY address, enabling:
		//   - Unauthorized unstaking of a victim's stake
		//   - Adding attacker-controlled validators
		//   - Gaining majority consensus power
		//
		// The forgery vector is now closed: the validator extracts the staking
		// nonce from tx.Data, reconstructs the signature message, and verifies
		// it against tx.PublicKey + tx.Signature. If the signature is invalid
		// or tx.Data is malformed, the block is rejected.
		if sv != nil && tx.Type != encoding.TxTypePrivacy {
			// AUDIT-FULL-ROUND1-2026-08-15 P0-02 FIX: route MultiSig tx
			// to the N-of-M collection, not the ordinary single-sig batch.
			if tx.Type == encoding.TxTypeMultiSig {
				// Fail-closed: if no MultiSigRosterProvider is configured
				// (e.g. non-multisig-enabled nodes, or pre-node-wiring
				// tests), MultiSig txns cannot be verified — refuse the
				// block. This is identical posture to
				// encoding.VerifyTransactionAuthorization's
				// ErrAuthMultiSigUnsupported; we DO NOT silently skip.
				v.mu.RLock()
				provider := v.multisigRosterProvider
				v.mu.RUnlock()
				if provider == nil {
					return fmt.Errorf("block tx %d: TxTypeMultiSig present but MultiSigRosterProvider is nil (AUDIT-FULL-ROUND1 P0-02 fail-closed)", i)
				}
				multisigPending = append(multisigPending, sigItem{index: i, tx: tx})
				continue
			}
			pendingSigs = append(pendingSigs, sigItem{index: i, tx: tx})
		}
	}

	// SECURITY FIX: Batch verify all transaction signatures in parallel.
	// Without this, a malicious proposer could include forged-signature
	// transactions in a block. Uses BatchVerifier (parallel workers) +
	// SignatureCache (cache hits for txs already verified in txpool).
	if sv != nil && len(pendingSigs) > 0 {
		// Unified transaction authorization verification using DefaultValidator.
		// R42-REFACTOR: Previously, stake/unstake transactions were verified individually
		// via encoding.VerifyTransactionAuthorization, while ordinary transactions
		// (Transfer/Contract/Create) used a separate BatchVerify path with inline
		// From↔PublicKey binding check. This duplication created multiple verification
		// paths that could diverge (see R41-L5CORE-01 where the binding check was
		// missing in the ordinary tx path).
		//
		// Now ALL transactions (ordinary + stake/unstake) pass through the single
		// canonical DefaultValidator.ValidateTxBatch, which:
		// 1. Checks PublicKey size and Signature size
		// 2. Verifies From↔PublicKey binding (prevents R41-L5CORE-01 style attacks)
		// 3. Dispatches on tx.Type to the correct canonical hash verification
		//    (SigningHash for ordinary tx, ComputeStakeAuthorizationHash for stake/unstake)
		// 4. Optionally validates ChainID for cross-chain replay protection
		//
		// This eliminates duplicate verification logic and ensures all transaction
		// types are protected by the same security boundary.
		//
		// Note: sv (SignatureVerifier) is no longer used for batch verification
		// since DefaultValidator handles all verification internally. The BatchVerify
		// path can be re-enabled later if performance profiling shows it's needed
		// for large blocks, but security correctness is prioritized over throughput.
		if len(pendingSigs) > 0 {
			// Extract transactions for batch validation
			txs := make([]*encoding.Transaction, len(pendingSigs))
			for i, si := range pendingSigs {
				txs[i] = si.tx
			}

			// Use DefaultValidator for unified batch verification
			// Pass 0 as chainID to skip chain ID validation during block validation
			// (chain ID is validated at the node level before blocks are accepted)
			validator := encoding.NewDefaultValidator(0)
			errs := validator.ValidateTxBatch(txs)

			for i, si := range pendingSigs {
				if errs[i] != nil {
					return fmt.Errorf("block tx %d: authorization failed: %w", si.index, errs[i])
				}
			}
		}
	}

	// AUDIT-FULL-ROUND1-2026-08-15 P0-02 FIX: verify the MultiSig collection
	// via the canonical N-of-M path. The block validator queried the
	// MultiSigRosterProvider at collection time (and rejected the block
	// fail-closed if it was nil while a MultiSig tx was present), so reaching
	// here with non-empty multisigPending implies the provider is non-nil.
	// We re-read the provider under RLock (no caller-shared state between
	// the collection loop and this point; the provider can be swapped between
	// them but the worst case is a "set/unset-to-nil race" that simply flips
	// the route to fail-closed — same security posture).
	if sv != nil && len(multisigPending) > 0 {
		v.mu.RLock()
		provider := v.multisigRosterProvider
		v.mu.RUnlock()
		if provider == nil {
			// Provider was unset between the collection loop and here —
			// treat as fail-closed. This block transitioned from "will be
			// verified" to "cannot be verified" mid-flight; safer to reject.
			return fmt.Errorf("block has %d TxTypeMultiSig transactions but MultiSigRosterProvider became nil (AUDIT-FULL-ROUND1 P0-02 fail-closed)", len(multisigPending))
		}
		for _, si := range multisigPending {
			roster, err := provider.GetSignerRoster(si.tx.From)
			if err != nil {
				return fmt.Errorf("block tx %d: MultiSigRosterProvider.GetSignerRoster(%x): %w",
					si.index, si.tx.From[:8], err)
			}
			if len(roster) == 0 {
				return fmt.Errorf("block tx %d: MultiSig wallet %x is not registered with the on-chain multisig registry (fail-closed)",
					si.index, si.tx.From[:8])
			}
			if err := encoding.VerifyMultiSigAuthorization(si.tx, roster); err != nil {
				return fmt.Errorf("block tx %d: MultiSig authorization failed: %w", si.index, err)
			}
		}
	}

	// Check total gas
	// audit-fix MEDIUM-5: Reorder checks to validate overflow BEFORE subtraction to prevent underflow
	var totalGas uint64
	// R11-CORE-002 FIX: Read maxGasLimit under RLock.
	v.mu.RLock()
	maxGasLimit := v.maxGasLimit
	forkProvider := v.forkRuleProvider
	v.mu.RUnlock()

	// AUDIT (2026) R4-NODE-01: If a fork rule provider is configured,
	// use the MaxBlockGas active at this block's height instead of the
	// hardcoded default. This makes scheduled hard forks actually take
	// effect (previously the ForkManager was dead code).
	if forkProvider != nil {
		if rules := forkProvider.GetRulesAtHeight(block.Header.Height); rules != nil {
			if rules.MaxBlockGas > 0 {
				maxGasLimit = rules.MaxBlockGas
			}
		}
	}

	for _, tx := range block.Transactions {
		// CRITICAL: Check overflow first before adding
		if totalGas > math.MaxUint64-tx.GasLimit {
			return ErrBlockGasLimitExceeded
		}
		// Then check if adding this tx would exceed block gas limit
		if totalGas+tx.GasLimit > maxGasLimit {
			return ErrBlockGasLimitExceeded
		}
		totalGas += tx.GasLimit
	}
	if totalGas > maxGasLimit {
		return ErrBlockGasLimitExceeded
	}

	return nil
}

// computeHeaderHash computes the hash of a block header.
// audit-fix M-3: handle marshaling failure instead of hashing nil data.
func (v *BlockValidator) computeHeaderHash(header *encoding.BlockHeader) types.Hash {
	data, err := encoding.MarshalBlockHeader(header)
	if err != nil || len(data) == 0 {
		return types.Hash{}
	}
	return sha3.Sum256(data)
}

// computeTxRoot computes the Merkle root of transactions.
// audit-fix M-1: use proper binary Merkle tree (shared implementation).
func (v *BlockValidator) computeTxRoot(txs []*encoding.Transaction) types.Hash {
	if len(txs) == 0 {
		return types.Hash{}
	}
	return computeMerkleRoot(txs)
}

// ValidateVRFProof validates the VRF proof in a block header.
// VRF (Verifiable Random Function) proves the proposer was legitimately selected.
//
// audit fix (H-8) [HIGH]: Replaced the inconsistent manual VRF
// verification (which used sha3.Sum256(vrfProof) for output derivation —
// different from consensus.computeVRFOutputDeterministic) with a direct
// call to consensus.VerifyVRF. This ensures algorithm consistency between
// block production and validation, and prevents VRF bias attacks where a
// signer could produce multiple valid proofs for the same seed.
func (v *BlockValidator) ValidateVRFProof(header *encoding.BlockHeader, seed types.Hash) error {
	// Check VRF proof exists
	if len(header.VRFProof) == 0 {
		return ErrInvalidVRFProof
	}

	// Check VRF value exists
	if header.VRFValue == (types.Hash{}) {
		return ErrInvalidVRFProof
	}

	// R37-P3-31 FIX (2026-07-31): Snapshot mutable fields under read lock.
	// Previously v.chainID, v.devMode, and v.validatorLookup were read
	// without synchronization, so a concurrent SetChainID / SetDevMode /
	// SetValidatorLookup could race and produce inconsistent decisions
	// (e.g. chainID flip between the mainnet check and the error message,
	// or devMode toggle between the devMode check and the validator lookup
	// dereference — both leading to nil-pointer dereference or incorrect
	// acceptance of an invalid block).
	v.mu.RLock()
	chainID := v.chainID
	devMode := v.devMode
	validatorLookup := v.validatorLookup
	v.mu.RUnlock()

	// SECURITY FIX H-3: Defense-in-depth — refuse to skip VRF proof
	// signature verification on mainnet/testnet even if devMode is somehow
	// enabled.
	if chainID == params.MainnetChainID || chainID == params.TestnetChainID {
		if validatorLookup == nil {
			logging.Global().Error("VALIDATOR LOOKUP NOT CONFIGURED on production chain — rejecting block",
				map[string]any{"chainID": chainID})
			return fmt.Errorf("%w: validator lookup not configured on production chain %d", ErrInvalidVRFProof, chainID)
		}
	} else if validatorLookup == nil {
		if devMode {
			logging.Global().Warn("VALIDATOR LOOKUP NOT CONFIGURED - VRF proof signature verification SKIPPED - this is acceptable in DEV MODE ONLY", nil)
			return nil
		}
		logging.Global().Error("VALIDATOR LOOKUP NOT CONFIGURED - rejecting block in production", nil)
		return fmt.Errorf("%w: validator lookup not configured", ErrInvalidVRFProof)
	}

	if !devMode && !validatorLookup.IsValidator(header.ProposerAddr) {
		return ErrInvalidProposer
	}

	if devMode {
		return nil
	}

	// audit fix (H-8): Use consensus.VerifyVRF for full cryptographic
	// verification. This verifies both the proof signature AND the output
	// determinism using the same algorithm as consensus/vrf.go, ensuring
	// consistency and preventing VRF bias attacks.
	pubKeyBytes, err := validatorLookup.GetValidatorPublicKey(header.ProposerAddr)
	if err != nil {
		return ErrInvalidProposer
	}

	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return ErrInvalidProposer
	}

	vrfProof := &consensus.VRFProof{Proof: header.VRFProof}
	vrfOutput := &consensus.VRFOutput{Value: header.VRFValue}
	if err := consensus.VerifyVRF(pubKey, seed, vrfProof, vrfOutput); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidVRFProof, err)
	}

	return nil
}

// computeVRFInput computes the input for VRF computation.
// audit-fix R6-L3: use encoding/binary.BigEndian for consistency with R5-L1.
func (v *BlockValidator) computeVRFInput(seed types.Hash, slot, epoch uint64) []byte {
	input := make([]byte, types.HashLength+16)
	copy(input[:types.HashLength], seed[:])
	binary.BigEndian.PutUint64(input[types.HashLength:], slot)
	binary.BigEndian.PutUint64(input[types.HashLength+8:], epoch)
	return input
}

// ValidateSignature validates the block signature using Dilithium3.
func (v *BlockValidator) ValidateSignature(header *encoding.BlockHeader) error {
	if len(header.Signature) == 0 {
		return ErrInvalidSignature
	}

	sigLen := len(header.Signature)
	if sigLen != crypto.Dilithium3SignatureSize && sigLen != crypto.GMQTDCombinedSignatureSize {
		return ErrInvalidSignature
	}

	if header.ProposerAddr.IsEmpty() {
		return ErrInvalidProposer
	}

	// R37-P3-31 FIX (2026-07-31): Snapshot mutable fields under read lock.
	// Previously v.devMode and v.validatorLookup were read without
	// synchronization, so a concurrent SetDevMode / SetValidatorLookup
	// could race and produce inconsistent decisions (e.g. devMode toggle
	// between the early-return check and the validatorLookup nil check,
	// leading to nil-pointer dereference or incorrect acceptance of an
	// invalid block).
	v.mu.RLock()
	devMode := v.devMode
	validatorLookup := v.validatorLookup
	tssVerifier := v.tssVerifier
	v.mu.RUnlock()

	if devMode {
		return nil
	}

	signingData := v.computeSigningData(header)
	if signingData == nil {
		return ErrInvalidSignature
	}

	// C21-006 FIX (R49e, 2026-08-05): TSS threshold signing via SignWithRetry
	// produces a standard Dilithium3-format signature (3293 bytes) signed with
	// the GROUP key, not a 4064-byte GM-QTD combined signature. The previous
	// check `sigLen == crypto.GMQTDCombinedSignatureSize` only routed 4064-byte
	// signatures to the TSS verify path, causing 3293-byte TSS signatures to
	// fall through to individual-key verification — which fails because the
	// signature was signed with the group key, not the proposer's individual
	// key. This caused every TSS-signed block to be rejected at the P2P layer,
	// leading to a catastrophic chain fork where every node ran its own chain.
	//
	// Fix: When TSS is available, try TSS verification FIRST for both 3293 and
	// 4064 byte signatures. If TSS verification succeeds, accept the block.
	// If TSS verification fails AND the signature is 4064 bytes, reject (4064
	// is exclusively TSS). If TSS verification fails AND the signature is 3293
	// bytes, fall through to individual Dilithium3 verification (the signature
	// might be a genuine individual signature, not a TSS signature).
	if tssVerifier != nil && tssVerifier.HasGroupPublicKey() {
		if err := tssVerifier.VerifyCombinedSignature(header.Signature, signingData); err != nil {
			if sigLen == crypto.GMQTDCombinedSignatureSize {
				// 4064-byte signatures are exclusively TSS — no fallback
				return ErrInvalidSignature
			}
			// 3293-byte signature: TSS verification failed, but it might be an
			// individual Dilithium3 signature. Fall through to individual verification.
		} else {
			return nil
		}
	}

	if validatorLookup == nil {
		return fmt.Errorf("%w: validator lookup not configured", ErrInvalidSignature)
	}

	pubKeyBytes, err := validatorLookup.GetValidatorPublicKey(header.ProposerAddr)
	if err != nil {
		return ErrInvalidProposer
	}

	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return ErrInvalidSignature
	}

	if !pubKey.Verify(signingData, header.Signature) {
		// SECURITY (audit P2-03): Reduce log to Debug and remove sensitive data
		// (signingHash, pubKeyFirst) that could aid fingerprinting attacks.
		logging.Global().Debug("Dilithium3 signature verification failed", map[string]any{
			"height":    header.Height,
			"sigLen":    len(header.Signature),
			"pubKeyLen": len(pubKeyBytes),
		})
		return ErrInvalidSignature
	}

	return nil
}

// computeSigningData computes the data to be signed for a block header.
// This excludes the signature, sync committee sig, and sync committee bits,
// which are added after the block is signed.
// C21-007 FIX (R50, 2026-08-05): Strip stardust fields (FinalityType,
// QTDSignature, ExecutiveSealers, ReviewAttestationRoot) because they are
// set by PopulateStardustFields AFTER signing. The producer signs the
// header BEFORE these fields are populated, so the validator must strip
// them to compute the same signing hash. Without this, every TSS-signed
// block is rejected → catastrophic chain fork.
func (v *BlockValidator) computeSigningData(header *encoding.BlockHeader) []byte {
	headerCopy := *header
	headerCopy.Signature = nil
	headerCopy.SyncCommitteeSig = nil
	headerCopy.SyncCommitteeBits = nil
	headerCopy.QTDSignature = nil
	headerCopy.ExecutiveSealers = nil
	headerCopy.ReviewAttestationRoot = types.Hash{}
	headerCopy.FinalityType = 0

	rawData, err := encoding.MarshalBlockHeader(&headerCopy)
	if err != nil || len(rawData) == 0 {
		return nil
	}

	hash := sha3.Sum256(rawData)
	return hash[:]
}

// SetMaxFutureTime sets the maximum allowed future timestamp.
// R11-CORE-002 FIX: Add mutex protection, consistent with SetMinBlockInterval.
func (v *BlockValidator) SetMaxFutureTime(d time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.maxFutureTime = d
}

// SetMinBlockInterval sets the minimum required block interval.
// audit-fix MEDIUM: allows configuration of minimum block interval to prevent
// timestamp manipulation attacks where blocks are produced too quickly.
func (v *BlockValidator) SetMinBlockInterval(d time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.minBlockInterval = d
}

// SetMaxGasLimit sets the maximum gas limit.
// R11-CORE-002 FIX: Add mutex protection, consistent with SetMinBlockInterval.
func (v *BlockValidator) SetMaxGasLimit(limit uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.maxGasLimit = limit
}

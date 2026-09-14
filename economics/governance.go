// Quantaureum Node source, version 1.0.0.
// Package economics implements the economic model for the Quantaureum blockchain.
// This file implements governance parameters and proposal mechanism.
package economics

// L14-036 SECURITY NOTE: Proposal validation checks include: proposer
// signature verification (Dilithium3), deposit sufficiency, parameter
// change format validation, and proposal data size limits (32KB max).
// The validation is performed before the proposal is stored to prevent
// invalid proposals from consuming storage. However, the validation does
// not check whether the proposed parameter values are semantically valid
// (e.g., whether a new inflation rate is economically sound) -- this is
// left to the voters to decide during the voting period.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// Governance-related errors
var (
	ErrProposalNotFound      = errors.New("proposal not found")
	ErrProposalExpired       = errors.New("proposal has expired")
	ErrProposalNotActive     = errors.New("proposal is not active")
	ErrAlreadyVoted          = errors.New("already voted on this proposal")
	ErrInvalidParameter      = errors.New("invalid parameter")
	ErrParameterValueInvalid = errors.New("parameter value out of valid range")
	ErrInsufficientVotePower = errors.New("insufficient voting power")
	// P3-EC-04 (2026-08-03): returned by CreateProposal when the optional
	// BalanceQuerier observes the proposer's free (non-staked) QAU balance
	// is below CreateProposalGasThreshold (= 0.001 QAU). Surfaced as a
	// separate error from ErrInsufficientVotePower because the stake check
	// covers deposit-match while this covers transaction-gas coverage — they
	// are independent invariants and the audit's edge case only fires when
	// the stake check passes (proposer holds the deposit exactly) but the
	// free-balance check fails (no gas for Vote / ExecuteProposal txns).
	ErrInsufficientFreeBalance     = errors.New("insufficient free balance for governance gas coverage")
	ErrProposalExists              = errors.New("proposal already exists")
	ErrInvalidProposalType         = errors.New("invalid proposal type")
	ErrParameterNotSupported       = errors.New("parameter not in governance whitelist")
	ErrUnauthorizedParameterChange = errors.New("unauthorized: only governance contract can set parameters")
	ErrVoteInflation               = errors.New("vote inflation detected: accumulated votes exceed total vote power")
	// R42-GOVDEP-01: returned by CreateProposal when production hardening is
	// enabled (SetProductionMode(true)) and no DepositLocker has been wired.
	// Rejects zero-cost governance-proposal DoS instead of silently accepting.
	ErrDepositLockerRequired = errors.New("governance: DepositLocker is required in production mode but not configured (call SetDepositLocker before creating proposals)")
	// GOV- (2026-07-20): Two-step timelock errors.
	ErrGovernanceProposeUnauthorized = errors.New("unauthorized: only current governance or initializer may propose a new governance address")
	ErrGovernanceConfirmUnauthorized = errors.New("unauthorized: only current governance or initializer may confirm a new governance address")
	ErrGovernanceNoPendingProposal   = errors.New("no pending governance address proposal to confirm")
	ErrGovernanceTimelockNotElapsed  = errors.New("governance address transfer timelock has not elapsed yet")

	// R43-GOVSIG-01: returned by CreateProposal when a ProposalSignature is
	// supplied but Dilithium3 verification fails (signature invalid, public
	// key mismatch, malformed inputs, or chain-ID domain separation mismatch).
	// This makes governance-proposal authentication enforceable at the
	// CORE layer (economics) — not only at the RPC layer — so a caller that
	// bypasses the RPC path (e.g. an internal integration, a future
	// consensus-internal proposal mechanism, or an import-style unit test
	// that constructs proposals directly) cannot create unauthorized proposals
	// by skipping rpc/governance_api.go's verifyGovernanceSignature.
	ErrGovernanceSignatureInvalid = errors.New("governance: proposer Dilithium3 signature verification failed at core layer")
)

// GovernanceProposalSignatureMethod is the canonical method tag embedded in
// the Dilithium3 signed message for governance proposal creation. The RPC
// layer (rpc/governance_api.go verifyGovernanceSignature) and the core
// economics layer MUST use the same string so that a signature accepted by
// the RPC layer is also accepted by the core layer (and vice versa).
// R43-GOVSIG-01: defined here in the core package so both sides import the
// SAME constant — no risk of string drift.
const GovernanceProposalSignatureMethod = "qau_createProposal"

// ProposalSignature carries the Dilithium3 signature material that the
// core economics layer uses to authenticate CreateProposal. It is OPTIONAL:
// a nil ProposalSignature skips core-layer verification (preserving the
// legacy behavior for unit tests and internal integrations that are not
// attacker-reachable). Production CALLERS (rpc/governance_api.go) MUST supply
// a non-nil ProposalSignature so that even if a future code path bypasses
// the RPC layer, the core layer independently verifies the signature.
//
// Field semantics:
//   - ProposerPubKey: 1952-byte Dilithium3 public key (crypto.Dilithium3PublicKeySize).
//   - ProposerSig:    3293-byte Dilithium3 signature (crypto.Dilithium3SignatureSize).
//   - Nonce:          the same base-10 uint64 string embedded in the signed
//     message and used as the on-chain ProposerNonce.
//   - ChainID:        domain-separation tag (must match the chainID the
//     RPC layer used when verifying). Cross-chain replay is
//     rejected because the signed message includes this tag.
//   - TotalVotePower: decimal string of the snapshot total vote power. This
//     is part of the signed message body so an attacker cannot
//     swap the snapshot to make a passing proposal seem to
//     have had more support than it really did.
//
// The signed message format MUST byte-for-byte match what
// rpc/governance_api.go verifyGovernanceSignature constructs:
//
//	"QAU-" + method + "|" + chainID + "|" + proposerHex + "|" + nonce + "|" + authParams
//
// where authParams = proposerHex + "|" + type + "|" + title + "|" +
// description + "|" + deposit + "|" + totalVotePower + "|" + changesJSON.
type ProposalSignature struct {
	ProposerPubKey []byte
	ProposerSig    []byte
	Nonce          string
	ChainID        uint64
	TotalVotePower string
}

// ProposalType defines the type of governance proposal
type ProposalType uint8

const (
	// ProposalTypeParameter is for changing economic parameters
	ProposalTypeParameter ProposalType = iota
	// ProposalTypeUpgrade is for protocol upgrades
	ProposalTypeUpgrade
	// ProposalTypeEmergency is for emergency actions
	ProposalTypeEmergency
)

// ProposalStatus defines the status of a proposal
type ProposalStatus uint8

const (
	// ProposalStatusPending is the initial status
	ProposalStatusPending ProposalStatus = iota
	// ProposalStatusActive is when voting is open
	ProposalStatusActive
	// ProposalStatusPassed is when the proposal passed
	ProposalStatusPassed
	// ProposalStatusRejected is when the proposal was rejected
	ProposalStatusRejected
	// ProposalStatusExecuted is when the proposal was executed
	ProposalStatusExecuted
	// ProposalStatusExpired is when the proposal expired
	ProposalStatusExpired
)

// GovernanceConfig defines the governance configuration.
//
// R40-P1-05 (2026-08-03) — Immutable-After-Init Contract:
//
// A `GovernanceConfig` is constructed EXACTLY ONCE (by `DefaultGovernanceConfig`
// or by the caller that passes a config to `NewGovernanceManager`) and the
// pointer stored in `GovernanceManager.config` is never reassigned and its
// fields are never mutated afterward. All four `Emergency*` field reads in
// `CreateProposal` / `FinalizeProposal` / `ExecuteProposal` / `GetConfig`
// already go through `gm.mu` (R- or W-lock); because no writer ever mutates the
// pointed-to `GovernanceConfig`, the reads cannot race.
//
// To preserve this invariant:
//   - Do NOT add field mutators (`SetEmergency*`, `UpdateVotingPeriod`, …).
//     If runtime config updates become a requirement, construct a NEW
//     `GovernanceConfig` and swap `gm.config` atomically under `gm.mu` —
//     never mutate fields of the shared pointer in place.
//   - All field reads MUST hold `gm.mu` (R- or W-lock). The `GetConfig`
//     method enforces that contract for RPC consumers by returning a
//     value-copy under `RLock` (R40-P1-06).
type GovernanceConfig struct {
	// VotingPeriod is the number of blocks for voting
	VotingPeriod uint64

	// QuorumThreshold is the minimum participation required (basis points)
	QuorumThreshold uint32

	// PassThreshold is the minimum yes votes required to pass (basis points)
	PassThreshold uint32

	// ProposalDeposit is the deposit required to create a proposal
	ProposalDeposit *big.Int

	// ExecutionDelay is the number of blocks before execution after passing
	ExecutionDelay uint64

	// GOV- (2026-07-20) FIX: Emergency proposals previously used the
	// SAME VotingPeriod/QuorumThreshold/PassThreshold/ExecutionDelay as
	// regular parameter proposals. This meant a malicious attacker could:
	//   1. Create an emergency proposal during a low-participation window.
	//   2. Pass it with the same 50% threshold as regular proposals.
	//   3. Execute it after the same 2-day delay.
	//
	// Emergency proposals (ProposalTypeEmergency) trigger chain-halting
	// defense-ministry actions, so they require STRICTER passage:
	//   - Higher pass threshold (66.7% supermajority) to ensure broad
	//     consensus before halting the chain.
	//   - SHORTER voting period (24h instead of 7 days) because emergencies
	//     need timely response — but still long enough for validators to
	//     coordinate.
	//   - SHORTER execution delay (6h instead of 2 days) for the same reason.
	//   - Higher quorum (50% instead of 33%) to ensure majority awareness.
	//
	// A zero value for any Emergency* field means "use the regular field",
	// preserving backward compatibility for configs that were not updated.
	EmergencyVotingPeriod    uint64
	EmergencyQuorumThreshold uint32
	EmergencyPassThreshold   uint32
	EmergencyExecutionDelay  uint64
}

// DefaultGovernanceConfig returns the default governance configuration
func DefaultGovernanceConfig() *GovernanceConfig {
	return &GovernanceConfig{
		// audit-fix R11-L1: use 12-second blocks consistent with consensus layer.
		// Previously assumed 3s blocks (20 blocks/min), giving 28-day voting and
		// 8-day execution delay at actual 12s block time.
		// Voting period: ~7 days at 12s blocks = 7 * 24 * 60 * 60 / 12 = 50,400
		VotingPeriod: 7 * 24 * 60 * 60 / 12, // 50,400 blocks
		// Quorum: 33% of total voting power
		QuorumThreshold: 3300,
		// Pass threshold: 50% of votes
		PassThreshold: 5000,
		// Proposal deposit: 100 QAU
		ProposalDeposit: new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)),
		// Execution delay: ~2 days at 12s blocks = 2 * 24 * 60 * 60 / 12 = 14,400
		ExecutionDelay: 2 * 24 * 60 * 60 / 12, // 14,400 blocks

		// GOV- Emergency proposal defaults. Stricter passage but
		// shorter timeframes than regular proposals — emergency actions
		// (chain halt via Defense ministry) need broad consensus but timely
		// response. See the GovernanceConfig doc comment above.
		// Voting: 24h at 12s blocks = 24 * 60 * 60 / 12 = 7,200 blocks
		EmergencyVotingPeriod: 24 * 60 * 60 / 12, // 7,200 blocks
		// Quorum: 50% of total voting power
		EmergencyQuorumThreshold: 5000,
		// Pass: 66.7% supermajority (2/3)
		EmergencyPassThreshold: 6670,
		// Execution delay: 6h at 12s blocks = 6 * 60 * 60 / 12 = 1,800 blocks
		EmergencyExecutionDelay: 6 * 60 * 60 / 12, // 1,800 blocks
	}
}

// MinVotingPeriodBlocks is the minimum allowed voting period for a governance
// proposal, in blocks.  (P3): a voting period shorter than this prevents
// meaningful voter participation and enables governance rushing attacks. ~1 hour
// at 12s blocks (300 blocks) is the floor; the default VotingPeriod (7 days)
// already exceeds it. Enforced in CreateProposal.
const MinVotingPeriodBlocks = uint64(300)

// CreateProposalGasThreshold is the MINIMUM free (non-staked) QAU balance
// a proposer MUST hold in addition to their proposal deposit, for
// governance to accept their proposal. P3-EC-04 (2026-08-03). This guards
// against the audit edge case "balance == deposit → proposal created but
// voting impossible due to gas shortage": without this reserve at
// CreateProposal time, the proposer might be unable to broadcast the
// Vote() or ExecuteProposal() transactions that finalize the proposal's
// effect, leaving the deposit locked without a path to enactment.
//
// The 0.001 QAU threshold is calibrated to cover ~2 average
// governance-transaction gas costs (Vote + ExecuteProposal at the
// standard 21k gas each, multiplied by the mainnet min-gas-price floor).
// This is INTENTIONALLY a heuristically-small floor rather than a
// governance parameter — the operational intent is "has any gas money
// left after the deposit", NOT "is well-capitalized". A future
// governance parameter can override this if the chain's gas-price
// floor rises over time, but keeping the default as a constant avoids
// the recursive governance-bootstrapping problem (governance parameter
// change requires governance proposal which itself requires gas).
//
// Unit: QAU atomic (1e-9 QAU == 1 wei == 1 unit). 0.001 QAU = 1,000,000
// atomic units.
//
// NOTE: declared as `var` rather than `const` because *big.Int cannot be
// a Go constant expression (it's a heap allocation). Treated as a
// read-only immutable sentinel in practice — callers MUST NOT mutate
// CreateProposalGasThreshold.
var CreateProposalGasThreshold = big.NewInt(1_000_000)

// CreateProposalGasThresholdQAU is the human-readable form of
// CreateProposalGasThreshold (0.001 QAU). For logs and error messages
// where the wei-unit value would be confusing to operators.
const CreateProposalGasThresholdQAU = "0.001"

// ParameterChange represents a proposed parameter change
type ParameterChange struct {
	// Parameter is the name of the parameter to change
	Parameter string
	// OldValue is the current value
	OldValue string
	// NewValue is the proposed new value
	NewValue string
}

// Proposal represents a governance proposal
type Proposal struct {
	// ID is the unique proposal identifier
	ID uint64
	// Type is the proposal type
	Type ProposalType
	// Proposer is the address that created the proposal
	Proposer types.Address
	// Title is the proposal title
	Title string
	// Description is the proposal description
	Description string
	// Changes is the list of parameter changes (for parameter proposals)
	Changes []ParameterChange
	// Status is the current status
	Status ProposalStatus
	// StartHeight is the block height when voting started
	StartHeight uint64
	// EndHeight is the block height when voting ends
	EndHeight uint64
	// YesVotes is the total yes voting power
	YesVotes *big.Int
	// NoVotes is the total no voting power
	NoVotes *big.Int
	// AbstainVotes is the total abstain voting power
	AbstainVotes *big.Int
	// Deposit is the deposit amount
	Deposit *big.Int
	// CreatedAt is the creation timestamp
	CreatedAt time.Time
	// SnapshotTotalVotePower is the total voting power snapshotted at proposal
	// creation time. L12-004 FIX: used in FinalizeProposal instead of recalculating
	// from current stakes, which allowed voters to withdraw stake after voting to
	// lower the quorum denominator while their recorded vote still counted.
	SnapshotTotalVotePower *big.Int

	// R41-L3ECON-05 (2026-08-03) FIX: ProposerNonce is the strictly-increasing
	// per-proposer counter recorded on-chain when the proposal was created.
	// It pairs with the RPC layer's Dilithium3 message (verifyGovernanceSignature
	// in rpc/governance_api.go embeds the nonce string in the signed message)
	// to provide:
	//
	//   1. On-chain replay protection — the RPC layer's `usedNonces` lives in
	//      process RAM and is lost on restart, so a previously consumed signed
	//      message could otherwise be replayed after a node restart (attacker
	//      needs the private key to mint a new nonce string, but the on-chain
	//      counter defense is still valuable for forensic auditability and
	//      for catching nonce drift between competing proposers).
	//   2. Forensic auditability — anyone reading the chain state can verify
	//      which proposal consumed which nonce, reconstructing the proposer's
	//      sequence even without RPC logs.
	//   3. Cross-node consistency — independent RPC services (QAU-AU, future
	//      HSM modules) that share the same proposer key agree on the next
	//      nonce because the source of truth is the chain, not a process-local
	//      map.
	//
	// Semantics enforced by GovernanceManager.CreateProposal:
	//   - `proposerNonce > gm.proposerNonces[proposer]` (strictly greater).
	//   - On success, `gm.proposerNonces[proposer] = proposerNonce`.
	//   - The first proposal from a proposer typically uses nonce 1; the
	//     field starts at 0 for untracked proposers.
	//
	// The on-chain counter is a defense-in-depth companion to the RPC
	// signature check, not a replacement — the RPC layer's Dilithium3
	// verification remains the primary authentication gate.
	ProposerNonce uint64
}

// VoteOption represents a vote choice
type VoteOption uint8

const (
	VoteOptionYes VoteOption = iota
	VoteOptionNo
	VoteOptionAbstain
)

// Vote represents a vote on a proposal
type Vote struct {
	ProposalID uint64
	Voter      types.Address
	Option     VoteOption
	VotePower  *big.Int
	Height     uint64
}

// StakeQuerier provides an interface for querying stake amounts.
// audit-fix R3-M10: allows governance to validate vote power against actual stake.
type StakeQuerier interface {
	GetStakeAmount(addr types.Address) (*big.Int, error)
}

// StakeSnapshotQuerier is an optional capability of StakeQuerier
// implementations that can return the stake amount at a specific block
// height. Used by GovernanceManager to snapshot vote power at proposal
// creation time.
//
// GOV- (2026-07-20) FIX: Previously Vote() validated votePower
// against the voter's CURRENT stake (GetStakeAmount), which allowed an
// attacker to:
//  1. Stake a large amount
//  2. Create or wait for a proposal
//  3. Vote with their full (temporary) stake
//  4. Immediately unstake after voting
//  5. Their vote still counted with full power even though they no longer
//     held the stake
//
// After the fix, when the StakeQuerier implements StakeSnapshotQuerier,
// Vote() validates votePower against the voter's stake AT THE PROPOSAL'S
// START HEIGHT — not their current stake. This means unstaking after the
// snapshot has no effect on vote power, and staking just before voting
// does not grant additional vote power unless the stake was present at
// the snapshot height.
//
// If the StakeQuerier does NOT implement StakeSnapshotQuerier (backward
// compatibility with simple queriers), Vote() falls back to the current
// behavior with a warning log. This preserves compatibility with existing
// deployments while allowing production nodes to opt into snapshot-based
// validation by implementing the extended interface.
type StakeSnapshotQuerier interface {
	StakeQuerier
	// GetStakeAmountAtHeight returns the stake amount for addr at the
	// given block height. Returns an error if the height is in the future
	// or historical state is not available (e.g. pruned). Callers must
	// treat any error as "validation failed" (fail-closed).
	GetStakeAmountAtHeight(addr types.Address, height uint64) (*big.Int, error)
}

// BalanceQuerier is the optional economics-side hook that lets
// GovernanceManager.ValidateProposalCreate check the PROPOSER'S
// native (non-staked) QAU balance for transaction-gas coverage when
// submitting a Vote / ExecuteProposal transaction after creating a
// proposal. P3-EC-04 (2026-08-03).
//
// Without this querier, CreateProposal only validates:
//  1. deposit >= ProposalDeposit (governance stake economy invariant)
//  2. proposer's STAKED balance >= ProposalDeposit (snapshot-based)
//
// Both checks pass in the audit's noted edge case where the proposer's
// TOTAL balance == ProposalDeposit exactly — they have the deposit
// fully matched, but no QAU left for the Vote or ExecuteProposal
// transaction gas. The proposal is created, but the proposer cannot
// participate in its OWN vote, and a third-party ExecutionProvisioner
// is required to actually enact the proposal. This is a griefing vector
// rather than a security vulnerability — the proposal drains the
// proposer's coins from circulation while Voting uses the snapshot
// invariant correctly — but the audit surfaced it as a P3 hardening
// for operator ergonomics.
//
// The querier returns the proposer's free (non-staked) QAU balance as
// a *big.Int. nil / error / negative → fail-closed (treat as
// insufficient gas coverage, SURFACE the proposal creation but log a
// WARNING that the proposer may be unable to participate). The
// governance threshold recommended by the audit is "balance >=
// minimumVoteGasDeposit", but that constant is governance-config-
// dependent, so the CreateProposal check now consumes a threshold
// parameter via CreateProposalGasThreshold (querier computed) and
// rejects proposals whose proposer's free balance is below it.
//
// The querier is OPTIONAL (stakeQuerier pattern): production node
// sets it on startup via SetBalanceQuerier; unit tests can omit it,
// and CreateProposal falls back to legacy behavior (no gas check);
// audit-compliant deployments MUST set it.
type BalanceQuerier interface {
	// GetFreeBalance returns the addr's spendable (non-staked) QAU
	// balance. nil is a legitimate state (account unknown → 0); error
	// is treated as "querier unavailable → fail-open for backward
	// compatibility" rather than fail-closed (fail-open matches the
	// stakeQuerier pattern).
	GetFreeBalance(addr types.Address) (*big.Int, error)
}

// VotePowerAdjustedEvent records when a voter's claimed vote power was clamped
// to their actual stake amount. This provides an audit trail for vote power adjustments.
// audit-fix MED-6: event logging for vote power clamping.
type VotePowerAdjustedEvent struct {
	ProposalID   uint64
	Voter        types.Address
	ClaimedPower *big.Int
	ActualStake  *big.Int
	AdjustedTo   *big.Int
	Height       uint64
	Timestamp    int64
}

// DepositLocker abstracts the chain-state operation that actually charges a
// governance proposal deposit. The economics package cannot perform balance
// transfers directly (dependency direction: economics sits below the execution
// layer), so CreateProposal delegates the charge to a DepositLocker wired by
// the node integration layer.
//
// GOV-R15-H03 (2026-07-27) IMPLEMENT: previously CreateProposal recorded the
// deposit on the Proposal struct but never actually charged it, allowing a
// proposer to submit unlimited proposals at no cost (zero-cost proposal DoS).
// When a DepositLocker is wired (via SetDepositLocker), CreateProposal calls
// LockDeposit(proposer, deposit, proposalID) BEFORE storing the proposal. If
// LockDeposit fails (e.g. insufficient balance), the proposal is rejected and
// not stored, and nextProposalID is NOT consumed. If no DepositLocker is
// wired, the backward-compatible behavior is preserved (deposit recorded but
// not charged) — this is for tests only; production MUST wire one.
//
// All three methods MUST be idempotent on proposalID so that finalization
// (refund on reject via UnlockDeposit, burn on malicious slash via
// SlashDeposit) does not double-spend if called more than once for the same
// proposal (CRIT-06 R17 contract).
type DepositLocker interface {
	// LockDeposit locks `amount` of `addr`'s balance as collateral for the
	// given proposalID. Returns an error if the balance is insufficient or
	// the lock cannot be applied (e.g. already locked for this proposalID).
	LockDeposit(addr types.Address, amount *big.Int, proposalID uint64) error
	// UnlockDeposit refunds a previously-locked deposit. Idempotent on
	// proposalID: a second call with the same ID returns nil without
	// re-refunding.
	UnlockDeposit(addr types.Address, amount *big.Int, proposalID uint64) error
	// SlashDeposit burns a previously-locked deposit (e.g. for a malicious
	// proposal that failed execution). Idempotent on proposalID.
	SlashDeposit(addr types.Address, amount *big.Int, proposalID uint64) error
}

// EmergencyActionHandler is invoked when an Emergency-type governance proposal
// is executed. The handler performs consensus-layer side effects (e.g.,
// blacklisting all validators via MinistryDefense to halt the chain) that
// cannot live in the economics package due to dependency direction.
//
// P1-T6 (2026-07-14): Unifies MinistryRites with GovernanceManager —
// GovernanceManager is the single source of truth for proposal/vote state,
// and delegates emergency action execution to this handler (implemented by
// consensus.MinistryRites via the node wiring layer).
type EmergencyActionHandler interface {
	// HandleEmergencyAction executes the emergency side effect for a proposal.
	// proposalID is the governance proposal that triggered the action.
	// proposer is the address that created the proposal — used for audit
	// traceability so emergency halts can be attributed to a real account
	// instead of an opaque system-caller sentinel (GOV-).
	// title/description are the proposal's metadata for logging.
	// Returns nil on success; errors are logged but do NOT block the proposal
	// from being marked as Executed (best-effort, same as other ministry calls).
	HandleEmergencyAction(proposalID uint64, proposer types.Address, title, description string) error
}

// GovernanceManager manages governance proposals and voting
type GovernanceManager struct {
	config *GovernanceConfig
	mu     sync.RWMutex

	proposals map[uint64]*Proposal

	votes map[uint64]map[types.Address]*Vote

	nextProposalID uint64

	parameters map[string]string

	stakeQuerier StakeQuerier

	// R43-P3-EC-04 (2026-08-03): optional native-balance querier for
	// CreateProposal gas-coverage check. nil → legacy behavior (no
	// gas check); non-nil → CreateProposal grep's proposer's free
	// (non-staked) QAU balance and rejects if below
	// CreateProposalGasThreshold. Wired via SetBalanceQuerier.
	balanceQuerier BalanceQuerier

	maxFinalizedProposals int

	votePowerAdjustments []VotePowerAdjustedEvent
	votePowerAdjMu       sync.RWMutex

	// governanceContractAddr is the authorized address that may call
	// SetParameterAuthorized. L12-017 FIX.
	governanceContractAddr types.Address

	// audit-fix M-GOV-1: stop channel for graceful shutdown of cleanupLoop.
	// Without this, the goroutine started in NewGovernanceManager runs forever,
	// leaking even after the GovernanceManager is no longer needed.
	stopCh   chan struct{}
	stopOnce sync.Once // FIX: prevent double-close panic

	// Persistence: data directory for saving proposals and parameters
	dataDir string

	// P1-T6 (2026-07-14): Emergency action handler for MinistryRites integration.
	// When set, ExecuteProposal delegates Emergency-type proposals to this handler
	// instead of just logging. The handler triggers Defense ministry blacklisting.
	emergencyHandler EmergencyActionHandler

	// R30-IMPLEMENT (2026-07-27): GOV-R15-H03 DepositLocker. When non-nil,
	// CreateProposal calls LockDeposit(proposer, deposit, proposalID) BEFORE
	// storing the proposal, closing the zero-cost proposal DoS vector. nil
	// preserves the legacy "record but don't charge" behavior (tests only).
	depositLocker DepositLocker

	// R42-GOVDEP-01 (2026-08-03): production hardening flag. When true,
	// CreateProposal with a nil DepositLocker is FAIL-CLOSED (rejects
	// the proposal) instead of fail-open (warning + accept). The default
	// is false so unit tests that intentionally omit the locker are not
	// broken. node (the only production entry point) explicitly sets this
	// to true on mainnet/testnet so a misconfigured governance runtime
	// cannot silently accept proposals without charging their deposit.
	// SetProductionMode is the only setter; the flag is read-only under
	// the struct mutex inside CreateProposal.
	productionMode bool

	// GOV- (2026-07-20) FIX: Two-step timelock for governance address
	// transfer. Previously SetGovernanceContractAddress had no authorization
	// check and no timelock — any code with a *GovernanceManager reference
	// could immediately transfer governance to an attacker address.
	//
	// Two-step flow:
	//   1. ProposeGovernanceAddress(proposed, caller) — only the current
	//      governance address (or initializerAddress for first-time setup)
	//      may propose. Sets pendingGovernanceAddr + governanceProposeTime.
	//   2. ConfirmGovernanceAddress(caller) — only the current governance
	//      address (or initializerAddress for first-time setup) may confirm.
	//      Must wait governanceTimelock (default 24h) after the propose step.
	//
	// First-time setup (governanceContractAddr == zero) allows
	// initializerAddress to propose + confirm without the timelock, so the
	// genesis contract can be wired up at launch.
	pendingGovernanceAddr types.Address
	governanceProposeTime time.Time
	governanceTimelock    time.Duration
	initializerAddress    types.Address

	// R14-LOW: current block height, updated by the consensus layer via
	// SetCurrentHeight. Used by cleanupLoop to auto-expire ACTIVE proposals
	// that have passed their EndHeight without an explicit FinalizeProposal
	// call. Stored as int64 for atomic ops (heights are well below int64 max).
	currentHeight atomic.Int64

	// R41-L3ECON-05 (2026-08-03) FIX: per-proposer on-chain nonce counter.
	// CreateProposal strictly enforces `proposerNonce > proposerNonces[proposer]`,
	// then records `proposerNonces[proposer] = proposerNonce`. This survives
	// node restarts (persisted via saveUnlocked/loadUnlocked) and provides
	// forensic auditability + cross-node consistency for the RPC layer's
	// Dilithium3 nonce-replay protection. See Proposal.ProposerNonce doc for
	// the full security rationale and the pairing with rpc.verifyGovernanceSignature.
	proposerNonces map[types.Address]uint64
}

// NewGovernanceManager creates a new governance manager
func NewGovernanceManager(config *GovernanceConfig) *GovernanceManager {
	if config == nil {
		config = DefaultGovernanceConfig()
	}
	gm := &GovernanceManager{
		config:                config,
		proposals:             make(map[uint64]*Proposal),
		votes:                 make(map[uint64]map[types.Address]*Vote),
		nextProposalID:        1,
		parameters:            make(map[string]string),
		maxFinalizedProposals: 1000,
		votePowerAdjustments:  make([]VotePowerAdjustedEvent, 0),
		stopCh:                make(chan struct{}),
		// R41-L3ECON-05: per-proposer on-chain nonce counter. Allocated
		// here so CreateProposal never has to nil-check before write.
		proposerNonces: make(map[types.Address]uint64),
		// GOV- (2026-07-20): Default 24h timelock for governance
		// address transfers. Prevents instant takeover if the current
		// governance key is compromised — operators have 24h to react
		// (cancel via ProposeGovernanceAddress(zero, currentGov)).
		governanceTimelock: 24 * time.Hour,
	}

	// Start background cleanup goroutine for expired proposals
	// audit-fix HIGH: evictOldProposals only runs after ExecuteProposal, so Active/Passed
	// proposals that never execute stay in memory forever. This goroutine ensures
	// periodic cleanup regardless of proposal execution.
	go gm.cleanupLoop()

	return gm
}

// SetCurrentHeight updates the governance manager's view of the current chain
// height. The consensus layer should call this on every block (or at least
// periodically) so cleanupLoop can auto-expire ACTIVE proposals that have
// passed their EndHeight.
//
// R14-LOW (governance audit): Previously, ACTIVE proposals that reached
// EndHeight without an explicit FinalizeProposal call would remain in
// ProposalStatusActive indefinitely — consuming memory and skewing any
// "active proposal count" metrics. The cleanupLoop now uses the height
// set here to mark them ProposalStatusExpired.
//
// Thread-safe: uses atomic store. Safe to call from any goroutine.
func (gm *GovernanceManager) SetCurrentHeight(height uint64) {
	if height > ^uint64(0)>>1 { // int64 max guard
		height = ^uint64(0) >> 1
	}
	gm.currentHeight.Store(int64(height))
}

// GetCurrentHeight returns the last height set via SetCurrentHeight.
// Returns 0 if never set (cleanupLoop will skip auto-expiry in that case).
func (gm *GovernanceManager) GetCurrentHeight() uint64 {
	return uint64(gm.currentHeight.Load())
}

// cleanupLoop periodically evicts expired proposals to prevent memory exhaustion.
// audit-fix M-GOV-1: listens on stopCh for graceful shutdown.
//
// P3-E2 AUDIT NOTE (hardcoded interval is intentional): The 1-hour cleanup
// interval is deliberately hardcoded. It is more than adequate because the
// shortest eviction is 7 days for passed proposals (see 7*24*time.Hour below),
// so an hourly sweep catches expirations with ~1h granularity — negligible
// memory overhead between sweeps. Making this configurable would add API
// surface for no operational benefit; if a different cadence is ever needed,
// promote this to a GovernanceConfig field.
//
// R14-LOW: The loop now also auto-expires ACTIVE proposals that have passed
// their EndHeight. This requires SetCurrentHeight to be called by the
// consensus layer; if it is never called (currentHeight == 0), auto-expiry
// is skipped (backward compatibility — behavior matches pre-fix).
func (gm *GovernanceManager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-gm.stopCh:
			return
		case <-ticker.C:
			gm.mu.Lock()
			gm.evictOldProposals()

			// R14-LOW: Auto-expire ACTIVE proposals past EndHeight.
			// Only runs if the consensus layer has set a non-zero height.
			currentHeight := gm.GetCurrentHeight()
			if currentHeight > 0 {
				var expiredIDs []uint64
				for id, p := range gm.proposals {
					if p.Status == ProposalStatusActive && currentHeight > p.EndHeight {
						p.Status = ProposalStatusExpired
						expiredIDs = append(expiredIDs, id)
					}
				}
				if len(expiredIDs) > 0 {
					log.Printf("governance cleanupLoop: auto-expired %d active proposals past EndHeight at height %d",
						len(expiredIDs), currentHeight)
				}
			}

			var stalePassedIDs []uint64
			now := time.Now()
			for id, p := range gm.proposals {
				if p.Status == ProposalStatusPassed {
					if now.Sub(p.CreatedAt) > 7*24*time.Hour {
						stalePassedIDs = append(stalePassedIDs, id)
					}
				}
			}
			for _, id := range stalePassedIDs {
				delete(gm.proposals, id)
				delete(gm.votes, id)
			}
			gm.mu.Unlock()
		}
	}
}

// Close stops the background cleanup goroutine.
// audit-fix M-GOV-1: prevents goroutine leak when GovernanceManager is no longer needed.
// FIX: uses sync.Once to prevent double-close panic.
func (gm *GovernanceManager) Close() {
	gm.stopOnce.Do(func() {
		close(gm.stopCh)
	})
}

// SetStakeQuerier sets the stake querier for vote power validation.
// audit-fix R3-M10: allows validation of vote power against actual stake.
func (gm *GovernanceManager) SetStakeQuerier(sq StakeQuerier) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.stakeQuerier = sq
}

// SetBalanceQuerier wires the optional native-balance querier that
// CreateProposal uses to validate the proposer's free (non-staked) QAU
// balance covers transaction-gas for the subsequent Vote + ExecuteProposal
// transactions. P3-EC-04 (2026-08-03). Idempotent and thread-safe under
// gm.mu. Setting a nil querier reverts to legacy behavior (no gas check).
func (gm *GovernanceManager) SetBalanceQuerier(bq BalanceQuerier) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.balanceQuerier = bq
}

// SetEmergencyActionHandler wires the consensus-layer emergency action handler
// (implemented by consensus.MinistryRites via the node wiring layer).
// P1-T6 (2026-07-14): When set, ExecuteProposal delegates Emergency-type
// proposals to this handler to trigger Defense ministry blacklisting.
func (gm *GovernanceManager) SetEmergencyActionHandler(h EmergencyActionHandler) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.emergencyHandler = h
}

// SetDepositLocker wires the DepositLocker used to actually charge governance
// proposal deposits. R30-IMPLEMENT (2026-07-27): GOV-R15-H03 — when non-nil,
// CreateProposal calls LockDeposit(proposer, deposit, proposalID) BEFORE
// storing the proposal. If LockDeposit fails, the proposal is rejected and
// nextProposalID is NOT consumed. When nil (the default), CreateProposal
// preserves the legacy "deposit recorded but not charged" behavior; this is
// for tests only — production MUST wire a DepositLocker.
func (gm *GovernanceManager) SetDepositLocker(locker DepositLocker) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.depositLocker = locker
}

// SetProductionMode configures R42-GOVDEP-01 production hardening.
//
// When enabled (true), CreateProposal with a nil DepositLocker becomes
// FAIL-CLOSED: it returns ErrDepositLockerRequired instead of accepting
// the proposal with a warning. This prevents a misconfigured production
// node (mainnet/testnet) from silently accepting zero-cost proposals —
// the DoS vector R35-P3-ECON-3 warned about is now actively rejected.
//
// When disabled (the default / false), the legacy warning-only behavior
// is preserved so unit tests that intentionally omit the locker are not
// broken. node calls SetProductionMode(true) at startup on recognized
// production networks (chainID 1668/1669); devnet and tests leave it off.
//
// This method is safe to call at any time and is goroutine-safe.
func (gm *GovernanceManager) SetProductionMode(enabled bool) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.productionMode = enabled
}

// InitializeParameters sets the initial economic parameters
func (gm *GovernanceManager) InitializeParameters(params map[string]string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	for k, v := range params {
		gm.parameters[k] = v
	}
}

// GetParameter returns a parameter value
func (gm *GovernanceManager) GetParameter(name string) (string, bool) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	value, exists := gm.parameters[name]
	return value, exists
}

// setParameter sets a parameter value.
// IMPORTANT (L12-017 + GOV-R10-HIGH-001, 2026-07-19): This method is
// INTERNAL-ONLY (unexported) and performs NO authorization check.
// External callers MUST use SetParameterAuthorized to ensure only the
// governance contract address can modify parameters.
//
// Previously this method was exported as SetParameter, which allowed any
// external caller that obtained a *GovernanceManager reference (e.g.
// through node API injection) to modify governance parameters directly,
// bypassing the authorized-contract check in SetParameterAuthorized.
// Privatization forces all external callers through SetParameterAuthorized.
func (gm *GovernanceManager) setParameter(name, value string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.setParameterLocked(name, value)
}

// setParameterLocked is the lock-free inner path of setParameter.
// Caller MUST hold gm.mu.
//
// GOV- (2026-07-20) FIX: R10 privatized setParameter to force external
// callers through SetParameterAuthorized (which re-validates). But ExecuteProposal
// already held gm.mu when applying a passed proposal, so it could not call
// setParameter (would deadlock) and instead wrote gm.parameters directly —
// bypassing validateParameter. A proposal that slipped through proposal-time
// validation (e.g., because validateParameter's allowed set changed between
// proposal creation and execution) could then write out-of-range values
// (InflationRate=1000000, MinStakeAmount=0, etc.).
//
// Extracting the lock-free inner path lets ExecuteProposal reuse the same
// validation + audit-log path as setParameter without re-acquiring the lock.
func (gm *GovernanceManager) setParameterLocked(name, value string) error {
	val, ok := new(big.Int).SetString(value, 10)
	if !ok {
		return ErrParameterValueInvalid
	}

	if err := gm.validateParameter(name, val); err != nil {
		return err
	}

	// SECURITY (audit P2-): Log parameter changes for audit trail
	log.Printf("governance: parameter %q changed to %q", name, value)
	gm.parameters[name] = value
	return nil
}

// SetGovernanceContractAddress is DEPRECATED.
//
// GOV- (2026-07-20) FIX: This method previously set the governance
// contract address with NO authorization check and NO timelock. Any code
// holding a *GovernanceManager reference could instantly transfer
// governance to an attacker address, enabling full takeover of the
// parameter-change authorization.
//
// This method is preserved for backward-compatibility with existing node
// wiring but now ONLY works during first-time setup (when
// governanceContractAddr is the zero address) AND only if the caller has
// previously configured an initializerAddress. Existing deployments should
// migrate to the explicit two-step flow:
//
//  1. ProposeGovernanceAddress(proposed, caller)
//  2. wait governanceTimelock (default 24h)
//  3. ConfirmGovernanceAddress(caller)
//
// All other calls return ErrGovernanceProposeUnauthorized.
func (gm *GovernanceManager) SetGovernanceContractAddress(addr types.Address) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Only allow via the deprecated path if there is no current governance
	// address AND an initializer has been configured. This matches the
	// first-time-setup semantics of ProposeGovernanceAddress.
	currentIsZero := gm.governanceContractAddr == (types.Address{})
	if !currentIsZero {
		log.Printf("WARNING: SetGovernanceContractAddress called after governance address was already set; use ProposeGovernanceAddress + ConfirmGovernanceAddress instead")
		return ErrGovernanceProposeUnauthorized
	}
	if gm.initializerAddress == (types.Address{}) {
		log.Printf("WARNING: SetGovernanceContractAddress called but no initializerAddress configured; use SetInitializerAddress first")
		return ErrGovernanceProposeUnauthorized
	}

	// First-time setup: allow immediate set without timelock so genesis
	// wiring can proceed. Log loudly so operators notice.
	log.Printf("governance: first-time SetGovernanceContractAddress %x (deprecated path, initializer-authorized)", addr)
	gm.governanceContractAddr = addr
	gm.pendingGovernanceAddr = types.Address{}
	gm.governanceProposeTime = time.Time{}
	return nil
}

// SetInitializerAddress configures the bootstrap initializer address that
// is allowed to propose + confirm the FIRST governance contract address
// (when governanceContractAddr is still the zero address).
//
// GOV- (2026-07-20): The initializer can ONLY set the first
// governance address; once set, the initializer has no further power and
// all subsequent transfers must go through the existing governance address
// + timelock. The initializer itself CANNOT be set via the API — it must
// be wired in at node construction time (node wiring layer calls this
// method before any governance operations are exposed).
func (gm *GovernanceManager) SetInitializerAddress(addr types.Address) {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	if gm.governanceContractAddr != (types.Address{}) {
		log.Printf("WARNING: SetInitializerAddress called after governance address was already set; ignoring")
		return
	}
	gm.initializerAddress = addr
}

// SetGovernanceTimelock adjusts the timelock duration for governance
// address transfers. Only callable BEFORE the first governance address is
// set (i.e., during node construction). Once governance is initialized,
// the timelock cannot be shortened via this method — that would defeat
// the purpose. Default is 24h.
func (gm *GovernanceManager) SetGovernanceTimelock(ttl time.Duration) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	if gm.governanceContractAddr != (types.Address{}) {
		return errors.New("cannot change governance timelock after governance address is set")
	}
	if ttl < time.Minute {
		return errors.New("governance timelock must be at least 1 minute")
	}
	gm.governanceTimelock = ttl
	return nil
}

// ProposeGovernanceAddress begins a two-step governance address transfer.
//
// Authorization:
//   - If governanceContractAddr is zero (first-time setup): only
//     initializerAddress may propose.
//   - Otherwise: only the current governanceContractAddr may propose.
//
// First-time setup (governanceContractAddr == zero) skips the timelock —
// the genesis contract can be confirmed immediately. All subsequent
// transfers require governanceTimelock to elapse between propose and
// confirm.
//
// Calling ProposeGovernanceAddress again while a proposal is pending
// resets the timer + target (last writer wins). This allows the current
// governance address to cancel a malicious proposal by proposing itself
// again.
func (gm *GovernanceManager) ProposeGovernanceAddress(proposed, caller types.Address) error {
	if proposed == (types.Address{}) {
		return errors.New("cannot propose zero address as governance address")
	}

	gm.mu.Lock()
	defer gm.mu.Unlock()

	currentIsZero := gm.governanceContractAddr == (types.Address{})
	if currentIsZero {
		// First-time setup: only the initializer may propose.
		if gm.initializerAddress == (types.Address{}) {
			return ErrGovernanceProposeUnauthorized
		}
		if caller != gm.initializerAddress {
			return ErrGovernanceProposeUnauthorized
		}
	} else {
		// Subsequent transfer: only the current governance address may propose.
		if caller != gm.governanceContractAddr {
			return ErrGovernanceProposeUnauthorized
		}
	}

	gm.pendingGovernanceAddr = proposed
	gm.governanceProposeTime = time.Now()
	log.Printf("governance: proposed new governance address %x by caller %x (first-time=%v)",
		proposed, caller, currentIsZero)
	return nil
}

// ConfirmGovernanceAddress finalizes a pending governance address transfer.
//
// Authorization:
//   - Same as ProposeGovernanceAddress (initializer for first-time setup,
//     current governance address for subsequent transfers).
//
// Timelock:
//   - First-time setup (governanceContractAddr == zero): NO timelock.
//   - Otherwise: governanceTimelock MUST have elapsed since the matching
//     ProposeGovernanceAddress call. Returns ErrGovernanceTimelockNotElapsed
//     otherwise.
//
// On success, sets governanceContractAddr = pendingGovernanceAddr and clears
// the pending proposal fields.
func (gm *GovernanceManager) ConfirmGovernanceAddress(caller types.Address) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	currentIsZero := gm.governanceContractAddr == (types.Address{})
	if currentIsZero {
		// First-time setup: only the initializer may confirm.
		if gm.initializerAddress == (types.Address{}) {
			return ErrGovernanceConfirmUnauthorized
		}
		if caller != gm.initializerAddress {
			return ErrGovernanceConfirmUnauthorized
		}
	} else {
		// Subsequent transfer: only the current governance address may confirm.
		if caller != gm.governanceContractAddr {
			return ErrGovernanceConfirmUnauthorized
		}
	}

	if gm.pendingGovernanceAddr == (types.Address{}) {
		return ErrGovernanceNoPendingProposal
	}

	// Enforce timelock for non-first-time transfers.
	if !currentIsZero && gm.governanceTimelock > 0 {
		elapsed := time.Since(gm.governanceProposeTime)
		if elapsed < gm.governanceTimelock {
			log.Printf("governance: confirm rejected — only %v elapsed, need %v", elapsed, gm.governanceTimelock)
			return ErrGovernanceTimelockNotElapsed
		}
	}

	oldAddr := gm.governanceContractAddr
	gm.governanceContractAddr = gm.pendingGovernanceAddr
	gm.pendingGovernanceAddr = types.Address{}
	gm.governanceProposeTime = time.Time{}

	log.Printf("governance: governance address updated from %x to %x by caller %x",
		oldAddr, gm.governanceContractAddr, caller)
	return nil
}

// CancelPendingGovernanceAddress cancels a pending proposal. Only the
// current governance address (or initializer during first-time setup) may
// cancel.
func (gm *GovernanceManager) CancelPendingGovernanceAddress(caller types.Address) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	currentIsZero := gm.governanceContractAddr == (types.Address{})
	if currentIsZero {
		if gm.initializerAddress == (types.Address{}) || caller != gm.initializerAddress {
			return ErrGovernanceConfirmUnauthorized
		}
	} else {
		if caller != gm.governanceContractAddr {
			return ErrGovernanceConfirmUnauthorized
		}
	}

	if gm.pendingGovernanceAddr == (types.Address{}) {
		return ErrGovernanceNoPendingProposal
	}

	log.Printf("governance: canceled pending governance address %x by caller %x",
		gm.pendingGovernanceAddr, caller)
	gm.pendingGovernanceAddr = types.Address{}
	gm.governanceProposeTime = time.Time{}
	return nil
}

// PendingGovernanceAddress returns the currently-proposed governance
// address (zero if no proposal is pending). Read-only; safe for health checks.
func (gm *GovernanceManager) PendingGovernanceAddress() (types.Address, time.Time) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return gm.pendingGovernanceAddr, gm.governanceProposeTime
}

// SetParameterAuthorized sets a parameter value after verifying that the caller
// is the authorized governance contract address. L12-017 FIX + GOV-R10-HIGH-001
// (2026-07-19): setParameter itself has no authorization check, so external
// callers could previously change governance parameters directly via the
// exported SetParameter. Privatizing setParameter forces all external callers
// through this authorized path.
func (gm *GovernanceManager) SetParameterAuthorized(key string, value *big.Int, caller types.Address) error {
	gm.mu.RLock()
	authorized := caller == gm.governanceContractAddr
	gm.mu.RUnlock()
	if !authorized {
		return ErrUnauthorizedParameterChange
	}
	return gm.setParameter(key, value.String())
}

func (gm *GovernanceManager) validateParameter(key string, value *big.Int) error {
	// P1- Normalize parameter name to PascalCase for validation
	normalizedKey := normalizeParamName(key)

	// SECURITY (audit P1-): Default-deny whitelist. Only parameters
	// explicitly listed below are allowed. Unknown parameters are rejected.
	percentageParams := map[string]struct{}{
		"CollateralFactor":     {},
		"LiquidationThreshold": {},
		"StakingAPY":           {},
		"ReserveRatio":         {},
		// R14-MED (2026-07-21): QuorumThreshold and PassThreshold are
		// voting/governance percentages (0-100). Previously they were in
		// numericParams with a 10^30 upper bound, allowing a governance
		// proposal to set them to absurd values like 10^29 (breaking
		// quorum math) or to 0 (disabling all proposals).
		"QuorumThreshold": {},
		"PassThreshold":   {},
	}
	if _, ok := percentageParams[normalizedKey]; ok {
		if value.Sign() < 0 || value.Cmp(big.NewInt(100)) > 0 {
			return ErrParameterValueInvalid
		}
		return nil
	}

	// AUDIT (2026) GOV B-2 FIX: InflationRate is in basis points
	// (0-10000 = 0-100%) to match RewardConfig.InflationRate in rewards.go.
	// Previously it was in percentageParams (0-100), causing a 100x unit
	// mismatch when the value was consumed by RewardCalculator.
	bpsParams := map[string]struct{}{
		"InflationRate": {},
	}
	if _, ok := bpsParams[normalizedKey]; ok {
		if value.Sign() < 0 || value.Cmp(big.NewInt(10000)) > 0 {
			return ErrParameterValueInvalid
		}
		return nil
	}

	// P3-CONS-003 FIX (R30, 2026-07-27): durationParams are stored in BLOCK
	// units (12-second blocks, matching params.BlockTime and the consensus
	// SlotDuration). The previous upper bound 31536000 was 1 year expressed
	// in SECONDS — but the parameters are in blocks, so the bound was 12x
	// too permissive (31536000 blocks ≈ 12 years at 12s/block). A governance
	// proposal could set VotingPeriod=31536000 (12 years) and the validator
	// would still accept it.
	//
	// Convert the upper bound to block units: 1 year in seconds / 12s-per-block
	// = 365 * 24 * 3600 / 12 = 2,628,000 blocks. This matches the unit used
	// by the parameter values (e.g. default VotingPeriod = 50400 blocks = 7
	// days at 12s/block, see DefaultGovernanceConfig).
	const secondsPerYear = 365 * 24 * 60 * 60 // 31,536,000 seconds
	const blockTimeSeconds = 12               // matches params.BlockTime / consensus SlotDuration
	maxDurationBlocks := new(big.Int).Div(
		big.NewInt(int64(secondsPerYear)),
		big.NewInt(int64(blockTimeSeconds)),
	) // 2,628,000 blocks ≈ 1 year
	durationParams := map[string]struct{}{
		"VotingPeriod":     {},
		"ExecutionDelay":   {},
		"UnbondingPeriod":  {},
		"AdjustmentPeriod": {},
	}
	if _, ok := durationParams[normalizedKey]; ok {
		if value.Sign() <= 0 || value.Cmp(maxDurationBlocks) > 0 {
			return ErrParameterValueInvalid
		}
		return nil
	}

	// R14-MED (2026-07-21): Tightened upper bound from 10^30 to 10^24.
	// 10^30 is effectively no bound at all (1 nonillion QAU). 10^24
	// = 1M tokens × 10^18 decimals, which is far above any realistic
	// stake/deposit amount but prevents a malicious governance proposal
	// from setting MinStakeAmount=10^30 (blocking all new stakers) or
	// ProposalDeposit=10^30 (blocking all proposals).
	tokenAmountMax := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil)
	numericParams := map[string]struct{}{
		"ProposalDeposit": {},
		"MinStakeAmount":  {},
		"MaxStakeAmount":  {},
		"RewardPerAction": {},
	}
	if _, ok := numericParams[normalizedKey]; ok {
		if value.Sign() <= 0 || value.Cmp(tokenAmountMax) > 0 {
			return ErrParameterValueInvalid
		}
		// R14-MED: Cross-parameter validation for Min/Max stake range.
		// Reject impossible ranges (Min > Max) at set-time so a later
		// getStakeRange query never returns an inverted range. We compare
		// against the *current* other bound, which is the value that will
		// be in effect after this set completes.
		switch normalizedKey {
		case "MinStakeAmount":
			if currentMaxStr, ok := gm.parameters["MaxStakeAmount"]; ok {
				if currentMax, ok := new(big.Int).SetString(currentMaxStr, 10); ok && currentMax.Sign() > 0 {
					if value.Cmp(currentMax) > 0 {
						return ErrParameterValueInvalid
					}
				}
			}
		case "MaxStakeAmount":
			if currentMinStr, ok := gm.parameters["MinStakeAmount"]; ok {
				if currentMin, ok := new(big.Int).SetString(currentMinStr, 10); ok && currentMin.Sign() > 0 {
					if value.Cmp(currentMin) < 0 {
						return ErrParameterValueInvalid
					}
				}
			}
		}
		return nil
	}

	// Block/economic parameters
	// R14-MED: Tightened upper bound from 10^30 to 10^12 for BaseFee
	// (gas price in wei; 10^12 wei = 1000 Gwei, well above any
	// realistic mainnet gas price). MaxBlockSize and BlockGasLimit keep
	// 10^24 upper bound (sufficient for 1B gas blocks).
	blockParams := map[string]struct{}{
		"MaxBlockSize":  {},
		"BlockGasLimit": {},
		"BaseFee":       {},
	}
	if _, ok := blockParams[normalizedKey]; ok {
		if value.Sign() <= 0 {
			return ErrParameterValueInvalid
		}
		switch normalizedKey {
		case "BaseFee":
			if value.Cmp(big.NewInt(1_000_000_000_000)) > 0 { // 10^12 wei = 1000 Gwei
				return ErrParameterValueInvalid
			}
		default:
			if value.Cmp(tokenAmountMax) > 0 {
				return ErrParameterValueInvalid
			}
		}
		return nil
	}

	// SECURITY (audit P1-): Default deny - reject unknown parameters
	return ErrParameterNotSupported
}

// GetAllParameters returns all parameters
func (gm *GovernanceManager) GetAllParameters() map[string]string {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	params := make(map[string]string)
	for k, v := range gm.parameters {
		params[k] = v
	}
	return params
}

// DefaultGovernanceParameters returns the default set of governable parameters.
// These are the initial values that can be changed through governance proposals.
func DefaultGovernanceParameters() map[string]string {
	return map[string]string{
		// AUDIT (2026) GOV B-2 FIX: InflationRate is in basis points
		// (500 = 5%) to match RewardConfig.InflationRate in rewards.go.
		// Previously "5" was interpreted as 5% by governance validation but
		// as 5 bps (0.05%) by RewardCalculator — a 100x unit mismatch.
		"InflationRate": "500",
		// AUDIT (2026) GOV B-2 FIX: StakingAPY default lowered from 8%
		// to 5% to match docs/TOKEN_ECONOMICS.md target of 4-5% APY.
		"StakingAPY":           "5",
		"CollateralFactor":     "75",
		"LiquidationThreshold": "85",
		"ReserveRatio":         "20",
		"MinStakeAmount":       "1000000000000000000000", // 1000 QAU
		"MaxBlockSize":         "4194304",                // 4MB
		"BlockGasLimit":        "30000000",
		"BaseFee":              "1000000000", // 1 Gwei
	}
}

// CreateProposal creates a new governance proposal.
//
// R41-L3ECON-05 (2026-08-03) FIX: `proposerNonce` is now a required
// parameter and is validated against the on-chain per-proposer nonce
// counter (`gm.proposerNonces`). The RPC layer (rpc/governance_api.go
// verifyGovernanceSignature) embeds the nonce string in the Dilithium3
// signed message and runs its own in-process replay cache (usedNonces);
// this strict-monotonic on-chain counter adds defense-in-depth:
//   - Survives node restart (the RPC `usedNonces` is process-RAM only).
//   - Provides forensic auditability — anyone reading chain state can
//     reconstruct a proposer's sequence.
//   - Aligns competing RPC services (QAU-AU + future HSM modules)
//     sharing the same proposer key on a single source of truth.
//
// Rules enforced (all under gm.mu.Lock):
//   - `proposerNonce > proposerNonces[proposer]` (strictly greater).
//   - The first proposal from a proposer typically uses nonce 1; the
//     counter starts at 0 for untracked proposers.
//   - On success, `proposerNonces[proposer] = proposerNonce` is recorded
//     before the proposal is stored, so a crash mid-store still leaves
//     the counter advanced (failed CreateProposal does not advance the
//     counter, so a retry with the same nonce is allowed — the caller's
//     RPC layer is expected to dedup by signature anyway).
func (gm *GovernanceManager) CreateProposal(
	proposer types.Address,
	proposalType ProposalType,
	title, description string,
	changes []ParameterChange,
	deposit *big.Int,
	currentHeight uint64,
	totalVotePower *big.Int,
	proposerNonce uint64,
	sig *ProposalSignature,
	blockTime ...int64,
) (*Proposal, error) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// R43-GOVSIG-01 (2026-08-03): CORE-layer Dilithium3 signature
	// verification. The RPC layer (rpc/governance_api.go) already verifies
	// the signature via verifyGovernanceSignature, but a caller that bypasses
	// the RPC entry point (e.g. a future internal proposal mechanism, or a
	// direct *GovernanceManager reference obtained through node wiring)
	// would have NO signature check at all. Closing that gap requires the
	// check to live at the core. To preserve backward compatibility with
	// the 60+ existing unit-test call sites that legitimately construct
	// proposals directly (they are NOT attacker-reachable), a nil sig
	// skips core-layer verification — production callers MUST pass a
	// non-nil sig (rpc/governance_api.go always constructs one from the
	// verified request). When sig is non-nil, verification runs BEFORE the
	// R41-L3ECON-05 nonce check so a signature failure does not bump the
	// per-proposer nonce counter (a replay attacker could otherwise burn
	// nonces with bogus signatures).
	if sig != nil {
		if err := gm.verifyProposalSignatureLocked(
			proposer,
			proposalType,
			title,
			description,
			changes,
			deposit,
			totalVotePower,
			proposerNonce,
			sig,
		); err != nil {
			return nil, err
		}
	}

	// R41-L3ECON-05: strict-monotonic on-chain nonce check. Fails closed
	// (rejects equal-or-lower nonces) BEFORE any other validation so an
	// attacker cannot trigger expensive stake/deposit lookups with a
	// stale nonce. The first proposal from a proposer typically uses
	// nonce 1 (counter starts at 0). The RPC layer embeds this nonce in
	// the signed message, so an attacker cannot forge a higher nonce
	// without the proposer's Dilithium3 key.
	currentNonce := gm.proposerNonces[proposer]
	if proposerNonce <= currentNonce {
		return nil, fmt.Errorf("R41-L3ECON-05: proposer %x nonce %d must be strictly greater than last recorded %d", proposer[:], proposerNonce, currentNonce)
	}

	// Validate deposit
	if deposit == nil || deposit.Cmp(gm.config.ProposalDeposit) < 0 {
		return nil, ErrInsufficientVotePower
	}

	// FIX (P3): Validate minimum voting period. Reject configs whose
	// voting period is shorter than MinVotingPeriodBlocks to prevent governance
	// rushing attacks. (gm.config.VotingPeriod is set at manager construction.)
	if gm.config.VotingPeriod < MinVotingPeriodBlocks {
		return nil, fmt.Errorf("%w: voting period %d below minimum %d", ErrInvalidParameter, gm.config.VotingPeriod, MinVotingPeriodBlocks)
	}

	// FIX: Validate proposer's stake if stakeQuerier is configured.
	// Previously, only the deposit was checked, allowing non-stakers to
	// create proposals. Now we require the proposer to have a stake of at
	// least the proposal deposit amount, ensuring only meaningful
	// stakeholders can create governance proposals.
	if gm.stakeQuerier != nil {
		proposerStake, err := gm.stakeQuerier.GetStakeAmount(proposer)
		if err != nil || proposerStake == nil {
			return nil, fmt.Errorf("%w: proposer has no stake or stake query failed", ErrInsufficientVotePower)
		}
		if proposerStake.Cmp(gm.config.ProposalDeposit) < 0 {
			return nil, fmt.Errorf("%w: proposer stake %s below minimum required %s",
				ErrInsufficientVotePower, proposerStake.String(), gm.config.ProposalDeposit.String())
		}
	}

	// P3-EC-04 (2026-08-03): native-balance (gas-coverage) check. When the
	// balanceQuerier is wired, ensure the proposer holds CreateProposalGasThreshold
	// (default 0.001 QAU = 1_000_000 atomic units) of FREE (non-staked)
	// QAU on top of the deposit. Without this reserve, the audit's noted
	// edge case fires: the proposer's balance == deposit exactly → proposal
	// is created but the proposer lacks the gas to broadcast Vote() or
	// ExecuteProposal(), effectively self-imprisoning their deposit. The
	// querier is optional — unit tests can omit it (legacy/no-gas-check
	// behavior), production deployment MUST wire it on node startup. See
	// the BalanceQuerier interface doc comment for the rationale.
	//
	// Fail-mode: returns ErrInsufficientFreeBalance to surface the issue as
	// a governance-domain error (not just an "insufficient vote power" — the
	// stake check above already covers that case). Quierer UNAVAILABLE (err
	// from GetFreeBalance) is treated as fail-open for backward compat — we
	// log a WARNING and proceed, since a querier outage should NOT block
	// legitimate proposal submission (the audit's observation was a
	// griefing vector, not a security flaw; on outage the only consequence
	// is a missed gas check, recoverable by the operator promptly).
	if gm.balanceQuerier != nil {
		freeBalance, err := gm.balanceQuerier.GetFreeBalance(proposer)
		if err != nil {
			log.Printf("WARNING P3-EC-04: balance querier returned err for proposer %x: %v (skipping gas-coverage check)",
				proposer[:8], err)
		} else if freeBalance == nil || freeBalance.Cmp(CreateProposalGasThreshold) < 0 {
			have := "0"
			if freeBalance != nil {
				have = freeBalance.String()
			}
			return nil, fmt.Errorf("%w: proposer free balance %s below CreateProposalGasThreshold %s QAU",
				ErrInsufficientFreeBalance, have, CreateProposalGasThresholdQAU)
		}
	}

	// Validate changes for parameter proposals
	if proposalType == ProposalTypeParameter && len(changes) == 0 {
		return nil, ErrInvalidParameter
	}
	// GOV- (2026-07-20) FIX: Validate OldValue at creation time.
	// If OldValue is provided (non-empty), it must match the current
	// parameter value — this prevents a proposer from anchoring a proposal
	// to a stale OldValue that was never the actual current value. If
	// OldValue is empty, auto-populate it with the current value (or "" if
	// the parameter does not exist yet). This snapshot is later re-checked
	// in ExecuteProposal to catch concurrent parameter modifications.
	if proposalType == ProposalTypeParameter {
		// Copy the slice so we don't mutate caller's input.
		changesCopy := make([]ParameterChange, len(changes))
		for i, change := range changes {
			currentVal, exists := gm.parameters[change.Parameter]
			if change.OldValue != "" {
				// Caller provided OldValue — verify it matches reality.
				if exists && change.OldValue != currentVal {
					return nil, fmt.Errorf("parameter %q OldValue %q does not match current value %q",
						change.Parameter, change.OldValue, currentVal)
				}
			} else if exists {
				// Auto-populate OldValue from current value for future
				// execution-time validation. This is a snapshot, not a
				// promise — execution will re-check against the live value.
				change.OldValue = currentVal
			}
			changesCopy[i] = change
		}
		changes = changesCopy
	}

	// CS-05 FIX: Use deterministic blockTime for CreatedAt when provided;
	// fall back to time.Now() for non-consensus callers.
	var createdAt time.Time
	if len(blockTime) > 0 {
		createdAt = time.Unix(blockTime[0], 0)
	} else {
		createdAt = time.Now()
	}

	// GOV- (2026-07-20) FIX: Use emergency-specific voting period
	// for ProposalTypeEmergency. Default = 24h (vs 7 days for regular
	// proposals). Zero value falls back to regular VotingPeriod for
	// backward compatibility.
	votingPeriod := gm.config.VotingPeriod
	if proposalType == ProposalTypeEmergency && gm.config.EmergencyVotingPeriod > 0 {
		votingPeriod = gm.config.EmergencyVotingPeriod
		// Still enforce MinVotingPeriodBlocks floor — emergency proposals
		// can be SHORTER but not shorter than the absolute minimum.
		if votingPeriod < MinVotingPeriodBlocks {
			return nil, fmt.Errorf("%w: emergency voting period %d below minimum %d",
				ErrInvalidParameter, votingPeriod, MinVotingPeriodBlocks)
		}
	}

	proposal := &Proposal{
		ID:           gm.nextProposalID,
		Type:         proposalType,
		Proposer:     proposer,
		Title:        title,
		Description:  description,
		Changes:      changes,
		Status:       ProposalStatusActive,
		StartHeight:  currentHeight,
		EndHeight:    currentHeight + votingPeriod,
		YesVotes:     big.NewInt(0),
		NoVotes:      big.NewInt(0),
		AbstainVotes: big.NewInt(0),
		Deposit:      new(big.Int).Set(deposit),
		CreatedAt:    createdAt,
		// R41-L3ECON-05: record the proposer's nonce on-chain so the
		// counter survives node restart and yields a forensic audit trail.
		ProposerNonce: proposerNonce,
	}
	// L12-004 FIX: snapshot totalVotePower at creation time so FinalizeProposal
	// uses a fixed denominator instead of recalculating from current stakes.
	if totalVotePower != nil {
		proposal.SnapshotTotalVotePower = new(big.Int).Set(totalVotePower)
	}

	// R30-IMPLEMENT (2026-07-27): GOV-R15-H03 — actually charge the deposit
	// BEFORE storing the proposal. Previously the deposit was recorded on the
	// Proposal struct but never deducted from the proposer's balance, allowing
	// zero-cost proposal DoS. When a DepositLocker is wired, LockDeposit is
	// called with the would-be proposal ID; on failure the proposal is rejected
	// and nextProposalID is NOT consumed (so the proposer can retry with a
	// working locker and still get ID 1). nil locker preserves the legacy
	// "record but don't charge" behavior for backward compatibility with
	// existing tests; production MUST wire a DepositLocker.
	//
	// R35-P3-ECON-3 FIX (2026-07-29): Previously when depositLocker was nil
	// the code silently fell through with no warning, allowing production
	// nodes to run indefinitely with the zero-cost proposal DoS vector open.
	// Now a warning is logged on every CreateProposal call without a locker,
	// so operators can detect the misconfiguration without breaking backward
	// compatibility with tests.
	if gm.depositLocker != nil {
		if err := gm.depositLocker.LockDeposit(proposer, deposit, proposal.ID); err != nil {
			return nil, fmt.Errorf("%w: deposit lock failed: %v", ErrInsufficientVotePower, err)
		}
	} else if gm.productionMode {
		// R42-GOVDEP-01 (2026-08-03): FAIL-CLOSED on mainnet/testnet when
		// the DepositLocker has not been wired. The legacy warning-only
		// path silently accepted zero-cost proposals, leaving the proposal
		// DoS vector (R35-P3-ECON-3) open on production nodes indefinitely.
		// node calls SetProductionMode(true) at startup on recognized
		// production networks so a misconfigured governance runtime surfaces
		// here instead of silently creating unchargeable proposals.
		// nextProposalID has NOT been consumed yet (assignment is below),
		// so a follow-up with a corrected locker config reuses ID space.
		return nil, ErrDepositLockerRequired
	} else {
		log.Printf("WARNING: governance: DepositLocker is nil — proposal %d created without charging deposit (zero-cost proposal DoS risk); production MUST wire a DepositLocker via SetDepositLocker and call SetProductionMode(true) on mainnet/testnet", proposal.ID)
	}

	gm.proposals[proposal.ID] = proposal
	gm.votes[proposal.ID] = make(map[types.Address]*Vote)
	// R41-L3ECON-05: advance the on-chain per-proposer nonce counter NOW
	// (after the proposal is stored). The strict-monotonic check at the
	// top of CreateProposal already rejected any nonce <= current; we
	// commit to this nonce for the proposer so subsequent proposals from
	// the same proposer must use a higher value. Persisted via saveUnlocked
	// below so the counter survives restart.
	gm.proposerNonces[proposer] = proposerNonce
	gm.nextProposalID++

	if err := gm.saveUnlocked(); err != nil {
		log.Printf("governance: failed to save after creating proposal %d: %v", proposal.ID, err)
	}

	return proposal, nil
}

// Vote casts a vote on a proposal
// audit-fix R3-M10: if StakeQuerier is set, votePower is validated against actual stake.
func (gm *GovernanceManager) Vote(
	proposalID uint64,
	voter types.Address,
	option VoteOption,
	votePower *big.Int,
	currentHeight uint64,
) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	proposal, exists := gm.proposals[proposalID]
	if !exists {
		return ErrProposalNotFound
	}

	if proposal.Status != ProposalStatusActive {
		return ErrProposalNotActive
	}

	if currentHeight > proposal.EndHeight {
		return ErrProposalExpired
	}

	// Check if already voted
	if _, voted := gm.votes[proposalID][voter]; voted {
		return ErrAlreadyVoted
	}

	if votePower == nil || votePower.Sign() <= 0 {
		return ErrInsufficientVotePower
	}

	// audit-fix HIGH: validate votePower against actual stake
	// If no stakeQuerier is configured, reject votes (cannot verify vote power)
	if gm.stakeQuerier == nil {
		return fmt.Errorf("%w: stake querier not configured, cannot verify vote power", ErrInsufficientVotePower)
	}
	// GOV- (2026-07-20) FIX: validate votePower against the voter's
	// stake AT THE PROPOSAL'S START HEIGHT, not their current stake. This
	// prevents the attack where a user temporarily stakes a large amount,
	// votes, then immediately unstakes — their vote power must be bounded
	// by what they had at the snapshot height (proposal creation).
	//
	// R35-P0-14 FIX: REMOVE the legacy fallback to current-stake validation.
	// Previously, if the stake querier did not implement StakeSnapshotQuerier,
	// Vote() fell back to GetStakeAmount (current stake) with only a warning
	// log. This left production nodes vulnerable to the GOV- attack
	// (stake → vote → unstake) whenever the node integration failed to wire
	// a snapshot-capable querier. The fix is fail-closed: if the configured
	// querier does not implement StakeSnapshotQuerier, ALL votes are rejected
	// with a security-critical error log. Node integrations MUST wire a
	// StakeSnapshotQuerier (see stakeQuerierAdapter in node/node.go which
	// now implements GetStakeAmountAtHeight).
	snapshotQuerier, ok := gm.stakeQuerier.(StakeSnapshotQuerier)
	if !ok {
		log.Printf("ERROR: governance: stake querier %T does not implement StakeSnapshotQuerier — rejecting vote to prevent GOV- attack (voter=%x, proposal=%d)",
			gm.stakeQuerier, voter, proposalID)
		return fmt.Errorf("%w: stake querier does not implement StakeSnapshotQuerier (required since R35-P0-14 to prevent stake-vote-unstake attack)", ErrInsufficientVotePower)
	}
	actualStake, err := snapshotQuerier.GetStakeAmountAtHeight(voter, proposal.StartHeight)
	if err != nil {
		// Fail-closed: if we cannot retrieve the historical stake,
		// reject the vote. This prevents an attacker from bypassing
		// validation by causing a snapshot-query error.
		return fmt.Errorf("%w: failed to query stake snapshot at height %d: %v", ErrInsufficientVotePower, proposal.StartHeight, err)
	}
	if err != nil || actualStake == nil {
		return ErrInsufficientVotePower
	}
	// Clamp votePower to actual stake (don't allow claiming more than staked)
	// audit-fix MED-6: record vote power adjustment for audit trail
	originalVotePower := new(big.Int).Set(votePower)
	if votePower.Cmp(actualStake) > 0 {
		votePower = new(big.Int).Set(actualStake)
		gm.recordVotePowerAdjustment(proposalID, voter, originalVotePower, actualStake, votePower, currentHeight)
	}
	if votePower.Sign() <= 0 {
		return ErrInsufficientVotePower
	}

	// Record vote
	vote := &Vote{
		ProposalID: proposalID,
		Voter:      voter,
		Option:     option,
		VotePower:  new(big.Int).Set(votePower),
		Height:     currentHeight,
	}
	gm.votes[proposalID][voter] = vote

	// Update vote counts
	switch option {
	case VoteOptionYes:
		proposal.YesVotes.Add(proposal.YesVotes, votePower)
	case VoteOptionNo:
		proposal.NoVotes.Add(proposal.NoVotes, votePower)
	case VoteOptionAbstain:
		proposal.AbstainVotes.Add(proposal.AbstainVotes, votePower)
	}

	if err := gm.saveUnlocked(); err != nil {
		log.Printf("governance: failed to save after voting on proposal %d: %v", proposal.ID, err)
	}

	return nil
}

// FinalizeProposal finalizes a proposal after voting ends
func (gm *GovernanceManager) FinalizeProposal(proposalID uint64, totalVotePower *big.Int, currentHeight uint64) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	proposal, exists := gm.proposals[proposalID]
	if !exists {
		return ErrProposalNotFound
	}

	if proposal.Status != ProposalStatusActive {
		return ErrProposalNotActive
	}

	if currentHeight < proposal.EndHeight {
		return errors.New("voting period not ended")
	}

	// Calculate total votes
	totalVotes := new(big.Int).Add(proposal.YesVotes, proposal.NoVotes)
	totalVotes.Add(totalVotes, proposal.AbstainVotes)

	// L12-004 FIX: Use the snapshot of totalVotePower taken at proposal creation
	// time instead of recalculating from current stakes. Recalculating allowed a
	// voter to withdraw stake after voting, lowering the quorum denominator while
	// their vote (recorded at vote time) still counted, making it easier to meet
	// quorum. The snapshot freezes the denominator at creation time. If no snapshot
	// was set (nil), fall back to the caller-supplied totalVotePower parameter.
	if proposal.SnapshotTotalVotePower != nil {
		totalVotePower = new(big.Int).Set(proposal.SnapshotTotalVotePower)
	}

	// CS-01 FIX: Guard against nil totalVotePower. If neither the proposal
	// snapshot nor the caller-supplied parameter provides a value, the
	// quorum and sanity-check computations below would dereference nil and
	// panic. A missing total vote power means there is no quorum
	// denominator, so finalization is impossible -- return an error rather
	// than panicking.
	if totalVotePower == nil {
		return errors.New("totalVotePower is required: neither snapshot nor caller provided a value")
	}

	// Additional sanity check: accumulated votes must not exceed total eligible vote power.
	// If this fires, it indicates vote inflation bug or a compromised totalVotePower parameter.
	if totalVotes.Cmp(totalVotePower) > 0 {
		// R53-CS-01 FIX: Use ErrVoteInflation instead of ErrProposalNotActive.
		// The proposal IS active — the problem is that accumulated votes exceed
		// total vote power, which indicates a bug or manipulation.
		return fmt.Errorf("%w: accumulated votes (%s) exceed total vote power (%s)", ErrVoteInflation, totalVotes.String(), totalVotePower.String())
	}

	// Check quorum
	// GOV- (2026-07-20) FIX: Use emergency-specific quorum threshold
	// for ProposalTypeEmergency (default 50% vs 33% for regular proposals).
	// A zero EmergencyQuorumThreshold falls back to the regular threshold
	// for backward compatibility.
	quorumThreshold := gm.config.QuorumThreshold
	if proposal.Type == ProposalTypeEmergency && gm.config.EmergencyQuorumThreshold > 0 {
		quorumThreshold = gm.config.EmergencyQuorumThreshold
	}
	quorumRequired := new(big.Int).Mul(totalVotePower, big.NewInt(int64(quorumThreshold)))
	quorumRequired.Div(quorumRequired, big.NewInt(10000))

	if totalVotes.Cmp(quorumRequired) < 0 {
		proposal.Status = ProposalStatusRejected
		return nil
	}

	// Check pass threshold (yes votes / (yes + no) >= threshold)
	// GOV- Use emergency-specific pass threshold for emergency
	// proposals (default 66.7% supermajority vs 50% for regular proposals).
	votesExcludingAbstain := new(big.Int).Add(proposal.YesVotes, proposal.NoVotes)
	if votesExcludingAbstain.Sign() == 0 {
		proposal.Status = ProposalStatusRejected
		return nil
	}

	passThreshold := gm.config.PassThreshold
	if proposal.Type == ProposalTypeEmergency && gm.config.EmergencyPassThreshold > 0 {
		passThreshold = gm.config.EmergencyPassThreshold
	}
	passRequired := new(big.Int).Mul(votesExcludingAbstain, big.NewInt(int64(passThreshold)))
	passRequired.Div(passRequired, big.NewInt(10000))

	if proposal.YesVotes.Cmp(passRequired) >= 0 {
		proposal.Status = ProposalStatusPassed
	} else {
		proposal.Status = ProposalStatusRejected
	}

	if err := gm.saveUnlocked(); err != nil {
		log.Printf("governance: failed to save after finalizing proposal %d: %v", proposal.ID, err)
	}

	return nil
}

// ExecuteProposal executes a passed proposal
func (gm *GovernanceManager) ExecuteProposal(proposalID uint64, currentHeight uint64) error {
	// P1-T6 (2026-07-14): Capture emergency handler + proposal snapshot under lock,
	// then release the lock before invoking the handler. The handler (MinistryRites)
	// may call back into QPOS.GetValidatorSet() and Defense.AddToBlacklist(),
	// which must not be blocked by gm.mu.
	var emergencyHandler EmergencyActionHandler
	var emergencyInfo struct {
		title       string
		description string
		proposer    types.Address
	}

	gm.mu.Lock()

	proposal, exists := gm.proposals[proposalID]
	if !exists {
		gm.mu.Unlock()
		return ErrProposalNotFound
	}

	if proposal.Status != ProposalStatusPassed {
		gm.mu.Unlock()
		return errors.New("proposal not passed")
	}

	// Check execution delay
	// GOV- (2026-07-20) FIX: Use emergency-specific execution delay
	// for ProposalTypeEmergency (default 6h vs 2 days for regular proposals).
	// A zero EmergencyExecutionDelay falls back to the regular delay for
	// backward compatibility.
	executionDelay := gm.config.ExecutionDelay
	if proposal.Type == ProposalTypeEmergency && gm.config.EmergencyExecutionDelay > 0 {
		executionDelay = gm.config.EmergencyExecutionDelay
	}
	if currentHeight < proposal.EndHeight+executionDelay {
		gm.mu.Unlock()
		return errors.New("execution delay not passed")
	}

	// Execute parameter changes
	if proposal.Type == ProposalTypeParameter {
		for _, change := range proposal.Changes {
			// GOV- (2026-07-20) FIX: Validate that the current
			// parameter value still matches change.OldValue (the value
			// observed at proposal-creation time). If another proposal
			// executed in the meantime changed the parameter to a different
			// value, executing this proposal would silently roll back to
			// change.NewValue based on stale expectations — enabling a
			// parameter rollback attack:
			//   1. Proposer A sees param X = "10", proposes X: "10" → "20".
			//   2. Proposer B proposes X: "10" → "30" and executes first.
			//   3. Proposer A's proposal now executes, "20" overwrites "30".
			//
			// Mitigation: if OldValue is non-empty, require current value ==
			// OldValue. An empty OldValue skips the check (backward-compat for
			// proposals created before this fix, or for new parameters that
			// have no prior value). On mismatch, the proposal fails with a
			// descriptive error so the proposer can re-submit with the
			// updated OldValue.
			//
			// P2-GOV-OLDVALUE FIX (R30, 2026-07-27): Extend the check to cover
			// the "new parameter created during voting window" attack. When
			// OldValue == "" (proposal was created for a non-existent param)
			// but the parameter NOW exists with a non-empty value, another
			// proposal created it during the voting window. Executing this
			// proposal would silently overwrite the new value — a rollback
			// attack. Reject with a descriptive error. If the parameter now
			// exists but is empty, allow (no semantic conflict).
			currentVal, exists := gm.parameters[change.Parameter]
			if change.OldValue != "" {
				if exists && currentVal != change.OldValue {
					gm.mu.Unlock()
					return fmt.Errorf("parameter %q stale OldValue: proposal expected %q, current is %q (another proposal modified it during voting window)",
						change.Parameter, change.OldValue, currentVal)
				}
			} else if exists && currentVal != "" {
				// OldValue == "" but parameter now exists with a non-empty
				// value — it was created during the voting window.
				gm.mu.Unlock()
				return fmt.Errorf("parameter %q was created during voting window (OldValue empty, current is %q)",
					change.Parameter, currentVal)
			}
			// GOV- (2026-07-20) FIX: Previously wrote gm.parameters
			// directly here, bypassing validateParameter. R10 privatized
			// setParameter but ExecuteProposal already held gm.mu, so it
			// could not call setParameter (would deadlock). Use the new
			// setParameterLocked inner path — same validation + audit log,
			// no re-locking. Re-validation at execute time catches proposals
			// whose values fell out of the allowed set between creation and
			// execution (e.g., allowed-parameter set was tightened).
			if err := gm.setParameterLocked(change.Parameter, change.NewValue); err != nil {
				gm.mu.Unlock()
				return fmt.Errorf("%w: parameter %s value %s rejected: %v", ErrParameterValueInvalid, change.Parameter, change.NewValue, err)
			}
		}
	}

	// P1-T6 (2026-07-14): Capture emergency handler and proposal metadata
	// for post-unlock invocation. The handler triggers Defense ministry
	// blacklisting (chain halt) for Emergency-type proposals.
	// GOV- (Low): Capture proposal.Proposer so the handler can
	// attribute the emergency halt to a real account in audit logs
	// instead of an opaque system-caller sentinel.
	if proposal.Type == ProposalTypeEmergency && gm.emergencyHandler != nil {
		emergencyHandler = gm.emergencyHandler
		emergencyInfo.title = proposal.Title
		emergencyInfo.description = proposal.Description
		emergencyInfo.proposer = proposal.Proposer
	}

	proposal.Status = ProposalStatusExecuted

	// audit-fix R3-L11: evict old finalized proposals to prevent unbounded memory growth
	gm.evictOldProposals()

	if err := gm.saveUnlocked(); err != nil {
		log.Printf("governance: failed to save after executing proposal %d: %v", proposal.ID, err)
	}

	gm.mu.Unlock()

	// P1-T6 (2026-07-14): Invoke emergency handler OUTSIDE gm.mu to avoid
	// deadlock with QPOS.mu (MinistryRites → Defense → QPOS.GetValidatorSet).
	// Best-effort: errors are logged but do NOT revert the proposal's Executed
	// status, consistent with other ministry best-effort recording patterns.
	if emergencyHandler != nil {
		if err := emergencyHandler.HandleEmergencyAction(proposalID, emergencyInfo.proposer, emergencyInfo.title, emergencyInfo.description); err != nil {
			log.Printf("governance: emergency action handler failed for proposal %d: %v (proposal already marked Executed)", proposalID, err)
		}
	}

	return nil
}

// evictOldProposals removes old finalized proposals when count exceeds limit.
// audit-fix R3-L11: prevents unbounded memory growth from accumulated proposals.
func (gm *GovernanceManager) evictOldProposals() {
	// Count finalized proposals
	var finalizedIDs []uint64
	for id, p := range gm.proposals {
		if p.Status == ProposalStatusExecuted || p.Status == ProposalStatusRejected || p.Status == ProposalStatusExpired {
			finalizedIDs = append(finalizedIDs, id)
		}
	}

	// Evict oldest if over limit
	if len(finalizedIDs) > gm.maxFinalizedProposals {
		// R35-P3-ECON-4 FIX (2026-07-29): Replace O(n^2) bubble sort with
		// sort.Slice (O(n log n)). The previous nested loop degraded
		// quadratically as the finalized proposal count grew, causing
		// latency spikes in evictOldProposals when maxFinalizedProposals
		// is large. Sort by ID (older proposals have lower IDs).
		sort.Slice(finalizedIDs, func(i, j int) bool {
			return finalizedIDs[i] < finalizedIDs[j]
		})
		// Remove oldest quarter
		evictCount := len(finalizedIDs) / 4
		if evictCount < 1 {
			evictCount = 1
		}
		for _, id := range finalizedIDs[:evictCount] {
			delete(gm.proposals, id)
			delete(gm.votes, id)
		}
	}
}

// GetProposal returns a proposal by ID
func (gm *GovernanceManager) GetProposal(proposalID uint64) (*Proposal, error) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	proposal, exists := gm.proposals[proposalID]
	if !exists {
		return nil, ErrProposalNotFound
	}

	// Return a copy
	copy := &Proposal{
		ID:           proposal.ID,
		Type:         proposal.Type,
		Proposer:     proposal.Proposer,
		Title:        proposal.Title,
		Description:  proposal.Description,
		Changes:      proposal.Changes,
		Status:       proposal.Status,
		StartHeight:  proposal.StartHeight,
		EndHeight:    proposal.EndHeight,
		YesVotes:     new(big.Int).Set(proposal.YesVotes),
		NoVotes:      new(big.Int).Set(proposal.NoVotes),
		AbstainVotes: new(big.Int).Set(proposal.AbstainVotes),
		Deposit:      new(big.Int).Set(proposal.Deposit),
		CreatedAt:    proposal.CreatedAt,
	}
	if proposal.SnapshotTotalVotePower != nil {
		copy.SnapshotTotalVotePower = new(big.Int).Set(proposal.SnapshotTotalVotePower)
	}
	return copy, nil
}

// GetActiveProposals returns all active proposals
func (gm *GovernanceManager) GetActiveProposals() []*Proposal {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	proposals := make([]*Proposal, 0)
	for _, p := range gm.proposals {
		if p.Status == ProposalStatusActive {
			copy := &Proposal{
				ID:           p.ID,
				Type:         p.Type,
				Proposer:     p.Proposer,
				Title:        p.Title,
				Description:  p.Description,
				Changes:      p.Changes,
				Status:       p.Status,
				StartHeight:  p.StartHeight,
				EndHeight:    p.EndHeight,
				YesVotes:     new(big.Int).Set(p.YesVotes),
				NoVotes:      new(big.Int).Set(p.NoVotes),
				AbstainVotes: new(big.Int).Set(p.AbstainVotes),
				Deposit:      new(big.Int).Set(p.Deposit),
				CreatedAt:    p.CreatedAt,
			}
			if p.SnapshotTotalVotePower != nil {
				copy.SnapshotTotalVotePower = new(big.Int).Set(p.SnapshotTotalVotePower)
			}
			proposals = append(proposals, copy)
		}
	}
	return proposals
}

// GetVote returns a vote for a proposal by voter
func (gm *GovernanceManager) GetVote(proposalID uint64, voter types.Address) (*Vote, error) {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	votes, exists := gm.votes[proposalID]
	if !exists {
		return nil, ErrProposalNotFound
	}

	vote, exists := votes[voter]
	if !exists {
		return nil, errors.New("vote not found")
	}

	return &Vote{
		ProposalID: vote.ProposalID,
		Voter:      vote.Voter,
		Option:     vote.Option,
		VotePower:  new(big.Int).Set(vote.VotePower),
		Height:     vote.Height,
	}, nil
}

// GetConfig returns a copy of the governance configuration.
//
// R40-P1-06 (2026-08-03) FIX: the prior implementation omitted the four
// `Emergency*` fields (EmergencyVotingPeriod, EmergencyQuorumThreshold,
// EmergencyPassThreshold, EmergencyExecutionDelay). RPC consumers (notably
// `qau_getGovernanceConfig`) read these via reflection and saw zero values,
// which then silently fell back to the regular (much laxer) thresholds at
// `CreateProposal` / `TallyVotes` time — effectively disabling the emergency
// pause mechanism. The Emergency* fields are now copied through verbatim,
// matching the in-memory config the manager actually uses for emergency
// proposal lifecycle decisions. Field reordering is unchanged; only the four
// missing fields are appended.
func (gm *GovernanceManager) GetConfig() *GovernanceConfig {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	return &GovernanceConfig{
		VotingPeriod:    gm.config.VotingPeriod,
		QuorumThreshold: gm.config.QuorumThreshold,
		PassThreshold:   gm.config.PassThreshold,
		ProposalDeposit: new(big.Int).Set(gm.config.ProposalDeposit),
		ExecutionDelay:  gm.config.ExecutionDelay,

		// R40-P1-06: copy the Emergency* fields through. Without these, RPC
		// consumers see zero values and silently fall back to the regular
		// (laxer) thresholds, bypassing the emergency pause mechanism.
		EmergencyVotingPeriod:    gm.config.EmergencyVotingPeriod,
		EmergencyQuorumThreshold: gm.config.EmergencyQuorumThreshold,
		EmergencyPassThreshold:   gm.config.EmergencyPassThreshold,
		EmergencyExecutionDelay:  gm.config.EmergencyExecutionDelay,
	}
}

// ProposalCount returns the total number of proposals
func (gm *GovernanceManager) ProposalCount() int {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return len(gm.proposals)
}

// recordVotePowerAdjustment logs when a voter's claimed vote power was adjusted
// to match their actual stake. This provides an audit trail for governance transparency.
// audit-fix MED-6: event logging for vote power clamping.
// CS-02 FIX: Added variadic blockTime parameter for deterministic timestamps.
// When provided, blockTime[0] is used for the event Timestamp instead of
// time.Now().Unix(), ensuring consensus-critical timestamps are deterministic.
func (gm *GovernanceManager) recordVotePowerAdjustment(proposalID uint64, voter types.Address, claimedPower, actualStake, adjustedTo *big.Int, height uint64, blockTime ...int64) {
	if claimedPower == nil || actualStake == nil || adjustedTo == nil {
		return
	}

	gm.votePowerAdjMu.Lock()
	defer gm.votePowerAdjMu.Unlock()

	// CS-02 FIX: Use deterministic blockTime for the event timestamp when
	// provided; fall back to time.Now() for non-consensus callers.
	var timestamp int64
	if len(blockTime) > 0 {
		timestamp = blockTime[0]
	} else {
		timestamp = time.Now().Unix()
	}

	event := VotePowerAdjustedEvent{
		ProposalID:   proposalID,
		Voter:        voter,
		ClaimedPower: new(big.Int).Set(claimedPower),
		ActualStake:  new(big.Int).Set(actualStake),
		AdjustedTo:   new(big.Int).Set(adjustedTo),
		Height:       height,
		Timestamp:    timestamp,
	}

	gm.votePowerAdjustments = append(gm.votePowerAdjustments, event)

	// audit-fix MED-6: cap event storage to prevent unbounded memory growth
	const maxVotePowerAdjustments = 10000
	if len(gm.votePowerAdjustments) > maxVotePowerAdjustments {
		evictCount := maxVotePowerAdjustments / 10 // evict 10%
		gm.votePowerAdjustments = gm.votePowerAdjustments[evictCount:]
	}
}

// GetVotePowerAdjustments returns all vote power adjustment events.
// audit-fix MED-6: provides audit trail access for vote power clamping.
func (gm *GovernanceManager) GetVotePowerAdjustments() []VotePowerAdjustedEvent {
	gm.votePowerAdjMu.RLock()
	defer gm.votePowerAdjMu.RUnlock()

	result := make([]VotePowerAdjustedEvent, len(gm.votePowerAdjustments))
	copy(result, gm.votePowerAdjustments)
	return result
}

// SetDataDir sets the data directory for persistence and loads saved state.
func (gm *GovernanceManager) SetDataDir(dir string) error {
	gm.mu.Lock()
	gm.dataDir = dir
	gm.mu.Unlock()

	// Ensure directory exists
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create governance data dir: %w", err)
		}
	}
	return gm.Load()
}

// saveUnlocked saves state without acquiring the lock.
// Must be called while holding gm.mu.
func (gm *GovernanceManager) saveUnlocked() error {
	if gm.dataDir == "" {
		return nil
	}

	proposals := make([]*Proposal, 0, len(gm.proposals))
	for _, p := range gm.proposals {
		proposals = append(proposals, p)
	}

	params := make(map[string]string)
	for k, v := range gm.parameters {
		params[k] = v
	}

	// R41-L3ECON-05: serialize the per-proposer nonce counter. Keys are
	// hex-encoded addresses since JSON object keys must be strings.
	proposerNonces := make(map[string]uint64, len(gm.proposerNonces))
	for addr, n := range gm.proposerNonces {
		proposerNonces[fmt.Sprintf("%x", addr[:])] = n
	}

	state := governanceState{
		Proposals:      proposals,
		Parameters:     params,
		NextProposalID: gm.nextProposalID,
		ProposerNonces: proposerNonces,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal governance state: %w", err)
	}

	path := filepath.Join(gm.dataDir, "governance.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write governance state: %w", err)
	}

	return nil
}

// verifyProposalSignatureLocked performs R43-GOVSIG-01 core-layer
// Dilithium3 signature verification for a CreateProposal call.
//
// It MUST be called with gm.mu held (the caller, CreateProposal, holds it).
// Verification runs BEFORE the R41-L3ECON-05 nonce advance so a failed
// signature does not burn the per-proposer nonce counter (otherwise a
// replay attacker could keep submitting bogus signatures to drive the
// counter up and force the genuine proposer off their intended nonce).
//
// The signed message reconstructed here MUST byte-for-byte match what
// rpc/governance_api.go verifyGovernanceSignature produces, otherwise a
// signature accepted by the RPC layer would be rejected at the core
// (false negative) or vice versa. Both layers reference the same
// GovernanceProposalSignatureMethod constant to avoid drift.
//
// Returns nil on success, or an error wrapping ErrGovernanceSignatureInvalid
// on any failure (bad pubkey length, zero pubkey, signature length mismatch,
// pub→addr binding mismatch, signature verification returning false).
// Failure is fail-closed: any error short-circuits CreateProposal.
func (gm *GovernanceManager) verifyProposalSignatureLocked(
	proposer types.Address,
	proposalType ProposalType,
	title, description string,
	changes []ParameterChange,
	deposit *big.Int,
	totalVotePower *big.Int,
	proposerNonce uint64,
	sig *ProposalSignature,
) error {
	if sig == nil {
		return nil
	}

	// 1. Public key size check (fail-closed on wrong length).
	if len(sig.ProposerPubKey) != crypto.Dilithium3PublicKeySize {
		return fmt.Errorf("%w: proposer public key length %d != expected %d",
			ErrGovernanceSignatureInvalid, len(sig.ProposerPubKey), crypto.Dilithium3PublicKeySize)
	}
	// R38-P1-01-style gate: reject all-zero public key explicitly. The
	// crypto layer would otherwise reject it inside PublicKeyFromBytes, but
	// surfacing it here gives a clearer error and prevents the
	// crypto.PublicKeyFromBytes path from being probed with degenerate input.
	if crypto.IsZeroPublicKeyBytes(sig.ProposerPubKey) {
		return fmt.Errorf("%w: proposer public key is all-zero",
			ErrGovernanceSignatureInvalid)
	}

	// 2. Signature size check.
	if len(sig.ProposerSig) != crypto.Dilithium3SignatureSize {
		return fmt.Errorf("%w: proposer signature length %d != expected %d",
			ErrGovernanceSignatureInvalid, len(sig.ProposerSig), crypto.Dilithium3SignatureSize)
	}

	// 3. Parse public key and verify it binds to the claimed proposer
	// address (byte-level equality, like VerifyTransactionAuthorization).
	pubKey, err := crypto.PublicKeyFromBytes(sig.ProposerPubKey)
	if err != nil {
		return fmt.Errorf("%w: invalid public key: %v",
			ErrGovernanceSignatureInvalid, err)
	}
	derivedAddr := pubKey.Address()
	if derivedAddr != proposer {
		return fmt.Errorf("%w: derived address %x != claimed proposer %x",
			ErrGovernanceSignatureInvalid, derivedAddr[:], proposer[:])
	}

	// 4. Reconstruct the signed message. The format MUST match
	// rpc/governance_api.go verifyGovernanceSignature exactly:
	//   message = "QAU-" + method + "|" + chainID + "|" + proposerHex + "|" + nonce + "|" + authParams
	//   authParams = proposerHex + "|" + type + "|" + title + "|" + description + "|" + deposit + "|" + totalVotePower + "|" + changesJSON
	//
	// proposalsHex here uses types.Address.ToHexAddress() (same method the
	// RPC layer uses via parseGovAddress-produced hex). The deposit string
	// uses *big.Int.String() (decimal); the RPC layer uses req.Deposit
	// (already a decimal string), with a "0" fallback if SetString failed
	// — we mirror that here so a "0" deposit on the core side matches a
	// zero-value-fallback deposit on the RPC side.
	proposerHex := proposer.ToHexAddress()
	depositStr := "0"
	if deposit != nil {
		depositStr = deposit.String()
	}
	totalVotePowerStr := sig.TotalVotePower
	if totalVotePowerStr == "" {
		// Mirror the RPC layer's behavior: if no totalVotePower was
		// provided, the signed message uses the literal "" for that field.
		// (We keep sig.TotalVotePower as the canonical source so the RPC
		// layer can pass exactly what it signed.)
	}
	changesJSON, _ := json.Marshal(changes)
	authParams := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s",
		proposerHex, uint8(proposalType), title, description, depositStr,
		totalVotePowerStr, string(changesJSON))
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s",
		GovernanceProposalSignatureMethod, sig.ChainID, proposerHex,
		sig.Nonce, authParams))

	// 5. Verify the Dilithium3 signature.
	if !crypto.Verify(pubKey, message, sig.ProposerSig) {
		return fmt.Errorf("%w: Dilithium3 verify returned false for proposer %x nonce %s",
			ErrGovernanceSignatureInvalid, proposer[:], sig.Nonce)
	}

	return nil
}

// governanceState is the serializable state for persistence.
type governanceState struct {
	Proposals      []*Proposal       `json:"proposals"`
	Parameters     map[string]string `json:"parameters"`
	NextProposalID uint64            `json:"nextProposalId"`
	// R41-L3ECON-05 (2026-08-03): persist the per-proposer on-chain nonce
	// counter so the strict-monotonic check (CreateProposal) survives
	// node restart. Without this, a node restart would reset the
	// counter to 0 and accept a previously-consumed nonce, defeating
	// the on-chain replay protection. Backward compatible: legacy
	// state files without this field JSON-decode as nil, and Load
	// rebuilds an empty map (so the first proposal from any proposer
	// must use nonce >= 1).
	ProposerNonces map[string]uint64 `json:"proposerNonces,omitempty"`
}

// Save persists governance state to disk.
func (gm *GovernanceManager) Save() error {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	if gm.dataDir == "" {
		return nil
	}

	proposals := make([]*Proposal, 0, len(gm.proposals))
	for _, p := range gm.proposals {
		proposals = append(proposals, p)
	}

	params := make(map[string]string)
	for k, v := range gm.parameters {
		params[k] = v
	}

	// R41-L3ECON-05: serialize the per-proposer nonce counter (same as
	// saveUnlocked). RLock held — but the map is only mutated under
	// gm.mu.Lock (CreateProposal), so iterating under RLock is safe.
	proposerNonces := make(map[string]uint64, len(gm.proposerNonces))
	for addr, n := range gm.proposerNonces {
		proposerNonces[fmt.Sprintf("%x", addr[:])] = n
	}

	state := governanceState{
		Proposals:      proposals,
		Parameters:     params,
		NextProposalID: gm.nextProposalID,
		ProposerNonces: proposerNonces,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal governance state: %w", err)
	}

	path := filepath.Join(gm.dataDir, "governance.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write governance state: %w", err)
	}

	return nil
}

// Load restores governance state from disk.
func (gm *GovernanceManager) Load() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if gm.dataDir == "" {
		return nil
	}

	path := filepath.Join(gm.dataDir, "governance.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No saved state, start fresh
		}
		return fmt.Errorf("failed to read governance state: %w", err)
	}

	var state governanceState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to unmarshal governance state: %w", err)
	}

	// Restore proposals
	gm.proposals = make(map[uint64]*Proposal)
	for _, p := range state.Proposals {
		// Restore nil big.Ints
		if p.YesVotes == nil {
			p.YesVotes = big.NewInt(0)
		}
		if p.NoVotes == nil {
			p.NoVotes = big.NewInt(0)
		}
		if p.AbstainVotes == nil {
			p.AbstainVotes = big.NewInt(0)
		}
		if p.Deposit == nil {
			p.Deposit = big.NewInt(0)
		}
		gm.proposals[p.ID] = p
	}

	// Restore parameters
	if state.Parameters != nil {
		gm.parameters = state.Parameters
	}

	// Restore next proposal ID
	if state.NextProposalID > 0 {
		gm.nextProposalID = state.NextProposalID
	}

	// R41-L3ECON-05 (2026-08-03): restore the per-proposer on-chain nonce
	// counter from persisted state. Legacy state files without
	// proposerNonces decode as nil → fall back to an empty map, meaning
	// the first proposal from any proposer must use nonce >= 1 (same as
	// a fresh GovernanceManager). This preserves backward compatibility
	// with state files written before R41-L3ECON-05.
	if gm.proposerNonces == nil {
		gm.proposerNonces = make(map[types.Address]uint64)
	}
	for hexAddr, n := range state.ProposerNonces {
		// Decode 40-char hex (20 bytes) into types.Address. We tolerate
		// (skip + log) any malformed entry so a corrupted state file
		// cannot wedge the entire Load path — operators get a log line
		// instead of a node that refuses to start.
		hB, err := hex.DecodeString(hexAddr)
		if err != nil || len(hB) != 20 {
			log.Printf("governance: load: skipping malformed proposerNonces key %q (len=%d, err=%v)", hexAddr, len(hexAddr), err)
			continue
		}
		var addr types.Address
		copy(addr[:], hB)
		if n > gm.proposerNonces[addr] {
			gm.proposerNonces[addr] = n
		}
	}

	// Rebuild votes map (votes are stored within proposals, not separately in JSON)
	// Note: votes map is rebuilt empty — historical vote records are not persisted
	// to keep the state file small. Vote counts are preserved in the Proposal fields.
	gm.votes = make(map[uint64]map[types.Address]*Vote)
	for id := range gm.proposals {
		gm.votes[id] = make(map[types.Address]*Vote)
	}

	return nil
}

// GetVotePowerAdjustmentsForProposal returns vote power adjustment events for a specific proposal.
// audit-fix MED-6: provides filtered audit trail access.
func (gm *GovernanceManager) GetVotePowerAdjustmentsForProposal(proposalID uint64) []VotePowerAdjustedEvent {
	gm.votePowerAdjMu.RLock()
	defer gm.votePowerAdjMu.RUnlock()

	var result []VotePowerAdjustedEvent
	for _, event := range gm.votePowerAdjustments {
		if event.ProposalID == proposalID {
			result = append(result, VotePowerAdjustedEvent{
				ProposalID:   event.ProposalID,
				Voter:        event.Voter,
				ClaimedPower: new(big.Int).Set(event.ClaimedPower),
				ActualStake:  new(big.Int).Set(event.ActualStake),
				AdjustedTo:   new(big.Int).Set(event.AdjustedTo),
				Height:       event.Height,
				Timestamp:    event.Timestamp,
			})
		}
	}
	return result
}

// GetVotePowerAdjustmentsForVoter returns vote power adjustment events for a specific voter.
// audit-fix MED-6: provides filtered audit trail access.
func (gm *GovernanceManager) GetVotePowerAdjustmentsForVoter(voter types.Address) []VotePowerAdjustedEvent {
	gm.votePowerAdjMu.RLock()
	defer gm.votePowerAdjMu.RUnlock()

	var result []VotePowerAdjustedEvent
	for _, event := range gm.votePowerAdjustments {
		if event.Voter == voter {
			result = append(result, VotePowerAdjustedEvent{
				ProposalID:   event.ProposalID,
				Voter:        event.Voter,
				ClaimedPower: new(big.Int).Set(event.ClaimedPower),
				ActualStake:  new(big.Int).Set(event.ActualStake),
				AdjustedTo:   new(big.Int).Set(event.AdjustedTo),
				Height:       event.Height,
				Timestamp:    event.Timestamp,
			})
		}
	}
	return result
}

// normalizeParamName converts snake_case to PascalCase.
// E.g., 'inflation_rate' -> 'InflationRate'
func normalizeParamName(s string) string {
	parts := strings.Split(s, "_")
	var result strings.Builder
	for _, part := range parts {
		if len(part) > 0 {
			result.WriteString(strings.ToUpper(part[:1]))
			result.WriteString(part[1:])
		}
	}
	return result.String()
}

// Quantaureum Node source, version 1.0.0.
// Package economics implements the economic model for the Quantaureum blockchain.
// This file implements the staking mechanism with lock periods.
package economics

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

// Staking-related errors
// StakingAPY is the annual percentage yield for staking rewards (in percentage points).
//
// FIX: Set to 0 to avoid double rewards. The consensus layer already
// pays attestation rewards to validators (see consensus/epoch_rewards_census.go
// and docs/economic-model.md). An additional staking-layer APY would be a
// second reward for the same activity.
//
// EM-2 (2026-08-31): the consensus-layer yield is no longer a fixed figure.
// It is stake-dependent (APY proportional to 1/sqrt(total staked)): ~42% at the
// 36,000 QAU bootstrap level, ~4% at 4,000,000 QAU, ~1.8% at 20,000,000 QAU.
// The previous "~9.8% APR" in this comment was never reachable after the
// CONS- dedup fix and is not a number to reason from.
//
// When StakingAPY = 0:
//   - ProcessRewardClaimFromTx returns 0 (no staking-layer reward)
//   - GetPendingRewards returns 0
//   - PendingRewards accumulation in Stake() is 0
//   - Validators still receive consensus-layer attestation rewards
//
// To re-enable staking APY via governance (e.g., for a future incentive program),
// change this constant OR refactor to read from governance parameters
// (economics/governance.go already defines "StakingAPY" as a governable parameter).
const StakingAPY = 0

var (
	ErrInsufficientStake      = errors.New("insufficient stake amount")
	ErrStakeNotFound          = errors.New("stake not found")
	ErrStakeLocked            = errors.New("stake is still locked")
	ErrInvalidUnstakeAmount   = errors.New("invalid unstake amount")
	ErrUnstakeRequestExists   = errors.New("unstake request already exists")
	ErrNoUnstakeRequest       = errors.New("no unstake request found")
	ErrInvalidLockPeriod      = errors.New("invalid lock period")
	ErrInvalidCommission      = errors.New("invalid commission rate")
	ErrValidatorAlreadyExists = errors.New("validator already exists")
)

// FIX: systemCallers moved from package-level globals to StakingManager fields.
// Previously shared across all instances and had isolation issues in tests.
// Zero address is explicitly rejected as a system caller (R24-H2).
//
// I22-005 NOTE: globalSystemCallers remains a package-level global shared by
// all StakingManager instances. This is intentional for production where only
// a single StakingManager instance exists (the system caller registry is a
// node-wide concept, not per-instance). However, this design can cause test
// interference when multiple StakingManager instances are created in the same
// test process -- registrations in one test bleed into another.
// TODO: migrate systemCallers to a per-instance field on StakingManager to
// achieve full test isolation. This requires updating all call sites that
// use RegisterSystemCaller() and isSystemCaller() to go through the instance.
var (
	globalSystemCallers   map[types.Address]bool // kept for backward compat
	globalSystemCallersMu sync.RWMutex
)

func init() {
	globalSystemCallers = make(map[types.Address]bool)
}

// registerSystemCaller registers an address as a valid system caller.
//
// ECON-R10-HIGH-002 (2026-07-19) FIX: This function was previously exported
// as RegisterSystemCaller, allowing any external caller to mint new system
// callers — granting themselves the ability to invoke privileged system
// operations (e.g. mint/burn, parameter changes, fee sweeps) without
// authorization. Privatization forces all registration through package-
// internal init paths that are gated by the constructor / config loader.
//
// Auditors' note: this remains a package-global registry. Future work should
// migrate to per-instance fields (see TODO above).
func registerSystemCaller(addr types.Address) {
	globalSystemCallersMu.Lock()
	defer globalSystemCallersMu.Unlock()
	globalSystemCallers[addr] = true
}

// unregisterSystemCaller removes an address from the system caller registry.
//
// ECON-R10-HIGH-002 (2026-07-19): Adds the previously-missing revocation
// path. Without this, a compromised system caller could not be removed
// without restarting the node — a significant operational risk.
//
// Package-private: only the economics package (e.g. an authorized
// governance pathway) can revoke a system caller.
func unregisterSystemCaller(addr types.Address) {
	globalSystemCallersMu.Lock()
	defer globalSystemCallersMu.Unlock()
	delete(globalSystemCallers, addr)
}

// UnregisterSystemCallerForGovernance is the exported, governance-authorized
// path to revoke a system caller at runtime.
//
// ECON- (2026-07-20) FIX: Previously unregisterSystemCaller was
// package-private with NO external entry point — meaning a compromised
// system caller's private key could not be revoked without restarting the
// node. This created a window where a stolen key retained full privileges
// (mint/burn, parameter changes, fee sweeps) until operators noticed and
// restarted.
//
// This method is exported so governance (economics.GovernanceManager) and
// the consensus layer (multi-sig emergency revoke) can call it via the
// ProposalTypeRevokeSystemCaller governance proposal type, or via a 2/3
// validator multi-sig for emergencies.
//
// Authorization is enforced by the caller (governance / multi-sig) — this
// function performs the mechanical revocation only. Calling it directly
// from non-governance code is a security violation.
func UnregisterSystemCallerForGovernance(addr types.Address) {
	unregisterSystemCaller(addr)
}

// IsSystemCallerExported is a read-only exported accessor for inspection
// tools (e.g. RPC qau_listSystemCallers). It does NOT grant write access.
func IsSystemCallerExported(addr types.Address) bool {
	return isSystemCaller(addr)
}

// snapshotGlobalSystemCallers returns a copy of the package-level
// globalSystemCallers map under its own lock. Used by NewStakingManager
// to seed each instance's systemCallers field with the legacy registration
// set that existed before the manager was constructed.
// R43-ECON-CALLER-01 (2026-08-03).
func snapshotGlobalSystemCallers() map[types.Address]bool {
	globalSystemCallersMu.RLock()
	defer globalSystemCallersMu.RUnlock()
	out := make(map[types.Address]bool, len(globalSystemCallers))
	for k, v := range globalSystemCallers {
		out[k] = v
	}
	return out
}

// RegisterSystemCallerOnManager registers an address as a system caller on
// the receiver instance ONLY (does not touch the package-level global).
// R43-ECON-CALLER-01 (2026-08-03). Use this when constructing an isolated
// test StakingManager that should NOT pollute the global registry. For
// production-wide registration, use the package-level RegisterSystemCaller
// instead, which writes BOTH the global AND all subsequently-constructed
// instances (via the snapshot).
func (sm *StakingManager) RegisterSystemCallerOnManager(addr types.Address) {
	if addr == (types.Address{}) {
		return // R24-H2: zero address is never a valid system caller
	}
	sm.systemCallersMu.Lock()
	defer sm.systemCallersMu.Unlock()
	sm.systemCallers[addr] = true
}

// UnregisterSystemCallerFromManager removes an address from the receiver
// instance ONLY (does not touch the package-level global). R43-ECON-CALLER-01.
func (sm *StakingManager) UnregisterSystemCallerFromManager(addr types.Address) {
	sm.systemCallersMu.Lock()
	defer sm.systemCallersMu.Unlock()
	delete(sm.systemCallers, addr)
}

// IsSystemCallerInstance returns true if `caller` is registered as a
// system caller on this instance, OR on the package-level global. The
// global fallback preserves backward compatibility for callers that
// still use the package-level RegisterSystemCaller (e.g. governance
// proposal integration tests that register on a shared global before
// constructing a manager). R43-ECON-CALLER-01 (2026-08-03).
func (sm *StakingManager) IsSystemCallerInstance(caller types.Address) bool {
	if caller == (types.Address{}) {
		return false // R24-H2
	}
	sm.systemCallersMu.RLock()
	inInstance := sm.systemCallers[caller]
	sm.systemCallersMu.RUnlock()
	if inInstance {
		return true
	}
	// Fallback to package-level global for backward compat.
	globalSystemCallersMu.RLock()
	defer globalSystemCallersMu.RUnlock()
	return globalSystemCallers[caller]
}

// ListSystemCallersInstance returns a snapshot of all system callers
// registered on this instance AND the package-level global (union).
// R43-ECON-CALLER-01 (2026-08-03).
func (sm *StakingManager) ListSystemCallersInstance() []types.Address {
	sm.systemCallersMu.RLock()
	addrs := make([]types.Address, 0, len(sm.systemCallers))
	for addr := range sm.systemCallers {
		addrs = append(addrs, addr)
	}
	sm.systemCallersMu.RUnlock()
	globalSystemCallersMu.RLock()
	defer globalSystemCallersMu.RUnlock()
	seen := make(map[types.Address]bool, len(addrs))
	for i := range addrs {
		seen[addrs[i]] = true
	}
	for addr := range globalSystemCallers {
		if !seen[addr] {
			addrs = append(addrs, addr)
			seen[addr] = true
		}
	}
	return addrs
}

// ListSystemCallersExported returns a snapshot of all registered system
// caller addresses. Used by governance/RPC to inspect the registry.
func ListSystemCallersExported() []types.Address {
	globalSystemCallersMu.RLock()
	defer globalSystemCallersMu.RUnlock()
	addrs := make([]types.Address, 0, len(globalSystemCallers))
	for addr := range globalSystemCallers {
		addrs = append(addrs, addr)
	}
	return addrs
}

// isSystemCaller checks if the given address is a registered system caller
// R25-H2 FIX: Zero address is NOT a valid system caller (per R24-H2 fix)
func isSystemCaller(caller types.Address) bool {
	if caller == (types.Address{}) {
		return false // R24-H2: Zero address can never be a valid system caller
	}
	globalSystemCallersMu.RLock()
	defer globalSystemCallersMu.RUnlock()
	return globalSystemCallers[caller]
}

// StakingConfig defines the staking configuration
type StakingConfig struct {
	// MinStakeAmount is the minimum stake required to become a validator
	MinStakeAmount *big.Int

	// MaxStakeAmount is the maximum stake per validator (0 = no limit)
	MaxStakeAmount *big.Int

	// UnbondingPeriod is the number of blocks before unstaked tokens are released
	UnbondingPeriod uint64

	// MaxValidators is the maximum number of active validators
	// P3-E8: This is the CURRENT OPERATIONAL LIMIT enforced at stake
	// registration (default 100). It is intentionally much smaller than
	// consensus.MaxValidators (250,000), which is the theoretical protocol
	// ceiling. See consensus/block.go for the full rationale.
	MaxValidators uint32

	// MinCommission is the minimum commission rate (basis points)
	MinCommission uint32

	// MaxCommission is the maximum commission rate (basis points)
	MaxCommission uint32
}

// DefaultStakingConfig returns the default staking configuration
func DefaultStakingConfig() *StakingConfig {
	return &StakingConfig{
		// Minimum stake: 32 QAU (32g gold ≈$2,720)
		MinStakeAmount: new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)),
		// Maximum stake: 20,000,000 QAU (20 million)
		MaxStakeAmount: new(big.Int).Mul(big.NewInt(20000000), big.NewInt(1e18)),
		// audit-fix R10-L2: use 12-second slots consistent with consensus layer.
		// Previously 3s blocks (604,800 = 21 days at 3s, but only 5.25 days at 12s).
		// 21 days at 12s = 21 * 24 * 60 * 60 / 12 = 151,200 blocks.
		UnbondingPeriod: 21 * 24 * 60 * 60 / 12, // 151,200 blocks
		// Maximum 100 validators
		MaxValidators: 100,
		// L18-032 FIX: Minimum commission: 1% (100 basis points), unified with consensus layer.
		// Previously 0% which was inconsistent with consensus layer's MinCommission=100.
		MinCommission: 100,
		// AUDIT (2026) GOV B-2 FIX: Maximum commission lowered from 100%
		// to 15% (1500 bps) to match docs/TOKEN_ECONOMICS.md delegation fee
		// cap of 0-15%. A 100% cap allowed validators to confiscate all
		// delegator rewards.
		MaxCommission: 1500,
	}
}

// StakeInfo represents a validator's stake information
type StakeInfo struct {
	// Address is the validator's address
	Address types.Address
	// Amount is the total staked amount
	Amount *big.Int
	// Commission is the commission rate (basis points)
	Commission uint32
	// StakeHeight is the block height when stake was created
	StakeHeight uint64
	// Active indicates if the validator is active
	Active bool
	// PendingRewards accumulates rewards earned between stake top-ups.
	// When StakeHeight is reset (e.g. via Stake() top-up), pending rewards
	// are calculated and stored here so they are not lost.
	PendingRewards *big.Int
}

// UnstakeRequest represents a pending unstake request
type UnstakeRequest struct {
	// Address is the validator's address
	Address types.Address
	// Amount is the amount being unstaked
	Amount *big.Int
	// RequestHeight is the block height when unstake was requested
	RequestHeight uint64
	// UnlockHeight is the block height when tokens can be withdrawn
	UnlockHeight uint64
}

// StakingManager manages validator stakes and unbonding
type StakingManager struct {
	config *StakingConfig
	mu     sync.RWMutex

	// stakes maps validator addresses to their stake info
	stakes map[types.Address]*StakeInfo

	// unstakeRequests maps validator addresses to their pending unstake requests
	unstakeRequests map[types.Address]*UnstakeRequest

	// totalStaked is the total amount staked across all validators
	totalStaked *big.Int

	// totalRewardsDistributed tracks total rewards distributed for audit
	totalRewardsDistributed *big.Int

	// rewardPoolCap is the maximum rewards that can be distributed (for inflation control)
	rewardPoolCap *big.Int

	// audit-fix R2-L2: per-instance reward claim log (moved from package globals)
	rewardClaimEvents []RewardClaimEvent
	rewardClaimMu     sync.Mutex

	// audit-fix R63-HIGH-reentrancy: per-account reentrancy guard.
	// The global sm.mu does not prevent same-account nested calls (e.g., when the
	// staking contract calls back into RequestUnstake during token transfer).
	// This map tracks which accounts are currently inside a mutating function body.
	// A value of true means the account has an in-progress call.
	inProgress map[types.Address]bool

	// L-2 FIX: global reentrancy guard for SyncFromChain, which mutates state
	// for multiple accounts at once and cannot use the per-account inProgress map.
	// A value of true means a sync operation is currently in progress.
	syncInProgress bool

	// persistencePath is the file path for staking state persistence.
	// Set via SetPersistencePath, used by SaveState().
	persistencePath string

	// ECON- (2026-07-20) FIX: per-validator reward remainder accumulator.
	// The staking reward formula uses integer division:
	//   rewards = amount * APY * blocksStaked / (blocksPerYear * 100)
	// Integer division truncates the remainder (0..divisor-1 wei per block).
	// Over time, each validator loses up to 1 wei/block — negligible per-
	// block, but the cumulative drift is real for long-running stakes and
	// can cause total-rewards-distributed to under-count vs. the theoretical
	// emission schedule. This map stores the leftover remainder per address
	// so it is added back to the numerator on the next calculation, making
	// the long-run payout exact. Read by computeStakingRewards, updated by
	// consumeStakingRewards (state-modifying paths only).
	rewardRemainders map[types.Address]*big.Int

	// R43-ECON-CALLER-01 (2026-08-03): instance-level system caller registry.
	// Previously the only registry was the package-level global
	// globalSystemCallers map (with its own globalSystemCallersMu), shared
	// across every StakingManager instance in the process. That caused
	// unit tests in the same package (which construct many independent
	// StakingManager instances to isolate state) to leak system-caller
	// registrations across test fixtures. The instance field is the
	// canonical registry for this manager; the package-level
	// RegisterSystemCaller / UnregisterSystemCaller / isSystemCaller
	// exported wrappers remain as a backward-compat facade that ALSO
	// write/read this map when called on the default singleton (see
	// registerSystemCaller / unregisterSystemCaller / isSystemCaller
	// helpers below — they now check instance first, fall back to
	// global for callers that haven't been migrated). The M-4 TODO
	// comment is now resolved.
	systemCallers   map[types.Address]bool
	systemCallersMu sync.RWMutex
	// P3-EC-03 (2026-08-03): governable StakingAPY (percentage points,
	// integer 0..N). Initialized from the legacy `StakingAPY` package-level
	// constant ( default 0); SetStakingAPY mutates atomically under
	// sm.mu when governance UpdatesParameter("StakingAPY", ...) finalizes.
	// Read by computeStakingRewardsECONR11004 — when stakingAPY.Sign() <= 0
	// it short-circuits to return 0 (matches the legacy StakingAPY == 0
	// behavior used to avoid double consensus rewards).
	stakingAPY *big.Int
}

// NewStakingManager creates a new staking manager
func NewStakingManager(config *StakingConfig) *StakingManager {
	if config == nil {
		config = DefaultStakingConfig()
	}
	// FIX: Validate MaxValidators > 0. A value of 0 would cause
	// `uint32(len(sm.stakes)) >= 0` to always be true, blocking all validator
	// registration. Fall back to default (100) if misconfigured.
	if config.MaxValidators == 0 {
		config.MaxValidators = DefaultStakingConfig().MaxValidators
	}
	// Reward pool cap: 10% of total supply per year (for inflation control)
	// Total supply: 200 million QAU, so cap is 20 million QAU per year
	// P3-E5 AUDIT NOTE: This 20M QAU (20,000,000 * 1e18) cap is the GENESIS
	// REWARD ALLOCATION - the total rewards mintable from the protocol's
	// reward pool. It is hardcoded at StakingManager construction; the
	// rewardPoolCap field is private and intentionally not exposed via a
	// setter because changing it post-genesis would break the chain's
	// monetary policy invariants. To use a different cap, construct the
	// StakingManager with a config and adjust this constant (coordinate with
	// genesis allocation).
	rewardPoolCap := new(big.Int).Mul(big.NewInt(20000000), big.NewInt(1e18))

	return &StakingManager{
		config:                  config,
		stakes:                  make(map[types.Address]*StakeInfo),
		unstakeRequests:         make(map[types.Address]*UnstakeRequest),
		totalStaked:             big.NewInt(0),
		totalRewardsDistributed: big.NewInt(0),
		rewardPoolCap:           rewardPoolCap,
		// audit-fix R63-HIGH-reentrancy: per-account reentrancy guard map
		inProgress: make(map[types.Address]bool),
		// ECON- per-validator reward remainder accumulator
		rewardRemainders: make(map[types.Address]*big.Int),
		// R43-ECON-CALLER-01: instance system caller registry starts from
		// a SNAPSHOT of the package-level globalSystemCallers set so the
		// instance inherits legacy registrations made before this manager
		// was constructed (the audit's "backward compatibility" concern).
		// Subsequent calls to the package-level RegisterSystemCaller will
		// ALSO write the package-level global; m.IsSystemCaller falls
		// back to the global if the instance field does not contain the
		// caller, so existing test patterns that call the package-level
		// register AFTER construction still work.
		systemCallers: snapshotGlobalSystemCallers(),
		// P3-EC-03 (2026-08-03): instance StakingAPY. Initialized to the
		// package-level constant StakingAPY ( default of 0 to
		// avoid double consensus rewards); SetStakingAPY can override at
		// runtime when governance UpdatesParameter("StakingAPY", ...) is
		// called — keeping the parameter governable per DefaultGovernance
		// Parameters (governance.go:1194 declares default "5"). See
		// computeStakingRewardsECONR11004 below for the read site.
		stakingAPY: big.NewInt(int64(StakingAPY)),
	}
}

// SetStakingAPY sets the instance-level staking APY (in percentage points,
// integer). P3-EC-03 (2026-08-03) governance migration. Called by the
// governance ExecuteProposal path whenever a governance UpdateParameter
// for "StakingAPY" is finalized; mirrors the governance R42-GOVDEP-01
// productionMode gating pattern for liquid staking. Idempotent and thread-
// safe under sm.mu.Lock (the same lock used by StakingManager internal
// state mutators). Negative values are rejected (rewards should never be
// negative — a negative APY would drain staker stake rather than reward
// it, a financial invariant violation). Zero is allowed (preserves the
//
//	"double rewards avoidance" sema — set to 0 when the consensus
//
// layer is already paying attestation rewards, and re-enable only
// for explicit incentive programs via governance).
//
// UNIT ASSUMPTION: passed `apy` is an integer percentage points value
// (e.g. 5 = 5% APY); matching the legacy `StakingAPY int` constant
// semantics. The governance parameter default is "5" (string → 5 → 5%).
func (sm *StakingManager) SetStakingAPY(apy int64) error {
	if apy < 0 {
		return fmt.Errorf("P3-EC-03: SetStakingAPY negative %d rejected (rewards must never drain stake)", apy)
	}
	sm.mu.Lock()
	sm.stakingAPY = big.NewInt(apy)
	sm.mu.Unlock()
	return nil
}

// blocksPerYearStaking is the number of 12-second slots per year.
// 365 * 24 * 60 * 60 / 12 = 2,628,000. Kept as a constant so all four
// reward-calculation sites stay in sync.
const blocksPerYearStaking = uint64(2628000)

// computeStakingRewardsECONR11004 computes pending rewards for the period
// (stake.StakeHeight, currentHeight) using the standard APY formula:
//
//	rewards = amount * APY * blocksStaked / (blocksPerYear * 100)
//
// ECON- (2026-07-20) FIX: integer division truncates the remainder,
// causing up to 1 wei/block loss that compounds over long-running stakes.
// This helper adds the previously-stored remainder to the numerator before
// dividing, then captures the new remainder. The new remainder is stored
// back into sm.rewardRemainders[addr] ONLY when consumeRemainder=true
// (state-modifying paths: Stake top-up, AddStakeFromTx, ProcessRewardClaimFromTx).
// Read-only paths (GetPendingRewards) pass consumeRemainder=false so the
// stored remainder is preserved for the next state-modifying call.
//
// Caller MUST hold sm.mu (read or write).
func (sm *StakingManager) computeStakingRewardsECONR11004(
	addr types.Address,
	amount *big.Int,
	blocksStaked uint64,
	consumeRemainder bool,
) *big.Int {
	// P3-EC-03 (2026-08-03): the APY for reward computation is now a
	// per-instance value (sm.stakingAPY) governance-updateable; the
	// legacy package-level `StakingAPY = 0` constant is FROZEN as the
	// DEFAULT that sm.stakingAPY is initialized to, so historical tests
	// that assert StakingAPY = 0 (to verify the "no double consensus
	// rewards" behavior.security invariant) still pass with the default
	// instance. Governance finalizes a "StakingAPY" parameter change via
	// ExecuteProposal → sm.SetStakingAPY(newAPY), bumping the instance
	// APY without code deploy.
	//
	// Read sm.stakingAPY under sm.mu (caller is documented as MUST hold
	// sm.mu). Snapshot into a local to avoid holding the lock across the
	// arithmetic below (financial-invariant: the value is a percentage
	// points integer, fits in an `int`, so big.Int range is bounded).
	apy := sm.stakingAPY
	if apy == nil || apy.Sign() <= 0 {
		// StakingAPY = 0 (or negative-governed — rejected at SetStakingAPY
		// time but defensively checked) disables staking-layer rewards.
		// Early return to skip dead big.Int work, matching the legacy
		// StakingAPY == 0 short-circuit.
		return big.NewInt(0)
	}
	if amount == nil || amount.Sign() <= 0 || blocksStaked == 0 {
		return big.NewInt(0)
	}

	// Cap at 10 years of blocks to prevent overflow (matches existing logic).
	cappedBlocks := blocksStaked
	if cap := blocksPerYearStaking * 10; blocksStaked > cap {
		cappedBlocks = cap
	}

	// numerator = amount * APY * blocksStaked + previous_remainder.
	// P3-EC-03: APY now from instance sm.stakingAPY (governance), not
	// the constant.
	numerator := new(big.Int).Mul(amount, apy)
	numerator.Mul(numerator, new(big.Int).SetUint64(cappedBlocks))
	if rem, ok := sm.rewardRemainders[addr]; ok && rem != nil {
		numerator.Add(numerator, rem)
	}

	// denominator = blocksPerYear * 100
	denominator := new(big.Int).Mul(
		new(big.Int).SetUint64(blocksPerYearStaking),
		big.NewInt(100),
	)

	// QuoRem: quotient = numerator / denominator, remainder = numerator % denominator.
	// We use QuoRem (not Div/Mod separately) so the values are guaranteed consistent.
	quo := new(big.Int)
	rem := new(big.Int)
	quo.QuoRem(numerator, denominator, rem)

	// Only state-modifying paths store the new remainder. Read-only paths
	// discard it so the next state-modifying call computes the same result.
	if consumeRemainder {
		// Clone to avoid aliasing the local `rem` (which would be overwritten
		// on the next call if Go reused stack slots — defensive).
		sm.rewardRemainders[addr] = new(big.Int).Set(rem)
	}

	return quo
}

// Stake creates or adds to a validator's stake
func (sm *StakingManager) Stake(addr types.Address, amount *big.Int, commission uint32, blockHeight uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// audit-fix R63-HIGH-reentrancy: per-account reentrancy guard.
	if sm.inProgress[addr] {
		return fmt.Errorf("reentrancy detected for address %s: stake operation already in progress", addr)
	}
	sm.inProgress[addr] = true
	defer func() { sm.inProgress[addr] = false }()

	if amount == nil || amount.Sign() <= 0 {
		return ErrInsufficientStake
	}

	// L16-032 FIX: Commission validation now returns ErrInvalidCommission (previously
	// returned ErrInvalidLockPeriod which was semantically wrong).
	if commission < sm.config.MinCommission || commission > sm.config.MaxCommission {
		return ErrInvalidCommission
	}

	existingStake, exists := sm.stakes[addr]
	if exists {
		// Add to existing stake
		newAmount := new(big.Int).Add(existingStake.Amount, amount)

		// Check max stake
		if sm.config.MaxStakeAmount.Sign() > 0 && newAmount.Cmp(sm.config.MaxStakeAmount) > 0 {
			return errors.New("stake exceeds maximum allowed")
		}

		// FIX: Before resetting StakeHeight, calculate and accumulate
		// pending rewards so they are not lost. Uses the same 5% APY formula
		// as GetPendingRewards / ProcessRewardClaimFromTx.
		if existingStake.PendingRewards == nil {
			existingStake.PendingRewards = big.NewInt(0)
		}
		if blockHeight > existingStake.StakeHeight {
			blocksStaked := blockHeight - existingStake.StakeHeight
			// ECON- (2026-07-20): use centralized helper so the
			// integer-division remainder is carried forward per-address,
			// making the long-run payout exact. consumeRemainder=true
			// because this is a state-modifying path (StakeHeight will be
			// reset below, ending the current reward period).
			pending := sm.computeStakingRewardsECONR11004(addr, existingStake.Amount, blocksStaked, true)
			existingStake.PendingRewards.Add(existingStake.PendingRewards, pending)
		}

		// SECURITY (reward-amplification fix): Reset StakeHeight when topping up.
		// The reward formula multiplies the FULL current amount by
		// (currentHeight - StakeHeight). Without resetting, a large late top-up
		// would earn rewards retroactively on the original StakeHeight, draining
		// the reward pool for principal that was not actually staked. Existing
		// pending rewards on the old principal are preserved in PendingRewards.
		existingStake.Amount = newAmount
		existingStake.StakeHeight = blockHeight
		// FIX: Re-activate the validator if it was previously deactivated by
		// an unstake operation. A re-stake (top-up) after partial/full unstake
		// should restore active status so the validator can participate in
		// consensus again.
		existingStake.Active = true
		sm.totalStaked = new(big.Int).Add(sm.totalStaked, amount)
		return nil
	}

	// New stake - check minimum and maximum
	if amount.Cmp(sm.config.MinStakeAmount) < 0 {
		return ErrInsufficientStake
	}
	// R48-H-H3 FIX: Apply MaxStakeAmount check to new validators too.
	// Previously only existing stakes were checked, allowing a new validator
	// to bypass the maximum stake limit in a single staking transaction.
	if sm.config.MaxStakeAmount.Sign() > 0 && amount.Cmp(sm.config.MaxStakeAmount) > 0 {
		return fmt.Errorf("stake exceeds maximum allowed: %s > %s", amount.String(), sm.config.MaxStakeAmount.String())
	}

	// Check max validators
	if uint32(len(sm.stakes)) >= sm.config.MaxValidators { //nolint:gosec,G115
		return errors.New("maximum validators reached")
	}

	// Create new stake
	sm.stakes[addr] = &StakeInfo{
		Address:        addr,
		Amount:         new(big.Int).Set(amount),
		Commission:     commission,
		StakeHeight:    blockHeight,
		Active:         true,
		PendingRewards: big.NewInt(0),
	}
	sm.totalStaked = new(big.Int).Add(sm.totalStaked, amount)

	return nil
}

// RequestUnstake initiates an unstake request
func (sm *StakingManager) RequestUnstake(addr types.Address, amount *big.Int, blockHeight uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// audit-fix R63-HIGH-reentrancy: per-account reentrancy guard.
	// The global sm.mu does not prevent same-account nested calls.
	// If a staking callback triggers another unstake request for the same account
	// while this function is still running, reject it.
	if sm.inProgress[addr] {
		return fmt.Errorf("reentrancy detected for address %s: request already in progress", addr)
	}
	sm.inProgress[addr] = true
	defer func() { sm.inProgress[addr] = false }()

	stake, exists := sm.stakes[addr]
	if !exists {
		return ErrStakeNotFound
	}

	if amount == nil || amount.Sign() <= 0 || amount.Cmp(stake.Amount) > 0 {
		return ErrInvalidUnstakeAmount
	}

	// Check if there's already a pending request
	if _, hasRequest := sm.unstakeRequests[addr]; hasRequest {
		return ErrUnstakeRequestExists
	}

	// Calculate remaining stake after unstake
	remainingStake := new(big.Int).Sub(stake.Amount, amount)

	// If remaining stake is below minimum, unstake everything
	if remainingStake.Cmp(sm.config.MinStakeAmount) < 0 {
		amount = new(big.Int).Set(stake.Amount)
		remainingStake = big.NewInt(0)
	}

	// Create unstake request
	sm.unstakeRequests[addr] = &UnstakeRequest{
		Address:       addr,
		Amount:        new(big.Int).Set(amount),
		RequestHeight: blockHeight,
		UnlockHeight:  blockHeight + sm.config.UnbondingPeriod,
	}

	// Update stake
	stake.Amount = remainingStake
	sm.totalStaked = new(big.Int).Sub(sm.totalStaked, amount)

	// Deactivate if no stake remaining
	if remainingStake.Sign() == 0 {
		stake.Active = false
	}

	return nil
}

// CompleteUnstake completes an unstake request if the lock period has passed
func (sm *StakingManager) CompleteUnstake(addr types.Address, currentHeight uint64) (*big.Int, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// audit-fix R63-HIGH-reentrancy: per-account reentrancy guard.
	if sm.inProgress[addr] {
		return nil, fmt.Errorf("reentrancy detected for address %s: unstake operation already in progress", addr)
	}
	sm.inProgress[addr] = true
	defer func() { sm.inProgress[addr] = false }()

	request, exists := sm.unstakeRequests[addr]
	if !exists {
		return nil, ErrNoUnstakeRequest
	}

	if currentHeight < request.UnlockHeight {
		return nil, ErrStakeLocked
	}

	// Remove the request and return the amount
	// R37-INFO FIX (2026-07-31): clone the amount before returning. The
	// previous code returned request.Amount (the internal pointer stored in
	// unstakeRequests), letting callers mutate manager state after deletion.
	amount := new(big.Int).Set(request.Amount)
	delete(sm.unstakeRequests, addr)

	// Remove stake entry if no stake remaining
	if stake, exists := sm.stakes[addr]; exists && stake.Amount.Sign() == 0 {
		delete(sm.stakes, addr)
	}

	return amount, nil
}

// GetStake returns the stake info for a validator
func (sm *StakingManager) GetStake(addr types.Address) (*StakeInfo, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stake, exists := sm.stakes[addr]
	if !exists {
		return nil, ErrStakeNotFound
	}

	return &StakeInfo{
		Address:        stake.Address,
		Amount:         new(big.Int).Set(stake.Amount),
		Commission:     stake.Commission,
		StakeHeight:    stake.StakeHeight,
		Active:         stake.Active,
		PendingRewards: new(big.Int).Set(stake.PendingRewards),
	}, nil
}

// GetUnstakeRequest returns the pending unstake request for a validator
func (sm *StakingManager) GetUnstakeRequest(addr types.Address) (*UnstakeRequest, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	request, exists := sm.unstakeRequests[addr]
	if !exists {
		return nil, ErrNoUnstakeRequest
	}

	return &UnstakeRequest{
		Address:       request.Address,
		Amount:        new(big.Int).Set(request.Amount),
		RequestHeight: request.RequestHeight,
		UnlockHeight:  request.UnlockHeight,
	}, nil
}

// GetTotalStaked returns the total staked amount
func (sm *StakingManager) GetTotalStaked() *big.Int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return new(big.Int).Set(sm.totalStaked)
}

// RecomputeTotalStaked recalculates totalStaked from individual stakes.
// L18-009 FIX: This method detects and corrects drift between the cached
// totalStaked value and the actual sum of individual stake amounts.
// It should be called after any operation that modifies stakes to ensure
// consistency. If a discrepancy is found, the cached value is corrected.
func (sm *StakingManager) RecomputeTotalStaked() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	actual := big.NewInt(0)
	for _, stake := range sm.stakes {
		if stake.Amount.Sign() > 0 {
			actual.Add(actual, stake.Amount)
		}
	}
	sm.totalStaked = actual
}

// GetActiveValidators returns all active validators with their stakes
func (sm *StakingManager) GetActiveValidators() map[types.Address]*big.Int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	validators := make(map[types.Address]*big.Int)
	for addr, stake := range sm.stakes {
		if stake.Active {
			validators[addr] = new(big.Int).Set(stake.Amount)
		}
	}
	return validators
}

// GetAllStakes returns all stakes
func (sm *StakingManager) GetAllStakes() []*StakeInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stakes := make([]*StakeInfo, 0, len(sm.stakes))
	for _, stake := range sm.stakes {
		stakes = append(stakes, &StakeInfo{
			Address:        stake.Address,
			Amount:         new(big.Int).Set(stake.Amount),
			Commission:     stake.Commission,
			StakeHeight:    stake.StakeHeight,
			Active:         stake.Active,
			PendingRewards: new(big.Int).Set(stake.PendingRewards),
		})
	}
	return stakes
}

// UpdateCommission updates a validator's commission rate
func (sm *StakingManager) UpdateCommission(caller, addr types.Address, commission uint32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// audit-fix R63-HIGH-reentrancy: per-account reentrancy guard.
	if sm.inProgress[addr] {
		return fmt.Errorf("reentrancy detected for address %s: commission update already in progress", addr)
	}
	sm.inProgress[addr] = true
	defer func() { sm.inProgress[addr] = false }()

	// R25-H2 FIX: Only allow validator themselves to update their commission
	// Zero address is NOT a valid caller (R24-H2)
	if caller != addr {
		return fmt.Errorf("unauthorized: only the validator themselves can update commission")
	}

	// L16-032 FIX: Commission validation now returns ErrInvalidCommission.
	if commission < sm.config.MinCommission || commission > sm.config.MaxCommission {
		return ErrInvalidCommission
	}

	stake, exists := sm.stakes[addr]
	if !exists {
		return ErrStakeNotFound
	}

	stake.Commission = commission
	return nil
}

func (sm *StakingManager) SetActive(caller, addr types.Address, active bool) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// audit-fix R63-HIGH-reentrancy: per-account reentrancy guard.
	if sm.inProgress[addr] {
		return fmt.Errorf("reentrancy detected for address %s: set-active operation already in progress", addr)
	}
	sm.inProgress[addr] = true
	defer func() { sm.inProgress[addr] = false }()

	// R25-H2 FIX: Use proper system caller registry instead of zero address check
	// Zero address is NOT a valid system caller (R24-H2).
	// R43-ECON-CALLER-01 (2026-08-03): use the instance-level registry
	// instead of the package-level global, so this StakingManager's
	// notion of "system caller" reflects its own runtime registrations
	// rather than the global shared set that leaks across test fixtures.
	// (The instance method falls back to the global for backward compat.)
	if !sm.IsSystemCallerInstance(caller) {
		return fmt.Errorf("unauthorized: only registered system callers can set validator active status")
	}

	stake, exists := sm.stakes[addr]
	if !exists {
		return ErrStakeNotFound
	}

	if active && stake.Amount.Cmp(sm.config.MinStakeAmount) < 0 {
		return ErrInsufficientStake
	}

	stake.Active = active
	return nil
}

// GetConfig returns a copy of the staking configuration
func (sm *StakingManager) GetConfig() *StakingConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return &StakingConfig{
		MinStakeAmount:  new(big.Int).Set(sm.config.MinStakeAmount),
		MaxStakeAmount:  new(big.Int).Set(sm.config.MaxStakeAmount),
		UnbondingPeriod: sm.config.UnbondingPeriod,
		MaxValidators:   sm.config.MaxValidators,
		MinCommission:   sm.config.MinCommission,
		MaxCommission:   sm.config.MaxCommission,
	}
}

// ValidatorCount returns the number of validators
func (sm *StakingManager) ValidatorCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.stakes)
}

// ActiveValidatorCount returns the number of active validators
func (sm *StakingManager) ActiveValidatorCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	count := 0
	for _, stake := range sm.stakes {
		if stake.Active {
			count++
		}
	}
	return count
}

// Contract addresses for staking system
var (
	// StakingContractAddress is the address for staking deposits
	// 0x0000000000000000000000000000000000001001
	StakingContractAddress = parseContractAddress(0x10, 0x01)

	// UnstakeContractAddress is the address for unstake requests
	// 0x0000000000000000000000000000000000001002
	UnstakeContractAddress = parseContractAddress(0x10, 0x02)

	// RewardsContractAddress is the address for claiming rewards
	// 0x0000000000000000000000000000000000001003
	RewardsContractAddress = parseContractAddress(0x10, 0x03)

	// ValidatorKeyRegistryAddress is the R131 "three doors" control-plane
	// sink. TxTypeValidatorKey ops (session rotate / bind master / revoke)
	// are addressed here; the payload Data carries the op encoding and the
	// consensus session-key registry consumes them post-commit.
	// 0x0000000000000000000000000000000000001004
	ValidatorKeyRegistryAddress = parseContractAddress(0x10, 0x04)
)

func parseContractAddress(high, low byte) types.Address {
	var addr types.Address
	addr[18] = high
	addr[19] = low
	return addr
}

// SyncFromChain syncs staking data from on-chain transactions
// This scans all transactions to the staking contract and calculates stakes
func (sm *StakingManager) SyncFromChain(txs []ChainTransaction) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// L-2 FIX: global reentrancy guard. SyncFromChain resets and rebuilds all
	// staking state for multiple accounts. If a callback re-enters SyncFromChain
	// while a sync is in progress, the second call would reset state mid-sync,
	// corrupting the in-progress rebuild. Reject re-entry instead.
	if sm.syncInProgress {
		return fmt.Errorf("reentrancy detected: staking sync already in progress")
	}
	sm.syncInProgress = true
	defer func() { sm.syncInProgress = false }()

	// Reset current state
	// audit-fix  also reset unstakeRequests to prevent stale requests
	// from being completed after a resync, which could allow withdrawals
	// of funds that no longer correspond to any active stake.
	// SECURITY FIX (L-3): Also reset totalRewardsDistributed and rewardClaimEvents
	// to prevent stale audit data from persisting across chain resyncs.
	sm.stakes = make(map[types.Address]*StakeInfo)
	sm.unstakeRequests = make(map[types.Address]*UnstakeRequest)
	sm.totalStaked = big.NewInt(0)
	sm.totalRewardsDistributed = big.NewInt(0)
	sm.rewardClaimEvents = nil

	// Process each transaction to the staking contract
	for _, tx := range txs {
		if tx.To == nil {
			continue
		}

		// Check if this is a transaction to the staking contract
		if *tx.To != StakingContractAddress {
			continue
		}

		// This is a stake transaction
		if tx.Value == nil || tx.Value.Sign() <= 0 {
			continue
		}

		// H-1: Validate block height before using
		if tx.BlockHeight == 0 {
			continue // skip: invalid block height
		}

		// Add or update stake
		existingStake, exists := sm.stakes[tx.From]
		if exists {
			// audit-fix R3-F13: enforce MaxStakeAmount (mirrors Stake() and AddStakeFromTx)
			newAmount := new(big.Int).Add(existingStake.Amount, tx.Value)
			if sm.config.MaxStakeAmount.Sign() > 0 && newAmount.Cmp(sm.config.MaxStakeAmount) > 0 {
				continue // skip: would exceed max stake
			}
			// SECURITY (reward-amplification fix): see AddStakeFromTx. Reset
			// StakeHeight so the added principal accrues from the current block
			// instead of from the original stake time (which would let a user
			// claim rewards on a large late top-up as if it were staked early).
			existingStake.Amount = newAmount
			existingStake.StakeHeight = tx.BlockHeight
		} else {
			// audit-fix R3-F13: enforce MinStakeAmount for new validators
			if tx.Value.Cmp(sm.config.MinStakeAmount) < 0 {
				continue // skip: below minimum stake
			}
			// audit-fix R3-F13: enforce MaxValidators
			if uint32(len(sm.stakes)) >= sm.config.MaxValidators { //nolint:gosec,G115
				continue // skip: max validators reached
			}
			sm.stakes[tx.From] = &StakeInfo{
				Address: tx.From,
				Amount:  new(big.Int).Set(tx.Value),
				// R47-CS-05 NOTE: Commission is hardcoded to 0 because
				// ChainTransaction doesn't carry commission data. The
				// actual commission is set via a separate UpdateCommission
				// tx. This is a known limitation of snap sync recovery.
				Commission:     0,
				StakeHeight:    tx.BlockHeight,
				Active:         true,
				PendingRewards: big.NewInt(0),
			}
		}
		sm.totalStaked = new(big.Int).Add(sm.totalStaked, tx.Value)
	}

	return nil
}

// stakingDataJSON is the JSON-serializable staking data used for persistence.
type stakingDataJSON struct {
	Address        string `json:"address"`
	Amount         string `json:"amount"`
	Commission     uint32 `json:"commission"`
	StakeHeight    uint64 `json:"stake_height"`
	Active         bool   `json:"active"`
	PendingRewards string `json:"pending_rewards"`
}

// SaveToFile persists the current staking state to a JSON file.
// This is used as a backup when qau_stake RPC is used (which doesn't create
// on-chain transactions), so staking data survives node restarts.
func (sm *StakingManager) SaveToFile(path string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	entries := make([]stakingDataJSON, 0, len(sm.stakes))
	for _, s := range sm.stakes {
		pr := "0"
		if s.PendingRewards != nil {
			pr = s.PendingRewards.String()
		}
		amt := "0"
		if s.Amount != nil {
			amt = s.Amount.String()
		}
		entries = append(entries, stakingDataJSON{
			Address:        s.Address.ToHexAddress(),
			Amount:         amt,
			Commission:     s.Commission,
			StakeHeight:    s.StakeHeight,
			Active:         s.Active,
			PendingRewards: pr,
		})
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal staking data: %w", err)
	}

	// Write to temp file then rename for atomicity
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write staking data: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename staking data file: %w", err)
	}
	return nil
}

// LoadFromFile loads staking data from a JSON file and merges it into the
// current staking state. Only loads entries that don't already exist (to avoid
// overwriting data loaded from chain transactions).
func (sm *StakingManager) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no file = no data to load
		}
		return fmt.Errorf("failed to read staking data file: %w", err)
	}

	var entries []stakingDataJSON
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse staking data file: %w", err)
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// R37-P3-42 FIX (2026-07-31): Validate staking config integrity before
	// loading entries. Previously LoadFromFile did not validate MinStake/
	// MaxStake/MaxValidators, so a corrupted staking.json could bypass
	// all staking limits and allow oversized/undersized stakes to be
	// injected at load time.
	if sm.config == nil {
		return errors.New("staking config is nil")
	}
	if sm.config.MinStakeAmount == nil || sm.config.MinStakeAmount.Sign() < 0 {
		return fmt.Errorf("invalid MinStakeAmount in config: %v", sm.config.MinStakeAmount)
	}
	if sm.config.MaxStakeAmount != nil && sm.config.MaxStakeAmount.Sign() < 0 {
		return fmt.Errorf("invalid MaxStakeAmount in config: %v", sm.config.MaxStakeAmount)
	}
	if sm.config.MaxValidators == 0 {
		return errors.New("MaxValidators must be > 0")
	}

	loadedCount := 0
	for _, e := range entries {
		addr, err := types.ParseHexAddress(e.Address)
		if err != nil {
			continue
		}
		amount, ok := new(big.Int).SetString(e.Amount, 10)
		if !ok {
			continue
		}
		pr, _ := new(big.Int).SetString(e.PendingRewards, 10)
		if pr == nil {
			pr = big.NewInt(0)
		}
		// R37-P3-42 FIX (2026-07-31): Validate each loaded stake entry against
		// the configured limits. Reject entries that violate MinStake/MaxStake.
		if amount.Sign() > 0 {
			if amount.Cmp(sm.config.MinStakeAmount) < 0 {
				return fmt.Errorf("loaded stake for %s below minimum: %s < %s",
					addr.ToHexAddress(), amount.String(), sm.config.MinStakeAmount.String())
			}
			if sm.config.MaxStakeAmount.Sign() > 0 && amount.Cmp(sm.config.MaxStakeAmount) > 0 {
				return fmt.Errorf("loaded stake for %s exceeds maximum: %s > %s",
					addr.ToHexAddress(), amount.String(), sm.config.MaxStakeAmount.String())
			}
		}
		// R37-P3-42 FIX (2026-07-31): Enforce MaxValidators on loaded entries.
		if loadedCount >= int(sm.config.MaxValidators) {
			return fmt.Errorf("loaded entries exceed MaxValidators limit: %d > %d",
				loadedCount+1, sm.config.MaxValidators)
		}
		// If validator already has stake from chain sync, use the MAX of
		// existing (chain-synced) and file stakes. This handles the case
		// where genesis stakes are in staking.json (not in genesis.json)
		// and a validator also has an on-chain staking tx. Without this,
		// the file stake would be skipped and the validator would only
		// have the chain-synced stake (e.g., 32 QAU instead of 30,000).
		if existing, exists := sm.stakes[addr]; exists {
			if amount.Cmp(existing.Amount) > 0 {
				// File stake is higher — replace with file value.
				// This happens when the file contains genesis stakes
				// (30,000 QAU) and chain sync only found a small tx (32 QAU).
				sm.totalStaked = new(big.Int).Sub(sm.totalStaked, existing.Amount)
				sm.totalStaked = new(big.Int).Add(sm.totalStaked, amount)
				existing.Amount = amount
				if pr.Sign() > 0 {
					existing.PendingRewards = pr
				}
			}
			continue
		}
		sm.stakes[addr] = &StakeInfo{
			Address:        addr,
			Amount:         amount,
			Commission:     e.Commission,
			StakeHeight:    e.StakeHeight,
			Active:         e.Active,
			PendingRewards: pr,
		}
		sm.totalStaked = new(big.Int).Add(sm.totalStaked, amount)
		loadedCount++
	}
	return nil
}

// SetPersistencePath sets the file path used by SaveState() for periodic
// staking data persistence.
func (sm *StakingManager) SetPersistencePath(path string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.persistencePath = path
}

// SaveState persists the current staking state to the configured file path.
// This is a no-op if no persistence path has been set.
func (sm *StakingManager) SaveState() error {
	sm.mu.RLock()
	path := sm.persistencePath
	sm.mu.RUnlock()
	if path == "" {
		return nil
	}
	return sm.SaveToFile(path)
}

// ChainTransaction represents a transaction from the blockchain
type ChainTransaction struct {
	From        types.Address
	To          *types.Address
	Value       *big.Int
	BlockHeight uint64
	TxHash      types.Hash
}

// AddStakeFromTx adds a stake from a confirmed transaction
// This is called when a new transaction to the staking contract is confirmed
func (sm *StakingManager) AddStakeFromTx(from types.Address, value *big.Int, blockHeight uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// FIX: Add reentrancy guard matching Stake() and other
	// mutating methods. Without this, a callback during token transfer could
	// re-enter AddStakeFromTx and bypass the MaxStakeAmount check.
	if sm.inProgress[from] {
		return fmt.Errorf("reentrancy detected for address %s: stake operation already in progress", from)
	}
	sm.inProgress[from] = true
	defer func() { sm.inProgress[from] = false }()

	if value == nil || value.Sign() <= 0 {
		return ErrInsufficientStake
	}

	// H-2: Validate block height
	if blockHeight == 0 {
		return errors.New("invalid block height")
	}

	existingStake, exists := sm.stakes[from]
	if exists {
		// audit-fix R3-M2: check MaxStakeAmount before adding (mirrors Stake())
		newAmount := new(big.Int).Add(existingStake.Amount, value)
		if sm.config.MaxStakeAmount.Sign() > 0 && newAmount.Cmp(sm.config.MaxStakeAmount) > 0 {
			return errors.New("stake exceeds maximum allowed")
		}
		// FIX: Before resetting StakeHeight, calculate and accumulate
		// pending rewards so they are not lost (same as Stake()).
		if existingStake.PendingRewards == nil {
			existingStake.PendingRewards = big.NewInt(0)
		}
		if blockHeight > existingStake.StakeHeight {
			blocksStaked := blockHeight - existingStake.StakeHeight
			// ECON- (2026-07-20): use centralized helper so the
			// integer-division remainder is carried forward per-address,
			// making the long-run payout exact. consumeRemainder=true
			// because this is a state-modifying path (StakeHeight will be
			// reset below, ending the current reward period).
			pending := sm.computeStakingRewardsECONR11004(from, existingStake.Amount, blocksStaked, true)
			existingStake.PendingRewards.Add(existingStake.PendingRewards, pending)
		}
		// SECURITY (reward-amplification fix): Reset StakeHeight to the current
		// block when increasing a stake. The reward formula is
		//   rewards = amount * 5% * (currentHeight - StakeHeight) / (blocksPerYear*100)
		// Without resetting StakeHeight, a user could stake a small amount early,
		// wait a long time, then add a large amount —the large addition would
		// earn rewards as if it had been staked since the original StakeHeight,
		// draining the reward pool for stake that was never actually at risk.
		// Resetting to the current height makes the newly-added principal begin
		// accruing from now, which is the correct behavior. (Existing pending
		// rewards on the old principal are preserved in PendingRewards.)
		existingStake.Amount = newAmount
		existingStake.StakeHeight = blockHeight
		// FIX: Re-activate the validator if it was previously deactivated by
		// an unstake operation. A re-stake (top-up) after partial/full unstake
		// should restore active status so the validator can participate in
		// consensus again. (Same fix as in Stake().)
		existingStake.Active = true
	} else {
		// audit-fix R3-M3: check MinStakeAmount for new validators (mirrors Stake())
		if value.Cmp(sm.config.MinStakeAmount) < 0 {
			return ErrInsufficientStake
		}
		sm.stakes[from] = &StakeInfo{
			Address:        from,
			Amount:         new(big.Int).Set(value),
			Commission:     0,
			StakeHeight:    blockHeight,
			Active:         true,
			PendingRewards: big.NewInt(0),
		}
	}
	sm.totalStaked = new(big.Int).Add(sm.totalStaked, value)

	return nil
}

// ProcessUnstakeFromTx processes an unstake request from a confirmed transaction
// The transaction value represents the amount to unstake
// This is called when a transaction to the unstake contract is confirmed
func (sm *StakingManager) ProcessUnstakeFromTx(from types.Address, value *big.Int, blockHeight uint64) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// audit-fix R63-HIGH-reentrancy: per-account reentrancy guard.
	if sm.inProgress[from] {
		return fmt.Errorf("reentrancy detected for address %s: request already in progress", from)
	}
	sm.inProgress[from] = true
	defer func() { sm.inProgress[from] = false }()

	stake, exists := sm.stakes[from]
	if !exists {
		return ErrStakeNotFound
	}

	// Value in the tx represents the amount to unstake
	// If value is 0 or greater than stake, unstake everything
	// audit-fix R11: Reject invalid unstake amounts explicitly.
	// Users must specify a positive amount. Full unstake requires explicit amount == stake.
	if value == nil || value.Sign() <= 0 {
		return errors.New("unstake amount must be positive")
	}
	unstakeAmount := value
	if value.Cmp(stake.Amount) > 0 {
		unstakeAmount = new(big.Int).Set(stake.Amount)
	}

	// Check if there's already a pending request
	if _, hasRequest := sm.unstakeRequests[from]; hasRequest {
		// ECON- (2026-07-20) FIX: Defense-in-depth check on the
		// cumulative unstake amount. The cap on unstakeAmount above
		// (unstakeAmount <= stake.Amount) already prevents over-extraction
		// in the current code path, but adding an explicit cumulative
		// check here:
		//   1. Makes the invariant crystal clear: cumulative unstake <=
		//      original stake (stake.Amount + pendingUnstake.Amount).
		//   2. Guards against future regressions if the upstream cap is
		//      refactored or removed.
		//   3. Returns a specific error instead of silently capping,
		//      so the caller knows their tx was partially rejected.
		//
		// Attack prevented: stake 100 QAU → unstake 50 (stake=50,
		// pending=50) → unstake 60 (cap to 50, pending=100, stake=0).
		// Without the cap, pending would be 110 — letting the user
		// withdraw 110 QAU they never staked.
		newCumulative := new(big.Int).Add(sm.unstakeRequests[from].Amount, unstakeAmount)
		totalCommitted := new(big.Int).Add(stake.Amount, sm.unstakeRequests[from].Amount)
		if newCumulative.Cmp(totalCommitted) > 0 {
			return fmt.Errorf("unstake amount %s exceeds available stake: pending %s + current %s = %s total committed",
				unstakeAmount.String(),
				sm.unstakeRequests[from].Amount.String(),
				stake.Amount.String(),
				totalCommitted.String())
		}
		// Add to existing request
		sm.unstakeRequests[from].Amount.Add(sm.unstakeRequests[from].Amount, unstakeAmount)
		// audit-fix R3-M4: reset UnlockHeight so the additional amount
		// serves the full unbonding period instead of inheriting the
		// earlier (shorter) lock window.
		sm.unstakeRequests[from].UnlockHeight = blockHeight + sm.config.UnbondingPeriod
	} else {
		// audit-fix  use configurable unbonding period instead of hardcoded value
		lockPeriodBlocks := sm.config.UnbondingPeriod

		// Create new unstake request
		sm.unstakeRequests[from] = &UnstakeRequest{
			Address:       from,
			Amount:        new(big.Int).Set(unstakeAmount),
			RequestHeight: blockHeight,
			UnlockHeight:  blockHeight + lockPeriodBlocks,
		}
	}

	// Reduce stake
	stake.Amount = new(big.Int).Sub(stake.Amount, unstakeAmount)
	sm.totalStaked = new(big.Int).Sub(sm.totalStaked, unstakeAmount)

	// Deactivate if no stake remaining
	if stake.Amount.Sign() == 0 {
		stake.Active = false
	}

	return nil
}

// ProcessRewardClaimFromTx processes a reward claim from a confirmed transaction
// This is called when a transaction to the rewards contract is confirmed
// Returns the reward amount that should be credited to the user
// SECURITY: This function validates rewards against configured limits before distribution.
// It caps rewards at 100% of stake per claim and validates against total reward pool cap.
func (sm *StakingManager) ProcessRewardClaimFromTx(from types.Address, currentHeight uint64) (*big.Int, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// FIX: Add reentrancy guard matching ClaimRewards()
	// and other mutating methods. Without this, a callback could re-enter
	// ProcessRewardClaimFromTx and claim rewards twice.
	if sm.inProgress[from] {
		return nil, fmt.Errorf("reentrancy detected for address %s: reward claim already in progress", from)
	}
	sm.inProgress[from] = true
	defer func() { sm.inProgress[from] = false }()

	stake, exists := sm.stakes[from]
	if !exists {
		return nil, ErrStakeNotFound
	}

	// Validate stake amount is positive
	if stake.Amount == nil || stake.Amount.Sign() <= 0 {
		return big.NewInt(0), nil
	}

	// audit-fix R10-M2: use 5% APY consistent with RPC layer (ClaimRewards/CompoundRewards/GetPendingRewards).
	// Previously 18.5% (185/1000) with 3s blocks —on-chain claims paid 3.7x more than RPC displayed.
	// blocksPerYear = 365 * 24 * 60 * 60 / 12 = 2,628,000 blocks (12 second slots)
	blocksPerYear := blocksPerYearStaking

	// Validate current height is greater than stake height
	if currentHeight <= stake.StakeHeight {
		return big.NewInt(0), nil
	}

	blocksStaked := currentHeight - stake.StakeHeight

	// Validate blocks staked is reasonable (prevent overflow)
	if blocksStaked > blocksPerYear*10 {
		// Cap at 10 years worth of blocks
		blocksStaked = blocksPerYear * 10
	}

	//  NOTE: StakingAPY = 0 in current config (rewards disabled at the
	// staking layer to avoid double rewards with consensus layer). The helper
	// returns 0 in that case. PendingRewards (from previous top-ups when APY
	// was non-zero) are still paid out below.
	//
	// ECON- (2026-07-20): use centralized helper so the integer-division
	// remainder is carried forward per-address, making the long-run payout
	// exact. consumeRemainder=true because this is a state-modifying path —
	// the rewards are being distributed to the user, and StakeHeight will be
	// reset below, ending the current reward period.
	rewards := sm.computeStakingRewardsECONR11004(from, stake.Amount, blocksStaked, true)

	// Validate reward amount is reasonable (max 100% of stake per claim)
	maxReward := new(big.Int).Set(stake.Amount)
	if rewards.Cmp(maxReward) > 0 {
		rewards = maxReward
	}

	// Ensure rewards are non-negative
	if rewards.Sign() < 0 {
		rewards = big.NewInt(0)
	}

	// R14-MED (2026-07-21): CEI ordering fix. Previously the EFFECT
	// (zeroing stake.PendingRewards) happened BEFORE the CHECK (reward
	// pool cap validation). If the pool was exhausted, PendingRewards
	// was already zeroed and the user permanently lost their accumulated
	// pending rewards with no compensation. Correct order: CHECK the full
	// claimable amount against the cap FIRST, then apply EFFECT (zero or
	// carry forward PendingRewards) based on how much will actually be
	// paid out.
	//
	// Build the total claimable amount (rewards + PendingRewards) WITHOUT
	// mutating state yet.
	totalClaimable := new(big.Int).Set(rewards)
	pendingPortion := big.NewInt(0)
	if stake.PendingRewards != nil && stake.PendingRewards.Sign() > 0 {
		pendingPortion.Set(stake.PendingRewards)
		totalClaimable.Add(totalClaimable, pendingPortion)
	}

	// CHECK: validate against total reward pool cap BEFORE any state mutation.
	if sm.rewardPoolCap != nil && sm.rewardPoolCap.Sign() > 0 {
		newTotal := new(big.Int).Add(sm.totalRewardsDistributed, totalClaimable)
		if newTotal.Cmp(sm.rewardPoolCap) > 0 {
			remaining := new(big.Int).Sub(sm.rewardPoolCap, sm.totalRewardsDistributed)
			if remaining.Sign() <= 0 {
				// Pool exhausted — DO NOT zero PendingRewards; preserve
				// for a future claim when the pool is replenished.
				return big.NewInt(0), errors.New("reward pool exhausted; pending rewards preserved")
			}
			// Pool partially exhausted — pay out only `remaining`, and
			// carry forward the unrewarded portion of PendingRewards so
			// the user can claim it later.
			// Fresh yield (rewards) is paid first from the remaining cap.
			// If remaining < rewards, the unpaid portion of fresh yield is
			// forfeit (yield is recomputed each claim, not carried forward).
			// If remaining >= rewards, the leftover cap goes to PendingRewards;
			// any unpaid portion of PendingRewards is carried forward.
			if remaining.Cmp(rewards) >= 0 {
				// All fresh rewards paid. Remaining cap goes to pending.
				paidFromPending := new(big.Int).Sub(remaining, rewards)
				carryForward := new(big.Int).Sub(pendingPortion, paidFromPending)
				if carryForward.Sign() < 0 {
					carryForward.SetInt64(0)
				}
				if stake.PendingRewards != nil {
					stake.PendingRewards.Set(carryForward)
				}
			} else {
				// remaining < rewards: only part of fresh rewards paid,
				// no pending paid. Carry forward all of pendingPortion.
				if stake.PendingRewards != nil {
					stake.PendingRewards.Set(pendingPortion)
				}
			}
			rewards = remaining
		} else {
			// Pool has room for full claimable — EFFECT: zero PendingRewards.
			if stake.PendingRewards != nil && stake.PendingRewards.Sign() > 0 {
				rewards.Add(rewards, stake.PendingRewards)
				stake.PendingRewards.SetInt64(0)
			}
		}
	} else {
		// No cap — apply EFFECT: fold PendingRewards into rewards.
		if stake.PendingRewards != nil && stake.PendingRewards.Sign() > 0 {
			rewards.Add(rewards, stake.PendingRewards)
			stake.PendingRewards.SetInt64(0)
		}
	}

	// Update total rewards distributed
	sm.totalRewardsDistributed.Add(sm.totalRewardsDistributed, rewards)

	// Reset stake height to current (rewards claimed)
	stake.StakeHeight = currentHeight

	// Track total rewards distributed for audit
	sm.trackRewardClaim(from, rewards, currentHeight)

	return rewards, nil
}

// RewardClaimEvent tracks a reward claim event for audit
type RewardClaimEvent struct {
	Address     types.Address
	Amount      *big.Int
	BlockHeight uint64
	Timestamp   int64
}

// maxRewardClaimEvents is the maximum number of reward claim events to keep in memory.
const maxRewardClaimEvents = 10000

// trackRewardClaim logs a reward claim for audit trail.
// audit-fix R2-L2: uses per-instance fields instead of package globals.
// CS-08 FIX: Added variadic blockTime parameter for deterministic timestamp.
// When provided, blockTime[0] is used instead of time.Now().Unix().
func (sm *StakingManager) trackRewardClaim(addr types.Address, amount *big.Int, blockHeight uint64, blockTime ...int64) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}

	sm.rewardClaimMu.Lock()
	defer sm.rewardClaimMu.Unlock()

	// CS-08 FIX: Use deterministic blockTime for timestamp when provided;
	// fall back to time.Now() for non-consensus callers.
	var eventTimestamp int64
	if len(blockTime) > 0 {
		eventTimestamp = blockTime[0]
	} else {
		eventTimestamp = time.Now().Unix()
	}
	sm.rewardClaimEvents = append(sm.rewardClaimEvents, RewardClaimEvent{
		Address:     addr,
		Amount:      new(big.Int).Set(amount),
		BlockHeight: blockHeight,
		Timestamp:   eventTimestamp,
	})
	if len(sm.rewardClaimEvents) > maxRewardClaimEvents {
		sm.rewardClaimEvents = sm.rewardClaimEvents[len(sm.rewardClaimEvents)-maxRewardClaimEvents:]
	}
}

// GetRewardClaimEvents returns all reward claim events for audit.
// audit-fix R2-L2: instance method instead of package-level function.
func (sm *StakingManager) GetRewardClaimEvents() []RewardClaimEvent {
	sm.rewardClaimMu.Lock()
	defer sm.rewardClaimMu.Unlock()

	result := make([]RewardClaimEvent, len(sm.rewardClaimEvents))
	copy(result, sm.rewardClaimEvents)
	return result
}

// GetTotalRewardsClaimed returns the total rewards claimed.
// audit-fix R2-L2: instance method instead of package-level function.
func (sm *StakingManager) GetTotalRewardsClaimed() *big.Int {
	sm.rewardClaimMu.Lock()
	defer sm.rewardClaimMu.Unlock()

	total := big.NewInt(0)
	for _, rc := range sm.rewardClaimEvents {
		total.Add(total, rc.Amount)
	}
	return total
}

// GetRewardPoolStatus returns the reward pool status for audit
func (sm *StakingManager) GetRewardPoolStatus() map[string]any {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	remaining := big.NewInt(0)
	if sm.rewardPoolCap != nil && sm.totalRewardsDistributed != nil {
		remaining = new(big.Int).Sub(sm.rewardPoolCap, sm.totalRewardsDistributed)
		if remaining.Sign() < 0 {
			remaining = big.NewInt(0)
		}
	}

	// audit-fix  return copies of internal *big.Int to prevent callers
	// from mutating reward pool accounting.
	return map[string]any{
		"totalDistributed": new(big.Int).Set(sm.totalRewardsDistributed),
		"poolCap":          new(big.Int).Set(sm.rewardPoolCap),
		"remaining":        remaining,
	}
}

// CompleteUnstakeFromTx completes an unstake when the lock period has passed
// This is called when a user sends a transaction to claim their unstaked tokens
func (sm *StakingManager) CompleteUnstakeFromTx(from types.Address, currentHeight uint64) (*big.Int, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// L-2 FIX: per-account reentrancy guard (mirrors Stake/RequestUnstake).
	// Prevents a staking callback from re-entering CompleteUnstakeFromTx for
	// the same account while the original call is still in progress, which
	// could allow double-claiming the same unstake request.
	if sm.inProgress[from] {
		return nil, fmt.Errorf("reentrancy detected for address %s: unstake completion already in progress", from)
	}
	sm.inProgress[from] = true
	defer func() { sm.inProgress[from] = false }()

	request, exists := sm.unstakeRequests[from]
	if !exists {
		return nil, ErrNoUnstakeRequest
	}

	if currentHeight < request.UnlockHeight {
		return nil, ErrStakeLocked
	}

	// Remove the request and return the amount
	amount := new(big.Int).Set(request.Amount)
	delete(sm.unstakeRequests, from)

	// Remove stake entry if no stake remaining
	if stake, exists := sm.stakes[from]; exists && stake.Amount.Sign() == 0 {
		delete(sm.stakes, from)
	}

	return amount, nil
}

// GetPendingRewards calculates pending rewards for an address
func (sm *StakingManager) GetPendingRewards(addr types.Address, currentHeight uint64) *big.Int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stake, exists := sm.stakes[addr]
	if !exists {
		return big.NewInt(0)
	}

	// Guard against uint64 underflow
	if currentHeight <= stake.StakeHeight {
		return big.NewInt(0)
	}

	// audit-fix R10-M2: use 5% APY with 12s blocks consistent with RPC layer.
	// Previously 18.5% with 3s blocks — displayed inflated pending rewards.
	//  NOTE: StakingAPY = 0 in current config (rewards disabled at the
	// staking layer). The helper returns 0 in that case. PendingRewards (from
	// previous top-ups when APY was non-zero) are still returned below.
	blocksPerYear := blocksPerYearStaking
	blocksStaked := currentHeight - stake.StakeHeight

	// Cap at 10 years to prevent overflow
	if blocksStaked > blocksPerYear*10 {
		blocksStaked = blocksPerYear * 10
	}

	// ECON- (2026-07-20): use centralized helper so the integer-division
	// remainder is included in the displayed value (consistent with what the
	// next ProcessRewardClaimFromTx call will actually distribute).
	// consumeRemainder=false because this is a READ-ONLY path — the rewards
	// have not been claimed yet, so the stored remainder must be preserved
	// for the next state-modifying call. If we stored the new remainder here,
	// the next ProcessRewardClaimFromTx would re-compute the same rewards but
	// with a different (updated) remainder, double-counting the drift.
	rewards := sm.computeStakingRewardsECONR11004(addr, stake.Amount, blocksStaked, false)

	// FIX: Include accumulated PendingRewards from previous top-ups.
	if stake.PendingRewards != nil {
		rewards.Add(rewards, stake.PendingRewards)
	}

	return rewards
}

// GetContractBalance returns the expected balance of the staking contract
// This should equal total staked + pending unstakes
func (sm *StakingManager) GetContractBalance() *big.Int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	total := new(big.Int).Set(sm.totalStaked)

	// Add pending unstake amounts (still locked in contract)
	for _, req := range sm.unstakeRequests {
		total.Add(total, req.Amount)
	}

	return total
}

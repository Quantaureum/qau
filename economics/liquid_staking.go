// Quantaureum Node source, version 1.0.0.
package economics

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/types"
)

var (
	ErrPoolFull                = errors.New("staking pool is full")
	ErrPoolNotFound            = errors.New("staking pool not found")
	ErrInvalidPoolOperator     = errors.New("invalid pool operator")
	ErrLiquidTokenInsufficient = errors.New("insufficient liquid staking tokens")
)

type StakingPool struct {
	ID                string
	Operator          types.Address
	Name              string
	TotalStaked       *big.Int
	TotalLiquidSupply *big.Int
	CommissionRate    uint32
	Delegators        map[types.Address]*big.Int
	RewardPool        *big.Int
	// L6-027: Tracks cumulative operator commission accrued from rewards.
	// In production this should be either burned or claimable by the operator.
	TotalCommission  *big.Int
	CreatedAt        int64
	Active           bool
	PerformanceScore uint64
}

type LiquidStakingToken struct {
	PoolID   string
	Owner    types.Address
	Amount   *big.Int
	MintedAt int64
}

type LiquidStakingManager struct {
	mu                sync.RWMutex
	config            *StakingConfig
	stakingManager    *StakingManager
	pools             map[string]*StakingPool
	liquidTokens      map[types.Address]map[string]*LiquidStakingToken
	exchangeRate      map[string]*big.Int
	totalLiquidStaked *big.Int

	// ECON-R13-CRIT-004 (2026-07-21): per-user token balance sheet for the
	// liquid staking subsystem. StakeLiquid must debit QAU from the delegator,
	// UnstakeLiquid must credit QAU to the delegator, and ClaimCommission
	// must credit QAU to the operator. Without this map there is no way to
	// move real funds — the previous implementation only mutated pool
	// accounting (TotalStaked/Delegators/TotalCommission) without ever
	// transferring tokens, allowing zero-cost staking and infinite withdrawals.
	// Asset key is the token symbol (e.g., "QAU"); matches the convention
	// used by LiquidityPoolManager and LendingManager.
	userTokenBalances map[types.Address]map[string]*big.Int

	// ECON- (2026-07-20): per-user reentrancy protection.
	// Tracks addresses currently executing a mutating liquid-staking op
	// (Stake/Unstake/ClaimCommission/...). Matches the activeUsers pattern
	// in LiquidityPoolManager and YieldFarmingManager. Prevents a malicious
	// contract from re-entering mid-execution to double-mint liquid tokens,
	// double-claim rewards, or drain pool reserves.
	activeUsers map[types.Address]bool

	// ECON- (2026-07-20): pool-level reentrancy protection.
	// Used for pool-scoped admin operations (DistributeRewards/CompoundRewards)
	// that do not take a user parameter. Prevents a callback from re-entering
	// the same pool's admin op while it is still in progress.
	activePools map[string]bool

	// R14-MED (2026-07-21): Optional treasury verifier hook. When set,
	// CompoundRewards calls VerifyPoolDeposit(poolID, pool.RewardPool)
	// BEFORE folding RewardPool into TotalStaked. This closes the
	// defense-in-depth gap where DistributeRewards could credit
	// RewardPool without an actual on-chain treasury debit, allowing
	// CompoundRewards to silently inflate TotalStaked (and the exchange
	// rate) with nonexistent funds. When nil (default, backward-compat),
	// verification is skipped — operators SHOULD inject a verifier at
	// node startup.
	treasuryVerifier TreasuryVerifier

	// R37-INFO FIX (2026-07-31): allowUnverifiedCompounding controls whether
	// CompoundRewards may fold RewardPool into TotalStaked WITHOUT an
	// injected TreasuryVerifier. Default false = fail-closed: compounding
	// is refused until either a verifier is injected (SetTreasuryVerifier)
	// or the operator explicitly opts out (AllowUnverifiedCompounding).
	// Previously the nil default silently skipped on-chain treasury
	// verification (R37 INFO: liquid_staking.go:666).
	allowUnverifiedCompounding bool

	// R43-ECON-POOLID-01 (2026-08-03): production hardening gate.
	// When true (production / long-running testnet), CreatePool REQUIRES
	// the caller to supply a blockHeight variadic argument > 0, refusing
	// the deterministic pool ID computation fallback to time.Now().
	// The fallback using time.Now() is non-deterministic across nodes,
	// so a proposed pool created at block N on validator A and block N+1
	// on validator B would get different IDs, breaking cross-node
	// consensus on pool identity. On devnet / unit tests, false (default)
	// keeps the legacy fallback for backward compatibility. Mirrors the
	// governance R42-GOVDEP-01 productionMode pattern.
	// R43-ECON-POOLID-01 atomic: stored as sync/atomic.Bool so we can
	// read it from inside CreatePool's already-held lsm.mu.Lock() WITHOUT
	// needing a second RLock (which would self-deadlock — Lua null),
	// while SetProductionMode is still concurrent-safe to call from
	// another goroutine during startup.
	productionMode atomic.Bool
}

// TreasuryVerifier verifies that a pool's reward distribution was backed
// by an actual on-chain treasury deposit. R14-MED (2026-07-21): this is
// a defense-in-depth hook for CompoundRewards — DistributeRewards debits
// the operator's internal balance sheet, but the internal balance sheet
// is a separate accounting layer from the actual protocol treasury. If
// they ever diverge (integration bug, missing upstream debit), without
// a verifier CompoundRewards would silently fold nonexistent funds into
// TotalStaked, permanently inflating the exchange rate.
//
// Implementations should query the actual on-chain treasury balance for
// the pool and confirm `expectedAmount` was credited. Returns nil if
// verified, non-nil error otherwise.
type TreasuryVerifier interface {
	VerifyPoolDeposit(poolID string, expectedAmount *big.Int) error
}

// SetTreasuryVerifier injects a treasury verifier hook. R14-MED: pass nil
// to disable verification (backward-compat). Pass a non-nil verifier to
// enforce on-chain treasury deposit checks before CompoundRewards folds
// rewards into TotalStaked.
func (lsm *LiquidStakingManager) SetTreasuryVerifier(v TreasuryVerifier) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()
	lsm.treasuryVerifier = v
}

// AllowUnverifiedCompounding explicitly opts out of treasury-deposit
// verification for CompoundRewards. R37-INFO (2026-07-31): the previous
// default (nil verifier) silently skipped verification; compounding is now
// fail-closed unless the operator makes a conscious, visible decision to
// skip it. Production nodes SHOULD inject a real TreasuryVerifier instead.
func (lsm *LiquidStakingManager) AllowUnverifiedCompounding() {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()
	lsm.allowUnverifiedCompounding = true
}

// StakeAsset is the native asset symbol used by the liquid staking subsystem.
// Quantaureum's native gas/token is QAU; stake amounts are denominated in QAU.
const StakeAsset = "QAU"

func NewLiquidStakingManager(config *StakingConfig, stakingManager *StakingManager) *LiquidStakingManager {
	return &LiquidStakingManager{
		config:            config,
		stakingManager:    stakingManager,
		pools:             make(map[string]*StakingPool),
		liquidTokens:      make(map[types.Address]map[string]*LiquidStakingToken),
		exchangeRate:      make(map[string]*big.Int),
		totalLiquidStaked: new(big.Int),
		userTokenBalances: make(map[types.Address]map[string]*big.Int),
		activeUsers:       make(map[types.Address]bool),
		activePools:       make(map[string]bool),
	}
}

// SetProductionMode enables R43-ECON-POOLID-01 production hardening.
// When true, CreatePool no longer accepts the time.Now() fallback for
// pool ID derivation — the caller MUST supply a valid blockHeight variadic.
// Idempotent. Intended to be called ONCE during node startup on mainnet
// (chainID 1668/1670) and long-running testnets (chainID 1669); false on
// devnet (chainID 1333/1334) preserves the legacy non-deterministic
// fallback for backward compatibility with existing devnet tests.
// Mirrors the governance R42-GOVDEP-01 productionMode gating pattern.
//
// Uses atomic.Bool so CreatePool (which already holds lsm.mu.Lock()) can
// read this field WITHOUT taking a second lock — eliminating self-deadlock
// risk. Safe to call from any goroutine.
func (lsm *LiquidStakingManager) SetProductionMode(prod bool) {
	lsm.productionMode.Store(prod)
}

// Deposit credits a user's liquid-staking token balance sheet. Required before
// StakeLiquid/ClaimCommission can debit any tokens from the user.
// ECON-R13-CRIT-004 (2026-07-21): mirrors the Deposit pattern used by
// LiquidityPoolManager.Deposit and LendingManager.Deposit.
func (lsm *LiquidStakingManager) Deposit(user types.Address, asset string, amount *big.Int) (*big.Int, error) {
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("amount must be positive")
	}
	lsm.mu.Lock()
	defer lsm.mu.Unlock()
	if lsm.userTokenBalances[user] == nil {
		lsm.userTokenBalances[user] = make(map[string]*big.Int)
	}
	if lsm.userTokenBalances[user][asset] == nil {
		lsm.userTokenBalances[user][asset] = new(big.Int)
	}
	lsm.userTokenBalances[user][asset].Add(lsm.userTokenBalances[user][asset], amount)
	return new(big.Int).Set(lsm.userTokenBalances[user][asset]), nil
}

// GetUserTokenBalance returns the user's liquid-staking balance for an asset.
// ECON-R13-CRIT-004 (2026-07-21).
func (lsm *LiquidStakingManager) GetUserTokenBalance(user types.Address, asset string) *big.Int {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()
	if m, ok := lsm.userTokenBalances[user]; ok {
		if bal, ok := m[asset]; ok && bal != nil {
			return new(big.Int).Set(bal)
		}
	}
	return new(big.Int)
}

// getUserBalanceLocked returns the user's balance without taking the lock.
// Caller MUST hold lsm.mu.
// ECON-R13-CRIT-004 (2026-07-21).
func (lsm *LiquidStakingManager) getUserBalanceLocked(user types.Address, asset string) *big.Int {
	if m, ok := lsm.userTokenBalances[user]; ok {
		if bal, ok := m[asset]; ok && bal != nil {
			return new(big.Int).Set(bal)
		}
	}
	return new(big.Int)
}

// subUserBalanceLocked debits amount from the user's balance sheet.
// Caller MUST hold lsm.mu and MUST verify balance >= amount beforehand.
// ECON-R13-CRIT-004 (2026-07-21).
func (lsm *LiquidStakingManager) subUserBalanceLocked(user types.Address, asset string, amount *big.Int) {
	if lsm.userTokenBalances[user] == nil {
		lsm.userTokenBalances[user] = make(map[string]*big.Int)
	}
	if lsm.userTokenBalances[user][asset] == nil {
		lsm.userTokenBalances[user][asset] = new(big.Int)
	}
	lsm.userTokenBalances[user][asset].Sub(lsm.userTokenBalances[user][asset], amount)
}

// addUserBalanceLocked credits amount to the user's balance sheet.
// Caller MUST hold lsm.mu.
// ECON-R13-CRIT-004 (2026-07-21).
func (lsm *LiquidStakingManager) addUserBalanceLocked(user types.Address, asset string, amount *big.Int) {
	if lsm.userTokenBalances[user] == nil {
		lsm.userTokenBalances[user] = make(map[string]*big.Int)
	}
	if lsm.userTokenBalances[user][asset] == nil {
		lsm.userTokenBalances[user][asset] = new(big.Int)
	}
	lsm.userTokenBalances[user][asset].Add(lsm.userTokenBalances[user][asset], amount)
}

// R49-CS-01 FIX: Added blockHeight parameter for deterministic pool ID generation.
// When blockHeight > 0, poolID uses blockHeight instead of time.Now().UnixNano().
func (lsm *LiquidStakingManager) CreatePool(operator types.Address, name string, commissionRate uint32, blockHeight ...uint64) (*StakingPool, error) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	// ECON- per-user reentrancy protection. Prevents the operator's
	// callback (e.g., a malicious pool-creation hook) from re-entering
	// CreatePool to register a duplicate pool with the same parameters.
	if lsm.activeUsers[operator] {
		return nil, errors.New("reentrant call: operator already has an in-progress liquid staking operation")
	}
	lsm.activeUsers[operator] = true
	defer delete(lsm.activeUsers, operator)

	if commissionRate > 10000 {
		return nil, ErrInvalidPoolOperator
	}

	// ECON-R15-M (2026-07-22): Enforce config MinCommission/MaxCommission
	// bounds, not just the loose 10000 bps cap. Without this, an operator
	// could set commissionRate=0 (below MinCommission=100) to undercut
	// the protocol's minimum, or commissionRate=10000 (above MaxCommission=1500)
	// to charge exorbitant fees. The loose cap only rejects > 10000 bps (100%).
	if lsm.config != nil {
		if commissionRate < lsm.config.MinCommission {
			return nil, fmt.Errorf("commissionRate %d below config min %d",
				commissionRate, lsm.config.MinCommission)
		}
		if commissionRate > lsm.config.MaxCommission {
			return nil, fmt.Errorf("commissionRate %d exceeds config max %d",
				commissionRate, lsm.config.MaxCommission)
		}
	}

	// R43-ECON-POOLID-01 (2026-08-03): production hardening. When
	// productionMode is enabled, the caller MUST supply a blockHeight
	// variadic argument > 0 — otherwise the pool ID derivation would fall
	// back to time.Now() (line ~281), which is NON-DETERMINISTIC across
	// nodes and breaks cross-node consensus on pool identity (validator A
	// hearing about a pool creation at block N may compute a different ID
	// than validator B hearing at block N+1). On devnet / unit tests
	// (productionMode=false), the fallback remains for backward
	// compatibility. Mirrors governance R42-GOVDEP-01 pattern.
	// R43 atomic-load: productionMode is atomic.Bool (see struct field),
	// so we read IT lock-free here without re-acquiring lsm.mu (CreatePool
	// already holds it — a second RLock would self-deadlock).
	if lsm.productionMode.Load() {
		if len(blockHeight) == 0 || blockHeight[0] == 0 {
			return nil, errors.New("R43-ECON-POOLID-01: productionMode requires non-zero blockHeight variadic for deterministic pool ID derivation (consensus path)")
		}
	}

	// R49-CS-01 FIX: Use deterministic block height for pool ID to ensure
	// all nodes produce the same pool ID. Fall back to time.Now() for backward
	// compatibility with tests/non-consensus callers.
	var poolID string
	var createdAt int64
	if len(blockHeight) > 0 && blockHeight[0] > 0 {
		poolID = fmt.Sprintf("pool-%s-%d", operator.ToHexAddress()[:8], blockHeight[0])
		createdAt = int64(blockHeight[0])
	} else {
		poolID = fmt.Sprintf("pool-%s-%d", operator.ToHexAddress()[:8], time.Now().UnixNano())
		createdAt = time.Now().Unix()
	}

	// R37-FIX P2-ECON-04 (2026-07-30): Reject duplicate pool IDs instead of
	// silently overwriting. The deterministic ID formula
	// pool-{operator[:8]}-{blockHeight} means the same operator creating two
	// pools in the same block would collide; overwriting orphanises the
	// first pool's stakes and exchange rate.
	if _, exists := lsm.pools[poolID]; exists {
		return nil, fmt.Errorf("pool ID %s already exists", poolID)
	}

	pool := &StakingPool{
		ID:                poolID,
		Operator:          operator,
		Name:              name,
		TotalStaked:       new(big.Int),
		TotalLiquidSupply: new(big.Int),
		CommissionRate:    commissionRate,
		Delegators:        make(map[types.Address]*big.Int),
		RewardPool:        new(big.Int),
		TotalCommission:   new(big.Int),
		CreatedAt:         createdAt,
		Active:            true,
	}

	lsm.pools[poolID] = pool
	lsm.exchangeRate[poolID] = big.NewInt(1e18)

	return pool, nil
}

// CS-07 FIX: Added variadic blockTime parameter for deterministic MintedAt
// timestamp. When provided, blockTime[0] is used instead of time.Now().Unix().
func (lsm *LiquidStakingManager) StakeLiquid(poolID string, delegator types.Address, amount *big.Int, blockTime ...int64) (*LiquidStakingToken, error) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	// ECON- per-user reentrancy protection. Prevents a malicious
	// delegator contract from re-entering StakeLiquid mid-execution to
	// double-mint liquid tokens or manipulate the exchange rate.
	if lsm.activeUsers[delegator] {
		return nil, errors.New("reentrant call: delegator already has an in-progress liquid staking operation")
	}
	lsm.activeUsers[delegator] = true
	defer delete(lsm.activeUsers, delegator)

	// L6-026 SECURITY FIX: Check for nil amount before calling Sign(),
	// which would panic on a nil *big.Int.
	if amount == nil {
		return nil, errors.New("amount must not be nil")
	}
	if amount.Sign() <= 0 {
		return nil, errors.New("amount must be positive")
	}

	pool, exists := lsm.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	if !pool.Active {
		return nil, ErrPoolNotFound
	}

	rate := lsm.exchangeRate[poolID]
	if rate == nil || rate.Sign() <= 0 {
		// R39-P0-04 (2026-08-02) FIX: An uninitialized/zero exchange rate
		// would either panic on Div(nil) or divide-by-zero. Fail closed
		// before touching any pool/user state so a misconfigured pool cannot
		// lock user funds.
		return nil, fmt.Errorf("liquid staking: exchange rate not initialized for pool %s", poolID)
	}
	liquidAmount := new(big.Int).Mul(amount, big.NewInt(1e18))
	liquidAmount.Div(liquidAmount, rate)

	// R39-P0-04 (2026-08-02) FIX: Guard against the integer-division-to-zero
	// permanent lock. When exchangeRate appreciates above amount*1e18,
	// liquidAmount rounds to zero: the user is debited real QAU yet receives
	// no liquid tokens, and can never recover via UnstakeLiquid (which
	// requires liquidAmount > 0). Reject such stake attempts atomically
	// BEFORE any pool/user balance mutation — no state is changed on failure.
	if liquidAmount.Sign() <= 0 {
		return nil, fmt.Errorf("liquid staking: liquid amount rounds to zero (rate=%s, amount=%s); stake rejected to prevent permanent fund lock",
			rate.String(), amount.String())
	}

	// ECON-R13-CRIT-004 (2026-07-21) FIX: verify the delegator has enough
	// QAU balance BEFORE mutating pool state. Previously StakeLiquid only
	// increased pool.TotalStaked/Delegators/liquidTokens without debiting
	// the user — equivalent to zero-cost staking, which combined with
	// zero-cost UnstakeLiquid let attackers drain pool reserves.
	userBal := lsm.getUserBalanceLocked(delegator, StakeAsset)
	if userBal.Cmp(amount) < 0 {
		return nil, fmt.Errorf("insufficient user balance: have %s %s, need %s",
			userBal.String(), StakeAsset, amount.String())
	}

	pool.TotalStaked.Add(pool.TotalStaked, amount)
	pool.TotalLiquidSupply.Add(pool.TotalLiquidSupply, liquidAmount)

	if pool.Delegators[delegator] == nil {
		pool.Delegators[delegator] = new(big.Int)
	}
	pool.Delegators[delegator].Add(pool.Delegators[delegator], amount)

	// ECON-R13-CRIT-004 FIX: actually debit the staked QAU from the
	// delegator's balance sheet.
	lsm.subUserBalanceLocked(delegator, StakeAsset, amount)

	// CS-07 FIX: Use deterministic blockTime for MintedAt when provided;
	// fall back to time.Now() for non-consensus callers.
	var mintedAt int64
	if len(blockTime) > 0 {
		mintedAt = blockTime[0]
	} else {
		mintedAt = time.Now().Unix()
	}
	token := &LiquidStakingToken{
		PoolID:   poolID,
		Owner:    delegator,
		Amount:   liquidAmount,
		MintedAt: mintedAt,
	}

	if lsm.liquidTokens[delegator] == nil {
		lsm.liquidTokens[delegator] = make(map[string]*LiquidStakingToken)
	}
	if existing, ok := lsm.liquidTokens[delegator][poolID]; ok {
		existing.Amount.Add(existing.Amount, liquidAmount)
		token = existing
	} else {
		lsm.liquidTokens[delegator][poolID] = token
	}

	lsm.totalLiquidStaked.Add(lsm.totalLiquidStaked, amount)

	return token, nil
}

func (lsm *LiquidStakingManager) UnstakeLiquid(poolID string, delegator types.Address, liquidAmount *big.Int) (*big.Int, error) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	// ECON- per-user reentrancy protection. Prevents a malicious
	// delegator contract from re-entering UnstakeLiquid mid-execution to
	// double-withdraw the same liquid tokens or drain pool reserves.
	if lsm.activeUsers[delegator] {
		return nil, errors.New("reentrant call: delegator already has an in-progress liquid staking operation")
	}
	lsm.activeUsers[delegator] = true
	defer delete(lsm.activeUsers, delegator)

	// FIX: nil-check unstake parameters before use.
	if liquidAmount == nil {
		return nil, errors.New("liquid amount must not be nil")
	}
	if liquidAmount.Sign() <= 0 {
		return nil, errors.New("liquid amount must be positive")
	}

	pool, exists := lsm.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	token, exists := lsm.liquidTokens[delegator][poolID]
	if !exists {
		return nil, ErrLiquidTokenInsufficient
	}

	if token.Amount.Cmp(liquidAmount) < 0 {
		return nil, ErrLiquidTokenInsufficient
	}

	rate := lsm.exchangeRate[poolID]
	// R40-P1-02 (2026-08-03) FIX: zero/missing exchange-rate guard. The
	// exchange-rate map is populated when a pool first accrues rewards and
	// defaults to nil (== 0 effective) for a pool that has never had a rate
	// set. Without this guard:
	//   - `new(big.Int).Mul(liquidAmount, nil)` panics (nil deref inside
	//     big.Int.Mul), crashing the node on a single RPC call against any
	//     freshly-created pool that has not yet accrued rewards.
	//   - Even if rate is non-nil but == 0 (corrupted pool state), the
	//     subsequent `underlyingAmount.Div(..., 1e18)` produces 0 — the
	//     delegator surrenders liquid tokens but receives 0 underlying QAU,
	//     allowing an attacker to drain the pool's liquid supply at zero
	//     cost to themselves.
	// Reject both cases explicitly BEFORE any pool accounting is mutated.
	// R41-L3ECON-08 (2026-08-03): tighten to `<= 0` so a corrupted NEGATIVE
	// exchange rate is also rejected. StakeLiquid (line 336) already uses
	// the stricter `rate.Sign() <= 0` form; without matching it here, an
	// UnstakeLiquid call against a pool whose rate was corrupted to a
	// negative value would silently compute `liquidAmount * negativeRate`
	// — a big.Int product that goes through with a nonsensical (negative)
	// result, breaking the implicit "exchange rate is always positive"
	// invariant that downstream accounting assumes. The two paths now use
	// the same predicate, eliminating the audit-flagged inconsistency.
	if rate == nil || rate.Sign() <= 0 {
		return nil, errors.New("cannot unstake liquid: pool exchange rate is zero, negative, or unset")
	}
	underlyingAmount := new(big.Int).Mul(liquidAmount, rate)
	underlyingAmount.Div(underlyingAmount, big.NewInt(1e18))

	// SECURITY (audit 2026-06-14, H7): Guard EVERY field that is about to be
	// decremented, not just token.Amount. The original code only checked the
	// liquid token balance, then subtracted `underlyingAmount` (=
	// liquidAmount * rate / 1e18, which is LARGER than liquidAmount once the
	// exchange rate appreciates above 1.0) from pool.TotalStaked,
	// pool.Delegators[delegator], and totalLiquidStaked. Go's big.Int.Sub does
	// not panic on underflow — it silently produces a large negative value,
	// corrupting the pool's accounting (negative delegator balances, negative
	// total staked) and causing reward mis-distribution and inconsistent state.
	// Each field is now validated; if any would go negative we reject.
	if token.Amount.Cmp(liquidAmount) < 0 ||
		pool.TotalLiquidSupply.Cmp(liquidAmount) < 0 ||
		pool.TotalStaked.Cmp(underlyingAmount) < 0 ||
		pool.Delegators[delegator].Cmp(underlyingAmount) < 0 ||
		lsm.totalLiquidStaked.Cmp(underlyingAmount) < 0 {
		return nil, ErrLiquidTokenInsufficient
	}

	token.Amount.Sub(token.Amount, liquidAmount)
	pool.TotalLiquidSupply.Sub(pool.TotalLiquidSupply, liquidAmount)
	pool.TotalStaked.Sub(pool.TotalStaked, underlyingAmount)
	pool.Delegators[delegator].Sub(pool.Delegators[delegator], underlyingAmount)

	lsm.totalLiquidStaked.Sub(lsm.totalLiquidStaked, underlyingAmount)

	// ECON-R13-CRIT-004 (2026-07-21) FIX: actually credit the unstaked QAU
	// to the delegator's balance sheet. Previously UnstakeLiquid only
	// reduced pool accounting (TotalStaked/Delegators/totalLiquidStaked)
	// without transferring any tokens to the user — the unstaked amount
	// simply vanished, allowing the pool to be silently drained.
	lsm.addUserBalanceLocked(delegator, StakeAsset, underlyingAmount)

	return underlyingAmount, nil
}

// DistributeRewards distributes rewards to a pool's delegators.
//
// ECON-R14-CRIT-004 (2026-07-21) FIX: this function previously had NO
// permission check and NO fund source — it just added rewardAmount to
// pool.RewardPool and pool.TotalCommission, effectively minting tokens
// out of thin air. Combined with CompoundRewards (which folds
// pool.RewardPool into TotalStaked), this let any caller inflate the
// exchange rate at will.
//
// Now the caller MUST be the pool's registered operator, and the full
// rewardAmount is debited from the operator's QAU balance sheet before
// any pool accounting is updated. This makes reward distribution a
// zero-sum transfer (operator → delegators via the pool) instead of
// infinite inflation.
func (lsm *LiquidStakingManager) DistributeRewards(poolID string, caller types.Address, rewardAmount *big.Int) error {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	// ECON- pool-level reentrancy protection. DistributeRewards has
	// no user parameter, so we guard by poolID. Prevents a callback (e.g.,
	// from a downstream reward-distribution hook) from re-entering
	// DistributeRewards for the same pool while it is still in progress,
	// which could double-count rewards or corrupt the exchange rate.
	if lsm.activePools[poolID] {
		return errors.New("reentrant call: pool already has an in-progress liquid staking admin operation")
	}
	lsm.activePools[poolID] = true
	defer delete(lsm.activePools, poolID)

	if rewardAmount == nil || rewardAmount.Sign() <= 0 {
		return errors.New("reward amount must be positive")
	}

	pool, exists := lsm.pools[poolID]
	if !exists {
		return ErrPoolNotFound
	}

	// ECON-R14-CRIT-004: permission check — only the pool's operator may
	// distribute rewards. Without this, any caller could mint rewards into
	// the pool and then compound them to inflate the exchange rate.
	if caller != pool.Operator {
		return fmt.Errorf("permission denied: caller %x is not the operator of pool %s",
			caller[:min(8, len(caller))], poolID)
	}

	// ECON-R14-CRIT-004: debit the reward from the operator's balance
	// BEFORE crediting the pool. If the operator has insufficient balance
	// we fail closed — no pool accounting is mutated.
	opBal := lsm.getUserBalanceLocked(caller, StakeAsset)
	if opBal.Cmp(rewardAmount) < 0 {
		return fmt.Errorf("insufficient operator balance for reward: have %s, need %s",
			opBal.String(), rewardAmount.String())
	}
	lsm.subUserBalanceLocked(caller, StakeAsset, rewardAmount)

	commission := new(big.Int).Mul(rewardAmount, big.NewInt(int64(pool.CommissionRate)))
	commission.Div(commission, big.NewInt(10000))

	delegatorReward := new(big.Int).Sub(rewardAmount, commission)
	pool.RewardPool.Add(pool.RewardPool, delegatorReward)

	// L6-027 SECURITY FIX: Track the operator commission to prevent it from
	// being silently lost. Previously the commission was computed but neither
	// credited to the operator nor burned, effectively destroying tokens without
	// accounting. Now the cumulative commission is tracked in TotalCommission.
	// In production, this should be either:
	//   - Burned (deflationary) via an explicit burn transaction, or
	//   - Credited to the operator's claimable balance.
	// Until then, we accumulate it here for auditability.
	pool.TotalCommission.Add(pool.TotalCommission, commission)

	if pool.TotalLiquidSupply.Sign() > 0 {
		newRate := new(big.Int).Mul(pool.TotalStaked, big.NewInt(1e18))
		newRate.Div(newRate, pool.TotalLiquidSupply)
		lsm.exchangeRate[poolID] = newRate
	}

	return nil
}

// deepCopyStakingPool creates a deep copy of a StakingPool.
// R37-P3-38 FIX (2026-07-31): prevents callers from mutating internal state.
func deepCopyStakingPool(pool *StakingPool) *StakingPool {
	if pool == nil {
		return nil
	}
	cp := &StakingPool{
		ID:                pool.ID,
		Operator:          pool.Operator,
		Name:              pool.Name,
		TotalStaked:       new(big.Int).Set(pool.TotalStaked),
		TotalLiquidSupply: new(big.Int).Set(pool.TotalLiquidSupply),
		CommissionRate:    pool.CommissionRate,
		RewardPool:        new(big.Int).Set(pool.RewardPool),
		TotalCommission:   new(big.Int).Set(pool.TotalCommission),
		CreatedAt:         pool.CreatedAt,
		Active:            pool.Active,
		PerformanceScore:  pool.PerformanceScore,
		Delegators:        make(map[types.Address]*big.Int, len(pool.Delegators)),
	}
	for addr, amt := range pool.Delegators {
		cp.Delegators[addr] = new(big.Int).Set(amt)
	}
	return cp
}

func (lsm *LiquidStakingManager) GetPool(poolID string) (*StakingPool, error) {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()

	pool, exists := lsm.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}
	return deepCopyStakingPool(pool), nil
}

func (lsm *LiquidStakingManager) GetExchangeRate(poolID string) (*big.Int, error) {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()

	rate, exists := lsm.exchangeRate[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}
	return new(big.Int).Set(rate), nil
}

func (lsm *LiquidStakingManager) GetDelegatorStake(poolID string, delegator types.Address) *big.Int {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()

	pool, exists := lsm.pools[poolID]
	if !exists {
		return new(big.Int)
	}

	stake := pool.Delegators[delegator]
	if stake == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(stake)
}

func (lsm *LiquidStakingManager) ListActivePools() []*StakingPool {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()

	var active []*StakingPool
	for _, pool := range lsm.pools {
		if pool.Active {
			active = append(active, deepCopyStakingPool(pool))
		}
	}
	return active
}

func (lsm *LiquidStakingManager) GetTotalLiquidStaked() *big.Int {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()
	return new(big.Int).Set(lsm.totalLiquidStaked)
}

// CompoundRewards folds the pool's accumulated RewardPool into TotalStaked,
// raising the liquid-staking exchange rate so future unstakes claim more
// underlying tokens per lsToken. This is an admin/privileged operation.
//
// ECON-R13-M02 (2026-07-21) FIX: Previously CompoundRewards accepted calls
// from any caller — there was no operator-authorization check and no
// verification that the reward funds reflected in pool.RewardPool actually
// arrived from a real protocol deposit (DistributeRewards must have been
// called first with a real rewardAmount). A malicious non-operator caller
// could compound rewards before the operator intended, front-running the
// legitimate compounding cadence; more critically, in conjunction with a
// buggy DistributeRewards that credited RewardPool without debiting the
// protocol treasury, this could be used to inflate TotalStaked at will.
//
// Fix:
//  1. Require the caller to be pool.Operator (matching ClaimCommission's
//     authorization pattern). This prevents unauthorized compounding.
//  2. Cross-check that pool.RewardPool is internally consistent (>= 0).
//     While we cannot verify on-chain treasury deposit at this layer
//     (the economics package has no view into the protocol treasury),
//     we explicitly document that DistributeRewards MUST be called with
//     funds already debited from the treasury before CompoundRewards is
//     invoked. A separate audit of the protocol-treasury integration
//     verifies the upstream debit.
//  3. Idempotency: if pool.RewardPool is already 0 (e.g., CompoundRewards
//     was called twice), return nil without mutating state. This is the
//     existing behavior and we preserve it.
func (lsm *LiquidStakingManager) CompoundRewards(poolID string, operator types.Address) error {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	// ECON- pool-level reentrancy protection. CompoundRewards is
	// an admin operation, so we guard by poolID. Prevents a callback from
	// re-entering CompoundRewards for the same pool while it is still in
	// progress, which could double-apply rewards to TotalStaked or
	// corrupt the exchange rate.
	if lsm.activePools[poolID] {
		return errors.New("reentrant call: pool already has an in-progress liquid staking admin operation")
	}
	lsm.activePools[poolID] = true
	defer delete(lsm.activePools, poolID)

	// ECON-R13-M02: per-user reentrancy protection for the operator. Even
	// though CompoundRewards is a pool-scoped admin operation, the operator
	// may have other concurrent liquid-staking operations in flight (e.g.,
	// ClaimCommission); rejecting reentry on the same operator prevents
	// interlocked callback chains from corrupting state.
	if lsm.activeUsers[operator] {
		return errors.New("reentrant call: operator already has an in-progress liquid staking operation")
	}
	lsm.activeUsers[operator] = true
	defer delete(lsm.activeUsers, operator)

	pool, exists := lsm.pools[poolID]
	if !exists {
		return ErrPoolNotFound
	}

	// ECON-R13-M02: authorize caller as the pool operator. This mirrors
	// ClaimCommission's check (line 564) and ensures only the operator can
	// decide when to fold accrued rewards back into TotalStaked. Without
	// this, any external caller could trigger compounding at a maliciously
	// chosen time (e.g., sandwiched around their own unstake to extract
	// MEV from the exchange-rate update).
	if pool.Operator != operator {
		return ErrInvalidPoolOperator
	}

	if pool.RewardPool.Sign() <= 0 {
		// Idempotent no-op: nothing to compound.
		return nil
	}

	// ECON-R13-M02: defensive consistency check. RewardPool must never be
	// negative; if it is, the internal accounting is corrupt and we refuse
	// to compound to prevent the corruption from propagating to
	// TotalStaked / exchangeRate.
	if pool.RewardPool.Sign() < 0 {
		return errors.New("internal error: pool.RewardPool is negative; refusing to compound corrupt state")
	}

	// R14-MED (2026-07-21): If a treasury verifier is configured, verify
	// that pool.RewardPool was actually backed by an on-chain treasury
	// deposit BEFORE folding it into TotalStaked. Without this check,
	// a divergence between the internal balance sheet and the actual
	// protocol treasury (integration bug, missing upstream debit) would
	// silently inflate TotalStaked and the exchange rate, letting
	// delegators unstake more than was actually deposited. When
	// treasuryVerifier is nil (default), verification is skipped to
	// preserve backward compatibility — operators SHOULD inject a
	// verifier at node startup.
	if lsm.treasuryVerifier != nil {
		if err := lsm.treasuryVerifier.VerifyPoolDeposit(poolID, new(big.Int).Set(pool.RewardPool)); err != nil {
			// DO NOT zero RewardPool — the deposit verification may
			// fail transiently (e.g., RPC lag). Leave the state
			// unchanged so the operator can retry after fixing the
			// upstream issue.
			return fmt.Errorf("treasury deposit verification failed for pool %s: %w", poolID, err)
		}
	} else if !lsm.allowUnverifiedCompounding {
		// R37-INFO FIX (2026-07-31): fail-closed. Refuse to compound when
		// no treasury verifier is configured and the operator has not
		// explicitly opted out via AllowUnverifiedCompounding. The state
		// is left unchanged so the operator can inject a verifier (or
		// consciously opt out) and retry.
		return errors.New("treasury verifier not configured: refusing to compound unverified rewards (inject a TreasuryVerifier via SetTreasuryVerifier or explicitly opt out via AllowUnverifiedCompounding)")
	}

	// Fold the reward pool into TotalStaked. DistributeRewards must have
	// been called beforehand to populate pool.RewardPool with real funds
	// debited from the protocol treasury. When treasuryVerifier is set,
	// the deposit has been verified above; when nil, the operator is
	// responsible for ensuring DistributeRewards was correctly funded
	// (see the function-level docstring for the rationale).
	pool.TotalStaked.Add(pool.TotalStaked, pool.RewardPool)

	if pool.TotalLiquidSupply.Sign() > 0 {
		newRate := new(big.Int).Mul(pool.TotalStaked, big.NewInt(1e18))
		newRate.Div(newRate, pool.TotalLiquidSupply)
		lsm.exchangeRate[poolID] = newRate
	}

	pool.RewardPool.SetInt64(0)

	return nil
}

// GetPendingCommission returns the accumulated operator commission for a pool.
// FIX: Operator commission was tracked in TotalCommission but never
// claimable. This method exposes the pending commission for query.
func (lsm *LiquidStakingManager) GetPendingCommission(poolID string) (*big.Int, error) {
	lsm.mu.RLock()
	defer lsm.mu.RUnlock()

	pool, exists := lsm.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}
	return new(big.Int).Set(pool.TotalCommission), nil
}

// ClaimCommission allows the pool operator to claim accumulated commission.
// FIX: Operator commission was tracked but never claimable. This
// method verifies the caller is the pool operator, returns the accumulated
// commission, and resets it to zero.
func (lsm *LiquidStakingManager) ClaimCommission(poolID string, operator types.Address) (*big.Int, error) {
	lsm.mu.Lock()
	defer lsm.mu.Unlock()

	// ECON- per-user reentrancy protection. Prevents the operator's
	// callback (e.g., a malicious commission-claim hook) from re-entering
	// ClaimCommission to double-claim the accumulated commission.
	if lsm.activeUsers[operator] {
		return nil, errors.New("reentrant call: operator already has an in-progress liquid staking operation")
	}
	lsm.activeUsers[operator] = true
	defer delete(lsm.activeUsers, operator)

	pool, exists := lsm.pools[poolID]
	if !exists {
		return nil, ErrPoolNotFound
	}

	// Only the pool operator can claim commission
	if pool.Operator != operator {
		return nil, ErrInvalidPoolOperator
	}

	commission := new(big.Int).Set(pool.TotalCommission)
	pool.TotalCommission.SetInt64(0)

	// ECON-R13-CRIT-004 (2026-07-21) FIX: actually transfer the claimed
	// commission to the operator's balance sheet. Previously ClaimCommission
	// returned the commission number and zeroed the accumulator but never
	// credited the operator — the operator could never actually spend the
	// commission they had earned.
	if commission.Sign() > 0 {
		lsm.addUserBalanceLocked(operator, StakeAsset, commission)
	}

	return commission, nil
}

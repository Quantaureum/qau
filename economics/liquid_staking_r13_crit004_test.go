// Quantaureum Node source, version 1.0.0.
// ECON-R13-CRIT-004 regression tests (2026-07-21).
// LiquidStaking StakeLiquid/UnstakeLiquid/ClaimCommission must actually move
// real user funds. Before the fix they only mutated pool accounting fields
// (TotalStaked / Delegators / TotalCommission) without transferring any
// tokens — allowing zero-cost staking, infinite withdrawals, and unclaimable
// commission.
package economics

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// newR13Crit004Manager creates a LiquidStakingManager with a single pool
// owned by `operator` and commission rate 500 (5%).
func newR13Crit004Manager(t *testing.T) (*LiquidStakingManager, *StakingPool, types.Address) {
	t.Helper()
	cfg := DefaultStakingConfig()
	sm := NewStakingManager(cfg)
	lsm := NewLiquidStakingManager(cfg, sm)
	operator := types.Address{0xAA}
	pool, err := lsm.CreatePool(operator, "R13-CRIT-004 Pool", 500)
	if err != nil {
		t.Fatalf("CreatePool failed: %v", err)
	}
	return lsm, pool, operator
}

// TestECON_R13_CRIT_004_StakeLiquid_DebitsUserBalance verifies that
// StakeLiquid actually debits the staked amount from the delegator's balance.
func TestECON_R13_CRIT_004_StakeLiquid_DebitsUserBalance(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	// Deposit 10000 QAU, then stake 1000.
	lsm.Deposit(delegator, StakeAsset, big.NewInt(10_000))
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000)); err != nil {
		t.Fatalf("StakeLiquid failed: %v", err)
	}

	// User balance should be 9000 (10000 - 1000).
	bal := lsm.GetUserTokenBalance(delegator, StakeAsset)
	if bal.Cmp(big.NewInt(9000)) != 0 {
		t.Errorf("expected QAU balance 9000 after StakeLiquid, got %s", bal)
	}

	// Pool.TotalStaked should be 1000.
	retrieved, _ := lsm.GetPool(pool.ID)
	if retrieved.TotalStaked.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected TotalStaked=1000, got %s", retrieved.TotalStaked)
	}
}

// TestECON_R13_CRIT_004_StakeLiquid_RejectsInsufficientBalance verifies that
// StakeLiquid rejects when the delegator has zero balance.
func TestECON_R13_CRIT_004_StakeLiquid_RejectsInsufficientBalance(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	// No Deposit — balance is 0.
	_, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000))
	if err == nil {
		t.Fatal("expected error for StakeLiquid with zero balance, got nil")
	}
	if !strings.Contains(err.Error(), "insufficient user balance") {
		t.Errorf("expected 'insufficient user balance' error, got: %v", err)
	}

	// Pool state must not have been mutated.
	retrieved, _ := lsm.GetPool(pool.ID)
	if retrieved.TotalStaked.Sign() != 0 {
		t.Errorf("TotalStaked mutated on rejected StakeLiquid: %s",
			retrieved.TotalStaked)
	}
}

// TestECON_R13_CRIT_004_StakeLiquid_PartialBalance_Rejected verifies that
// StakeLiquid rejects when the delegator has some balance but not enough.
func TestECON_R13_CRIT_004_StakeLiquid_PartialBalance_Rejected(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	// Deposit 500, then try to stake 1000.
	lsm.Deposit(delegator, StakeAsset, big.NewInt(500))
	_, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000))
	if err == nil {
		t.Fatal("expected error for partial-balance StakeLiquid, got nil")
	}
	if !strings.Contains(err.Error(), "insufficient user balance") {
		t.Errorf("expected 'insufficient user balance', got: %v", err)
	}

	// Balance must remain 500 (no mutation).
	bal := lsm.GetUserTokenBalance(delegator, StakeAsset)
	if bal.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("balance changed on rejected StakeLiquid: %s", bal)
	}
	retrieved, _ := lsm.GetPool(pool.ID)
	if retrieved.TotalStaked.Sign() != 0 {
		t.Errorf("TotalStaked mutated on rejected StakeLiquid: %s",
			retrieved.TotalStaked)
	}
}

// TestECON_R40_P1_02_UnstakeLiquidRejectsZeroRate pins the R40-P1-02 fix:
// a pool whose exchange rate has been corrupted to zero must reject
// UnstakeLiquid instead of silently crediting 0 underlying QAU to the
// delegator while still decrementing pool.TotalLiquidSupply — a zero-cost
// drain of the pool's liquid supply. CreatePool initializes the rate to
// 1e18 (rate=1.0), so this test forcibly corrupts the rate to reproduce
// the exact attack / bug-condition the audit described, then verifies the
// rejection happens BEFORE any pool accounting is mutated.
//
// The nil-rate variant (a pool whose `lsm.exchangeRate[poolID]` map entry
// has never been set) is exercised by the guard `rate == nil` in the
// production code; under CreatePool that path is not reachable in a test
// without corrupting internal state, so we cover the equivalent zero-value
// invariant here.
func TestECON_R40_P1_02_UnstakeLiquidRejectsZeroRate(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	// Seed the delegator with a balance and buy liquid tokens. StakeLiquid
	// succeeds regardless of the exchange rate — it credits liquid tokens
	// 1:1 with the staked amount and does not depend on the rate.
	lsm.Deposit(delegator, StakeAsset, big.NewInt(10_000))
	liquid, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000))
	if err != nil {
		t.Fatalf("StakeLiquid precondition failed: %v", err)
	}
	if liquid == nil || liquid.Amount == nil || liquid.Amount.Sign() <= 0 {
		t.Fatalf("StakeLiquid returned non-positive liquid amount: %v", liquid)
	}

	// Snapshot pool accounting BEFORE the unstake attempt.
	totalLiquidSupplyBefore := new(big.Int).Set(pool.TotalLiquidSupply)
	totalStakedBefore := new(big.Int).Set(pool.TotalStaked)
	totalLiquidStakedBefore := new(big.Int).Set(lsm.totalLiquidStaked)
	delegatorStakeBefore := new(big.Int).Set(pool.Delegators[delegator])
	tokenAmountBefore := new(big.Int).Set(lsm.liquidTokens[delegator][pool.ID].Amount)

	// R40-P1-02 attack scenario: corrupt the pool's exchange rate to zero.
	// CreatePool initializes the rate to 1e18 (rate=1.0), so the zero-rate
	// path is not reachable on a healthy pool. The audit's concern is the
	// corrupted-state variant: an attacker (or a buggy CompoundRewards /
	// fee-distribution path) that sets the rate to zero would let
	// UnstakeLiquid surrender liquid tokens but return 0 underlying QAU —
	// a zero-cost drain. Reproduce that exact condition here.
	lsm.exchangeRate[pool.ID] = big.NewInt(0)

	// UnstakeLiquid MUST reject because the pool's exchange rate is zero.
	returned, err := lsm.UnstakeLiquid(pool.ID, delegator, big.NewInt(100))
	if err == nil {
		t.Fatalf("UnstakeLiquid on zero-rate pool must fail, returned=%v", returned)
	}
	if !strings.Contains(err.Error(), "exchange rate") {
		t.Fatalf("UnstakeLiquid error should mention exchange rate, got: %v", err)
	}
	if returned != nil {
		t.Fatalf("UnstakeLiquid returned amount must be nil on error, got %v", returned)
	}

	// The rejection MUST happen before any pool accounting mutation, otherwise
	// the pool is drained for free.
	if pool.TotalLiquidSupply.Cmp(totalLiquidSupplyBefore) != 0 {
		t.Errorf("TotalLiquidSupply mutated on rejected unstake: before=%s after=%s",
			totalLiquidSupplyBefore.String(), pool.TotalLiquidSupply.String())
	}
	if pool.TotalStaked.Cmp(totalStakedBefore) != 0 {
		t.Errorf("TotalStaked mutated on rejected unstake: before=%s after=%s",
			totalStakedBefore.String(), pool.TotalStaked.String())
	}
	if lsm.totalLiquidStaked.Cmp(totalLiquidStakedBefore) != 0 {
		t.Errorf("totalLiquidStaked mutated on rejected unstake: before=%s after=%s",
			totalLiquidStakedBefore.String(), lsm.totalLiquidStaked.String())
	}
	if pool.Delegators[delegator].Cmp(delegatorStakeBefore) != 0 {
		t.Errorf("Delegators[delegator] mutated on rejected unstake: before=%s after=%s",
			delegatorStakeBefore.String(), pool.Delegators[delegator].String())
	}
	if lsm.liquidTokens[delegator][pool.ID].Amount.Cmp(tokenAmountBefore) != 0 {
		t.Errorf("liquid token amount mutated on rejected unstake: before=%s after=%s",
			tokenAmountBefore.String(), lsm.liquidTokens[delegator][pool.ID].Amount.String())
	}
}

// TestECON_R13_CRIT_004_UnstakeLiquid_CreditsUserBalance verifies that
// UnstakeLiquid actually credits the underlying QAU amount to the delegator.
func TestECON_R13_CRIT_004_UnstakeLiquid_CreditsUserBalance(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	// Deposit 10000, stake 10000 (balance = 0 after stake).
	lsm.Deposit(delegator, StakeAsset, big.NewInt(10_000))
	token, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(10_000))
	if err != nil {
		t.Fatalf("StakeLiquid setup failed: %v", err)
	}
	balAfterStake := lsm.GetUserTokenBalance(delegator, StakeAsset)
	if balAfterStake.Sign() != 0 {
		t.Fatalf("expected 0 balance after StakeLiquid, got %s", balAfterStake)
	}

	// Unstake half of the liquid tokens.
	half := new(big.Int).Div(token.Amount, big.NewInt(2))
	returned, err := lsm.UnstakeLiquid(pool.ID, delegator, half)
	if err != nil {
		t.Fatalf("UnstakeLiquid failed: %v", err)
	}
	if returned.Sign() <= 0 {
		t.Fatalf("expected positive returned amount, got %s", returned)
	}

	// User balance should be ~5000 (half of the 10000 staked).
	balAfterUnstake := lsm.GetUserTokenBalance(delegator, StakeAsset)
	expected := big.NewInt(5000)
	// Allow ±1 wei dust for integer division.
	diff := new(big.Int).Sub(balAfterUnstake, expected)
	if diff.Sign() < 0 {
		diff.Neg(diff)
	}
	if diff.Cmp(big.NewInt(1)) > 0 {
		t.Errorf("expected ~5000 balance after UnstakeLiquid, got %s (diff=%s)",
			balAfterUnstake, diff)
	}
}

// TestECON_R13_CRIT_004_UnstakeLiquid_FullAmount_RestoresBalance verifies
// that unstaking all liquid tokens restores the user's full original stake.
func TestECON_R13_CRIT_004_UnstakeLiquid_FullAmount_RestoresBalance(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	originalAmount := big.NewInt(10_000)
	lsm.Deposit(delegator, StakeAsset, originalAmount)
	token, err := lsm.StakeLiquid(pool.ID, delegator, originalAmount)
	if err != nil {
		t.Fatalf("StakeLiquid setup failed: %v", err)
	}

	// Unstake all liquid tokens.
	returned, err := lsm.UnstakeLiquid(pool.ID, delegator, token.Amount)
	if err != nil {
		t.Fatalf("UnstakeLiquid failed: %v", err)
	}
	if returned.Cmp(originalAmount) != 0 {
		t.Errorf("expected returned=%s, got %s", originalAmount, returned)
	}

	// User balance should equal the original stake.
	bal := lsm.GetUserTokenBalance(delegator, StakeAsset)
	if bal.Cmp(originalAmount) != 0 {
		t.Errorf("expected balance %s after full unstake, got %s", originalAmount, bal)
	}

	// Pool.TotalStaked should be 0.
	retrieved, _ := lsm.GetPool(pool.ID)
	if retrieved.TotalStaked.Sign() != 0 {
		t.Errorf("expected TotalStaked=0 after full unstake, got %s",
			retrieved.TotalStaked)
	}
}

// TestECON_R13_CRIT_004_ClaimCommission_CreditsOperator verifies that
// ClaimCommission actually credits the accumulated commission to the
// operator's balance sheet.
func TestECON_R13_CRIT_004_ClaimCommission_CreditsOperator(t *testing.T) {
	lsm, pool, operator := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	// Setup: deposit, stake 1000 QAU.
	lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000)); err != nil {
		t.Fatalf("StakeLiquid failed: %v", err)
	}

	// Distribute 100 QAU reward. Commission rate is 500 bps = 5%, so
	// commission = 5 QAU, delegator reward = 95 QAU.
	// ECON-R14-CRIT-004: DistributeRewards now requires operator auth
	// and debits from the operator's balance.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(100)); err != nil {
		t.Fatalf("DistributeRewards failed: %v", err)
	}

	// Pending commission should be 5.
	pending, err := lsm.GetPendingCommission(pool.ID)
	if err != nil {
		t.Fatalf("GetPendingCommission failed: %v", err)
	}
	if pending.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("expected pending commission=5, got %s", pending)
	}

	// Operator balance before claim should be 900 (1000 funded - 100 distributed).
	// ECON-R14-CRIT-004: DistributeRewards debits the reward from the operator.
	opBalBefore := lsm.GetUserTokenBalance(operator, StakeAsset)
	if opBalBefore.Cmp(big.NewInt(900)) != 0 {
		t.Fatalf("expected operator balance=900 before claim, got %s", opBalBefore)
	}

	// Claim commission.
	claimed, err := lsm.ClaimCommission(pool.ID, operator)
	if err != nil {
		t.Fatalf("ClaimCommission failed: %v", err)
	}
	if claimed.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("expected claimed=5, got %s", claimed)
	}

	// Operator balance after claim should be 905 (900 + 5 commission).
	opBalAfter := lsm.GetUserTokenBalance(operator, StakeAsset)
	if opBalAfter.Cmp(big.NewInt(905)) != 0 {
		t.Errorf("expected operator balance=905 after claim, got %s", opBalAfter)
	}

	// Pending commission should be reset to 0.
	pendingAfter, _ := lsm.GetPendingCommission(pool.ID)
	if pendingAfter.Sign() != 0 {
		t.Errorf("expected pending=0 after claim, got %s", pendingAfter)
	}
}

// TestECON_R13_CRIT_004_ClaimCommission_RejectsNonOperator verifies that
// ClaimCommission rejects callers who are not the pool operator.
func TestECON_R13_CRIT_004_ClaimCommission_RejectsNonOperator(t *testing.T) {
	lsm, pool, operator := newR13Crit004Manager(t)
	delegator := types.Address{0x42}
	attacker := types.Address{0xBB}

	// Setup: deposit, stake, distribute rewards (accrues commission).
	lsm.Deposit(delegator, StakeAsset, big.NewInt(1000))
	if _, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(1000)); err != nil {
		t.Fatalf("StakeLiquid failed: %v", err)
	}
	// ECON-R14-CRIT-004: fund operator so DistributeRewards can debit.
	lsm.Deposit(operator, StakeAsset, big.NewInt(1000))
	if err := lsm.DistributeRewards(pool.ID, operator, big.NewInt(100)); err != nil {
		t.Fatalf("DistributeRewards failed: %v", err)
	}

	// Non-operator attempts to claim — must be rejected.
	_, err := lsm.ClaimCommission(pool.ID, attacker)
	if err == nil {
		t.Fatal("expected error when non-operator claims commission, got nil")
	}
	if !strings.Contains(err.Error(), "invalid pool operator") {
		t.Errorf("expected 'invalid pool operator', got: %v", err)
	}

	// Attacker balance must remain 0.
	attackerBal := lsm.GetUserTokenBalance(attacker, StakeAsset)
	if attackerBal.Sign() != 0 {
		t.Errorf("attacker received commission despite rejection: %s", attackerBal)
	}
}

// TestECON_R13_CRIT_004_StakeUnstake_RoundTrip_PreservesBalance verifies
// the full stake -> unstake round-trip preserves the delegator's balance.
func TestECON_R13_CRIT_004_StakeUnstake_RoundTrip_PreservesBalance(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x42}

	// Start with 1_000_000 QAU.
	original := big.NewInt(1_000_000)
	lsm.Deposit(delegator, StakeAsset, original)

	// Stake then unstake in multiple rounds.
	remaining := new(big.Int).Set(original)
	for i := 0; i < 3; i++ {
		stakeAmount := big.NewInt(100_000)
		token, err := lsm.StakeLiquid(pool.ID, delegator, stakeAmount)
		if err != nil {
			t.Fatalf("round %d StakeLiquid failed: %v", i, err)
		}
		returned, err := lsm.UnstakeLiquid(pool.ID, delegator, token.Amount)
		if err != nil {
			t.Fatalf("round %d UnstakeLiquid failed: %v", i, err)
		}
		if returned.Cmp(stakeAmount) != 0 {
			t.Errorf("round %d: expected returned=%s, got %s",
				i, stakeAmount, returned)
		}
		// No rewards distributed, so balance should be restored exactly.
		remaining.Add(remaining, big.NewInt(0))
	}

	// Final balance should equal the original deposit (no rewards/penalties).
	finalBal := lsm.GetUserTokenBalance(delegator, StakeAsset)
	if finalBal.Cmp(original) != 0 {
		t.Errorf("round-trip should preserve balance: expected %s, got %s",
			original, finalBal)
	}
}

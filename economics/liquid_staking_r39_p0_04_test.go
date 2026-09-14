// Quantaureum Node source, version 1.0.0.
// R39-P0-04 (2026-08-02) regression tests.
//
// StakeLiquid MUST reject attempts where the integer-division
// liquidAmount = amount * 1e18 / exchangeRate rounds to zero. Before the
// fix, the user was debited real QAU but minted zero liquid tokens, then
// could never recover via UnstakeLiquid (which requires liquidAmount > 0)
// — a permanent fund lock. These tests pin the fail-closed behavior.
package economics

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestECON_R39_P0_04_StakeLiquid_RejectsZeroLiquidAmount verifies that when
// exchangeRate is high enough that liquidAmount = amount*1e18/rate == 0,
// StakeLiquid fails atomically: the user keeps their balance and the pool
// accounting is untouched.
func TestECON_R39_P0_04_StakeLiquid_RejectsZeroLiquidAmount(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x99}

	// Deposit 1e18 QAU so an amount of 1e17 is well within balance.
	lsm.Deposit(delegator, StakeAsset, big.NewInt(0).SetUint64(1e18))

	// Push the exchange rate to a value that forces liquidAmount = 0 for
	// amount = 1e17: liquidAmount = 1e17 * 1e18 / 1e36 = 0. rate=1e36 is
	// outside uint64 range, so set it from a decimal string.
	rate1e36, ok := new(big.Int).SetString("1000000000000000000000000000000000000", 10)
	if !ok {
		t.Fatal("invalid rate literal")
	}
	lsm.mu.Lock()
	lsm.exchangeRate[pool.ID] = rate1e36
	lsm.mu.Unlock()

	balBefore := lsm.GetUserTokenBalance(delegator, StakeAsset)
	totalStakedBefore := new(big.Int).Set(pool.TotalStaked)
	totalLiquidBefore := new(big.Int).Set(pool.TotalLiquidSupply)

	// amount = 1e17 (in uint64 range — 1e17 < uint64 max ~1.8e19).
	amount := new(big.Int).SetUint64(100_000_000_000_000_000) // 1e17
	_, err := lsm.StakeLiquid(pool.ID, delegator, amount)
	if err == nil {
		t.Fatal("expected StakeLiquid to fail when liquidAmount rounds to zero, got nil")
	}
	if !strings.Contains(err.Error(), "rounds to zero") {
		t.Fatalf("expected error to mention 'rounds to zero', got: %v", err)
	}

	// State must be unchanged: no debit, no pool mutation.
	balAfter := lsm.GetUserTokenBalance(delegator, StakeAsset)
	if balAfter.Cmp(balBefore) != 0 {
		t.Errorf("user balance changed on rejected stake: before=%s after=%s", balBefore.String(), balAfter.String())
	}
	if pool.TotalStaked.Cmp(totalStakedBefore) != 0 {
		t.Errorf("pool.TotalStaked mutated on rejected stake: before=%s after=%s",
			totalStakedBefore.String(), pool.TotalStaked.String())
	}
	if pool.TotalLiquidSupply.Cmp(totalLiquidBefore) != 0 {
		t.Errorf("pool.TotalLiquidSupply mutated on rejected stake: before=%s after=%s",
			totalLiquidBefore.String(), pool.TotalLiquidSupply.String())
	}
}

// TestECON_R39_P0_04_StakeLiquid_RejectsUninitializedRate verifies that a
// pool whose exchange rate was never set (or set to zero) is rejected
// atomically rather than panicking on Div(nil) or divide-by-zero.
func TestECON_R39_P0_04_StakeLiquid_RejectsUninitializedRate(t *testing.T) {
	lsm, pool, _ := newR13Crit004Manager(t)
	delegator := types.Address{0x77}
	lsm.Deposit(delegator, StakeAsset, big.NewInt(10_000))

	// Simulate a misconfigured pool: zero out the exchange rate.
	lsm.mu.Lock()
	lsm.exchangeRate[pool.ID] = big.NewInt(0)
	lsm.mu.Unlock()

	balBefore := lsm.GetUserTokenBalance(delegator, StakeAsset)
	_, err := lsm.StakeLiquid(pool.ID, delegator, big.NewInt(100))
	if err == nil {
		t.Fatal("expected StakeLiquid to fail when exchange rate is zero, got nil")
	}
	if !strings.Contains(err.Error(), "exchange rate") {
		t.Fatalf("expected error to mention 'exchange rate', got: %v", err)
	}
	if got := lsm.GetUserTokenBalance(delegator, StakeAsset); got.Cmp(balBefore) != 0 {
		t.Errorf("user balance changed on rejected stake: before=%s after=%s", balBefore.String(), got.String())
	}

	// Also bound the nil-rate path (map key removed entirely) — must not
	// panic on Div(nil).
	lsm.mu.Lock()
	delete(lsm.exchangeRate, pool.ID)
	lsm.mu.Unlock()
	_, err = lsm.StakeLiquid(pool.ID, delegator, big.NewInt(100))
	if err == nil {
		t.Fatal("expected StakeLiquid to fail when exchange rate is missing, got nil")
	}
	if !strings.Contains(err.Error(), "exchange rate") {
		t.Fatalf("expected error to mention 'exchange rate', got: %v", err)
	}
}

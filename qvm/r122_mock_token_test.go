// Quantaureum Node source, version 1.0.0.
package qvm

// R122 step-2: MockToken contract tests.
// Constructor pre-mints 1e24 (1M tokens, 18dp) to the deployer; owner-only mint.

import (
	"math/big"
	"testing"
)

func newMockTokenFixture(t *testing.T, deployer Address) *tokenFixture {
	t.Helper()
	initCode := loadContractHex(t, "../contracts/qasm/mock_token.hex")
	db := newMockStateDB()
	db.SetBalance(deployer, big.NewInt(1_000_000))
	db.SetNonce(deployer, 1)
	exec := NewExecutor()
	ctx := &BlockContext{BlockNumber: 1, Timestamp: 1700000000, GasLimit: 20_000_000, ChainID: 1668}
	res, addr := exec.Create(db, deployer, initCode, 2_000_000, big.NewInt(0), ctx, 0)
	if res.Err != nil {
		t.Fatalf("mocktoken deploy: %v", res.Err)
	}
	return &tokenFixture{db: db, contract: addr, exec: exec, ctx: ctx, deployer: deployer}
}

// tokenFixture is shared ERC20-style contract test scaffolding (wQAU + MockToken).
type tokenFixture struct {
	db       *mockStateDB
	contract Address
	exec     *Executor
	ctx      *BlockContext
	deployer Address
}

func (f *tokenFixture) call(t *testing.T, caller Address, input []byte, gas uint64) ([]byte, error) {
	t.Helper()
	res := f.exec.Call(f.db, caller, f.contract, input, gas, big.NewInt(0), f.ctx, 0)
	return res.ReturnData, res.Err
}

func (f *tokenFixture) mustCall(t *testing.T, caller Address, input []byte, gas uint64) []byte {
	t.Helper()
	ret, err := f.call(t, caller, input, gas)
	if err != nil {
		t.Fatalf("call sel=%x: %v", input[:4], err)
	}
	return ret
}

func (f *tokenFixture) balanceOf(t *testing.T, who Address) *big.Int {
	input := append(append([]byte{}, wSelBalOf...), padAddressWord(who)...)
	return new(big.Int).SetBytes(f.mustCall(t, who, input, 200_000))
}

func (f *tokenFixture) totalSupply(t *testing.T) *big.Int {
	return new(big.Int).SetBytes(f.mustCall(t, f.deployer, wSelSupply, 100_000))
}

// --- tests ---

func TestR122MockTokenPremint(t *testing.T) {
	deployer := Address{0x11}
	f := newMockTokenFixture(t, deployer)

	want := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil) // 1e24
	if got := f.balanceOf(t, deployer); got.Cmp(want) != 0 {
		t.Fatalf("deployer balance = %s, want %s", got, want)
	}
	if got := f.totalSupply(t); got.Cmp(want) != 0 {
		t.Fatalf("supply = %s, want %s", got, want)
	}
}

func TestR122MockTokenMintOwnerOnly(t *testing.T) {
	deployer := Address{0x11}
	f := newMockTokenFixture(t, deployer)
	other := Address{0x22}
	// mint input: sel + pad(to) + pad(amount)
	mintInput := func(to Address, amt *big.Int) []byte {
		input := append([]byte{}, 0x40, 0xc1, 0x0f, 0x19)
		input = append(input, padAddressWord(to)...)
		return append(input, amt.FillBytes(make([]byte, 32))...)
	}

	// non-owner mint reverts
	if _, err := f.call(t, other, mintInput(other, big.NewInt(5)), 200_000); err == nil {
		t.Fatal("non-owner mint should revert")
	}
	// owner mints 5 to other
	f.mustCall(t, deployer, mintInput(other, big.NewInt(5)), 200_000)
	if got := f.balanceOf(t, other); got.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("other balance = %s, want 5", got)
	}
	supply := new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil)
	supply.Add(supply, big.NewInt(5))
	if got := f.totalSupply(t); got.Cmp(supply) != 0 {
		t.Fatalf("supply = %s, want %s", got, supply)
	}
}

func TestR122MockTokenTransferAllowance(t *testing.T) {
	deployer := Address{0x11}
	f := newMockTokenFixture(t, deployer)
	bob, carol := Address{0x22}, Address{0x33}

	// transfer 100 to bob
	f.mustCall(t, deployer, wqauTransferInput(bob, big.NewInt(100)), 500_000)
	if got := f.balanceOf(t, bob); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("bob = %s, want 100", got)
	}
	// approve carol 60, transferFrom 60
	f.mustCall(t, bob, wqauApproveInput(carol, big.NewInt(60)), 500_000)
	f.mustCall(t, carol, wqauTransferFromInput(bob, carol, big.NewInt(60)), 500_000)
	if got := f.balanceOf(t, carol); got.Cmp(big.NewInt(60)) != 0 {
		t.Fatalf("carol = %s, want 60", got)
	}
	// allowance now 0: another pull reverts
	if _, err := f.call(t, carol, wqauTransferFromInput(bob, carol, big.NewInt(1)), 500_000); err == nil {
		t.Fatal("spent-allowance pull should revert")
	}
}

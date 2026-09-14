// Quantaureum Node source, version 1.0.0.
package qvm

// R122 step-1: wQAU (wrapped native QAU) contract tests.
// Drives the assembled contracts/qasm/wqau.hex through the real QVM executor.
//
// Covered: deposit/withdraw round-trip, supply invariants, transfer,
// approve/allowance double-mapping, transferFrom allowance burn,
// infinite-allowance exception, revert paths leave state intact.

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
)

// wQAU selectors (keccak256 of Solidity signatures).
var (
	wSelDeposit   = []byte{0xd0, 0xe3, 0x0d, 0xb0}
	wSelWithdraw  = []byte{0x2e, 0x1a, 0x7d, 0x4d}
	wSelSupply    = []byte{0x18, 0x16, 0x0d, 0xdd}
	wSelBalOf     = []byte{0x70, 0xa0, 0x82, 0x31}
	wSelAllow     = []byte{0xdd, 0x62, 0xed, 0x3e}
	wSelApprove   = []byte{0x09, 0x5e, 0xa7, 0xb3}
	wSelTransfer  = []byte{0xa9, 0x05, 0x9c, 0xbb}
	wSelTransFrom = []byte{0x23, 0xb8, 0x72, 0xdd}
)

func loadWqauHex(t *testing.T) []byte {
	t.Helper()
	return loadContractHex(t, "../contracts/qasm/wqau.hex")
}

// wqauFixture deploys wQAU and returns helpers bound to it.
type wqauFixture struct {
	db       *mockStateDB
	contract Address
	exec     *Executor
	ctx      *BlockContext
}

func newWqauFixture(t *testing.T) *wqauFixture {
	t.Helper()
	initCode := loadWqauHex(t)
	db := newMockStateDB()
	deployer := Address{0x11}
	db.SetBalance(deployer, big.NewInt(1_000_000_000))
	db.SetNonce(deployer, 1)
	exec := NewExecutor()
	ctx := &BlockContext{BlockNumber: 1, Timestamp: 1700000000, GasLimit: 20_000_000, ChainID: 1668}
	res, addr := exec.Create(db, deployer, initCode, 2_000_000, big.NewInt(0), ctx, 0)
	if res.Err != nil {
		t.Fatalf("wqau deploy: %v", res.Err)
	}
	return &wqauFixture{db: db, contract: addr, exec: exec, ctx: ctx}
}

// call runs a function; returns return-data and error.
func (f *wqauFixture) call(t *testing.T, caller Address, input []byte, value *big.Int, gas uint64) ([]byte, error) {
	t.Helper()
	res := f.exec.Call(f.db, caller, f.contract, input, gas, value, f.ctx, 0)
	return res.ReturnData, res.Err
}

// mustCall expects success and returns the 32-byte ret word.
func (f *wqauFixture) mustCall(t *testing.T, caller Address, input []byte, value *big.Int, gas uint64) []byte {
	t.Helper()
	ret, err := f.call(t, caller, input, value, gas)
	if err != nil {
		t.Fatalf("call sel=%x: %v", input[:4], err)
	}
	return ret
}

func (f *wqauFixture) balanceOf(t *testing.T, who Address) *big.Int {
	input := append(append([]byte{}, wSelBalOf...), padAddressWord(who)...)
	ret := f.mustCall(t, who, input, big.NewInt(0), 200_000)
	return new(big.Int).SetBytes(ret)
}

func (f *wqauFixture) totalSupply(t *testing.T, who Address) *big.Int {
	ret := f.mustCall(t, who, wSelSupply, big.NewInt(0), 100_000)
	return new(big.Int).SetBytes(ret)
}

func (f *wqauFixture) allowance(t *testing.T, owner, spender Address) *big.Int {
	input := append(append([]byte{}, wSelAllow...), padAddressWord(owner)...)
	input = append(input, padAddressWord(spender)...)
	ret := f.mustCall(t, owner, input, big.NewInt(0), 200_000)
	return new(big.Int).SetBytes(ret)
}

func wqauTransferInput(to Address, wad *big.Int) []byte {
	input := append(append([]byte{}, wSelTransfer...), padAddressWord(to)...)
	input = append(input, wad.FillBytes(make([]byte, 32))...)
	return input
}

func wqauApproveInput(spender Address, wad *big.Int) []byte {
	input := append(append([]byte{}, wSelApprove...), padAddressWord(spender)...)
	input = append(input, wad.FillBytes(make([]byte, 32))...)
	return input
}

func wqauTransferFromInput(from, to Address, wad *big.Int) []byte {
	input := append(append([]byte{}, wSelTransFrom...), padAddressWord(from)...)
	input = append(input, padAddressWord(to)...)
	input = append(input, wad.FillBytes(make([]byte, 32))...)
	return input
}

// --- tests ---

// TestR122WqauDepositWithdrawRoundTrip: deposit 10 -> balance 10, supply 10;
// withdraw 3 -> balance 7, supply 7; contract native balance tracks value.
func TestR122WqauDepositWithdrawRoundTrip(t *testing.T) {
	f := newWqauFixture(t)
	alice := Address{0x22}
	f.db.SetBalance(alice, big.NewInt(1000))

	// deposit 10 (value = 10 wei of native)
	f.mustCall(t, alice, wSelDeposit, big.NewInt(10), 500_000)
	if got := f.balanceOf(t, alice); got.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("after deposit, balance = %s, want 10", got)
	}
	if got := f.totalSupply(t, alice); got.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("after deposit, supply = %s, want 10", got)
	}

	// withdraw 3
	input := append(append([]byte{}, wSelWithdraw...), big.NewInt(3).FillBytes(make([]byte, 32))...)
	f.mustCall(t, alice, input, big.NewInt(0), 500_000)
	if got := f.balanceOf(t, alice); got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("after withdraw, balance = %s, want 7", got)
	}
	if got := f.totalSupply(t, alice); got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("after withdraw, supply = %s, want 7", got)
	}

	// native balance moved back: 1000 - 10 + 3 = 993
	if got := f.db.GetBalance(alice); got.Cmp(big.NewInt(993)) != 0 {
		t.Fatalf("alice native = %s, want 993", got)
	}
	if got := f.db.GetBalance(f.contract); got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("contract native = %s, want 7", got)
	}
}

// TestR122WqauWithdrawOverdraft: withdrawing more than balance reverts
// and leaves state untouched.
func TestR122WqauWithdrawOverdraft(t *testing.T) {
	f := newWqauFixture(t)
	alice := Address{0x22}
	f.db.SetBalance(alice, big.NewInt(1000))
	f.mustCall(t, alice, wSelDeposit, big.NewInt(5), 500_000)

	input := append(append([]byte{}, wSelWithdraw...), big.NewInt(99).FillBytes(make([]byte, 32))...)
	if _, err := f.call(t, alice, input, big.NewInt(0), 500_000); err == nil {
		t.Fatal("overdraft withdraw should revert")
	}
	if got := f.balanceOf(t, alice); got.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("after failed withdraw, balance = %s, want 5", got)
	}
}

// TestR122WqauTransfer: 100-40 → 60/40 exact, overdraft reverts clean.
func TestR122WqauTransfer(t *testing.T) {
	f := newWqauFixture(t)
	alice, bob := Address{0x22}, Address{0x33}
	f.db.SetBalance(alice, big.NewInt(1000))
	f.mustCall(t, alice, wSelDeposit, big.NewInt(100), 500_000)

	ret := f.mustCall(t, alice, wqauTransferInput(bob, big.NewInt(40)), big.NewInt(0), 500_000)
	if len(ret) != 32 || new(big.Int).SetBytes(ret).Int64() != 1 {
		t.Fatalf("transfer ret = %x, want true", ret)
	}
	if got := f.balanceOf(t, alice); got.Cmp(big.NewInt(60)) != 0 {
		t.Fatalf("alice = %s, want 60", got)
	}
	if got := f.balanceOf(t, bob); got.Cmp(big.NewInt(40)) != 0 {
		t.Fatalf("bob = %s, want 40", got)
	}

	// overdraft revert
	if _, err := f.call(t, alice, wqauTransferInput(bob, big.NewInt(61)), big.NewInt(0), 500_000); err == nil {
		t.Fatal("overdraft transfer should revert")
	}
	if got := f.balanceOf(t, alice); got.Cmp(big.NewInt(60)) != 0 {
		t.Fatalf("after failed transfer, alice = %s, want 60 (rollback)", got)
	}
}

// TestR122WqauApproveTransferFrom: approve 50 → transferFrom 30 burns
// allowance to 20 and moves balances; transferFrom 21 reverts.
func TestR122WqauApproveTransferFrom(t *testing.T) {
	f := newWqauFixture(t)
	alice, bob, carol := Address{0x22}, Address{0x33}, Address{0x44}
	f.db.SetBalance(alice, big.NewInt(1000))
	f.mustCall(t, alice, wSelDeposit, big.NewInt(100), 500_000)

	// approve(bob, 50)
	f.mustCall(t, alice, wqauApproveInput(bob, big.NewInt(50)), big.NewInt(0), 500_000)
	if got := f.allowance(t, alice, bob); got.Cmp(big.NewInt(50)) != 0 {
		t.Fatalf("allowance = %s, want 50", got)
	}

	// bob pulls 30 from alice to carol
	f.mustCall(t, bob, wqauTransferFromInput(alice, carol, big.NewInt(30)), big.NewInt(0), 500_000)
	if got := f.allowance(t, alice, bob); got.Cmp(big.NewInt(20)) != 0 {
		t.Fatalf("allowance after pull = %s, want 20", got)
	}
	if got := f.balanceOf(t, alice); got.Cmp(big.NewInt(70)) != 0 {
		t.Fatalf("alice = %s, want 70", got)
	}
	if got := f.balanceOf(t, carol); got.Cmp(big.NewInt(30)) != 0 {
		t.Fatalf("carol = %s, want 30", got)
	}

	// over-allowance pull reverts, allowance unchanged
	if _, err := f.call(t, bob, wqauTransferFromInput(alice, carol, big.NewInt(21)), big.NewInt(0), 500_000); err == nil {
		t.Fatal("over-allowance transferFrom should revert")
	}
	if got := f.allowance(t, alice, bob); got.Cmp(big.NewInt(20)) != 0 {
		t.Fatalf("after failed pull, allowance = %s, want 20 (rollback)", got)
	}
}

// TestR122WqauInfiniteAllowance: approving max (2^256-1) skips the burn.
func TestR122WqauInfiniteAllowance(t *testing.T) {
	f := newWqauFixture(t)
	alice, bob, carol := Address{0x22}, Address{0x33}, Address{0x44}
	f.db.SetBalance(alice, big.NewInt(1000))
	f.mustCall(t, alice, wSelDeposit, big.NewInt(100), 500_000)

	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	f.mustCall(t, alice, wqauApproveInput(bob, max), big.NewInt(0), 500_000)

	f.mustCall(t, bob, wqauTransferFromInput(alice, carol, big.NewInt(30)), big.NewInt(0), 500_000)
	if got := f.allowance(t, alice, bob); got.Cmp(max) != 0 {
		t.Fatalf("infinite allowance should stay max, got %s", got)
	}
}

// TestR122WqauTransferFromNoAllowance: zero allowance reverts.
func TestR122WqauTransferFromNoAllowance(t *testing.T) {
	f := newWqauFixture(t)
	alice, bob, carol := Address{0x22}, Address{0x33}, Address{0x44}
	f.db.SetBalance(alice, big.NewInt(1000))
	f.mustCall(t, alice, wSelDeposit, big.NewInt(100), 500_000)

	if _, err := f.call(t, bob, wqauTransferFromInput(alice, carol, big.NewInt(1)), big.NewInt(0), 500_000); err == nil {
		t.Fatal("transferFrom with zero allowance should revert")
	}
	if got := f.balanceOf(t, alice); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("balance must be untouched, got %s", got)
	}
}

// TestR122WqauSupplyNeverBreaks: deposit+transfer+withdraw keep
// supply == sum(balances).
func TestR122WqauSupplyNeverBreaks(t *testing.T) {
	f := newWqauFixture(t)
	alice, bob := Address{0x22}, Address{0x33}
	f.db.SetBalance(alice, big.NewInt(1000))

	f.mustCall(t, alice, wSelDeposit, big.NewInt(50), 500_000)
	f.mustCall(t, alice, wqauTransferInput(bob, big.NewInt(20)), big.NewInt(0), 500_000)

	sum := new(big.Int).Add(f.balanceOf(t, alice), f.balanceOf(t, bob))
	if got := f.totalSupply(t, alice); got.Cmp(sum) != 0 {
		t.Fatalf("supply %s != sum(balances) %s", got, sum)
	}

	// withdraw some and re-check
	input := append(append([]byte{}, wSelWithdraw...), big.NewInt(5).FillBytes(make([]byte, 32))...)
	f.mustCall(t, bob, input, big.NewInt(0), 500_000)
	sum = new(big.Int).Add(f.balanceOf(t, alice), f.balanceOf(t, bob))
	if got := f.totalSupply(t, alice); got.Cmp(sum) != 0 {
		t.Fatalf("after withdraw: supply %s != sum %s", got, sum)
	}
}

// loadContractHex is the shared hex loader for R122 contract tests.
func loadContractHex(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("hex not assembled (%v); run the qasm assembler first", err)
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "0x")
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in %s: %v", path, err)
	}
	return out
}

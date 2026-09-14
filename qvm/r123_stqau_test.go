// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// R123 Step-1: stQAU liquid-staking receipt contract tests (plan §3)
//
// storage: 0=owner 1=paused 2=totalSupply 3=balanceOf mapping 4=allowance mapping
//       5=totalQueued 6=queuedShares 7=queuedOwed 8=queuedUnlock 9=totalExtracted
//
// deploy: owner nonce=1 → stqau contract (no constructor args)
//
// core lifecycle:
//   deposit() payable         → shares = CV × supply / backing (first mint 1:1)
//   withdraw(shares)          → burn + queue (owed locked at the rate; unlock = NUMBER + 151200)
//   claimWithdrawal()         → native payout once NUMBER ≥ unlock
//   injectRewards() payable   → takes CALLVALUE as-is (rate rises automatically)
//   extractForStaking(amt)    → owner extracts native (totalExtracted accrues)
//   exchangeRate()            → (SELFBALANCE − totalQueued) × 1e18 / supply

var (
	stSelDeposit         = []byte{0xd0, 0xe3, 0x0d, 0xb0} // deposit()
	stSelWithdraw        = []byte{0x2e, 0x1a, 0x7d, 0x4d} // withdraw(uint256)
	stSelClaimWithdrawal = []byte{0x6e, 0x66, 0xd8, 0x4a} // claimWithdrawal()
	stSelInjectRewards   = []byte{0x99, 0xc7, 0x22, 0xbc} // injectRewards()
	stSelExtract         = []byte{0x8c, 0xc5, 0x7d, 0x95} // extractForStaking(uint256)
	stSelExchangeRate    = []byte{0x3b, 0xa0, 0xb9, 0xa9} // exchangeRate()
	stSelTotalBacking    = []byte{0xeb, 0x2c, 0xd2, 0x58} // totalBacking()
	stSelWithdrawalOf    = []byte{0x14, 0xbf, 0x9d, 0x2b} // withdrawalOf(address)
	stSelPauseDeposits   = []byte{0x02, 0x19, 0x19, 0x80} // pauseDeposits()
	stSelUnpauseDeposits = []byte{0x63, 0xd8, 0x88, 0x2a} // unpauseDeposits()
	stSelTransferOwner   = []byte{0xf2, 0xfd, 0xe3, 0x8b} // transferOwnership(address)
	stSelOwner           = []byte{0x8d, 0xa5, 0xcb, 0x5b} // owner()
	stSelTotalSupply     = []byte{0x18, 0x16, 0x0d, 0xdd} // totalSupply()
	stSelBalanceOf       = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	stSelTransfer        = []byte{0xa9, 0x05, 0x9c, 0xbb} // transfer(address,uint256)
)

// stqauUnbondBlocks: 21 days @ 12s = 151,200 blocks (UnbondingPeriod in economics/staking.go)
const stqauUnbondBlocks = 151_200

type stqauFixture struct {
	db    *mockStateDB
	exec  *Executor
	ctx   *BlockContext
	owner Address
	alice Address
	bob   Address
	st    Address
}

func newStqauFixture(t *testing.T) *stqauFixture {
	t.Helper()
	f := &stqauFixture{
		db:    newMockStateDB(),
		exec:  NewExecutor(),
		ctx:   &BlockContext{BlockNumber: 1_000, Timestamp: 1_788_676_000, GasLimit: 20_000_000, ChainID: 1668},
		owner: Address{0x51},
		alice: Address{0x22},
		bob:   Address{0x33},
	}
	f.db.SetBalance(f.owner, big.NewInt(0).Mul(big.NewInt(1_000_000), big.NewInt(1e18)))
	f.db.SetBalance(f.alice, big.NewInt(0).Mul(big.NewInt(1_000_000), big.NewInt(1e18)))
	f.db.SetBalance(f.bob, big.NewInt(0).Mul(big.NewInt(1_000_000), big.NewInt(1e18)))

	f.db.SetNonce(f.owner, 1)
	res, addr := f.exec.Create(f.db, f.owner, loadContractHex(t, "../contracts/qasm/stqau.hex"), 5_000_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("deploy stqau: %v", res.Err)
	}
	f.st = addr
	return f
}

// call: value-less call
func (f *stqauFixture) call(caller Address, input []byte, gas uint64) ([]byte, error) {
	res := f.exec.Call(f.db, caller, f.st, input, gas, big.NewInt(0), f.ctx, 0)
	return res.ReturnData, res.Err
}

// callValue: call with value
func (f *stqauFixture) callValue(caller Address, input []byte, gas uint64, value *big.Int) ([]byte, error) {
	res := f.exec.Call(f.db, caller, f.st, input, gas, value, f.ctx, 0)
	return res.ReturnData, res.Err
}

// stqauBal: stQAU balanceOf
func (f *stqauFixture) stqauBal(t *testing.T, who Address) *big.Int {
	t.Helper()
	in := append(append([]byte{}, stSelBalanceOf...), padAddressWord(who)...)
	out, err := f.call(who, in, 200_000)
	if err != nil {
		t.Fatalf("stqauBal: %v", err)
	}
	return new(big.Int).SetBytes(out)
}

// rate: exchangeRate()
func (f *stqauFixture) rate(t *testing.T) *big.Int {
	t.Helper()
	out, err := f.call(f.alice, stSelExchangeRate, 200_000)
	if err != nil {
		t.Fatalf("exchangeRate: %v", err)
	}
	return new(big.Int).SetBytes(out)
}

// backing: totalBacking()
func (f *stqauFixture) backing(t *testing.T) *big.Int {
	t.Helper()
	out, err := f.call(f.alice, stSelTotalBacking, 200_000)
	if err != nil {
		t.Fatalf("totalBacking: %v", err)
	}
	return new(big.Int).SetBytes(out)
}

// nativeBal: user's native balance
func (f *stqauFixture) nativeBal(who Address) *big.Int {
	return new(big.Int).Set(f.db.GetBalance(who))
}

// mustDeposit: deposit{CV}
func (f *stqauFixture) mustDeposit(t *testing.T, who Address, cv *big.Int) {
	t.Helper()
	if _, err := f.callValue(who, stSelDeposit, 8_000_000, cv); err != nil {
		t.Fatalf("deposit %s: %v", cv, err)
	}
}

// withdrawSharesInput: withdraw(shares)
func stqauWithdrawInput(shares *big.Int) []byte {
	return append(append([]byte{}, stSelWithdraw...), u256(shares)...)
}

// e18
func stqauE18(v int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(v), big.NewInt(1e18))
}

// ============ deployment and initial state ============

func TestR123StqauDeployInit(t *testing.T) {
	f := newStqauFixture(t)
	// owner = deployer
	out, err := f.call(f.alice, stSelOwner, 100_000)
	if err != nil {
		t.Fatalf("owner(): %v", err)
	}
	if got := new(big.Int).SetBytes(out); got.Cmp(new(big.Int).SetBytes(padAddressWord(f.owner))) != 0 {
		t.Fatalf("owner = %x, want %x", got, padAddressWord(f.owner))
	}
	// totalSupply = 0
	out, err = f.call(f.alice, stSelTotalSupply, 100_000)
	if err != nil {
		t.Fatalf("totalSupply(): %v", err)
	}
	if got := new(big.Int).SetBytes(out); got.Sign() != 0 {
		t.Fatalf("totalSupply = %s, want 0", got)
	}
	// exchangeRate = 1e18 (supply=0)
	if got := f.rate(t); got.Cmp(stqauE18(1)) != 0 {
		t.Fatalf("rate = %s, want 1e18", got)
	}
	// backing = 0
	if got := f.backing(t); got.Sign() != 0 {
		t.Fatalf("backing = %s, want 0", got)
	}
}

// ============ deposit: first mint 1:1 ============

func TestR123StqauDepositFirstShares(t *testing.T) {
	f := newStqauFixture(t)
	f.mustDeposit(t, f.alice, stqauE18(100))
	if got := f.stqauBal(t, f.alice); got.Cmp(stqauE18(100)) != 0 {
		t.Fatalf("alice stQAU = %s, want 100e18", got)
	}
	if got := f.backing(t); got.Cmp(stqauE18(100)) != 0 {
		t.Fatalf("backing = %s, want 100e18", got)
	}
	if got := f.rate(t); got.Cmp(stqauE18(1)) != 0 {
		t.Fatalf("rate = %s, want 1e18 (first mint 1:1)", got)
	}
}

// ============ deposit: proportional mint + rate ============

func TestR123StqauDepositProportional(t *testing.T) {
	f := newStqauFixture(t)
	// alice deposits 100 → 100 shares
	f.mustDeposit(t, f.alice, stqauE18(100))
	// inject 50 reward → rate = (100+50)/100 = 1.5
	if _, err := f.callValue(f.owner, stSelInjectRewards, 8_000_000, stqauE18(50)); err != nil {
		t.Fatalf("injectRewards: %v", err)
	}
	// bob deposits 30 → shares = 30 × 100 / 150 = 20
	f.mustDeposit(t, f.bob, stqauE18(30))
	if got := f.stqauBal(t, f.bob); got.Cmp(stqauE18(20)) != 0 {
		t.Fatalf("bob stQAU = %s, want 20e18", got)
	}
	// total supply 120, total backing 180 → rate stays 1.5
	if got := f.rate(t); got.Cmp(big.NewInt(15e17)) != 0 {
		t.Fatalf("rate = %s, want 1.5e18", got)
	}
}

// ============ deposit: zero-value gate ============

func TestR123StqauDepositZeroRejected(t *testing.T) {
	f := newStqauFixture(t)
	if _, err := f.callValue(f.alice, stSelDeposit, 8_000_000, big.NewInt(0)); err == nil {
		t.Fatal("deposit 0 should revert")
	}
}

// ============ withdraw: locked-rate queueing ============

func TestR123StqauWithdrawQueue(t *testing.T) {
	f := newStqauFixture(t)
	f.mustDeposit(t, f.alice, stqauE18(100))
	// inject 100 reward → rate 2.0; alice queues everything
	if _, err := f.callValue(f.owner, stSelInjectRewards, 8_000_000, stqauE18(100)); err != nil {
		t.Fatalf("inject: %v", err)
	}
	shares := f.stqauBal(t, f.alice) // 100e18
	// owed = shares × rate / 1e18 = 100 × 2 = 200 QAU
	if _, err := f.call(f.alice, stqauWithdrawInput(shares), 8_000_000); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	// shares already burned
	if got := f.stqauBal(t, f.alice); got.Sign() != 0 {
		t.Fatalf("alice stQAU after withdraw = %s, want 0", got)
	}
	// after queueing: backing goes to zero (the 200 belongs to the queued withdrawer and no longer counts toward holders' rate basis)
	//   — this is exactly the D4 honest-accounting semantics: exchangeRate answers to the still-held shares without silently shifting or inflating
	if got := f.backing(t); got.Sign() != 0 {
		t.Fatalf("backing after queue = %s, want 0 (queued 200e18 excluded)", got)
	}
	// rewards injected after queueing do not change owed: +60 → the queued withdrawer still gets 200
	if _, err := f.callValue(f.owner, stSelInjectRewards, 8_000_000, stqauE18(60)); err != nil {
		t.Fatalf("inject2: %v", err)
	}
	// withdrawalOf query: owed=200e18, unlock=1000+151200
	in := append(append([]byte{}, stSelWithdrawalOf...), padAddressWord(f.alice)...)
	out, err := f.call(f.alice, in, 200_000)
	if err != nil {
		t.Fatalf("withdrawalOf: %v", err)
	}
	if len(out) != 96 {
		t.Fatalf("withdrawalOf len = %d, want 96", len(out))
	}
	owed := new(big.Int).SetBytes(out[0:32])
	unlock := new(big.Int).SetBytes(out[32:64])
	qShares := new(big.Int).SetBytes(out[64:96])
	if owed.Cmp(stqauE18(200)) != 0 {
		t.Fatalf("owed = %s, want 200e18 (rate locked at queue time)", owed)
	}
	wantUnlock := big.NewInt(1_000 + stqauUnbondBlocks)
	if unlock.Cmp(wantUnlock) != 0 {
		t.Fatalf("unlock = %s, want %s", unlock, wantUnlock)
	}

	if qShares.Cmp(shares) != 0 {
		t.Fatalf("queued shares = %s, want %s", qShares, shares)
	}
}

// ============ claimWithdrawal: rejects before maturity ============

func TestR123StqauClaimBeforeUnlockRejected(t *testing.T) {
	f := newStqauFixture(t)
	f.mustDeposit(t, f.alice, stqauE18(10))
	if _, err := f.call(f.alice, stqauWithdrawInput(stqauE18(10)), 8_000_000); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	// ctx still at block 1000, unlock at 152200 → reject
	if _, err := f.call(f.alice, stSelClaimWithdrawal, 8_000_000); err == nil {
		t.Fatal("claim before unlock should revert")
	}
}

// ============ claimWithdrawal: pays out at maturity ============

func TestR123StqauClaimAfterUnlock(t *testing.T) {
	f := newStqauFixture(t)
	f.mustDeposit(t, f.alice, stqauE18(100))
	if _, err := f.callValue(f.owner, stSelInjectRewards, 8_000_000, stqauE18(100)); err != nil {
		t.Fatalf("inject: %v", err)
	}
	aliceNativeBefore := f.nativeBal(f.alice)
	if _, err := f.call(f.alice, stqauWithdrawInput(stqauE18(100)), 8_000_000); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	// fast-forward time: block height passes unlock
	f.ctx.BlockNumber = 1_000 + stqauUnbondBlocks + 1
	if _, err := f.call(f.alice, stSelClaimWithdrawal, 8_000_000); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// alice receives 200 (rate locked; later injections have no effect)
	delta := new(big.Int).Sub(f.nativeBal(f.alice), aliceNativeBefore)
	if delta.Cmp(stqauE18(200)) != 0 {
		t.Fatalf("claim delta = %s, want 200e18", delta)
	}
	// queue drained
	in := append(append([]byte{}, stSelWithdrawalOf...), padAddressWord(f.alice)...)
	out, err := f.call(f.alice, in, 200_000)
	if err != nil {
		t.Fatalf("withdrawalOf: %v", err)
	}

	if got := new(big.Int).SetBytes(out[0:32]); got.Sign() != 0 {
		t.Fatalf("owed after claim = %s, want 0", got)
	}
}

// ============ extractForStaking: owner gate + accounting ============

func TestR123StqauExtractForStaking(t *testing.T) {
	f := newStqauFixture(t)
	f.mustDeposit(t, f.alice, stqauE18(100))
	f.mustDeposit(t, f.bob, stqauE18(100))
	// non-owner rejected
	in := append(append([]byte{}, stSelExtract...), u256(stqauE18(50))...)
	if _, err := f.call(f.alice, in, 8_000_000); err == nil {
		t.Fatal("non-owner extract should revert")
	}
	// owner extracts 50 (backing 200, no queue)
	ownerBefore := f.nativeBal(f.owner)
	if _, err := f.call(f.owner, in, 8_000_000); err != nil {
		t.Fatalf("owner extract: %v", err)
	}
	delta := new(big.Int).Sub(f.nativeBal(f.owner), ownerBefore)
	if delta.Cmp(stqauE18(50)) != 0 {
		t.Fatalf("extract delta = %s, want 50e18", delta)
	}
	// extracting more than the remaining backing is rejected (150 left)
	in2 := append(append([]byte{}, stSelExtract...), u256(stqauE18(151))...)
	if _, err := f.call(f.owner, in2, 8_000_000); err == nil {
		t.Fatal("over-extract should revert")
	}
}

// ============ paused gate ============

func TestR123StqauPauseDeposits(t *testing.T) {
	f := newStqauFixture(t)
	// non-owner cannot pause
	if _, err := f.call(f.alice, stSelPauseDeposits, 200_000); err == nil {
		t.Fatal("non-owner pause should revert")
	}
	if _, err := f.call(f.owner, stSelPauseDeposits, 200_000); err != nil {
		t.Fatalf("pause: %v", err)
	}
	// while paused, deposit/withdraw are rejected
	if _, err := f.callValue(f.alice, stSelDeposit, 8_000_000, stqauE18(1)); err == nil {
		t.Fatal("deposit while paused should revert")
	}
	// unpause restores both
	if _, err := f.call(f.owner, stSelUnpauseDeposits, 200_000); err != nil {
		t.Fatalf("unpause: %v", err)
	}
	f.mustDeposit(t, f.alice, stqauE18(1))
}

// ============ ERC20: transfer (same semantics as wqau) ============

func TestR123StqauTransfer(t *testing.T) {
	f := newStqauFixture(t)
	f.mustDeposit(t, f.alice, stqauE18(100))
	// alice → bob 40
	in := append(append([]byte{}, stSelTransfer...), padAddressWord(f.bob)...)
	in = append(in, u256(stqauE18(40))...)
	if _, err := f.call(f.alice, in, 1_000_000); err != nil {
		t.Fatalf("transfer: %v", err)
	}
	if got := f.stqauBal(t, f.bob); got.Cmp(stqauE18(40)) != 0 {
		t.Fatalf("bob = %s, want 40e18", got)
	}
	if got := f.stqauBal(t, f.alice); got.Cmp(stqauE18(60)) != 0 {
		t.Fatalf("alice = %s, want 60e18", got)
	}
	// over-transfer rejected
	in2 := append(append([]byte{}, stSelTransfer...), padAddressWord(f.bob)...)
	in2 = append(in2, u256(stqauE18(61))...)
	if _, err := f.call(f.alice, in2, 1_000_000); err == nil {
		t.Fatal("over-transfer should revert")
	}
}

// ============ conservation: full deposit/withdraw/claim/inject cycle ============

func TestR123StqauConservationFullCycle(t *testing.T) {
	f := newStqauFixture(t)
	// three users deposit different amounts
	f.mustDeposit(t, f.alice, stqauE18(300))
	f.mustDeposit(t, f.bob, stqauE18(200))
	// 100 reward
	if _, err := f.callValue(f.owner, stSelInjectRewards, 8_000_000, stqauE18(100)); err != nil {
		t.Fatalf("inject: %v", err)
	}
	// owner extracts 50 for staking
	in := append(append([]byte{}, stSelExtract...), u256(stqauE18(50))...)
	if _, err := f.call(f.owner, in, 8_000_000); err != nil {
		t.Fatalf("extract: %v", err)
	}
	// alice queues her full exit
	aliceShares := f.stqauBal(t, f.alice)
	aliceOwedExpected := new(big.Int).Mul(aliceShares, f.rate(t))
	aliceOwedExpected.Div(aliceOwedExpected, big.NewInt(1e18))
	aliceBefore := f.nativeBal(f.alice)
	if _, err := f.call(f.alice, stqauWithdrawInput(aliceShares), 8_000_000); err != nil {
		t.Fatalf("alice withdraw: %v", err)
	}
	// another 30 injected (after alice queued — does not affect her owed)
	if _, err := f.callValue(f.owner, stSelInjectRewards, 8_000_000, stqauE18(30)); err != nil {
		t.Fatalf("inject2: %v", err)
	}
	// claim at maturity
	f.ctx.BlockNumber = 1_000 + stqauUnbondBlocks + 1
	if _, err := f.call(f.alice, stSelClaimWithdrawal, 8_000_000); err != nil {
		t.Fatalf("claim: %v", err)
	}
	aliceDelta := new(big.Int).Sub(f.nativeBal(f.alice), aliceBefore)
	if aliceDelta.Cmp(aliceOwedExpected) != 0 {
		t.Fatalf("alice claim = %s, want rate-locked owed %s", aliceDelta, aliceOwedExpected)
	}
	// conservation: contractBalance = total deposits − extract − claimed; queued = bob's share + 0
	//    initial: 300+200+100 −50 +30 − aliceClaim
	//    alice shares = 300 (first mint), owed = 300×1.2 = 360
	wantBal := new(big.Int).Add(stqauE18(300), stqauE18(200))
	wantBal.Add(wantBal, stqauE18(100))
	wantBal.Sub(wantBal, stqauE18(50))
	wantBal.Add(wantBal, stqauE18(30))
	wantBal.Sub(wantBal, aliceOwedExpected)
	if got := f.db.GetBalance(f.st); got.Cmp(wantBal) != 0 {
		t.Fatalf("contract balance = %s, want %s (conserved)", got, wantBal)
	}
}

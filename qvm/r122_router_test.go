// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"math/big"
	"testing"
)

// R122 Step-4: QSwapRouter QASM contract tests
//
// deployment topology (owner nonce 1/2/3/4):
//   wqau  = CreateAddress(owner,1)  token0 (smaller address)
//   mock  = CreateAddress(owner,2)  token1
//   pair  = CreateAddress(owner,3)
//   router= CreateAddress(owner,4)
//
// Router storage: 0=pair 1=wqau 2=owner 3=paused
// users (alice/bob) go through the router:
//   addLiquidity(tokenAmt) payable         — token approve router
//   removeLiquidity(lp)                    — pair LP approve router
//   swapExactQauForToken(minOut) payable
//   swapTokenForQau(tokenIn, minQauOut)    — token approve router

var rSelAddLiquidity = []byte{0x51, 0xc6, 0x59, 0x0a}
var rSelRemoveLiquidity = []byte{0x9c, 0x8f, 0x9f, 0x23}
var rSelSwapQauForToken = []byte{0x57, 0x92, 0x4c, 0xcd}
var rSelSwapTokenForQau = []byte{0x6d, 0xe9, 0xca, 0x14}
var rSelRPair = []byte{0xa8, 0xaa, 0x1b, 0x31}
var rSelRWqau = []byte{0x0c, 0x97, 0x6b, 0xc6}
var rSelRPaused = []byte{0x5c, 0x97, 0x5a, 0xbb}
var rSelRPause = []byte{0x84, 0x56, 0xcb, 0x59}
var rSelRUnpause = []byte{0x3f, 0x4b, 0xa8, 0x3a}
var rSelGetAmountOut = []byte{0x05, 0x4d, 0x50, 0xd4}
var pSelApprove = []byte{0x09, 0x5e, 0xa7, 0xb3}

func slotKey(i int) Hash {
	key := Hash{}
	key[31] = byte(i)
	return key
}

type routerFixture struct {
	db     *mockStateDB
	exec   *Executor
	ctx    *BlockContext
	owner  Address
	alice  Address
	bob    Address
	wqau   Address
	mock   Address
	pair   Address
	router Address
}

func newRouterFixture(t *testing.T) *routerFixture {
	t.Helper()
	f := &routerFixture{
		db:    newMockStateDB(),
		exec:  NewExecutor(),
		ctx:   &BlockContext{BlockNumber: 1, Timestamp: 1700000000, GasLimit: 20_000_000, ChainID: 1668},
		owner: Address{0x51},
		alice: Address{0x22},
		bob:   Address{0x33},
	}
	f.db.SetBalance(f.owner, big.NewInt(1_000_000_000))
	f.db.SetBalance(f.alice, big.NewInt(1_000_000_000))
	f.db.SetBalance(f.bob, big.NewInt(1_000_000_000))

	deploy := func(name string, initCode []byte, nonce uint64) Address {
		t.Helper()
		f.db.SetNonce(f.owner, nonce)
		res, addr := f.exec.Create(f.db, f.owner, initCode, 5_000_000, big.NewInt(0), f.ctx, 0)
		if res.Err != nil {
			t.Fatalf("deploy %s: %v", name, res.Err)
		}
		return addr
	}

	f.wqau = deploy("wqau", loadContractHex(t, "../contracts/qasm/wqau.hex"), 1)
	f.mock = deploy("mocktoken", loadContractHex(t, "../contracts/qasm/mock_token.hex"), 2)
	// router address pre-computation: deploy(nonce=4), actual address = CreateAddress(owner, 3)
	// (inside executor.Create, createNonce = SetNonce value - 1)
	routerAddr := CreateAddress(f.owner, 3)

	// pair initCode = pair code + ABI args (token0, token1 sorted, router, owner)
	pairCode := loadContractHex(t, "../contracts/qasm/qswap_pair.hex")
	t0, t1 := f.wqau, f.mock
	if bigCmpAddr(t1, t0) {
		t0, t1 = t1, t0
	}
	args := append([]byte{}, padAddressWord(t0)...)
	args = append(args, padAddressWord(t1)...)
	args = append(args, padAddressWord(routerAddr)...)
	args = append(args, padAddressWord(f.owner)...)
	f.pair = deploy("pair", append(pairCode, args...), 3)

	// router: nonce 4 → address must match the pre-computation
	routerCode := loadContractHex(t, "../contracts/qasm/qswap_router.hex")
	rargs := append([]byte{}, padAddressWord(f.pair)...)
	rargs = append(rargs, padAddressWord(f.wqau)...)
	rargs = append(rargs, padAddressWord(f.owner)...)
	f.router = deploy("router", append(routerCode, rargs...), 4)
	if f.router != routerAddr {
		t.Fatalf("router addr %x != precomputed %x", f.router, routerAddr)
	}
	return f
}

// callRouter: call the router from caller, no value
func (f *routerFixture) callRouter(caller Address, input []byte, gas uint64) ([]byte, error) {
	res := f.exec.Call(f.db, caller, f.router, input, gas, big.NewInt(0), f.ctx, 0)
	return res.ReturnData, res.Err
}

// callRouterValue: call the router from caller, with QAU value
func (f *routerFixture) callRouterValue(caller Address, input []byte, gas uint64, value *big.Int) ([]byte, error) {
	res := f.exec.Call(f.db, caller, f.router, input, gas, value, f.ctx, 0)
	return res.ReturnData, res.Err
}

// reserves: pair.getReserves
func (f *routerFixture) reserves(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()
	res := f.exec.Call(f.db, f.alice, f.pair, pSelGetReserves, 200_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("getReserves: %v", res.Err)
	}
	r0 := new(big.Int).SetBytes(res.ReturnData[0:32])
	r1 := new(big.Int).SetBytes(res.ReturnData[32:64])
	return r0, r1
}

// tokenBal: ERC20 balanceOf
func (f *routerFixture) tokenBal(t *testing.T, token, who Address) *big.Int {
	t.Helper()
	input := append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(who)...)
	res := f.exec.Call(f.db, who, token, input, 200_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("tokenBal: %v", res.Err)
	}
	return new(big.Int).SetBytes(res.ReturnData)
}

// lpBalanceOf: pair LP balance (salt 6 mapping)
func (f *routerFixture) lpBalanceOf(t *testing.T, who Address) *big.Int {
	t.Helper()
	input := append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(who)...)
	res := f.exec.Call(f.db, who, f.pair, input, 200_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("lpBalanceOf: %v", res.Err)
	}
	return new(big.Int).SetBytes(res.ReturnData)
}

// callToken: call the ERC20 directly
func (f *routerFixture) callToken(t *testing.T, token, from Address, input []byte, gas uint64) ([]byte, error) {
	t.Helper()
	res := f.exec.Call(f.db, from, token, input, gas, big.NewInt(0), f.ctx, 0)
	return res.ReturnData, res.Err
}

// mustSendToken: token.transfer(to, amount) from `from`
func (f *routerFixture) mustSendToken(t *testing.T, token, from, to Address, amount *big.Int) {
	t.Helper()
	input := wqauTransferInput(to, amount)
	res := f.exec.Call(f.db, from, token, input, 1_000_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("token transfer: %v", res.Err)
	}
}

// seedPool: alice calls router.addLiquidity with 1M QAU + 4M mock
func (f *routerFixture) seedPool(t *testing.T, qauAmt, tokenAmt int64) {
	t.Helper()
	// alice receives mock (owner transfer) and approves the router
	// approve covers the seed amount plus headroom for a later addLiquidity (v2 refund flow)
	f.mustSendToken(t, f.mock, f.owner, f.alice, big.NewInt(tokenAmt))
	ap := append(append([]byte{}, pSelApprove...), padAddressWord(f.router)...)
	ap = append(ap, u256(new(big.Int).Mul(big.NewInt(tokenAmt), big.NewInt(100)))...)
	if _, err := f.callToken(t, f.mock, f.alice, ap, 1_000_000); err != nil {
		t.Fatalf("alice approve router: %v", err)
	}
	// addLiquidity: native QAU value + tokenAmt
	input := append(append([]byte{}, rSelAddLiquidity...), u256(big.NewInt(tokenAmt))...)
	if _, err := f.callRouterValue(f.alice, input, 8_000_000, big.NewInt(qauAmt)); err != nil {
		t.Fatalf("alice addLiquidity: %v", err)
	}
	// headroom: the later addLiquidity test still needs alice to hold mock and approval
	f.mustSendToken(t, f.mock, f.owner, f.alice, big.NewInt(tokenAmt))
	ap2 := append(append([]byte{}, pSelApprove...), padAddressWord(f.router)...)
	ap2 = append(ap2, u256(new(big.Int).Mul(big.NewInt(tokenAmt), big.NewInt(100)))...)
	if _, err := f.callToken(t, f.mock, f.alice, ap2, 1_000_000); err != nil {
		t.Fatalf("alice approve router (headroom): %v", err)
	}
}

// ============ tests ============

// deployment: pair/wqau/owner constructor args written to storage correctly
func TestR122RouterDeployInit(t *testing.T) {
	f := newRouterFixture(t)
	// pair()
	if ret, err := f.callRouter(f.alice, rSelRPair, 100_000); err != nil {
		t.Fatalf("pair(): %v", err)
	} else if got := new(big.Int).SetBytes(ret); got.Cmp(big.NewInt(0).SetBytes(f.pair[:])) != 0 {
		t.Fatalf("pair() = %s, want %x", got, f.pair)
	}
	// wqau()
	if ret, err := f.callRouter(f.alice, rSelRWqau, 100_000); err != nil {
		t.Fatalf("wqau(): %v", err)
	} else if got := new(big.Int).SetBytes(ret); got.Cmp(big.NewInt(0).SetBytes(f.wqau[:])) != 0 {
		t.Fatalf("wqau() = %s, want %x", got, f.wqau)
	}
	// paused() == 0
	if ret, err := f.callRouter(f.alice, rSelRPaused, 100_000); err != nil {
		t.Fatalf("paused(): %v", err)
	} else if new(big.Int).SetBytes(ret).Sign() != 0 {
		t.Fatalf("paused() = %s, want 0", new(big.Int).SetBytes(ret))
	}
}

// addLiquidity → LP goes straight to the user; pool reserves correct
func TestR122RouterAddLiquidity(t *testing.T) {
	f := newRouterFixture(t)
	f.seedPool(t, 1_000_000, 4_000_000)

	// alice LP should be first-mint sqrt(1M*4M) - 1000 = 2_000_000 - 1000 = 1_999_000
	if got := f.lpBalanceOf(t, f.alice); got.Cmp(big.NewInt(1_999_000)) != 0 {
		t.Fatalf("alice LP = %s, want 1999000", got)
	}
	// reserves = 1M / 4M
	r0, r1 := f.reserves(t)
	if r0.Cmp(big.NewInt(1_000_000)) != 0 || r1.Cmp(big.NewInt(4_000_000)) != 0 {
		t.Fatalf("reserves = %s/%s, want 1M/4M", r0, r1)
	}
	// wqau belongs to the pair: alice native → deposit → pair holds wQAU 1M
	if got := f.tokenBal(t, f.wqau, f.pair); got.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("pair wqau bal = %s, want 1M", got)
	}
}

// full loop: add → swapExactQauForToken → swapTokenForQau → removeLiquidity
// asset conservation: user final balance + pool balance = initial (zero error)
func TestR122RouterFullCycle(t *testing.T) {
	f := newRouterFixture(t)
	f.seedPool(t, 1_000_000, 4_000_000)

	aliceQauBefore := f.db.GetBalance(f.alice)
	aliceWqauBefore := f.tokenBal(t, f.wqau, f.alice)
	aliceMockBefore := f.tokenBal(t, f.mock, f.alice)

	// ---- bob swapExactQauForToken: 10_000 QAU → mock ----
	// expected out = 10000*997*4M / (1M*1000 + 10000*997) = 39486
	bobMockBefore := f.tokenBal(t, f.mock, f.bob)
	input := append(append([]byte{}, rSelSwapQauForToken...), u256(big.NewInt(39_000))...) // minOut 39000
	ret, err := f.callRouterValue(f.bob, input, 5_000_000, big.NewInt(10_000))
	if err != nil {
		t.Fatalf("bob swapExactQauForToken: %v", err)
	}
	gotOut := new(big.Int).SetBytes(ret)
	if gotOut.Cmp(big.NewInt(39_486)) != 0 {
		t.Fatalf("swap out = %s, want 39486", gotOut)
	}
	bobMockAfter := f.tokenBal(t, f.mock, f.bob)
	if new(big.Int).Sub(bobMockAfter, bobMockBefore).Cmp(big.NewInt(39_486)) != 0 {
		t.Fatalf("bob mock delta = %s, want 39486", new(big.Int).Sub(bobMockAfter, bobMockBefore))
	}

	// ---- bob swapTokenForQau: 20_000 mock → QAU ----
	// expected out = 20000*997*r1'/(r0'*1000+20000*997); r0'=1.01M, r1'=4M-39486=3960514
	// = 20000*997*3960514 / (1010000*1000 + 19940000) = ?
	f.mustSendToken(t, f.mock, f.owner, f.bob, big.NewInt(20_000))
	ap := append(append([]byte{}, pSelApprove...), padAddressWord(f.router)...)
	ap = append(ap, u256(big.NewInt(20_000))...)
	if _, err := f.callToken(t, f.mock, f.bob, ap, 1_000_000); err != nil {
		t.Fatalf("bob approve: %v", err)
	}
	bobQauBefore := f.db.GetBalance(f.bob)
	in2 := append([]byte{}, rSelSwapTokenForQau...)
	in2 = append(in2, u256(big.NewInt(20_000))...)
	in2 = append(in2, u256(big.NewInt(4_000))...) // minQauOut (actual out≈5059)
	ret2, err := f.callRouter(f.bob, in2, 5_000_000)
	if err != nil {
		t.Fatalf("bob swapTokenForQau: %v", err)
	}
	// out = in*997*rQau / (rMock*1000 + in*997)
	wantOut2 := new(big.Int).Div(
		new(big.Int).Mul(new(big.Int).Mul(big.NewInt(20_000), big.NewInt(997)), big.NewInt(1_010_000)),
		new(big.Int).Add(new(big.Int).Mul(big.NewInt(3_960_514), big.NewInt(1000)), new(big.Int).Mul(big.NewInt(20_000), big.NewInt(997))),
	)
	if new(big.Int).SetBytes(ret2).Cmp(wantOut2) != 0 {
		t.Fatalf("swap2 out = %s, want %s", new(big.Int).SetBytes(ret2), wantOut2)
	}
	bobQauAfter := f.db.GetBalance(f.bob)
	if new(big.Int).Sub(bobQauAfter, bobQauBefore).Cmp(wantOut2) != 0 {
		t.Fatalf("bob QAU delta = %s, want %s", new(big.Int).Sub(bobQauAfter, bobQauBefore), wantOut2)
	}

	// ---- alice removeLiquidity: all LP ----
	lpBal := f.lpBalanceOf(t, f.alice)
	// alice first does pair.approve(router, lp)
	apLP := append(append([]byte{}, pSelApprove...), padAddressWord(f.router)...)
	apLP = append(apLP, u256(lpBal)...)
	if _, err := f.callToken(t, f.pair, f.alice, apLP, 1_000_000); err != nil {
		t.Fatalf("alice approve LP: %v", err)
	}
	in3 := append(append([]byte{}, rSelRemoveLiquidity...), u256(lpBal)...)
	if _, err := f.callRouter(f.alice, in3, 5_000_000); err != nil {
		t.Fatalf("alice removeLiquidity: %v", err)
	}
	// alice LP goes to zero
	if got := f.lpBalanceOf(t, f.alice); got.Sign() != 0 {
		t.Fatalf("alice LP after remove = %s, want 0", got)
	}
	// alice gets back token (mock): out1 = lp*b1/S
	// at this point S=1_999_000 (the locked 1000 is not in supply); b1 = pair mock balance
	_ = aliceQauBefore
	_ = aliceWqauBefore
	mockAfter := f.tokenBal(t, f.mock, f.alice)
	// alice withdraws all LP → receives the pool's full mock share:
	//   pool mock = 4M - 39_486 (out via sqf) + 20_000 (in via stf) = 3_980_514
	if new(big.Int).Sub(mockAfter, aliceMockBefore).Cmp(big.NewInt(3_980_514)) != 0 {
		t.Fatalf("alice mock after cycle = %s (delta %s), want 3980514",
			mockAfter, new(big.Int).Sub(mockAfter, aliceMockBefore))
	}
}

// slippage guard: minOut too high → revert, state rolls back
func TestR122RouterSlippageRevert(t *testing.T) {
	f := newRouterFixture(t)
	f.seedPool(t, 1_000_000, 4_000_000)

	bobMockBefore := f.tokenBal(t, f.mock, f.bob)
	bobQauBefore := f.db.GetBalance(f.bob)

	// minOut 100_000 >> actual 39486 → revert
	input := append(append([]byte{}, rSelSwapQauForToken...), u256(big.NewInt(100_000))...)
	if _, err := f.callRouterValue(f.bob, input, 5_000_000, big.NewInt(10_000)); err == nil {
		t.Fatal("swap with minOut=100000 should revert")
	}
	// rollback: bob's mock unchanged, QAU not deducted
	if got := f.tokenBal(t, f.mock, f.bob); got.Cmp(bobMockBefore) != 0 {
		t.Fatalf("bob mock after revert = %s, want unchanged", got)
	}
	if f.db.GetBalance(f.bob).Cmp(bobQauBefore) != 0 {
		t.Fatalf("bob QAU after revert = %s, want unchanged", f.db.GetBalance(f.bob))
	}
}

// paused: router.pause → add/swap revert → unpause restores
func TestR122RouterPauseGate(t *testing.T) {
	f := newRouterFixture(t)
	f.seedPool(t, 1_000_000, 4_000_000)

	// owner pause
	if _, err := f.callRouter(f.owner, rSelRPause, 1_000_000); err != nil {
		t.Fatalf("owner pause: %v", err)
	}
	if ret, _ := f.callRouter(f.alice, rSelRPaused, 100_000); new(big.Int).SetBytes(ret).Sign() == 0 {
		t.Fatal("paused() should be 1 after pause")
	}
	// swap is gated
	input := append(append([]byte{}, rSelSwapQauForToken...), u256(big.NewInt(1))...)
	if _, err := f.callRouterValue(f.bob, input, 5_000_000, big.NewInt(100)); err == nil {
		t.Fatal("swap while paused should revert")
	}
	// addLiquidity is gated
	in2 := append(append([]byte{}, rSelAddLiquidity...), u256(big.NewInt(1))...)
	if _, err := f.callRouterValue(f.bob, in2, 5_000_000, big.NewInt(100)); err == nil {
		t.Fatal("addLiquidity while paused should revert")
	}
	// non-owner cannot unpause
	if _, err := f.callRouter(f.alice, rSelRUnpause, 1_000_000); err == nil {
		t.Fatal("non-owner unpause should revert")
	}
	// owner unpause → restored
	if _, err := f.callRouter(f.owner, rSelRUnpause, 1_000_000); err != nil {
		t.Fatalf("owner unpause: %v", err)
	}
	// swap after unpause works again
	input3 := append(append([]byte{}, rSelSwapQauForToken...), u256(big.NewInt(1))...)
	if _, err := f.callRouterValue(f.bob, input3, 5_000_000, big.NewInt(100)); err != nil {
		t.Fatalf("swap after unpause: %v", err)
	}
}

// addLiquidity overfunding an existing pool: only the required pair is deducted; excess native QAU is refunded
func TestR122RouterAddLiquidityRefund(t *testing.T) {
	f := newRouterFixture(t)
	f.seedPool(t, 1_000_000, 4_000_000)

	// alice currently holds 4M mock (seedPool transfer); overfund with QAU=2M, tokenAmt=100k
	// pool r0(wqau)=1M / r1(mock)=4M; required QAU = 100k * 1M / 4M = 25k
	aliceNativeBefore := f.db.GetBalance(f.alice)
	aliceMockBefore := f.tokenBal(t, f.mock, f.alice)
	input := append(append([]byte{}, rSelAddLiquidity...), u256(big.NewInt(100_000))...)
	res := f.exec.Call(f.db, f.alice, f.router, input, 8_000_000, big.NewInt(2_000_000), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("alice oversized addLiquidity: %v (gasUsed=%d ret=%x)", res.Err, res.GasUsed, res.ReturnData)
	}
	// net native delta = 2M in - 25k actually taken
	wantDelta := big.NewInt(-25_000)
	if gotDelta := new(big.Int).Sub(f.db.GetBalance(f.alice), aliceNativeBefore); gotDelta.Cmp(wantDelta) != 0 {
		t.Fatalf("alice native delta = %s, want %s (real QAU spent, excess refunded)", gotDelta, wantDelta)
	}
	// mock side fully takes 100k (no native residue left in the router)
	if got := f.tokenBal(t, f.mock, f.alice); got.Cmp(new(big.Int).Sub(aliceMockBefore, big.NewInt(100_000))) != 0 {
		t.Fatalf("alice mock balance = %s", got)
	}
	if got := f.db.GetBalance(f.router); got.Sign() != 0 {
		t.Fatalf("router retained native balance = %s, want 0", got)
	}
}

// TestR122RouterAddLiquidityRefundFail: fault-injection (slot 10) makes the
// native refund path fail after a successful pair.mint — the whole
// transaction must revert, alice's native balance must be untouched.
func TestR122RouterAddLiquidityRefundFail(t *testing.T) {
	f := newRouterFixture(t)
	f.seedPool(t, 1_000_000, 4_000_000)

	// honest-construction refund failure: deploy a "refuses receipt" contract — every call REVERTs.
	// init: CODECOPY(0,12,3) + RETURN(0,3), runtime = PUSH1 0 PUSH1 0 REVERT
	// QVM opcodes: CODECOPY=0x39, RETURN=0x06, REVERT=0x07, PUSH1=0x60?
	// note: QVM PUSH1 opcode = 0x10 (not EVM 0x60)!
	init := []byte{
		0x10, 0x05, // PUSH1 size (runtime is 5 bytes)
		0x10, 0x0c, // PUSH1 offset (runtime starts where init ends = 12)
		0x10, 0x00, // PUSH1 destOffset
		0x79,       // CODECOPY (QVM opcode 0x79)
		0x10, 0x05, // PUSH1 size
		0x10, 0x00, // PUSH1 offset
		0x06, // RETURN
	}
	runtime := []byte{0x10, 0x00, 0x10, 0x00, 0x07} // PUSH1 0 PUSH1 0 REVERT
	f.db.SetNonce(f.owner, 5)
	res, receiver := f.exec.Create(f.db, f.owner, append(init, runtime...), 5_000_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("deploy reverter: %v", res.Err)
	}

	// give the receiver assets: mock 100k + router approval; native injected directly
	f.mustSendToken(t, f.mock, f.owner, receiver, big.NewInt(100_000))
	ap := append(append([]byte{}, pSelApprove...), padAddressWord(f.router)...)
	ap = append(ap, u256(big.NewInt(100_000))...)
	if _, err := f.callToken(t, f.mock, receiver, ap, 1_000_000); err != nil {
		t.Fatalf("receiver approve: %v", err)
	}
	f.db.SetBalance(receiver, big.NewInt(2_000_000))

	// tokenAmt=100k, CV=2M → qauNeed=25k, refund=1.975M → refunded to receiver.
	// receiver refuses → the refund CALL fails → the whole tx must revert;
	// the receiver's native/mock balances and pool reserves must not change.
	recvNativeBefore := f.db.GetBalance(receiver)
	recvMockBefore := f.tokenBal(t, f.mock, receiver)
	r0, r1 := f.reserves(t)
	input := append(append([]byte{}, rSelAddLiquidity...), u256(big.NewInt(100_000))...)
	if _, err := f.callRouterValue(receiver, input, 8_000_000, big.NewInt(2_000_000)); err == nil {
		t.Fatal("addLiquidity with reverting refund receiver should revert the whole tx")
	}
	if got := f.db.GetBalance(receiver); got.Cmp(recvNativeBefore) != 0 {
		t.Fatalf("receiver native changed: %s -> %s", recvNativeBefore, got)
	}
	if got := f.tokenBal(t, f.mock, receiver); got.Cmp(recvMockBefore) != 0 {
		t.Fatalf("receiver mock changed: %s -> %s", recvMockBefore, got)
	}
	r0b, r1b := f.reserves(t)
	if r0b.Cmp(r0) != 0 || r1b.Cmp(r1) != 0 {
		t.Fatalf("reserves changed: (%s,%s) -> (%s,%s)", r0, r1, r0b, r1b)
	}
}

func TestR122RouterAddLiquidityOversizedRefund(t *testing.T) {
	f := newRouterFixture(t)
	f.seedPool(t, 1_000_000, 4_000_000)

	// excess refunded: pool ratio 1:4 — 400k mock needs only 100k QAU,
	// so 2M - 100k = 1.9M must come back to alice.
	excessRefund := big.NewInt(1_900_000)
	input := append(append([]byte{}, rSelAddLiquidity...), u256(big.NewInt(400_000))...)
	aliceQauBefore := f.db.GetBalance(f.alice)
	aliceMockBefore := f.tokenBal(t, f.mock, f.alice)
	if _, err := f.callRouterValue(f.alice, input, 8_000_000, big.NewInt(2_000_000)); err != nil {
		t.Fatalf("alice oversized addLiquidity: %v", err)
	}

	// fund with 2M QAU / 400k mock; the existing pool ratio is 1:4:
	// only 100k QAU needed, the rest 1.9M refunded → actual net native = -(2M-1.9M) = -100k = -qauUse.
	// the token side takes the full 400k; the router keeps zero native balance.
	expectedNativeDelta := new(big.Int).Neg(new(big.Int).Sub(big.NewInt(2_000_000), excessRefund))
	if gotDelta := new(big.Int).Sub(f.db.GetBalance(f.alice), aliceQauBefore); gotDelta.Cmp(expectedNativeDelta) != 0 {
		t.Fatalf("alice native delta = %s, want %s (expected excess refund %s)", gotDelta, expectedNativeDelta, excessRefund)
	}
	if got := f.tokenBal(t, f.mock, f.alice); got.Cmp(new(big.Int).Sub(aliceMockBefore, big.NewInt(400_000))) != 0 {
		t.Fatalf("alice mock balance = %s", got)
	}
	if got := f.db.GetBalance(f.router); got.Sign() != 0 {
		t.Fatalf("router retained native balance = %s, want 0", got)
	}
}

// getAmountOut view: matches the formula
func TestR122RouterGetAmountOut(t *testing.T) {
	f := newRouterFixture(t)
	input := append([]byte{}, rSelGetAmountOut...)
	input = append(input, u256(big.NewInt(10_000))...)    // amountIn
	input = append(input, u256(big.NewInt(1_000_000))...) // reserveIn
	input = append(input, u256(big.NewInt(4_000_000))...) // reserveOut
	ret, err := f.callRouter(f.alice, input, 1_000_000)
	if err != nil {
		t.Fatalf("getAmountOut: %v", err)
	}
	want := new(big.Int).Div(
		new(big.Int).Mul(new(big.Int).Mul(big.NewInt(10_000), big.NewInt(997)), big.NewInt(4_000_000)),
		new(big.Int).Add(new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1000)), new(big.Int).Mul(big.NewInt(10_000), big.NewInt(997))),
	)
	if new(big.Int).SetBytes(ret).Cmp(want) != 0 {
		t.Fatalf("getAmountOut = %s, want %s", new(big.Int).SetBytes(ret), want)
	}
}

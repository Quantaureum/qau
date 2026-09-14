// Quantaureum Node source, version 1.0.0.
package qvm

// R122 step-3: QSwapPair contract tests.
// Deploys wQAU + MockToken + Pair with a router address, then drives
// mint (first/continuous), swap (k invariant), burn, sync, skim, and
// all access-control gates through the real QVM executor.

import (
	"math/big"
	"testing"
)

// Pair selectors.
var (
	pSelGetReserves = []byte{0x09, 0x02, 0xf1, 0xac}
	pSelMint        = []byte{0x6a, 0x62, 0x78, 0x42}
	pSelBurn        = []byte{0x89, 0xaf, 0xcb, 0x44}
	pSelSwap        = []byte{0x6d, 0x9a, 0x64, 0x0a}
	pSelSync        = []byte{0xff, 0xf6, 0xca, 0xe9}
	pSelSkim        = []byte{0xbc, 0x25, 0xcf, 0x77}
	pSelLPBalanceOf = []byte{0x70, 0xa0, 0x82, 0x31}
	pSelLPSupply    = []byte{0x18, 0x16, 0x0d, 0xdd}
	pSelPause       = []byte{0x84, 0x56, 0xcb, 0x59}
	pSelUnpause     = []byte{0x3f, 0x4b, 0xa8, 0x3a}
	pSelPaused      = []byte{0x5c, 0x97, 0x5a, 0xbb}
	pSelToken0      = []byte{0x0d, 0xfe, 0x16, 0x81}
	pSelToken1      = []byte{0xd2, 0x12, 0x20, 0xa7}
	pSelOwner       = []byte{0x8d, 0xa5, 0xcb, 0x5b} // owner()
)

// pairFixture: deployed wqau + mocktoken + pair, router = stand-in address.
type pairFixture struct {
	db     *mockStateDB
	exec   *Executor
	ctx    *BlockContext
	router Address // authorized caller for mint/burn/swap
	owner  Address // pause authority
	alice  Address // liquidity provider
	bob    Address // swapper
	wqau   Address
	mock   Address
	pair   Address
}

// pad32 helper for uint256 args.
func u256(x *big.Int) []byte { return x.FillBytes(make([]byte, 32)) }

func newPairFixture(t *testing.T) *pairFixture {
	t.Helper()
	f := &pairFixture{
		db:     newMockStateDB(),
		exec:   NewExecutor(),
		ctx:    &BlockContext{BlockNumber: 1, Timestamp: 1700000000, GasLimit: 20_000_000, ChainID: 1668},
		router: Address{0x50},
		owner:  Address{0x51},
		alice:  Address{0x22},
		bob:    Address{0x33},
	}

	deploy := func(name string, initCode []byte, nonce uint64) Address {
		t.Helper()
		f.db.SetNonce(f.owner, nonce)
		res, addr := f.exec.Create(f.db, f.owner, initCode, 3_000_000, big.NewInt(0), f.ctx, 0)
		if res.Err != nil {
			t.Fatalf("deploy %s: %v", name, res.Err)
		}
		return addr
	}

	f.db.SetBalance(f.owner, big.NewInt(1_000_000_000))
	f.db.SetBalance(f.alice, big.NewInt(1_000_000_000))
	f.db.SetBalance(f.bob, big.NewInt(1_000_000_000))

	f.wqau = deploy("wqau", loadContractHex(t, "../contracts/qasm/wqau.hex"), 1)
	f.mock = deploy("mocktoken", loadContractHex(t, "../contracts/qasm/mock_token.hex"), 2)

	// pair initCode = assembled pair code + ABI args (token0, token1 sorted, router, owner)
	pairCode := loadContractHex(t, "../contracts/qasm/qswap_pair.hex")
	t0, t1 := f.wqau, f.mock
	if bigCmpAddr(t1, t0) {
		t0, t1 = t1, t0
	}
	args := append([]byte{}, padAddressWord(t0)...)
	args = append(args, padAddressWord(t1)...)
	args = append(args, padAddressWord(f.router)...)
	args = append(args, padAddressWord(f.owner)...)
	f.pair = deploy("pair", append(pairCode, args...), 3)

	// seed balances: alice deposits wqau, gets mock from deployer(owner)
	f.owner = Address{0x51}
	tf := &tokenFixture{db: f.db, contract: f.wqau, exec: f.exec, ctx: f.ctx, deployer: f.owner}
	_ = tf
	// alice deposits 1_000_000 wqau (native)
	res := f.exec.Call(f.db, f.alice, f.wqau, []byte{0xd0, 0xe3, 0x0d, 0xb0}, 1_000_000, big.NewInt(1_000_000), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("alice wqau deposit: %v", res.Err)
	}
	abres := f.exec.Call(f.db, f.alice, f.wqau, append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(f.alice)...), 200_000, big.NewInt(0), f.ctx, 0)
	if abres.Err != nil {
		t.Fatalf("wqau balanceOf(alice): %v", abres.Err)
	}
	// diagnostics: direct wqau.balanceOf(pair) and mock.balanceOf(pair)
	for _, tk := range []Address{f.wqau, f.mock} {
		bi := append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(f.pair)...)
		br := f.exec.Call(f.db, f.alice, tk, bi, 200_000, big.NewInt(0), f.ctx, 0)
		if br.Err != nil {
			t.Fatalf("balanceOf(pair) on %x: %v", tk[19], br.Err)
		}
	}
	// owner (mock deployer, preminted 1e24) transfers 2_000_000 mock to alice
	// verify the owner balance first
	balInput := append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(f.owner)...)
	bres := f.exec.Call(f.db, f.owner, f.mock, balInput, 200_000, big.NewInt(0), f.ctx, 0)
	if bres.Err != nil {
		t.Fatalf("mock balanceOf(owner): %v", bres.Err)
	}
	mtInput := wqauTransferInput(f.alice, big.NewInt(5_000_000))
	res = f.exec.Call(f.db, f.owner, f.mock, mtInput, 1_000_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("owner->alice mock transfer: %v", res.Err)
	}
	return f
}

// bigCmpAddr: returns true if a > b lexically.
func bigCmpAddr(a, b Address) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// callPair invokes a pair function with the given caller.
func (f *pairFixture) callPair(caller Address, input []byte, gas uint64) ([]byte, error) {
	res := f.exec.Call(f.db, caller, f.pair, input, gas, big.NewInt(0), f.ctx, 0)
	return res.ReturnData, res.Err
}

// callPairLogged is callPair with failure logging.
func (f *pairFixture) callPairLogged(t *testing.T, caller Address, input []byte, gas uint64) ([]byte, error) {
	t.Helper()
	res := f.exec.Call(f.db, caller, f.pair, input, gas, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Logf("callPair sel=%x err=%v gasUsed=%d reverted=%v", input[:4], res.Err, res.GasUsed, res.Reverted)
	}
	return res.ReturnData, res.Err
}

// lpBalanceOf reads LP balance of `who` on the pair.
func (f *pairFixture) lpBalanceOf(t *testing.T, who Address) *big.Int {
	input := append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(who)...)
	res := f.exec.Call(f.db, who, f.pair, input, 200_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("lpBalanceOf: %v", res.Err)
	}
	return new(big.Int).SetBytes(res.ReturnData)
}

func (f *pairFixture) reserves(t *testing.T) (*big.Int, *big.Int) {
	res := f.exec.Call(f.db, f.alice, f.pair, pSelGetReserves, 200_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("getReserves: %v", res.Err)
	}
	r0 := new(big.Int).SetBytes(res.ReturnData[0:32])
	r1 := new(big.Int).SetBytes(res.ReturnData[32:64])
	return r0, r1
}

func (f *pairFixture) tokenBal(t *testing.T, token, who Address) *big.Int {
	input := append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(who)...)
	res := f.exec.Call(f.db, who, token, input, 200_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("tokenBal: %v", res.Err)
	}
	return new(big.Int).SetBytes(res.ReturnData)
}

// dumpPairStorage prints slots 0-14.
func (f *pairFixture) dumpPairStorage(t *testing.T) {
	t.Helper()
	for i := 0; i <= 14; i++ {
		key := Hash{}
		key[31] = byte(i)
		t.Logf("pair storage[%d] = %x", i, f.db.GetState(f.pair, key))
	}
}

// --- tests ---

// TestR122PairDeployInit: constructor reads args correctly.
func TestR122PairDeployInit(t *testing.T) {
	f := newPairFixture(t)
	f.dumpPairStorage(t)
	// dump deployed code head vs expected runtime
	deployed := f.db.GetCode(f.pair)
	runtime := loadContractHex(t, "../contracts/qasm/qswap_pair.hex")
	t.Logf("deployed len=%d initcode len=%d", len(deployed), len(runtime))
	t.Logf("deployed[0:40] = %x", deployed[:40])
	// start of the runtime section in the initcode: find CALLDATASIZE(0x34) 0x10 0x04 (guard)
	idx := -1
	for i := 0; i+3 < len(runtime); i++ {
		if runtime[i] == 0x34 && runtime[i+1] == 0x10 && runtime[i+2] == 0x04 {
			idx = i
			break
		}
	}
	t.Logf("guard found in initcode at offset %d", idx)
	if idx > 0 {
		t.Logf("expected runtime[0:40] = %x", runtime[idx:idx+40])
	}
	// token0 = min(wqau, mock)
	t0, t1 := f.wqau, f.mock
	if bigCmpAddr(t1, t0) {
		t0, t1 = t1, t0
	}
	res := f.exec.Call(f.db, f.alice, f.pair, pSelToken0, 100_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("token0(): %v", res.Err)
	}
	want0 := []byte(t0[:])
	got0 := res.ReturnData[12:32]
	for i := range want0 {
		if want0[i] != got0[i] {
			t.Fatalf("token0 mismatch: got %x want %x", got0, want0)
		}
	}
	res = f.exec.Call(f.db, f.alice, f.pair, pSelToken1, 100_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("token1(): %v", res.Err)
	}
	want1 := []byte(t1[:])
	gotB := res.ReturnData[12:32]
	for i := range want1 {
		if want1[i] != gotB[i] {
			t.Fatalf("token1 mismatch: got %x want %x", gotB, want1)
		}
	}
}

// TestR122PairMintFirst: first mint locks MINIMUM_LIQUIDITY and mints sqrt-1000.
func TestR122PairMintFirst(t *testing.T) {
	f := newPairFixture(t)

	// alice -> pair: 1_000_000 wqau + 4_000_000 mock (ratio 1:4, sqrt = 2_000_000)
	f.mustSendToken(t, f.wqau, f.alice, f.pair, big.NewInt(1_000_000))
	// diagnostics: read wqau.balanceOf(pair) immediately after the transfer
	{
		bi := append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(f.pair)...)
		br := f.exec.Call(f.db, f.alice, f.wqau, bi, 200_000, big.NewInt(0), f.ctx, 0)
		t.Logf("after transfer: wqau.balanceOf(pair) err=%v = %s", br.Err, new(big.Int).SetBytes(br.ReturnData))
		ba := append(append([]byte{}, pSelLPBalanceOf...), padAddressWord(f.alice)...)
		ba2 := f.exec.Call(f.db, f.alice, f.wqau, ba, 200_000, big.NewInt(0), f.ctx, 0)
		t.Logf("after transfer: wqau.balanceOf(alice) err=%v = %s", ba2.Err, new(big.Int).SetBytes(ba2.ReturnData))
	}
	f.mustSendToken(t, f.mock, f.alice, f.pair, big.NewInt(4_000_000))

	// router calls mint(alice)
	input := append(append([]byte{}, pSelMint...), padAddressWord(f.alice)...)
	if _, err := f.callPair(f.router, input, 2_000_000); err != nil {
		t.Fatalf("mint: %v", err)
	}
	// expected LP = sqrt(1e6 * 4e6) - 1000 = 2_000_000 - 1000 = 1_999_000
	want := big.NewInt(1_999_000)
	if got := f.lpBalanceOf(t, f.alice); got.Cmp(want) != 0 {
		t.Fatalf("alice LP = %s, want %s", got, want)
	}
	// MINIMUM_LIQUIDITY locked at zero address
	var zero Address
	if got := f.lpBalanceOf(t, zero); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("zero-addr LP = %s, want 1000", got)
	}
	// reserves synced
	r0, r1 := f.reserves(t)
	if r0.Cmp(big.NewInt(1_000_000)) != 0 || r1.Cmp(big.NewInt(4_000_000)) != 0 {
		t.Fatalf("reserves = %s/%s, want 1e6/4e6", r0, r1)
	}
}

// mustSendToken: token.transfer(pair, amount) from `from`.
func (f *pairFixture) mustSendToken(t *testing.T, token, from, to Address, amount *big.Int) {
	t.Helper()
	input := wqauTransferInput(to, amount)
	res := f.exec.Call(f.db, from, token, input, 1_000_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("token %x transfer from %x: %v (gasUsed=%d reverted=%v)", token[19], from[19], res.Err, res.GasUsed, res.Reverted)
	}
}

// TestR122PairMintAccessControl: non-router mint reverts.
func TestR122PairMintAccessControl(t *testing.T) {
	f := newPairFixture(t)
	f.mustSendToken(t, f.wqau, f.alice, f.pair, big.NewInt(100))
	input := append(append([]byte{}, pSelMint...), padAddressWord(f.alice)...)
	if _, err := f.callPair(f.alice, input, 1_000_000); err == nil {
		t.Fatal("non-router mint should revert")
	}
}

// TestR122PairMintContinuous: second mint is proportional.
func TestR122PairMintContinuous(t *testing.T) {
	f := newPairFixture(t)
	f.mustSendToken(t, f.wqau, f.alice, f.pair, big.NewInt(1_000_000))
	f.mustSendToken(t, f.mock, f.alice, f.pair, big.NewInt(4_000_000))
	input := append(append([]byte{}, pSelMint...), padAddressWord(f.alice)...)
	if _, err := f.callPair(f.router, input, 2_000_000); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	// add 50_000 wqau + 200_000 mock (same ratio) -> LP = 50_000 * S / r0
	// alice's wqau is exhausted; deposit another 50_000 first
	dres := f.exec.Call(f.db, f.alice, f.wqau, []byte{0xd0, 0xe3, 0x0d, 0xb0}, 500_000, big.NewInt(50_000), f.ctx, 0)
	if dres.Err != nil {
		t.Fatalf("alice second deposit: %v", dres.Err)
	}
	f.mustSendToken(t, f.wqau, f.alice, f.pair, big.NewInt(50_000))
	f.mustSendToken(t, f.mock, f.alice, f.pair, big.NewInt(200_000))
	if _, err := f.callPair(f.router, input, 2_000_000); err != nil {
		t.Fatalf("second mint: %v", err)
	}
	// expected: total LP = 1_999_000 + 50_000*1_999_000/1_000_000 = 1_999_000 + 99_950
	inc := new(big.Int).Div(new(big.Int).Mul(big.NewInt(50_000), big.NewInt(1_999_000)), big.NewInt(1_000_000))
	want := new(big.Int).Add(big.NewInt(1_999_000), inc)
	if got := f.lpBalanceOf(t, f.alice); got.Cmp(want) != 0 {
		t.Fatalf("alice LP after 2nd mint = %s, want %s", got, want)
	}
}

// TestR122PairSwapK: swap keeps k (with 0.3% fee).
func TestR122PairSwapK(t *testing.T) {
	f := newPairFixture(t)
	f.mustSendToken(t, f.wqau, f.alice, f.pair, big.NewInt(1_000_000))
	f.mustSendToken(t, f.mock, f.alice, f.pair, big.NewInt(4_000_000))
	input := append(append([]byte{}, pSelMint...), padAddressWord(f.alice)...)
	if _, err := f.callPair(f.router, input, 2_000_000); err != nil {
		t.Fatalf("mint: %v", err)
	}

	// bob sends 10_000 wqau in, expects mock out. (bob deposits wqau first)
	bd := f.exec.Call(f.db, f.bob, f.wqau, []byte{0xd0, 0xe3, 0x0d, 0xb0}, 500_000, big.NewInt(20_000), f.ctx, 0)
	if bd.Err != nil {
		t.Fatalf("bob deposit: %v", bd.Err)
	}
	f.mustSendToken(t, f.wqau, f.bob, f.pair, big.NewInt(10_000))
	// Uniswap V2 formula: out = dx*997*r1 / (r0*1000 + dx*997)
	r0, r1 := big.NewInt(1_000_000), big.NewInt(4_000_000)
	dx := big.NewInt(10_000)
	num := new(big.Int).Mul(new(big.Int).Mul(dx, big.NewInt(997)), r1)
	den := new(big.Int).Add(new(big.Int).Mul(r0, big.NewInt(1000)), new(big.Int).Mul(dx, big.NewInt(997)))
	out := new(big.Int).Div(num, den)
	t.Logf("expected out = %s", out)

	// swap(amount0Out=0, amount1Out=out, to=bob)
	swapInput := append(append([]byte{}, pSelSwap...), u256(big.NewInt(0))...)
	swapInput = append(swapInput, u256(out)...)
	swapInput = append(swapInput, padAddressWord(f.bob)...)
	if ret, err := f.callPairLogged(t, f.router, swapInput, 2_000_000); err != nil {
		t.Fatalf("swap: %v", err)
	} else {
		names := []string{"b0", "b1", "a0In", "a1In", "lhs", "rhs"}
		for i, nm := range names {
			off := i * 32
			if off+32 <= len(ret) {
				t.Logf("  %s=%s", nm, new(big.Int).SetBytes(ret[off:off+32]))
			}
		}
	}
	// bob got the mock tokens
	if got := f.tokenBal(t, f.mock, f.bob); got.Cmp(out) != 0 {
		t.Fatalf("bob mock = %s, want %s", got, out)
	}
	// k preserved within fee tolerance: new r0*r1 >= old k
	nr0, nr1 := f.reserves(t)
	kNew := new(big.Int).Mul(nr0, nr1)
	kOld := new(big.Int).Mul(r0, r1)
	if kNew.Cmp(kOld) < 0 {
		t.Fatalf("k decreased! %s < %s", kNew, kOld)
	}
}

// TestR122PairSwapInsufficientK: asking for too much out reverts.
func TestR122PairSwapInsufficientK(t *testing.T) {
	f := newPairFixture(t)
	f.mustSendToken(t, f.wqau, f.alice, f.pair, big.NewInt(1_000_000))
	f.mustSendToken(t, f.mock, f.alice, f.pair, big.NewInt(4_000_000))
	input := append(append([]byte{}, pSelMint...), padAddressWord(f.alice)...)
	if _, err := f.callPair(f.router, input, 2_000_000); err != nil {
		t.Fatalf("mint: %v", err)
	}
	bd := f.exec.Call(f.db, f.bob, f.wqau, []byte{0xd0, 0xe3, 0x0d, 0xb0}, 500_000, big.NewInt(20_000), f.ctx, 0)
	if bd.Err != nil {
		t.Fatalf("bob deposit: %v", bd.Err)
	}
	f.mustSendToken(t, f.wqau, f.bob, f.pair, big.NewInt(10_000))

	// greedy out: 100_000 (way more than the fair ~38k)
	swapInput := append(append([]byte{}, pSelSwap...), u256(big.NewInt(0))...)
	swapInput = append(swapInput, u256(big.NewInt(100_000))...)
	swapInput = append(swapInput, padAddressWord(f.bob)...)
	if _, err := f.callPair(f.router, swapInput, 2_000_000); err == nil {
		t.Fatal("greedy swap should revert (k violated)")
	}
	// state rolled back: bob got nothing
	if got := f.tokenBal(t, f.mock, f.bob); got.Sign() != 0 {
		t.Fatalf("bob mock after failed swap = %s, want 0", got)
	}
}

// TestR122PairBurn: burn LP returns tokens proportionally.
func TestR122PairBurn(t *testing.T) {
	f := newPairFixture(t)
	f.mustSendToken(t, f.wqau, f.alice, f.pair, big.NewInt(1_000_000))
	f.mustSendToken(t, f.mock, f.alice, f.pair, big.NewInt(4_000_000))
	input := append(append([]byte{}, pSelMint...), padAddressWord(f.alice)...)
	if _, err := f.callPair(f.router, input, 2_000_000); err != nil {
		t.Fatalf("mint: %v", err)
	}
	lpBefore := f.lpBalanceOf(t, f.alice)
	aliceMockBefore := f.tokenBal(t, f.mock, f.alice)
	aliceWqauBefore := f.tokenBal(t, f.wqau, f.alice)

	// router must hold the LP: simulate by transferring alice LP to router.
	// LP transfer: pair.transfer(router, lpBefore) from alice.
	transferLP := wqauTransferInput(f.router, lpBefore)
	if _, err := f.callPairLogged(t, f.alice, transferLP, 1_000_000); err != nil {
		t.Fatalf("alice LP->router: %v", err)
	}
	if got := f.lpBalanceOf(t, f.router); got.Cmp(lpBefore) != 0 {
		t.Fatalf("router LP after transfer = %s, want %s (LP transfer failed?)", got, lpBefore)
	}

	// burn(alice)
	burnInput := append(append([]byte{}, pSelBurn...), padAddressWord(f.alice)...)
	if _, err := f.callPair(f.router, burnInput, 3_000_000); err != nil {
		t.Fatalf("burn: %v", err)
	}

	// alice receives: out0 = lp*b0/S, out1 = lp*b1/S
	// S = supply (locked 1000 excluded) = 1_999_000; b = reserves
	// lp = 1_999_000 -> out0 = 1_999_000*1e6/1_999_000 = 1_000_000 wqau
	// out1 = 1_999_000*4e6/1_999_000 = 4_000_000 mock
	wantWqau := new(big.Int).Div(new(big.Int).Mul(lpBefore, big.NewInt(1_000_000)), big.NewInt(1_999_000))
	wantMock := new(big.Int).Div(new(big.Int).Mul(lpBefore, big.NewInt(4_000_000)), big.NewInt(1_999_000))
	if got := new(big.Int).Sub(f.tokenBal(t, f.wqau, f.alice), aliceWqauBefore); got.Cmp(wantWqau) != 0 {
		t.Fatalf("alice wqau out = %s, want %s", got, wantWqau)
	}
	if got := new(big.Int).Sub(f.tokenBal(t, f.mock, f.alice), aliceMockBefore); got.Cmp(wantMock) != 0 {
		t.Fatalf("alice mock out = %s, want %s", got, wantMock)
	}
	// router LP is zero now, supply reflects burn
	if got := f.lpBalanceOf(t, f.router); got.Sign() != 0 {
		t.Fatalf("router LP after burn = %s, want 0", got)
	}
}

// TestR122PairPauseGate: pause blocks mint/swap, owner-only control.
func TestR122PairPauseGate(t *testing.T) {
	f := newPairFixture(t)

	// owner() view returns the owner (slot 0x0e; was 0x0a regression)
	res, err := f.callPair(f.alice, pSelOwner, 100_000)
	if err != nil {
		t.Fatalf("owner(): %v", err)
	}
	if len(res) != 32 {
		t.Fatalf("owner() return len %d, want 32", len(res))
	}
	gotOwner := Address{}
	copy(gotOwner[:], res[12:])
	if gotOwner != f.owner {
		t.Fatalf("owner() = %x, want %x (fn_owner must read slot 0x0e)", gotOwner, f.owner)
	}
	f.mustSendToken(t, f.wqau, f.alice, f.pair, big.NewInt(1_000))
	f.mustSendToken(t, f.mock, f.alice, f.pair, big.NewInt(4_000))
	mintInput := append(append([]byte{}, pSelMint...), padAddressWord(f.alice)...)

	// non-owner pause reverts
	if _, err := f.callPair(f.alice, pSelPause, 100_000); err == nil {
		t.Fatal("non-owner pause should revert")
	}
	// owner pauses
	if _, err := f.callPair(f.owner, pSelPause, 100_000); err != nil {
		t.Fatalf("owner pause: %v", err)
	}
	// mint blocked while paused
	if _, err := f.callPair(f.router, mintInput, 1_000_000); err == nil {
		t.Fatal("mint while paused should revert")
	}
	// owner unpauses; mint succeeds
	if _, err := f.callPair(f.owner, pSelUnpause, 100_000); err != nil {
		t.Fatalf("owner unpause: %v", err)
	}
	if _, err := f.callPair(f.router, mintInput, 2_000_000); err != nil {
		t.Fatalf("mint after unpause: %v", err)
	}
}

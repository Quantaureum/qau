// Quantaureum Node source, version 1.0.0.
package qvm

// R123 security-audit regression tests (2026-09-07 pre-mainnet audit found three vulnerabilities + regression locks for their fixes)
//
//   SEC-1  CRITICAL  claimWithdrawal CEI violation: originally the CALL payout preceded state cleanup,
//                    so a contract receiver could re-enter claim inside its receive callback and double-pay (QVM only applies
//                    an economic reentry penalty + MaxReentriesPerAddress=10; it does not block). Fix:
//                    CEI reorder — clear queuedOwed/Shares/Unlock + totalQueued first,
//                    then the native CALL. Regression lock: actually run a reentrancy proxy contract through it.
//   SEC-2  HIGH      deposit did not reject zero shares → ERC4626 inflation attack: attacker
//                    first-mints 1 wei + injects a huge reward to pump the rate; the victim's deposit
//                    yields 0 shares — QAU gifted to the pool. Fix: shares==0 → revert.
//   SEC-3  MEDIUM    withdraw with owed=0: shares already burned, queued owed=0 never claimable,
//                    shares locked forever. Fix: owed==0 → revert.

import (
	"math/big"
	"os"
	"strings"
	"testing"
)

const r123AttackerPlaceholder = "0000000000000000000000000000000000001234"

// loadAttackerInitcode reads the pre-assembled template and substitutes the placeholder address with the real stqau address.
func loadAttackerInitcode(t *testing.T, stqau Address) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/r123_attacker.init.hex")
	if err != nil {
		t.Fatalf("read attacker initcode: %v", err)
	}
	h := strings.TrimSpace(string(raw))
	h = strings.TrimPrefix(h, "0x")
	addrHex := ""
	for _, b := range stqau {
		const hexd = "0123456789abcdef"
		addrHex += string(hexd[b>>4]) + string(hexd[b&0x0f])
	}
	if strings.Count(h, r123AttackerPlaceholder) != 1 {
		t.Fatalf("attacker template placeholder count != 1")
	}
	h = strings.Replace(h, r123AttackerPlaceholder, addrHex, 1)
	out := make([]byte, len(h)/2)
	for i := 0; i+1 < len(h); i += 2 {
		out[i/2] = (hexNibble(h[i]) << 4) | hexNibble(h[i+1])
	}
	return out
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// deployAttacker deploys the attacker contract via the fixture's Executor.
func deployAttacker(t *testing.T, f *stqauFixture) Address {
	t.Helper()
	code := loadAttackerInitcode(t, f.st)
	f.db.SetNonce(f.owner, 2) // stqau deployment consumed nonce=1; next slot
	res, addr := f.exec.Create(f.db, f.owner, code, 5_000_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("deploy attacker: %v", res.Err)
	}
	return addr
}

// callAny: the fixture calls any contract address directly (the EOA → attacker → stqau entry)
func (f *stqauFixture) callAny(caller, target Address, input []byte, value *big.Int) ([]byte, error) {
	res := f.exec.Call(f.db, caller, target, input, 5_000_000, value, f.ctx, 0)
	return res.ReturnData, res.Err
}

// callAnyDbg with diagnostics (SEC internal debugging)
func (f *stqauFixture) callAnyDbg(caller, target Address, input []byte, value *big.Int) ([]byte, *ExecutionResult, error) {
	res := f.exec.Call(f.db, caller, target, input, 5_000_000, value, f.ctx, 0)
	return res.ReturnData, res, res.Err
}

// ---------------------------------------------------------------------------
// SEC-2: rate-inflation attack — the victim's deposit must revert; no funds lost
// ---------------------------------------------------------------------------
func TestR123Sec2DepositZeroSharesReverts(t *testing.T) {
	f := newStqauFixture(t)
	attacker := Address{0xAA}
	victim := Address{0xBB}
	f.db.SetBalance(attacker, new(big.Int).Mul(big.NewInt(2_000_000), stqauE18(1)))
	f.db.SetBalance(victim, stqauE18(1_000))

	// 1) attacker first-mints 1 wei at 1:1
	if _, err := f.callValue(attacker, stSelDeposit, 8_000_000, big.NewInt(1)); err != nil {
		t.Fatalf("attacker dust deposit: %v", err)
	}
	// 2) attacker injects a huge amount to pump the rate
	inject := new(big.Int).Mul(big.NewInt(1_000_000), stqauE18(1))
	if _, err := f.callValue(attacker, stSelInjectRewards, 8_000_000, inject); err != nil {
		t.Fatalf("attacker inject: %v", err)
	}
	// 3) victim deposits 10 QAU: shares = 10e18×1/(1+1e24) → 0 → must revert
	if _, err := f.callValue(victim, stSelDeposit, 8_000_000, stqauE18(10)); err == nil {
		t.Fatal("R123-SEC-2 BREACH: zero-share deposit accepted — inflation attack live")
	}
	// 4) the victim's native balance should only decrease by gas (well under 1 QAU)
	lost := new(big.Int).Sub(stqauE18(1_000), f.db.GetBalance(victim))
	if lost.Cmp(stqauE18(1)) > 0 {
		t.Fatalf("victim lost %s wei (>1 QAU) — inflation attack stole funds", lost)
	}
}

// ---------------------------------------------------------------------------
// SEC-3: dust withdraw (owed=0) must revert, preventing permanently locked shares
// construct backing < supply (owner extract pulls backing down) → withdraw(1) → owed=0
// ---------------------------------------------------------------------------
func TestR123Sec3WithdrawDustOwedReverts(t *testing.T) {
	f := newStqauFixture(t)
	alice := f.alice

	// alice deposits 100 QAU → 100 shares
	f.mustDeposit(t, alice, stqauE18(100))
	// owner extracts 50 QAU → backing < supply (rate becomes 0.5)
	extIn := append(append([]byte{}, stSelExtract...), u256(stqauE18(50))...)
	if _, err := f.call(f.owner, extIn, 8_000_000); err != nil {
		t.Fatalf("owner extract: %v", err)
	}
	// withdraw(1 wei shares): owed = 1×backing/supply = 0 → revert
	wd := stqauWithdrawInput(big.NewInt(1))
	if _, err := f.call(alice, wd, 8_000_000); err == nil {
		t.Fatal("R123-SEC-3 BREACH: dust-withdraw accepted — shares burned + queue locked forever")
	}
	// a normal withdraw(1 share) should succeed (owed ≈ 0.5 QAU)
	if _, err := f.call(alice, stqauWithdrawInput(stqauE18(1)), 8_000_000); err != nil {
		t.Fatalf("normal withdraw should still work after SEC-3 guard: %v", err)
	}
	// queue active: owed ≈ 0.5 QAU
	owed0, _, _ := f.queueOf(t, alice)
	if owed0.Sign() <= 0 {
		t.Fatalf("normal withdraw should queue owed>0, got 0")
	}
}

// ---------------------------------------------------------------------------
// SEC-1: claim reentrancy — after the fix the attacker's net gain must equal owed exactly
// ---------------------------------------------------------------------------
func TestR123Sec1ClaimReentrancyBlocked(t *testing.T) {
	f := newStqauFixture(t)
	attacker := deployAttacker(t, f)
	t.Logf("attacker deployed at %x", attacker[:6])

	alice := f.alice
	bob := f.bob

	// alice deposit 10 QAU → 10 shares
	f.mustDeposit(t, alice, stqauE18(10))
	// bob deposits 500 QAU → the pool now holds extra funds worth stealing
	f.mustDeposit(t, bob, stqauE18(500))

	// alice transfers 1 share → the attacker contract
	trx := append(append([]byte{}, stSelTransfer...), padAddressWord(attacker)...)
	trx = append(trx, u256(stqauE18(1))...)
	if _, err := f.call(alice, trx, 8_000_000); err != nil {
		t.Fatalf("alice → attacker share transfer: %v", err)
	}
	if got := f.stqauBal(t, attacker); got.Cmp(stqauE18(1)) != 0 {
		t.Fatalf("attacker shares: got %s want 1e18", got)
	}

	// EOA (alice) calls stqau.withdraw(1 share) on behalf of the attacker contract: the attacker contract passes it through
	wd := stqauWithdrawInput(stqauE18(1))
	{
		out, res, err := f.callAnyDbg(alice, attacker, wd, big.NewInt(0))
		t.Logf("attacker-proxy withdraw: out=%d B, resErr=%v err=%v gasUsed=%d",
			len(out), res.Err, err, res.GasUsed)
	}
	// queued: attacker contract owed = 1 QAU (rate 1.0, no injections), unlock = head+151200
	owedA, _, _ := f.queueOf(t, attacker)
	if owedA.Cmp(stqauE18(1)) != 0 {
		t.Fatalf("attacker queue owed: got %s want 1e18", owedA)
	}

	// fast-forward 21 days to unlock
	f.ctx.BlockNumber += 151_201

	// the stqau contract's current native balance ≈ 510 QAU (517?); record it
	balBefore := f.db.GetBalance(f.st)
	attackBalBefore := f.db.GetBalance(attacker)

	// EOA (alice) initiates claim on behalf of the attacker contract → stqau.CALL sends owed to the attacker contract
	// → the attacker contract's receive → immediately re-enters stqau.claim (must revert)
	if _, err := f.callAny(alice, attacker, append([]byte{}, stSelClaimWithdrawal...), big.NewInt(0)); err != nil {
		t.Fatalf("attacker claim via proxy: %v", err)
	}

	attackGain := new(big.Int).Sub(f.db.GetBalance(attacker), attackBalBefore)
	stLoss := new(big.Int).Sub(balBefore, f.db.GetBalance(f.st))
	t.Logf("attacker gained %s wei (owed=%s); stqau loss=%s", attackGain, stqauE18(1), stLoss)

	// fixed semantics: attacker net gain == owed, contract loss == owed (never a wei more)
	if attackGain.Cmp(stqauE18(1)) != 0 {
		t.Fatalf("R123-SEC-1: attacker gained %s, expected exactly owed=%s (reentrancy!)", attackGain, stqauE18(1))
	}
	if stLoss.Cmp(stqauE18(1)) != 0 {
		t.Fatalf("R123-SEC-1: stqau lost %s, expected exactly owed=%s (pool drained!)", stLoss, stqauE18(1))
	}
	// the attacker's queue is drained — another claim must revert (complete defense)
	if _, err := f.callAny(alice, attacker, append([]byte{}, stSelClaimWithdrawal...), big.NewInt(0)); err == nil {
		t.Fatalf("R123-SEC-1: re-claim after payout did not revert — queue not cleared")
	}
}

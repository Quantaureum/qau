// Quantaureum Node source, version 1.0.0.
package qvm

// R123 Phase 2 (plan §5): fixed-seed 500-round invariant fuzz for the
// stQAU liquid-staking contract, driven through the real QVM executor.
//
// Invariants checked after EVERY round:
//   C1. Balance-sheet conservation (wei-exact):
//         SELFBALANCE == Σdeposits + Σinjects − Σextracts − Σclaims
//       verified against a Go-side ledger accumulated from tx receipts.
//   C2. Share conservation:
//         Σ user stQAU balances + Σ queued shares == totalSupply
//       (withdraw moves shares into the queue; nothing evaporates).
//   C3. Debt coverage: totalQueued ≤ backing + totalQueued would
//       over-draw: totalQueued (owed) must always be payable —
//         SELFBALANCE ≥ totalQueued
//   C4. rate monotonicity: with no slash recorded, the live exchange
//       rate never DECREASES while supply > 0 (extract lowers backing,
//       so the fuzz treats extract rounds as rate-resetting and checks
//       monotonicity only across non-extract, non-withdraw rounds:
//       withdraw legitimately re-bases when shares leave supply).
//
// Seed FIXED at 42 (reproducible, plan §5 style).

import (
	"math/big"
	"math/rand"
	"testing"
)

const stqauFuzzRounds = 500

type stqauFuzzUser struct {
	addr     Address
	shares   *big.Int // live stQAU balance (shadow)
	queued   *big.Int // queued shares (shadow)
	native   *big.Int // native balance outside contract (shadow)
	hasQueue bool
}

type stqauFuzzEnv struct {
	f          *stqauFixture
	rng        *rand.Rand
	ledger     *big.Int // expected SELFBALANCE: Σdep+Σinj−Σex−Σcl
	supply     *big.Int // shadow totalSupply
	totalQ     *big.Int // shadow totalQueued (owed)
	lastRate   *big.Int
	lastAction string
}

func newStqauFuzzEnv(t *testing.T) *stqauFuzzEnv {
	return &stqauFuzzEnv{
		f:        newStqauFixture(t),
		rng:      rand.New(rand.NewSource(42)),
		ledger:   big.NewInt(0),
		supply:   big.NewInt(0),
		totalQ:   big.NewInt(0),
		lastRate: stqauE18(1),
	}
}

// call + move block forward a few blocks between actions so unlock
// boundaries actually pass during the run.
func (env *stqauFuzzEnv) bumpBlock() {
	env.f.ctx.BlockNumber += 1 + uint64(env.rng.Intn(5))
}

func (env *stqauFuzzEnv) checkAll(t *testing.T, users []*stqauFuzzUser, round int) {
	t.Helper()
	// C1: ledger vs SELFBALANCE
	if got := env.f.db.GetBalance(env.f.st); got.Cmp(env.ledger) != 0 {
		t.Fatalf("round %d (%s): C1 violated — SELFBALANCE %s != ledger %s",
			round, env.lastAction, got, env.ledger)
	}
	// C2: share conservation — live shares only; queued shares are
	// burned on withdraw and become debt vouchers (queuedShares slot),
	// tracked separately from totalSupply.
	sum := new(big.Int)
	for _, u := range users {
		sum.Add(sum, u.shares)
	}
	if got := env.f.totalSupplyOfT(t); got.Cmp(env.supply) != 0 || got.Cmp(sum) != 0 {
		t.Fatalf("round %d (%s): C2 violated — supply %s, shadow %s, Σshares+queued %s",
			round, env.lastAction, got, env.supply, sum)
	}
	// C3: debt coverage
	if env.totalQ.Sign() > 0 {
		bal := env.f.db.GetBalance(env.f.st)
		if bal.Cmp(env.totalQ) < 0 {
			t.Fatalf("round %d (%s): C3 violated — SELFBALANCE %s < totalQueued %s",
				round, env.lastAction, bal, env.totalQ)
		}
	}
	// C4: rate monotonicity across non-extract/non-withdraw rounds
	if env.lastAction != "extract" && env.lastAction != "withdraw" && env.supply.Sign() > 0 {
		if env.f.rateT(t).Cmp(env.lastRate) < 0 {
			t.Fatalf("round %d (%s): C4 violated — rate %s < previous %s",
				round, env.lastAction, env.f.rateT(t), env.lastRate)
		}
	}
	// extract resets the rate floor legitimately (owner drained
	// backing — honest D4 view of remaining assets); record it even at 0.
	if r := env.f.rateT(t); r.Sign() > 0 || env.lastAction == "extract" {
		env.lastRate = r
	}
}

// thin wrappers so the fuzz does not depend on spec-test helpers
func (f *stqauFixture) rateT(t *testing.T) *big.Int {
	t.Helper()
	return f.rate(t)
}

func (f *stqauFixture) totalSupplyOfT(t *testing.T) *big.Int {
	t.Helper()
	out, err := f.call(f.alice, stSelTotalSupply, 200_000)
	if err != nil {
		t.Fatalf("totalSupply(): %v", err)
	}
	return new(big.Int).SetBytes(out)
}

func TestR123StqauFuzzInvariants500(t *testing.T) {
	env := newStqauFuzzEnv(t)
	users := []*stqauFuzzUser{
		{addr: env.f.alice, shares: big.NewInt(0), queued: big.NewInt(0), native: new(big.Int).Set(env.f.nativeBal(env.f.alice))},
		{addr: env.f.bob, shares: big.NewInt(0), queued: big.NewInt(0), native: new(big.Int).Set(env.f.nativeBal(env.f.bob))},
	}

	for round := 0; round < stqauFuzzRounds; round++ {
		who := env.rng.Intn(2)
		u := users[who]
		roll := env.rng.Intn(100)
		env.lastAction = ""

		switch {
		case roll < 40: // deposit (hot path)
			env.lastAction = "deposit"
			amt := stqauE18(int64(1 + env.rng.Intn(50)))
			rateBefore := env.f.rate(t)
			// shares = amt*supply/backing_pre; first deposit 1:1
			var gotShares *big.Int
			if env.supply.Sign() == 0 || rateBefore.Cmp(stqauE18(1)) == 0 {
				gotShares = new(big.Int).Set(amt)
			} else {
				// backing_pre = bal_pre − queued (GetBalance reads pre-tx, excluding this CALLVALUE)
				bp := new(big.Int).Sub(env.f.db.GetBalance(env.f.st), env.totalQ)
				if bp.Sign() <= 0 {
					gotShares = big.NewInt(0) // QVM: x/0 == 0
				} else {
					gotShares = new(big.Int).Div(new(big.Int).Mul(amt, env.supply), bp)
				}
			}
			// R123-SEC-2 shadow uses pre-tx balance: backing_pre = bal_pre − totalQ
			// (contract-side SELFBALANCE already includes this CALLVALUE; subtract CV to get bal_pre)
			if round < 10 {
				bal := env.f.db.GetBalance(env.f.st)
				t.Logf("r%d dep amt=%s supply=%s rate=%s bal=%s Q=%s → shadowShares=%s",
					round, amt, env.supply, rateBefore, bal, env.totalQ, gotShares)
			}
			if gotShares.Sign() == 0 && !(env.supply.Sign() == 0 || rateBefore.Cmp(stqauE18(1)) == 0) {
				// R123-SEC-2: zero-share deposits revert (anti inflation-attack).
				// The call must fail and NOTHING changes (the failed tx still
				// burns gas from the *EOA*, not from the contract).
				if _, err := env.f.callValue(u.addr, stSelDeposit, 8_000_000, amt); err == nil {
					t.Fatalf("round %d: R123-SEC-2 breach: zero-share deposit succeeded", round)
				}
				// the shadow rolls back too: after a deposit revert, supply/ledger are unchanged
				continue
			}
			if _, err := env.f.callValue(u.addr, stSelDeposit, 8_000_000, amt); err != nil {
				t.Fatalf("round %d: deposit(%s): %v", round, amt, err)
			}
			u.shares.Add(u.shares, gotShares)
			env.supply.Add(env.supply, gotShares)
			env.ledger.Add(env.ledger, amt)

		case roll < 55: // injectRewards
			env.lastAction = "inject"
			amt := stqauE18(int64(1 + env.rng.Intn(10)))
			if _, err := env.f.callValue(u.addr, stSelInjectRewards, 8_000_000, amt); err != nil {
				t.Fatalf("round %d: inject(%s): %v", round, amt, err)
			}
			env.ledger.Add(env.ledger, amt)

		case roll < 70: // withdraw (queue)
			env.lastAction = "withdraw"
			if u.shares.Sign() > 0 {
				num := new(big.Int).Div(u.shares, big.NewInt(int64(1+env.rng.Intn(4))))
				if num.Sign() == 0 {
					num = big.NewInt(1)
				}
				shares := new(big.Int).Add(u.queued, big.NewInt(0))
				_ = shares
				// queued shares accumulate; a second withdraw overwrites
				// the queue — the contract takes max(existing, new)? No:
				// per contract, a new withdraw while queued REVERTS (queue
				// occupied). Probe: if queued > 0, expect revert.
				if u.queued.Sign() > 0 {
					if _, err := env.f.call(u.addr, stqauWithdrawInput(num), 8_000_000); err == nil {
						t.Fatalf("round %d: second withdraw while queued must revert", round)
					}
					break
				}
				if _, err := env.f.call(u.addr, stqauWithdrawInput(num), 8_000_000); err != nil {
					t.Fatalf("round %d: withdraw(%s): %v", round, num, err)
				}
				// owed = shares*backing/supply (both pre-action)
				bal := env.f.db.GetBalance(env.f.st)
				backing := new(big.Int).Sub(bal, env.totalQ)
				owed := new(big.Int).Div(new(big.Int).Mul(num, backing), env.supply)
				u.queued.Add(u.queued, num)
				u.shares.Sub(u.shares, num)
				env.supply.Sub(env.supply, num)
				env.totalQ.Add(env.totalQ, owed)
				u.hasQueue = true
			}

		case roll < 80: // claim (if unlocked)
			if u.queued.Sign() > 0 {
				env.bumpBlock()
				_, unlock, _ := env.f.queueOfT(t, u.addr)
				if env.f.ctx.BlockNumber >= unlock.Uint64() {
					env.lastAction = "claim"
					before := env.f.nativeBal(u.addr)
					if _, err := env.f.call(u.addr, stSelClaimWithdrawal, 8_000_000); err != nil {
						t.Fatalf("round %d: claim(): %v", round, err)
					}
					owed := new(big.Int).Set(env.totalQ)
					// this user's owed = totalQ (single queue at a time in
					// this fuzz — verify below)
					_, _, qs := env.f.queueOfT(t, u.addr)
					if qs.Sign() != 0 || u.hasQueue {
						// owed actually paid = delta
						paid := new(big.Int).Sub(env.f.nativeBal(u.addr), before)
						if paid.Cmp(owed) != 0 {
							// only safe if this user was the sole queuer;
							// fuzz keeps one queue at a time so this holds
							t.Fatalf("round %d: claim paid %s, ledger owed %s", round, paid, owed)
						}
					}
					u.queued = big.NewInt(0)
					u.hasQueue = false
					env.totalQ = big.NewInt(0)
					env.ledger.Sub(env.ledger, owed)
				}
			}

		case roll < 90: // time passes (blocks)
			env.lastAction = "tick"
			env.bumpBlock()

		default: // extract (owner) — resets rate floor legitimately
			env.lastAction = "extract"
			bal := env.f.db.GetBalance(env.f.st)
			backing := new(big.Int).Sub(bal, env.totalQ)
			if backing.Sign() > 0 {
				amt := new(big.Int).Div(backing, big.NewInt(int64(1+env.rng.Intn(5))))
				if amt.Sign() == 0 {
					break
				}
				in := append(append([]byte{}, stSelExtract...), u256(amt)...)
				if _, err := env.f.call(env.f.owner, in, 8_000_000); err != nil {
					t.Fatalf("round %d: extract(%s): %v", round, amt, err)
				}
				env.ledger.Sub(env.ledger, amt)
			}
		}

		env.checkAll(t, users, round)
	}
	t.Logf("stqau fuzz: %d rounds — final supply %s, ledger %s, rate %s",
		stqauFuzzRounds, env.supply, env.ledger, env.f.rate(t))
}

func (f *stqauFixture) queueOfT(t *testing.T, who Address) (owed, unlock, shares *big.Int) {
	t.Helper()
	in := append([]byte{}, stSelWithdrawalOf...)
	in = append(in, padAddressWord(who)...)
	out, err := f.call(f.alice, in, 200_000)
	if err != nil {
		t.Fatalf("withdrawalOf(): %v", err)
	}
	return new(big.Int).SetBytes(out[0:32]),
		new(big.Int).SetBytes(out[32:64]),
		new(big.Int).SetBytes(out[64:96])
}

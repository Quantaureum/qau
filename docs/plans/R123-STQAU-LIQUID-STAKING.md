# R123 — stQAU staking receipt (QASM on-chain liquid staking + the first QSwap pool asset)

| Field | Content ||
---|---||
| **Status** | ✅ Done (2026-09-07: Phases 0-4 all complete; mainnet deployment awaits Plan B per the runbook) ||
| **Owner** | Core-team delivery (fund-trust design; v1 does not open the main contract to community claims; fuzz tooling and the CLI are claimable) ||
| **Priority** | High (missing first QSwap pool asset + the whitepaper's liquid-staking promise) ||
| **Target** | Pure mainnet contract deployment (no node binary changes, zero consensus changes) ||
| **Prerequisite** | R122 (the QSwap suite + a fully verified QASM stack) ||
| **Docs** | [R121-DELEGATION-LIQUID-STAKING.md](R121-DELEGATION-LIQUID-STAKING.md), [R122-QSWAP-QASM-AMM.md](R122-QSWAP-QASM-AMM.md), [TOKEN_ECONOMICS_CN.md §4](../TOKEN_ECONOMICS_CN.md) ||

---

## 0. Executive Summary

Implement **stQAU**: an on-chain liquid staking receipt wrapped in a QASM contract. Users deposit QAU into the contract and receive stQAU
(ERC20, 18 decimals, its rate rising as rewards are injected); the operator batches the pooled principal into consensus-layer staking to earn
epoch rewards, periodically injecting proceeds back into the contract to raise the rate; stQAU can be traded on QSwap at any time or redeemed via a queue.

**Why it is R123** (answering the prior question, namely the second asset for the first QSwap pool):

1. **There is no second ERC20 on mainnet.** The QSwap runbook had a pending item: "the first pool's second token is decided".
   A wQAU/QAU pool is the same asset (swapping with yourself) and economically meaningless; external bridged assets (BTC/ETH/stablecoins) depend on
   activating L1Bridge on mainnet — "planned" in the whitepaper, a distant hope that solves nothing near-term.
2. **Staking liquidity is a real need**: consensus staking (from 32 QAU via `qau_stake`) has a 21-day unbonding period
   (151,200 blocks @12s) and stakers have no mid-course exit. stQAU is the chain's first asset with **genuine user demand**
   driving volume — not a manufactured need.
3. **The economic loop closes**: mainnet currently has 6 validators with 36,000 QAU staked at 42.43% APY
   (`go run ./cmd/econsim table -preset live`, the EM-2 formula) — the stQAU rate has a real source of growth.

**Deliverables:**
1. `contracts/qasm/stqau.qasm` + `.hex` — the staking receipt contract (~2KB; gas budgets in §5)
2. `qvm/` unit tests (table-driven, 60+ cases) + 500 rounds of fuzz (conservation reconciliation)
3. Local 6-node e2e: deposit -> reward injection -> withdraw queue -> claim -> **QSwap stQAU/wQAU first-pool creation + swap**
4. The stQAU section of the mainnet runbook (including the operator SOP)

**Estimated effort**: 9-10 working days (one person), in 5 phases, with the half-day Phase 0 smoke test first.

### 0.1 Relationship to R121 (boundary split)

R121 plans **node-layer** delegation (modifying `economics/liquid_staking.go` + new RPCs + consensus hooks,
~21 days of work, touching node code). This plan, R123, is **pure contract-layer** liquid staking — zero node changes, zero consensus risk,
directly reusing the R122-verified QASM stack. The two plans do not conflict:

| | R121 (delegation) | R123 (stQAU, this document) ||
---|---||---|
| Layer | node Go code | on-chain QASM contract ||
| Fund entry | `qau_stake` RPC extension | the stQAU contract's deposit ||
| Receipt | in-memory ledger (never in blocks) | on-chain ERC20 (listable on QSwap) ||
| Consensus risk | yes (reward hooks) | none ||
| Status | 📋 Planning, awaiting a claimant | 📋 Planning, this document ||

### 0.2 Numbering note

R122 §8 once previewed "QSwap v2 (Factory/multi-hop/governance takeover)" as R123. Because stQAU has higher priority
(the first-pool asset is a precondition of R122's mainnet write-back), **QSwap v2 slides to R125**; R124 remains
the EVM translation-layer operand-swap rewrite (see `docs/EVM-COMPATIBILITY.md §5`). This document adds a note to
R122 §8 upon landing.

---

## 1. Background: the on-chain staking landscape (all with code provenance)

### 1.1 Consensus-layer native staking (live, running on the R120 mainnet)

| Item | Value | Provenance ||
---|---||---|
| system staking contract address | `0x…1001` (`StakingContractAddress`, native, not QVM) | `economics/staking.go:967` ||
| transaction type | `TxTypeStake`; `To` must equal `0x…1001` (R38-P0-02 strict AND check) | `node/node.go:5203` ||
| posting path | `syncStakingFromBlock` -> `AddStakeFromTx` -> QPOS `AddStakingValidator` | `node/node.go:5158,5209,5226` ||
| minimum stake | 32 QAU (new stakers; top-ups unrestricted for existing) | `economics/staking.go:282`, `consensus/validator_manager.go:75` ||
| commission | 100–1500 bps（1%–15%） | `economics/staking.go:288-292` |
| unbonding period | 151,200 blocks = 21 days @12s/slot | `economics/staking.go:279` ||
| unlock check | `currentHeight >= request.UnlockHeight` | `economics/staking.go:1692` ||

### 1.2 Reward flow (EM-2, deterministic recomputation)

- Formula: `stake × 31 / sqrt(total_staked)` (gwei), 87.5% attester / 12.5% proposer
  （`consensus/epoch.go:356` `CalculateBaseReward`，`consensus/block.go:59`）。
- The **epoch boundary block header embeds the attestation census**; every node deterministically recomputes the same rewards
  (`node/syncer.go:1412` `applyEpochRewards`, CNS-EPH-001) -> **credited directly via `stateDB.AddBalance`
  to the validator address (native balance)**. Rewards never pass through any QVM contract.
- Corollary: rewards for the stQAU contract can only be **manually injected by the operator** (see D5).

### 1.3 The existing liquid-staking framework (Go in-memory layer; not directly usable)

`economics/liquid_staking.go` (906 lines) already has the full framework — `StakingPool/StakeLiquid/UnstakeLiquid/
DistributeRewards/GetExchangeRate` — with RPCs like `qau_liquidStake` registered
(`rpc/economics_api.go:93-98`). **But it is all node-memory state: poolID is a string, it bypasses consensus,
never syncs, and never enters the state root**. R121 is precisely about making it on-chain (~21 days, touching consensus).

**R123 takes a different path**: the pool token QSwap needs must be an **on-chain ERC20** (the QVM pair/router can only
CALL on-chain contracts; see the R122 pair's storage slot 0/1 token0/token1 checks). The Go ledger is invisible to the QVM,
so stQAU must be a QASM contract — the framework code remains as reference semantics for R121.

### 1.4 QASM capability list (verified in R122; all reused here)

| Capability | R122 provenance | stQAU usage ||
---|---||---|
| keccak256 map storage keys | smoke_token/mock_token `balanceOf` maps | the balanceOf/allowance/withdrawalOf maps ||
| ERC20 transfer/approve/transferFrom | the full wqau.qasm suite | stQAU itself (callable by the QSwap pair) ||
| native CALL-value transfers + zero residue | the router's `helper_send_native` + addLiquidity refund (REFUND VERIFIED on-chain) | claimWithdrawal payouts, injectRewards intake ||
| Babylonian sqrt loop | qswap_pair first mint | **not needed** (stQAU has no sqrt) ||
| NUMBER/TIMESTAMP/SELFBALANCE/CHAINID | `qvm/environment.go:821-826` (opNumber/opTimestamp/opSelfBalance implemented) | unlock-height checks (NUMBER), the contract's own balance (SELFBALANCE, §D4) ||
| rate division as a single MUL+DIV | router addLiquidity `qauNeed = tokenAmt*r_qau/r_token` | shares = amt × totalSupply / backing ||

QVM arithmetic semantics (SUB/LT/DIV pop order — a = top op b = second-from-top, etc.) are not repeated here — **read
R122 plan §1.3 before writing any contract**; the full table has code provenance.

---

## 2. Design decisions

### D1 — stQAU is an on-chain QASM contract, not a node ledger
Rationale: §1.3. QSwap integration requires an on-chain ERC20; the pure-contract route has zero consensus risk, zero node changes, and reuses all
R122 patterns. The cost: rewards/staking actions need the operator as intermediary (see the D3/D5 trust analysis).

### D2 — exchange-rate accumulator, no rebasing
`The stQAU count never changes; each unit becomes worth more`: `rate = (contractBalance − totalQueued) / totalSupply`.
- Semantics match the existing `LiquidStakingManager.GetExchangeRate` (`economics/liquid_staking.go:679`);
- The QASM implementation is a single MUL+DIV (as in R122), with no rebasing-style rewriting of historical balances (QASM suits that poorly anyway);
- QSwap is oblivious: stQAU is just an ordinary ERC20.

### D3 — nomination-pool model: the operator stakes in batches on behalf of users
**A contract cannot initiate `TxTypeStake`** (stake transactions must be externally signed with `To=0x…1001`; see §1.1) —
a hard consensus-layer constraint, not a fixable defect. Hence:

```
user deposit(QAU) --> stqau contract (native balance, shares minted)
operator extractForStaking(amt) --> native QAU to the owner address (accounted as totalExtracted)
operator qau_stake(TxTypeStake) --> stakes under their own name (reusing existing RPCs, zero new node code)
   the 21-day unbonding is managed in operator batches
rewards (auto-credited to the operator's native balance each epoch) -- operator --> injectRewards(){CALLVALUE} (rate rises)
user withdraw(shares) --> burn + queue (rate locked, owedNative recorded)
   -- 21 days (151,200 blocks) --> claimWithdrawal() --> paid via a native CALL
```

### D4 — the contract's native balance is the single source of truth (honest accounting)
The `SELFBALANCE` opcode reads the contract's own balance directly (`qvm/environment.go:824` opSelfBalance);
backing is not stored in a slot but computed on read:
```
effectiveBacking = SELFBALANCE − totalQueued (the unclaimed queue)
rate             = effectiveBacking × 1e18 / totalSupply
```
The operator **cannot lie about the rate**: when slash losses stay on the consensus side, less money returns to the contract, `SELFBALANCE`
drops honestly and the rate impairs automatically. `recordSlash(uint256)` only writes an audit-snapshot slot (historical record), affecting no arithmetic.

### D5 — trust-point list (honestly disclosed for v1; all auditable on-chain)
| Trust point | Impact | Mitigation ||
---|---||---|
| operator runs off after `extractForStaking` | 🔴 principal | v1: operator = a whitelisted team validator + public documentation + fully transparent on-chain `totalExtracted`; v2 (R125+): owner becomes multisig/governance and extract requires a timelock ||
| operator withholds rewards (receives but never re-injects) | 🟡 yield | on-chain reconciliation is possible (operator balance rising while injectRewards has no transactions for a long stretch = evidence); migration is possible ||
| two-layer withdrawal delay (user 21 days + operator batch unbonding 21 days) | 🟡 UX | documentation states the worst case of 42 days; the operator keeps a liquidity buffer (optional treasury-funded early-payout reserve) ||
| slash pass-through | 🟡 rate impairment | D4 honest accounting impairs automatically + recordSlash snapshots ||

Handled on par with R122's centralization list (the v1 router's single-party `paused` switch): **disclosed in documentation + later migrated to governance**,
with no pretense of decentralization.

### D6 — withdrawal queue: per-address slots
QASM storage is full-width uint256 (the R122 pair's fn_sync already does full-width SSTORE; packing yields nothing), so each
address gets two maps: `queuedShares(addr)` (shares already burned at request time) + `queuedOwed(addr)` (the native amount owed at the locked
rate) + `queuedUnlock(addr)` (the unlock block height). The rate is locked at request time -> subsequent rate swings
do not affect queued users; `claimWithdrawal` checks `NUMBER >= queuedUnlock`, reusing R122's
"maturity comparison" pattern (LT/GT pop semantics in R122 §1.3).

### D7 — the R122 pattern-reuse list (no reinvention)
- helper-area memory-layout conventions (0x180/0x1a0/...), the `PUSH2 @label / JUMP @helper` continuation pattern;
- zero-value gates (amt=0 reverts), REVERTs carrying position markers (the gas-reconciliation locating technique);
- the dispatcher's per-selector equality + JUMPI chain;
- MockToken's constant-return pattern for name/symbol/decimals.

---

## 3. Contract spec (stqau.qasm)

### 3.1 Storage layout (plain slots, full width)

| slot | Field | Type ||
---|---||---|
| 0 | owner (the operator; deployer) | address ||
| 1 | paused (0=normal, 1=new deposits/withdrawals paused) | uint ||
| 2 | totalSupply (total stQAU) | uint ||
| 3 | balanceOf map root | key = keccak256(pad(addr) ++ pad(3)) ||
| 4 | allowance map root | key = keccak256(pad(owner) ++ pad(spender) ++ pad(4)) ||
| 5 | totalQueued (total native amount in the unclaimed queue) | uint ||
| 6 | queuedShares map root (shares requested for redemption, already burned) | keccak256(pad(addr) ++ pad(6)) ||
| 7 | queuedOwed map root (native owed on redemption, rate-locked) | keccak256(pad(addr) ++ pad(7)) ||
| 8 | queuedUnlock map root (redemption unlock height) | keccak256(pad(addr) ++ pad(8)) ||
| 9 | totalExtracted (cumulative operator extractions, for audit) | uint ||
| 10 | lastSlashSnapshot (latest recordSlash snapshot) | uint ||

The map-key construction is fully isomorphic to R122's smoke_token/mock_token (`keccak256(pad(addr) ++ slot)`).

### 3.2 Function table (selectors actually computed via keccak256)

| Function | selector | Access | Key logic | Gas budget ||
------|---|---|||---|
| `deposit()` | `0xd0e30db0` | anyone (not paused), CALLVALUE>0 | shares=CV×supply/backing; first deposit 1:1 | ~90k ||
| `withdraw(uint256 shares)` | `0x2e1a7d4d` | anyone (not paused), shares>0 and <=balance | burn + three queue-slot writes + owed locked at the current rate | ~110k ||
| `claimWithdrawal()` | `0x6e66d84a` | has a queue entry and NUMBER>=unlock | clear the queue + native CALL payout (helper_send_native copied) | ~70k ||
| `injectRewards()` | `0x99c722bc` | anyone, CALLVALUE>0 | pure CALLVALUE intake; the rate rises automatically (D4) | ~25k ||
| `extractForStaking(uint256 amt)` | `0x8cc57d95` | owner only, amt<=backing−queued−buffer | native CALL to the owner + totalExtracted increment | ~60k ||
| `recordSlash(uint256 snapshot)` | `0x0f75baca` | owner only | write the slot-10 audit snapshot | ~25k ||
| `pauseDeposits()` / `unpauseDeposits()` | `0x02191980` / `0x63d8882a` | owner only | set/clear slot 1 | ~25k ||
| `transferOwnership(address)` | `0xf2fde38b` | owner only, non-zero address | slot 0 | ~25k ||
| ERC20 reads/writes | `0x18160ddd` `0x70a08231` `0xdd62ed3e` `0x095ea7b3` `0xa9059cbb` `0x23b872dd` | standard | byte-for-byte reuse of the wqau.qasm implementation | same as wqau ||
| `name()` `symbol()` `decimals()` | `0x06fdde03` `0x95d89b41` `0x313ce567` | read-only | "Staked QAU" / "stQAU" / 18 | same as mock ||
| `exchangeRate()` | `0x3ba0b9a9` | read-only | (SELFBALANCE−totalQueued)×1e18/supply; supply=0 -> 1e18 | ~5k ||
| `totalBacking()` | `0xeb2cd258` | read-only | SELFBALANCE−totalQueued | ~3k ||
| `withdrawalOf(address)` | `0x14bf9d2b` | read-only | the queue triple (owed/unlock/shares) | ~5k ||

Unknown selector -> REVERT (same as the R122 dispatcher).

### 3.3 Gas budgets (measured and backfilled 2026-09-07, localtest 1333 e2e)

| Operation | **Measured** | Original estimate | Notes ||
------|---|---|||
| deploy stqau (2082B bytecode) | **0x7f9e3 (523,363)** | <=1.5M | five-contract suite totals ~2.4M ||
| deposit | **~0x8c95 (35,989)** | ~90k | far below estimate ✓ ||
| injectRewards | **~0x52f0 (21,232)** | — | the receive-without-mint path ||
| withdraw (enqueue) | **~0x1e206 (123,910)** | ~110k | includes the three queue-map writes ||
| stqau.approve + router.addLiquidity | **~0x6ae7 + ~0x28f9c** | ~300k | first LP mint includes the wrap path ||
| swapTokenForQau (instant stQAU->QAU exit) | **~0x27433 (158,259)** | — | same as R122 ||

> Note: the localtest receipt's gasUsed field is unreliable (it can still show the 0x5208 transfer baseline even after real contract execution);
> the table takes genuinely-displayed full values across rounds, and all reconciliation goes by eth_call state
>(a lesson from R122+R123; the tooling now has built-in reorg-settle defenses).

The gas ceiling follows the R122 convention: GasLimit 5M per tx (`QAU_DEPLOY_GAS`).

### 3.4 Arithmetic-semantics reminders (memorize before writing code)

- `DIV/SUB/LT/GT/MUL/MOD`: a = top op b = second-from-top (R122 §1.3 full table + validated by 500 fuzz rounds);
- Share computation `shares = amt × supply / backing`: push backing first (second-from-top), then amt (top) —
  does `DIV` then yield amt/backing? **No** — MUL first, then DIV in one shot (`amt×supply` on top, `backing` second-from-top);
  wrong order = the whole batch of shares is wrong (the same risk as the R122 refund bug; a code-review checklist item);
- Overflow: QVM MUL has no detection and `amt×supply` can reach 2^256 — so `deposit` has a pre-gate
  `amt <= 2^128` (supply and per-deposit both capped, so the product cannot overflow); covered by the documented gas-gate tests.

---

## 4. QSwap integration (the mainnet first pool = stQAU/wQAU)

1. Deployment order: WQAU -> stQAU -> Pair -> Router (deploy_qswap `-pool-token <stQAU addr>`,
   **resolving the runbook's pending "first-pool second token decided" item**; `-deploy-mock` remains strictly forbidden on mainnet).
2. The pair's token0/token1 is determined by address ordering automatically (implemented in R122; no deployment-order constraint).
3. User paths: native QAU -> deposit -> stQAU; or deposit -> approve(router) -> addLiquidity
   into the pool. Exiting: swap, or withdraw (21-day queue) — **the instant swap exit is stQAU's core selling point**.
4. The e2e rehearsal extends `cmd/qswap_smoke`: the stQAU segment (deposit->injectRewards->rate assertion->withdraw->
   time fast-forward->claim->balance reconciliation) + the existing QSwap loop (receipt reorg-settle defense carried over from `17d5d1a`).

---

## 5. Implementation plan (5 phases, 9-10 days)

### Phase 0 — smoke (0.5d) [stop-loss gate]
- [x] Unit-test that `SELFBALANCE/NUMBER` return correctly on both the executor.go JIT path and the interpreter path
  ✅ `qvm/r123_phase0_smoke_test.go` dual-path PASS (commit 6e6e51e)
  (R122 already flagged dual-path divergence risk; on failure D4 would switch to owner-fed values + a manually accounted totalBacking slot, and the document would be re-evaluated)

### Phase 1 — contract + unit tests (4-5d)
- [x] `contracts/qasm/stqau.qasm` full-function implementation (§3 spec) ✅ 2082B deployed bytecode, 22 selectors
- [x] `go run ./cmd/qasm assemble contracts/qasm/stqau.qasm contracts/qasm/stqau.hex` ✅
- [x] `qvm/r123_stqau_test.go` (11 lifecycle) + `qvm/r123_stqau_spec_test.go` (49 table-driven) = 60 cases —
  first deposit 1:1, proportional mints, zero-value gates, overflow gates (amt=2^128), the full approve/transferFrom paths,
  owed immune to rate swings after withdraw locks it, unlock boundaries (NUMBER−1 rejected / NUMBER passes),
  claim clears the queue, the paused gate (deposit/withdraw rejected; claim exempt — paying locked debts must not freeze user exits), the owner gate (non-owner calls to owner functions revert)
- [x] Mis-ordering review: **push-order line-by-line verification of every MUL/DIV/SUB/LT** (the R122 refund-bug lesson)
  ✅ 5 real catches (CV-pre/backing, late supply decrement, 0x24EA0, the keccak 96B, SSTORE order)
  + 2 more from fuzz/spec (the queue-occupied guard, the zero-address owner) — all fixed and locked

### Phase 2 — fuzz (2d) [community-claimable]
- [x] `qvm/r123_stqau_fuzz_test.go`: 500 rounds of random sequences (deposit/withdraw/claim/inject/
  extract/time advancement), per-round conservation reconciliation: ✅ fixed seed=42, zero violations of C1-C4
  extract/time advancement), per-round conservation reconciliation:
  `SELFBALANCE == initial + Σinject + Σdeposit − Σclaim − Σextract`
  and `supply>0 -> rate monotonically non-decreasing (with no simulated slash)`

### Phase 3 — local 6-node e2e (1.5d)
- [x] Deploy the five-contract suite (WQAU+stQAU+mock+pair+router) + wiring sanity ✅ `deploy_qswap -deploy-stqau`
- [x] `qswap_smoke` extension segments all green (§4.4) ✅ stQAU segment + reorg-settle defenses
- [x] **First-pool creation + swap out exact to wei** (aligned with R122's acceptance bar)
  ✅ stQAU/wQAU pool opened at 23.6:20.3; swap exit out matches getAmountOut exactly (same-source gas diff);
      unlock=head+151200 drift=0；lock-rate implied==live rate

### Phase 4 — mainnet runbook + docs (1d)
- [x] `QSWAP-Mainnet-Runbook.md`: the stQAU section (deployment parameters, operator SOP, key-separation guidance —
  owner key ≠ validator key ≠ wallet key) ✅ one-command five-contract deploy + §3b operator SOP +
  stQAU ABI table + the four localtest pitfalls
      owner key ≠ validator key ≠ wallet key）
- [x] Note added to R122 §8 on the numbering shift (already present); this document's status -> Done ✅

**Dependency ordering**: R122's mainnet write-back (after the 72h window) does **not** block R123 development, but before the first pool opens
the QSwap suite must already be on mainnet — stQAU deploys second; see the runbook timeline.

---

## 6. Acceptance criteria (DoD)

- [x] >=60 unit cases all green; 500 fuzz rounds with zero conservation violations ✅ 60 cases (11+49) + bug regression locks; fuzz zero violations of C1-C4
- [x] Repo-wide `go test ./... -count=1 -short -timeout 10m` with 0 FAIL (no regression across 65 packages) ✅ measured 2026-09-07
- [x] Local-chain e2e: the full stQAU lifecycle + **QSwap stQAU/wQAU first-pool swaps exact to wei** ✅
  fresh-genesis 6-node chain with the five-contract suite + deposit/inject/pool-open/swap-exit/withdraw-enqueue all green
- [x] Measured-gas table backfilled into §3.3 (measurements replacing estimates) ✅ 2026-09-07
- [x] The D5 trust-point list entered the runbook verbatim; the operator announcement copy is ready ✅ runbook §3b (including the worst-case-42-days announcement)
- [x] Commit convention: `R123: stQAU ...`, with plan checkboxes kept in sync ✅ (10b0cfc -> 225f132 -> e51c224 -> 8a5883c)

## 7. Risk table

| # | Risk | Probability × impact | Mitigation ||
------|---|---|||
| R-1 | operator trust (extract-and-run / withheld rewards) | low × 🔴 | D5 full on-chain transparency + whitelist + the v2 multisig path is documented ||
| R-2 | divergence between the two QVM execution paths (JIT/interpreter) | medium × 🔴 | the Phase 0 smoke gate; R122 already documented returnData-residue-after-REVERT pitfalls; tests run on both paths ||
| R-3 | arithmetic push-order errors (same family as the R122 refund bug) | medium × 🔴 | the §3.4 review checklist + fuzz conservation as the safety net ||
| R-4 | the two-layer 21 days triggering user complaints | high × 🟡 | product copy states "worst case 42 days; instant exit via swap"; buffered payouts optional ||
| R-5 | insufficient first-pool depth causing large slippage | high × 🟡 | treasury ecosystem funds seed the first LPs (the whitepaper 8.2 ecosystem fund's 2M QAU authorization; separate governance) ||
| R-6 | gas over budget | low × 🟡 | the §3.3 measured ceiling table backfilled; stQAU has no sqrt loop and a simpler structure than the pair ||
| R-7 | numbering/doc drift (R123 colliding with QSwap v2) | certain × 🟢 | settled in §0.2: v2 -> R125; R122 §8 updated upon landing ||

## 8. Contribution guide (limited to Phase 2 fuzz tooling and the qswap_smoke extension segments)

Same rules as R121 §6: branch `feat/r123-<task>-<name>`, Conventional Commits,
`go test ./qvm/... -run R123` fully green + `golangci-lint run` zero warnings before opening a PR.
The main contract (stqau.qasm) is v1 core-team delivery — fund-trust design is not outsourced.

---

*Plan frozen 2026-09-06. Implementation changes must be written back here with DoD kept in sync.*

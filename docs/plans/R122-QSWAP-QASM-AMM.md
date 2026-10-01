# R122 — QSwap AMM native QASM implementation plan

| Field | Content ||
---|---||
| **Status** | Done (development and local acceptance complete; mainnet deployment write-back pending) ||
| **Owner** | Core team (internal delivery preceding R121) ||
| **Priority** | Critical (a DEX is a precondition for token circulation) ||
| **Target** | Mainnet deployment (no node binary changes; pure contract deployment) ||
| **Preliminary study** | EVM compatibility translation-layer defect investigation (see §1.1) ||
| **Docs** | [R121-DELEGATION-LIQUID-STAKING.md](R121-DELEGATION-LIQUID-STAKING.md) ||

---

## 0. Executive Summary

Implement the full AMM DEX contract suite (wQAU + QSwapPair + Router) in **QASM (chain-native assembly)**
instead of the previous Solidity + evmcompat translation route. Rationale: the translation layer has an **unfixable operand-order defect**
(EVM/QVM arithmetic semantics are opposite, so a 1:1 transliteration necessarily computes wrong), while the only contract path verified on mainnet
(the six R120 LinearVesting contracts locking 15,000,000 QAU) is hand-written QASM.

**Deliverables:**
1. `contracts/qasm/` — wQAU.qasm, QSwapPair.qasm, Router.qasm (+ MockToken.qasm for tests)
2. Go unit tests (driving the QVM executor directly, covering every function's boundaries)
3. Local multi-node end-to-end deployment rehearsal (`cmd/deploy_qswap` is ready and consumes hex bytecode)
4. Mainnet deployment runbook update

**Estimated effort**: 7-10 working days (step 0 smoke experiment first; if it fails, stop-loss and reassess immediately).

---

## 1. Background and technical decisions

### 1.1 Why not Solidity + the evmcompat translation layer

The investigation found three fatal defects:

1. **QVM vs EVM stack semantics must be settled by implementation and differential testing**: the current QVM pop order of `SUB/LT/GT/DIV/EXP` must be verified per opcode, not blanket-claimed as "all reversed"; any compatibility-layer fix must use asymmetric-operand differential tests.
   (`qvm/operations.go:102`: `a=Pop(); b=Pop(); Push(a-b)`). `LT/GT/DIV/EXP` are likewise all reversed.
   evmcompat is a 1:1 opcode transliteration (`evmcompat/evmcompat.go:325`), **without inserting any
   operand-swap sequences** -> any arithmetic-bearing Solidity contract computes wrong results after translation.
   For an AMM this means direct user fund loss.
2. **metadata cannot be translated**: the arbitrary bytes in the ipfs CBOR tail of Solidity initcode (e.g. `69 70 66 73`)
   (`0x22`,`0xda`,`0xc9`,`0x2d` etc.) are not in the map -> `TranslateBytecode` fails wholesale
   -> the node falls back to "native QVM executing EVM bytecode" -> garbage -> OOG (gasUsed maxed at 5M).
   Local-chain test: WQAU.sol deployment status=0x0.
3. **No Solidity contract has ever run on-chain.** The only contract family deployed on mainnet (LinearVesting)
   is hand-written QASM (`contracts/linear_vesting.qasm`); everything on the EVM route was tests.

### 1.2 Why QASM is the right path (evidence chain)

| Evidence | Source ||
---|---||
| the 15M QAU vesting contract is QASM and stable on mainnet | `contracts/linear_vesting.qasm` + mainnet diagnostics ||
| the QASM assembler is mature (labels, `@label` delta expressions, macros, strict mode) | `cmd/qasm/main.go` ||
| QASM contracts still use Solidity ABI selectors -> wallets/RPC call them unchanged | linear_vesting.qasm uses `0x8da5cb5b` = owner() ||
| 512B of vesting implements what Solidity does in 2000B, an order of magnitude less gas | bytecode comparison ||
| the chain uses Dilithium3 signatures and was never MetaMask-toolchain compatible; little is lost by not being "EVM compatible" | `crypto/signing_verifier.go` rejects 65-byte ECDSA ||

### 1.3 Verified QVM semantics (must remember before writing contracts; all have code provenance)

> ⚠️ **These differ from EVM. Each was verified against the Go source; reason about the stack accordingly when writing QASM.**

| Semantics | Actual QVM behavior | EVM behavior (for contrast) | Provenance ||
------|---||---||
| `SUB` | `top − second-from-top` | second-from-top − top | `qvm/operations.go:102` ||
| `LT`/`GT` | `top ? second-from-top` | reversed | `qvm/operations.go:262` ||
| `DIV` | `top ÷ second-from-top` | reversed | `qvm/operations.go` opDiv ||
| `CALL` (QVM mode) | pop order `outSize,outOffset,inSize,inOffset,value,addr,gas` (retSize on top) | gas on top | `qvm/call.go:194` ||
| `CALL` parameter-mode switch | the `env.ctx.EVMCompatible` flag (translated contracts use EVM order; QASM uses QVM order) | — | `qvm/call.go:207` ||
| `MSTORE` | `top=offset, second-from-top=value` (offset popped first) | value first | `linear_vesting.qasm` comments ||
| `SSTORE` | `top=key, second-from-top=value` | reversed | same ||
| JUMP validity | the target must be a JUMPDEST; `jumpDests` analysis skips PUSH data | same | `qvm/qvm.go analyzeJumpDests` ||
| `KECCAK256` | exists (0x89), parameter semantics as in EVM (top=offset, second=size) | — | `qvm/opcodes.go:196` ||
| Gas costs | explicit per-entry in opcodeInfoTable; AMM function budgets in §4 | EIP-150 etc. | `qvm/opcodes.go` ||

**Writing discipline**: annotate every arithmetic/comparison instruction in QASM with which operand is "top/second-from-top"; function-level tests
must cover "operand order" cases (e.g. an asymmetric `a−b ≠ b−a` case), guarding against slips.

### 1.4 Decision record: fail-closed translation layer (parallel task)

Once the open-source repo is public, community developers may deploy Solidity -> wrong operands -> fund losses blamed on the project.
**Countermeasure**: the `deploy` entry point **rejects EVM-shaped bytecode with an explicit error** (IsEVMBytecode true and translation fails)
(fail-closed); the successful-translation path remains but is documented "experimental, arithmetic semantics unfixed".
The change only touches the deployment branch of `qvm/parallel/executor.go` plus unit tests, **not consensus** (contract deployment is not
a consensus-critical path — failed transactions never enter blocks), so it can be verified safely on a local chain.

---

## 2. Contract specs

### 2.1 wQAU (native-token wrapper)

| Item | Value ||
---|---||
| Purpose | wrap native QAU into a "token" the Pair can hold, pegged 1:1 ||
| Storage | `slot0 name="Wrapped QAU" symbol="wQAU"` (constants hardcoded into code), `slot1 totalSupply`, `slot2 balanceOf(map root)`, `slot3 allowance(map root)` ||
| Map storage keys | `keccak256(ownerAddr, slot)`, the same scheme as EVM (KECCAK256 opcode 0x89 is available) ||
| Functions (ABI selectors computed as in Solidity) | `deposit()` payable, `withdraw(wad)`, `balanceOf(a)`, `transfer(to,wad)`, `approve(spender,wad)`, `transferFrom(...)`, `allowance(o,s)`, `totalSupply()` ||
| Safety | withdraw balance checks; transferFrom allowance decrement (unlimited max approvals skipped); the `receive` entry = auto-deposit when calldata is empty (QASM side: CALLDATA check) ||
| Gas budget | deposit/transfer <= 60k; transferFrom <= 90k ||

**ABI selector computation**: `keccak256("transfer(address,uint256)")[0:4]` etc. — via a small Go-side tool
`cmd/qasm/abi.go` (new) that generates them and embeds them directly as QASM constants, avoiding hand-copying errors. The tool also generates
constructor-argument encodings for deploy_qswap to assemble.

### 2.2 QSwapPair (the AMM core; security-critical)

| Item | Value ||
---|---||
| Pool | a pair of token addresses (token0 < token1 ordering, as in Uniswap V2) ||
| Storage slots | `0:factory 1:token0 2:token1 3:reserve0 4:reserve1 5:blockTsLast 6:totalSupply 7:lpBalanceOf map root 8:lpAllowance map root 9:kLast 10:paused (emergency switch, see §2.4)` ||
| Core formula | constant product `x*y>=k`; swap fee 0.3%: the `in*997` formulation (as in Uniswap V2: `balanceAdjusted = balance*1000 − in*3`, `require(adj0*adj1 >= reserve0*reserve1*1000^2)`) ||
| LP mint | first mint `sqrt(x*y) − 1000` (MINIMUM_LIQUIDITY permanently locked to 0x0); subsequent mints `min(Δx·S/rx, Δy·S/ry)` ||
| LP burn | `out = lp·balance/S`, pro rata to pool balance ||
| sqrt | Babylonian iteration (`z=x; while((y/z+z)/2<z) z=(y/z+z)/2`), **QVM has no native sqrt** — hand-written loop; big-integer division, mind QVM DIV operand order ||
| Reentrancy guard | a storage lock slot (enter=1, exit=0; reentry reverts). QVM CALL executes synchronously, so the lock works ||
| Events | Mint/Burn/Swap/Sync — **the event system's current state awaits step-0 verification** (LOG opcode existence and the RPC log interface); if unavailable, go storage-only + wallet polling of reserves (accepted for v1) ||
| Router-only calls | mint/burn/swap require `CALLER` to equal the factory-registered router (v1 hard-codes the router address in post-deploy INIT; see the §2.4 simplification) ||

### 2.3 Router (user entry point; v1 minimal)

| Item | Value ||
---|---||
| v1 scope | single-pool direct routing only (one hop). Multi-hop / dynamic Factory pools -> **R123** (community task) ||
| Storage | `0:pair0 1:wqau 2:feeToSetter 3:paused` ||
| Functions | `addLiquidity(tokenAmt, qauValue)` payable (internally native QAU -> deposit -> wQAU), `removeLiquidity(lp)`, `swapExactQauForToken(minOut)` payable, `swapTokenForQau(tokenIn, minQauOut)`, `quote/read-ahead functions` ||
| Slippage protection | a `minOut` parameter + explicit revert ||
| Refunds | surplus native QAU from addLiquidity/swap is refunded to the CALLER by the difference ||
| Approval flow | the user first calls wQAU.approve(Router) (tokenToQau path); the Router pulls via transferFrom ||
| Gas budget | add <= 300k; swap <= 200k ||

### 2.4 v1 security simplifications (documented, never silent)

- **No dynamic Factory pool creation**: the first pool address is assembled by the deploy script (deterministic address derived from the deploy nonce).
  A dynamic CREATE2 pool factory -> R123. Rationale: a single v1 pool is enough to validate the market; CREATE2 semantics in QVM
  exist (opcode 0x95) but have no mainnet precedent, so the risk is concentrated.
- **The paused emergency switch**: feeToSetter can `pause()`/`unpause()` — minimizing attack surface before open-sourcing.
  The centralization point is documented (it conflicts with the "long-lived L1" vision; R123 migrates to unpausable + governance).
- **No flash swaps**: v1 supports only add/remove/swap on QAU/x pools, no flash-swap callbacks
  (the `data` parameter does not support external contract callbacks — the IQSwapCallee surface is cut).

---

## 3. Implementation steps (in order; each has an acceptance gate)

### Step 0 — smoke experiment (half a day) ★ stop-loss point
- [x] Write `contracts/qasm/smoke_token.qasm`: map storage + transfer + REVERT rollback (the separate smoke_call contract was merged directionally into smoke_token for CALL-semantics verification) ✅ 4/4 PASS (262c9ab)
- [x] Verify key QVM semantics (all annotated with source lines):
  - QVM-mode CALL stack order (`call.go:207` else branch)
  - `KECCAK256` map-key read/write correctness (keccak pops: size pushed first, offset second)
  - **storage isolation** for contract-to-contract calls
  - events: the LOG opcode works and RPC can retrieve them
- [x] **Gate**: all four pass ✅ 4/4 PASS -> continue

### Step 1 — wQAU.qasm + unit tests (1-1.5 days)
- [x] ABI tool (`cmd/qasm/abi.go`): selector computation + constructor-argument encoder
- [x] wQAU implementation + `qvm/r122_wqau_test.go` (driving the QVM executor directly)
- [x] Cases: deposit/withdraw round-trip conservation, transfer balance zero-sum shifts, transferFrom allowance decrement,
      unauthorized transferFrom revert, operand-order trap cases (`a−b ≠ b−a` assertions), the unlimited-approval exception
- [x] **Gate**: all green ✅ 7/7 PASS (5d40bd6)

### Step 2 — MockToken.qasm (0.5 days)
- [x] Standard ERC20 surface (mint restricted to the deployer), reusing the ABI tool
- [x] Unit tests at wQAU standard ✅ 3/3 PASS (c1edd26)

### Step 3 — QSwapPair.qasm (3-4 days) ★ the core battle
- [x] Babylonian sqrt loop (with internal convergence) ✅
- [x] swap: slippage check + k-conservation check + the 0.3% fee adjustment (all formulas re-derived under QVM operand order) ✅
- [x] mint/burn LP: first-mint MINIMUM_LIQUIDITY locked to 0x0, pro-rata subsequent mints, burns pro rata to balance ✅
- [x] Reentrancy lock + CALLER=router check ✅
- [x] Fixed-point invariant assertions (embedded in each test: k monotonically non-decreasing, LP conservation, asset conservation) ✅ 8/8 PASS (a6f4d72)
- [x] 500 rounds of random fuzz (independent random sequence, fixed seed 42, `qvm/r122_pair_fuzz_test.go`): 500/500 pass
- [x] **Gate**: 500 fuzz rounds with zero violations + all fixed-point cases green: 35/35 pass

### Step 4 — Router.qasm (1-1.5 days)
- [x] Four functions + refund logic + the paused switch
- [x] Unit tests: full add->swap->remove loop, slippage revert, accurate refunds
- [x] **addLiquidity refund-defect fix**: the v1 version had only the first-mint path and no refunds; rewrote fn_add_liquidity — subsequent adds proportionally clipped on both legs (token leg fully pulled when capped / qauNeed clipped pro rata by CV), depositing only the actually-needed qauUse, refunding the surplus CALLVALUE difference to the CALLER and reverting the whole tx on refund failure; the fix also moved the token0-direction check ahead of the first-mint check, adapted DIV/LT/SUB pop order to QVM semantics, and raised helper_send_native gas 23000->500000
- [x] Three dedicated refund tests: Refund (2M surplus, only 25k taken) / OversizedRefund (2M/400k, only 100k actually taken) / RefundFail (a rejecting contract reverts the whole tx; receiver assets and reserves unchanged)
- [x] **Gate**: closed-loop asset conservation (final user balance + pool balance = initial) with zero error: 9/9 pass

### Step 5 — local-chain end-to-end + mainnet runbook (1 day)
- [x] `qasm assemble` produces 4 hex blobs -> `cmd/deploy_qswap` full flow on a local multi-node chain: 4/4 status=0x1
- [x] Full rehearsal of wallet-style RPC calls (eth_call pre-reads + signed deployment transactions) ✅ cmd/qswap_smoke
- [x] Updated `QSWAP-Mainnet-Runbook.md`: QASM hex paths, address list, pool-creation script
- [x] **Gate**: local-chain add/swap/remove all pass, diagnostics all green ✅ amounts exact to wei
- [x] **v2 refund-router hex re-verification** on a fresh-genesis local chain: deploy 4/4 + wiring sanity; qswap_smoke full loop (first-mint + subsequent addLiquidity, both swap directions exact to wei, removeLiquidity to zero); surplus-CALLVALUE on-chain verification (CV=10x qauNeed, exactly qauNeed taken, refund returned, zero residual native balance in the router)
- Note: re-verification surfaced two localtest environment issues (not R122 defects): (a) wiping chain data while keeping validator keys causes attestations to be rejected with "source epoch has no canonical root" -> chronic forking; the fix is a fresh genesis (regenerate via `cmd/localnet`) and letting the chain self-heal after the epoch-0 boundary; (b) during a fork window `eth_getTransactionReceipt` can return a temporary receipt from a discarded branch (status=0x0/gasUsed=0x5208 fallback) — re-check after settling; deploy_qswap/qswap_smoke now carry reorg-settle defenses, and the true on-chain state is what eth_call reconciliation says

### Step 6 (parallel, throughout) — evmcompat fail-closed
- [x] `qvm/parallel/executor.go`: EVM detected and translation fails -> deployment reverts with a reason ✅ (commit b6382b5)
- [x] Added `docs/EVM-COMPATIBILITY.md`: defect description + known-unsupported list + fix roadmap (operand-swap translator rewrite, community task R124)
- [x] Renamed the Solidity contract directory to `contracts/solidity-reference/`, with the README marking them as reference implementations

---

## 4. Gas budget table (deploy/call)

| Operation | Budget | Notes ||
---|---||---|
| deploy wQAU | <= 120k | init + copying ~2KB of code ||
| deploy Pair | ≤ 250k | |
| deploy Router | <= 150k | v1 minimal ||
| swap | <= 200k | includes two token-transfer CALLs ||
| addLiquidity | ≤ 300k | |
| removeLiquidity | ≤ 200k | |
| gas cost per deployment | ~0.005 QAU @ gasPrice=1 | 3 contracts < 0.02 QAU ||

---

## 5. Testing and quality gates

1. **Three test layers:**
   - L1 Go directly driving the QVM (fixed-point per function + revert branches) ✅ done
   - L2 fuzz invariants (500 rounds of random sequences, seed 42) ✅ done (mixed driving of swap/mint/burn/sync/transfer/rejection paths)
   - L3 local multi-node end-to-end (real signatures, real blocks, real receipts): done
2. Run before **every git commit**:
   `go test ./qvm -run '^TestR122' -count=1`
   `go test ./cmd/... ./qvm/...`
3. Unit-test file naming: `qvm/contract_<name>_test.go`, consistent with the vesting test style
4. The fuzz seed is fixed (`rand.New(rand.NewSource(42))`) to guarantee reproducibility

---

## 6. Risk register

| # | Risk | Likelihood | Mitigation ||
------|---||---||
| R-1 | Unknown semantic defects in QVM contract-to-contract CALL (surfaced in step 0) | medium | the step-0 stop-loss gate; defects get their own R item — no forcing through ||
| R-2 | hand-written QASM arithmetic overflowing at extreme values (uint112 reserve cap) | medium | conservative bounds in every comparison + fuzz with 2^111/2^112 boundary cases ||
| R-3 | LOG events unavailable -> wallets lack transaction history | medium | v1 storage-polling plan; events -> R123 ||
| R-4 | gas budget overrun (OOG masking a real bug) | low | explicit gas accumulation per opcodeInfoTable entry; tests assert gasUsed < budget ||
| R-5 | deploy-script nonce/address derivation wrong | low | deploy_qswap already rehearsed on the local chain (the 3-contract sequential deployment path works) ||
| R-6 | accidentally touching production | — | all validation stays local; no production write operations ||

---

## 7. Delivery checklist (Definition of Done)

- [x] `contracts/qasm/{wqau,qswap_pair,qswap_router,mock_token}.qasm` + assembled hex
- [x] All Go tests green (fixed-point + fuzz500 + boundaries): 35/35 pass
- [x] Local multi-node end-to-end: deploy -> add -> swap -> remove all pass
- [x] `cmd/deploy_qswap` rehearsal succeeds + manifest output
- [x] Mainnet runbook updated
- [x] evmcompat fail-closed merged + `docs/EVM-COMPATIBILITY.md`
- [x] Solidity reference implementations quarantined and labeled
- [x] This document's status set to Done
- [ ] Mainnet deployment write-back: execute the runbook and backfill the manifest addresses here

---

## 8. Follow-up task preview (outside this plan)

**Numbering change**: this section originally previewed R123; because the first QSwap pool needs an asset (see
[R123-STQAU-LIQUID-STAKING.md](R123-STQAU-LIQUID-STAKING.md), the stQAU staking receipt),
**the R123 number was ceded to stQAU**, and this section's QSwap v2 slides to **R125**; R124 remains
the EVM translation-layer operand-swap rewrite (`docs/EVM-COMPATIBILITY.md §5`).

### R125 (formerly R123) — QSwap v2 (community task)

- dynamic Factory pool creation (CREATE2 deterministic addresses)
- multi-hop routing + flash swaps
- an event system (if step 0 confirms LOG is unavailable)
- removal of the paused switch -> governance takes over
- EVM translation-layer operand-swap rewrite (true EVM compatibility, at which point the Solidity reference implementations can be activated) -> stays R124

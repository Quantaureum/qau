# QSwap / WQAU / stQAU — wallet-side API specification (v1)

> This document is the **single authoritative spec** for wallet (extension/mobile) QSwap features.
> Both wallets must implement the same selectors / ABI encodings / error semantics / signature fields, each in its own language.
> Baseline: R122 QSwap QASM contracts are deployed on mainnet; the R123 stQAU contract awaits deployment (Phase 1 in progress).
> Any change to this document must be communicated to both wallet maintainers.

---

## 0. Definitions and scope

| Term | Meaning ||
|---|---|
| **QSwap** | QVM-native AMM composed of two QASM contracts, Router + Pair (no Factory) ||
| **WQAU** | wrapped QAU (`deposit()` payable + `withdraw`), ERC20-compatible ||
| **stQAU** | liquid staking token (R123), ERC20-compatible + reward injection + 21-day redemption queue ||
| **first pool** | the `WQAU/stQAU` pair (opens once R123 ships) ||
| **TxTypeContract** | transaction type = `0x01` (contract call); the Data field carries calldata ||
| **CRV2 exemption** | commit-reveal only affects `TxTypeTransfer`; contract calls **do not** need commit-reveal ||

**Out of scope for this spec:**
- node-side QVM semantics design (see `node/docs/plans/R122-QSWAP-QASM-AMM.md`)
- stQAU economic formulas and slashing (see `node/docs/plans/R123-STQAU-LIQUID-STAKING.md`)

---

## 1. Mainnet contract addresses

> ⏳ R123 stQAU is not yet deployed. Wallet constants are filled in once, after deployment.

```ts
// === after deployment, update all of these constants (address case is irrelevant; RPC responses are authoritative) ===

wqaustqau: 0x????????????????????????????????????????  // R122 WQAU contract
stqau:     0x????????????????????????????????????????  // R123 stQAU contract
pair:      0x????????????????????????????????????????  // WQAU/stQAU pair contract
router:    0x????????????????????????????????????????  // QSwap Router contract
```

**Action required** — immediately after deployment:
1. fill the actual addresses into this document
2. fill the same values into both wallets' `QSWAP_CONTRACTS` (extension `lib/qswap/contracts.ts` / mobile `src/chain/qswap/constants.ts`)
3. the deploy script automatically publishes `qau_getQSwapContracts` via RPC for the deployed Router — wallets then cross-check it at startup

---

## 2. Selector quick reference (ABI level)

> All are standard EVM selectors; wallets encode them once. Zero-arg view selectors and argument-bearing logic selectors are listed side by side.

### ERC20 (shared by WQAU/stQAU/Pair LP tokens)

```
balanceOf(address)            0x70a08231
totalSupply()                 0x18160ddd
decimals()                    0x313ce567
approve(address,uint256)      0x095ea7b3
transfer(address,uint256)     0xa9059cbb
transferFrom(address,address,uint256) 0x23b872dd
allowance(address,address)    0xdd62ed3e
```

### WQAU (wrapped)

```
deposit()                     0xd0e30db0    (payable)
withdraw(uint256)             0x2e1a7d4d
```

### stQAU（R123）

```
deposit()                     0xd0e30db0
withdraw(uint256)             0x2e1a7d4d
claimWithdrawal()             0x6e66d84a
injectRewards()               0x99c722bc    (payable owner)
exchangeRate()                0x3ba0b9a9    (view)
totalBacking()                0xeb2cd258    (view)
withdrawalOf(address)         0x14bf9d2b    (view -> returns three 32B words: owed/unlock/shares)
pauseDeposits()               0x02191980    (owner)
unpauseDeposits()             0x63d8882a    (owner)
transferOwnership(address)    0xf2fde38b    (owner)
owner()                       0x8da5cb5b
name()                        0x06fdde03 → "Staked QAU"
symbol()                      0x95d89b41 → "stQAU"
```

### QSwap Router

```
addLiquidity(uint256 tokenAmt)          0x51c6590a   (payable: QAU sent together with tokenAmt)
removeLiquidity(uint256 lp)             0x9c8f9f23   (needs prior approve(pair, lp))
swapExactQauForToken(uint256 minOut)    0x57924ccd   (payable: QAU in)
swapTokenForQau(uint256 tokenIn, uint256 minQauOut) 0x6de9ca14  (needs approve(router, tokenIn))
getAmountOut(uint256,uint256,uint256)   0x054d50d4   (view-pure: quotes together with reserves)
```

### QSwap Pair

```
getReserves()                 0x0902f1ac   (view -> returns 3 packed uint112/uint112/uint32)
token0()                      0x0dfe1681   (view)
token1()                      0xd21220a7   (view)
totalSupply()                 0x18160ddd   (LP total supply)
balanceOf(address)            0x70a08231   (LP balance)
allowance(address,address)    0xdd62ed3e   (LP allowance)
approve(address,uint256)      0x095ea7b3   (LP approval)
transfer(address,uint256)     0xa9059cbb   (LP transfer)
transferFrom(address,address,uint256)  0x23b872dd   (LP delegated transfer)
skim(address)                 0xbc25cf77
sync()                        0xfff6cae9
pause()                       0x8456cb59   (owner)
unpause()                     0x3f4ba83a   (owner)
```

---

## 3. RPC calling patterns

Wallets use **only** the following RPC methods (whitelisted in PublicMethods in `rpc/auth.go`):

| Method | Usage ||
|---|---|
| `eth_call` | all view calls: reserves / totalSupply / balanceOf / getAmountOut / exchangeRate / withdrawalOf etc. ||
| `eth_sendRawTransaction` | all state-changing transactions (RLP encoding, Dilithium3 signing) ||
| `eth_getTransactionReceipt` | post-broadcast confirmation (must wait for `status == 0x1`; anything else is a failure) ||
| `eth_getBalance` | native QAU balance ||
| `qau_getQSwapContracts` | fetch deployed contract addresses at startup and cross-check against hardcoded constants (R122+ RPC anchoring) ||
| `eth_estimateGas` | gas estimation (the UI routinely adds a 30% buffer; monitor large-value paths) ||
| `net_version` | chainId read (expect `1668`) ||
| `eth_blockNumber` | block height for polling ||

**Forbidden**: wallets must never call admin RPCs (`qau_resetEpochKeys` etc.). All carry the `qau_admin` prefix and have no public access mechanism.

---

## 4. Transaction construction (Proto/RLP encoding)

### Structure and construction steps

```
TxType:   0x01 (Contract)
From:     the user's address
To:       the 20-byte contract address
Value:    in wei
Data:     selector + ABI-encoded args
GasLimit: chosen by the UI (based on eth_estimateGas, explicitly +30%)
GasPrice: dynamic in the wallet (never hard-coded)
Nonce:    strictly consistent on-chain nonce (duplicate transactions can run through => see §5)
ChainID:  1668
```

### Example: `swapExactQauForToken(0.5 QAU for stQAU)`

```
Data:
  57924ccd                                    ← selector
  0000000000000000000000000000000000000000000000000a968163f0a57b400  ← minOut = 0.5 * 0.95 * 1e18

TX:
  Type = 0x01
  To = router
  Value = 0.5 QAU in wei (qaToWei)
  Data = as above
  ...
```

### Example: `addLiquidity` (WQAU/stQAU pool at a 1:1 ratio)

```
// Step 1: <stqau.approve(router, tokenAmt)>
Data(selector=095ea7b3) + pad32(router) + pad32(tokenAmt)
to = stqau contract, value = 0

// Step 2: router.addLiquidity(tokenAmt) carrying QAU
Data(selector=51c6590a) + pad32(tokenAmt)
to = router, value = <the staked QAU amount>
```

### Failure handling (mandatory)

- RPC returns `"status": "0x0"` (reverted) -> **no funds were deducted** (the contract reverted the transaction)
- The UI shows a "transaction reverted" indicator + gas already spent, clearly telling the user:
  ```
  the transaction was rolled back, QAU/stQAU not deducted;
  only X gas was spent (= gasUsed × gasPrice);
  possible causes: min-out too tight / insufficient liquidity depth /
  ```

---

## 5. Safety collaboration and DoS protection

### User funds (loss prevention)

| Rule | Note ||
|---|---|
| `eth_estimateGas` + 30% buffer | on estimation failure the UI does not auto-retry ||
| max single-input limit | the UI checks `amount <= pool reserves × 5%` (filtering trades with excessive price impact) ||
| slippage floor | user selection × automatic getAmountOut -> `minOut`, enforced on-chain ||
| double confirmation | after building the tx the UI shows a "final confirmation" step whose content matches the on-chain calldata exactly ||
| exact approvals | swaps never grant `MaxUint256`; re-approve when the balance is insufficient ||

### Wallet UX is not always pretty, but these must never be compromised

| Rule | Reason ||
|---|---|
| user cancels the double confirmation -> nonce already consumed (the next retry after broadcast uses nonce+1) | replay must be prevented ||
| RPC drops -> the UI surfaces "connection failed" as a hard error | never fall back to stale data ||
| `qau_getQSwapContracts` conflicts with hardcoded constants -> disable the entire feature | security-level error ||

---

## 6. Error-code / failure-scenario mapping

| Failure scenario | RPC response | Required UI message ||
|---|---|---|
| insufficient balance | HTTP 200, result: `{jsonrpc error: -32602, message: "insufficient balance"}` | "Insufficient balance — X QAU short" ||
| invalid signature | `-32003 unauthorized user` | "Signature verification failed; retry or contact support" ||
| chainId mismatch | the chainId is bound into the signed byte domain | "Wrong network; switch to the Quantaureum mainnet" ||
| node-internal error (duplicate nonce stake / underpriced replacement) | `-32603 Internal error` (sanitized in production) | "A pending stake transaction may be stuck; do not resubmit — refresh later" ||
| contract revert | receipt status=0x0 | "Transaction reverted; nothing deducted (except gas)" ||
| insufficient liquidity | pre-checked in the UI; an on-chain error is not expected | "Insufficient liquidity depth; reduce the amount" ||
| RPC timeout | fetch failure | "Network latency; check balances and history later" ||

### On-chain confirmation of stake transactions (a hard requirement after R124-STAKE-P2P)

The `txHash` returned by `qau_stake` **only means the transaction entered the node's queue**, not that it was included. Wallets must:
1. poll `eth_getTransactionReceipt` after submission (recommended: 1.5s interval, 15s timeout)
2. receipt received -> show "confirmed on-chain"
3. timeout without receipt -> honestly show "submitted, awaiting on-chain confirmation"; never report success outright

> History: before R124, validators dropped stake transactions at the p2p entrance (a leftover R37 defense), and mainnet saw
> "submitted but never included" incidents (fixed 2026-09-07; see R124-STAKE-P2P in the node repo).

---

## 7. Account-state effects of each operation

| Operation | On-chain effect | gas ||
|---|---|---|
| `stqau.deposit()` | QAU -> stQAU mint, immediately in the user's balance | ~80k ||
| `stqau.withdraw()` | starts the 21-day redemption queue | ~100k ||
| `stqau.claimWithdrawal()` | completes redemption; QAU returns to the account | ~60k ||
| addLiquidity -> LP | the user's QAU leaves; LP minted to the wallet | ~200k ||
| `swapExactQauForToken` | instant QAU -> stQAU swap | ~120k ||
| `swapTokenForQau` | stQAU -> QAU swap | ~120k ||

---

## 8. Roadmap

- **Current v1 (this spec)**: single WQAU/stQAU pool; manually fixed pair; no Factory
- **QSwap v2 (R125, in development)**: multi-pool Factory + Router routing. Wallets will then need:
  - a hop indicator in the swap UI
  - a pool-selector control
  - pool contract addresses no longer fixed — fetched at runtime from `factory.getPair(tokenA, tokenB)`
- **R126+ (governance)**: QSwap parameters change via DAO proposals — wallets do not implement governance; they only link proposals to a browser

---

## 9. References

- R122 design and end-to-end smoke-test report: `node/docs/plans/R122-QSWAP-QASM-AMM.md`
- R123 plan and Phase 1 completion checklist: `node/docs/plans/R123-STQAU-LIQUID-STAKING.md`
- External-flow smoke test: `node/cmd/qswap_smoke/main.go`
- Extension integration plan: `extension/docs/roadmaps/QSWAP-STQAU-EXTENSION-INTEGRATION.md`
- Mobile integration plan: `mobile/docs/roadmaps/QSWAP-STQAU-MOBILE-INTEGRATION.md`

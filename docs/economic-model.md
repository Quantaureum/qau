# Quantaureum economic model design document

> **Version**: v3.0 (EM-2) — **implemented**. v1.0 is void (see §1); v2.0's two blocking errors are fixed (see §14)
> **Status**: landed in the consensus layer; takes effect at chain reset
> **Code impact**: `consensus/` has been changed per this document. Effective after the chain reset — pre-reset blocks follow the old rules; the two are incompatible
> **Reproducibility**: every number here was computed by `cmd/econsim`; commands in §10. Simulator-vs-consensus consistency is locked wei-for-wei by `consensus/econ_model_parity_test.go`
> **Related**: `economics/model/` (simulator), `consensus/block.go` (constants), `consensus/epoch.go`, `consensus/epoch_rewards_census.go`, genesis `genesis/mainnet.json`

---

## 0. Summary

| Item | Conclusion ||
---|---||
| Supply cap | **none** (strictly like Ethereum). 20,000,000 QAU issued at genesis; thereafter issuance scales with stake ||
| Issuance function | isomorphic to Ethereum Altair: per validator `baseReward = stake·F / √(totalStake)`; total issuance = Σ baseReward ||
| Calibration constant | **F = 31** (the incumbent was F=2 with the phase0 `/4` divisor) ||
| Reward split | attester **87.5%** / proposer **12.5%** (8/64 weights), decoupled from validator count ||
| Fees | baseFee **100% burned**; priorityFee to the proposer ||
| Long-run shape | equilibrium staking APY ~3%, gross inflation ~1%/yr; with burn at 0.8% of supply per year, net inflation ~ +0.25% ||
| Defects fixed | near-zero issuance (1,560 QAU/yr) and proposers taking 84.2% — both fixed in the consensus layer (§9) ||

In one line: **do it the Ethereum way — lift issuance from "nearly zero" to "the 1% range", and lift attestation pay from 15.8% back to 87.5%**.

---

## 1. Why v1.0 is void

v1.0 rested on three judgments disproved by measurement. None of the three is a matter of interpretation — they were miscalculations.

| # | v1.0 claimed | Measured | Root cause ||
---------|---||||
| 1 | current annual issuance ~1,560,000 QAU, inflation 7.8%, "issuing too much, tighten" | annual issuance **1,560 QAU**, inflation **0.008%** — the opposite direction | `node/block_producer.go` logs in **qau-wei**. That "19" was `1.9e16 wei = 0.019 QAU`, not 19 QAU. A 1000x unit misread ||
| 2 | 100,000,000 QAU hard cap + exponential tail issuance | zero enforcement in code, and the user had already decided **strictly Ethereum = no cap** | v1.0 took the stale 100M description in AGENTS.md as settled; the genesis mint was actually 20M ||
| 3 | calibration constant `c = 0.0021` (a self-invented `c×√S` formula) | Ethereum's formula is `stake·F/√(totalStake)`; the parameter is F, not c | v1.0 invented a formula not isomorphic to the consensus implementation, impossible to align with `consensus/epoch.go` ||

> **Correction record**: this round of solving at one point produced `F=137`, which is equally invalid — it implicitly kept the phase0 `BaseRewardsPerEpoch=4` divisor. Under strict Altair (the divisor folded into the weight table = 1) the correct answer is **F=31**.

The simulator pins the historical 1.9e16 wei issuance baseline so the unit misread can never recur.

---

## 2. Pre-change mainnet baseline (computed; historical)

> This section describes behavior **before EM-2** (r105 and earlier), kept as a contrast baseline and a unit-misread tripwire. Current chain parameters are in §4/§5. In the simulator this is `PreEM2MainnetParams()`, CLI `-preset pre-em2`.

Parameter sources (pre-change): `consensus/block.go:46` (F=2), `consensus/epoch.go:556` (the combined divisor 4), `consensus/epoch_rewards_census.go` (one attester reward per validator per epoch; one full proposer reward per attested block slot).

```
6 validators × 6,000 QAU = 36,000 QAU total stake
  epoch issuance  0.019000 QAU  (= 19,000,000,000,000,000 wei, digit-for-digit identical to the pinned historical baseline)
  annual issuance 1,560.4 QAU
  staking APY     4.334%
  attester share  15.8%
  proposer share  84.2%
```

Chain timing: 32 slots × 12 s = 384 s/epoch -> **82,125 epochs/year** (at 365.00 days; a true 365.25-day year gives 82,181, a 0.07% deviation with no bearing on the conclusions below).

---

## 3. Two structural defects (fixed)

> Both are fixed in §9. The full diagnosis is retained because the reasoning chain "why F must change together with the divisor and the proposer structure" is a precondition for any future parameter adjustment.

### 3.1 F=2 drives yield to zero at any meaningful scale ✅ fixed (F=31)

The calibration comment at `consensus/block.go:41-46` claimed "with 6 validators × 30,000 QAU, F=2 yields ~9.8% APR". That figure held only under the old semantics of **rewarding each validator once per slot** (32 times/epoch). After `CONS-R8-001` fixed double counting and switched to once per epoch, issuance was silently cut 32x **without recalibrating F**. The comment therefore overstates the implementation by 32x (`TestStaleCalibrationComment` reproduces this).

The consequence is scale collapse:

| Total stake (QAU) | Validators | APY ||
---|---||---|
| 36,000 | 6 | 4.334% |
| 600,000 | 100 | 0.221% |
| 6,000,000 | 1,000 | 0.055% |
| 18,000,000 | 3,000 | 0.031% |

**At any meaningfully decentralized scale, staking yield is effectively zero — nobody will stake.**

### 3.2 proposer weighting is deformed; attestations systematically undervalued ✅ fixed (8/64 weights)

The incumbent code gives each attester 1 baseReward per epoch but the proposer **one per proposed slot** (32 per epoch). So the proposer share = `32/(N+32)`, and **total issuance couples to validator count** (N up -> issuance up, which should never happen).

| Validators | Proposer share ||
---|---||
| 6 | 84.2% |
| 100 | 24.2% |
| 3,000 | 1.1% |
| Ethereum | constant 12.5% ||

Attesting is what drives finality — the very thing R101-R105 just fixed — yet it receives only 15.8%, **undervalued 5.54x** against the 87.5% target (0.875 ÷ 0.15789). Note that 5.33 is the proposer-to-attester ratio, not this undervaluation multiple; do not conflate the two.

> The 84.2% and 0.019 QAU above are the **full-participation ceiling**. Missed slots, unattested blocks, and absent validators all depress total issuance and the proposer share together. Agreement with the mainnet log means current participation is 100% — an empirical fact, not an identity.

> Side finding: `ProposerRewardQuotient = 8`, declared at `consensus/block.go:47`, has **zero references** in the codebase. Ethereum's intent was declared; the implementation never caught up. `TestProposerRewardQuotientIsDeadConstant` pins this fact so nobody reuses it by name later — it is the name of a different phase0-era quantity, not to be reused literally.

---

## 4. EM-2: strictly following Ethereum Altair

```
Per validator per epoch:
  baseReward = stakeGwei × F / ( isqrt(totalStakeGwei) × D )      D = 1

Total epoch issuance:
  I_epoch    = Σ baseReward(each validator)

Distribution:
  proposer  = I_epoch × 8/64   = 12.5%
  attester  = I_epoch × 56/64  = 87.5%
```

Three differences from the incumbent implementation, all **converging toward Ethereum**:

| Item | Incumbent | EM-2 ||
---|---||---|
| `BaseRewardFactor` | 2 | **31** |
| `BaseRewardsPerEpoch` (divisor) | 4 (phase0 legacy) | **1** (Altair folds it into the weight table) ||
| proposer pay | one full share per proposed slot | **an 8/64-weight slice of the total** ||

All three must change **together**. Changing F alone without the proposer structure would proportionally amplify the deformed 84.2% share.

**Properties:**
- Total issuance decouples from validator count (`TestIssuanceIndependentOfValidatorCount`)
- APY ∝ 1/√S: doubling the stake drops APY to 71% (`TestAPYScalesAsInverseSqrt`), countering the "first-mover snowball"
- The proposer share is constant at 12.5%, not drifting with N

### 4.1 Per-validator attribution rules (required for implementation)

The formulas above answer "how much does the protocol issue this epoch". The consensus implementation must also answer "how much does each account gain", and integer division truncates per validator. Following Altair, each validator's baseReward is split on the spot into two parts:

```
For each validator v:
  toProposerPool(v) = baseReward(v) × 8  / 64      <- truncated
  toSelf(v)         = baseReward(v) × 56 / 64      <- truncated
proposerPool = Σ toProposerPool(v)
Total issuance        = Σ baseReward(v)
```

**Truncation loss is exactly zero** — provable, not coincidental: baseReward is produced at gwei granularity (the formula multiplies 1e9 back in at the end), and 64 divides 1e9 (1e9 = 2^9 x 1953125), so splitting a gwei-granular quantity by x/64 leaves no remainder. **Hence the consensus implementation can equal the simulator wei-for-wei, not merely "approximately".**

If `WeightDenominator` is later changed to a value that does not divide 1e9, dust becomes non-zero but strictly below `WeightDenominator` wei per validator (two truncations per validator, each losing one remainder). `TestAttributionDustIsBounded` locks both assertions — "it is 0 now" and "even if changed, never above this bound" — and fails loudly when the precondition breaks, prompting a sync of this section and the implementation.

How proposerPool splits among per-slot proposers is a consensus responsibility, not a monetary-policy question, and this document does not prescribe it; but the split must be a pure function of the on-chain census, or we return to the pre-R59-CENSUS-PROP world that forked.

---

## 5. Solving for F = 31, and sensitivity

Solving target: APY ~4% at 4,000,000 QAU staked (the bootstrap band), converging to 3% at equilibrium.

| Target APY @4M stake | F | Annual issuance ||
---|---||---|
| 3% | 24 | 124,595 QAU |
| **4%** | **31** | **160,935 QAU** |
| 5% | 39 | 202,466 QAU |

Why 31: Ethereum's pure-issuance yield at 30M ETH staked computes to **3.035%**, pinned by `TestEthereumGroundTruth` (annual issuance 910,356 ETH, gross inflation 0.759%, proposer exactly 12.5%). F=31 lets QAU start at 4% and converge naturally to the same band as stake grows, leaving no inflation legacy.

> **v2.0 of this document originally said 3.2% here — that was wrong.** 3.2 was the tolerance target constant in `approx(..., 0.032, 0.10)`; the ±10% band (2.88%-3.52%) can hide a 0.5-percentage-point error, and I quoted it as a computed value. The assertion is now tightened to `0.03035 ± 1%` so the document can quote the computed value verbatim. Observed beacon-chain APR is ~3.0-3.3%; the excess above pure issuance comes from real participation and MEV, neither of which is in this model.

**The absolute cost of the bootstrap bonus** (a harder argument than "the √ curve decays naturally"): 42.43% APY at 36,000 QAU staked sounds alarming, but the absolute issuance is only **15,275 QAU/year = 0.076% of total supply**. The ceiling on early-APY cost is tiny, and `TestAPYScalesAsInverseSqrt` guarantees monotonic √S decay without manual intervention. The real risk was never high early APY — it is APY collapsing to zero at scale (§3.1).

Full-range behavior of F=31:

| Total stake (QAU) | Validators | QAU/epoch | Annual issuance | APY | Per validator/year ||
------------|---||||---||
| 36,000 | 6 | 0.1860 | 15,275 | 42.43% | 2,546 |
| 120,000 | 20 | 0.3396 | 27,889 | 23.24% | 1,394 |
| 600,000 | 100 | 0.7593 | 62,361 | 10.39% | 624 |
| 3,996,000 | 666 | 1.9596 | 160,935 | 4.03% | 242 |
| 9,996,000 | 1,666 | 3.0994 | 254,537 | 2.55% | 153 |
| 19,998,000 | 3,333 | 4.3838 | 360,023 | 1.80% | 108 |
| 60,000,000 | 10,000 | 7.5934 | 623,609 | 1.04% | 62 |

The early 42% is a **bootstrap bonus** that disappears automatically as stake grows, no intervention needed — that is exactly what the √ curve is for.

---

## 6. Long-run projection

Assumptions: 20M initial supply, 35% of float staked, 6,000 QAU per validator, the 15M genesis linear-vesting lock unlocking yearly per `MainnetVesting()`, burn = 0.8% of supply per year.

> **How heavy the 0.8% assumption is**: 0.8% × 20M = 160,000 QAU/year. In gas terms this is **gas target saturated + baseFee ~4.06 gwei** (or block limits saturated + ~2.03 gwei). For contrast, with the gas target saturated but baseFee stuck at the 1 gwei floor, annual burn is only 39,420 QAU = 0.197% of supply. So 0.8% describes an **already busy chain**, not a cold start — the early years will not reach it.

| Year | Supply | Float | Staked | Validators | Issued | Burned | Net | APY | Gross infl. | Net infl. ||
---------------|---||---||---||---||---||---|
| 1 | 19,946,380 | 5,000,000 | 1,746,000 | 291 | 106,380 | 160,000 | −53,620 | 6.09% | 0.532% | −0.268% |
| 3 | 19,933,125 | 12,192,919 | 4,266,000 | 711 | 166,283 | 159,410 | +6,873 | 3.90% | 0.834% | +0.034% |
| 5 | 20,011,833 | 19,163,118 | 6,702,000 | 1,117 | 208,420 | 159,705 | +48,715 | 3.11% | 1.044% | +0.244% |
| 10 | 20,275,037 | 20,222,693 | 7,074,000 | 1,179 | 214,126 | 161,782 | +52,344 | 3.03% | 1.059% | +0.259% |
| 20 | 20,790,560 | 20,739,644 | 7,254,000 | 1,209 | 216,833 | 165,917 | +50,916 | 2.99% | 1.046% | +0.246% |

**After 20 years, total supply is 20,790,560 QAU (+3.95%)**. The first two years are net-deflationary because vesting constrains float and stake is small; from year 3 on it turns to mild net inflation, settling near +0.25%.

> **Two things to know before reading this table.**
>
> **(a) Year 1 is not the chain's current state.** Year 1 in the table is 291 validators / 1,746,000 QAU staked — 48x the current 6 validators / 36,000 QAU. That comes from the **exogenous assumption** `StakeRatioOfFloat = 0.35` (float 5M × 35% ÷ 6,000 = 291), not a forecast. Likewise §5 calling 4,000,000 QAU the "bootstrap band" refers to the calibration anchor, not the chain's current position.
>
> **(b) The "float" and "supply" columns use different conventions**: `FloatWei` = supply at **year start** minus locked, while `SupplyWei` is at **year end**. So in year 20, with vesting long finished (max 5 years), the float 20,739,644 is still 50,916 below the supply 20,790,560 — the difference equals that year's net issuance, **not 50k QAU still locked**.

Zero-burn contrast (pure issuance): 24,197,544 QAU after 20 years (+20.99%), gross inflation stable at ~1.0%/yr.

Fee activity required for net-zero supply (F=31, 4M staked, 21,000 gas/tx, annual issuance 160,935 QAU = 440.9 QAU/day):

| baseFee | QAU burned per tx | tx/day for net zero ||
---|---||---|
| 10 gwei | 0.000210 | 2,099,605 |
| 100 gwei | 0.002100 | 209,960 |
| 300 gwei | 0.006300 | 69,987 |
| 1,000 gwei | 0.021000 | 20,996 |

**But this table is a conditional statement, not a roadmap**. Real baseFee is not a free parameter: it is determined by demand relative to the gas target. The chain's gas target is 15,000,000/block × 2,628,000 blocks/year = 39.42e12 gas/year, which takes **5,142,857 tx/day** (21,000 gas/tx) to exactly saturate. Below that, EIP-1559 lowers baseFee on every under-full block, pressing it all the way down to the 1 gwei floor (`params.MinGasPrice`; the txpool rejects cheaper transactions).

So row 3 above, "300 gwei + 69,987 tx/day", is physically impossible: 69,987 tx/day is only 1.4% of target capacity, and under that load baseFee is necessarily 1 gwei, not 300. Running the same inputs with `-fee-market` (50,000 tx/day, 40% annual growth, 12 years):

| Year | Supply | Utilization | baseFee | Burned | Net inflation ||
------------|---||||---||
| 1 | 20,105,997 | 0.97% | 1 gwei | 383 QAU | +0.530% |
| 6 | 21,030,718 | 5.23% | 1 gwei | 2,061 QAU | +1.034% |
| 12 | 22,310,402 | 39.37% | 1 gwei | 15,520 QAU | +0.943% |

After 12 years: +11.55%, **no deflation**. The same inputs computed at a fixed 300 gwei yield "12 years burns 69% of supply" — that is a model defect, not a forecast. See §11.1.

The real threshold for net deflation: **daily transactions in the millions** (approaching the gas target), only then does baseFee leave the floor. That is a product goal, not something monetary policy can schedule.

---

## 7. Fees and burning

```
txFee = gasUsed × (baseFee + priorityFee)
  baseFee     -> 100% burned (permanently out of circulation, credited to no account)
  priorityFee -> to the proposer
```

- baseFee adapts to block utilization (EIP-1559-isomorphic: parent full -> child +12.5%; empty -> −12.5%)
- The burn path **skips the credit entirely** in the state transition; balances of `0x0`/`0xdead`-style addresses must not be written (otherwise supply reconciliation counts burned coins as owned)
- An RPC like `qau_getSupply` should expose cumulative `totalIssued` / `totalBurned` for audit and reconciliation

v1.0's "80/20 tip split to attesters" is **cancelled**: EM-2 already pays attestations amply via the 87.5% issuance weight; splitting tips again would be duplicate design, and Ethereum does not do it.

---

## 8. Why no hard cap

User decision: strictly follow Ethereum; no cap. The reasoning is sound and deserves to be written out:

1. **Perpetual security budget**. A hard cap necessarily drives the block subsidy toward zero — Bitcoin's unresolved security-budget question is a consequence of exactly that structure. No cap + √-decaying issuance keeps the security budget tied to stake forever.
2. **The hard-cap narrative buys nothing**. Ethereum has no hard cap and the market has not punished it for that; real scarcity comes from baseFee burn offsetting issuance, not a number written in a document.
3. **The 100M was never enforced in code**. v1.0's 100M was a stale AGENTS.md description (the same document elsewhere already noted "the old doc's 100M is outdated"; the genesis mint was 20M). Writing an unimplemented, unpromised number up as a hard constraint is shackling yourself for nothing.

External-messaging discipline: QAU is a **gas token + network-security incentive**; no "hold to profit" phrasing.

---

## 9. Implementation status

**Implemented (2026-08-31).** The consensus layer was changed directly and the chain was reset before external users depended on the old transition path.

### 9.1 The decision not to add an epoch gate

The R102/R103-style `weightedProposerCutover` gate was **not adopted**. A gate exists to protect existing on-chain users; that premise vanishes after a reset, and a gate that never flips is dead code — `ProposerRewardQuotient` is exactly how that ends: declared, commented as if in use, actually zero references, misleading for months.

### 9.2 Actual changes

| File | Change ||
---|---||
| `consensus/block.go` | `BaseRewardFactor` 2 -> **31**; added `BaseRewardsPerEpoch = 1`, `ProposerWeight = 8`, `WeightDenominator = 64`; **removed** `ProposerRewardQuotient` ||
| `consensus/epoch.go:397` and `:557` | bare literal `big.NewInt(4)` -> `big.NewInt(BaseRewardsPerEpoch)`. **Both places** ||
| `consensus/epoch_rewards_census.go` | attester changed from "one full baseReward" to `×56/64`; proposer changed from "one full share per slot" to a two-pass scan: first accumulate the pool `Σ baseReward×8/64`, then split evenly across attested block slots ||
| `consensus/ministry_revenue.go` | removed the dead constant `DefaultBaseRewardFactor = 2`; added known-divergence warnings to `DefaultProposerRewardShare` etc. ||
| `economics/model/model.go` | `LiveMainnetParams` -> `MainnetParams` (EM-2); the old values kept as `PreEM2MainnetParams` (historical anchor) ||

**Promoting the divisor to a named constant is the root-cause fix for B1** (see §14): it was originally two duplicated bare `4`s, and "change the divisor" is precisely the kind of action that changes only one of them — which produces a silently wrong issuance, not a compile error.

### 9.3 The proposer pool's two-pass scan

The only structure in the change that needs explaining:

```
First pass (attestation loop): accumulate proposerPool += baseReward(v) × 8/64
Second pass (slot loop):        collect attested block slots -> the pool splits evenly across them
```

The accumulation must complete before distribution because the pool is a fixed 8/64 of total issuance. Pay-as-you-go is exactly the coupling EM-2 eliminates — it would make issuance a function of "however many blocks happened to be produced this epoch".

Two details:
- **The division remainder goes to the earliest slot**, never discarded. Discarding would re-couple total issuance to slot count in the last few digits.
- **If not a single slot was proposed, the pool is not issued**, consistent with the attester side: unearned issuance is not created — neither rolled over nor stuffed to some validator.

### 9.4 Not yet implemented (outside this round's scope)

| Layer | Item ||
---|---||
| L2 `qaudb/state` | `totalIssued` / `totalBurned` persistence ||
| L7 `rpc/` | `qau_getSupply` |
| L3 | two contradictory fee-policy modules (see the warning below) ||
| **L6 `txpool`** | **burn covers only 1 of 10 transaction types** (see BURN-GAP below) ||

> ✅ **baseFee burn is implemented** (previously mis-listed here as pending; corrected). The actual charge is at
> `txpool/executor.go:563-580`: the sender is charged `gasUsed × effectiveGasPrice`, while
> coinbase receives **only** `priorityFee = gasUsed×(effectiveGasPrice − baseFee)`.
> The baseFee portion enters no account — that is the burn. The comment at `economics/gas_fees.go:120-126` is
> correct; it was this document's v3.0 first draft that was wrong.

> 🔴 **BURN-GAP (identified during integration testing 2026-08-31; needs a ruling)**: the burn branch at `txpool/executor.go:566`
> is gated on `isDynamicFee`, where `isDynamicFee := tx.Type == TxTypeDynamicFee`
> (`txpool/executor.go:421`). `encoding/proto.go:45-56` defines **10 transaction types**, so:
>
>
| | Transaction type | Burns baseFee? ||
> ---|---||
| | `TxTypeDynamicFee`(5) | ✅ yes ||
| | `TxTypeTransfer`(0), `TxTypeContract`(1), `TxTypeCreate`(2), `TxTypeStake`(3), `TxTypeUnstake`(4), `TxTypeBlob`(6), `TxTypeMultiSig`(7), `TxTypePrivacy`(8), `TxTypeCommit`(9) | ❌ no — **100% of the fee goes to the proposer** ||
>
> **Impact**: all burn projections in §6/§7 (0.8%/yr, net inflation +0.25%) presuppose "every gas expenditure burns
> its baseFee". In reality a plain **QAU transfer** (`TxTypeTransfer`) burns nothing and the full fee lands in
> the proposer's pocket. If the dominant flow is not type-5, real net inflation is markedly higher than the table, the ceiling being the "zero burn"
> column (§6 gives it separately: 24,197,544 QAU / +20.99% over 20 years).
>
> **Deviation from Ethereum**: after London, Ethereum burns baseFee from gasPrice on **all** transaction types
> (legacy type-0 included). Quantaureum currently does it only for type-5 — a substantive deviation,
> not a stylistic one. `TxTypeBlob` being missed is especially suspicious — the comment at `node/node.go:7580` lists
> `TxTypeDynamicFee/TxTypeBlob` side by side as EIP-1559, yet the executor recognizes only the former.
>
> **Why not fixed unilaterally**: extending burn to all types changes the state transition of legacy transactions (proposer
> income down, sender net spend unchanged) — an economic-policy change, not a pure bug fix, and requires explicit authorization. The chain-reset
> window is the lowest-cost moment to do it.

> ⚠️ **The repo contains two fee policies contradicting this document, and both are live**:
> - `economics/gas_fees.go:75-96`: Burn 10% / Proposer 30% / ValidatorPool 20%, and `CalculateBurnRate` is a four-year ladder of 10%->20%->35%->50%.
> - `economics/fee_distribution.go:35-44`: Validator 60% / **Burn 15% / Treasury 10% / Developer 10% / Insurance 5%** — precisely the treasury split D6/D8 claim was "rejected", and `node/node.go:2155` hard-wires the three accounts to account8/account6/account4.
>
> `node/node.go:2198` calls `em.SetFeeDistributor`, and `node/node.go:7610/7618` invoke it on **every committed block**. Per the comment at `node/node.go:7561` this path is **bookkeeping only, no StateDB changes**, so balances are right — but it feeds the Economics RPC, so **the chain's externally reported fee split disagrees with "100% burn, no treasury"**.
>
> The "self-contradictory comment" question is **resolved by following the code**: `economics/gas_fees.go:120-126` is right, and the burn is indeed implemented at `txpool/executor.go:563-580` (not in `qvm/`). But it covers only `TxTypeDynamicFee` — see BURN-GAP above.

### 9.5 Chain reset

Old and new rules are incompatible (a 9.8x issuance difference for the same epoch), so a reset is mandatory:

```bash
# Per validator: stop the node -> wipe blocks + state -> deploy the new binary -> start the node
# validator.key must match the new genesis (AGENTS.md: "validator.key must be replaced after a chain reset")
```

The first post-reset epoch should show `total=186000000000000000 qau-wei` (6 validators × 6,000 QAU). Seeing `19000000000000000` means the old binary is still running.

| Layer | Module | Change ||
---|---||---|
| L5 | `consensus/block.go:46` | `BaseRewardFactor` 2 → 31 |
| L5 | `consensus/epoch.go:397` **and** `consensus/epoch.go:557` | divisor 4 -> 1. **Both places** ||
| L5 | `consensus/ministry_revenue.go:17` | `DefaultBaseRewardFactor = 2` (the second dead constant, with the same stale comment) — sync or delete ||
| L5 | `consensus/block.go:47` | `ProposerRewardQuotient` deleted or properly used ||
| L5 | `consensus/epoch_rewards_census.go:196-229` | proposer pay changes from "one full share per slot" to the §4.1 per-validator 8/64 split ||
| L5 | `consensus/ministry_revenue.go:14-16` | `DefaultProposerRewardShare/Attester/Sealer = 8/1/4` are **live** (used for governance audit records). After the census moves to 8/64, this audit record will diverge from actual payouts and must be synced ||
| L4 | `qvm/` | baseFee burn path (skip the credit); priorityFee routed to the proposer ||
| L3 | `economics/gas_fees.go:75-96` and `economics/fee_distribution.go:35-44` | **two fee policies directly contradicting this document**, see the warning below ||
| L2 | `qaudb/state` | persistence of cumulative `totalIssued` / `totalBurned` ||
| L7 | `rpc/` | `qau_getSupply` |
| L1 | `types/` | if an epoch gate is adopted: new economics-parameter struct + genesis field ||

> ⚠️ **The first draft of §9 wrote the divisor's location wrong; building to that text yields 1/4 of the issuance.** It said "`consensus/block.go`: F 2->31; divisor 4->1", but `block.go` contains **no divisor constant** — the literal `4` is hardcoded in two places, `epoch.go:397` and `epoch.go:557` (each `big.NewInt(4) // BASE_REWARDS_PER_EPOCH = 4`), not a named constant. Changing only F and missing the divisor gives an epoch issuance of `6e12x31/(6e6x4) = 0.0465 QAU` at 36,000 QAU staked instead of the `0.1860 QAU` in the §5 table; annual issuance 3,819 instead of 15,275, APY 10.6% instead of 42.43%. §9 is the sole implementation contract; writing it wrong is the direct cause of "half-applied change" incidents.

> ⚠️ **The repo contains two fee policies contradicting this document, and both are live**:
> - `economics/gas_fees.go:75-96`: `DefaultGasFeeConfig` = Burn 10% / Proposer 30% / ValidatorPool 20%, and `CalculateBurnRate` is a four-year ladder of 10%->20%->35%->50%.
> - `economics/fee_distribution.go:35-44`: `DefaultFeeDistributionConfig` = Validator 60% / **Burn 15% / Treasury 10% / Developer 10% / Insurance 5%** — precisely the treasury split D6/D8 claim was "rejected", and `node/node.go:2155` hard-wires the Treasury, Developer, and Insurance destinations to configured accounts.
>
> They are **not dead code**: `node/node.go:2198` calls `em.SetFeeDistributor`, and `node/node.go:7610/7618` invoke `ProcessEIP1559Block`/`ProcessBlock` on **every committed block**. Per the comment at `node/node.go:7561`, this path is **bookkeeping only (no StateDB changes)**, so it does not move real balances. But it feeds the Economics RPC, meaning **the chain's externally reported fee split disagrees with this document's "100% burn, no treasury"**. During implementation, pick one: align these configs with D6/D7/D8, or remove them from the assembly.
>
> On "is the burn implemented at all": **confirmed by following the code — yes**, at `txpool/executor.go:563-580`, not in `qvm/` (the claim in `economics/gas_fees.go:120-126` is correct). But it applies **only to `TxTypeDynamicFee`**; the other 9 types burn zero — see the BURN-GAP in §9.4. All burn projections below this point presuppose "all traffic is type-5".

**The switching mechanism reuses the existing R102/R103 paradigm** (`weightedProposerCutover` at `consensus/block.go:419`): a `uint64` field on QPOS, default `math.MaxUint64` = never activates, enabled via a setter from node config, with the pre-cutover code path **byte-for-byte identical** to the old behavior. No new gate is invented. Activation requires >=5/6 validator-signed announcement + binary distribution to all nodes + a >=7-day notice period, atomically effective at a designated epoch boundary, with the legacy path fully retained for rollback.

**Porting recipe (the line-by-line checkable kind):**

1. `calculateBaseRewardEM2Unlocked` = the arithmetic of the existing `CalculateBaseReward` with only `BaseRewardFactor` -> 31 and the combined divisor's 4 -> 1. The truncation order must not change (multiply first, then a single division, R46-CS-05).
2. Attester: no longer a full baseReward; pay `baseReward × 56/64`.
3. Proposer: no longer a full share per slot; accumulate the pool `Σ baseReward(v) × 8/64`, then attribute per the census's per-slot proposer table.
4. Penalties (inactivity 2x baseReward) are outside this change's scope; untouched.

**Parity strategy**: the three existing cases in `consensus/econ_model_parity_test.go` pin the LIVE parameters. Add an EM-2 case asserting that the consensus's per-validator attester amounts and the proposer pool are **wei-for-wei equal** to `model.EpochIssuanceAttributed` (zero dust makes this feasible, §4.1). `TestProposerRewardQuotientIsDeadConstant` will fail the day the census is fixed — that is a designed signal; change it then.

> **Change impact**: at the current stake level (36,000 QAU), epoch issuance goes 0.019 -> **0.186 QAU**, and validator yield **rises ~9.8x**. This is the opposite of v1.0's forecast of a "98% yield crash" — because v1.0's baseline number was off by 1000x. Validators are not harmed by this change; no soothing announcement is needed. The announcement copy must be rewritten accordingly.

---

## 10. Simulator and reproducibility

Code locations:

| Path | Role ||
---|---||
| `economics/model/model.go` | issuance formulas, parameter presets (live / eth / legacy), fee model, per-validator attribution (`EpochIssuanceAttributed`) ||
| `economics/model/projection.go` | multi-year projection, vesting unlocks, endogenous 1559 fee market, F solving, net-zero-burn solving ||
| `cmd/econsim/` | CLI：`current` / `compare` / `table` / `project` / `solve` / `breakeven` |
| `consensus/econ_model_parity_test.go` | **locks the simulator to `QPOS.CalculateBaseReward` wei-for-wei** (caveat: no slashed members in the validator set, see §11.2 #5) ||

Layering discipline: `economics/model` sits at L3 and **must not import `consensus`** (L5); the formulas are re-implemented, not called, avoiding a reverse dependency; parity tests guarantee no drift. All token arithmetic uses `math/big` integers with truncation order matching the consensus implementation; `float64` appears only in reporting (APY/ratios), never on any path that produces token quantities.

Reproducing this document's numbers:

```bash
cd the Quantaureum repo
go run ./cmd/econsim current                                          # §2 baseline
go run ./cmd/econsim compare                                          # §3 the two defects
go run ./cmd/econsim solve -preset eth -apy 0.04 -at 4000000          # §5 F=31
go run ./cmd/econsim table -preset eth -f 31                          # §5 full range
go run ./cmd/econsim project -preset eth -f 31 -years 20 -burn-share 0.008   # §6 projection
go run ./cmd/econsim breakeven -preset eth -f 31 -at 4000000          # §6 net-zero burn
go run ./cmd/econsim project -preset eth -f 31 -years 12 -fee-market \
  -tx-per-day 50000 -growth 0.4                                       # §6 endogenous baseFee
```

Verification commands:

```bash
go build ./economics/... ./cmd/econsim/ ./consensus/
go test ./economics/model/
go test -run 'Econ|Parity|Proposer' ./consensus/
```

---

## 11. Known model boundaries

Stating clearly what the model **cannot** answer matters more than a few extra tables.

### 11.1 baseFee has three conventions; the wrong one gives false answers

| Convention | CLI | When to use | Nature ||
---------|---||||
| fixed nominal gwei | `-basefee` | single year, convention contrast | **an exogenous assumption**; across years it fabricates deflation — the CLI prints a CAUTION ||
| endogenous 1559 | `-fee-market` | derive baseFee from a given transaction volume | below the gas target -> the 1 gwei floor; above target -> throughput capped at the block limit ||
| supply share | `-burn-share` | long horizons, no desire to assume gas prices | directly states "burn = X% of supply per year", immune to nominal-price issues ||

`-fee-market` encodes exactly two hard facts, nothing more:

1. **Below target -> the floor**. The 1559 controller lowers baseFee on every under-full block (at most −12.5%/block); this chain's floor is `params.MinGasPrice = 1 gwei` (the txpool rejects cheaper transactions, so baseFee cannot stabilize below it).
2. **Above target -> throughput cap**. Annual burn cannot exceed `2,628,000 blocks × 30,000,000 gas × baseFee`. Excess demand queues or is priced out; it does not burn more gas. Measured: raising demand 10x beyond 200M tx/day changes burn by nothing.

**Still unmodeled**: the clearing price under congestion. Once demand exceeds target, baseFee is set by users' fiat willingness to pay, outside this model. `-congestion-basefee` **defaults to 100 gwei** — silently adopted unless explicitly set, and labeled "congestion assumption" in output. When reading the tables, judge that assumption yourself; the model does not derive it.

Regression tests pin all three: `TestFeeMarketFloorBelowTarget` (50k tx/day must rest at the floor with supply growth), `TestFeeMarketCapsBurnAtBlockLimit` (post-saturation burn decouples from demand), `TestFeeMarketFloorIsChainMinimum` (floor = `params.MinGasPrice`; target×2 = limit).

### 11.2 Remaining boundaries

1. **Annual granularity**. Issuance is the year's stake level times 82,125 epochs, not iterated per epoch; since issuance is a pure function of stake and stake is constant within a year, the two differ only by intra-year compounding, negligible at these rates.
2. **The stake ratio and validator count are exogenous assumptions**, with no behavioral feedback of "APY falls -> stakers exit". Whether a 3% equilibrium APY sustains a 35% stake ratio is not a question the model answers.
3. **No token price, no fiat returns, no MEV.**
4. **Slashing is not modeled.** The consensus layer's existing rules stand; EM-2 adds no new economic-slash parameters; a separate effort after full TSS deployment.
5. **Inactivity penalties are not modeled either, and they are not slashing**. `consensus/epoch_rewards_census.go:161-166` deducts **2× baseReward** from active validators who did not participate; the deduction enters no account — a real **supply reduction**. The model omits it entirely, so at low participation the true net issuance is below the modeled value. Item 4 above only disclaimed slashing, which could mislead one into thinking inactivity penalties were covered.
6. **Parity's "wei-for-wei equality" holds only without slashed validators**. `CalculateBaseReward` (`consensus/epoch.go:365-370`) filters only by `Active` in the denominator, while `calculateBaseRewardUnlocked` (`consensus/epoch.go:513-522`, R28-029) additionally excludes `q.slashedValidators`. When a "slashed but still Active" validator exists, the denominators differ and so do the results. None of the six existing parity cases constructs a slashed set.

---

## 12. Decision record

| # | Decision | Chosen | Rejected | Rationale ||
---------|---||||---|
| D1 | supply cap | **no hard cap** | 100M cap + exponential tail (v1.0) | perpetual security budget; the 100M was never code-enforced and is stale ||
| D2 | issuance formula | Ethereum Altair `stake·F/√total` | self-invented `c×√S` (v1.0) | isomorphic to `consensus/epoch.go`, lockable by parity tests ||
| D3 | F | **31** | 2 (incumbent) / 24 / 39 / 137 (divisor miscalculation) | 4% at 4M stake, converging to 3% at equilibrium, the same band as Ethereum ||
| D4 | divisor | 1 (Altair) | 4 (phase0 legacy) | strictly follow Ethereum; must change together with F ||
| D5 | proposer share | 8/64 = 12.5% | one full share per slot (incumbent, 84.2%) | attestations drive finality and should not be undervalued 5.54x against target ||
| D6 | baseFee | 100% burned | partial treasury share | a treasury is a big governance attack surface; burn is the cleanest holder consideration ||
| D7 | priorityFee | fully to the proposer | 80/20 split to attesters (v1.0) | the 87.5% issuance weight already pays attesters; Ethereum does not split ||
| D8 | on-chain treasury / DAO treasury | not built | 10% of issuance to a treasury | genesis ecosystem 2M + development 2M + validator incentives 4M already cover it ||
| D9 | switch method | epoch gate + 5/6 multisig announcement | immediate switch | finality was just fixed; stability first, keep rollback ||
| D10 | ecosystem funding | entirely from genesis-allocated amounts | borrowing against future issuance | no inflation advances ||

---

## 13. Definition of done

Completed (this round):

- [x] Parity constant-by-constant verification: F / divisor / ProposerWeight / WeightDenominator / SlotsPerEpoch all match the consensus compile-time values, with an assertion that `WeightDenominator` divides 1e9 (`TestEconModelParityWithConsensus`)
- [x] **Strong parity**: the consensus's per-validator attester amounts and proposer pool are **wei-for-wei equal** to `model.EpochIssuanceAttributed`, dust=0, across three stake distributions (`TestEconModelParityAttribution`)
- [x] Proposer share constant at 12.5% independent of N, for N=1/6/32/128/1000 (`TestProposerShareIsAltairWeight`)
- [x] End-to-end: the census actually produces 0.186 QAU, 87.5%/12.5%, with the two-part recomputation leaking nothing (`TestEM2CensusIssuesPublishedAmounts`)
- [x] Issuance decoupled from proposed-slot count: 6 slots and 1 slot give identical total issuance and pool size (`TestEM2IssuanceIndependentOfProposedSlotCount`)
- [x] The two reward paths (local P2P and on-chain census) still agree per validator (`TestCensusRewardsMatchLocal`)
- [x] Repo-wide regression: `consensus` / `node` / `core` / `qvm` / `qaudb/...` / `encoding` / `economics/...` all green
- [x] The historical anchor still reproduces: `PreEM2MainnetParams` produces 1.9e16 wei (`TestPreEM2ReproducesObservedIssuance`)

To verify after the chain reset:

- [ ] The first epoch's log shows `total=186000000000000000 qau-wei`
- [ ] justified/finalized progress normally (6 validators satisfy `MinValidatorsForChambers`)
- [ ] `qau_qposStatus` staking and reward fields match the §5 table

Later milestones (§9.4 scope):

- [ ] Burn accounting: no loss of 1e18 precision, correct `totalBurned` accumulation, burned coins absent from every account balance
- [ ] `qau_getSupply` reconciles with the 20M genesis baseline (the R40.G convention)
- [ ] Wallets and the explorer correctly display the new issuance/burn fields
- [ ] Adjudicate the policy conflict between `economics/gas_fees.go` and `fee_distribution.go` (the §9.4 warning)

---

## 14. Revision history

| Version | Date | Notes ||
---|---||---|
| v1.0 | 2026-08-31 | First draft (EM-1). Baseline numbers carried a 1000x unit misread; the formula was not isomorphic to the consensus implementation. Voided ||
| v2.0 | 2026-08-31 | EM-2. Baseline fully recomputed; strictly Ethereum Altair (no hard cap, F=31, divisor 1, proposer 8/64); `economics/model` simulator and parity tests established; endogenous EIP-1559 fee market added (fixing the false deflation from a fixed nominal baseFee); §4.1 per-validator attribution rules and zero-dust proof added (enabling wei-for-wei consensus porting); model-boundary statements added ||
| v3.0 | 2026-08-31 | **EM-2 lands in the consensus layer**. A hard fork plus chain reset was selected before external users depended on a transition, so no epoch gate was added. Changed `consensus/block.go` (F=31, new divisor and weight constants, `ProposerRewardQuotient` removed), both `epoch.go` divisors, `epoch_rewards_census.go` (56/64 attester + 8/64 proposer pool two-pass scan), removed the dead `ministry_revenue.go` constant. Added strong parity (per-validator, dust=0) and two end-to-end census assertions. §2/§3 became historical contrast; §9 became implementation status ||
| v2.1 | 2026-08-31 | After adversarial review, two blocking errors fixed: §9 had the divisor's location wrong (it lives at `epoch.go:397/557`, not `block.go`; building to the wrong text yields 1/4 of the issuance), and the Ethereum APR quoted the tolerance target 3.2% instead of the computed 3.035% (test tolerance also tightened from ±10% to ±1%). Also corrected the undervaluation multiple 5.3->5.54, documented the two contradictory fee-policy modules, the inactivity penalty and the parity caveat under slashed sets, the float/supply column-convention footnotes, and the statement that projection year 1 is not the chain's current state ||

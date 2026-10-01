# R121 — Delegation & Liquid Staking mainnet rollout plan

| Field | Content ||
---|---||
| **Status** | 📋 Planning (R120 stable and running; work not started) ||
| **Owner** | Open — awaiting an open-source contributor ||
| **Priority** | High (promised in the whitepaper; currently missing) ||
| **Target** | Forkless mainnet integration (the v1 EM-2 reward module already has extension points) ||
| **Issue** | _GitHub Issue #1, to be created_ ||
| **Docs** | [TOKEN_ECONOMICS.md §4.4](../TOKEN_ECONOMICS.md), [WHITEPAPER.md §5](../WHITEPAPER.md), consensus package docs ||

---

## 1. Background / Problem Statement

### Current state (R120 mainnet at h≈4400+)

| Role | Staking ability | Rewards ||
---|---||---|
| 6 genesis validators | ✅ 6000 QAU each, active | ✅ auto-paid each epoch, ~7 QAU/day each ||
| Ordinary address holders | ❌ no entry point | ❌ none ||
| Delegation | ❌ framework exists in the codebase but no pool | ❌ none ||
| Liquid staking | ❌ framework exists, no pool | ❌ none ||

### Gaps versus whitepaper promises

| Whitepaper | Reality | Gap ||
---|---||---|
| "delegate staking from 1 QAU" | no qau_stake / qau_delegate user-facing RPC | 🔴 Critical ||
| "7-day unbonding" | no user-facing unbonding queue | 🔴 Critical ||
| "delegators share validator rewards pro rata" | LiquidStakingManager framework exists but pool active=false | 🔴 Critical ||
| "pools can switch validators" | no pool->validator binding logic | 🟡 ||
| "liquid staking receipt token" | the LiquidQ contract is undeveloped | 🟡 ||

### Risks

- **Trust risk**: the whitepaper is public; long-delayed delivery damages credibility
- **Vesting contradiction**: 50% of the pre-allocation is locked via LinearVesting (15M), but part of the 3,000,000 QAU ecosystem allocation **should go to early delegators**, and there is currently nowhere to put it
- **Centralization**: all 6 nodes are team-staked; a mis-slash costs a non-diversifiable 6000 QAU per validator

---

## 2. Goals / Non-Goals

### Goals
1. **Users can call an RPC directly on the R121 mainnet to delegate-stake** to any validator, from 1 QAU, earning rewards immediately
2. **7-day (145,152-epoch) unbonding period + cancellable**
3. **Rewards are shared pro rata to attestation contribution** across delegators / pools, net of commission
4. **Backward-compatible**: no hard fork; the R120 genesis stays in force; only new RPCs/logic
5. **Observable**: three read RPCs — `qau_getDelegation`, `qau_getStakingPool`, `qau_getPendingRewards`

### Non-Goals
- ❌ ERC-5484/NFT liquid receipts (next phase, R122)
- ❌ switching validators mid-lock — R122
- ❌ flash-loan-powered "fast unbonding" — forbidden
- ❌ infrastructure fixes for sub-max uptime (e.g. the batch of validator-node RPC issues) — separate task
- ❌ multisig treasury governance — deferred to R123 governance + timelock

---

## 3. Design draft

### 3.1 Data model

Extends the existing `economics/liquid_staking.go`:

```go
// economics/staking.go already exists; extended channel
type Delegation struct {
    Delegator   types.Address   // the user
    Pool        types.Address   // the validator delegated to
    Principal   *big.Int        // principal (wei)
    RewardBasis *big.Int        // cumulative RewardPerUnit at last claim
    LockedUntil uint64          // if not re-activated after unbonding, it may later be force-withdrawn as a fix
    State       DelegationState // Active / Unbonding / Withdrawn
}

type Pool struct {
    Validator     types.Address // acting as operator
    Commission    uint16        // basis 10000; 5% = 500
    TotalPrincipal *big.Int
    Delegators    map[types.Address]*Delegation
    // Extends LiquidStaking.go — drops the fake reward-pool aggregate
    // in favor of an epoch-level cumulative RewardPerUnit model
    CumulativeRewardPerUnit *big.Int
}
```

### 3.2 Reward algorithm (per-unit cumulative model)

```
At the end of each epoch:
    pool.CumulativeRewardPerUnit += thisEpochPoolReward * 1e18 / pool.TotalPrincipal

When a delegator queries rewards:
    reward = Principal * (CumulativeRewardPerUnit_now - CumulativeRewardPerUnit_atLastClaim) / 1e18
    RewardBasis = CumulativeRewardPerUnit_now
```

This design is a variant of Ma (2021), compatible with the existing EM-2 reward module:
- **No recomputing totals** — reward distribution costs O(1)/epoch
- **Locatable** — Merkle-style proofs remain possible later

### 3.3 Unbonding flow

| Phase | Duration | Notes ||
---|---||---|
| Active | unlimited | rewards distributed each epoch ||
| undelegate clicked | epoch N | rewards stop immediately; the principal enters the UnbondingQueue ||
| In queue | epoch N ~ N+145,152 (=7 days) | no rewards; the delegator can cancel at any time (back to Active) ||
| epoch N+145,152 | after completion | `ClaimNow()` withdraws principal + rewards ||

---

## 4. Implementation plan

### Phase 1 — contracts + RPC layer (~8 days)
| Task | Estimate | Owner ||
---|---||---|
| Extend `LiquidStakingManager` into `DelegationManager`; rewrite the pool-active/withdraw flow over this protocol's data | 2d | TBD ||
| Write the `qau_delegate` / `qau_undelegate` / `qau_claimRewards` RPCs (with delegator signature verification) | 2d | TBD ||
| Read RPCs: `qau_getDelegation`, `qau_getPool`, `qau_getPoolRewards`, `qau_estimateAPR` | 1d | TBD ||
| **Unit tests** > economics/delegation_test.go (table-driven, at least 50 cases covering boundaries, overflow, reentrancy paths) | 3d | TBD ||

### Phase 2 — hook into EM-2 distribution (~5 days)
| Task | Estimate ||
---|---||
| `epoch_rewards.go` hook: compute delegator rewards at each epoch end, updating CumulativeRewardPerUnit | 2d ||
| Consensus-layer hook: the proposer's reward feeds the pool share before commission | 1d ||
| **Integration test**: 6 nodes, 2 delegators, 1000 epochs, reconciling accounts at every step | 2d ||

### Phase 3 — security + tests (~7 days)
| Task | Estimate ||
---|---||
| Fuzz: `qau_delegate(qty)` / `qau_unbond` with large volumes of random quantities / junk values | 2d ||
| Liquid-staking-specific attack vectors: reentrancy / overflow / DoS spreads<br>&bull; CumulativeRewardPerUnit ghost overflow<br>&bull; unbond queue starvation attack<br>&bull; attestation reward-quantization gaming | 2d ||
| Slashing -> pro-rata delegator view<br/>(if a validator is slashed, delegators bear their share) | 1d ||
| Memory-leak test: UnbondingQueue at +100k entries per delegate | 2d ||

### Phase 4 — docs + launch (~4 days)
| Task | Estimate ||
---|---||
| TOKEN_ECONOMICS §4.4 update: (status = planned -> live) | 1d ||
| English docs/delegation-quickstart.md | 1d ||
| Chinese docs/delegation-quickstart-cn.md | 0.5d ||
| Update qau-cli: `qau-cli delegate --to <validator-addr> 1.0` command (working) | 1.5d ||

### Totals
| Category | Tasks | Delivery ||
---|---||---|
| Code | Phases 1 + 2 | 10 days ||
| Tests + security | Phase 3 | 7 days ||
| Docs + UX | Phase 4 | 4 days ||
 **Total** | | **21 person-days** |

**Target calendar**: with 1 full-time developer + 1 reviewer working in parallel, testnet in ~4 weeks, then 2 weeks of monitoring before mainnet.

---

## 5. Acceptance criteria

After opening a PR:

- [ ] all new RPCs respond correctly (matching the §3.2 queries)
- [ ] per-epoch reward error < 0.000001 QAU (over a 1-day accumulation test)
- [ ] 3250 epochs with no cross-pool reentrancy
- [ ] stress: 1000x delegate, 1000x undelegate, 1000x claim, no panic
- [ ] integration simulation: 3 validators + delegators over 5000 epochs; the reward formula reconciles
- [ ] golangci-lint zero warnings (except explicit waivers)
- [ ] unit coverage >= 90% (go test -cover ./economics/...)

---

## 6. How to contribute

If you would like to take a task:

```bash
# 1. Fork repo
git clone https://github.com/YOUR-NAME/quantaureum-node.git

# 2. Claim a task in GitHub Issue #_R121-DELEGATION
#    with a one-line comment: "Working on Task 3.1 LiquidStakingManager refactor"

# 3. New branch
git checkout -b feat/r121-delegation-T3.1-your-name

# 4. Tests are mandatory (lint zero warnings, coverage >85% for the economics package)
go test -v ./economics/...
golangci-lint run

# 5. Commit messages follow Conventional Commits:
git commit -m "feat(economics): add Delegation struct with reward-per-unit tracking

Implements per-epoch reward accumulation for delegators with CumulativeRewardPerUnit.
- Add Delegation struct with Principal, RewardBasis, Unbonding fields
- Add Pool struct with commission and pool accounting
- Implements unbonding queue with 145,152 epoch expiry

Ref: #1"
```

**Code-review essentials** (maintainers must check):
- [ ] reward computation is all integer/big.Int, with no float precision loss
- [ ] RPC errors return detailed `-32003` (without sensitive internals)
- [ ] `time.Now()` must not drive business logic — all time comes from injected blockTime/epoch (per R43)

---

## 7. Incentives (motivation model)

To encourage community developers (no mainnet treasury is reserved yet; this is v1):

```
Incentives (initial intent; final amounts confirmed via a governance proposal):
  first contributor to complete Phase 1 -> 250 QAU
  first contributor to complete Phase 2 -> 125 QAU
  contributors of the 3rd-5th valid merged PRs -> 25 QAU each
  ‑‑
  total incentive cap: 450 QAU (~0.009% of circulating supply)
```

**Design philosophy**: small and stable. It rewards "people who genuinely want to build together", not incentive-farming speculators.

---

## 8. Dependencies / blockers

| Dependency | Status | Impact ||
---|---||---|
| EM-2 epoch rewards stably running on mainnet | ✅ live | none ||
| the 6000 QAU stake of allocation accounts is a genesis value | ✅ | none ||
| Governance/QIP process | ⏸️ planned | soft dependency; R121 can launch without governance ||
| Treasury multisig | 📋 not started | blocks delegator rewards; interim plan: "protocol-native rewards" ||
| validator registry RPC | ✅ exists in qpos | none ||

---

## 9. References

- [Token Economics §4.4](../TOKEN_ECONOMICS.md) — user-facing promise
- consensus/epoch_rewards_census.go — current reward pipeline
- [economics/liquid_staking.go](../../economics/liquid_staking.go) — code entry point
- localtest/ — reference for spinning up a local 6-node network

---

*Document version: v1.0 · 2026-09-04 · Author: mainnet maintainers (collective attribution)*
*License: GPL-3.0*
*Issue tracking: https://github.com/Quantaureum/qau/issues (post your intent in the issue before claiming a task)*
